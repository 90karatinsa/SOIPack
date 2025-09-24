import type { Pool } from 'pg';

import { toHttpError } from '../errors';
import type { JobDetails, JobExecutionContext, JobKind, JobStatus, JobSummary } from '../queue';

interface JobErrorInfo {
  statusCode: number;
  code: string;
  message: string;
  details?: unknown;
}

export interface PostgresQueueEnqueueOptions<TPayload> {
  tenantId: string;
  id: string;
  kind: JobKind;
  hash: string;
  payload?: TPayload;
  createdAt?: Date;
  updatedAt?: Date;
}

interface QueueJobRow {
  tenant_id: string;
  id: string;
  kind: JobKind;
  hash: string;
  status: JobStatus;
  payload: unknown;
  result: unknown;
  error: JobErrorInfo | null;
  created_at: Date;
  updated_at: Date;
  completed_at: Date | null;
}

interface ClaimedJobRow {
  tenant_id: string;
  id: string;
  kind: JobKind;
  hash: string;
  payload: unknown;
}

export interface PostgresQueueRetentionOptions {
  completedMs?: number | null;
  failedMs?: number | null;
  sweepIntervalMs?: number;
}

export interface PostgresQueueOptions {
  pool: Pool;
  concurrency?: number;
  createRunner: (context: JobExecutionContext) => () => Promise<unknown>;
  retention?: PostgresQueueRetentionOptions;
}

const DEFAULT_COMPLETED_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
const DEFAULT_FAILED_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
const DEFAULT_SWEEP_INTERVAL_MS = 5 * 60 * 1000;

const STATUS_RUNNING: JobStatus = 'running';
const STATUS_QUEUED: JobStatus = 'queued';
const STATUS_COMPLETED: JobStatus = 'completed';
const STATUS_FAILED: JobStatus = 'failed';

export class PostgresQueue {
  private readonly pool: Pool;

  private readonly concurrency: number;

  private readonly createRunner: (context: JobExecutionContext) => () => Promise<unknown>;

  private readonly runningTenants = new Set<string>();

  private readonly retention: Required<PostgresQueueRetentionOptions>;

  private active = 0;

  private closed = false;

  private scheduling = false;

  private pendingSchedule = false;

  private retentionTimer?: NodeJS.Timeout;

  private readonly startPromise: Promise<void>;

  constructor(options: PostgresQueueOptions) {
    this.pool = options.pool;
    this.concurrency = Math.max(1, options.concurrency ?? 1);
    this.createRunner = options.createRunner;

    const retentionOptions = options.retention ?? {};
    const {
      completedMs = DEFAULT_COMPLETED_RETENTION_MS,
      failedMs = DEFAULT_FAILED_RETENTION_MS,
      sweepIntervalMs = DEFAULT_SWEEP_INTERVAL_MS,
    } = retentionOptions;
    this.retention = {
      completedMs,
      failedMs,
      sweepIntervalMs,
    };

    this.startPromise = this.initialize();
    this.startPromise
      .then(() => {
        if (!this.closed) {
          this.requestSchedule();
        }
      })
      .catch(() => undefined);
  }

  static async ensureSchema(pool: Pool): Promise<void> {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS queue_jobs (
        tenant_id TEXT,
        id TEXT,
        kind TEXT,
        hash TEXT,
        payload JSONB,
        status TEXT,
        result JSONB,
        error JSONB,
        created_at TIMESTAMP,
        updated_at TIMESTAMP,
        started_at TIMESTAMP,
        completed_at TIMESTAMP,
        attempts INTEGER
      )
    `);
    await pool.query('ALTER TABLE queue_jobs ADD COLUMN IF NOT EXISTS attempts INTEGER');
    await pool.query('UPDATE queue_jobs SET attempts = 0 WHERE attempts IS NULL');
    await pool.query(
      'CREATE UNIQUE INDEX IF NOT EXISTS queue_jobs_tenant_id_id_idx ON queue_jobs (tenant_id, id)',
    );
    await pool.query(
      'CREATE INDEX IF NOT EXISTS queue_jobs_status_idx ON queue_jobs (status, created_at, tenant_id)',
    );
    await pool.query(
      'CREATE INDEX IF NOT EXISTS queue_jobs_tenant_idx ON queue_jobs (tenant_id, created_at DESC)',
    );
  }

  async ready(): Promise<void> {
    await this.startPromise;
  }

  async enqueue<TPayload>(options: PostgresQueueEnqueueOptions<TPayload>): Promise<void> {
    await this.startPromise;
    if (this.closed) {
      throw new Error('Queue is shut down.');
    }
    const createdAtValue = options.createdAt ?? new Date();
    const updatedAtValue = options.updatedAt ?? createdAtValue;
    await this.pool.query(
      `
        INSERT INTO queue_jobs (tenant_id, id, kind, hash, payload, status, created_at, updated_at, result, error, started_at, completed_at, attempts)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, NULL, NULL, NULL, 0)
        ON CONFLICT (tenant_id, id)
        DO UPDATE SET
          kind = EXCLUDED.kind,
          hash = EXCLUDED.hash,
          payload = EXCLUDED.payload,
          status = $6,
          created_at = CASE
            WHEN queue_jobs.created_at <= EXCLUDED.created_at THEN queue_jobs.created_at
            ELSE EXCLUDED.created_at
          END,
          updated_at = CURRENT_TIMESTAMP,
          result = NULL,
          error = NULL,
          started_at = NULL,
          completed_at = NULL
      `,
      [
        options.tenantId,
        options.id,
        options.kind,
        options.hash,
        options.payload ?? null,
        STATUS_QUEUED,
        createdAtValue,
        updatedAtValue,
      ],
    );
    this.requestSchedule();
  }

  async get<T = unknown>(tenantId: string, id: string): Promise<JobDetails<T> | undefined> {
    await this.startPromise;
    const { rows } = await this.pool.query<QueueJobRow>(
      `
        SELECT tenant_id, id, kind, hash, status, payload, result, error, created_at, updated_at, completed_at
        FROM queue_jobs
        WHERE tenant_id = $1 AND id = $2
      `,
      [tenantId, id],
    );
    if (rows.length === 0) {
      return undefined;
    }
    return this.toDetails(rows[0]);
  }

  async streamSummaries(tenantId: string): Promise<JobSummary[]> {
    await this.startPromise;
    const { rows } = await this.pool.query<QueueJobRow>(
      `
        SELECT tenant_id, id, kind, hash, status, payload, result, error, created_at, updated_at, completed_at
        FROM queue_jobs
        WHERE tenant_id = $1
        ORDER BY created_at ASC, id ASC
      `,
      [tenantId],
    );
    return rows.map((row) => this.toSummary(row));
  }

  async waitForIdle(): Promise<void> {
    await this.startPromise;
    for (;;) {
      const pending = await this.countActiveJobs();
      if (pending === 0 && this.active === 0 && !this.scheduling) {
        return;
      }
      await PostgresQueue.delay(10);
    }
  }

  async close(): Promise<void> {
    this.closed = true;
    if (this.retentionTimer) {
      clearInterval(this.retentionTimer);
      this.retentionTimer = undefined;
    }
    await this.startPromise;
    while (this.active > 0) {
      await PostgresQueue.delay(10);
    }
  }

  async sweepRetention(): Promise<void> {
    await this.startPromise;
    await this.runRetentionSweep();
  }

  private async initialize(): Promise<void> {
    await PostgresQueue.ensureSchema(this.pool);
    await this.resetStalledJobs();
    this.startRetentionTimer();
  }

  private async resetStalledJobs(): Promise<void> {
    await this.pool.query(
      `
        UPDATE queue_jobs
           SET status = $1,
               updated_at = CURRENT_TIMESTAMP,
               started_at = NULL
         WHERE status = $2
      `,
      [STATUS_QUEUED, STATUS_RUNNING],
    );
  }

  private requestSchedule(): void {
    if (this.closed) {
      return;
    }
    if (this.scheduling) {
      this.pendingSchedule = true;
      return;
    }
    this.scheduling = true;
    this.pendingSchedule = false;
    void this.scheduleLoop();
  }

  private async scheduleLoop(): Promise<void> {
    try {
      while (!this.closed && this.active < this.concurrency) {
        const job = await this.claimNextJob();
        if (!job) {
          break;
        }
        this.startJob(job);
      }
    } finally {
      this.scheduling = false;
      if (this.pendingSchedule && !this.closed) {
        this.requestSchedule();
      }
    }
  }

  private async claimNextJob(): Promise<ClaimedJobRow | undefined> {
    const { rows } = await this.pool.query<ClaimedJobRow & { created_at: Date }>(
      `
        SELECT tenant_id, id, kind, hash, payload, created_at
        FROM queue_jobs
        WHERE status = $1
        ORDER BY created_at ASC, id ASC
      `,
      [STATUS_QUEUED],
    );

    for (const row of rows) {
      if (this.runningTenants.has(row.tenant_id)) {
        continue;
      }
      const update = await this.pool.query<ClaimedJobRow>(
        `
          UPDATE queue_jobs
             SET status = $1,
                 updated_at = CURRENT_TIMESTAMP,
                 started_at = CURRENT_TIMESTAMP,
                 error = NULL,
                 attempts = attempts + 1
           WHERE tenant_id = $2 AND id = $3 AND status = $4
           RETURNING tenant_id, id, kind, hash, payload
        `,
        [STATUS_RUNNING, row.tenant_id, row.id, STATUS_QUEUED],
      );
      if ((update.rowCount ?? 0) > 0) {
        return update.rows[0];
      }
    }

    return undefined;
  }

  private startJob(row: ClaimedJobRow): void {
    const context: JobExecutionContext = {
      tenantId: row.tenant_id,
      id: row.id,
      kind: row.kind,
      hash: row.hash,
      payload: row.payload ?? undefined,
    };

    this.active += 1;
    this.runningTenants.add(row.tenant_id);

    let runner: () => Promise<unknown>;
    try {
      runner = this.createRunner(context);
    } catch (error) {
      void this.failJob(row.tenant_id, row.id, error).finally(() => {
        this.finishJob(row.tenant_id);
      });
      return;
    }

    Promise.resolve()
      .then(() => runner())
      .then((result) => this.completeJob(row.tenant_id, row.id, result))
      .catch((error) => this.failJob(row.tenant_id, row.id, error))
      .finally(() => {
        this.finishJob(row.tenant_id);
      });
  }

  private async completeJob(tenantId: string, id: string, result: unknown): Promise<void> {
    await this.pool.query(
      `
        UPDATE queue_jobs
           SET status = $1,
               result = $4,
               error = NULL,
               updated_at = CURRENT_TIMESTAMP,
               completed_at = CURRENT_TIMESTAMP
         WHERE tenant_id = $2 AND id = $3
      `,
      [STATUS_COMPLETED, tenantId, id, result ?? null],
    );
  }

  private async failJob(tenantId: string, id: string, error: unknown): Promise<void> {
    const normalized = this.normalizeError(error);
    await this.pool.query(
      `
        UPDATE queue_jobs
           SET status = $1,
               result = NULL,
               error = $4,
               updated_at = CURRENT_TIMESTAMP,
               completed_at = CURRENT_TIMESTAMP
         WHERE tenant_id = $2 AND id = $3
      `,
      [STATUS_FAILED, tenantId, id, normalized],
    );
  }

  private finishJob(tenantId: string): void {
    this.active -= 1;
    this.runningTenants.delete(tenantId);
    this.requestSchedule();
  }

  private toSummary(row: QueueJobRow): JobSummary {
    return {
      id: row.id,
      kind: row.kind,
      hash: row.hash,
      status: row.status,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  private toDetails<T>(row: QueueJobRow): JobDetails<T> {
    return {
      ...this.toSummary(row),
      result: row.result as T | undefined,
      error: row.error ?? undefined,
    };
  }

  private normalizeError(error: unknown): JobErrorInfo {
    const httpError = toHttpError(error, {
      code: 'JOB_FAILED',
      message: 'İş başarısız oldu.',
      statusCode: 500,
    });
    return {
      statusCode: httpError.statusCode,
      code: httpError.code,
      message: httpError.message,
      details: httpError.details,
    };
  }

  private async countActiveJobs(): Promise<number> {
    const { rows } = await this.pool.query<{ count: number }>(
      `
        SELECT COUNT(*)::INT AS count
          FROM queue_jobs
         WHERE status IN ($1, $2)
      `,
      [STATUS_QUEUED, STATUS_RUNNING],
    );
    return rows[0]?.count ?? 0;
  }

  private startRetentionTimer(): void {
    if (!this.retention.sweepIntervalMs || this.retention.sweepIntervalMs <= 0) {
      return;
    }
    this.retentionTimer = setInterval(() => {
      void this.runRetentionSweep().catch(() => undefined);
    }, this.retention.sweepIntervalMs);
    if (this.retentionTimer.unref) {
      this.retentionTimer.unref();
    }
  }

  private async runRetentionSweep(): Promise<void> {
    if (this.retention.completedMs !== null) {
      await this.pool.query(
        `
          DELETE FROM queue_jobs
           WHERE status = $1
             AND completed_at IS NOT NULL
             AND completed_at < CURRENT_TIMESTAMP - ($2)::interval
        `,
        [STATUS_COMPLETED, this.toInterval(this.retention.completedMs)],
      );
    }
    if (this.retention.failedMs !== null) {
      await this.pool.query(
        `
          DELETE FROM queue_jobs
           WHERE status = $1
             AND completed_at IS NOT NULL
             AND completed_at < CURRENT_TIMESTAMP - ($2)::interval
        `,
        [STATUS_FAILED, this.toInterval(this.retention.failedMs)],
      );
    }
  }

  private toInterval(milliseconds: number): string {
    const clamped = Number.isFinite(milliseconds) ? Math.max(0, Math.floor(milliseconds)) : 0;
    return `${clamped} milliseconds`;
  }

  private static async delay(ms: number): Promise<void> {
    await new Promise((resolve) => setTimeout(resolve, ms));
  }
}
