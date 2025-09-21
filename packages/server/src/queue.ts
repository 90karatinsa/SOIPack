import fs from 'fs';
import path from 'path';

import { HttpError, toHttpError } from './errors';

export type JobKind = 'import' | 'analyze' | 'report' | 'pack';

export type JobStatus = 'queued' | 'running' | 'completed' | 'failed';

interface JobErrorInfo {
  statusCode: number;
  code: string;
  message: string;
  details?: unknown;
}

interface InternalJob<T = unknown> {
  tenantId: string;
  id: string;
  kind: JobKind;
  hash: string;
  status: JobStatus;
  createdAt: Date;
  updatedAt: Date;
  run?: () => Promise<unknown>;
  payload?: unknown;
  result?: T;
  error?: JobErrorInfo;
  filePath: string;
}

export interface JobSummary {
  id: string;
  kind: JobKind;
  hash: string;
  status: JobStatus;
  createdAt: Date;
  updatedAt: Date;
}

export interface JobDetails<T = unknown> extends JobSummary {
  result?: T;
  error?: JobErrorInfo;
}

interface EnqueueOptions<TPayload> {
  tenantId: string;
  id: string;
  kind: JobKind;
  hash: string;
  payload?: TPayload;
}

interface AdoptOptions<T> {
  tenantId: string;
  id: string;
  kind: JobKind;
  hash: string;
  createdAt: string;
  updatedAt?: string;
  result: T;
}

export interface JobExecutionContext<TPayload = unknown> {
  tenantId: string;
  id: string;
  kind: JobKind;
  hash: string;
  payload?: TPayload;
}

export interface JobQueueOptions {
  directory: string;
  createRunner: (context: JobExecutionContext) => () => Promise<unknown>;
}

interface PersistedJob {
  tenantId: string;
  id: string;
  kind: JobKind;
  hash: string;
  status: JobStatus;
  createdAt: string;
  updatedAt: string;
  payload?: unknown;
  result?: unknown;
  error?: JobErrorInfo;
}

export class JobQueue {
  private readonly concurrency: number;

  private readonly jobs = new Map<string, InternalJob<unknown>>();

  private readonly order: InternalJob<unknown>[] = [];

  private readonly pending: InternalJob<unknown>[] = [];

  private active = 0;

  private idleResolvers: Array<() => void> = [];

  private readonly directory: string;

  private readonly createRunner: (context: JobExecutionContext) => () => Promise<unknown>;

  constructor(concurrency = 1, options: JobQueueOptions) {
    this.concurrency = Math.max(1, concurrency);
    this.directory = options.directory;
    this.createRunner = options.createRunner;
    fs.mkdirSync(this.directory, { recursive: true, mode: 0o750 });
    this.loadPersistedJobs();
  }

  private loadPersistedJobs(): void {
    const tenantDirs = fs
      .readdirSync(this.directory, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name);

    const jobs: InternalJob<unknown>[] = [];

    for (const tenantId of tenantDirs) {
      const tenantDir = path.join(this.directory, tenantId);
      const files = fs
        .readdirSync(tenantDir, { withFileTypes: true })
        .filter((entry) => entry.isFile() && entry.name.endsWith('.json'))
        .map((entry) => entry.name);

      for (const fileName of files) {
        const filePath = path.join(tenantDir, fileName);
        try {
          const raw = fs.readFileSync(filePath, 'utf8');
          const parsed = JSON.parse(raw) as PersistedJob;
          const job = this.fromPersistedJob(parsed, filePath);
          jobs.push(job);
        } catch {
          // Ignore corrupted job files.
        }
      }
    }

    jobs.sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());

    for (const job of jobs) {
      const key = this.getKey(job.tenantId, job.id);
      this.jobs.set(key, job);
      this.order.push(job);

      if (job.status === 'running') {
        job.status = 'queued';
        job.updatedAt = new Date();
        job.run = this.createRunner(this.toExecutionContext(job));
        this.pending.push(job);
        this.saveJob(job);
      } else if (job.status === 'queued') {
        job.run = this.createRunner(this.toExecutionContext(job));
        this.pending.push(job);
      }
    }

    if (this.pending.length > 0) {
      this.process();
    }
  }

  private getKey(tenantId: string, id: string): string {
    return `${tenantId}:${id}`;
  }

  public enqueue<TPayload = unknown, TResult = unknown>({
    tenantId,
    id,
    kind,
    hash,
    payload,
  }: EnqueueOptions<TPayload>): JobDetails<TResult> {
    const key = this.getKey(tenantId, id);
    const existing = this.jobs.get(key) as InternalJob<TResult> | undefined;
    if (existing) {
      return this.toDetails(existing);
    }

    const createdAt = new Date();
    const job: InternalJob<TResult> = {
      tenantId,
      id,
      kind,
      hash,
      status: 'queued',
      createdAt,
      updatedAt: createdAt,
      payload,
      filePath: this.getJobFilePath(tenantId, id),
    };

    job.run = this.createRunner(this.toExecutionContext(job));

    this.jobs.set(key, job);
    this.order.push(job);
    this.pending.push(job);
    this.saveJob(job);
    this.process();

    return this.toDetails(job);
  }

  public adoptCompleted<T>({
    tenantId,
    id,
    kind,
    hash,
    createdAt,
    updatedAt,
    result,
  }: AdoptOptions<T>): JobDetails<T> {
    const key = this.getKey(tenantId, id);
    const existing = this.jobs.get(key) as InternalJob<T> | undefined;
    if (existing) {
      if (existing.status === 'completed' && existing.result === undefined) {
        existing.result = result;
        this.saveJob(existing);
      }
      return this.toDetails(existing);
    }

    const created = new Date(createdAt);
    const updated = updatedAt ? new Date(updatedAt) : created;
    const job: InternalJob<T> = {
      tenantId,
      id,
      kind,
      hash,
      status: 'completed',
      createdAt: created,
      updatedAt: updated,
      result,
      filePath: this.getJobFilePath(tenantId, id),
    };

    this.jobs.set(key, job);
    this.order.push(job);
    this.saveJob(job);
    return this.toDetails(job);
  }

  public list(tenantId: string): JobSummary[] {
    return this.order.filter((job) => job.tenantId === tenantId).map((job) => this.toSummary(job));
  }

  public get<T = unknown>(tenantId: string, id: string): JobDetails<T> | undefined {
    const job = this.jobs.get(this.getKey(tenantId, id)) as InternalJob<T> | undefined;
    if (!job) {
      return undefined;
    }
    return this.toDetails(job);
  }

  public remove<T = unknown>(tenantId: string, id: string): JobDetails<T> | undefined {
    const key = this.getKey(tenantId, id);
    const job = this.jobs.get(key) as InternalJob<T> | undefined;
    if (!job) {
      return undefined;
    }

    if (job.status === 'running') {
      throw new HttpError(409, 'JOB_RUNNING', 'İş şu anda çalışıyor ve kaldırılamaz.');
    }

    this.jobs.delete(key);
    this.removeFromOrder(job);
    this.removeFromPending(job);
    this.deleteJobFile(job);

    const details = this.toDetails(job);
    this.notifyIdleIfNeeded();
    return details;
  }

  public async waitForIdle(): Promise<void> {
    if (this.active === 0 && this.pending.length === 0) {
      return;
    }

    await new Promise<void>((resolve) => {
      this.idleResolvers.push(resolve);
    });
  }

  private removeFromOrder(job: InternalJob<unknown>): void {
    const index = this.order.indexOf(job);
    if (index >= 0) {
      this.order.splice(index, 1);
    }
  }

  private removeFromPending(job: InternalJob<unknown>): void {
    const index = this.pending.indexOf(job);
    if (index >= 0) {
      this.pending.splice(index, 1);
    }
  }

  private process(): void {
    while (this.active < this.concurrency) {
      const job = this.pending.shift();
      if (!job) {
        break;
      }
      if (!job.run) {
        continue;
      }

      this.active += 1;
      job.status = 'running';
      job.updatedAt = new Date();
      job.error = undefined;
      this.saveJob(job);

      Promise.resolve()
        .then(() => job.run!())
        .then((result) => {
          job.status = 'completed';
          job.result = result;
          job.updatedAt = new Date();
          this.saveJob(job);
        })
        .catch((error) => {
          const normalized = this.normalizeError(error);
          job.status = 'failed';
          job.error = normalized;
          job.updatedAt = new Date();
          this.saveJob(job);
        })
        .finally(() => {
          this.active -= 1;
          this.process();
          this.notifyIdleIfNeeded();
        });
    }
    this.notifyIdleIfNeeded();
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

  private toSummary(job: InternalJob<unknown>): JobSummary {
    return {
      id: job.id,
      kind: job.kind,
      hash: job.hash,
      status: job.status,
      createdAt: job.createdAt,
      updatedAt: job.updatedAt,
    };
  }

  private toDetails<T>(job: InternalJob<T>): JobDetails<T> {
    return {
      ...this.toSummary(job),
      result: job.result,
      error: job.error,
    };
  }

  private getJobFilePath(tenantId: string, id: string): string {
    const tenantDir = path.join(this.directory, tenantId);
    fs.mkdirSync(tenantDir, { recursive: true, mode: 0o750 });
    return path.join(tenantDir, `${id}.json`);
  }

  private saveJob(job: InternalJob<unknown>): void {
    const serialized: PersistedJob = {
      tenantId: job.tenantId,
      id: job.id,
      kind: job.kind,
      hash: job.hash,
      status: job.status,
      createdAt: job.createdAt.toISOString(),
      updatedAt: job.updatedAt.toISOString(),
      payload: job.payload,
      result: job.result,
      error: job.error,
    };
    fs.writeFileSync(job.filePath, `${JSON.stringify(serialized, null, 2)}\n`, 'utf8');
  }

  private deleteJobFile(job: InternalJob<unknown>): void {
    try {
      fs.rmSync(job.filePath, { force: true });
      const tenantDir = path.dirname(job.filePath);
      const entries = fs.readdirSync(tenantDir);
      if (entries.length === 0) {
        fs.rmdirSync(tenantDir);
      }
    } catch {
      // Ignore cleanup errors.
    }
  }

  private fromPersistedJob(data: PersistedJob, filePath: string): InternalJob<unknown> {
    const job: InternalJob<unknown> = {
      tenantId: data.tenantId,
      id: data.id,
      kind: data.kind,
      hash: data.hash,
      status: data.status,
      createdAt: new Date(data.createdAt),
      updatedAt: new Date(data.updatedAt),
      payload: data.payload,
      result: data.result,
      error: data.error,
      filePath,
    };

    if (job.status === 'queued') {
      job.run = this.createRunner(this.toExecutionContext(job));
    }

    return job;
  }

  private toExecutionContext(job: InternalJob<unknown>): JobExecutionContext {
    return {
      tenantId: job.tenantId,
      id: job.id,
      kind: job.kind,
      hash: job.hash,
      payload: job.payload,
    };
  }

  private notifyIdleIfNeeded(): void {
    if (this.active !== 0 || this.pending.length !== 0 || this.idleResolvers.length === 0) {
      return;
    }

    const resolvers = this.idleResolvers;
    this.idleResolvers = [];
    resolvers.forEach((resolve) => {
      try {
        resolve();
      } catch {
        // Ignore resolver errors.
      }
    });
  }
}
