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
  run?: () => Promise<T>;
  result?: T;
  error?: JobErrorInfo;
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

interface EnqueueOptions<T> {
  tenantId: string;
  id: string;
  kind: JobKind;
  hash: string;
  run: () => Promise<T>;
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

export class JobQueue {
  private readonly concurrency: number;

  private readonly jobs = new Map<string, InternalJob<unknown>>();

  private readonly order: InternalJob<unknown>[] = [];

  private readonly pending: InternalJob<unknown>[] = [];

  private active = 0;

  private idleResolvers: Array<() => void> = [];

  constructor(concurrency = 1) {
    this.concurrency = Math.max(1, concurrency);
  }

  private getKey(tenantId: string, id: string): string {
    return `${tenantId}:${id}`;
  }

  public enqueue<T>({ tenantId, id, kind, hash, run }: EnqueueOptions<T>): JobDetails<T> {
    const key = this.getKey(tenantId, id);
    const existing = this.jobs.get(key) as InternalJob<T> | undefined;
    if (existing) {
      return this.toDetails(existing);
    }

    const createdAt = new Date();
    const job: InternalJob<T> = {
      tenantId,
      id,
      kind,
      hash,
      status: 'queued',
      createdAt,
      updatedAt: createdAt,
      run,
    };

    this.jobs.set(key, job);
    this.order.push(job);
    this.pending.push(job);
    this.process();

    return this.toDetails(job);
  }

  public adoptCompleted<T>({ tenantId, id, kind, hash, createdAt, updatedAt, result }: AdoptOptions<T>): JobDetails<T> {
    const key = this.getKey(tenantId, id);
    const existing = this.jobs.get(key) as InternalJob<T> | undefined;
    if (existing) {
      if (existing.status === 'completed' && existing.result === undefined) {
        existing.result = result;
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
    };

    this.jobs.set(key, job);
    this.order.push(job);
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

      Promise.resolve()
        .then(() => job.run!())
        .then((result) => {
          job.status = 'completed';
          job.result = result;
          job.updatedAt = new Date();
        })
        .catch((error) => {
          const normalized = this.normalizeError(error);
          job.status = 'failed';
          job.error = normalized;
          job.updatedAt = new Date();
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
