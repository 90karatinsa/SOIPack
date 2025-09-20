import { toHttpError } from './errors';

type JobKind = 'import' | 'analyze' | 'report' | 'pack';

type JobStatus = 'queued' | 'running' | 'completed' | 'failed';

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

  private readonly jobs = new Map<string, InternalJob<any>>();

  private readonly order: InternalJob<any>[] = [];

  private readonly pending: InternalJob<any>[] = [];

  private active = 0;

  constructor(concurrency = 1) {
    this.concurrency = Math.max(1, concurrency);
  }

  private getKey(tenantId: string, id: string): string {
    return `${tenantId}:${id}`;
  }

  public enqueue<T>({ tenantId, id, kind, hash, run }: EnqueueOptions<T>): JobDetails<T> {
    const key = this.getKey(tenantId, id);
    const existing = this.jobs.get(key);
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
    const existing = this.jobs.get(key);
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
    const job = this.jobs.get(this.getKey(tenantId, id));
    if (!job) {
      return undefined;
    }
    return this.toDetails(job) as JobDetails<T>;
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
        });
    }
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

  private toSummary(job: InternalJob<any>): JobSummary {
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
}
