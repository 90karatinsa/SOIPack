import type { Request, Response } from 'express';

import type { LedgerEntry, ManifestMerkleSummary } from '@soipack/core';
import type { ComplianceRiskFactorContributions, RiskProfile } from '@soipack/engine';

import type { JobSummary } from './queue';

export type ComplianceEventType = 'riskProfile' | 'ledgerEntry' | 'queueState' | 'manifestProof';

export interface ComplianceEventBase {
  tenantId: string;
  id?: string;
  emittedAt?: string;
}

export interface ComplianceRiskEvent extends ComplianceEventBase {
  type: 'riskProfile';
  profile: RiskProfile;
  contributions: ComplianceRiskFactorContributions;
}

export interface ComplianceLedgerEvent extends ComplianceEventBase {
  type: 'ledgerEntry';
  entry: LedgerEntry;
}

export interface ComplianceQueueEvent extends ComplianceEventBase {
  type: 'queueState';
  jobs: Array<{
    id: string;
    kind: JobSummary['kind'];
    status: JobSummary['status'];
    hash: string;
    createdAt: string;
    updatedAt: string;
  }>;
  counts: Record<JobSummary['status'], number>;
}

export interface ComplianceManifestProofEvent extends ComplianceEventBase {
  type: 'manifestProof';
  manifestId: string;
  jobId?: string;
  merkle?: ManifestMerkleSummary | null;
  files: Array<{ path: string; sha256: string; hasProof: boolean; verified: boolean }>;
}

export type ComplianceEvent =
  | ComplianceRiskEvent
  | ComplianceLedgerEvent
  | ComplianceQueueEvent
  | ComplianceManifestProofEvent;

export class EventAuthorizationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EventAuthorizationError';
  }
}

const toIsoString = (value: Date): string => value.toISOString();

const formatSseMessage = (event: ComplianceEvent, eventId?: string): string => {
  const lines: string[] = [];
  if (eventId) {
    lines.push(`id: ${eventId}`);
  }
  lines.push(`event: ${event.type}`);
  const payload = JSON.stringify(event);
  payload.split(/\n/).forEach((line) => {
    lines.push(`data: ${line}`);
  });
  return `${lines.join('\n')}\n\n`;
};

class SseConnection {
  private readonly queue: string[] = [];

  private paused = false;

  private readonly heartbeat?: NodeJS.Timeout;

  private closed = false;

  constructor(
    private readonly response: Response,
    private readonly onClose: () => void,
    heartbeatMs: number,
  ) {
    this.response.setHeader('Content-Type', 'text/event-stream');
    this.response.setHeader('Cache-Control', 'no-cache, no-transform');
    this.response.setHeader('Connection', 'keep-alive');
    this.response.setHeader('X-Accel-Buffering', 'no');
    if (typeof (this.response as Response & { flushHeaders?: () => void }).flushHeaders === 'function') {
      (this.response as Response & { flushHeaders: () => void }).flushHeaders();
    } else {
      this.response.writeHead?.(200);
    }
    this.response.write(': connected\n\n');

    if (heartbeatMs > 0) {
      this.heartbeat = setInterval(() => {
        this.sendRaw(`: heartbeat ${Date.now()}\n\n`);
      }, heartbeatMs).unref();
    }

    this.response.on('close', () => this.terminate());
    this.response.on('finish', () => this.terminate());
    this.response.on('error', () => this.terminate());
  }

  public send(payload: string): void {
    if (this.closed) {
      return;
    }
    if (this.paused) {
      this.queue.push(payload);
      return;
    }

    const ready = this.response.write(payload);
    if (!ready) {
      this.paused = true;
      this.response.once('drain', () => {
        this.paused = false;
        this.flush();
      });
    }
  }

  private sendRaw(payload: string): void {
    this.send(payload);
  }

  private flush(): void {
    if (this.closed || this.paused) {
      return;
    }
    while (this.queue.length > 0) {
      const next = this.queue.shift();
      const ready = this.response.write(next);
      if (!ready) {
        this.paused = true;
        this.response.once('drain', () => {
          this.paused = false;
          this.flush();
        });
        break;
      }
    }
  }

  public close(): void {
    if (this.closed) {
      return;
    }
    this.closed = true;
    if (this.heartbeat) {
      clearInterval(this.heartbeat);
    }
    try {
      this.response.end();
    } finally {
      this.onClose();
    }
  }

  private terminate(): void {
    if (this.closed) {
      return;
    }
    this.closed = true;
    if (this.heartbeat) {
      clearInterval(this.heartbeat);
    }
    this.onClose();
  }
}

interface ConnectOptions {
  tenantId: string;
  actorTenantId: string;
  response: Response;
  request: Request;
  actorLabel?: string;
  heartbeatMs?: number;
}

interface PublishOptions {
  id?: string;
  emittedAt?: string;
}

export class ComplianceEventStream {
  private readonly connections = new Map<string, Set<SseConnection>>();

  private readonly defaultHeartbeatMs: number;

  constructor(options?: { heartbeatMs?: number }) {
    this.defaultHeartbeatMs = Math.max(5_000, options?.heartbeatMs ?? 30_000);
  }

  public connect(options: ConnectOptions): void {
    if (options.actorTenantId !== options.tenantId) {
      throw new EventAuthorizationError('Actor tenant does not match requested tenant.');
    }

    const socket = options.request.socket;
    socket.setTimeout?.(0);
    socket.setNoDelay?.(true);
    socket.setKeepAlive?.(true);

    const connection = new SseConnection(
      options.response,
      () => this.remove(options.tenantId, connection),
      options.heartbeatMs ?? this.defaultHeartbeatMs,
    );

    const clients = this.connections.get(options.tenantId) ?? new Set<SseConnection>();
    clients.add(connection);
    this.connections.set(options.tenantId, clients);

    connection.send(': ready\n\n');
  }

  public publish(event: ComplianceEvent, options: PublishOptions = {}): void {
    const clients = this.connections.get(event.tenantId);
    if (!clients || clients.size === 0) {
      return;
    }
    const enriched: ComplianceEvent = {
      ...event,
      emittedAt: event.emittedAt ?? options.emittedAt ?? new Date().toISOString(),
    } as ComplianceEvent;
    const message = formatSseMessage(enriched, options.id);
    clients.forEach((client) => client.send(message));
  }

  public publishRiskProfile(
    tenantId: string,
    profile: RiskProfile,
    options: PublishOptions & { contributions?: ComplianceRiskFactorContributions } = {},
  ): void {
    const contributions = options.contributions ?? {
      coverageDrift: 0,
      testFailures: 0,
      backlogSeverity: 0,
    };
    this.publish(
      {
        type: 'riskProfile',
        tenantId,
        profile,
        contributions,
        emittedAt: options.emittedAt,
      },
      options,
    );
  }

  public publishLedgerEntry(tenantId: string, entry: LedgerEntry, options: PublishOptions = {}): void {
    this.publish(
      {
        type: 'ledgerEntry',
        tenantId,
        entry,
        emittedAt: options.emittedAt,
      },
      options,
    );
  }

  public publishQueueState(tenantId: string, jobs: JobSummary[], options: PublishOptions = {}): void {
    const normalizedJobs = jobs.map((job) => ({
      id: job.id,
      kind: job.kind,
      status: job.status,
      hash: job.hash,
      createdAt: toIsoString(job.createdAt),
      updatedAt: toIsoString(job.updatedAt),
    }));
    const counts = jobs.reduce(
      (acc, job) => {
        acc[job.status] += 1;
        return acc;
      },
      { queued: 0, running: 0, completed: 0, failed: 0 } as Record<JobSummary['status'], number>,
    );
    this.publish(
      {
        type: 'queueState',
        tenantId,
        jobs: normalizedJobs,
        counts,
        emittedAt: options.emittedAt,
      },
      options,
    );
  }

  public publishManifestProof(
    tenantId: string,
    payload: { manifestId: string; jobId?: string; merkle?: ManifestMerkleSummary | null; files: ComplianceManifestProofEvent['files'] },
    options: PublishOptions = {},
  ): void {
    this.publish(
      {
        type: 'manifestProof',
        tenantId,
        manifestId: payload.manifestId,
        jobId: payload.jobId,
        merkle: payload.merkle ?? null,
        files: payload.files,
        emittedAt: options.emittedAt,
      },
      options,
    );
  }

  public closeAll(): void {
    for (const clients of this.connections.values()) {
      for (const client of clients) {
        client.close();
      }
    }
    this.connections.clear();
  }

  public getSubscriberCount(tenantId?: string): number {
    if (tenantId) {
      return this.connections.get(tenantId)?.size ?? 0;
    }
    let total = 0;
    this.connections.forEach((set) => {
      total += set.size;
    });
    return total;
  }

  private remove(tenantId: string, connection: SseConnection): void {
    const clients = this.connections.get(tenantId);
    if (!clients) {
      return;
    }
    clients.delete(connection);
    if (clients.size === 0) {
      this.connections.delete(tenantId);
    }
  }
}
