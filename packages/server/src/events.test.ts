import { Writable } from 'stream';

import type { Request, Response } from 'express';

import type { LedgerEntry } from '@soipack/core';
import type { RiskProfile } from '@soipack/engine';

import type { JobSummary } from './queue';
import { ComplianceEventStream, EventAuthorizationError } from './events';

class MockResponse extends Writable {
  public readonly headers = new Map<string, string>();

  public statusCode = 200;

  public readonly chunks: string[] = [];

  constructor() {
    super();
  }

  public setHeader(name: string, value: string): void {
    this.headers.set(name.toLowerCase(), value);
  }

  public writeHead(statusCode: number): void {
    this.statusCode = statusCode;
  }

  public flushHeaders(): void {}

  public override _write(
    chunk: unknown,
    _encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    const value = typeof chunk === 'string' ? chunk : Buffer.from(chunk as Buffer).toString('utf8');
    this.chunks.push(value);
    callback();
  }
}

const createMockRequest = (): Request => {
  const socket = {
    setTimeout: jest.fn(),
    setNoDelay: jest.fn(),
    setKeepAlive: jest.fn(),
  } as unknown;
  return { socket } as Request;
};

describe('ComplianceEventStream', () => {
  const tenantId = 'tenant-a';

  let stream: ComplianceEventStream;
  let response: MockResponse;
  let request: Request;

  beforeEach(() => {
    jest.useRealTimers();
    stream = new ComplianceEventStream({ heartbeatMs: 10_000 });
    response = new MockResponse();
    request = createMockRequest();
  });

  it('formats SSE messages with JSON payloads for each event type', () => {
    stream.connect({ tenantId, actorTenantId: tenantId, response: response as unknown as Response, request, heartbeatMs: 0 });

    const profile: RiskProfile = {
      score: 42,
      classification: 'moderate',
      breakdown: [
        { factor: 'coverage', contribution: 10, weight: 40, details: 'Coverage gaps detected' },
      ],
      missingSignals: [],
    };

    stream.publishRiskProfile(tenantId, profile, { id: 'risk-1', emittedAt: '2024-08-01T10:00:00Z' });

    const ledgerEntry: LedgerEntry = {
      index: 1,
      snapshotId: '20240101T000000Z-deadbeef',
      manifestDigest: 'a'.repeat(64),
      timestamp: '2024-08-01T09:50:00Z',
      evidence: [],
      merkleRoot: 'b'.repeat(64),
      previousRoot: 'c'.repeat(64),
      ledgerRoot: 'd'.repeat(64),
    };
    stream.publishLedgerEntry(tenantId, ledgerEntry);

    const jobs: JobSummary[] = [
      {
        id: 'job-1',
        kind: 'report',
        hash: 'hash1',
        status: 'queued',
        createdAt: new Date('2024-08-01T09:45:00Z'),
        updatedAt: new Date('2024-08-01T09:45:00Z'),
      },
    ];
    stream.publishQueueState(tenantId, jobs, { emittedAt: '2024-08-01T10:05:00Z' });

    const payloads = response.chunks.filter((chunk) => chunk.includes('event:'));
    expect(payloads).toHaveLength(3);

    const [riskChunk, ledgerChunk, queueChunk] = payloads;

    const parseData = (chunk: string) => {
      const json = chunk
        .split('\n')
        .filter((line) => line.startsWith('data: '))
        .map((line) => line.slice(6))
        .join('\n');
      return JSON.parse(json) as Record<string, unknown>;
    };

    const riskData = parseData(riskChunk);
    expect(riskData.type).toBe('riskProfile');
    expect(riskData.tenantId).toBe(tenantId);
    expect(riskData.profile).toMatchObject({ score: 42, classification: 'moderate' });

    const ledgerData = parseData(ledgerChunk);
    expect(ledgerData.type).toBe('ledgerEntry');
    expect(ledgerData.entry).toMatchObject({ ledgerRoot: ledgerEntry.ledgerRoot });

    const queueData = parseData(queueChunk);
    expect(queueData.type).toBe('queueState');
    expect(queueData.jobs).toHaveLength(1);
    expect(queueData.counts).toMatchObject({ queued: 1, running: 0, completed: 0, failed: 0 });
  });

  it('rejects subscriptions when tenant context does not match actor tenant', () => {
    expect(() =>
      stream.connect({
        tenantId,
        actorTenantId: 'tenant-b',
        response: response as unknown as Response,
        request,
        heartbeatMs: 0,
      }),
    ).toThrow(EventAuthorizationError);
  });

  it('cleans up connections when the client disconnects', () => {
    stream.connect({ tenantId, actorTenantId: tenantId, response: response as unknown as Response, request, heartbeatMs: 0 });
    expect(stream.getSubscriberCount(tenantId)).toBe(1);

    response.emit('close');

    expect(stream.getSubscriberCount(tenantId)).toBe(0);

    expect(() =>
      stream.publishQueueState(tenantId, [
        {
          id: 'job-2',
          kind: 'pack',
          hash: 'hash-2',
          status: 'completed',
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ]),
    ).not.toThrow();
  });
});
