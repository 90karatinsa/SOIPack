import { newDb } from 'pg-mem';

import type { Pool } from 'pg';

import { PostgresQueue } from './postgresQueue';
import type { PostgresQueueOptions } from './postgresQueue';

interface TestContext {
  pool: Pool;
  queue: PostgresQueue;
}

describe('PostgresQueue', () => {
  const createQueue = async (
    options: Partial<PostgresQueueOptions> = {},
  ): Promise<TestContext> => {
    const db = newDb();
    const { Pool: MemPool } = db.adapters.createPg();
    const pool = new MemPool();
    const queue = new PostgresQueue({
      pool,
      concurrency: options.concurrency ?? 1,
      createRunner: options.createRunner ?? (() => async () => undefined),
      retention: options.retention,
    });
    await queue.ready();
    return { pool, queue };
  };

  afterEach(async () => {
    jest.useRealTimers();
  });

  it('replays orphaned running jobs after restart', async () => {
    const { pool, queue } = await createQueue();
    await queue.close();

    await pool.query(
      `
        INSERT INTO queue_jobs (tenant_id, id, kind, hash, payload, status, created_at, updated_at, started_at, attempts)
        VALUES ('tenant-a', 'job-1', 'import', 'hash-1', '{}'::jsonb, 'running', NOW() - INTERVAL '5 minutes', NOW() - INTERVAL '5 minutes', NOW() - INTERVAL '5 minutes', 0)
      `,
    );

    const restarted = new PostgresQueue({
      pool,
      concurrency: 1,
      createRunner: () => async () => ({ ok: true }),
    });
    await restarted.ready();
    await restarted.waitForIdle();

    const job = await restarted.get<{ ok: boolean }>('tenant-a', 'job-1');
    expect(job?.status).toBe('completed');
    expect(job?.result).toEqual({ ok: true });

    await restarted.close();
  });

  it('processes tenants in parallel while serialising per-tenant jobs', async () => {
    const db = newDb();
    const { Pool: MemPool } = db.adapters.createPg();
    const pool = new MemPool();
    const starts: string[] = [];
    const completions = new Map<string, () => void>();
    const queue = new PostgresQueue({
      pool,
      concurrency: 2,
      createRunner: ({ tenantId, id }) => {
        return async () => {
          starts.push(`${tenantId}/${id}`);
          await new Promise<void>((resolve) => {
            completions.set(`${tenantId}/${id}`, resolve);
          });
          return `${tenantId}-${id}`;
        };
      },
    });
    await queue.ready();

    await queue.enqueue({ tenantId: 'tenant-a', id: 'job-1', kind: 'import', hash: 'h1' });
    await queue.enqueue({ tenantId: 'tenant-a', id: 'job-2', kind: 'import', hash: 'h2' });
    await queue.enqueue({ tenantId: 'tenant-b', id: 'job-3', kind: 'import', hash: 'h3' });

    await waitUntil(() => starts.length >= 2);
    expect(starts).toEqual(['tenant-a/job-1', 'tenant-b/job-3']);

    completions.get('tenant-a/job-1')?.();
    completions.get('tenant-b/job-3')?.();

    await waitUntil(() => starts.length === 3);
    expect(starts[2]).toBe('tenant-a/job-2');

    completions.get('tenant-a/job-2')?.();

    await queue.waitForIdle();
    await queue.close();
  });

  it('purges completed and failed jobs according to retention settings', async () => {
    const { pool, queue } = await createQueue({
      retention: { completedMs: 0, failedMs: 0, sweepIntervalMs: 0 },
      createRunner: ({ id }) => {
        if (id === 'success') {
          return async () => 'ok';
        }
        return async () => {
          throw new Error('boom');
        };
      },
    });

    await queue.enqueue({ tenantId: 'tenant-ret', id: 'success', kind: 'import', hash: 'hs' });
    await queue.waitForIdle();
    await queue.enqueue({ tenantId: 'tenant-ret', id: 'failure', kind: 'import', hash: 'hf' });
    await queue.waitForIdle();

    const before = await pool.query("SELECT id, status FROM queue_jobs ORDER BY id");
    expect(before.rows).toHaveLength(2);

    await queue.sweepRetention();

    const after = await pool.query('SELECT id FROM queue_jobs');
    expect(after.rows).toHaveLength(0);

    await queue.close();
  });
});

async function waitUntil(predicate: () => boolean, timeoutMs = 1000): Promise<void> {
  const start = Date.now();
  while (true) {
    if (predicate()) {
      return;
    }
    if (Date.now() - start > timeoutMs) {
      throw new Error('Timed out waiting for condition.');
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}
