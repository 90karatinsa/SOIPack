import { newDb } from 'pg-mem';

import { DatabaseManager } from './database';

describe('DatabaseManager', () => {
  const createManager = () => {
    const mem = newDb();
    const { Pool } = mem.adapters.createPg();
    let createdPool: InstanceType<typeof Pool> | undefined;
    const manager = new DatabaseManager('pg-mem', () => {
      createdPool = new Pool();
      return createdPool;
    });
    return { manager, getPool: () => createdPool! };
  };

  it('runs migrations idempotently', async () => {
    const { manager, getPool } = createManager();

    await manager.initialize();
    await manager.initialize();

    const pool = manager.getPool();
    expect(pool).toBe(getPool());

    const appliedMigrations = await pool.query('SELECT id, name FROM soipack_migrations ORDER BY id');
    expect(appliedMigrations.rows).toEqual([{ id: '001', name: 'init' }]);

    const { rows } = await pool.query(
      "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_name IN ('jobs','audit_logs','reviews','evidence','pipeline_jobs','pipeline_artifacts','audit_events') ORDER BY table_name",
    );
    const tableNames = rows.map((row: { table_name: string }) => row.table_name).sort();
    expect(tableNames).toEqual([
      'audit_events',
      'audit_logs',
      'evidence',
      'jobs',
      'pipeline_artifacts',
      'pipeline_jobs',
      'reviews',
    ]);

    await expect(pool.query('SELECT 1 FROM jobs')).resolves.toBeDefined();

    await pool.query(
      "INSERT INTO pipeline_jobs (id, tenant_id, checksum, data, created_at, updated_at) VALUES ('job-old', 'tenant-a', 'sum', '{}'::jsonb, NOW() - INTERVAL '45 days', NOW() - INTERVAL '45 days')",
    );
    await pool.query(
      "INSERT INTO pipeline_artifacts (id, job_id, tenant_id, checksum, data, created_at, updated_at) VALUES ('artifact-old', 'job-old', 'tenant-a', 'sum', '{}'::jsonb, NOW() - INTERVAL '40 days', NOW() - INTERVAL '40 days')",
    );
    await pool.query(
      "INSERT INTO audit_events (id, tenant_id, checksum, payload, created_at, updated_at) VALUES ('event-old', 'tenant-a', 'sum', '{}'::jsonb, NOW() - INTERVAL '50 days', NOW() - INTERVAL '50 days')",
    );

    const markResult = await pool.query(
      'SELECT * FROM soipack_mark_expired_pipeline_records($1, $2, $3)',
      [30, 30, 30],
    );
    expect(Number(markResult.rows[0].marked_jobs)).toBe(1);
    expect(Number(markResult.rows[0].marked_artifacts)).toBe(1);
    expect(Number(markResult.rows[0].marked_events)).toBe(1);

    const { rows: flagged } = await pool.query(
      "SELECT id, deleted_at FROM pipeline_jobs WHERE id = 'job-old'",
    );
    expect(flagged[0].deleted_at).not.toBeNull();

    const purgeResult = await pool.query(
      'SELECT * FROM soipack_purge_deleted_pipeline_records($1, $2, $3)',
      [0, 0, 0],
    );
    expect(Number(purgeResult.rows[0].deleted_jobs)).toBe(1);
    expect(Number(purgeResult.rows[0].deleted_artifacts)).toBeGreaterThanOrEqual(1);
    expect(Number(purgeResult.rows[0].deleted_events)).toBe(1);

    const remainingJobs = await pool.query('SELECT COUNT(*)::INT FROM pipeline_jobs');
    expect(remainingJobs.rows[0].count).toBe(0);

    await manager.close();
  });

  it('propagates errors when migrations fail', async () => {
    const mem = newDb();
    const { Pool } = mem.adapters.createPg();
    const failingPool = new Pool();
    const connectSpy = jest
      .spyOn(failingPool, 'connect')
      .mockRejectedValue(new Error('connection failed'));
    const endSpy = jest.spyOn(failingPool, 'end');

    const manager = new DatabaseManager('pg-mem', () => failingPool);

    await expect(manager.initialize()).rejects.toThrow('Veritabanı şeması güncellenemedi: connection failed');
    expect(connectSpy).toHaveBeenCalledTimes(1);
    expect(endSpy).toHaveBeenCalledTimes(1);
  });
});

