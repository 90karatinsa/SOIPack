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

