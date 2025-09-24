import fs from 'fs';
import path from 'path';

import type { Pool } from 'pg';
import { Pool as DefaultPool } from 'pg';

export type PoolFactory = (connectionString: string) => Pool;

interface SqlMigration {
  readonly id: string;
  readonly name: string;
  readonly sql: string;
}

const migrationsDirectory = path.resolve(__dirname, '../migrations');

function loadMigrations(): SqlMigration[] {
  let entries: string[] = [];
  try {
    entries = fs.readdirSync(migrationsDirectory);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return [];
    }
    throw error;
  }

  return entries
    .filter((fileName) => fileName.endsWith('.sql'))
    .sort()
    .map((fileName) => {
      const absolutePath = path.join(migrationsDirectory, fileName);
      const sql = fs.readFileSync(absolutePath, 'utf8');
      const baseName = fileName.replace(/\.sql$/u, '');
      const underscoreIndex = baseName.indexOf('_');
      const id = underscoreIndex >= 0 ? baseName.slice(0, underscoreIndex) : baseName;
      const name = underscoreIndex >= 0 ? baseName.slice(underscoreIndex + 1) : '';
      return { id, name, sql };
    });
}

const SQL_MIGRATIONS = loadMigrations();

export class DatabaseManager {
  private pool?: Pool;
  private readonly createPool: PoolFactory;

  constructor(private readonly connectionString: string, poolFactory?: PoolFactory) {
    if (!connectionString) {
      throw new Error('Veritabanı bağlantı dizesi tanımlanmalıdır.');
    }
    this.createPool = poolFactory ?? ((connection) => new DefaultPool({ connectionString: connection }));
  }

  static fromEnv(poolFactory?: PoolFactory): DatabaseManager {
    const connectionString = process.env.SOIPACK_DATABASE_URL;
    if (!connectionString) {
      throw new Error('SOIPACK_DATABASE_URL ortam değişkeni tanımlanmalıdır.');
    }
    return new DatabaseManager(connectionString, poolFactory);
  }

  async initialize(): Promise<void> {
    if (!this.pool) {
      this.pool = this.createPool(this.connectionString);
      this.patchPool(this.pool);
    }
    try {
      await this.runMigrations(this.pool);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      await this.close().catch(() => undefined);
      throw new Error(`Veritabanı şeması güncellenemedi: ${message}`);
    }
  }

  getPool(): Pool {
    if (!this.pool) {
      throw new Error('Veritabanı bağlantısı henüz başlatılmadı.');
    }
    return this.pool;
  }

  async close(): Promise<void> {
    if (!this.pool) {
      return;
    }
    const pool = this.pool;
    this.pool = undefined;
    await pool.end();
  }

  private async runMigrations(pool: Pool): Promise<void> {
    const client = await pool.connect();
    try {
      await client.query(`
        CREATE TABLE IF NOT EXISTS soipack_migrations (
          id TEXT,
          name TEXT,
          applied_at TIMESTAMP
        )
      `);

      for (const migration of SQL_MIGRATIONS) {
        const applied = await client.query('SELECT 1 FROM soipack_migrations WHERE id = $1', [migration.id]);
        if ((applied.rowCount ?? 0) > 0) {
          continue;
        }

        await client.query('BEGIN');
        try {
          if (migration.sql.trim()) {
            await client.query(migration.sql);
          }
          await client.query('INSERT INTO soipack_migrations (id, name, applied_at) VALUES ($1, $2, CURRENT_TIMESTAMP)', [
            migration.id,
            migration.name,
          ]);
          await client.query('COMMIT');
        } catch (error) {
          await client.query('ROLLBACK').catch(() => undefined);
          const message = error instanceof Error ? error.message : String(error);
          throw new Error(`Migration ${migration.id}_${migration.name} failed: ${message}`);
        }
      }
    } finally {
      client.release();
    }
  }

  private patchPool(pool: Pool): void {
    const marker = '__soipackPatchedQuery';
    if ((pool as unknown as Record<string, unknown>)[marker]) {
      return;
    }
    (pool as unknown as Record<string, unknown>)[marker] = true;
    const originalQuery = pool.query.bind(pool);
    const enhanceResult = (result: unknown): void => {
      if (!result || typeof result !== 'object') {
        return;
      }
      const rows = (result as { rows?: unknown[] }).rows;
      if (!Array.isArray(rows)) {
        return;
      }
      for (const row of rows) {
        if (row && typeof row === 'object' && 'int' in (row as Record<string, unknown>) && !('count' in (row as Record<string, unknown>))) {
          (row as Record<string, unknown>).count = (row as Record<string, unknown>).int;
        }
      }
    };
    const patchedQuery: typeof pool.query = ((...args: unknown[]) => {
      const last = args[args.length - 1];
      if (typeof last === 'function') {
        const callback = last as (err: unknown, result: unknown) => void;
        args[args.length - 1] = (error: unknown, result: unknown) => {
          if (!error) {
            enhanceResult(result);
          }
          callback(error, result);
        };
        return originalQuery(...(args as Parameters<typeof originalQuery>));
      }
      const queryResult = originalQuery(...(args as Parameters<typeof originalQuery>));
      const isPromiseLike = (value: unknown): value is PromiseLike<unknown> =>
        typeof value === 'object' && value !== null && typeof (value as { then?: unknown }).then === 'function';
      if (isPromiseLike(queryResult)) {
        return queryResult.then((result) => {
          enhanceResult(result);
          return result;
        });
      }
      return queryResult;
    }) as typeof pool.query;
    (pool as unknown as { query: typeof patchedQuery }).query = patchedQuery;
  }
}
