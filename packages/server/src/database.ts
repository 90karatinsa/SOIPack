import type { Pool } from 'pg';
import { Pool as DefaultPool } from 'pg';

export type PoolFactory = (connectionString: string) => Pool;

interface MigrationStep {
  readonly description: string;
  readonly createSql: string;
  readonly checkSql?: string;
  readonly checkParams?: readonly unknown[];
}

const MIGRATION_STEPS: MigrationStep[] = [
  {
    description: 'jobs table',
    checkSql:
      "SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1",
    checkParams: ['jobs'],
    createSql: `CREATE TABLE jobs (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      kind TEXT NOT NULL,
      status TEXT NOT NULL,
      hash TEXT,
      payload JSONB,
      result JSONB,
      error JSONB,
      created_at TIMESTAMP NOT NULL,
      updated_at TIMESTAMP NOT NULL
    )`,
  },
  {
    description: 'jobs hash column',
    createSql: 'ALTER TABLE jobs ADD COLUMN IF NOT EXISTS hash TEXT',
  },
  {
    description: 'jobs tenant+status index',
    checkParams: ['jobs_tenant_status_idx'],
    createSql: 'CREATE INDEX jobs_tenant_status_idx ON jobs (tenant_id, status, created_at DESC)',
  },
  {
    description: 'pipeline_jobs table',
    checkSql:
      "SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1",
    checkParams: ['pipeline_jobs'],
    createSql: `CREATE TABLE pipeline_jobs (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      checksum TEXT NOT NULL,
      data JSONB,
      created_at TIMESTAMP NOT NULL,
      updated_at TIMESTAMP NOT NULL,
      deleted_at TIMESTAMP
    )`,
  },
  {
    description: 'pipeline_jobs tenant index',
    checkParams: ['pipeline_jobs_tenant_idx'],
    createSql: 'CREATE INDEX pipeline_jobs_tenant_idx ON pipeline_jobs (tenant_id, created_at DESC)',
  },
  {
    description: 'pipeline_artifacts table',
    checkSql:
      "SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1",
    checkParams: ['pipeline_artifacts'],
    createSql: `CREATE TABLE pipeline_artifacts (
      id TEXT PRIMARY KEY,
      job_id TEXT NOT NULL,
      tenant_id TEXT NOT NULL,
      checksum TEXT NOT NULL,
      data JSONB,
      created_at TIMESTAMP NOT NULL,
      updated_at TIMESTAMP NOT NULL,
      deleted_at TIMESTAMP
    )`,
  },
  {
    description: 'pipeline_artifacts job index',
    checkParams: ['pipeline_artifacts_job_idx'],
    createSql: 'CREATE INDEX pipeline_artifacts_job_idx ON pipeline_artifacts (job_id)',
  },
  {
    description: 'pipeline_artifacts tenant index',
    checkParams: ['pipeline_artifacts_tenant_idx'],
    createSql:
      'CREATE INDEX pipeline_artifacts_tenant_idx ON pipeline_artifacts (tenant_id, created_at DESC)',
  },
  {
    description: 'audit_events table',
    checkSql:
      "SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1",
    checkParams: ['audit_events'],
    createSql: `CREATE TABLE audit_events (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      checksum TEXT NOT NULL,
      payload JSONB,
      created_at TIMESTAMP NOT NULL,
      updated_at TIMESTAMP NOT NULL,
      deleted_at TIMESTAMP
    )`,
  },
  {
    description: 'audit_events tenant index',
    checkParams: ['audit_events_tenant_idx'],
    createSql: 'CREATE INDEX audit_events_tenant_idx ON audit_events (tenant_id, created_at DESC)',
  },
  {
    description: 'audit_logs table',
    checkSql:
      "SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1",
    checkParams: ['audit_logs'],
    createSql: `CREATE TABLE audit_logs (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      actor TEXT,
      action TEXT NOT NULL,
      metadata JSONB,
      created_at TIMESTAMP NOT NULL
    )`,
  },
  {
    description: 'audit_logs tenant index',
    checkParams: ['audit_logs_tenant_idx'],
    createSql: 'CREATE INDEX audit_logs_tenant_idx ON audit_logs (tenant_id, created_at DESC)',
  },
  {
    description: 'reviews table',
    checkSql:
      "SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1",
    checkParams: ['reviews'],
    createSql: `CREATE TABLE reviews (
      id TEXT PRIMARY KEY,
      job_id TEXT NOT NULL,
      tenant_id TEXT NOT NULL,
      reviewer TEXT,
      decision TEXT,
      notes TEXT,
      metadata JSONB,
      created_at TIMESTAMP NOT NULL,
      updated_at TIMESTAMP NOT NULL
    )`,
  },
  {
    description: 'reviews job index',
    checkParams: ['reviews_job_idx'],
    createSql: 'CREATE INDEX reviews_job_idx ON reviews (job_id)',
  },
  {
    description: 'reviews tenant index',
    checkParams: ['reviews_tenant_idx'],
    createSql: 'CREATE INDEX reviews_tenant_idx ON reviews (tenant_id, created_at DESC)',
  },
  {
    description: 'evidence table',
    checkSql:
      "SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1",
    checkParams: ['evidence'],
    createSql: `CREATE TABLE evidence (
      id TEXT PRIMARY KEY,
      review_id TEXT NOT NULL,
      tenant_id TEXT NOT NULL,
      filename TEXT NOT NULL,
      sha256 TEXT NOT NULL,
      size_bytes BIGINT NOT NULL,
      metadata JSONB,
      created_at TIMESTAMP NOT NULL
    )`,
  },
  {
    description: 'evidence review index',
    checkParams: ['evidence_review_idx'],
    createSql: 'CREATE INDEX evidence_review_idx ON evidence (review_id)',
  },
  {
    description: 'evidence tenant index',
    checkParams: ['evidence_tenant_idx'],
    createSql: 'CREATE INDEX evidence_tenant_idx ON evidence (tenant_id, created_at DESC)',
  },
];

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
      for (const step of MIGRATION_STEPS) {
        let shouldCreate = true;
        if (step.checkSql) {
          try {
            const result = await client.query(step.checkSql, Array.from(step.checkParams ?? []));
            shouldCreate = result.rowCount === 0;
          } catch {
            shouldCreate = true;
          }
        }
        if (!shouldCreate) {
          continue;
        }
        try {
          await client.query(step.createSql);
        } catch (error) {
          if (!this.isAlreadyExistsError(error)) {
            throw error;
          }
        }
      }
    } finally {
      client.release();
    }
  }

  private isAlreadyExistsError(error: unknown): boolean {
    if (error && typeof error === 'object') {
      const code = (error as { code?: unknown }).code;
      if (code === '42P07') {
        return true;
      }
    }
    if (error instanceof Error) {
      const message = error.message.toLowerCase();
      return message.includes('already exists');
    }
    return false;
  }
}
