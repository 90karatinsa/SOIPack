import type { DatabaseManager } from '../database';

interface PipelineJobInput {
  id: string;
  tenantId: string;
  checksum: string;
  data?: unknown;
}

export interface PipelineJobRecord extends PipelineJobInput {
  createdAt: Date;
  updatedAt: Date;
  deletedAt: Date | null;
}

interface PipelineArtifactInput {
  id: string;
  jobId: string;
  tenantId: string;
  checksum: string;
  data?: unknown;
}

export interface PipelineArtifactRecord extends PipelineArtifactInput {
  createdAt: Date;
  updatedAt: Date;
  deletedAt: Date | null;
}

interface AuditEventInput {
  id: string;
  tenantId: string;
  checksum: string;
  payload?: unknown;
}

export interface AuditEventRecord extends AuditEventInput {
  createdAt: Date;
  updatedAt: Date;
  deletedAt: Date | null;
}

interface ListOptions {
  includeDeleted?: boolean;
}

interface ArtifactListOptions extends ListOptions {
  jobId?: string;
}

const parseJson = <T>(value: unknown): T | undefined => {
  if (value === null || value === undefined) {
    return undefined;
  }
  if (typeof value === 'string') {
    try {
      return JSON.parse(value) as T;
    } catch {
      return undefined;
    }
  }
  return value as T;
};

const parseDate = (value: unknown): Date => {
  if (value instanceof Date) {
    return value;
  }
  if (typeof value === 'string' || typeof value === 'number') {
    const parsed = new Date(value);
    if (!Number.isNaN(parsed.getTime())) {
      return parsed;
    }
  }
  return new Date();
};

const toNullableJson = (value: unknown): unknown =>
  value === undefined ? null : JSON.stringify(value);

export class PostgresStorageProvider {
  constructor(private readonly database: DatabaseManager) {}

  private get pool() {
    return this.database.getPool();
  }

  private toJobRecord(row: Record<string, unknown>): PipelineJobRecord {
    return {
      id: String(row.id),
      tenantId: String(row.tenant_id),
      checksum: String(row.checksum),
      data: parseJson(row.data),
      createdAt: parseDate(row.created_at),
      updatedAt: parseDate(row.updated_at),
      deletedAt: row.deleted_at ? parseDate(row.deleted_at) : null,
    };
  }

  private toArtifactRecord(row: Record<string, unknown>): PipelineArtifactRecord {
    return {
      id: String(row.id),
      jobId: String(row.job_id),
      tenantId: String(row.tenant_id),
      checksum: String(row.checksum),
      data: parseJson(row.data),
      createdAt: parseDate(row.created_at),
      updatedAt: parseDate(row.updated_at),
      deletedAt: row.deleted_at ? parseDate(row.deleted_at) : null,
    };
  }

  private toAuditRecord(row: Record<string, unknown>): AuditEventRecord {
    return {
      id: String(row.id),
      tenantId: String(row.tenant_id),
      checksum: String(row.checksum),
      payload: parseJson(row.payload),
      createdAt: parseDate(row.created_at),
      updatedAt: parseDate(row.updated_at),
      deletedAt: row.deleted_at ? parseDate(row.deleted_at) : null,
    };
  }

  public async createPipelineJob(input: PipelineJobInput): Promise<PipelineJobRecord> {
    const now = new Date().toISOString();
    const { rows } = await this.pool.query(
      `INSERT INTO pipeline_jobs (id, tenant_id, checksum, data, created_at, updated_at, deleted_at)
       VALUES ($1, $2, $3, $4, $5, $5, NULL)
       ON CONFLICT (id) DO UPDATE SET
         checksum = EXCLUDED.checksum,
         data = EXCLUDED.data,
         updated_at = EXCLUDED.updated_at,
         deleted_at = NULL
       RETURNING id, tenant_id, checksum, data, created_at, updated_at, deleted_at`,
      [input.id, input.tenantId, input.checksum, toNullableJson(input.data), now],
    );
    return this.toJobRecord(rows[0] as Record<string, unknown>);
  }

  public async getPipelineJob(tenantId: string, id: string): Promise<PipelineJobRecord | undefined> {
    const { rows } = await this.pool.query(
      `SELECT id, tenant_id, checksum, data, created_at, updated_at, deleted_at
       FROM pipeline_jobs
       WHERE id = $1 AND tenant_id = $2`,
      [id, tenantId],
    );
    if (rows.length === 0) {
      return undefined;
    }
    return this.toJobRecord(rows[0] as Record<string, unknown>);
  }

  public async listPipelineJobs(
    tenantId: string,
    options: ListOptions = {},
  ): Promise<PipelineJobRecord[]> {
    const conditions: string[] = ['tenant_id = $1'];
    const params: unknown[] = [tenantId];
    if (!options.includeDeleted) {
      conditions.push('deleted_at IS NULL');
    }
    const { rows } = await this.pool.query(
      `SELECT id, tenant_id, checksum, data, created_at, updated_at, deleted_at
       FROM pipeline_jobs
       WHERE ${conditions.join(' AND ')}
       ORDER BY created_at DESC`,
      params,
    );
    return rows.map((row) => this.toJobRecord(row as Record<string, unknown>));
  }

  public async updatePipelineJob(
    tenantId: string,
    id: string,
    patch: Partial<Omit<PipelineJobInput, 'id' | 'tenantId'>>,
  ): Promise<PipelineJobRecord> {
    const updates: string[] = [];
    const params: unknown[] = [];
    if (patch.checksum !== undefined) {
      updates.push(`checksum = $${updates.length + 1}`);
      params.push(patch.checksum);
    }
    if (patch.data !== undefined) {
      updates.push(`data = $${updates.length + 1}`);
      params.push(toNullableJson(patch.data));
    }
    const nowIso = new Date().toISOString();
    updates.push(`updated_at = $${updates.length + 1}`);
    params.push(nowIso);
    params.push(id, tenantId);
    const { rows } = await this.pool.query(
      `UPDATE pipeline_jobs
       SET ${updates.join(', ')}
       WHERE id = $${updates.length + 1} AND tenant_id = $${updates.length + 2}
       RETURNING id, tenant_id, checksum, data, created_at, updated_at, deleted_at`,
      params,
    );
    if (rows.length === 0) {
      throw new Error('Pipeline job not found');
    }
    return this.toJobRecord(rows[0] as Record<string, unknown>);
  }

  public async softDeletePipelineJob(tenantId: string, id: string): Promise<void> {
    const nowIso = new Date().toISOString();
    await this.pool.query(
      `UPDATE pipeline_jobs
       SET deleted_at = $1, updated_at = $1
       WHERE id = $2 AND tenant_id = $3`,
      [nowIso, id, tenantId],
    );
  }

  public async createPipelineArtifact(
    input: PipelineArtifactInput,
  ): Promise<PipelineArtifactRecord> {
    const now = new Date().toISOString();
    const { rows } = await this.pool.query(
      `INSERT INTO pipeline_artifacts (id, job_id, tenant_id, checksum, data, created_at, updated_at, deleted_at)
       VALUES ($1, $2, $3, $4, $5, $6, $6, NULL)
       ON CONFLICT (id) DO UPDATE SET
         checksum = EXCLUDED.checksum,
         data = EXCLUDED.data,
         updated_at = EXCLUDED.updated_at,
         deleted_at = NULL
       RETURNING id, job_id, tenant_id, checksum, data, created_at, updated_at, deleted_at`,
      [input.id, input.jobId, input.tenantId, input.checksum, toNullableJson(input.data), now],
    );
    return this.toArtifactRecord(rows[0] as Record<string, unknown>);
  }

  public async getPipelineArtifact(
    tenantId: string,
    id: string,
  ): Promise<PipelineArtifactRecord | undefined> {
    const { rows } = await this.pool.query(
      `SELECT id, job_id, tenant_id, checksum, data, created_at, updated_at, deleted_at
       FROM pipeline_artifacts
       WHERE id = $1 AND tenant_id = $2`,
      [id, tenantId],
    );
    if (rows.length === 0) {
      return undefined;
    }
    return this.toArtifactRecord(rows[0] as Record<string, unknown>);
  }

  public async listPipelineArtifacts(
    tenantId: string,
    options: ArtifactListOptions = {},
  ): Promise<PipelineArtifactRecord[]> {
    const conditions: string[] = ['tenant_id = $1'];
    const params: unknown[] = [tenantId];
    if (!options.includeDeleted) {
      conditions.push('deleted_at IS NULL');
    }
    if (options.jobId) {
      conditions.push(`job_id = $${params.length + 1}`);
      params.push(options.jobId);
    }
    const { rows } = await this.pool.query(
      `SELECT id, job_id, tenant_id, checksum, data, created_at, updated_at, deleted_at
       FROM pipeline_artifacts
       WHERE ${conditions.join(' AND ')}
       ORDER BY created_at DESC`,
      params,
    );
    return rows.map((row) => this.toArtifactRecord(row as Record<string, unknown>));
  }

  public async updatePipelineArtifact(
    tenantId: string,
    id: string,
    patch: Partial<Omit<PipelineArtifactInput, 'id' | 'tenantId' | 'jobId'>>,
  ): Promise<PipelineArtifactRecord> {
    const updates: string[] = [];
    const params: unknown[] = [];
    if (patch.checksum !== undefined) {
      updates.push(`checksum = $${updates.length + 1}`);
      params.push(patch.checksum);
    }
    if (patch.data !== undefined) {
      updates.push(`data = $${updates.length + 1}`);
      params.push(toNullableJson(patch.data));
    }
    const nowIso = new Date().toISOString();
    updates.push(`updated_at = $${updates.length + 1}`);
    params.push(nowIso);
    params.push(id, tenantId);
    const { rows } = await this.pool.query(
      `UPDATE pipeline_artifacts
       SET ${updates.join(', ')}
       WHERE id = $${updates.length + 1} AND tenant_id = $${updates.length + 2}
       RETURNING id, job_id, tenant_id, checksum, data, created_at, updated_at, deleted_at`,
      params,
    );
    if (rows.length === 0) {
      throw new Error('Pipeline artifact not found');
    }
    return this.toArtifactRecord(rows[0] as Record<string, unknown>);
  }

  public async softDeletePipelineArtifact(tenantId: string, id: string): Promise<void> {
    const nowIso = new Date().toISOString();
    await this.pool.query(
      `UPDATE pipeline_artifacts
       SET deleted_at = $1, updated_at = $1
       WHERE id = $2 AND tenant_id = $3`,
      [nowIso, id, tenantId],
    );
  }

  public async createAuditEvent(input: AuditEventInput): Promise<AuditEventRecord> {
    const now = new Date().toISOString();
    const { rows } = await this.pool.query(
      `INSERT INTO audit_events (id, tenant_id, checksum, payload, created_at, updated_at, deleted_at)
       VALUES ($1, $2, $3, $4, $5, $5, NULL)
       ON CONFLICT (id) DO UPDATE SET
         checksum = EXCLUDED.checksum,
         payload = EXCLUDED.payload,
         updated_at = EXCLUDED.updated_at,
         deleted_at = NULL
       RETURNING id, tenant_id, checksum, payload, created_at, updated_at, deleted_at`,
      [input.id, input.tenantId, input.checksum, toNullableJson(input.payload), now],
    );
    return this.toAuditRecord(rows[0] as Record<string, unknown>);
  }

  public async getAuditEvent(
    tenantId: string,
    id: string,
  ): Promise<AuditEventRecord | undefined> {
    const { rows } = await this.pool.query(
      `SELECT id, tenant_id, checksum, payload, created_at, updated_at, deleted_at
       FROM audit_events
       WHERE id = $1 AND tenant_id = $2`,
      [id, tenantId],
    );
    if (rows.length === 0) {
      return undefined;
    }
    return this.toAuditRecord(rows[0] as Record<string, unknown>);
  }

  public async listAuditEvents(
    tenantId: string,
    options: ListOptions = {},
  ): Promise<AuditEventRecord[]> {
    const conditions: string[] = ['tenant_id = $1'];
    const params: unknown[] = [tenantId];
    if (!options.includeDeleted) {
      conditions.push('deleted_at IS NULL');
    }
    const { rows } = await this.pool.query(
      `SELECT id, tenant_id, checksum, payload, created_at, updated_at, deleted_at
       FROM audit_events
       WHERE ${conditions.join(' AND ')}
       ORDER BY created_at DESC`,
      params,
    );
    return rows.map((row) => this.toAuditRecord(row as Record<string, unknown>));
  }

  public async updateAuditEvent(
    tenantId: string,
    id: string,
    patch: Partial<Omit<AuditEventInput, 'id' | 'tenantId'>>,
  ): Promise<AuditEventRecord> {
    const updates: string[] = [];
    const params: unknown[] = [];
    if (patch.checksum !== undefined) {
      updates.push(`checksum = $${updates.length + 1}`);
      params.push(patch.checksum);
    }
    if (patch.payload !== undefined) {
      updates.push(`payload = $${updates.length + 1}`);
      params.push(toNullableJson(patch.payload));
    }
    const nowIso = new Date().toISOString();
    updates.push(`updated_at = $${updates.length + 1}`);
    params.push(nowIso);
    params.push(id, tenantId);
    const { rows } = await this.pool.query(
      `UPDATE audit_events
       SET ${updates.join(', ')}
       WHERE id = $${updates.length + 1} AND tenant_id = $${updates.length + 2}
       RETURNING id, tenant_id, checksum, payload, created_at, updated_at, deleted_at`,
      params,
    );
    if (rows.length === 0) {
      throw new Error('Audit event not found');
    }
    return this.toAuditRecord(rows[0] as Record<string, unknown>);
  }

  public async softDeleteAuditEvent(tenantId: string, id: string): Promise<void> {
    const nowIso = new Date().toISOString();
    await this.pool.query(
      `UPDATE audit_events
       SET deleted_at = $1, updated_at = $1
       WHERE id = $2 AND tenant_id = $3`,
      [nowIso, id, tenantId],
    );
  }
}
