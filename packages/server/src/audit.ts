import { randomUUID } from 'crypto';

import type { DatabaseManager } from './database';

export interface AuditLogEntry {
  id: string;
  tenantId: string;
  actor: string;
  action: string;
  target?: string;
  payload?: unknown;
  createdAt: Date;
}

export interface AppendAuditLogInput {
  id?: string;
  tenantId: string;
  actor: string;
  action: string;
  target?: string;
  payload?: unknown;
  createdAt?: Date | string;
}

export interface AuditLogQueryOptions {
  tenantId: string;
  actor?: string;
  action?: string;
  target?: string;
  since?: Date | string;
  until?: Date | string;
  limit?: number;
  offset?: number;
  order?: 'asc' | 'desc';
}

export interface AuditLogQueryResult {
  items: AuditLogEntry[];
  hasMore: boolean;
  nextOffset?: number;
}

const DEFAULT_PAGE_SIZE = 50;
const MAX_PAGE_SIZE = 200;

type AuditLogRow = {
  id: unknown;
  tenant_id: unknown;
  actor: unknown;
  action: unknown;
  metadata?: unknown;
  created_at: unknown;
};

type ParsedMetadata = {
  target?: string;
  payload?: unknown;
};

export class AuditLogStore {
  constructor(private readonly database: DatabaseManager) {}

  private get pool() {
    return this.database.getPool();
  }

  private parseDate(value: unknown): Date {
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
  }

  private normalizeDate(value?: Date | string): Date {
    if (!value) {
      return new Date();
    }
    if (value instanceof Date) {
      return value;
    }
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? new Date() : parsed;
  }

  private parseMetadata(value: unknown): ParsedMetadata {
    if (value === null || value === undefined) {
      return {};
    }
    if (typeof value === 'string') {
      try {
        const parsed = JSON.parse(value) as ParsedMetadata;
        return parsed ?? {};
      } catch {
        return {};
      }
    }
    if (typeof value === 'object') {
      return value as ParsedMetadata;
    }
    return {};
  }

  private serializeMetadata(target?: string, payload?: unknown): string {
    const metadata: Record<string, unknown> = {};
    if (target !== undefined) {
      metadata.target = target;
    }
    if (payload !== undefined) {
      metadata.payload = payload;
    }
    return JSON.stringify(metadata);
  }

  private fromRow(row: AuditLogRow): AuditLogEntry {
    const metadata = this.parseMetadata(row.metadata);
    const target = typeof metadata.target === 'string' ? metadata.target : undefined;
    return {
      id: String(row.id),
      tenantId: String(row.tenant_id),
      actor: String(row.actor),
      action: String(row.action),
      target,
      payload: metadata.payload,
      createdAt: this.parseDate(row.created_at),
    };
  }

  public async append(input: AppendAuditLogInput): Promise<AuditLogEntry> {
    const id = input.id ?? randomUUID();
    const createdAt = this.normalizeDate(input.createdAt);
    const serializedMetadata = this.serializeMetadata(input.target, input.payload);

    const { rows } = await this.pool.query(
      `INSERT INTO audit_logs (id, tenant_id, actor, action, metadata, created_at)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (id) DO UPDATE SET
         tenant_id = EXCLUDED.tenant_id,
         actor = EXCLUDED.actor,
         action = EXCLUDED.action,
         metadata = EXCLUDED.metadata,
         created_at = EXCLUDED.created_at
       RETURNING id, tenant_id, actor, action, metadata, created_at`,
      [id, input.tenantId, input.actor, input.action, serializedMetadata, createdAt],
    );

    return this.fromRow(rows[0] as AuditLogRow);
  }

  public async query(options: AuditLogQueryOptions): Promise<AuditLogQueryResult> {
    const conditions: string[] = ['tenant_id = $1'];
    const params: unknown[] = [options.tenantId];

    if (options.actor) {
      params.push(options.actor);
      conditions.push(`actor = $${params.length}`);
    }
    if (options.action) {
      params.push(options.action);
      conditions.push(`action = $${params.length}`);
    }
    if (options.target) {
      params.push(options.target);
      conditions.push(`metadata ->> 'target' = $${params.length}`);
    }
    if (options.since) {
      params.push(this.normalizeDate(options.since));
      conditions.push(`created_at >= $${params.length}`);
    }
    if (options.until) {
      params.push(this.normalizeDate(options.until));
      conditions.push(`created_at <= $${params.length}`);
    }

    const orderDirection = options.order === 'asc' ? 'ASC' : 'DESC';
    const limit = Math.min(MAX_PAGE_SIZE, Math.max(1, options.limit ?? DEFAULT_PAGE_SIZE));
    const offset = Math.max(0, options.offset ?? 0);

    params.push(limit + 1);
    const limitPlaceholder = `$${params.length}`;
    params.push(offset);
    const offsetPlaceholder = `$${params.length}`;

    const query = `
      SELECT id, tenant_id, actor, action, metadata, created_at
      FROM audit_logs
      WHERE ${conditions.join(' AND ')}
      ORDER BY created_at ${orderDirection}, id ${orderDirection}
      LIMIT ${limitPlaceholder}
      OFFSET ${offsetPlaceholder}
    `;

    const { rows } = await this.pool.query(query, params);
    const hasMore = rows.length > limit;
    const items = rows.slice(0, limit).map((row) => this.fromRow(row as AuditLogRow));

    return {
      items,
      hasMore,
      nextOffset: hasMore ? offset + limit : undefined,
    };
  }
}
