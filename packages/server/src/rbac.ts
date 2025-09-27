import { createHash, pbkdf2, randomBytes, randomUUID, timingSafeEqual } from 'crypto';
import { promisify } from 'util';

import type { DatabaseManager } from './database';

const pbkdf2Async = promisify(pbkdf2);
const SECRET_ITERATIONS = 210_000;
const SECRET_LENGTH = 64;
const SECRET_DIGEST = 'sha512';

const formatSecretHash = (iterations: number, salt: Buffer, derived: Buffer): string =>
  `pbkdf2$${iterations}$${salt.toString('hex')}$${derived.toString('hex')}`;

const hashSecret = async (secret: string, iterations = SECRET_ITERATIONS): Promise<string> => {
  const salt = randomBytes(16);
  const derived = await pbkdf2Async(secret, salt, iterations, SECRET_LENGTH, SECRET_DIGEST);
  return formatSecretHash(iterations, salt, derived);
};

const verifySecret = async (secret: string, encoded: string): Promise<boolean> => {
  const parts = encoded.split('$');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2') {
    return false;
  }
  const iterations = Number.parseInt(parts[1], 10);
  if (!Number.isFinite(iterations) || iterations <= 0) {
    return false;
  }
  const salt = Buffer.from(parts[2], 'hex');
  const expected = Buffer.from(parts[3], 'hex');
  const derived = await pbkdf2Async(secret, salt, iterations, expected.length, SECRET_DIGEST);
  return timingSafeEqual(derived, expected);
};

const fingerprintSecret = (secret: string): string =>
  createHash('sha256').update(secret, 'utf8').digest('hex');

const toDate = (value: unknown): Date => {
  if (value instanceof Date) {
    return value;
  }
  if (typeof value === 'string' || typeof value === 'number') {
    const parsed = new Date(value);
    if (!Number.isNaN(parsed.getTime())) {
      return parsed;
    }
  }
  return new Date(0);
};

export interface RbacUser {
  id: string;
  tenantId: string;
  email: string;
  displayName?: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface CreateUserInput {
  tenantId: string;
  email: string;
  secret: string;
  displayName?: string | null;
  id?: string;
}

export interface RbacRole {
  id: string;
  tenantId: string;
  name: string;
  description?: string | null;
  createdAt: Date;
}

export interface CreateRoleInput {
  tenantId: string;
  name: string;
  description?: string | null;
  id?: string;
}

export interface RbacApiKey {
  id: string;
  tenantId: string;
  label?: string | null;
  fingerprint: string;
  createdAt: Date;
  lastUsedAt?: Date | null;
}

export interface CreateApiKeyInput {
  tenantId: string;
  secret: string;
  label?: string | null;
  id?: string;
}

export interface RbacGroup {
  id: string;
  tenantId: string;
  name: string;
  description?: string | null;
  createdAt: Date;
}

export interface CreateGroupInput {
  tenantId: string;
  name: string;
  description?: string | null;
  id?: string;
}

export interface RbacGroupMember {
  tenantId: string;
  groupId: string;
  userId: string;
  assignedAt: Date;
}

export class RbacStore {
  constructor(private readonly database: DatabaseManager) {}

  private get pool() {
    return this.database.getPool();
  }

  private mapUser(row: Record<string, unknown>): RbacUser {
    return {
      id: String(row.id),
      tenantId: String(row.tenant_id),
      email: String(row.email),
      displayName: row.display_name as string | null | undefined,
      createdAt: toDate(row.created_at),
      updatedAt: toDate(row.updated_at),
    };
  }

  private mapRole(row: Record<string, unknown>): RbacRole {
    return {
      id: String(row.id),
      tenantId: String(row.tenant_id),
      name: String(row.name),
      description: row.description as string | null | undefined,
      createdAt: toDate(row.created_at),
    };
  }

  private mapApiKey(row: Record<string, unknown>): RbacApiKey {
    return {
      id: String(row.id),
      tenantId: String(row.tenant_id),
      label: row.label as string | null | undefined,
      fingerprint: String(row.fingerprint),
      createdAt: toDate(row.created_at),
      lastUsedAt: row.last_used_at ? toDate(row.last_used_at) : null,
    };
  }

  private mapGroup(row: Record<string, unknown>): RbacGroup {
    return {
      id: String(row.id),
      tenantId: String(row.tenant_id),
      name: String(row.name),
      description: row.description as string | null | undefined,
      createdAt: toDate(row.created_at),
    };
  }

  private mapGroupMember(row: Record<string, unknown>): RbacGroupMember {
    return {
      tenantId: String(row.tenant_id),
      groupId: String(row.group_id),
      userId: String(row.user_id),
      assignedAt: toDate(row.assigned_at),
    };
  }

  public async createUser(input: CreateUserInput): Promise<RbacUser> {
    const id = input.id ?? randomUUID();
    const now = new Date().toISOString();
    const secretHash = await hashSecret(input.secret);
    const { rows } = await this.pool.query(
      `INSERT INTO rbac_users (id, tenant_id, email, display_name, secret_hash, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $6)
       ON CONFLICT (id) DO UPDATE SET
         email = EXCLUDED.email,
         display_name = EXCLUDED.display_name,
         secret_hash = EXCLUDED.secret_hash,
         updated_at = EXCLUDED.updated_at
       RETURNING id, tenant_id, email, display_name, created_at, updated_at`,
      [id, input.tenantId, input.email, input.displayName ?? null, secretHash, now],
    );
    return this.mapUser(rows[0] as Record<string, unknown>);
  }

  public async getUser(tenantId: string, userId: string): Promise<RbacUser | undefined> {
    const { rows } = await this.pool.query(
      `SELECT id, tenant_id, email, display_name, created_at, updated_at
         FROM rbac_users
        WHERE tenant_id = $1 AND id = $2
        LIMIT 1`,
      [tenantId, userId],
    );
    if (!rows[0]) {
      return undefined;
    }
    return this.mapUser(rows[0] as Record<string, unknown>);
  }

  public async listUsers(tenantId: string): Promise<RbacUser[]> {
    const { rows } = await this.pool.query(
      `SELECT id, tenant_id, email, display_name, created_at, updated_at
         FROM rbac_users
        WHERE tenant_id = $1
        ORDER BY created_at ASC`,
      [tenantId],
    );
    return rows.map((row: unknown) => this.mapUser(row as Record<string, unknown>));
  }

  public async updateUserSecret(tenantId: string, userId: string, secret: string): Promise<void> {
    const secretHash = await hashSecret(secret);
    await this.pool.query(
      `UPDATE rbac_users
          SET secret_hash = $1, updated_at = $2
        WHERE tenant_id = $3 AND id = $4`,
      [secretHash, new Date().toISOString(), tenantId, userId],
    );
  }

  public async verifyUserSecret(tenantId: string, userId: string, secret: string): Promise<boolean> {
    const { rows } = await this.pool.query(
      `SELECT secret_hash FROM rbac_users WHERE tenant_id = $1 AND id = $2 LIMIT 1`,
      [tenantId, userId],
    );
    if (!rows[0]) {
      return false;
    }
    return verifySecret(secret, String((rows[0] as Record<string, unknown>).secret_hash));
  }

  public async deleteUser(tenantId: string, userId: string): Promise<void> {
    await this.pool.query(`DELETE FROM rbac_users WHERE tenant_id = $1 AND id = $2`, [tenantId, userId]);
  }

  public async createRole(input: CreateRoleInput): Promise<RbacRole> {
    const id = input.id ?? randomUUID();
    const now = new Date().toISOString();
    const { rows } = await this.pool.query(
      `INSERT INTO rbac_roles (id, tenant_id, name, description, created_at)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (id) DO UPDATE SET
         name = EXCLUDED.name,
         description = EXCLUDED.description
       RETURNING id, tenant_id, name, description, created_at`,
      [id, input.tenantId, input.name, input.description ?? null, now],
    );
    return this.mapRole(rows[0] as Record<string, unknown>);
  }

  public async listRoles(tenantId: string): Promise<RbacRole[]> {
    const { rows } = await this.pool.query(
      `SELECT id, tenant_id, name, description, created_at
         FROM rbac_roles
        WHERE tenant_id = $1
        ORDER BY created_at ASC`,
      [tenantId],
    );
    return rows.map((row: unknown) => this.mapRole(row as Record<string, unknown>));
  }

  public async assignRole(tenantId: string, userId: string, roleId: string): Promise<void> {
    await this.pool.query(
      `INSERT INTO rbac_user_roles (tenant_id, user_id, role_id, assigned_at)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (tenant_id, user_id, role_id) DO NOTHING`,
      [tenantId, userId, roleId, new Date().toISOString()],
    );
  }

  public async listUserRoles(tenantId: string, userId: string): Promise<RbacRole[]> {
    const { rows } = await this.pool.query(
      `SELECT r.id, r.tenant_id, r.name, r.description, r.created_at
         FROM rbac_roles r
         JOIN rbac_user_roles ur ON ur.role_id = r.id AND ur.tenant_id = r.tenant_id
        WHERE ur.tenant_id = $1 AND ur.user_id = $2
        ORDER BY r.created_at ASC`,
      [tenantId, userId],
    );
    return rows.map((row: unknown) => this.mapRole(row as Record<string, unknown>));
  }

  public async revokeRole(tenantId: string, userId: string, roleId: string): Promise<void> {
    await this.pool.query(
      `DELETE FROM rbac_user_roles
        WHERE tenant_id = $1 AND user_id = $2 AND role_id = $3`,
      [tenantId, userId, roleId],
    );
  }

  public async createApiKey(input: CreateApiKeyInput): Promise<RbacApiKey> {
    const id = input.id ?? randomUUID();
    const fingerprint = fingerprintSecret(input.secret);
    const secretHash = await hashSecret(input.secret);
    const now = new Date().toISOString();
    const { rows } = await this.pool.query(
      `INSERT INTO rbac_api_keys (id, tenant_id, label, secret_hash, fingerprint, created_at, last_used_at)
       VALUES ($1, $2, $3, $4, $5, $6, NULL)
       ON CONFLICT (id) DO UPDATE SET
         label = EXCLUDED.label,
         secret_hash = EXCLUDED.secret_hash,
         fingerprint = EXCLUDED.fingerprint
       RETURNING id, tenant_id, label, fingerprint, created_at, last_used_at`,
      [id, input.tenantId, input.label ?? null, secretHash, fingerprint, now],
    );
    return this.mapApiKey(rows[0] as Record<string, unknown>);
  }

  public async listApiKeys(tenantId: string): Promise<RbacApiKey[]> {
    const { rows } = await this.pool.query(
      `SELECT id, tenant_id, label, fingerprint, created_at, last_used_at
         FROM rbac_api_keys
        WHERE tenant_id = $1
        ORDER BY created_at ASC`,
      [tenantId],
    );
    return rows.map((row: unknown) => this.mapApiKey(row as Record<string, unknown>));
  }

  public async verifyApiKeySecret(tenantId: string, keyId: string, secret: string): Promise<boolean> {
    const { rows } = await this.pool.query(
      `SELECT secret_hash FROM rbac_api_keys WHERE tenant_id = $1 AND id = $2 LIMIT 1`,
      [tenantId, keyId],
    );
    if (!rows[0]) {
      return false;
    }
    return verifySecret(secret, String((rows[0] as Record<string, unknown>).secret_hash));
  }

  public async deleteApiKey(tenantId: string, keyId: string): Promise<void> {
    await this.pool.query(`DELETE FROM rbac_api_keys WHERE tenant_id = $1 AND id = $2`, [tenantId, keyId]);
  }

  public async createGroup(input: CreateGroupInput): Promise<RbacGroup> {
    const id = input.id ?? randomUUID();
    const now = new Date().toISOString();
    const { rows } = await this.pool.query(
      `INSERT INTO rbac_groups (id, tenant_id, name, description, created_at)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (id) DO UPDATE SET
         name = EXCLUDED.name,
         description = EXCLUDED.description
       RETURNING id, tenant_id, name, description, created_at`,
      [id, input.tenantId, input.name, input.description ?? null, now],
    );
    return this.mapGroup(rows[0] as Record<string, unknown>);
  }

  public async listGroups(tenantId: string): Promise<RbacGroup[]> {
    const { rows } = await this.pool.query(
      `SELECT id, tenant_id, name, description, created_at
         FROM rbac_groups
        WHERE tenant_id = $1
        ORDER BY created_at ASC`,
      [tenantId],
    );
    return rows.map((row: unknown) => this.mapGroup(row as Record<string, unknown>));
  }

  public async addUserToGroup(tenantId: string, groupId: string, userId: string): Promise<void> {
    await this.pool.query(
      `INSERT INTO rbac_group_members (tenant_id, group_id, user_id, assigned_at)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (tenant_id, group_id, user_id) DO NOTHING`,
      [tenantId, groupId, userId, new Date().toISOString()],
    );
  }

  public async listGroupMembers(tenantId: string, groupId: string): Promise<RbacGroupMember[]> {
    const { rows } = await this.pool.query(
      `SELECT tenant_id, group_id, user_id, assigned_at
         FROM rbac_group_members
        WHERE tenant_id = $1 AND group_id = $2
        ORDER BY assigned_at ASC`,
      [tenantId, groupId],
    );
    return rows.map((row: unknown) => this.mapGroupMember(row as Record<string, unknown>));
  }

  public async removeUserFromGroup(tenantId: string, groupId: string, userId: string): Promise<void> {
    await this.pool.query(
      `DELETE FROM rbac_group_members
        WHERE tenant_id = $1 AND group_id = $2 AND user_id = $3`,
      [tenantId, groupId, userId],
    );
  }
}

export const __testHooks = {
  hashSecret,
  verifySecret,
  fingerprintSecret,
};
