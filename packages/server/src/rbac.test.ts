import { newDb } from 'pg-mem';

import { DatabaseManager } from './database';
import { RbacStore, __testHooks } from './rbac';

const { verifySecret, fingerprintSecret } = __testHooks;

describe('RbacStore', () => {
  let manager: DatabaseManager;
  let store: RbacStore;

  const createSchema = async () => {
    const pool = manager.getPool();
    await pool.query(`
      CREATE TABLE rbac_users (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        email TEXT NOT NULL,
        display_name TEXT,
        secret_hash TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL,
        updated_at TIMESTAMP NOT NULL
      );
    `);
    await pool.query(`
      CREATE TABLE rbac_roles (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        created_at TIMESTAMP NOT NULL
      );
    `);
    await pool.query(`
      CREATE TABLE rbac_user_roles (
        tenant_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        role_id TEXT NOT NULL,
        assigned_at TIMESTAMP NOT NULL,
        PRIMARY KEY (tenant_id, user_id, role_id)
      );
    `);
    await pool.query(`
      CREATE TABLE rbac_api_keys (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        label TEXT,
        secret_hash TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL,
        last_used_at TIMESTAMP
      );
    `);
    await pool.query(`
      CREATE TABLE rbac_groups (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        created_at TIMESTAMP NOT NULL
      );
    `);
    await pool.query(`
      CREATE TABLE rbac_group_members (
        tenant_id TEXT NOT NULL,
        group_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        assigned_at TIMESTAMP NOT NULL,
        PRIMARY KEY (tenant_id, group_id, user_id)
      );
    `);
  };

  beforeEach(async () => {
    const mem = newDb();
    const { Pool } = mem.adapters.createPg();
    manager = new DatabaseManager('pg-mem', () => new Pool());
    await manager.initialize();
    await createSchema();
    store = new RbacStore(manager);
  });

  afterEach(async () => {
    await manager.close();
  });

  it('hashes user secrets and supports credential updates', async () => {
    const user = await store.createUser({
      tenantId: 'tenant-a',
      email: 'alice@example.com',
      secret: 's3cret!',
      displayName: 'Alice',
      id: 'user-alice',
    });

    expect(user.email).toBe('alice@example.com');
    expect(user.displayName).toBe('Alice');

    const pool = manager.getPool();
    const { rows } = await pool.query(
      'SELECT secret_hash FROM rbac_users WHERE tenant_id = $1 AND id = $2',
      ['tenant-a', 'user-alice'],
    );
    const storedHash = String(rows[0].secret_hash);
    expect(storedHash).not.toBe('s3cret!');
    expect(storedHash.startsWith('pbkdf2$')).toBe(true);
    expect(await verifySecret('s3cret!', storedHash)).toBe(true);

    expect(await store.verifyUserSecret('tenant-a', 'user-alice', 's3cret!')).toBe(true);
    expect(await store.verifyUserSecret('tenant-a', 'user-alice', 'wrong')).toBe(false);

    await store.updateUserSecret('tenant-a', 'user-alice', 'n3wSecret');
    expect(await store.verifyUserSecret('tenant-a', 'user-alice', 's3cret!')).toBe(false);
    expect(await store.verifyUserSecret('tenant-a', 'user-alice', 'n3wSecret')).toBe(true);

    const users = await store.listUsers('tenant-a');
    expect(users).toHaveLength(1);
    expect(users[0].id).toBe('user-alice');

    await store.deleteUser('tenant-a', 'user-alice');
    expect(await store.getUser('tenant-a', 'user-alice')).toBeUndefined();
  });

  it('assigns and revokes roles for users', async () => {
    await store.createUser({ tenantId: 'tenant-a', email: 'bob@example.com', secret: 'passw0rd', id: 'user-bob' });
    const role = await store.createRole({ tenantId: 'tenant-a', name: 'maintainer', description: 'Can manage pipelines', id: 'role-maintainer' });

    await store.assignRole('tenant-a', 'user-bob', role.id);
    const roles = await store.listUserRoles('tenant-a', 'user-bob');
    expect(roles).toEqual([expect.objectContaining({ id: role.id, name: 'maintainer' })]);

    await store.revokeRole('tenant-a', 'user-bob', role.id);
    expect(await store.listUserRoles('tenant-a', 'user-bob')).toHaveLength(0);
  });

  it('stores API key fingerprints and hashed secrets', async () => {
    const apiKey = await store.createApiKey({ tenantId: 'tenant-a', secret: 'topsecret', label: 'CI', id: 'key-ci' });
    expect(apiKey.fingerprint).toBe(fingerprintSecret('topsecret'));

    const pool = manager.getPool();
    const { rows } = await pool.query(
      'SELECT secret_hash FROM rbac_api_keys WHERE tenant_id = $1 AND id = $2',
      ['tenant-a', 'key-ci'],
    );
    const storedApiHash = String(rows[0].secret_hash);
    expect(storedApiHash).not.toBe('topsecret');
    expect(storedApiHash.startsWith('pbkdf2$')).toBe(true);
    expect(await store.verifyApiKeySecret('tenant-a', 'key-ci', 'topsecret')).toBe(true);

    const keys = await store.listApiKeys('tenant-a');
    expect(keys).toHaveLength(1);
    expect(keys[0].fingerprint).toBe(apiKey.fingerprint);

    await store.deleteApiKey('tenant-a', 'key-ci');
    expect(await store.listApiKeys('tenant-a')).toHaveLength(0);
  });

  it('manages group membership lifecycle', async () => {
    await store.createUser({ tenantId: 'tenant-a', email: 'carol@example.com', secret: 'carolpass', id: 'user-carol' });
    const group = await store.createGroup({ tenantId: 'tenant-a', name: 'reviewers', description: 'Review board', id: 'group-review' });

    await store.addUserToGroup('tenant-a', group.id, 'user-carol');
    const members = await store.listGroupMembers('tenant-a', group.id);
    expect(members).toEqual([
      expect.objectContaining({ tenantId: 'tenant-a', groupId: group.id, userId: 'user-carol' }),
    ]);

    await store.removeUserFromGroup('tenant-a', group.id, 'user-carol');
    expect(await store.listGroupMembers('tenant-a', group.id)).toHaveLength(0);
  });
});
