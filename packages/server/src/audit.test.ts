import { newDb } from 'pg-mem';

import { DatabaseManager } from './database';
import { AuditLogStore } from './audit';

describe('AuditLogStore', () => {
  let manager: DatabaseManager;
  let store: AuditLogStore;

  beforeEach(async () => {
    const mem = newDb();
    const { Pool } = mem.adapters.createPg();
    manager = new DatabaseManager('pg-mem', () => new Pool());
    await manager.initialize();
    store = new AuditLogStore(manager);
  });

  afterEach(async () => {
    await manager.close();
  });

  it('persists audit entries and filters by tenant, actor, and action', async () => {
    const baseTime = new Date('2024-07-01T10:00:00Z');

    await store.append({
      tenantId: 'tenant-a',
      actor: 'alice',
      action: 'pipeline.created',
      target: 'pipeline:alpha',
      payload: { revision: '1.0.0' },
      createdAt: new Date(baseTime.getTime() + 1_000),
    });

    await store.append({
      tenantId: 'tenant-a',
      actor: 'bob',
      action: 'pipeline.updated',
      target: 'pipeline:alpha',
      payload: { revision: '1.1.0' },
      createdAt: new Date(baseTime.getTime() + 2_000),
    });

    await store.append({
      tenantId: 'tenant-a',
      actor: 'alice',
      action: 'pipeline.deleted',
      target: 'pipeline:beta',
      payload: { revision: '1.1.0' },
      createdAt: new Date(baseTime.getTime() + 3_000),
    });

    await store.append({
      tenantId: 'tenant-b',
      actor: 'mallory',
      action: 'pipeline.created',
      target: 'pipeline:zeta',
      payload: { revision: '2.0.0' },
      createdAt: new Date(baseTime.getTime() + 4_000),
    });

    const tenantA = await store.query({ tenantId: 'tenant-a' });
    expect(tenantA.items).toHaveLength(3);
    expect(tenantA.items.map((item) => item.action)).toEqual([
      'pipeline.deleted',
      'pipeline.updated',
      'pipeline.created',
    ]);
    expect(tenantA.items[0].target).toBe('pipeline:beta');
    expect(tenantA.items[0].payload).toEqual({ revision: '1.1.0' });

    const aliceEntries = await store.query({ tenantId: 'tenant-a', actor: 'alice' });
    expect(aliceEntries.items).toHaveLength(2);
    expect(aliceEntries.items.every((item) => item.actor === 'alice')).toBe(true);

    const updated = await store.query({ tenantId: 'tenant-a', action: 'pipeline.updated' });
    expect(updated.items).toHaveLength(1);
    expect(updated.items[0].target).toBe('pipeline:alpha');
    expect(updated.items[0].payload).toEqual({ revision: '1.1.0' });
  });

  it('supports time window filtering and pagination helpers', async () => {
    const baseTime = new Date('2024-07-02T08:00:00Z');

    for (let index = 0; index < 5; index += 1) {
      await store.append({
        tenantId: 'tenant-a',
        actor: 'system',
        action: `event-${index}`,
        target: `resource-${index}`,
        createdAt: new Date(baseTime.getTime() + index * 60_000),
      });
    }

    const since = new Date(baseTime.getTime() + 60_000);
    const until = new Date(baseTime.getTime() + 180_000);
    const ranged = await store.query({ tenantId: 'tenant-a', since, until });
    expect(ranged.items.map((item) => item.action)).toEqual(['event-3', 'event-2', 'event-1']);

    const firstPage = await store.query({ tenantId: 'tenant-a', limit: 2, order: 'asc' });
    expect(firstPage.items.map((item) => item.action)).toEqual(['event-0', 'event-1']);
    expect(firstPage.hasMore).toBe(true);
    expect(firstPage.nextOffset).toBe(2);

    const secondPage = await store.query({ tenantId: 'tenant-a', limit: 2, order: 'asc', offset: firstPage.nextOffset });
    expect(secondPage.items.map((item) => item.action)).toEqual(['event-2', 'event-3']);
    expect(secondPage.hasMore).toBe(true);
    expect(secondPage.nextOffset).toBe(4);

    const finalPage = await store.query({ tenantId: 'tenant-a', limit: 2, order: 'asc', offset: secondPage.nextOffset });
    expect(finalPage.items.map((item) => item.action)).toEqual(['event-4']);
    expect(finalPage.hasMore).toBe(false);
    expect(finalPage.nextOffset).toBeUndefined();
  });
});
