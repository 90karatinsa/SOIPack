import { newDb } from 'pg-mem';

import { DatabaseManager } from '../database';

import { PostgresStorageProvider } from './postgres';

describe('PostgresStorageProvider', () => {
  let manager: DatabaseManager;
  let provider: PostgresStorageProvider;

  beforeEach(async () => {
    const mem = newDb();
    const { Pool } = mem.adapters.createPg();
    manager = new DatabaseManager('pg-mem', () => new Pool());
    await manager.initialize();
    provider = new PostgresStorageProvider(manager);
  });

  afterEach(async () => {
    await manager.close();
  });

  it('creates, updates, and soft deletes pipeline jobs', async () => {
    const created = await provider.createPipelineJob({
      id: 'job-1',
      tenantId: 'tenant-a',
      checksum: 'checksum-1',
      data: { foo: 'bar' },
    });
    expect(created.id).toBe('job-1');
    expect(created.deletedAt).toBeNull();
    expect(created.data).toEqual({ foo: 'bar' });

    const fetched = await provider.getPipelineJob('tenant-a', 'job-1');
    expect(fetched?.checksum).toBe('checksum-1');

    const updated = await provider.updatePipelineJob('tenant-a', 'job-1', {
      checksum: 'checksum-2',
      data: { foo: 'baz' },
    });
    expect(updated.checksum).toBe('checksum-2');
    expect(updated.data).toEqual({ foo: 'baz' });

    await provider.softDeletePipelineJob('tenant-a', 'job-1');
    const deleted = await provider.getPipelineJob('tenant-a', 'job-1');
    expect(deleted?.deletedAt).toBeInstanceOf(Date);

    const activeJobs = await provider.listPipelineJobs('tenant-a');
    expect(activeJobs).toHaveLength(0);

    const allJobs = await provider.listPipelineJobs('tenant-a', { includeDeleted: true });
    expect(allJobs).toHaveLength(1);
    expect(allJobs[0].deletedAt).toBeInstanceOf(Date);
  });

  it('manages pipeline artifacts with filtering and soft delete', async () => {
    await provider.createPipelineJob({
      id: 'job-2',
      tenantId: 'tenant-a',
      checksum: 'checksum-job-2',
    });

    await provider.createPipelineArtifact({
      id: 'artifact-1',
      jobId: 'job-2',
      tenantId: 'tenant-a',
      checksum: 'artifact-checksum-1',
      data: { path: 'a.txt' },
    });
    await provider.createPipelineArtifact({
      id: 'artifact-2',
      jobId: 'job-3',
      tenantId: 'tenant-a',
      checksum: 'artifact-checksum-2',
      data: { path: 'b.txt' },
    });

    const jobArtifacts = await provider.listPipelineArtifacts('tenant-a', { jobId: 'job-2' });
    expect(jobArtifacts).toHaveLength(1);
    expect(jobArtifacts[0].id).toBe('artifact-1');

    const updated = await provider.updatePipelineArtifact('tenant-a', 'artifact-1', {
      checksum: 'artifact-checksum-updated',
    });
    expect(updated.checksum).toBe('artifact-checksum-updated');

    await provider.softDeletePipelineArtifact('tenant-a', 'artifact-1');

    const activeArtifacts = await provider.listPipelineArtifacts('tenant-a');
    expect(activeArtifacts.map((artifact) => artifact.id)).toEqual(['artifact-2']);

    const allArtifacts = await provider.listPipelineArtifacts('tenant-a', { includeDeleted: true });
    const deletedArtifact = allArtifacts.find((artifact) => artifact.id === 'artifact-1');
    expect(deletedArtifact?.deletedAt).toBeInstanceOf(Date);
  });

  it('records and soft deletes audit events', async () => {
    const created = await provider.createAuditEvent({
      id: 'event-1',
      tenantId: 'tenant-a',
      checksum: 'audit-checksum-1',
      payload: { action: 'created' },
    });
    expect(created.payload).toEqual({ action: 'created' });

    const listed = await provider.listAuditEvents('tenant-a');
    expect(listed).toHaveLength(1);

    const updated = await provider.updateAuditEvent('tenant-a', 'event-1', {
      checksum: 'audit-checksum-2',
      payload: { action: 'updated' },
    });
    expect(updated.checksum).toBe('audit-checksum-2');
    expect(updated.payload).toEqual({ action: 'updated' });

    await provider.softDeleteAuditEvent('tenant-a', 'event-1');

    const activeEvents = await provider.listAuditEvents('tenant-a');
    expect(activeEvents).toHaveLength(0);

    const allEvents = await provider.listAuditEvents('tenant-a', { includeDeleted: true });
    expect(allEvents).toHaveLength(1);
    expect(allEvents[0].deletedAt).toBeInstanceOf(Date);
  });
});
