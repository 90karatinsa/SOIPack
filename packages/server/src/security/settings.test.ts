import { promises as fsPromises } from 'fs';
import os from 'os';
import path from 'path';

import { FileSystemStorage } from '../storage';
import {
  SaveSecuritySettingsInput,
  SecuritySettingsConflictError,
  SecuritySettingsStore,
  SecuritySettingsValidationError,
} from './settings';

describe('SecuritySettingsStore', () => {
  let baseDir: string;
  let storage: FileSystemStorage;

  beforeEach(async () => {
    baseDir = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'security-settings-test-'));
    storage = new FileSystemStorage(baseDir);
  });

  afterEach(async () => {
    await fsPromises.rm(baseDir, { recursive: true, force: true });
  });

  const buildInput = (overrides: Partial<SaveSecuritySettingsInput> = {}): SaveSecuritySettingsInput => ({
    tenantId: 'tenant-a',
    settings: {
      incidentContact: {
        name: 'Alice Responders',
        email: 'alice@example.com',
        phone: '+1-555-0100',
      },
      retention: {
        uploadsDays: 30,
        reportsDays: 90,
      },
      maintenance: {
        dayOfWeek: 'saturday',
        startTime: '02:00',
        durationMinutes: 120,
        timezone: 'UTC',
      },
    },
    ...overrides,
  });

  it('creates a new settings document with revision metadata', async () => {
    const clock = jest.fn(() => new Date('2024-01-01T00:00:00.000Z'));
    const store = new SecuritySettingsStore(storage, {
      clock,
      revisionIdFactory: () => 'rev-1',
    });

    const created = await store.save(buildInput());

    expect(created.revision).toEqual({
      id: 'rev-1',
      number: 1,
      updatedAt: '2024-01-01T00:00:00.000Z',
    });
    expect(created.createdAt).toBe('2024-01-01T00:00:00.000Z');

    const fetched = await store.get('tenant-a');
    expect(fetched).toEqual(created);
  });

  it('updates existing settings and increments the revision while preserving createdAt', async () => {
    const clock = jest
      .fn<() => Date>()
      .mockReturnValueOnce(new Date('2024-01-01T00:00:00.000Z'))
      .mockReturnValueOnce(new Date('2024-02-01T00:00:00.000Z'));
    const revisionIds = jest.fn().mockReturnValueOnce('rev-1').mockReturnValueOnce('rev-2');

    const store = new SecuritySettingsStore(storage, {
      clock,
      revisionIdFactory: () => revisionIds(),
    });

    const initial = await store.save(buildInput());

    const updatedInput = buildInput({
      settings: {
        incidentContact: {
          name: 'Alice Responders',
          email: 'alice@example.com',
          phone: '+1-555-0100',
        },
        retention: {
          uploadsDays: 45,
          reportsDays: 90,
          packagesDays: 120,
        },
        maintenance: {
          dayOfWeek: 'sunday',
          startTime: '03:30',
          durationMinutes: 180,
          timezone: 'UTC',
        },
      },
      expectedRevision: initial.revision.number,
    });

    const updated = await store.save(updatedInput);

    expect(updated.revision).toEqual({
      id: 'rev-2',
      number: 2,
      updatedAt: '2024-02-01T00:00:00.000Z',
    });
    expect(updated.createdAt).toBe(initial.createdAt);
    expect(updated.settings.retention.uploadsDays).toBe(45);
    expect(updated.settings.retention.packagesDays).toBe(120);

    const fetched = await store.get('tenant-a');
    expect(fetched).toEqual(updated);
  });

  it('rejects malformed payloads', async () => {
    const store = new SecuritySettingsStore(storage);

    await expect(
      store.save(
        buildInput({
          settings: {
            incidentContact: {
              name: '',
              email: 'not-an-email',
            },
            retention: {},
            maintenance: {
              dayOfWeek: 'monday',
              startTime: '25:00',
              durationMinutes: 5,
              timezone: '',
            },
          },
        }),
      ),
    ).rejects.toBeInstanceOf(SecuritySettingsValidationError);
  });

  it('enforces optimistic concurrency when revisions diverge', async () => {
    const clock = jest
      .fn<() => Date>()
      .mockReturnValueOnce(new Date('2024-01-01T00:00:00.000Z'))
      .mockReturnValueOnce(new Date('2024-02-01T00:00:00.000Z'));
    const revisionIds = jest.fn().mockReturnValueOnce('rev-1').mockReturnValueOnce('rev-2');

    const store = new SecuritySettingsStore(storage, {
      clock,
      revisionIdFactory: () => revisionIds(),
    });

    const initial = await store.save(buildInput());

    const update = buildInput({
      settings: {
        incidentContact: {
          name: 'Alice Responders',
          email: 'alice@example.com',
          phone: '+1-555-0100',
        },
        retention: {
          uploadsDays: 60,
          reportsDays: 120,
        },
        maintenance: {
          dayOfWeek: 'saturday',
          startTime: '01:00',
          durationMinutes: 60,
          timezone: 'UTC',
        },
      },
      expectedRevision: initial.revision.number,
    });

    await store.save(update);

    await expect(store.save(update)).rejects.toBeInstanceOf(SecuritySettingsConflictError);
    expect(clock).toHaveBeenCalledTimes(2);
    expect(revisionIds).toHaveBeenCalledTimes(2);
  });
});
