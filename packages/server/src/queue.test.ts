import fs from 'fs';
import { promises as fsPromises } from 'fs';
import os from 'os';
import path from 'path';

import { JobExecutionContext, JobQueue } from './queue';

describe('JobQueue persistence', () => {
  it('replays queued jobs from disk without duplication', async () => {
    const baseDir = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'soipack-queue-test-'));
    try {
      const tenantId = 'tenant-a';
      const jobId = 'abcdef1234567890';
      const hash = 'test-hash';
      const payload = { value: 'resume-me' };
      const tenantDir = path.join(baseDir, tenantId);
      await fsPromises.mkdir(tenantDir, { recursive: true });
      const createdAt = new Date().toISOString();
      const jobFilePath = path.join(tenantDir, `${jobId}.json`);
      await fsPromises.writeFile(
        jobFilePath,
        `${JSON.stringify(
          {
            tenantId,
            id: jobId,
            kind: 'import' as const,
            hash,
            status: 'queued' as const,
            createdAt,
            updatedAt: createdAt,
            payload,
          },
          null,
          2,
        )}\n`,
        'utf8',
      );

      let resumedRuns = 0;
      const queue = new JobQueue(1, {
        directory: baseDir,
        createRunner: (context: JobExecutionContext) => async () => {
          resumedRuns += 1;
          expect(context.tenantId).toBe(tenantId);
          expect(context.id).toBe(jobId);
          expect(context.payload).toEqual(payload);
          return { ok: true };
        },
      });

      await queue.waitForIdle();

      expect(resumedRuns).toBe(1);
      const job = queue.get<{ ok: boolean }>(tenantId, jobId);
      expect(job?.status).toBe('completed');
      expect(job?.result).toEqual({ ok: true });

      let additionalRuns = 0;
      const queueAfterRestart = new JobQueue(1, {
        directory: baseDir,
        createRunner: () => async () => {
          additionalRuns += 1;
          return undefined;
        },
      });
      await queueAfterRestart.waitForIdle();
      expect(additionalRuns).toBe(0);
      const persistedJob = queueAfterRestart.get<{ ok: boolean }>(tenantId, jobId);
      expect(persistedJob?.status).toBe('completed');
      expect(persistedJob?.result).toEqual({ ok: true });
    } finally {
      await fsPromises.rm(baseDir, { recursive: true, force: true });
    }
  });

  it('keeps completed jobs intact when rename fails during persistence', async () => {
    const baseDir = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'soipack-queue-rename-'));
    const tenantId = 'tenant-rename';
    const completedJobId = 'job-completed';
    const failingJobId = 'job-rename-failure';
    try {
      const queue = new JobQueue(1, {
        directory: baseDir,
        createRunner: () => async () => ({ ok: true }),
      });

      queue.enqueue({
        tenantId,
        id: completedJobId,
        kind: 'import',
        hash: 'hash-completed',
        payload: { value: 'initial' },
      });
      await queue.waitForIdle();

      const jobFilePath = path.join(baseDir, tenantId, `${completedJobId}.json`);
      const originalContent = await fsPromises.readFile(jobFilePath, 'utf8');

      const renameOriginal = fs.renameSync.bind(fs);
      const renameSpy = jest
        .spyOn(fs, 'renameSync')
        .mockImplementation((from, to) => {
          const targetName = path.basename(typeof to === 'string' ? to : to.toString());
          if (targetName === `${failingJobId}.json`) {
            throw Object.assign(new Error('rename failed'), { code: 'EPERM' });
          }
          return renameOriginal(from, to);
        });

      const timestamp = new Date().toISOString();
      try {
        expect(() =>
          queue.adoptCompleted({
            tenantId,
            id: failingJobId,
            kind: 'pack',
            hash: 'hash-failing',
            createdAt: timestamp,
            updatedAt: timestamp,
            result: { ok: false },
          }),
        ).toThrow('rename failed');
      } finally {
        renameSpy.mockRestore();
      }

      const persistedContent = await fsPromises.readFile(jobFilePath, 'utf8');
      expect(persistedContent).toBe(originalContent);

      const tenantEntries = await fsPromises.readdir(path.join(baseDir, tenantId));
      expect(tenantEntries).toEqual([`${completedJobId}.json`]);

      const reloaded = new JobQueue(1, {
        directory: baseDir,
        createRunner: () => async () => undefined,
      });
      await reloaded.waitForIdle();
      const job = reloaded.get<{ ok: boolean }>(tenantId, completedJobId);
      expect(job?.status).toBe('completed');
      expect(job?.result).toEqual({ ok: true });
    } finally {
      await fsPromises.rm(baseDir, { recursive: true, force: true });
    }
  });
});

describe('JobQueue streaming and ephemeral mode', () => {
  it('allows disabling persistence for ephemeral processing', async () => {
    const baseDir = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'soipack-queue-ephemeral-'));
    try {
      const queue = new JobQueue(2, {
        directory: baseDir,
        createRunner: () => async () => undefined,
        persistJobs: false,
      });

      const tenantId = 'tenant-ephemeral';
      queue.enqueue({
        tenantId,
        id: 'job-ephemeral',
        kind: 'import',
        hash: 'hash-ephemeral',
        payload: { value: 1 },
      });
      await queue.waitForIdle();

      const entries = await fsPromises.readdir(baseDir);
      expect(entries).toEqual([]);
    } finally {
      await fsPromises.rm(baseDir, { recursive: true, force: true });
    }
  });

  it('streams job summaries for a tenant without allocating intermediate arrays', async () => {
    const baseDir = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'soipack-queue-stream-'));
    try {
      const queue = new JobQueue(1, {
        directory: baseDir,
        createRunner: () => async () => undefined,
        persistJobs: false,
      });

      const tenantId = 'tenant-stream';
      const total = 25;
      const createdAt = new Date().toISOString();
      for (let index = 0; index < total; index += 1) {
        queue.adoptCompleted({
          tenantId,
          id: `job-${index.toString().padStart(5, '0')}`,
          kind: 'analyze',
          hash: `hash-${index}`,
          createdAt,
          result: { ok: index },
        });
      }

      const firstFive: string[] = [];
      let streamedCount = 0;
      for (const summary of queue.stream(tenantId)) {
        streamedCount += 1;
        firstFive.push(summary.id);
        if (streamedCount === 5) {
          break;
        }
      }

      expect(firstFive).toEqual([
        'job-00000',
        'job-00001',
        'job-00002',
        'job-00003',
        'job-00004',
      ]);

      const collected = Array.from(queue.stream(tenantId));
      expect(collected).toHaveLength(total);
      expect(collected[collected.length - 1].id).toBe('job-00024');
    } finally {
      await fsPromises.rm(baseDir, { recursive: true, force: true });
    }
  });
});
