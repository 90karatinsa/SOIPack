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
});
