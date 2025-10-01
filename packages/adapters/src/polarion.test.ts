import http from 'http';
import { createHash } from 'crypto';
import { AddressInfo } from 'net';

import { fetchPolarionArtifacts } from './polarion';
import { RemoteRequirementRecord } from './types';

const listen = (server: http.Server): Promise<AddressInfo> =>
  new Promise((resolve) => {
    server.listen(0, () => {
      resolve(server.address() as AddressInfo);
    });
  });

const close = (server: http.Server): Promise<void> =>
  new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });
  });

describe('fetchPolarionArtifacts', () => {
  it('retrieves requirements, tests and build metadata with basic authentication', async () => {
    const receivedPaths: string[] = [];
    let receivedAuth: string | undefined;

    const server = http.createServer((req, res) => {
      receivedPaths.push(req.url ?? '');
      receivedAuth = req.headers.authorization;

      if (!req.headers.authorization || !req.headers.authorization.startsWith('Basic ')) {
        res.statusCode = 401;
        res.end('Unauthorized');
        return;
      }

      if (req.url?.startsWith('/requirements')) {
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            items: [
              {
                id: 'REQ-1',
                title: 'Autopilot engages',
                description: 'The autopilot shall engage within 200ms.',
                status: 'Approved',
                type: 'System Requirement',
              },
            ],
          }),
        );
        return;
      }

      if (req.url?.startsWith('/tests')) {
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify([
            {
              id: 'TR-101',
              name: 'Autopilot engagement qualification',
              className: 'polarion.Tests',
              status: 'passed',
              durationMs: 1200,
              requirementIds: ['REQ-1'],
            },
          ]),
        );
        return;
      }

      if (req.url?.startsWith('/builds')) {
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify([
            {
              id: 'build-77',
              name: 'Integration build #77',
              url: 'https://polarion.example.com/builds/77',
              status: 'SUCCESS',
              branch: 'main',
              revision: 'abcdef123456',
              completedAt: '2024-05-01T09:15:00.000Z',
            },
          ]),
        );
        return;
      }

      if (req.url?.startsWith('/attachments/')) {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ items: [] }));
        return;
      }

      res.statusCode = 404;
      res.end('Not Found');
    });

    const address = await listen(server);
    const baseUrl = `http://127.0.0.1:${address.port}`;

    const result = await fetchPolarionArtifacts({
      baseUrl,
      projectId: 'DEMO',
      username: 'demo',
      password: 'secret',
      requirementsEndpoint: '/requirements',
      testRunsEndpoint: '/tests',
      buildsEndpoint: '/builds',
      attachmentsEndpoint: '/attachments/:workItemId',
    });

    expect(result.warnings).toHaveLength(0);
    expect(result.data.requirements).toHaveLength(1);
    expect(result.data.tests).toHaveLength(1);
    expect(result.data.builds).toHaveLength(1);
    expect(result.data.attachments).toHaveLength(0);
    expect(result.data.relationships).toEqual([
      { fromId: 'REQ-1', toId: 'TR-101', type: 'verifies' },
    ]);

    expect(result.data.requirements[0]).toMatchObject({ id: 'REQ-1', status: 'Approved' });
    expect(result.data.tests[0]).toMatchObject({ id: 'TR-101', status: 'passed', durationMs: 1200 });
    expect(result.data.builds[0]).toMatchObject({ id: 'build-77', status: 'SUCCESS', revision: 'abcdef123456' });

    expect(receivedAuth).toBe(`Basic ${Buffer.from('demo:secret').toString('base64')}`);
    expect(receivedPaths).toEqual(
      expect.arrayContaining([
        expect.stringContaining('/requirements'),
        expect.stringContaining('projectId=DEMO'),
        expect.stringContaining('/tests'),
        expect.stringContaining('/builds'),
      ]),
    );

    await close(server);
  });

  it('paginates requirements with retries, caching and configurable page size', async () => {
    const requirementPages = new Map<
      string,
      { items: RemoteRequirementRecord[]; next?: string; etag: string }
    >();
    const createRequirements = (offset: number, count: number): RemoteRequirementRecord[] =>
      Array.from({ length: count }, (_, index) => {
        const id = offset + index + 1;
        return {
          id: `REQ-${id}`,
          title: `Requirement ${id}`,
          description: `Requirement description ${id}`,
        };
      });

    requirementPages.set('start', {
      items: createRequirements(0, 60),
      next: 'cursor-1',
      etag: '"page-1"',
    });
    requirementPages.set('cursor-1', {
      items: createRequirements(60, 60),
      next: 'cursor-2',
      etag: '"page-2"',
    });
    requirementPages.set('cursor-2', {
      items: createRequirements(120, 50),
      etag: '"page-3"',
    });

    const attemptCounts = new Map<string, number>();
    const pageSizes: string[] = [];

    const server = http.createServer((req, res) => {
      if (req.url?.startsWith('/requirements')) {
        const url = new URL(req.url, 'http://127.0.0.1');
        const cursor = url.searchParams.get('cursor') ?? 'start';
        const entry = requirementPages.get(cursor);
        if (!entry) {
          res.statusCode = 404;
          res.end('Missing page');
          return;
        }

        pageSizes.push(url.searchParams.get('pageSize') ?? '');

        const attempts = attemptCounts.get(cursor) ?? 0;
        if (cursor === 'start' && attempts === 0) {
          attemptCounts.set(cursor, attempts + 1);
          res.statusCode = 429;
          res.setHeader('Retry-After', '0');
          res.end('Too Many Requests');
          return;
        }

        attemptCounts.set(cursor, attempts + 1);
        const ifNoneMatch = req.headers['if-none-match'];
        if (typeof ifNoneMatch === 'string' && ifNoneMatch === entry.etag) {
          res.statusCode = 304;
          res.setHeader('ETag', entry.etag);
          res.end();
          return;
        }

        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('ETag', entry.etag);
        res.end(
          JSON.stringify({
            items: entry.items,
            pageInfo: entry.next ? { nextCursor: entry.next } : undefined,
          }),
        );
        return;
      }

      if (req.url?.startsWith('/tests')) {
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify([
            {
              id: 'TR-1',
              name: 'Smoke suite',
              status: 'passed',
            },
          ]),
        );
        return;
      }

      if (req.url?.startsWith('/builds')) {
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify([
            {
              id: 'build-1',
              name: 'Nightly build',
              status: 'SUCCESS',
            },
          ]),
        );
        return;
      }

      if (req.url?.startsWith('/attachments/')) {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ items: [] }));
        return;
      }

      res.statusCode = 404;
      res.end('Not Found');
    });

    const address = await listen(server);
    const baseUrl = `http://127.0.0.1:${address.port}`;

    const options = {
      baseUrl,
      projectId: 'BIG',
      requirementsEndpoint: '/requirements',
      testRunsEndpoint: '/tests',
      buildsEndpoint: '/builds',
      pageSize: 55,
      attachmentsEndpoint: '/attachments/:workItemId',
    } as const;

    const firstPass = await fetchPolarionArtifacts(options);
    expect(firstPass.data.requirements).toHaveLength(170);
    expect(firstPass.data.tests).toHaveLength(1);
    expect(firstPass.data.builds).toHaveLength(1);
    expect(firstPass.data.relationships).toHaveLength(0);
    expect(firstPass.data.attachments).toHaveLength(0);
    expect(firstPass.warnings).toHaveLength(1);
    expect(firstPass.warnings[0]).toContain('throttled');
    expect(firstPass.warnings[0]).toContain('429');

    const secondPass = await fetchPolarionArtifacts(options);
    expect(secondPass.data.requirements).toHaveLength(170);
    expect(secondPass.warnings).toHaveLength(0);
    expect(secondPass.data.relationships).toHaveLength(0);
    expect(secondPass.data.attachments).toHaveLength(0);

    expect(new Set(pageSizes)).toEqual(new Set(['55']));
    expect(attemptCounts.get('start')).toBe(3);
    expect(attemptCounts.get('cursor-1')).toBe(2);
    expect(attemptCounts.get('cursor-2')).toBe(2);

    await close(server);
  });

  it('collects requirement-test trace links across paginated responses with throttling', async () => {
    const requirementPages = new Map<string, { items: unknown[]; next?: string }>();
    requirementPages.set('start', {
      items: [
        {
          id: 'REQ-501',
          title: 'Maintain control law',
          linkedWorkItems: [
            { id: 'TR-800', role: 'verifies' },
            { id: 'TR-801', role: 'implements' },
          ],
        },
      ],
      next: 'req-next',
    });
    requirementPages.set('req-next', {
      items: [
        {
          id: 'REQ-502',
          title: 'Limit actuator deflection',
          linkedTests: ['TR-801'],
        },
      ],
    });

    const testPages = new Map<string, { items: unknown[]; next?: string }>();
    testPages.set('start', {
      items: [
        {
          id: 'TR-800',
          name: 'Control law regression',
          status: 'passed',
          requirementIds: ['REQ-501'],
        },
      ],
      next: 'tests-next',
    });
    testPages.set('tests-next', {
      items: [
        {
          id: 'TR-801',
          name: 'Actuator integration',
          status: 'failed',
          linkedWorkItems: [{ workItemId: 'REQ-502', role: 'verifies' }],
        },
      ],
    });

    let testAttempts = 0;

    const server = http.createServer((req, res) => {
      if (!req.url) {
        res.statusCode = 400;
        res.end('Invalid request');
        return;
      }

      if (req.url.startsWith('/linked/requirements')) {
        const url = new URL(req.url, 'http://127.0.0.1');
        const cursor = url.searchParams.get('cursor') ?? 'start';
        const entry = requirementPages.get(cursor);
        if (!entry) {
          res.statusCode = 404;
          res.end('Missing requirement page');
          return;
        }
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            items: entry.items,
            pageInfo: entry.next ? { nextCursor: entry.next } : undefined,
          }),
        );
        return;
      }

      if (req.url.startsWith('/linked/tests')) {
        const url = new URL(req.url, 'http://127.0.0.1');
        const cursor = url.searchParams.get('cursor') ?? 'start';
        const entry = testPages.get(cursor);
        if (!entry) {
          res.statusCode = 404;
          res.end('Missing test page');
          return;
        }

        if (cursor === 'start' && testAttempts === 0) {
          testAttempts += 1;
          res.statusCode = 429;
          res.setHeader('Retry-After', '0.01');
          res.end('Rate limited');
          return;
        }

        testAttempts += 1;
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            items: entry.items,
            pageInfo: entry.next ? { nextCursor: entry.next } : undefined,
          }),
        );
        return;
      }

      if (req.url.startsWith('/linked/builds')) {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ items: [] }));
        return;
      }

      if (req.url.startsWith('/attachments/')) {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ items: [] }));
        return;
      }

      res.statusCode = 404;
      res.end('Not Found');
    });

    const address = await listen(server);
    const baseUrl = `http://127.0.0.1:${address.port}`;

    try {
      const result = await fetchPolarionArtifacts({
        baseUrl,
        projectId: 'TRACE',
        requirementsEndpoint: '/linked/requirements',
        testRunsEndpoint: '/linked/tests',
        buildsEndpoint: '/linked/builds',
        pageSize: 1,
        attachmentsEndpoint: '/attachments/:workItemId',
      });

      expect(result.data.requirements).toHaveLength(2);
      expect(result.data.tests).toHaveLength(2);
      expect(result.data.relationships).toEqual(
        expect.arrayContaining([
          { fromId: 'REQ-501', toId: 'TR-800', type: 'verifies' },
          { fromId: 'REQ-501', toId: 'TR-801', type: 'implements' },
          { fromId: 'REQ-502', toId: 'TR-801', type: 'verifies' },
        ]),
      );
      expect(result.data.relationships).toHaveLength(3);
      expect(result.data.attachments).toHaveLength(0);
      expect(result.warnings).toEqual(
        expect.arrayContaining([
          'Polarion testRuns request was throttled (HTTP 429). Retrying with backoff.',
        ]),
      );
      expect(testAttempts).toBeGreaterThanOrEqual(2);
    } finally {
      await close(server);
    }
  });

  it('downloads work item attachments with concurrency, caching and size enforcement', async () => {
    const downloadRequests: Array<Record<string, string | undefined>> = [];
    let activeDownloads = 0;
    let maxConcurrentDownloads = 0;

    const server = http.createServer((req, res) => {
      if (!req.url) {
        res.statusCode = 400;
        res.end('Invalid request');
        return;
      }

      const url = new URL(req.url, 'http://127.0.0.1');

      if (url.pathname === '/requirements') {
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            items: [
              { id: 'REQ-ATT-1', title: 'Attachment alpha' },
              { id: 'REQ-ATT-2', title: 'Attachment beta' },
            ],
          }),
        );
        return;
      }

      if (url.pathname === '/tests') {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ items: [] }));
        return;
      }

      if (url.pathname === '/builds') {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ items: [] }));
        return;
      }

      if (url.pathname.startsWith('/attachments/REQ-ATT-1')) {
        const cursor = url.searchParams.get('cursor');
        if (cursor) {
          res.statusCode = 404;
          res.end('Missing cursor');
          return;
        }
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            items: [
              {
                id: 'ATT-1',
                fileName: 'alpha.txt',
                url: '/files/REQ-ATT-1/alpha.txt',
                contentType: 'text/plain',
                size: 12,
              },
              {
                id: 'ATT-2',
                fileName: 'oversized.bin',
                url: '/files/REQ-ATT-1/oversized.bin',
                contentType: 'application/octet-stream',
                size: 10,
              },
            ],
            pageInfo: { nextCursor: 'ignored' },
          }),
        );
        return;
      }

      if (url.pathname.startsWith('/attachments/REQ-ATT-2')) {
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            items: [
              {
                id: 'ATT-3',
                fileName: 'beta.json',
                downloadUrl: '/files/REQ-ATT-2/beta.json',
                mimeType: 'application/json',
                size: 14,
              },
            ],
          }),
        );
        return;
      }

      const downloadHeaders: Record<string, string | undefined> = {
        path: url.pathname,
        ifNoneMatch: Array.isArray(req.headers['if-none-match'])
          ? req.headers['if-none-match'][0]
          : (req.headers['if-none-match'] as string | undefined),
      };
      downloadRequests.push(downloadHeaders);

      const beginDownload = (): void => {
        activeDownloads += 1;
        maxConcurrentDownloads = Math.max(maxConcurrentDownloads, activeDownloads);
        let finalized = false;
        const markDone = () => {
          if (!finalized) {
            finalized = true;
            activeDownloads -= 1;
          }
        };
        res.on('finish', markDone);
        res.on('close', markDone);
      };

      if (url.pathname === '/files/REQ-ATT-1/alpha.txt') {
        if (downloadHeaders.ifNoneMatch === '"alpha1"') {
          res.statusCode = 304;
          res.end();
          return;
        }
        beginDownload();
        res.setHeader('Content-Type', 'text/plain');
        res.setHeader('ETag', '"alpha1"');
        res.write('alpha-data');
        res.end();
        return;
      }

      if (url.pathname === '/files/REQ-ATT-1/oversized.bin') {
        beginDownload();
        res.setHeader('Content-Type', 'application/octet-stream');
        const payload = 'X'.repeat(128);
        res.write(payload);
        res.end();
        return;
      }

      if (url.pathname === '/files/REQ-ATT-2/beta.json') {
        if (downloadHeaders.ifNoneMatch === '"beta1"') {
          res.statusCode = 304;
          res.end();
          return;
        }
        beginDownload();
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('ETag', '"beta1"');
        res.write('{"beta":"content"}');
        res.end();
        return;
      }

      res.statusCode = 404;
      res.end('Unknown path');
    });

    const address = await listen(server);
    const baseUrl = `http://127.0.0.1:${address.port}`;

    try {
      const result = await fetchPolarionArtifacts({
        baseUrl,
        projectId: 'ATT',
        requirementsEndpoint: '/requirements',
        testRunsEndpoint: '/tests',
        buildsEndpoint: '/builds',
        attachmentsEndpoint: '/attachments/:workItemId',
        attachmentsConcurrency: 2,
        maxAttachmentBytes: 32,
      });

      expect(result.data.attachments).toHaveLength(2);
      const alphaHash = createHash('sha256').update('alpha-data').digest('hex');
      const betaHash = createHash('sha256').update('{"beta":"content"}').digest('hex');

      expect(result.data.attachments).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            id: 'ATT-1',
            workItemId: 'REQ-ATT-1',
            filename: 'alpha.txt',
            sha256: alphaHash,
            bytes: 'alpha-data'.length,
            contentType: 'text/plain',
          }),
          expect.objectContaining({
            id: 'ATT-3',
            workItemId: 'REQ-ATT-2',
            filename: 'beta.json',
            sha256: betaHash,
            bytes: '{"beta":"content"}'.length,
            contentType: 'application/json',
          }),
        ]),
      );

      expect(maxConcurrentDownloads).toBeLessThanOrEqual(2);
      expect(result.warnings).toEqual(
        expect.arrayContaining([
          expect.stringContaining('returned 404'),
          expect.stringContaining('oversized.bin'),
          expect.stringContaining('32 byte limit'),
        ]),
      );

      const secondPass = await fetchPolarionArtifacts({
        baseUrl,
        projectId: 'ATT',
        requirementsEndpoint: '/requirements',
        testRunsEndpoint: '/tests',
        buildsEndpoint: '/builds',
        attachmentsEndpoint: '/attachments/:workItemId',
        attachmentsConcurrency: 2,
        maxAttachmentBytes: 32,
      });

      expect(secondPass.data.attachments).toHaveLength(2);
      const alphaRequests = downloadRequests.filter((entry) => entry.path === '/files/REQ-ATT-1/alpha.txt');
      const betaRequests = downloadRequests.filter((entry) => entry.path === '/files/REQ-ATT-2/beta.json');
      expect(alphaRequests.some((entry) => entry.ifNoneMatch === '"alpha1"')).toBe(true);
      expect(betaRequests.some((entry) => entry.ifNoneMatch === '"beta1"')).toBe(true);
    } finally {
      await close(server);
    }
  });
});
