import http from 'http';
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
    });

    expect(result.warnings).toHaveLength(0);
    expect(result.data.requirements).toHaveLength(1);
    expect(result.data.tests).toHaveLength(1);
    expect(result.data.builds).toHaveLength(1);

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
    } as const;

    const firstPass = await fetchPolarionArtifacts(options);
    expect(firstPass.data.requirements).toHaveLength(170);
    expect(firstPass.data.tests).toHaveLength(1);
    expect(firstPass.data.builds).toHaveLength(1);
    expect(firstPass.warnings).toHaveLength(1);
    expect(firstPass.warnings[0]).toContain('throttled');
    expect(firstPass.warnings[0]).toContain('429');

    const secondPass = await fetchPolarionArtifacts(options);
    expect(secondPass.data.requirements).toHaveLength(170);
    expect(secondPass.warnings).toHaveLength(0);

    expect(new Set(pageSizes)).toEqual(new Set(['55']));
    expect(attemptCounts.get('start')).toBe(3);
    expect(attemptCounts.get('cursor-1')).toBe(2);
    expect(attemptCounts.get('cursor-2')).toBe(2);

    await close(server);
  });
});
