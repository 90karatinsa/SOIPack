import { createHash } from 'crypto';
import http from 'http';
import type { AddressInfo } from 'net';

import { fetchAzureDevOpsArtifacts } from './azureDevOps';

const listen = (server: http.Server): Promise<AddressInfo> =>
  new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        reject(new Error('Unable to determine server address.'));
        return;
      }
      resolve(address);
    });
  });

const close = (server: http.Server): Promise<void> =>
  new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });

describe('fetchAzureDevOpsArtifacts', () => {
  it('aggregates paginated resources, retries on throttling, and caches attachments', async () => {
    let baseUrl = 'http://127.0.0.1';
    const authHeaders: string[] = [];
    const attachmentRequestCounts = new Map<string, number>();
    let testRequestCount = 0;

    const server = http.createServer((req, res) => {
      const url = new URL(req.url ?? '/', baseUrl);
      if (req.headers.authorization) {
        authHeaders.push(String(req.headers.authorization));
      }

      if (url.pathname.startsWith('/attachments/')) {
        const current = attachmentRequestCounts.get(url.pathname) ?? 0;
        attachmentRequestCounts.set(url.pathname, current + 1);
      }

      if (url.pathname === '/org/proj/_apis/wit/workitems') {
        res.setHeader('Content-Type', 'application/json');
        const continuationToken = url.searchParams.get('continuationToken');
        if (!continuationToken) {
          res.statusCode = 200;
          res.setHeader('x-ms-continuationtoken', 'req-page-2');
          res.end(
            JSON.stringify({
              value: [
                {
                  id: 101,
                  fields: {
                    'System.Title': 'MFA shall be required',
                    'System.Description': 'Detailed requirement description',
                    'System.State': 'Approved',
                    'System.WorkItemType': 'Requirement',
                  },
                  url: `${baseUrl}/org/proj/_apis/wit/workitems/101`,
                  attachments: [
                    {
                      id: 'att-spec',
                      name: 'spec.md',
                      url: '/attachments/spec.md',
                      contentType: 'text/markdown',
                      size: 20,
                    },
                    {
                      id: 'att-shared',
                      name: 'shared.txt',
                      url: '/attachments/shared.txt',
                      contentType: 'text/plain',
                    },
                    {
                      id: 'att-missing',
                      name: 'missing.txt',
                      url: '/attachments/missing.txt',
                    },
                  ],
                },
                {
                  id: 102,
                  fields: {
                    'System.Title': 'Audit events shall be recorded',
                    'System.State': 'New',
                  },
                  url: `${baseUrl}/org/proj/_apis/wit/workitems/102`,
                },
              ],
            }),
          );
          return;
        }

        if (continuationToken === 'req-page-2') {
          res.statusCode = 200;
          res.end(
            JSON.stringify({
              value: [
                {
                  id: 103,
                  fields: {
                    'System.Title': 'Configuration shall be version controlled',
                    'System.State': 'Committed',
                  },
                  attachments: [
                    {
                      id: 'att-large',
                      name: 'oversized.bin',
                      url: '/attachments/oversized.bin',
                      contentType: 'application/octet-stream',
                      size: 128,
                    },
                  ],
                },
              ],
            }),
          );
          return;
        }

        res.statusCode = 404;
        res.end('unknown continuation');
        return;
      }

      if (url.pathname === '/org/proj/_apis/test/Runs') {
        testRequestCount += 1;
        if (testRequestCount === 1) {
          res.statusCode = 429;
          res.setHeader('Retry-After', '0.01');
          res.end('Throttled');
          return;
        }

        const continuationToken = url.searchParams.get('continuationToken');
        res.setHeader('Content-Type', 'application/json');
        if (!continuationToken) {
          res.statusCode = 200;
          res.setHeader('x-ms-continuationtoken', 'tests-page-2');
          res.end(
            JSON.stringify({
              value: [
                {
                  id: 'TC-1',
                  name: 'MFA login succeeds',
                  outcome: 'Passed',
                  durationInMs: 1250,
                  associatedRequirementIds: [101],
                  attachments: [
                    {
                      id: 'att-log',
                      name: 'results.log',
                      url: '/attachments/results.log',
                      contentType: 'text/plain',
                    },
                  ],
                },
              ],
            }),
          );
          return;
        }

        if (continuationToken === 'tests-page-2') {
          res.statusCode = 200;
          res.end(
            JSON.stringify({
              value: [
                {
                  id: 'TC-2',
                  name: 'Audit failure path',
                  outcome: 'Failed',
                  errorMessage: 'Expected audit event not found',
                  associatedRequirementIds: [102, 103],
                  attachments: [
                    {
                      id: 'att-shared-test',
                      name: 'shared.txt',
                      url: '/attachments/shared.txt',
                      contentType: 'text/plain',
                    },
                  ],
                },
              ],
            }),
          );
          return;
        }

        res.statusCode = 404;
        res.end('unknown continuation');
        return;
      }

      if (url.pathname === '/org/proj/_apis/build/builds') {
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            value: [
              {
                id: 'build-1',
                buildNumber: '2024.05.01',
                result: 'succeeded',
                sourceBranch: 'refs/heads/main',
                sourceVersion: 'abc123',
                startTime: '2024-05-01T10:00:00Z',
                finishTime: '2024-05-01T10:15:00Z',
                url: `${baseUrl}/org/proj/_build/results?buildId=1`,
              },
            ],
          }),
        );
        return;
      }

      if (url.pathname === '/attachments/spec.md') {
        const payload = 'requirement-spec-data';
        res.statusCode = 200;
        res.setHeader('Content-Type', 'text/markdown');
        res.setHeader('Content-Length', String(Buffer.byteLength(payload)));
        res.end(payload);
        return;
      }

      if (url.pathname === '/attachments/results.log') {
        const payload = 'test-log-output';
        res.statusCode = 200;
        res.setHeader('Content-Type', 'text/plain');
        res.setHeader('Content-Length', String(Buffer.byteLength(payload)));
        res.end(payload);
        return;
      }

      if (url.pathname === '/attachments/shared.txt') {
        const payload = 'shared-attachment-body';
        res.statusCode = 200;
        res.setHeader('Content-Type', 'text/plain');
        res.setHeader('Content-Length', String(Buffer.byteLength(payload)));
        res.end(payload);
        return;
      }

      if (url.pathname === '/attachments/missing.txt') {
        res.statusCode = 404;
        res.end('Not Found');
        return;
      }

      if (url.pathname === '/attachments/oversized.bin') {
        const payload = 'X'.repeat(80);
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Content-Length', String(Buffer.byteLength(payload)));
        res.end(payload);
        return;
      }

      res.statusCode = 404;
      res.end('Unknown path');
    });

    const address = await listen(server);
    baseUrl = `http://127.0.0.1:${address.port}`;

    try {
      const result = await fetchAzureDevOpsArtifacts({
        baseUrl,
        organization: 'org',
        project: 'proj',
        personalAccessToken: 'pat-token',
        pageSize: 2,
        maxAttachmentBytes: 40,
      });

      expect(result.data.requirements).toHaveLength(3);
      expect(result.data.requirements.map((req) => req.id)).toEqual(['101', '102', '103']);
      expect(result.data.tests).toHaveLength(2);
      expect(result.data.builds).toHaveLength(1);
      expect(result.data.traces).toEqual(
        expect.arrayContaining([
          { fromId: 'TC-1', toId: '101', type: 'verifies' },
          { fromId: 'TC-2', toId: '102', type: 'verifies' },
          { fromId: 'TC-2', toId: '103', type: 'verifies' },
        ]),
      );

      const specHash = createHash('sha256').update('requirement-spec-data').digest('hex');
      const sharedHash = createHash('sha256').update('shared-attachment-body').digest('hex');
      const logHash = createHash('sha256').update('test-log-output').digest('hex');

      expect(result.data.attachments).toHaveLength(4);
      expect(result.data.attachments).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            id: 'att-spec',
            artifactId: '101',
            artifactType: 'requirement',
            filename: 'spec.md',
            sha256: specHash,
            bytes: 'requirement-spec-data'.length,
            contentType: 'text/markdown',
          }),
          expect.objectContaining({
            id: 'att-shared',
            artifactId: '101',
            artifactType: 'requirement',
            filename: 'shared.txt',
            sha256: sharedHash,
            bytes: 'shared-attachment-body'.length,
            contentType: 'text/plain',
          }),
          expect.objectContaining({
            id: 'att-log',
            artifactId: 'TC-1',
            artifactType: 'test',
            filename: 'results.log',
            sha256: logHash,
            bytes: 'test-log-output'.length,
            contentType: 'text/plain',
          }),
          expect.objectContaining({
            id: 'att-shared-test',
            artifactId: 'TC-2',
            artifactType: 'test',
            filename: 'shared.txt',
            sha256: sharedHash,
            bytes: 'shared-attachment-body'.length,
            contentType: 'text/plain',
          }),
        ]),
      );

      const attachmentIds = result.data.attachments.map((entry) => entry.id);
      expect(attachmentIds).not.toContain('att-missing');
      expect(attachmentIds).not.toContain('att-large');

      expect(result.warnings).toEqual(
        expect.arrayContaining([
          expect.stringContaining('404'),
          expect.stringContaining('byte limit'),
        ]),
      );

      const expectedAuthHeader = `Basic ${Buffer.from(':pat-token').toString('base64')}`;
      expect(authHeaders).toEqual(expect.arrayContaining([expectedAuthHeader]));
      expect(testRequestCount).toBe(3);
      expect(attachmentRequestCounts.get('/attachments/shared.txt')).toBe(1);
      expect(attachmentRequestCounts.get('/attachments/spec.md')).toBe(1);
    } finally {
      await close(server);
    }
  });

  it('propagates upstream build failures after retry attempts are exhausted', async () => {
    let baseUrl = 'http://127.0.0.1';
    let buildRequestCount = 0;

    const server = http.createServer((req, res) => {
      const url = new URL(req.url ?? '/', baseUrl);
      if (url.pathname === '/org/proj/_apis/wit/workitems') {
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ value: [] }));
        return;
      }
      if (url.pathname === '/org/proj/_apis/test/Runs') {
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ value: [] }));
        return;
      }
      if (url.pathname === '/org/proj/_apis/build/builds') {
        buildRequestCount += 1;
        res.statusCode = 503;
        res.setHeader('Retry-After', '0');
        res.end();
        return;
      }
      res.statusCode = 404;
      res.end('Unknown path');
    });

    const address = await listen(server);
    baseUrl = `http://127.0.0.1:${address.port}`;

    try {
      await expect(
        fetchAzureDevOpsArtifacts({
          baseUrl,
          organization: 'org',
          project: 'proj',
          personalAccessToken: 'pat-token',
          rateLimitDelaysMs: [1, 1],
        }),
      ).rejects.toThrow('HTTP 503');
      expect(buildRequestCount).toBeGreaterThanOrEqual(2);
    } finally {
      await close(server);
    }
  });
});

