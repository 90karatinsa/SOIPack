import { createHash } from 'crypto';
import { promises as fsPromises } from 'fs';
import http from 'http';
import { AddressInfo } from 'net';
import { tmpdir } from 'os';
import path from 'path';

import { fetchJenkinsArtifacts } from './jenkins';

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

describe('fetchJenkinsArtifacts', () => {
  it('refreshes the crumb on 403 responses and retries throttled reports', async () => {
    let crumbRequests = 0;
    let buildAttempts = 0;
    let reportAttempts = 0;
    const observedCrumbs: string[] = [];

    const server = http.createServer((req, res) => {
      const path = req.url ?? '';

      if (path.startsWith('/crumb')) {
        crumbRequests += 1;
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            crumbRequestField: 'Jenkins-Crumb',
            crumb: `crumb-${crumbRequests}`,
          }),
        );
        return;
      }

      if (path.startsWith('/build')) {
        buildAttempts += 1;
        const crumb = String(req.headers['jenkins-crumb'] ?? '');
        observedCrumbs.push(crumb);

        if (buildAttempts === 1) {
          res.statusCode = 403;
          res.end('Forbidden');
          return;
        }

        if (crumb !== 'crumb-2') {
          res.statusCode = 401;
          res.end('Invalid crumb');
          return;
        }

        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            id: 'build-42',
            result: 'SUCCESS',
            timestamp: Date.UTC(2024, 5, 1, 12, 30, 0),
            duration: 5000,
            url: 'http://jenkins.local/job/demo/42/',
          }),
        );
        return;
      }

      if (path.startsWith('/tests')) {
        reportAttempts += 1;
        if (reportAttempts === 1) {
          res.statusCode = 429;
          res.setHeader('Retry-After', '0.01');
          res.end('Throttled');
          return;
        }

        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            suites: [
              {
                name: 'demo',
                cases: [
                  {
                    className: 'jenkins.Demo',
                    name: 'should-pass',
                    status: 'PASSED',
                    duration: 0.12,
                  },
                ],
              },
            ],
          }),
        );
        return;
      }

      res.statusCode = 404;
      res.end('Not Found');
    });

    const address = await listen(server);
    const baseUrl = `http://127.0.0.1:${address.port}`;

    const result = await fetchJenkinsArtifacts({
      baseUrl,
      job: 'demo',
      buildEndpoint: '/build',
      testReportEndpoint: '/tests',
      crumbIssuerEndpoint: '/crumb',
      timeoutMs: 250,
    });

    expect(result.data.builds).toHaveLength(1);
    expect(result.data.tests).toHaveLength(1);
    expect(result.data.builds[0]).toMatchObject({ id: 'build-42', status: 'SUCCESS' });
    expect(result.data.tests[0]).toMatchObject({ id: expect.stringContaining('should-pass'), status: 'PASSED' });

    expect(crumbRequests).toBeGreaterThanOrEqual(2);
    expect(buildAttempts).toBe(2);
    expect(reportAttempts).toBe(2);
    expect(observedCrumbs).toEqual(expect.arrayContaining(['crumb-1', 'crumb-2']));

    expect(result.warnings).toEqual(
      expect.arrayContaining([
        expect.stringContaining('Jenkins crumb refreshed'),
        expect.stringContaining('429'),
      ]),
    );

    await close(server);
  });

  it('limits oversized test reports and records a warning', async () => {
    let crumbRequests = 0;
    const server = http.createServer((req, res) => {
      const path = req.url ?? '';

      if (path.startsWith('/crumb')) {
        crumbRequests += 1;
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            crumbRequestField: 'Jenkins-Crumb',
            crumb: `crumb-${crumbRequests}`,
          }),
        );
        return;
      }

      if (path.startsWith('/build')) {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ id: 'build-99', result: 'UNSTABLE' }));
        return;
      }

      if (path.startsWith('/tests')) {
        res.setHeader('Content-Type', 'application/json');
        const largeMessage = 'x'.repeat(4096);
        res.end(
          JSON.stringify({
            suites: [
              {
                name: 'oversized',
                cases: [
                  { name: 'giant-report', status: 'FAILED', errorDetails: largeMessage },
                ],
              },
            ],
          }),
        );
        return;
      }

      res.statusCode = 404;
      res.end('Not Found');
    });

    const address = await listen(server);
    const baseUrl = `http://127.0.0.1:${address.port}`;

    const result = await fetchJenkinsArtifacts({
      baseUrl,
      job: 'demo',
      buildEndpoint: '/build',
      testReportEndpoint: '/tests',
      crumbIssuerEndpoint: '/crumb',
      maxReportBytes: 1024,
    });

    expect(result.data.builds).toHaveLength(1);
    expect(result.data.builds[0]).toMatchObject({ id: 'build-99', status: 'UNSTABLE' });
    expect(result.data.tests).toHaveLength(0);
    expect(result.warnings).toEqual(
      expect.arrayContaining([expect.stringContaining('byte limit')]),
    );

    await close(server);
  });

  it('downloads and parses coverage artifacts with retries and hashing', async () => {
    const tempDir = await fsPromises.mkdtemp(path.join(tmpdir(), 'soipack-jenkins-'));
    let crumbRequests = 0;
    let coverageAttempts = 0;
    const lcovContent = ['TN:demo-test', 'SF:src/app.ts', 'LF:4', 'LH:3', 'BRF:2', 'BRH:1', 'end_of_record'].join('\n');
    const expectedHash = createHash('sha256').update(lcovContent).digest('hex');

    const server = http.createServer((req, res) => {
      const requestPath = req.url ?? '';

      if (requestPath.startsWith('/crumb')) {
        crumbRequests += 1;
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            crumbRequestField: 'Jenkins-Crumb',
            crumb: `crumb-${crumbRequests}`,
          }),
        );
        return;
      }

      if (requestPath.startsWith('/build')) {
        const host = req.headers.host ?? '127.0.0.1';
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            id: 'build-42',
            number: 42,
            url: `http://${host}/job/demo/42/`,
            artifacts: [
              {
                fileName: 'lcov.info',
                relativePath: 'reports/lcov.info',
              },
            ],
          }),
        );
        return;
      }

      if (requestPath.startsWith('/tests')) {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ suites: [] }));
        return;
      }

      if (requestPath.startsWith('/job/demo/42/artifact/reports/lcov.info')) {
        coverageAttempts += 1;
        if (coverageAttempts === 1) {
          res.statusCode = 503;
          res.end('Busy');
          return;
        }
        res.setHeader('Content-Type', 'text/plain');
        res.end(lcovContent);
        return;
      }

      res.statusCode = 404;
      res.end('Not Found');
    });

    const address = await listen(server);
    const baseUrl = `http://127.0.0.1:${address.port}`;

    try {
      const result = await fetchJenkinsArtifacts({
        baseUrl,
        job: 'demo',
        buildEndpoint: '/build',
        testReportEndpoint: '/tests',
        crumbIssuerEndpoint: '/crumb',
        artifactsDir: tempDir,
        coverageArtifacts: [{ type: 'lcov', path: 'reports/lcov.info' }],
        timeoutMs: 250,
      });

      expect(result.data.coverage).toHaveLength(1);
      const coverage = result.data.coverage?.[0];
      expect(coverage).toBeDefined();
      expect(coverage?.path).toBe('reports/lcov.info');
      expect(coverage?.sha256).toBe(expectedHash);
      expect(coverage?.report.files).toHaveLength(1);
      expect(coverage?.report.totals.statements.covered).toBe(3);
      expect(coverage?.report.totals.branches?.total).toBe(2);

      const savedPath = path.join(tempDir, 'reports', 'lcov.info');
      const savedContent = await fsPromises.readFile(savedPath, 'utf8');
      expect(savedContent).toBe(lcovContent);

      expect(coverageAttempts).toBe(2);
      expect(result.warnings).toEqual(
        expect.arrayContaining([expect.stringContaining('artifact download (reports/lcov.info) returned 503')]),
      );
    } finally {
      await close(server);
      await fsPromises.rm(tempDir, { recursive: true, force: true });
    }
  });

  it('enforces coverage artifact byte limits and removes partial downloads', async () => {
    const tempDir = await fsPromises.mkdtemp(path.join(tmpdir(), 'soipack-jenkins-'));
    let crumbRequests = 0;

    const server = http.createServer((req, res) => {
      const requestPath = req.url ?? '';

      if (requestPath.startsWith('/crumb')) {
        crumbRequests += 1;
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            crumbRequestField: 'Jenkins-Crumb',
            crumb: `crumb-${crumbRequests}`,
          }),
        );
        return;
      }

      if (requestPath.startsWith('/build')) {
        const host = req.headers.host ?? '127.0.0.1';
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            id: 'build-7',
            number: 7,
            url: `http://${host}/job/demo/7/`,
            artifacts: [
              {
                fileName: 'lcov.info',
                relativePath: 'reports/lcov.info',
              },
            ],
          }),
        );
        return;
      }

      if (requestPath.startsWith('/tests')) {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ suites: [] }));
        return;
      }

      if (requestPath.startsWith('/job/demo/7/artifact/reports/lcov.info')) {
        res.setHeader('Content-Type', 'text/plain');
        res.end('X'.repeat(2048));
        return;
      }

      res.statusCode = 404;
      res.end('Not Found');
    });

    const address = await listen(server);
    const baseUrl = `http://127.0.0.1:${address.port}`;
    const targetPath = path.join(tempDir, 'reports', 'lcov.info');

    try {
      const result = await fetchJenkinsArtifacts({
        baseUrl,
        job: 'demo',
        buildEndpoint: '/build',
        testReportEndpoint: '/tests',
        crumbIssuerEndpoint: '/crumb',
        artifactsDir: tempDir,
        coverageArtifacts: [{ type: 'lcov', path: 'reports/lcov.info', maxBytes: 1024 }],
      });

      expect(result.data.coverage).toBeUndefined();
      expect(result.warnings).toEqual(
        expect.arrayContaining([expect.stringContaining('exceeded the 1024 byte limit')]),
      );

      await expect(fsPromises.access(targetPath)).rejects.toThrow();
    } finally {
      await close(server);
      await fsPromises.rm(tempDir, { recursive: true, force: true });
    }
  });
});
