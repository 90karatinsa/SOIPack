import http from 'http';
import { AddressInfo } from 'net';

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
  it('maps build metadata and test cases', async () => {
    const requests: string[] = [];
    const authHeaders: string[] = [];

    const server = http.createServer((req, res) => {
      requests.push(req.url ?? '');
      authHeaders.push(req.headers.authorization ?? '');

      if (req.url?.startsWith('/job/Avionics/job/Build/lastCompletedBuild/api/json')) {
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            id: '88',
            fullDisplayName: 'Avionics » Build #88',
            url: 'https://ci.example.com/job/Avionics/job/Build/88/',
            result: 'SUCCESS',
            timestamp: 1715155200000,
            duration: 90000,
            actions: [
              {
                lastBuiltRevision: {
                  SHA1: '123456abcdef',
                  branch: [{ name: 'origin/main' }],
                },
              },
            ],
          }),
        );
        return;
      }

      if (req.url?.startsWith('/job/Avionics/job/Build/lastCompletedBuild/testReport/api/json')) {
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            suites: [
              {
                name: 'Autopilot Suite',
                cases: [
                  {
                    className: 'autopilot.Qualification',
                    name: 'engagesWithinLimit',
                    status: 'PASSED',
                    duration: 2.5,
                  },
                  {
                    className: 'autopilot.Qualification',
                    name: 'failsOnInvalidInput',
                    status: 'FAILED',
                    duration: 1.1,
                    errorDetails: 'AssertionError: expected fail state',
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
      job: 'Avionics/Build',
      username: 'ci',
      token: 'apitoken',
    });

    expect(result.warnings).toHaveLength(0);
    expect(result.data.builds).toHaveLength(1);
    expect(result.data.tests).toHaveLength(2);

    const build = result.data.builds[0];
    expect(build).toMatchObject({
      id: '88',
      status: 'SUCCESS',
      revision: '123456abcdef',
      branch: 'origin/main',
    });
    expect(build.startedAt).toBe('2024-05-08T08:00:00.000Z');
    expect(build.completedAt).toBe('2024-05-08T08:01:30.000Z');

    const [firstTest, secondTest] = result.data.tests;
    expect(firstTest.id).toBe('autopilot.Qualification::engagesWithinLimit');
    expect(firstTest.status).toBe('PASSED');
    expect(firstTest.durationMs).toBeCloseTo(2500, 5);

    expect(secondTest.id).toBe('autopilot.Qualification::failsOnInvalidInput');
    expect(secondTest.status).toBe('FAILED');
    expect(secondTest.errorMessage).toBe('AssertionError: expected fail state');

    expect(authHeaders.filter((value) => value)).toHaveLength(2);
    expect(authHeaders[0]).toBe(`Basic ${Buffer.from('ci:apitoken').toString('base64')}`);
    expect(requests).toEqual(
      expect.arrayContaining([
        expect.stringContaining('/job/Avionics/job/Build/lastCompletedBuild/api/json'),
        expect.stringContaining('/job/Avionics/job/Build/lastCompletedBuild/testReport/api/json'),
      ]),
    );

    await close(server);
  });
});
