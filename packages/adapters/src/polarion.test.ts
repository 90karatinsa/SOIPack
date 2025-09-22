import http from 'http';
import { AddressInfo } from 'net';

import { fetchPolarionArtifacts } from './polarion';

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
});
