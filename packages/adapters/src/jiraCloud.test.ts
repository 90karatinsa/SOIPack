import http from 'http';
import { AddressInfo } from 'net';

import { fetchJiraChangeRequests, fetchJiraArtifacts } from './jiraCloud';

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

describe('fetchJiraChangeRequests', () => {
  it('retrieves paginated change requests with transitions and attachments', async () => {
    const requests: string[] = [];

    const server = http.createServer((req, res) => {
      if (!req.url) {
        res.statusCode = 400;
        res.end();
        return;
      }

      requests.push(req.url);

      if (req.url.startsWith('/rest/api/3/search') && req.url.includes('startAt=0')) {
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            startAt: 0,
            maxResults: 2,
            total: 3,
            issues: [
              {
                id: '1001',
                key: 'CR-1',
                fields: {
                  summary: 'Update DAL A requirements',
                  status: { name: 'In Progress', statusCategory: { name: 'In Progress' } },
                  assignee: { displayName: 'Alex Pilot' },
                  updated: '2024-09-01T10:00:00Z',
                  priority: { name: 'High' },
                  issuetype: { name: 'Change Request' },
                  attachment: [
                    {
                      id: 'att-1',
                      filename: 'impact-analysis.pdf',
                      mimeType: 'application/pdf',
                      size: 2048,
                      content: 'https://jira.example.com/secure/attachment/att-1',
                      created: '2024-09-01T09:55:00Z',
                    },
                  ],
                },
              },
              {
                id: '1002',
                key: 'CR-2',
                fields: {
                  summary: 'Audit configuration management plan',
                  status: { name: 'Ready for Review', statusCategory: { name: 'To Do' } },
                  assignee: null,
                  updated: '2024-09-01T08:30:00Z',
                  priority: { name: 'Medium' },
                  issuetype: { name: 'Problem' },
                  attachment: [],
                },
              },
            ],
          }),
        );
        return;
      }

      if (req.url.startsWith('/rest/api/3/search') && req.url.includes('startAt=2')) {
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            startAt: 2,
            maxResults: 2,
            total: 3,
            issues: [
              {
                id: '1003',
                key: 'CR-3',
                fields: {
                  summary: 'Propagate software build for lab',
                  status: { name: 'In Review', statusCategory: { name: 'In Progress' } },
                  assignee: { displayName: 'Jamie QA' },
                  updated: '2024-09-01T07:15:00Z',
                  priority: { name: 'Low' },
                  issuetype: { name: 'Change Request' },
                  attachment: null,
                },
              },
            ],
          }),
        );
        return;
      }

      if (req.url.startsWith('/rest/api/3/issue/1001/transitions')) {
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            transitions: [
              { id: '1', name: 'Submit for Review', to: { name: 'Ready for Review', statusCategory: { name: 'To Do' } } },
            ],
          }),
        );
        return;
      }

      if (req.url.startsWith('/rest/api/3/issue/1002/transitions')) {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ transitions: [] }));
        return;
      }

      if (req.url.startsWith('/rest/api/3/issue/1003/transitions')) {
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            transitions: [
              { id: '3', name: 'Approve', to: { name: 'Ready for Release', statusCategory: { name: 'Done' } } },
            ],
          }),
        );
        return;
      }

      res.statusCode = 404;
      res.end('Not Found');
    });

    try {
      const address = await listen(server);
      const baseUrl = `http://127.0.0.1:${address.port}`;

      const result = await fetchJiraChangeRequests({
        baseUrl,
        projectKey: 'DO178',
        authToken: 'token',
        pageSize: 2,
      });

      expect(result).toHaveLength(3);
      expect(result[0]).toMatchObject({
        key: 'CR-1',
        summary: 'Update DAL A requirements',
        assignee: 'Alex Pilot',
        priority: 'High',
      });
      expect(result[0].attachments).toHaveLength(1);
      expect(result[0].attachments[0]).toMatchObject({ filename: 'impact-analysis.pdf', url: expect.stringContaining('attachment') });
      expect(result[0].transitions[0]).toMatchObject({ name: 'Submit for Review', toStatus: 'Ready for Review' });
      expect(result[1]).toMatchObject({ key: 'CR-2', status: 'Ready for Review', assignee: undefined });
      expect(result[2]).toMatchObject({ key: 'CR-3', transitions: [{ name: 'Approve', category: 'Done' }] });

      const searchRequests = requests.filter((entry) => entry.startsWith('/rest/api/3/search'));
      expect(searchRequests).toHaveLength(2);
    } finally {
      await close(server);
    }
  });

  it('retries when Jira returns HTTP 429 with Retry-After header', async () => {
    let searchCount = 0;

    const server = http.createServer((req, res) => {
      if (!req.url) {
        res.statusCode = 400;
        res.end();
        return;
      }

      if (req.url.startsWith('/rest/api/3/search')) {
        searchCount += 1;
        if (searchCount === 1) {
          res.statusCode = 429;
          res.setHeader('Retry-After', '0.05');
          res.end('Rate limited');
          return;
        }

        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            startAt: 0,
            maxResults: 1,
            total: 1,
            issues: [
              {
                id: '2001',
                key: 'CR-10',
                fields: {
                  summary: 'Reset actuator tolerance',
                  status: { name: 'In Progress', statusCategory: { name: 'In Progress' } },
                  assignee: { displayName: 'Morgan Systems' },
                  updated: '2024-09-02T11:22:33Z',
                  priority: { name: 'High' },
                  issuetype: { name: 'Change Request' },
                  attachment: [],
                },
              },
            ],
          }),
        );
        return;
      }

      if (req.url?.startsWith('/rest/api/3/issue/2001/transitions')) {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ transitions: [] }));
        return;
      }

      res.statusCode = 404;
      res.end('Not Found');
    });

    try {
      const address = await listen(server);
      const baseUrl = `http://127.0.0.1:${address.port}`;

      const result = await fetchJiraChangeRequests({
        baseUrl,
        projectKey: 'SAFETY',
        authToken: 'token',
        rateLimitDelaysMs: [10, 25],
      });

      expect(searchCount).toBe(2);
      expect(result).toHaveLength(1);
      expect(result[0]).toMatchObject({ key: 'CR-10', assignee: 'Morgan Systems' });
    } finally {
      await close(server);
    }
  });
});

describe('fetchJiraArtifacts', () => {
  const respondWithJson = (res: http.ServerResponse, payload: unknown): void => {
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(payload));
  };

  it('paginates requirements and tests while collecting attachments and traces', async () => {
    const server = http.createServer((req, res) => {
      if (!req.url) {
        res.statusCode = 400;
        res.end();
        return;
      }

      const parsed = new URL(req.url, 'http://localhost');
      if (parsed.pathname === '/rest/api/3/search') {
        const jql = parsed.searchParams.get('jql') ?? '';
        const startAt = Number.parseInt(parsed.searchParams.get('startAt') ?? '0', 10);

        if (jql.includes('Requirement')) {
          if (startAt === 0) {
            respondWithJson(res, {
              startAt: 0,
              maxResults: 1,
              total: 2,
              issues: [
                {
                  id: 'req-1',
                  key: 'REQ-1',
                  fields: {
                    summary: 'Autopilot requirement',
                    description: 'Maintain altitude',
                    status: { name: 'Approved' },
                    issuetype: { name: 'Requirement' },
                    attachment: [
                      {
                        id: 'att-req-1',
                        filename: 'analysis.pdf',
                        content: 'https://jira.example.com/secure/attachment/att-req-1',
                        mimeType: 'application/pdf',
                        size: 1024,
                        created: '2024-09-01T10:00:00Z',
                      },
                    ],
                  },
                },
              ],
            });
            return;
          }

          respondWithJson(res, {
            startAt: 1,
            maxResults: 1,
            total: 2,
            issues: [
              {
                id: 'req-2',
                key: 'REQ-2',
                fields: {
                  summary: 'Stability requirement',
                  status: { name: 'In Progress' },
                  issuetype: { name: 'Story' },
                  attachment: [],
                },
              },
            ],
          });
          return;
        }

        if (jql.includes('Test')) {
          respondWithJson(res, {
            startAt: 0,
            maxResults: 50,
            total: 1,
            issues: [
              {
                id: 'test-1',
                key: 'TEST-1',
                fields: {
                  summary: 'Verify altitude hold',
                  status: { name: 'Passed' },
                  timetracking: { timeSpentSeconds: 120 },
                  issuelinks: [
                    {
                      id: 'link-1',
                      outwardIssue: { key: 'REQ-1' },
                    },
                    {
                      id: 'link-2',
                      inwardIssue: { key: 'REQ-2' },
                    },
                  ],
                  attachment: [
                    {
                      id: 'att-test-1',
                      filename: 'results.txt',
                      size: 256,
                      content: 'https://jira.example.com/secure/attachment/att-test-1',
                    },
                  ],
                },
              },
            ],
          });
          return;
        }
      }

      res.statusCode = 404;
      res.end();
    });

    try {
      const address = await listen(server);
      const baseUrl = `http://127.0.0.1:${address.port}`;

      const result = await fetchJiraArtifacts({
        baseUrl,
        projectKey: 'FLIGHT',
        authToken: 'token',
        pageSize: 1,
      });

      expect(result.data.requirements).toHaveLength(2);
      expect(result.data.tests).toHaveLength(1);
      expect(result.data.traces).toEqual(
        expect.arrayContaining([
          { fromId: 'REQ-1', toId: 'TEST-1', type: 'verifies' },
          { fromId: 'REQ-2', toId: 'TEST-1', type: 'verifies' },
        ]),
      );
      expect(result.data.attachments).toHaveLength(2);
      expect(result.data.attachments.find((item) => item.id === 'att-req-1')).toMatchObject({
        issueKey: 'REQ-1',
        filename: 'analysis.pdf',
      });
      expect(result.data.attachments.find((item) => item.id === 'att-test-1')).toMatchObject({
        issueKey: 'TEST-1',
        filename: 'results.txt',
      });
    } finally {
      await close(server);
    }
  });

  it('retries searches when the API responds with 429', async () => {
    let attempts = 0;

    const server = http.createServer((req, res) => {
      if (!req.url) {
        res.statusCode = 400;
        res.end();
        return;
      }

      const parsed = new URL(req.url, 'http://localhost');
      if (parsed.pathname === '/rest/api/3/search') {
        const jql = parsed.searchParams.get('jql') ?? '';
        if (jql.includes('Requirement')) {
          respondWithJson(res, {
            startAt: 0,
            maxResults: 50,
            total: 0,
            issues: [],
          });
          return;
        }

        if (jql.includes('Test')) {
          attempts += 1;
          if (attempts === 1) {
            res.statusCode = 429;
            res.setHeader('Retry-After', '0.05');
            res.end('Rate limited');
            return;
          }

          respondWithJson(res, {
            startAt: 0,
            maxResults: 1,
            total: 1,
            issues: [
              {
                id: 'test-2',
                key: 'TEST-2',
                fields: {
                  summary: 'Regression test',
                  status: { name: 'In Progress' },
                },
              },
            ],
          });
          return;
        }
      }

      res.statusCode = 404;
      res.end();
    });

    try {
      const address = await listen(server);
      const baseUrl = `http://127.0.0.1:${address.port}`;

      const result = await fetchJiraArtifacts({
        baseUrl,
        projectKey: 'SAFETY',
        authToken: 'token',
        rateLimitDelaysMs: [10, 20, 40],
      });

      expect(attempts).toBe(2);
      expect(result.data.tests).toHaveLength(1);
      expect(result.data.tests[0]?.id).toBe('TEST-2');
    } finally {
      await close(server);
    }
  });
});

