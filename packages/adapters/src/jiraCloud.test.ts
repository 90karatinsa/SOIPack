import http from 'http';
import { AddressInfo } from 'net';

import { fetchJiraChangeRequests } from './jiraCloud';

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

