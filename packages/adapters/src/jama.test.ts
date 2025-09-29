jest.mock('./utils/http', () => {
  const actual = jest.requireActual('./utils/http');
  return {
    ...actual,
    requestJson: jest.fn(),
  };
});

import { HttpError, requestJson } from './utils/http';
import { fetchJamaArtifacts } from './jama';

describe('fetchJamaArtifacts', () => {
  const mockedRequestJson = requestJson as jest.MockedFunction<typeof requestJson>;

  beforeEach(() => {
    mockedRequestJson.mockReset();
  });

  it('normalizes requirements, tests and relationships while collecting warnings', async () => {
    mockedRequestJson.mockImplementation(async (options) => {
      const url = options.url instanceof URL ? options.url : new URL(options.url);
      const attachmentMatch = url.pathname.match(/\/items\/(\d+)\/attachments$/u);
      if (attachmentMatch) {
        const itemId = attachmentMatch[1];
        if (itemId === '101') {
          if (!url.searchParams.has('cursor')) {
            return {
              data: [
                {
                  id: 'att-req-1',
                  fileName: 'locks.pdf',
                  url: 'https://jama.example.com/attachments/att-req-1',
                  contentType: 'application/pdf',
                  size: 2048,
                  createdDate: '2024-01-01T00:00:00Z',
                },
              ],
              meta: {
                pageInfo: {
                  next: 'https://jama.example.com/rest/latest/items/101/attachments?cursor=page-2',
                },
              },
            };
          }

          if (url.searchParams.get('cursor') === 'page-2') {
            return {
              data: [
                {
                  id: 'att-req-1',
                  fileName: 'locks.pdf',
                  url: 'https://jama.example.com/attachments/att-req-1',
                  contentType: 'application/pdf',
                  size: 2048,
                  createdDate: '2024-01-01T00:00:00Z',
                },
              ],
            };
          }
        }

        if (itemId === '201') {
          return {
            data: [
              {
                id: 'att-tc-1',
                fileName: 'results.txt',
                urls: { download: 'https://jama.example.com/attachments/att-tc-1' },
                mimeType: 'text/plain',
                size: 512,
                createdAt: '2024-01-02T00:00:00Z',
                item: { itemType: 'TEST_CASE' },
              },
            ],
          };
        }

        return { data: [] };
      }

      if (url.pathname.includes('/items') && url.searchParams.get('itemType') === 'REQUIREMENT') {
        return {
          data: [
            {
              id: 101,
              documentKey: 'REQ-1',
              fields: {
                name: 'Landing gear locks',
                status: 'Approved',
                description: '<p>Landing gear <br> must lock.&nbsp;</p>',
                tags: ['DAL-A', ' Safety '],
              },
              location: { url: 'https://jama.example.com/requirements/101' },
            },
            {
              id: 102,
              documentKey: 'REQ-2',
              fields: {
                status: 'Implemented',
                tags: ['Flight'],
              },
              location: { url: null },
            },
          ],
        };
      }

      if (url.pathname.includes('/items') && url.searchParams.get('itemType') === 'TEST_CASE') {
        return {
          data: [
            {
              id: 201,
              documentKey: 'TC-1',
              fields: {
                name: 'Landing gear qualification',
                status: 'PASS',
                executionTime: 15,
                failureMessage: 'Minor mismatch',
              },
              location: { url: 'https://jama.example.com/testcases/201' },
            },
            {
              id: 202,
              fields: {
                status: 'Blocked',
                duration: 9,
              },
              location: {},
            },
          ],
        };
      }

      if (url.pathname.includes('/relationships')) {
        return {
          data: [
            {
              id: 'rel-1',
              relationshipType: 'validates',
              fromItem: { id: 101 },
              toItem: { id: 201 },
            },
            {
              id: 'rel-2',
              relationshipType: 'verifies',
              fromItem: { id: 202 },
              toItem: { id: 102 },
            },
            {
              id: 'rel-3',
              relationshipType: 'invalid',
              fromItem: {},
              toItem: {},
            },
          ],
        };
      }

      throw new Error(`Unexpected URL: ${url.toString()}`);
    });

    const result = await fetchJamaArtifacts({
      baseUrl: 'https://jama.example.com',
      projectId: 'A320',
      token: 'secret-token',
      pageSize: 25,
      maxPages: 3,
      rateLimitDelaysMs: [0, 0],
    });

    expect(result.data.requirements).toHaveLength(2);
    expect(result.data.objectives).toEqual([]);
    expect(result.data.requirements[0]).toEqual({
      id: 'REQ-1',
      title: 'Landing gear locks',
      description: 'Landing gear must lock.',
      status: 'approved',
      tags: ['DAL-A', 'Safety'],
    });
    expect(result.data.requirements[1]).toEqual({
      id: 'REQ-2',
      title: 'REQ-2',
      description: undefined,
      status: 'implemented',
      tags: ['Flight'],
    });

    expect(result.data.testResults).toEqual([
      {
        testId: 'TC-1',
        className: 'jama',
        name: 'Landing gear qualification',
        status: 'passed',
        duration: 15,
        errorMessage: 'Minor mismatch',
        requirementsRefs: ['REQ-1'],
      },
      {
        testId: '202',
        className: 'jama',
        name: '202',
        status: 'skipped',
        duration: 9,
        requirementsRefs: ['REQ-2'],
      },
    ]);

    expect(result.data.traceLinks).toEqual([
      { requirementId: 'REQ-1', testCaseId: 'TC-1', relationshipType: 'validates' },
      { requirementId: 'REQ-2', testCaseId: '202', relationshipType: 'verifies' },
    ]);

    expect(result.data.attachments).toEqual([
      {
        itemId: 'REQ-1',
        itemType: 'requirement',
        filename: 'locks.pdf',
        url: 'https://jama.example.com/attachments/att-req-1',
        size: 2048,
        contentType: 'application/pdf',
        createdAt: '2024-01-01T00:00:00Z',
      },
      {
        itemId: 'TC-1',
        itemType: 'TEST_CASE',
        filename: 'results.txt',
        url: 'https://jama.example.com/attachments/att-tc-1',
        size: 512,
        contentType: 'text/plain',
        createdAt: '2024-01-02T00:00:00Z',
      },
    ]);

    expect(result.data.evidenceIndex).toEqual({});
    expect(typeof result.data.generatedAt).toBe('string');
    expect(Number.isNaN(Date.parse(result.data.generatedAt))).toBe(false);

    expect(result.warnings).toEqual([
      'Requirement REQ-2 is missing a name.',
      'Test case 202 is missing a name.',
      'Encountered relationship with missing endpoint identifiers.',
    ]);

    expect(mockedRequestJson).toHaveBeenCalledTimes(8);
    const firstCallOptions = mockedRequestJson.mock.calls[0][0];
    expect(firstCallOptions.headers).toEqual({ Authorization: 'Bearer secret-token' });
    expect((firstCallOptions.url as URL).searchParams.get('pageSize')).toBe('25');
  });

  it('retries on rate limits, honors retry-after headers and stops after max pages', async () => {
    const attempts = new Map<string, number>();

    mockedRequestJson.mockImplementation(async (options) => {
      const url = options.url instanceof URL ? options.url : new URL(options.url);
      const key = url.toString();
      const count = (attempts.get(key) ?? 0) + 1;
      attempts.set(key, count);

      const attachmentMatch = url.pathname.match(/\/items\/(\d+)\/attachments$/u);
      if (attachmentMatch) {
        const itemId = attachmentMatch[1];
        if (itemId === '1' && count === 1) {
          throw new HttpError(429, 'Too Many Requests', 'rate limited', { 'retry-after': '0' });
        }
        if (itemId === '1') {
          return {
            data: [
              {
                id: 'att-1',
                fileName: 'requirement-1.pdf',
                downloadUrl: 'https://jama.example.com/files/att-1',
                size: 1024,
                contentType: 'application/pdf',
              },
            ],
          };
        }

        return { data: [] };
      }

      if (url.pathname.includes('/items') && url.searchParams.get('itemType') === 'REQUIREMENT') {
        if (!url.searchParams.has('cursor') && count === 1) {
          throw new HttpError(429, 'Too Many Requests', 'rate limited', { 'retry-after': '0' });
        }

        if (!url.searchParams.has('cursor')) {
          return {
            data: [
              { id: 1, documentKey: 'REQ-1', fields: { name: 'Requirement 1', status: 'Approved' } },
            ],
            meta: {
              pageInfo: {
                next: 'https://jama.example.com/rest/latest/projects/99/items?itemType=REQUIREMENT&cursor=page-2',
              },
            },
          };
        }

        if (url.searchParams.get('cursor') === 'page-2') {
          return {
            data: [
              { id: 2, documentKey: 'REQ-2', fields: { name: 'Requirement 2', status: 'Verified' } },
            ],
            meta: {
              pageInfo: {
                next: 'https://jama.example.com/rest/latest/projects/99/items?itemType=REQUIREMENT&cursor=page-3',
              },
            },
          };
        }

        if (url.searchParams.get('cursor') === 'page-3') {
          return {
            data: [
              { id: 3, documentKey: 'REQ-3', fields: { name: 'Requirement 3', status: 'Draft' } },
            ],
          };
        }
      }

      if (url.pathname.includes('/items') && url.searchParams.get('itemType') === 'TEST_CASE') {
        return { data: [] };
      }

      if (url.pathname.includes('/relationships')) {
        return { data: [] };
      }

      throw new Error(`Unexpected URL: ${url.toString()}`);
    });

    const result = await fetchJamaArtifacts({
      baseUrl: 'https://jama.example.com',
      projectId: 99,
      token: 'retry-token',
      pageSize: 2,
      maxPages: 2,
      rateLimitDelaysMs: [0, 0, 0],
    });

    expect(result.data.requirements).toHaveLength(2);
    expect(result.data.requirements.map((req) => req.id)).toEqual(['REQ-1', 'REQ-2']);
    expect(result.data.objectives).toEqual([]);
    expect(result.data.testResults).toHaveLength(0);
    expect(result.data.traceLinks).toHaveLength(0);
    expect(result.data.attachments).toEqual([
      {
        itemId: 'REQ-1',
        itemType: 'requirement',
        filename: 'requirement-1.pdf',
        url: 'https://jama.example.com/files/att-1',
        size: 1024,
        contentType: 'application/pdf',
        createdAt: undefined,
      },
    ]);
    expect(result.warnings).toHaveLength(0);

    const requestUrls = mockedRequestJson.mock.calls.map((call) => {
      const url = call[0].url as URL;
      return url.toString();
    });

    expect(requestUrls.filter((href) => href.includes('itemType=REQUIREMENT'))).toEqual([
      'https://jama.example.com/rest/latest/projects/99/items?itemType=REQUIREMENT&pageSize=2',
      'https://jama.example.com/rest/latest/projects/99/items?itemType=REQUIREMENT&pageSize=2',
      'https://jama.example.com/rest/latest/projects/99/items?itemType=REQUIREMENT&cursor=page-2',
    ]);

    expect(requestUrls.some((href) => href.includes('cursor=page-3'))).toBe(false);
  });

  it('emits warnings when attachment requests fail or return malformed payloads', async () => {
    mockedRequestJson.mockImplementation(async (options) => {
      const url = options.url instanceof URL ? options.url : new URL(options.url);
      const attachmentMatch = url.pathname.match(/\/items\/(\d+)\/attachments$/u);
      if (attachmentMatch) {
        const itemId = attachmentMatch[1];
        if (itemId === '10') {
          throw new HttpError(500, 'Internal Server Error', 'failure');
        }

        if (itemId === '20') {
          return {
            data: [
              null,
              {
                id: '',
                fileName: 'orphan.txt',
                contentType: 'text/plain',
              },
            ],
          };
        }

        return { data: [] };
      }

      if (url.pathname.includes('/items') && url.searchParams.get('itemType') === 'REQUIREMENT') {
        return {
          data: [
            { id: 10, documentKey: 'REQ-10', fields: { name: 'Requirement 10', status: 'Approved' } },
          ],
        };
      }

      if (url.pathname.includes('/items') && url.searchParams.get('itemType') === 'TEST_CASE') {
        return {
          data: [
            { id: 20, documentKey: 'TC-20', fields: { name: 'Test 20', status: 'Pass', executionTime: 1 } },
          ],
        };
      }

      if (url.pathname.includes('/relationships')) {
        return { data: [] };
      }

      throw new Error(`Unexpected URL: ${url.toString()}`);
    });

    const result = await fetchJamaArtifacts({
      baseUrl: 'https://jama.example.com',
      projectId: 'WARN',
      token: 'warning-token',
    });

    expect(result.data.attachments).toEqual([
      {
        itemId: 'TC-20',
        itemType: 'testCase',
        filename: 'orphan.txt',
        url: undefined,
        size: undefined,
        contentType: 'text/plain',
        createdAt: undefined,
      },
    ]);

    expect(result.warnings).toEqual([
      'Failed to fetch attachments for item REQ-10: 500 failure.',
      'Received malformed attachment payload for item TC-20.',
      'Skipped attachment for item TC-20 because it was missing an identifier.',
    ]);
  });
});
