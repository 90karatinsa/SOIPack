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

    expect(result.data.evidenceIndex).toEqual({});
    expect(typeof result.data.generatedAt).toBe('string');
    expect(Number.isNaN(Date.parse(result.data.generatedAt))).toBe(false);

    expect(result.warnings).toEqual([
      'Requirement REQ-2 is missing a name.',
      'Test case 202 is missing a name.',
      'Encountered relationship with missing endpoint identifiers.',
    ]);

    expect(mockedRequestJson).toHaveBeenCalledTimes(3);
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
});
