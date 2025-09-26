import type { DoorsNextHttpRequest, DoorsNextHttpResponse } from './doorsNext';
import { fetchDoorsNextArtifacts } from './doorsNext';

describe('fetchDoorsNextArtifacts', () => {
  it('aggregates paginated resources and extracts relationships', async () => {
    const responses: DoorsNextHttpResponse[] = [
      {
        status: 200,
        headers: { 'content-type': 'application/json', etag: '"page-1"' },
        body: {
          members: [
            {
              id: 'REQ-1',
              title: 'Login shall require MFA',
              description: 'Requirement description',
              status: 'approved',
              type: 'requirement',
              about: 'https://doors.example.com/rm/resources/REQ-1',
              links: {
                elaboratedBy: ['https://doors.example.com/rm/resources/DES-1'],
                validatedBy: [{ id: 'TEST-1' }],
              },
            },
            {
              id: 'DES-1',
              title: 'MFA Architecture Diagram',
              description: 'Design description',
              status: 'allocated',
              type: 'design',
              about: 'https://doors.example.com/rm/resources/DES-1',
              requirements: ['REQ-1'],
              links: {
                satisfies: ['REQ-1'],
                implements: ['CODE:auth/mfa.ts'],
              },
            },
          ],
          next: 'https://doors.example.com/rm/Engineering/artifacts?page=2',
        },
      },
      {
        status: 200,
        headers: { 'content-type': 'application/json', etag: '"page-2"' },
        body: {
          members: [
            {
              id: 'TEST-1',
              title: 'MFA flow integration test',
              status: 'passed',
              type: 'testcase',
              durationMs: 1250,
              validates: ['REQ-1'],
              links: {
                tracesTo: ['REQ-1'],
              },
            },
          ],
        },
      },
    ];

    const requestMock = jest.fn(async (_request: DoorsNextHttpRequest) => {
      const response = responses.shift();
      if (!response) {
        throw new Error('Unexpected request');
      }
      return response;
    });

    const result = await fetchDoorsNextArtifacts({
      baseUrl: 'https://doors.example.com',
      projectArea: 'Engineering',
      accessToken: 'token-123',
      request: requestMock,
    });

    expect(requestMock).toHaveBeenCalledTimes(2);
    expect(result.warnings).toEqual([]);
    expect(result.data.requirements).toEqual([
      {
        id: 'REQ-1',
        title: 'Login shall require MFA',
        description: 'Requirement description',
        status: 'approved',
        type: 'requirement',
        url: 'https://doors.example.com/rm/resources/REQ-1',
      },
    ]);
    expect(result.data.designs).toEqual([
      {
        id: 'DES-1',
        title: 'MFA Architecture Diagram',
        description: 'Design description',
        status: 'allocated',
        type: 'design',
        url: 'https://doors.example.com/rm/resources/DES-1',
        requirementIds: ['REQ-1'],
        codeRefs: ['CODE:auth/mfa.ts'],
      },
    ]);
    expect(result.data.tests).toEqual([
      {
        id: 'TEST-1',
        name: 'MFA flow integration test',
        status: 'passed',
        durationMs: 1250,
        requirementIds: ['REQ-1'],
      },
    ]);
    expect(result.data.relationships).toEqual([
      { fromId: 'REQ-1', toId: 'DES-1', type: 'elaboratedBy' },
      { fromId: 'REQ-1', toId: 'TEST-1', type: 'validatedBy' },
      { fromId: 'DES-1', toId: 'REQ-1', type: 'satisfies' },
      { fromId: 'DES-1', toId: 'CODE:auth/mfa.ts', type: 'implements' },
      { fromId: 'TEST-1', toId: 'REQ-1', type: 'tracesTo' },
    ]);
    expect(result.data.etagCache).toMatchObject({
      'https://doors.example.com/rm/Engineering/artifacts?oslc.pageSize=200': '"page-1"',
      'https://doors.example.com/rm/Engineering/artifacts?page=2': '"page-2"',
    });
  });

  it('falls back to basic authentication when bearer token is rejected', async () => {
    const requestMock = jest
      .fn(async (request: DoorsNextHttpRequest): Promise<DoorsNextHttpResponse> => {
        if (request.headers?.Authorization?.startsWith('Bearer')) {
          return { status: 401, headers: {} };
        }
        expect(request.headers?.Authorization).toBe(`Basic ${Buffer.from('user:pass').toString('base64')}`);
        return { status: 200, headers: { 'content-type': 'application/json' }, body: { members: [] } };
      })
      .mockName('doorsNextAuthRequest');

    const result = await fetchDoorsNextArtifacts({
      baseUrl: 'https://doors.example.com',
      projectArea: 'Engineering',
      accessToken: 'expired-token',
      username: 'user',
      password: 'pass',
      request: requestMock,
    });

    expect(requestMock).toHaveBeenCalledTimes(2);
    expect(result.warnings).toContain('DOORS Next bearer token rejected, retrying with basic authentication.');
  });

  it('reuses cached ETags to avoid unnecessary downloads', async () => {
    const requestMock = jest.fn(async (request: DoorsNextHttpRequest): Promise<DoorsNextHttpResponse> => {
      expect(request.headers?.['If-None-Match']).toBe('"cached-etag"');
      return { status: 304, headers: { etag: '"cached-etag"' } };
    });

    const etagCache = {
      'https://doors.example.com/rm/Engineering/artifacts?oslc.pageSize=200': '"cached-etag"',
    };

    const result = await fetchDoorsNextArtifacts({
      baseUrl: 'https://doors.example.com',
      projectArea: 'Engineering',
      request: requestMock,
      etagCache,
    });

    expect(requestMock).toHaveBeenCalledTimes(1);
    expect(result.data.requirements).toEqual([]);
    expect(result.data.designs).toEqual([]);
    expect(result.data.tests).toEqual([]);
    expect(result.warnings).toEqual([]);
    expect(result.data.etagCache).toEqual(etagCache);
  });
});
