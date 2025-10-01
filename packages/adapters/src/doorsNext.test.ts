import { createHash } from 'crypto';
import { promises as fs } from 'fs';
import path from 'path';
import { Readable } from 'stream';

import type { DoorsNextHttpRequest, DoorsNextHttpResponse } from './doorsNext';
import { fetchDoorsNextArtifacts } from './doorsNext';

describe('fetchDoorsNextArtifacts', () => {
  it('aggregates paginated resources and extracts relationships', async () => {
    const baseDir = path.join(process.cwd(), 'test-output', `doorsNext-${Date.now()}`);
    const attachmentsDir = path.join(baseDir, 'attachments', 'doorsNext');
    const requirementAttachmentBody = 'spec-pdf-content';

    const requestMock = jest.fn(async (request: DoorsNextHttpRequest): Promise<DoorsNextHttpResponse> => {
      const target = typeof request.url === 'string' ? request.url : request.url.toString();

      if (target.includes('/rm/Engineering/artifacts?page=2')) {
        return {
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
        };
      }

      if (target.includes('/rm/Engineering/artifacts/REQ-1/attachments')) {
        return {
          status: 200,
          headers: { 'content-type': 'application/json' },
          body: {
            members: [
              {
                id: 'ATT-1',
                title: 'SRS Extract',
                fileName: 'spec.pdf',
                contentType: 'application/pdf',
                size: requirementAttachmentBody.length,
                downloadUrl:
                  'https://doors.example.com/rm/Engineering/artifacts/REQ-1/attachments/ATT-1/content',
              },
            ],
          },
        };
      }

      if (target.includes('/rm/Engineering/artifacts/TEST-1/attachments')) {
        return {
          status: 200,
          headers: { 'content-type': 'application/json' },
          body: { members: [] },
        };
      }

      if (target.includes('/rm/Engineering/artifacts?oslc.pageSize=200')) {
        return {
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
        };
      }

      throw new Error(`Unexpected request for ${target}`);
    });

    const attachmentDownload = jest.fn(async () => ({
      status: 200,
      headers: { 'content-length': String(Buffer.byteLength(requirementAttachmentBody)) },
      stream: Readable.from([Buffer.from(requirementAttachmentBody, 'utf8')]),
    }));

    await fs.rm(baseDir, { recursive: true, force: true }).catch(() => undefined);

    const result = await fetchDoorsNextArtifacts({
      baseUrl: 'https://doors.example.com',
      projectArea: 'Engineering',
      accessToken: 'token-123',
      request: requestMock,
      attachmentsDir,
      attachmentDownload,
    });

    const attachmentPath = result.data.attachments[0]?.path ?? '';
    const attachmentAbsolute = path.resolve(process.cwd(), attachmentPath);
    const attachmentHash = createHash('sha256').update(requirementAttachmentBody).digest('hex');

    expect(requestMock).toHaveBeenCalled();
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
    expect(result.data.attachments).toEqual([
      {
        id: 'ATT-1',
        artifactId: 'REQ-1',
        title: 'SRS Extract',
        filename: 'spec.pdf',
        contentType: 'application/pdf',
        size: requirementAttachmentBody.length,
        path: attachmentPath,
        sha256: attachmentHash,
      },
    ]);
    expect(result.data.etagCache).toMatchObject({
      'https://doors.example.com/rm/Engineering/artifacts?oslc.pageSize=200': '"page-1"',
      'https://doors.example.com/rm/Engineering/artifacts?page=2': '"page-2"',
    });
    await expect(fs.stat(attachmentAbsolute)).resolves.toMatchObject({ isFile: expect.any(Function) });

    await fs.rm(baseDir, { recursive: true, force: true }).catch(() => undefined);
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

  it('refreshes OAuth token when attachment requests return 401', async () => {
    const baseDir = path.join(process.cwd(), 'test-output', `doorsNext-${Date.now()}-oauth`);
    const attachmentsDir = path.join(baseDir, 'attachments', 'doorsNext');
    let attachmentCalls = 0;
    const seenAuthHeaders: string[] = [];

    const requestMock = jest.fn(async (request: DoorsNextHttpRequest): Promise<DoorsNextHttpResponse> => {
      const target = typeof request.url === 'string' ? request.url : request.url.toString();

      if (target === 'https://doors.example.com/oauth/token') {
        expect(request.method).toBe('POST');
        return {
          status: 200,
          headers: { 'content-type': 'application/json' },
          body: { access_token: 'new-token' },
        };
      }

      if (target.includes('/rm/Engineering/artifacts?oslc.pageSize=200')) {
        return {
          status: 200,
          headers: { 'content-type': 'application/json' },
          body: { members: [{ id: 'REQ-2', type: 'requirement', title: 'Encrypted backups' }] },
        };
      }

      if (target.includes('/rm/Engineering/artifacts/REQ-2/attachments')) {
        if (request.headers?.Authorization) {
          seenAuthHeaders.push(request.headers.Authorization);
        }
        attachmentCalls += 1;
        if (attachmentCalls === 1) {
          return { status: 401, headers: {} };
        }
        return {
          status: 200,
          headers: { 'content-type': 'application/json' },
          body: {
            members: [
              {
                id: 'ATT-2',
                title: 'Backup Policy',
                fileName: 'policy.txt',
                downloadUrl:
                  'https://doors.example.com/rm/Engineering/artifacts/REQ-2/attachments/ATT-2/content',
              },
            ],
          },
        };
      }

      throw new Error(`Unexpected request to ${target}`);
    });

    const attachmentDownload = jest.fn(async () => ({
      status: 200,
      headers: {},
      stream: Readable.from([Buffer.from('policy-body', 'utf8')]),
    }));

    await fs.rm(baseDir, { recursive: true, force: true }).catch(() => undefined);

    const result = await fetchDoorsNextArtifacts({
      baseUrl: 'https://doors.example.com',
      projectArea: 'Engineering',
      accessToken: 'expired-token',
      oauth: {
        tokenUrl: 'https://doors.example.com/oauth/token',
        clientId: 'client',
        clientSecret: 'secret',
      },
      request: requestMock,
      attachmentsDir,
      attachmentDownload,
    });

    expect(seenAuthHeaders).toEqual(['Bearer expired-token', 'Bearer new-token']);
    expect(attachmentDownload).toHaveBeenCalledTimes(1);
    expect(result.data.attachments).toHaveLength(1);
    expect(result.warnings).toEqual([]);

    await fs.rm(baseDir, { recursive: true, force: true }).catch(() => undefined);
  });

  it('retries attachment listing after 429 responses', async () => {
    const baseDir = path.join(process.cwd(), 'test-output', `doorsNext-${Date.now()}-throttle`);
    const attachmentsDir = path.join(baseDir, 'attachments', 'doorsNext');
    let attachmentCalls = 0;

    const requestMock = jest.fn(async (request: DoorsNextHttpRequest): Promise<DoorsNextHttpResponse> => {
      const target = typeof request.url === 'string' ? request.url : request.url.toString();

      if (target.includes('/rm/Engineering/artifacts?oslc.pageSize=200')) {
        return {
          status: 200,
          headers: { 'content-type': 'application/json' },
          body: { members: [{ id: 'REQ-3', type: 'requirement', title: 'Audit logging' }] },
        };
      }

      if (target.includes('/rm/Engineering/artifacts/REQ-3/attachments')) {
        attachmentCalls += 1;
        if (attachmentCalls === 1) {
          return { status: 429, headers: { 'retry-after': '0' } };
        }
        return {
          status: 200,
          headers: { 'content-type': 'application/json' },
          body: {
            members: [
              {
                id: 'ATT-3',
                title: 'Audit Plan',
                fileName: 'plan.txt',
                downloadUrl:
                  'https://doors.example.com/rm/Engineering/artifacts/REQ-3/attachments/ATT-3/content',
              },
            ],
          },
        };
      }

      throw new Error(`Unexpected request to ${target}`);
    });

    const attachmentDownload = jest.fn(async () => ({
      status: 200,
      headers: {},
      stream: Readable.from([Buffer.from('audit-plan', 'utf8')]),
    }));

    await fs.rm(baseDir, { recursive: true, force: true }).catch(() => undefined);

    const result = await fetchDoorsNextArtifacts({
      baseUrl: 'https://doors.example.com',
      projectArea: 'Engineering',
      accessToken: 'token-xyz',
      request: requestMock,
      attachmentsDir,
      attachmentDownload,
      rateLimitDelaysMs: [0],
    });

    expect(attachmentCalls).toBeGreaterThan(1);
    expect(attachmentDownload).toHaveBeenCalledTimes(1);
    expect(result.data.attachments).toHaveLength(1);
    expect(result.warnings).toEqual([]);

    await fs.rm(baseDir, { recursive: true, force: true }).catch(() => undefined);
  });

  it('records warnings when attachment payloads are malformed', async () => {
    const baseDir = path.join(process.cwd(), 'test-output', `doorsNext-${Date.now()}-malformed`);
    const attachmentsDir = path.join(baseDir, 'attachments', 'doorsNext');

    const requestMock = jest.fn(async (request: DoorsNextHttpRequest): Promise<DoorsNextHttpResponse> => {
      const target = typeof request.url === 'string' ? request.url : request.url.toString();

      if (target.includes('/rm/Engineering/artifacts?oslc.pageSize=200')) {
        return {
          status: 200,
          headers: { 'content-type': 'application/json' },
          body: { members: [{ id: 'REQ-4', type: 'requirement', title: 'Secure boot' }] },
        };
      }

      if (target.includes('/rm/Engineering/artifacts/REQ-4/attachments')) {
        return {
          status: 200,
          headers: { 'content-type': 'application/json' },
          body: {
            members: [
              {
                id: 'ATT-4',
                title: 'Broken attachment',
              },
            ],
          },
        };
      }

      throw new Error(`Unexpected request to ${target}`);
    });

    const attachmentDownload = jest.fn();

    await fs.rm(baseDir, { recursive: true, force: true }).catch(() => undefined);

    const result = await fetchDoorsNextArtifacts({
      baseUrl: 'https://doors.example.com',
      projectArea: 'Engineering',
      accessToken: 'token-xyz',
      request: requestMock,
      attachmentsDir,
      attachmentDownload,
    });

    expect(result.data.attachments).toHaveLength(0);
    expect(result.warnings).toContain(
      'DOORS Next attachment ATT-4 for artifact REQ-4 skipped due to missing download URL.',
    );
    expect(attachmentDownload).not.toHaveBeenCalled();

    await fs.rm(baseDir, { recursive: true, force: true }).catch(() => undefined);
  });
});
