import {
  ApiError,
  approveWorkspaceSignoff,
  buildAuthHeaders,
  createAdminApiKey,
  createAdminUser,
  createReview,
  createWorkspaceComment,
  deleteAdminApiKey,
  deleteAdminUser,
  deleteAdminRole,
  getAdminApiKey,
  getWorkspaceDocumentThread,
  importArtifacts,
  listAdminApiKeys,
  listAdminRoles,
  listAdminUsers,
  listAuditLogs,
  listJobs,
  listManifestProofs,
  listReviews,
  requestWorkspaceSignoff,
  rotateAdminApiKey,
  updateAdminRole,
  updateAdminUser,
  updateReview,
  updateWorkspaceDocument,
  getManifestProof,
  fetchComplianceSummary,
} from './api';

const IMPORT_META_OVERRIDE_KEY = '__SOIPACK_IMPORT_META_ENV__';

describe('buildAuthHeaders', () => {
  it('returns sanitized headers when token and license are provided', () => {
    const headers = buildAuthHeaders({ token: ' demo-token ', license: '  ZXhhbXBsZV9saWNlbnNl\n' });
    expect(headers.Authorization).toBe('Bearer demo-token');
    expect(headers['X-SOIPACK-License']).toBe('ZXhhbXBsZV9saWNlbnNl');
  });

  it('throws an error when the token is missing', () => {
    expect(() => buildAuthHeaders({ token: '   ', license: 'ZW1wdHk=' })).toThrow('Token gereklidir.');
  });

  it('throws an error when the license is missing', () => {
    expect(() => buildAuthHeaders({ token: 'valid', license: '   ' })).toThrow('Lisans gereklidir.');
  });
});

describe('resolveBaseUrl', () => {
  afterEach(() => {
    delete (globalThis as Record<string, unknown>)[IMPORT_META_OVERRIDE_KEY];
    delete process.env.VITE_API_BASE_URL;
    jest.resetModules();
  });

  it('prefers values from import.meta.env when available', async () => {
    (globalThis as Record<string, unknown>)[IMPORT_META_OVERRIDE_KEY] = {
      VITE_API_BASE_URL: 'https://import-meta.example/api/',
    };
    process.env.VITE_API_BASE_URL = 'https://process-env.example/base/';

    await jest.isolateModulesAsync(async () => {
      const module = await import('./api');
      expect(module.__test__.getConfiguredBaseUrl()).toBe('https://import-meta.example/api');
    });
  });

  it('falls back to process.env when import.meta.env is unavailable', async () => {
    process.env.VITE_API_BASE_URL = 'https://process-env.example/base/';

    await jest.isolateModulesAsync(async () => {
      const module = await import('./api');
      expect(module.__test__.getConfiguredBaseUrl()).toBe('https://process-env.example/base');
    });
  });

  it('returns an empty base URL when no overrides exist', async () => {
    await jest.isolateModulesAsync(async () => {
      const module = await import('./api');
      expect(module.__test__.getConfiguredBaseUrl()).toBe('');
      expect(module.__test__.resolveBaseUrl()).toBe('');
    });
  });
});

const createResponse = ({
  ok = true,
  status = ok ? 200 : 400,
  statusText = ok ? 'OK' : 'Error',
  body,
  jsonError,
}: {
  ok?: boolean;
  status?: number;
  statusText?: string;
  body?: unknown;
  jsonError?: Error;
}): Response => {
  return {
    ok,
    status,
    statusText,
    json: jest.fn(async () => {
      if (jsonError) {
        throw jsonError;
      }
      return body;
    }),
    text: jest.fn(async () => (typeof body === 'string' ? body : JSON.stringify(body ?? ''))),
  } as unknown as Response;
};

describe('API integrations', () => {
  beforeEach(() => {
    global.fetch = jest.fn();
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  const credentials = { token: 'token', license: 'license' };

  it('fetches compliance summary payloads', async () => {
    const payload = {
      computedAt: '2024-10-01T08:00:00Z',
      latest: {
        id: 'comp-1',
        createdAt: '2024-10-01T07:59:00Z',
        project: 'Demo',
        level: 'B',
        generatedAt: '2024-10-01T07:30:00Z',
        summary: { total: 3, covered: 2, partial: 1, missing: 0 },
        coverage: { statements: 87.5, functions: 66.1 },
        gaps: { missingIds: [], partialIds: ['REQ-2'], openObjectiveCount: 1 },
      },
    } as const;

    (global.fetch as jest.Mock).mockResolvedValue(createResponse({ body: payload }));

    const response = await fetchComplianceSummary(credentials);

    expect(global.fetch).toHaveBeenCalledWith('http://localhost/v1/compliance/summary', {
      method: 'GET',
      headers: { Authorization: 'Bearer token', 'X-SOIPACK-License': 'license' },
      signal: undefined,
    });
    expect(response).toEqual(payload);
  });

  it('throws ApiError when compliance summary request fails', async () => {
    (global.fetch as jest.Mock).mockResolvedValue(
      createResponse({ ok: false, status: 502, body: { error: { message: 'Upstream down' } } }),
    );

    await expect(fetchComplianceSummary(credentials)).rejects.toBeInstanceOf(ApiError);
  });

  it('fetches audit logs with query parameters', async () => {
    (global.fetch as jest.Mock).mockResolvedValue(
      createResponse({ body: { items: [], hasMore: false, nextOffset: null } }),
    );

    await listAuditLogs({
      ...credentials,
      actor: 'alice',
      limit: 10,
      offset: 5,
      order: 'asc',
    });

    const [url, options] = (global.fetch as jest.Mock).mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/audit-logs?actor=alice&limit=10&offset=5&order=asc');
    expect(options).toMatchObject({
      method: 'GET',
      headers: {
        Authorization: 'Bearer token',
        'X-SOIPACK-License': 'license',
      },
    });
  });

  it('throws ApiError for failed audit log responses', async () => {
    (global.fetch as jest.Mock).mockResolvedValue(
      createResponse({ ok: false, status: 403, body: { error: { message: 'Denied' } } }),
    );

    await expect(listAuditLogs({ ...credentials })).rejects.toBeInstanceOf(ApiError);
  });

  it('creates and updates reviews with correct payloads', async () => {
    (global.fetch as jest.Mock).mockResolvedValue(
      createResponse({ body: { review: { id: 'r1', hash: 'h1' } } }),
    );

    await createReview({
      ...credentials,
      target: { kind: 'analyze', reference: null },
      approvers: ['approver-1'],
    });

    let call = (global.fetch as jest.Mock).mock.calls[0] as [string, RequestInit];
    expect(call[0]).toContain('/v1/reviews');
    expect(call[1]).toMatchObject({
      method: 'POST',
      body: JSON.stringify({
        target: { kind: 'analyze', reference: null },
        approvers: ['approver-1'],
      }),
    });

    await updateReview({
      ...credentials,
      id: 'r1',
      action: 'submit',
      expectedHash: 'h1',
    });

    call = (global.fetch as jest.Mock).mock.calls[1] as [string, RequestInit];
    expect(call[0]).toContain('/v1/reviews/r1');
    expect(call[1]).toMatchObject({
      method: 'PATCH',
      body: JSON.stringify({ action: 'submit', expectedHash: 'h1' }),
    });
  });

  it('lists reviews with status filters', async () => {
    (global.fetch as jest.Mock).mockResolvedValue(
      createResponse({ body: { reviews: [], hasMore: false, nextOffset: null } }),
    );

    await listReviews({
      ...credentials,
      status: ['pending', 'approved'],
      limit: 25,
    });

    const reviewCall = (global.fetch as jest.Mock).mock.calls[0] as [string, RequestInit];
    expect(reviewCall[0]).toContain('/v1/reviews?status=pending&status=approved&limit=25');
    expect(reviewCall[1]).toMatchObject({ method: 'GET' });
  });

  it('fetches manifest proof listings with encoded identifiers', async () => {
    (global.fetch as jest.Mock).mockResolvedValue(
      createResponse({ body: { manifestId: 'm1', jobId: 'j1', merkle: null, files: [] } }),
    );

    await listManifestProofs({ ...credentials, manifestId: 'manifest/with/slash' });

    const [url, options] = (global.fetch as jest.Mock).mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/v1/manifests/manifest%2Fwith%2Fslash/proofs');
    expect(options).toMatchObject({ method: 'GET' });
  });

  it('retrieves individual manifest proof payloads', async () => {
    (global.fetch as jest.Mock).mockResolvedValue(
      createResponse({
        body: {
          manifestId: 'm1',
          jobId: 'j1',
          path: 'reports/manifest.json',
          sha256: 'abc',
          verified: true,
          merkle: null,
          proof: { algorithm: 'ledger-merkle-v1', merkleRoot: 'root', proof: '{"path":[]}' },
        },
      }),
    );

    const result = await getManifestProof({
      ...credentials,
      manifestId: 'm1',
      filePath: 'reports/manifest.json',
    });

    expect(result.path).toBe('reports/manifest.json');
    const [url] = (global.fetch as jest.Mock).mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/v1/manifests/m1/proofs/reports%2Fmanifest.json');
  });

  it('updates workspace documents and comments', async () => {
    (global.fetch as jest.Mock).mockResolvedValue(
      createResponse({ body: { document: { id: 'doc1' } } }),
    );

    await updateWorkspaceDocument({
      ...credentials,
      workspaceId: 'ws1',
      documentId: 'doc1',
      expectedHash: 'hash',
      content: { requirements: [] },
    });

    let workspaceCall = (global.fetch as jest.Mock).mock.calls[0] as [string, RequestInit];
    expect(workspaceCall[0]).toContain('/v1/workspaces/ws1/documents/doc1');
    expect(workspaceCall[1]).toMatchObject({ method: 'PUT' });

    (global.fetch as jest.Mock).mockResolvedValue(
      createResponse({ body: { comment: { id: 'comment1' } } }),
    );

    await createWorkspaceComment({
      ...credentials,
      workspaceId: 'ws1',
      documentId: 'doc1',
      revisionId: 'rev1',
      body: 'Looks good',
    });

    workspaceCall = (global.fetch as jest.Mock).mock.calls[1] as [string, RequestInit];
    expect(workspaceCall[0]).toContain('/v1/workspaces/ws1/documents/doc1/comments');
    expect(workspaceCall[1]).toMatchObject({ method: 'POST' });
  });

  it('fetches workspace document threads with normalized hashes', async () => {
    (global.fetch as jest.Mock).mockResolvedValue(
      createResponse({
        body: {
          document: {
            id: 'doc1',
            tenantId: 'tenant-1',
            workspaceId: 'ws1',
            kind: 'requirements',
            title: 'Requirements',
            createdAt: '2024-01-01T00:00:00.000Z',
            updatedAt: '2024-01-01T00:00:00.000Z',
            revision: {
              id: 'rev1',
              number: 1,
              hash: 'ABCDEF1234',
              authorId: 'alice',
              createdAt: '2024-01-01T00:00:00.000Z',
              content: [],
            },
          },
          comments: [],
          signoffs: [
            {
              id: 'signoff-1',
              documentId: 'doc1',
              revisionId: 'rev1',
              tenantId: 'tenant-1',
              workspaceId: 'ws1',
              revisionHash: 'ABCDEF1234',
              status: 'pending',
              requestedBy: 'alice',
              requestedFor: 'qa',
              createdAt: '2024-01-01T00:00:00.000Z',
              updatedAt: '2024-01-01T00:00:00.000Z',
            },
          ],
          nextCursor: 'cursor-1',
        },
      }),
    );

    const thread = await getWorkspaceDocumentThread({
      ...credentials,
      workspaceId: 'ws1',
      documentId: 'doc1',
      cursor: 'cursor-0',
      limit: 10,
    });

    const [url, options] = (global.fetch as jest.Mock).mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/v1/workspaces/ws1/documents/doc1?cursor=cursor-0&limit=10');
    expect(options).toMatchObject({ method: 'GET' });
    expect(thread.document.revision.hash).toBe('abcdef1234');
    expect(thread.signoffs[0]?.revisionHash).toBe('abcdef1234');
    expect(thread.nextCursor).toBe('cursor-1');
  });

  it('propagates errors when document thread request fails', async () => {
    (global.fetch as jest.Mock).mockResolvedValue(
      createResponse({ ok: false, status: 404, body: { error: { message: 'Missing' } } }),
    );

    await expect(
      getWorkspaceDocumentThread({
        ...credentials,
        workspaceId: 'ws1',
        documentId: 'doc1',
      }),
    ).rejects.toBeInstanceOf(ApiError);
  });

  it('requests and approves workspace signoffs', async () => {
    (global.fetch as jest.Mock).mockResolvedValue(
      createResponse({ body: { signoff: { id: 's1' } } }),
    );

    await requestWorkspaceSignoff({
      ...credentials,
      workspaceId: 'ws1',
      documentId: 'doc1',
      revisionId: 'rev1',
      requestedFor: 'approver',
    });

    let signoffCall = (global.fetch as jest.Mock).mock.calls[0] as [string, RequestInit];
    expect(signoffCall[0]).toContain('/v1/workspaces/ws1/signoffs');
    expect(signoffCall[1]).toMatchObject({ method: 'POST' });

    await approveWorkspaceSignoff({
      ...credentials,
      workspaceId: 'ws1',
      signoffId: 's1',
      signature: 'sig',
      timestamp: new Date().toISOString(),
    });

    signoffCall = (global.fetch as jest.Mock).mock.calls[1] as [string, RequestInit];
    expect(signoffCall[0]).toContain('/v1/workspaces/ws1/signoffs/s1');
    expect(signoffCall[1]).toMatchObject({ method: 'PATCH' });
  });

  it('provides queue metrics with filters', async () => {
    (global.fetch as jest.Mock).mockResolvedValue(createResponse({ body: { jobs: [] } }));

    await listJobs({
      ...credentials,
      status: ['queued', 'running'],
      kind: 'analyze',
      limit: 50,
    });

    const jobsCall = (global.fetch as jest.Mock).mock.calls[0] as [string, RequestInit];
    expect(jobsCall[0]).toContain('/v1/jobs?status=queued&status=running&kind=analyze&limit=50');
    expect(jobsCall[1]).toMatchObject({ method: 'GET' });
  });

  it('builds import form data for extended artifacts and independence', async () => {
    (global.fetch as jest.Mock).mockResolvedValue(
      createResponse({ body: { id: 'job-1', status: 'queued', reused: false } }),
    );

    const files = [
      new File(['design'], 'system-design.csv', { type: 'text/csv' }),
      new File(['defects'], 'critical-defects.xlsx', {
        type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      }),
      new File(['polyspace'], 'polyspace-results.zip', { type: 'application/zip' }),
      new File(['ldra'], 'ldra-run.tgz', { type: 'application/gzip' }),
      new File(['vector'], 'vectorcast-report.tar', { type: 'application/x-tar' }),
      new File(['qa'], 'qa-acceptance.log', { type: 'text/plain' }),
      new File(['qa'], 'qa-observations.txt', { type: 'text/plain' }),
      new File(['json'], 'objectives.json', { type: 'application/json' }),
      new File(['coverage'], 'coverage.info', { type: 'text/plain' }),
      new File(['jira'], 'requirements.csv', { type: 'text/csv' }),
    ];

    await importArtifacts({
      token: 'token',
      license: 'license',
      files,
      projectName: 'Extended Import',
      projectVersion: '1.0.0',
      independentSources: ['junit', 'lcov'],
      independentArtifacts: ['analysis', 'test'],
    });

    const [, options] = (global.fetch as jest.Mock).mock.calls[0] as [string, RequestInit];
    expect(options.method).toBe('POST');
    expect(options.body).toBeInstanceOf(FormData);

    const formData = options.body as FormData;
    const entries: Array<[string, FormDataEntryValue]> = [];
    formData.forEach((value, key) => {
      entries.push([key, value]);
    });
    const entryKeys = entries.map(([key]) => key);
    expect(entryKeys).toEqual(
      expect.arrayContaining(['designCsv', 'polyspace', 'ldra', 'vectorcast', 'qaLogs', 'jiraDefects']),
    );

    const defectEntries = formData.getAll('jiraDefects');
    expect(defectEntries).toHaveLength(1);
    expect(defectEntries[0]).toBeTruthy();


    const qaEntries = formData.getAll('qaLogs');
    expect(qaEntries).toHaveLength(2);
    expect(qaEntries.every((entry) => Boolean(entry))).toBe(true);

    expect(formData.get('independentSources')).toBe(JSON.stringify(['junit', 'lcov']));
    expect(formData.get('independentArtifacts')).toBe(JSON.stringify(['analysis', 'test']));
  });

  it('manages admin resources with authentication', async () => {
    (global.fetch as jest.Mock).mockResolvedValue(
      createResponse({ body: { roles: [], apiKeys: [], users: [] } }),
    );

    await listAdminRoles(credentials);
    let adminCall = (global.fetch as jest.Mock).mock.calls[0] as [string, RequestInit];
    expect(adminCall[0]).toContain('/v1/admin/roles');
    expect(adminCall[1]).toMatchObject({ method: 'GET' });

    (global.fetch as jest.Mock).mockResolvedValue(createResponse({ body: { role: { name: 'ops', permissions: [] } } }));
    await updateAdminRole({ ...credentials, roleId: 'role-1', name: 'ops', permissions: [] });
    adminCall = (global.fetch as jest.Mock).mock.calls[1] as [string, RequestInit];
    expect(adminCall[0]).toContain('/v1/admin/roles/role-1');
    expect(adminCall[1]).toMatchObject({ method: 'PUT' });

    (global.fetch as jest.Mock).mockResolvedValue(createResponse({ body: { apiKeys: [] } }));
    await listAdminApiKeys(credentials);
    adminCall = (global.fetch as jest.Mock).mock.calls[2] as [string, RequestInit];
    expect(adminCall[0]).toContain('/v1/admin/api-keys');

    (global.fetch as jest.Mock).mockResolvedValue(
      createResponse({ body: { apiKey: { name: 'svc', scopes: [] }, secret: 'shh' } }),
    );
    await createAdminApiKey({ ...credentials, name: 'svc', scopes: [] });
    adminCall = (global.fetch as jest.Mock).mock.calls[3] as [string, RequestInit];
    expect(adminCall[0]).toContain('/v1/admin/api-keys');
    expect(adminCall[1]).toMatchObject({ method: 'POST' });

    (global.fetch as jest.Mock).mockResolvedValue(createResponse({ body: { apiKey: { name: 'svc', scopes: [] } } }));
    await getAdminApiKey({ ...credentials, keyId: 'key-1' });
    adminCall = (global.fetch as jest.Mock).mock.calls[4] as [string, RequestInit];
    expect(adminCall[0]).toContain('/v1/admin/api-keys/key-1');
    expect(adminCall[1]).toMatchObject({ method: 'GET' });

    (global.fetch as jest.Mock).mockResolvedValue(
      createResponse({ body: { apiKey: { name: 'svc', scopes: [] }, secret: 'new' } }),
    );
    await rotateAdminApiKey({ ...credentials, keyId: 'key-1', name: 'svc', scopes: [] });
    adminCall = (global.fetch as jest.Mock).mock.calls[5] as [string, RequestInit];
    expect(adminCall[0]).toContain('/v1/admin/api-keys/key-1');
    expect(adminCall[1]).toMatchObject({ method: 'PUT' });

    (global.fetch as jest.Mock).mockResolvedValue(createResponse({ body: { success: true } }));
    await deleteAdminRole({ ...credentials, roleId: 'role-1' });
    adminCall = (global.fetch as jest.Mock).mock.calls[6] as [string, RequestInit];
    expect(adminCall[0]).toContain('/v1/admin/roles/role-1');
    expect(adminCall[1]).toMatchObject({ method: 'DELETE' });

    (global.fetch as jest.Mock).mockResolvedValue(createResponse({ body: { success: true } }));
    await deleteAdminApiKey({ ...credentials, keyId: 'key-1' });
    adminCall = (global.fetch as jest.Mock).mock.calls[7] as [string, RequestInit];
    expect(adminCall[0]).toContain('/v1/admin/api-keys/key-1');
    expect(adminCall[1]).toMatchObject({ method: 'DELETE' });
  });
});

describe('admin users', () => {
  const credentials = { token: 'token', license: 'license' };

  beforeEach(() => {
    global.fetch = jest.fn();
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  it('handles CRUD operations with role assignments and secret rotation', async () => {
    (global.fetch as jest.Mock)
      .mockResolvedValueOnce(
        createResponse({
          body: {
            users: [
              {
                id: 'u1',
                email: 'alice@example.com',
                roles: ['admin'],
                status: 'active',
              },
            ],
          },
        }),
      )
      .mockResolvedValueOnce(
        createResponse({
          body: {
            user: {
              id: 'u2',
              email: 'new@example.com',
              roles: ['admin'],
              status: 'invited',
            },
            secret: 'temp-secret',
          },
        }),
      )
      .mockResolvedValueOnce(
        createResponse({
          body: {
            user: {
              id: 'u2',
              email: 'new@example.com',
              roles: ['operator'],
              status: 'active',
            },
            secret: 'rotated-secret',
          },
        }),
      )
      .mockResolvedValueOnce(createResponse({ body: { success: true } }));

    const list = await listAdminUsers(credentials);
    expect(list.users).toHaveLength(1);
    expect(list.users[0]?.roles).toEqual(['admin']);

    await createAdminUser({
      ...credentials,
      email: 'new@example.com',
      roles: ['admin'],
      displayName: 'New Admin',
    });

    const createCall = (global.fetch as jest.Mock).mock.calls[1] as [string, RequestInit];
    expect(createCall[0]).toContain('/v1/admin/users');
    expect(createCall[1]?.method).toBe('POST');
    expect(JSON.parse((createCall[1]?.body as string) ?? '{}').roles).toEqual(['admin']);

    await updateAdminUser({
      ...credentials,
      userId: 'u2',
      email: 'new@example.com',
      roles: ['operator'],
      rotateSecret: true,
    });

    const updateCall = (global.fetch as jest.Mock).mock.calls[2] as [string, RequestInit];
    expect(updateCall[0]).toContain('/v1/admin/users/u2');
    expect(updateCall[1]?.method).toBe('PUT');
    const updatePayload = JSON.parse((updateCall[1]?.body as string) ?? '{}');
    expect(updatePayload.roles).toEqual(['operator']);
    expect(updatePayload.rotateSecret).toBe(true);

    await deleteAdminUser({ ...credentials, userId: 'u2' });
    const deleteCall = (global.fetch as jest.Mock).mock.calls[3] as [string, RequestInit];
    expect(deleteCall[0]).toContain('/v1/admin/users/u2');
    expect(deleteCall[1]?.method).toBe('DELETE');
  });

  it('propagates validation errors from the admin user endpoints', async () => {
    (global.fetch as jest.Mock).mockResolvedValue(
      createResponse({ ok: false, status: 422, body: { error: { message: 'ROLE_REQUIRED' } } }),
    );

    await expect(
      createAdminUser({
        ...credentials,
        email: 'bad@example.com',
        roles: [],
      }),
    ).rejects.toBeInstanceOf(ApiError);
  });
});
