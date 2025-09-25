import {
  ApiError,
  approveWorkspaceSignoff,
  buildAuthHeaders,
  createAdminApiKey,
  createReview,
  createWorkspaceComment,
  deleteAdminApiKey,
  deleteAdminUser,
  deleteAdminRole,
  getAdminApiKey,
  listAdminApiKeys,
  listAdminRoles,
  listAdminUsers,
  listAuditLogs,
  listJobs,
  listReviews,
  requestWorkspaceSignoff,
  rotateAdminApiKey,
  updateAdminRole,
  updateAdminUser,
  updateReview,
  updateWorkspaceDocument,
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

    (global.fetch as jest.Mock).mockResolvedValue(createResponse({ body: { users: [] } }));
    await listAdminUsers(credentials);
    adminCall = (global.fetch as jest.Mock).mock.calls[2] as [string, RequestInit];
    expect(adminCall[0]).toContain('/v1/admin/users');

    (global.fetch as jest.Mock).mockResolvedValue(createResponse({ body: { user: { email: 'a@b.c', roleId: 'role' } } }));
    await updateAdminUser({ ...credentials, userId: 'u1', email: 'a@b.c', roleId: 'role' });
    adminCall = (global.fetch as jest.Mock).mock.calls[3] as [string, RequestInit];
    expect(adminCall[0]).toContain('/v1/admin/users/u1');
    expect(adminCall[1]).toMatchObject({ method: 'PUT' });

    (global.fetch as jest.Mock).mockResolvedValue(createResponse({ body: { apiKeys: [] } }));
    await listAdminApiKeys(credentials);
    adminCall = (global.fetch as jest.Mock).mock.calls[4] as [string, RequestInit];
    expect(adminCall[0]).toContain('/v1/admin/api-keys');

    (global.fetch as jest.Mock).mockResolvedValue(
      createResponse({ body: { apiKey: { name: 'svc', scopes: [] }, secret: 'shh' } }),
    );
    await createAdminApiKey({ ...credentials, name: 'svc', scopes: [] });
    adminCall = (global.fetch as jest.Mock).mock.calls[5] as [string, RequestInit];
    expect(adminCall[0]).toContain('/v1/admin/api-keys');
    expect(adminCall[1]).toMatchObject({ method: 'POST' });

    (global.fetch as jest.Mock).mockResolvedValue(createResponse({ body: { apiKey: { name: 'svc', scopes: [] } } }));
    await getAdminApiKey({ ...credentials, keyId: 'key-1' });
    adminCall = (global.fetch as jest.Mock).mock.calls[6] as [string, RequestInit];
    expect(adminCall[0]).toContain('/v1/admin/api-keys/key-1');
    expect(adminCall[1]).toMatchObject({ method: 'GET' });

    (global.fetch as jest.Mock).mockResolvedValue(
      createResponse({ body: { apiKey: { name: 'svc', scopes: [] }, secret: 'new' } }),
    );
    await rotateAdminApiKey({ ...credentials, keyId: 'key-1', name: 'svc', scopes: [] });
    adminCall = (global.fetch as jest.Mock).mock.calls[7] as [string, RequestInit];
    expect(adminCall[0]).toContain('/v1/admin/api-keys/key-1');
    expect(adminCall[1]).toMatchObject({ method: 'PUT' });

    (global.fetch as jest.Mock).mockResolvedValue(createResponse({ body: { success: true } }));
    await deleteAdminUser({ ...credentials, userId: 'u1' });
    adminCall = (global.fetch as jest.Mock).mock.calls[8] as [string, RequestInit];
    expect(adminCall[0]).toContain('/v1/admin/users/u1');
    expect(adminCall[1]).toMatchObject({ method: 'DELETE' });

    (global.fetch as jest.Mock).mockResolvedValue(createResponse({ body: { success: true } }));
    await deleteAdminRole({ ...credentials, roleId: 'role-1' });
    adminCall = (global.fetch as jest.Mock).mock.calls[9] as [string, RequestInit];
    expect(adminCall[0]).toContain('/v1/admin/roles/role-1');
    expect(adminCall[1]).toMatchObject({ method: 'DELETE' });

    (global.fetch as jest.Mock).mockResolvedValue(createResponse({ body: { success: true } }));
    await deleteAdminApiKey({ ...credentials, keyId: 'key-1' });
    adminCall = (global.fetch as jest.Mock).mock.calls[10] as [string, RequestInit];
    expect(adminCall[0]).toContain('/v1/admin/api-keys/key-1');
    expect(adminCall[1]).toMatchObject({ method: 'DELETE' });
  });
});
