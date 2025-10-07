import {
  ApiError,
  approveWorkspaceSignoff,
  buildAuthHeaders,
  buildReportAssets,
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
  fetchChangeRequests,
} from './api';

import type { ApiJob, PackJobResult, ReportJobResult } from '../types/pipeline';

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
    expect(response).toEqual({
      computedAt: payload.computedAt,
      latest: {
        ...payload.latest,
        changeImpact: [],
        independence: null,
      },
    });
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

  it('posts manual artefacts under dedicated fields and infers Simulink uploads', async () => {
    const files = [
      new File(['plan'], 'PSAC.PDF', { type: 'application/pdf' }),
      new File(['qa'], 'QA-RECORD.csv', { type: 'text/csv' }),
      new File(['json'], 'Simulink-Coverage.JSON', { type: 'application/json' }),
      new File(['zip'], 'model-coverage.zip', { type: 'application/zip' }),
      new File(['objectives'], 'objectives.json', { type: 'application/json' }),
    ];

    (global.fetch as jest.Mock).mockResolvedValue(createResponse({ body: { id: 'job-import' } }));

    await importArtifacts({
      token: 'token',
      license: 'license',
      files,
      manualArtifacts: {
        plan: ['psac.pdf', '  PSAC.PDF  '],
        qa_record: [' qa-record.csv '],
      },
    });

    const [, options] = (global.fetch as jest.Mock).mock.calls[0] as [string, RequestInit];
    const formData = options.body as FormData;

    const planEntries = formData.getAll('plan');
    expect(planEntries).toHaveLength(1);
    expect(planEntries[0]).toBeInstanceOf(File);
    expect((planEntries[0] as File).name).toBe('PSAC.PDF');

    const qaEntries = formData.getAll('qa_record');
    expect(qaEntries).toHaveLength(1);
    expect((qaEntries[0] as File).name).toBe('QA-RECORD.csv');

    const simulinkEntries = formData.getAll('simulink');
    expect(simulinkEntries).toHaveLength(2);
    expect(simulinkEntries.map((entry) => (entry as File).name)).toEqual(
      expect.arrayContaining(['Simulink-Coverage.JSON', 'model-coverage.zip']),
    );

    const objectiveEntries = formData.getAll('objectives');
    expect(objectiveEntries.some((entry) => (entry as File).name === 'objectives.json')).toBe(true);
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

    const polarionConfig = {
      baseUrl: 'https://polarion.example.com',
      projectId: 'space-avionics',
      username: 'polarion-user',
      token: 'polarion-token',
      requirementsEndpoint: '/requirements',
      testsEndpoint: '/tests',
      buildsEndpoint: '/builds',
    } as const;

    const jenkinsConfig = {
      baseUrl: 'https://ci.example.com',
      job: 'avionics/build',
      build: '123',
      username: 'jenkins-user',
      token: 'jenkins-token',
      buildEndpoint: '/custom-build',
      testReportEndpoint: '/custom-report',
    } as const;

    const doorsNextConfig = {
      baseUrl: 'https://doors.example.com',
      projectArea: 'systems',
      pageSize: 500,
      maxPages: 10,
      timeoutMs: 15000,
      username: 'doors-user',
    } as const;

    const jamaConfig = {
      baseUrl: 'https://jama.example.com',
      projectId: 'proj-88',
      token: 'jama-token',
      requirementsEndpoint: '/reqs',
      testCasesEndpoint: '/tests',
      relationshipsEndpoint: '/links',
    } as const;

    const jiraCloudConfig = {
      baseUrl: 'https://jira.example.com',
      projectKey: 'SOI',
      email: 'jira@example.com',
      token: 'jira-token',
      requirementsJql: 'project = SOI AND issuetype = Requirement',
      testsJql: 'project = SOI AND issuetype = Test',
      pageSize: 50,
      maxPages: 5,
      timeoutMs: 45000,
    } as const;

    await importArtifacts({
      token: 'token',
      license: 'license',
      files,
      projectName: 'Extended Import',
      projectVersion: '1.0.0',
      independentSources: ['junit', 'lcov'],
      independentArtifacts: ['analysis', 'test'],
      polarion: polarionConfig,
      jenkins: jenkinsConfig,
      doorsNext: doorsNextConfig,
      jama: jamaConfig,
      jiraCloud: jiraCloudConfig,
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
      expect.arrayContaining(['designCsv', 'polyspace', 'ldra', 'vectorcast', 'qaLogs', 'jiraDefects', 'jiraCloud']),
    );

    const defectEntries = formData.getAll('jiraDefects');
    expect(defectEntries).toHaveLength(1);
    expect(defectEntries[0]).toBeTruthy();


    const qaEntries = formData.getAll('qaLogs');
    expect(qaEntries).toHaveLength(2);
    expect(qaEntries.every((entry) => Boolean(entry))).toBe(true);

    expect(formData.get('independentSources')).toBe(JSON.stringify(['junit', 'lcov']));
    expect(formData.get('independentArtifacts')).toBe(JSON.stringify(['analysis', 'test']));

    expect(formData.get('polarion')).toBe(JSON.stringify(polarionConfig));
    expect(formData.get('jenkins')).toBe(JSON.stringify(jenkinsConfig));
    expect(formData.get('doorsNext')).toBe(JSON.stringify(doorsNextConfig));
    expect(formData.get('jama')).toBe(JSON.stringify(jamaConfig));
    expect(formData.get('jiraCloud')).toBe(JSON.stringify(jiraCloudConfig));
  });

  it('sanitizes compliance independence summaries from the API', async () => {
    (global.fetch as jest.Mock).mockResolvedValue(
      createResponse({
        body: {
          computedAt: '2024-05-01T10:00:00Z',
          latest: {
            id: 'summary-9',
            createdAt: '2024-05-01T10:00:00Z',
            summary: { total: 1, covered: 0, partial: 1, missing: 0 },
            coverage: { statements: 42 },
            gaps: { missingIds: [], partialIds: ['OBJ-1'], openObjectiveCount: 1 },
            independence: {
              totals: { covered: '2', partial: '1', missing: 0 },
              objectives: [
                {
                  objectiveId: ' OBJ-1 ',
                  status: 'partial',
                  independence: 'required',
                  missingArtifacts: ['  evidence.md  '],
                },
                {
                  objectiveId: '',
                  status: 'unknown',
                  independence: 'custom',
                  missingArtifacts: [123],
                },
              ],
            },
          },
        },
      }),
    );

    const response = await fetchComplianceSummary({ token: 'token', license: 'license' });

    expect((global.fetch as jest.Mock).mock.calls[0][0]).toContain('/v1/compliance/summary');
    const independence = response.latest?.independence;
    expect(independence?.totals.partial).toBe(1);
    expect(independence?.objectives).toHaveLength(1);
    expect(independence?.objectives[0]).toEqual({
      objectiveId: 'OBJ-1',
      status: 'partial',
      independence: 'required',
      missingArtifacts: ['evidence.md'],
    });
    expect(response.latest?.changeImpact).toEqual([]);
  });

  it('sanitizes compliance change impact entries from the API', async () => {
    (global.fetch as jest.Mock).mockResolvedValue(
      createResponse({
        body: {
          computedAt: '2024-06-10T12:00:00Z',
          latest: {
            id: 'summary-10',
            createdAt: '2024-06-10T12:00:00Z',
            summary: { total: 5, covered: 2, partial: 3, missing: 0 },
            coverage: { statements: 55 },
            gaps: { missingIds: ['REQ-5'], partialIds: [], openObjectiveCount: 1 },
            changeImpact: [
              {
                id: '  REQ-5  ',
                type: ' REQUIREMENT ',
                severity: 1.6,
                state: 'ADDED',
                reasons: [' Updated coverage ', '', 123],
              },
              {
                id: 'TC-9',
                type: 'test',
                severity: -0.25,
                state: 'modified',
                reasons: ['Regression failed'],
              },
              {
                id: 'CODE-1',
                type: 'component',
                severity: 0.8,
                state: 'added',
                reasons: ['Ignored'],
              },
            ],
          },
        },
      }),
    );

    const response = await fetchComplianceSummary({ token: 'token', license: 'license' });

    expect(response.latest?.changeImpact).toEqual([
      {
        id: 'REQ-5',
        type: 'requirement',
        severity: 1,
        state: 'added',
        reasons: ['Updated coverage'],
      },
      {
        id: 'TC-9',
        type: 'test',
        severity: 0,
        state: 'modified',
        reasons: ['Regression failed'],
      },
    ]);
  });

  it('handles malformed change impact payloads gracefully', async () => {
    (global.fetch as jest.Mock).mockResolvedValue(
      createResponse({
        body: {
          computedAt: '2024-06-11T09:00:00Z',
          latest: {
            id: 'summary-11',
            createdAt: '2024-06-11T09:00:00Z',
            summary: { total: 1, covered: 1, partial: 0, missing: 0 },
            coverage: { statements: 90 },
            gaps: { missingIds: [], partialIds: [], openObjectiveCount: 0 },
            changeImpact: [null, {}, { id: '', type: 'code', severity: 0.5, state: 'added' }],
          },
        },
      }),
    );

    const response = await fetchComplianceSummary({ token: 'token', license: 'license' });

    expect(response.latest?.changeImpact).toEqual([]);
  });

  it('fetches and normalizes change request backlog entries', async () => {
    (global.fetch as jest.Mock).mockResolvedValue(
      createResponse({
        body: {
          fetchedAt: 123456,
          items: [
            {
              id: '1001',
              key: 'CR-7',
              summary: 'Investigate failing regression',
              status: 'To Do',
              statusCategory: 'To Do',
              assignee: '  qa-user  ',
              updatedAt: '2024-05-02T09:30:00Z',
              url: 'https://jira.example.com/browse/CR-7',
              transitions: [
                { id: '1', name: 'Start Progress', toStatus: 'In Progress', category: 'In Progress' },
                null,
              ],
              attachments: [
                { id: 'att-1', filename: ' logs.txt ', url: 'https://jira.example.com/att/att-1' },
                { id: null },
              ],
            },
            { id: null },
          ],
        },
      }),
    );

    const result = await fetchChangeRequests({
      token: 'token',
      license: 'license',
      projectKey: 'SOI',
      jql: 'status = "To Do"',
    });

    const [url] = (global.fetch as jest.Mock).mock.calls[0] as [string];
    const parsedUrl = new URL(url);
    expect(parsedUrl.pathname).toBe('/v1/change-requests');
    expect(parsedUrl.searchParams.get('projectKey')).toBe('SOI');
    expect(parsedUrl.searchParams.get('jql')).toBe('status = "To Do"');
    expect(result.items).toHaveLength(1);
    const item = result.items[0];
    expect(item.assignee).toBe('qa-user');
    expect(item.attachments[0]?.filename).toBe('logs.txt');
    expect(item.transitions).toHaveLength(1);
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

describe('buildReportAssets', () => {
  const createJob = (overrides?: Partial<ReportJobResult['outputs']>): ApiJob<ReportJobResult> => ({
    id: 'abcd1234ef567890',
    kind: 'report',
    status: 'completed',
    hash: 'hash',
    createdAt: '2024-01-01T00:00:00.000Z',
    updatedAt: '2024-01-01T00:05:00.000Z',
    result: {
      outputs: {
        directory: 'reports/demo-tenant/abcd1234ef567890',
        complianceHtml: 'reports/demo-tenant/abcd1234ef567890/compliance.html',
        complianceJson: 'reports/demo-tenant/abcd1234ef567890/compliance.json',
        complianceCsv: 'reports/demo-tenant/abcd1234ef567890/compliance.csv',
        traceCsv: 'reports/demo-tenant/abcd1234ef567890/trace.csv',
        traceHtml: 'reports/demo-tenant/abcd1234ef567890/trace.html',
        gapsHtml: 'reports/demo-tenant/abcd1234ef567890/gaps.html',
        analysis: 'reports/demo-tenant/abcd1234ef567890/analysis.json',
        snapshot: 'reports/demo-tenant/abcd1234ef567890/snapshot.json',
        traces: 'reports/demo-tenant/abcd1234ef567890/traces.json',
        gsnGraphDot: {
          path: 'reports/demo-tenant/abcd1234ef567890/gsn/gsn-graph.dot',
          href: 'gsn/gsn-graph.dot',
        },
        toolQualification: {
          summary: {
            generatedAt: '2024-01-01T00:00:00.000Z',
            tools: [
              {
                id: 'tool-1',
                name: 'Analyzer',
                category: 'verification' as const,
                outputs: ['Plan'],
                pendingActivities: 0,
              },
            ],
          },
          tqp: 'reports/demo-tenant/abcd1234ef567890/tool-qualification/analyzer-plan.md',
          tar: 'reports/demo-tenant/abcd1234ef567890/tool-qualification/analyzer-report.md',
          tqpHref: 'tool-qualification/analyzer-plan.md',
          tarHref: 'tool-qualification/analyzer-report.md',
        },
        ...overrides,
      },
    },
  });

  const createPackJob = (
    overrides?: Partial<PackJobResult>,
    outputOverrides?: Partial<PackJobResult['outputs']>,
  ): ApiJob<PackJobResult> => ({
    id: 'pack-job-123',
    kind: 'pack',
    status: 'completed',
    hash: 'pack-hash',
    createdAt: '2024-01-01T00:00:00.000Z',
    updatedAt: '2024-01-01T00:05:00.000Z',
    result: {
      manifestId: 'manifest-1',
      outputs: {
        directory: 'packages/demo-tenant/pack-job-123',
        manifest: 'packages/demo-tenant/pack-job-123/manifest.json',
        archive: 'packages/demo-tenant/pack-job-123/archive.zip',
        sbom: 'packages/demo-tenant/pack-job-123/sbom.spdx.json',
        ...outputOverrides,
      },
      sbomSha256: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      ...overrides,
    },
  });

  it('normalizes compliance CSV and tool qualification asset paths', () => {
    const assets = buildReportAssets(createJob());
    expect(assets.assets.complianceCsv).toBe('compliance.csv');
    expect(assets.assets.traceCsv).toBe('trace.csv');
    expect(assets.assets.toolQualificationPlan).toBe('tool-qualification/analyzer-plan.md');
    expect(assets.assets.toolQualificationReport).toBe('tool-qualification/analyzer-report.md');
    expect(assets.assets.gsnGraphDot).toBe('gsn/gsn-graph.dot');
  });

  it('omits tool qualification assets when absent', () => {
    const jobWithoutTq = createJob({ toolQualification: undefined });
    const assets = buildReportAssets(jobWithoutTq);
    expect(assets.assets.toolQualificationPlan).toBeUndefined();
    expect(assets.assets.toolQualificationReport).toBeUndefined();
    expect(assets.assets.gsnGraphDot).toBe('gsn/gsn-graph.dot');
  });

  it('falls back to deriving the GSN path when href is missing', () => {
    const job = createJob({
      gsnGraphDot: {
        path: 'reports/demo-tenant/abcd1234ef567890/gsn/alt.dot',
      },
    });
    const assets = buildReportAssets(job);
    expect(assets.assets.gsnGraphDot).toBe('gsn/alt.dot');
  });

  it('includes SBOM download metadata when pack job contains SBOM output', () => {
    const packJob = createPackJob();
    const assets = buildReportAssets(createJob(), packJob);

    expect(assets.packageId).toBe('pack-job-123');
    expect(assets.sbom).toEqual({
      packageId: 'pack-job-123',
      downloadUrl: `/v1/packages/${encodeURIComponent('pack-job-123')}/sbom`,
      relativePath: 'sbom.spdx.json',
      sha256: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    });
  });

  it('omits SBOM metadata when pack job lacks SBOM outputs', () => {
    const packJob = createPackJob({ sbomSha256: undefined }, { sbom: undefined });
    const assets = buildReportAssets(createJob(), packJob);

    expect(assets.sbom).toBeUndefined();
  });
});
