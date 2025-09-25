import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { DefaultBodyType, ResponseComposition, RestContext, RestRequest } from 'msw';
import { rest } from 'msw';
import { setupServer } from 'msw/node';

import App from './App';
import { createComplianceEventStream } from './services/events';
import type { ComplianceEvent, ComplianceStreamOptions } from './services/events';
import { RbacProvider } from './providers/RbacProvider';
import type {
  AnalyzeJobResult,
  ApiJob,
  ComplianceMatrixPayload,
  ImportJobResult,
  JobKind,
  JobStatus,
  PackJobResult,
  ReportJobResult,
  RequirementTracePayload,
} from './types/pipeline';

jest.mock('file-saver', () => ({
  saveAs: jest.fn()
}));

jest.mock('./services/events', () => {
  const actual = jest.requireActual('./services/events');
  return {
    ...actual,
    createComplianceEventStream: jest.fn(),
  };
});

const saveAsMock = jest.requireMock('file-saver').saveAs as jest.Mock;

jest.setTimeout(15000);

const createStreamMock = jest.mocked(createComplianceEventStream);

interface StreamInstance {
  options: ComplianceStreamOptions;
  close: jest.Mock;
}

const streamInstances: StreamInstance[] = [];

beforeEach(() => {
  streamInstances.length = 0;
  createStreamMock.mockImplementation((options: ComplianceStreamOptions) => {
    const close = jest.fn();
    streamInstances.push({ options, close });
    return {
      close,
      getState: () => ({ connected: false, retries: 0, lastEventId: undefined }),
    };
  });
});

interface JobState<T = unknown> {
  id: string;
  kind: JobKind;
  createdAt: string;
  statuses: JobStatus[];
  cursor: number;
  result: T;
  hash: string;
}

const buildJob = <T,>(id: string, kind: JobKind, result: T): JobState<T> => ({
  id,
  kind,
  createdAt: new Date().toISOString(),
  statuses: ['queued', 'completed'],
  cursor: 0,
  result,
  hash: `${kind}-${id}`
});

const compliancePayload: ComplianceMatrixPayload = {
  generatedAt: '2024-04-01T10:00:00Z',
  version: '1.0.0',
  stats: {
    objectives: { total: 2, covered: 1, partial: 1, missing: 0 },
    requirements: { total: 2 },
    tests: { total: 3, passed: 1, failed: 1, skipped: 1 },
    codePaths: { total: 2 }
  },
  objectives: [],
  requirementCoverage: [
    {
      requirementId: 'REQ-1',
      title: 'Kullanıcı girişi doğrulama',
      status: 'covered',
      coverage: {
        statements: { covered: 10, total: 10, percentage: 100 }
      },
      codePaths: ['src/auth/login.ts']
    },
    {
      requirementId: 'REQ-2',
      title: 'Audit kayıtları tutulmalı',
      status: 'partial',
      coverage: {
        statements: { covered: 6, total: 10, percentage: 60 }
      },
      codePaths: []
    }
  ]
};

const tracesPayload: RequirementTracePayload[] = [
  {
    requirement: {
      id: 'REQ-1',
      title: 'Kullanıcı girişi doğrulama',
      description: 'Çok faktörlü giriş doğrulanmalı.',
      status: 'approved',
      tags: ['auth']
    },
    tests: [
      { testId: 'TC-LOGIN-1', name: 'happy path', status: 'passed' },
      { testId: 'TC-LOGIN-2', name: 'hatali giriş engellenir', status: 'failed' }
    ],
    code: [
      {
        path: 'src/auth/login.ts',
        coverage: {
          statements: { covered: 10, total: 10, percentage: 100 }
        }
      }
    ]
  },
  {
    requirement: {
      id: 'REQ-2',
      title: 'Audit kayıtları tutulmalı',
      description: 'Kritik olaylar kaydedilmeli.',
      status: 'implemented',
      tags: ['audit']
    },
    tests: [{ testId: 'TC-AUDIT-1', name: 'audit kaydı üretilir', status: 'skipped' }],
    code: [
      {
        path: 'src/security/audit.ts',
        coverage: {
          statements: { covered: 6, total: 10, percentage: 60 }
        }
      }
    ]
  }
];

const requirementsThreadResponse = {
  document: {
    id: 'requirements',
    tenantId: 'tenant-1',
    workspaceId: 'demo-workspace',
    kind: 'requirements',
    title: 'Uçuş Kontrolleri',
    createdAt: '2024-04-01T00:00:00.000Z',
    updatedAt: '2024-04-01T00:00:00.000Z',
    revision: {
      id: 'rev-1',
      number: 1,
      hash: 'abcdef123456',
      authorId: 'alice',
      createdAt: '2024-04-01T00:00:00.000Z',
      content: [
        {
          id: 'REQ-CTRL-1',
          title: 'Otopilot manuel müdahalede kapanır',
          description: 'Uçuş ekibi override yaptığında sistem kontrolü devreder.',
          status: 'draft',
          tags: ['flight'],
        },
      ],
    },
  },
  comments: [
    {
      id: 'comment-1',
      documentId: 'requirements',
      revisionId: 'rev-1',
      tenantId: 'tenant-1',
      workspaceId: 'demo-workspace',
      authorId: 'qa',
      body: 'Gözden geçirildikten sonra DER imzası bekleniyor.',
      createdAt: '2024-04-01T10:00:00.000Z',
    },
  ],
  signoffs: [
    {
      id: 'signoff-1',
      documentId: 'requirements',
      revisionId: 'rev-1',
      tenantId: 'tenant-1',
      workspaceId: 'demo-workspace',
      revisionHash: 'abcdef123456',
      status: 'pending',
      requestedBy: 'alice',
      requestedFor: 'qa-lead',
      createdAt: '2024-04-02T09:00:00.000Z',
      updatedAt: '2024-04-02T09:00:00.000Z',
    },
  ],
  nextCursor: null,
};

const adminRolesResponse = {
  roles: [
    { name: 'admin', permissions: ['*'] },
    { name: 'operator', permissions: ['documents:write'] },
  ],
};

const adminUsersResponse = {
  users: [
    {
      id: 'user-1',
      email: 'ops@example.com',
      displayName: 'Ops Review',
      roles: ['operator'],
      status: 'active',
    },
  ],
};

const reportAssets: Record<string, string> = {
  'analysis.json': JSON.stringify({ meta: 'analysis' }),
  'snapshot.json': JSON.stringify({ stats: {} }),
  'traces.json': JSON.stringify(tracesPayload),
  'compliance.json': JSON.stringify(compliancePayload),
  'compliance.html': '<html><body>compliance</body></html>',
  'trace.html': '<html><body>trace</body></html>',
  'gaps.html': '<html><body>gaps</body></html>'
};

const packResult: PackJobResult = {
  manifestId: 'MANIFEST-1234',
  outputs: {
    directory: 'packages/demo/job-pack',
    manifest: 'packages/demo/job-pack/manifest.json',
    archive: 'packages/demo/job-pack/archive.zip'
  }
};

const jobStore = new Map<string, JobState<unknown>>();
const licensePayload = { tenant: 'demo', expiresAt: '2025-12-31T00:00:00Z' };
const expectedLicenseHeader = Buffer.from(JSON.stringify(licensePayload)).toString('base64');
const capturedLicenses: string[] = [];

type LicenseResponse = ReturnType<ResponseComposition<DefaultBodyType>>;

const ensureLicense = (
  req: RestRequest<DefaultBodyType>,
  res: ResponseComposition<DefaultBodyType>,
  ctx: RestContext,
): LicenseResponse | null => {
  const authHeader = req.headers.get('authorization');
  expect(authHeader).toBe('Bearer demo-token');

  const licenseHeader = req.headers.get('x-soipack-license');
  if (!licenseHeader) {
    return res(
      ctx.status(401),
      ctx.json({ error: { message: 'LICENSE_REQUIRED' } })
    );
  }

  const sanitized = licenseHeader.replace(/\s+/g, '');
  if (sanitized !== expectedLicenseHeader) {
    return res(
      ctx.status(401),
      ctx.json({ error: { message: 'LICENSE_INVALID' } })
    );
  }

  capturedLicenses.push(sanitized);
  return null;
};

const server = setupServer(
  rest.post('/v1/import', async (_req, res, ctx) => {
    const authError = ensureLicense(_req, res, ctx);
    if (authError) {
      return authError;
    }
    const jobId = 'job-import';
    const result: ImportJobResult = {
      warnings: ['REQ-2 testleri eksik'],
      outputs: {
        directory: 'workspaces/demo/job-import',
        workspace: 'workspaces/demo/job-import/workspace.json'
      }
    };
    jobStore.set(jobId, buildJob(jobId, 'import', result));
    return res(
      ctx.status(202),
      ctx.json({
        id: jobId,
        kind: 'import',
        hash: 'hash-import',
        status: 'queued',
        createdAt: jobStore.get(jobId)!.createdAt,
        updatedAt: jobStore.get(jobId)!.createdAt
      })
    );
  }),
  rest.post('/v1/analyze', async (req, res, ctx) => {
    const authError = ensureLicense(req, res, ctx);
    if (authError) {
      return authError;
    }
    const body = await req.json();
    if (!body.importId) {
      return res(ctx.status(400));
    }
    const jobId = 'job-analyze';
    const result: AnalyzeJobResult = {
      exitCode: 0,
      outputs: {
        directory: 'analyses/demo/job-analyze',
        snapshot: 'analyses/demo/job-analyze/snapshot.json',
        traces: 'analyses/demo/job-analyze/traces.json',
        analysis: 'analyses/demo/job-analyze/analysis.json'
      }
    };
    jobStore.set(jobId, buildJob(jobId, 'analyze', result));
    return res(
      ctx.status(202),
      ctx.json({
        id: jobId,
        kind: 'analyze',
        hash: 'hash-analyze',
        status: 'queued',
        createdAt: jobStore.get(jobId)!.createdAt,
        updatedAt: jobStore.get(jobId)!.createdAt
      })
    );
  }),
  rest.post('/v1/report', async (req, res, ctx) => {
    const authError = ensureLicense(req, res, ctx);
    if (authError) {
      return authError;
    }
    const body = await req.json();
    if (!body.analysisId) {
      return res(ctx.status(400));
    }
    const jobId = 'job-report';
    const result: ReportJobResult = {
      outputs: {
        directory: 'reports/demo/job-report',
        complianceHtml: 'reports/demo/job-report/compliance.html',
        complianceJson: 'reports/demo/job-report/compliance.json',
        traceHtml: 'reports/demo/job-report/trace.html',
        gapsHtml: 'reports/demo/job-report/gaps.html',
        analysis: 'reports/demo/job-report/analysis.json',
        snapshot: 'reports/demo/job-report/snapshot.json',
        traces: 'reports/demo/job-report/traces.json'
      }
    };
    jobStore.set(jobId, buildJob(jobId, 'report', result));
    return res(
      ctx.status(202),
      ctx.json({
        id: jobId,
        kind: 'report',
        hash: 'hash-report',
        status: 'queued',
        createdAt: jobStore.get(jobId)!.createdAt,
        updatedAt: jobStore.get(jobId)!.createdAt
      })
    );
  }),
  rest.post('/v1/pack', async (req, res, ctx) => {
    const authError = ensureLicense(req, res, ctx);
    if (authError) {
      return authError;
    }
    const body = await req.json();
    if (!body.reportId) {
      return res(ctx.status(400));
    }
    const jobId = 'job-pack';
    jobStore.set(jobId, buildJob(jobId, 'pack', packResult));
    return res(
      ctx.status(202),
      ctx.json({
        id: jobId,
        kind: 'pack',
        hash: 'hash-pack',
        status: 'queued',
        createdAt: jobStore.get(jobId)!.createdAt,
        updatedAt: jobStore.get(jobId)!.createdAt
      })
    );
  }),
  rest.get('/v1/jobs/:id', (req, res, ctx) => {
    const authError = ensureLicense(req, res, ctx);
    if (authError) {
      return authError;
    }
    const { id } = req.params as { id: string };
    const job = jobStore.get(id);
    if (!job) {
      return res(ctx.status(404));
    }
    const index = Math.min(job.cursor, job.statuses.length - 1);
    const status = job.statuses[index];
    job.cursor = Math.min(job.cursor + 1, job.statuses.length - 1);
    const updatedAt = new Date(Date.parse(job.createdAt) + index * 500).toISOString();
    const payload: ApiJob<unknown> = {
      id,
      kind: job.kind,
      hash: job.hash,
      status,
      createdAt: job.createdAt,
      updatedAt
    };
    if (status === 'completed') {
      payload.result = job.result;
    }
    return res(ctx.status(status === 'completed' ? 200 : 202), ctx.json(payload));
  }),
  rest.get('/v1/reports/:id/compliance.json', (req, res, ctx) => {
    const authError = ensureLicense(req, res, ctx);
    if (authError) {
      return authError;
    }
    return res(ctx.status(200), ctx.json(compliancePayload));
  }),
  rest.get('/v1/reports/:id/traces.json', (req, res, ctx) => {
    const authError = ensureLicense(req, res, ctx);
    if (authError) {
      return authError;
    }
    return res(ctx.status(200), ctx.json(tracesPayload));
  }),
  rest.get('/v1/workspaces/demo-workspace/documents/requirements', (req, res, ctx) => {
    const authError = ensureLicense(req, res, ctx);
    if (authError) {
      return authError;
    }
    return res(ctx.status(200), ctx.json(requirementsThreadResponse));
  }),
  rest.get('/v1/admin/roles', (req, res, ctx) => {
    const authError = ensureLicense(req, res, ctx);
    if (authError) {
      return authError;
    }
    return res(ctx.status(200), ctx.json(adminRolesResponse));
  }),
  rest.get('/v1/admin/users', (req, res, ctx) => {
    const authError = ensureLicense(req, res, ctx);
    if (authError) {
      return authError;
    }
    return res(ctx.status(200), ctx.json(adminUsersResponse));
  }),
  rest.get('/v1/reports/:id/:asset', (req, res, ctx) => {
    const authError = ensureLicense(req, res, ctx);
    if (authError) {
      return authError;
    }
    const { asset } = req.params as { asset: string };
    const content = reportAssets[asset];
    if (!content) {
      return res(ctx.status(404));
    }
    const isJson = asset.endsWith('.json');
    return isJson ? res(ctx.status(200), ctx.json(JSON.parse(content))) : res(ctx.status(200), ctx.text(content));
  }),
  rest.get('/v1/packages/:id/archive', (req, res, ctx) => {
    const authError = ensureLicense(req, res, ctx);
    if (authError) {
      return authError;
    }
    return res(
      ctx.status(200),
      ctx.set('Content-Type', 'application/zip'),
      ctx.set('Content-Disposition', 'attachment; filename="soipack-demo.zip"'),
      ctx.body('FAKEZIP')
    );
  }),
  rest.get('/v1/packages/:id/manifest', (req, res, ctx) => {
    const authError = ensureLicense(req, res, ctx);
    if (authError) {
      return authError;
    }
    return res(
      ctx.status(200),
      ctx.set('Content-Type', 'application/json'),
      ctx.set('Content-Disposition', 'attachment; filename="manifest.json"'),
      ctx.json({ manifest: 'demo' })
    );
  })
);

beforeAll(() => server.listen());
afterEach(() => {
  server.resetHandlers();
  jobStore.clear();
  capturedLicenses.length = 0;
  saveAsMock.mockReset();
  createStreamMock.mockReset();
});
afterAll(() => server.close());

describe('App integration', () => {
  it('runs the pipeline and renders report data from the API', async () => {
    const user = userEvent.setup();
    render(<App />);

    const tokenInput = screen.getByPlaceholderText('Token girilmeden demo kilitli kalır');
    await act(async () => {
      await user.type(tokenInput, 'demo-token');
    });

    const licenseTextarea = screen.getByPlaceholderText('{"tenant":"demo","expiresAt":"2024-12-31"}');
    await act(async () => {
      fireEvent.change(licenseTextarea, { target: { value: JSON.stringify(licensePayload) } });
    });

    await screen.findByText('Kaynak: Panodan yapıştırıldı');

    const file = new File(['reqif'], 'requirements.reqif', { type: 'application/xml' });
    const fileInput = screen.getByLabelText(/Dosyaları sürükleyip bırakın ya da seçin/i, { selector: 'input' });
    await act(async () => {
      await user.upload(fileInput, file);
    });

    const runButton = screen.getByRole('button', { name: 'Pipeline Başlat' });
    await act(async () => {
      await user.click(runButton);
    });

    const downloadButton = screen.getByRole('button', { name: 'Rapor paketini indir' });
    await waitFor(() => expect(downloadButton).toBeEnabled(), { timeout: 10000 });

    const complianceTab = screen.getByRole('button', { name: 'Uyum Matrisi' });
    await act(async () => {
      await user.click(complianceTab);
    });

    await screen.findByText('REQ-1');
    expect(screen.getByText('Kullanıcı girişi doğrulama')).toBeInTheDocument();
    expect(screen.getByText('REQ-2')).toBeInTheDocument();

    const traceTab = screen.getByRole('button', { name: 'İzlenebilirlik' });
    await act(async () => {
      await user.click(traceTab);
    });
    await screen.findByText('Audit kayıtları tutulmalı');

    const testsList = screen.getAllByText(/TC-/);
    expect(testsList.some((node) => node.textContent?.includes('TC-LOGIN-1'))).toBe(true);

    await act(async () => {
      await user.click(downloadButton);
    });

    await waitFor(() => expect(saveAsMock).toHaveBeenCalledTimes(1));
    const blob = saveAsMock.mock.calls[0][0] as Blob;
    const downloadedName = saveAsMock.mock.calls[0][1];
    expect(downloadedName).toBe('soipack-demo.zip');
    const content = await blob.text();
    expect(content).toBe('FAKEZIP');

    const timelineTab = screen.getByRole('button', { name: 'Zaman Çizelgesi' });
    await act(async () => {
      await user.click(timelineTab);
    });

    await screen.findByText('Gerçek zamanlı bağlantı kuruluyor…');
    expect(streamInstances).toHaveLength(1);

    const timelineStream = streamInstances[0];

    act(() => {
      timelineStream.options.onStatusChange?.('open', { attempt: 1 });
    });

    await screen.findByText('Canlı akış aktif. Yeni olaylar anında görünecek.');

    const ledgerEvent: ComplianceEvent = {
      type: 'ledgerEntry',
      tenantId: 'demo',
      emittedAt: '2024-05-01T12:00:00Z',
      entry: {
        index: 1,
        snapshotId: 'SNAP-1',
        manifestDigest: 'a'.repeat(64),
        timestamp: '2024-05-01T12:00:00Z',
        merkleRoot: 'b'.repeat(64),
        previousRoot: 'c'.repeat(64),
        ledgerRoot: 'd'.repeat(64),
        evidence: [],
      },
    };

    act(() => {
      timelineStream.options.onEvent?.(ledgerEvent);
    });

    await screen.findByText('Ledger kaydı eklendi');
    expect(screen.getByText(/Snapshot SNAP-1/)).toBeInTheDocument();

    act(() => {
      timelineStream.options.onStatusChange?.('retrying', { delayMs: 2000, attempt: 2 });
    });

    await screen.findByText('Bağlantı koptu, 2 saniye içinde yeniden denenecek.');

    act(() => {
      timelineStream.options.onError?.(new Error('Kimlik doğrulama başarısız oldu'));
    });

    const disconnectNotices = await screen.findAllByText('Bağlantı hatası: Kimlik doğrulama başarısız oldu');
    expect(disconnectNotices.length).toBeGreaterThanOrEqual(1);

    expect(capturedLicenses.length).toBeGreaterThan(0);
    capturedLicenses.forEach((value) => {
      expect(value).toBe(expectedLicenseHeader);
      expect(value).not.toMatch(/\s/);
    });
  });

  it('renders risk cockpit analytics and enforces RBAC gating', async () => {
    const user = userEvent.setup();
    const { unmount } = render(
      <RbacProvider roles={['risk:read', 'ledger:read']}>
        <App />
      </RbacProvider>,
    );

    const tokenInput = screen.getByPlaceholderText('Token girilmeden demo kilitli kalır');
    await act(async () => {
      await user.type(tokenInput, 'demo-token');
    });

    const licenseTextarea = screen.getByPlaceholderText('{"tenant":"demo","expiresAt":"2024-12-31"}');
    await act(async () => {
      fireEvent.change(licenseTextarea, { target: { value: JSON.stringify(licensePayload) } });
    });

    await screen.findByText('Kaynak: Panodan yapıştırıldı');

    const riskTab = screen.getByRole('button', { name: 'Risk Kokpiti' });
    await act(async () => {
      await user.click(riskTab);
    });

    await screen.findByText('Risk akışı bağlanıyor…');
    expect(streamInstances).toHaveLength(1);

    const riskStream = streamInstances[0];

    act(() => {
      riskStream.options.onStatusChange?.('open', { attempt: 1 });
    });

    await screen.findByText('Canlı risk akışı aktif. Yeni veriler otomatik olarak güncellenecek.');

    const riskEvent: ComplianceEvent = {
      type: 'riskProfile',
      tenantId: 'demo',
      emittedAt: '2024-05-01T10:00:00Z',
      profile: {
        score: 74,
        classification: 'orta',
        missingSignals: ['threat', 'pen-test'],
        breakdown: [
          { factor: 'Kapsam Açığı', contribution: 0.4, weight: 0.5, details: 'Bazı kritik fonksiyonlar izlenmiyor.' },
          { factor: 'Test Başarısızlığı', contribution: 0.3, weight: 0.3 },
          { factor: 'Statik Analiz Bulguları', contribution: 0.2, weight: 0.15 },
          { factor: 'Audit Bayrakları', contribution: 0.1, weight: 0.05 },
        ],
      },
    };

    act(() => {
      riskStream.options.onEvent?.(riskEvent);
    });

    const topFactor = await screen.findByText('Kapsam Açığı');
    const heatmapRow = topFactor.closest('li');
    expect(heatmapRow).not.toBeNull();
    if (heatmapRow) {
      const scoped = within(heatmapRow);
      expect(scoped.getByText('0.50')).toBeInTheDocument();
      expect(scoped.getByText('0.40')).toBeInTheDocument();
      expect(scoped.getByText('0.20')).toBeInTheDocument();
      expect(scoped.getByText('%62')).toBeInTheDocument();
    }

    const summary = screen.getByText('Skor').closest('dl');
    expect(summary).not.toBeNull();
    if (summary) {
      const scoped = within(summary);
      expect(scoped.getByText('74')).toBeInTheDocument();
      expect(scoped.getByText('orta')).toBeInTheDocument();
      expect(scoped.getByText('2')).toBeInTheDocument();
    }

    const previousRoot = 'a'.repeat(64);
    const ledgerRoot = `${'a'.repeat(56)}${'b'.repeat(8)}`;

    const ledgerEvent: ComplianceEvent = {
      type: 'ledgerEntry',
      tenantId: 'demo',
      emittedAt: '2024-05-01T12:00:00Z',
      entry: {
        index: 2,
        snapshotId: 'SNAP-2',
        manifestDigest: 'd'.repeat(64),
        timestamp: '2024-05-01T12:00:00Z',
        merkleRoot: 'f'.repeat(64),
        previousRoot,
        ledgerRoot,
        evidence: [],
      },
    };

    act(() => {
      riskStream.options.onEvent?.(ledgerEvent);
    });

    const ledgerCardTitle = await screen.findByText('Snapshot SNAP-2');
    const ledgerCard = ledgerCardTitle.closest('li');
    expect(ledgerCard).not.toBeNull();
    if (ledgerCard) {
      const scoped = within(ledgerCard);
      const diffLabel = scoped.getByText('Fark pozisyonu:');
      const diffContainer = diffLabel.closest('p');
      expect(diffContainer).not.toBeNull();
      expect(diffContainer?.textContent?.trim()).toContain('56');
      expect(scoped.getByText('Önceki: aaaaaaaa → Yeni: bbbbbbbb')).toBeInTheDocument();
    }

    unmount();
    expect(riskStream.close).toHaveBeenCalled();

    streamInstances.length = 0;
    createStreamMock.mockClear();

    const { unmount: unmountNoLedger } = render(
      <RbacProvider roles={['risk:read']}>
        <App />
      </RbacProvider>,
    );

    const tokenInput2 = screen.getByPlaceholderText('Token girilmeden demo kilitli kalır');
    await act(async () => {
      await user.type(tokenInput2, 'demo-token');
    });

    const licenseTextarea2 = screen.getByPlaceholderText('{"tenant":"demo","expiresAt":"2024-12-31"}');
    await act(async () => {
      fireEvent.change(licenseTextarea2, { target: { value: JSON.stringify(licensePayload) } });
    });

    await screen.findByText('Kaynak: Panodan yapıştırıldı');

    const riskTab2 = screen.getByRole('button', { name: 'Risk Kokpiti' });
    await act(async () => {
      await user.click(riskTab2);
    });

    await screen.findByText('Ledger verilerine erişim yetkiniz yok.');

    unmountNoLedger();

    streamInstances.length = 0;
    createStreamMock.mockClear();

    const { unmount: unmountNoRisk } = render(
      <RbacProvider roles={['ledger:read']}>
        <App />
      </RbacProvider>,
    );

    const tokenInput3 = screen.getByPlaceholderText('Token girilmeden demo kilitli kalır');
    await act(async () => {
      await user.type(tokenInput3, 'demo-token');
    });

    const licenseTextarea3 = screen.getByPlaceholderText('{"tenant":"demo","expiresAt":"2024-12-31"}');
    await act(async () => {
      fireEvent.change(licenseTextarea3, { target: { value: JSON.stringify(licensePayload) } });
    });

    await screen.findByText('Kaynak: Panodan yapıştırıldı');

    const riskTab3 = screen.getByRole('button', { name: 'Risk Kokpiti' });
    await act(async () => {
      await user.click(riskTab3);
    });

    await screen.findByText('Risk verilerine erişim yetkiniz yok.');

    unmountNoRisk();
  });

  it('gates requirements editor and admin users routes', async () => {
    const user = userEvent.setup();
    render(
      <RbacProvider roles={['workspace:write', 'admin']}>
        <App />
      </RbacProvider>,
    );

    const requirementsTab = screen.getByRole('button', { name: 'Gereksinim Editörü' });
    await user.click(requirementsTab);

    await screen.findByText('Kimlik bilgileri gerekli');

    const adminTab = screen.getByRole('button', { name: 'Yönetici Kullanıcılar' });
    await user.click(adminTab);
    await screen.findByText('Yönetici kullanıcılarını görüntülemek için token ve lisans girmelisiniz.');

    const tokenInput = screen.getByPlaceholderText('Token girilmeden demo kilitli kalır');
    await act(async () => {
      await user.type(tokenInput, 'demo-token');
    });

    const licenseTextarea = screen.getByPlaceholderText('{"tenant":"demo","expiresAt":"2024-12-31"}');
    await act(async () => {
      fireEvent.change(licenseTextarea, { target: { value: JSON.stringify(licensePayload) } });
    });

    await screen.findByText('Kaynak: Panodan yapıştırıldı');

    await user.click(requirementsTab);

    await screen.findByLabelText('Requirement ID 1');
    expect(screen.getByText('Otopilot manuel müdahalede kapanır')).toBeInTheDocument();
    expect(screen.getByText('Gözden geçirildikten sonra DER imzası bekleniyor.')).toBeInTheDocument();

    await user.click(adminTab);
    await screen.findByText('RBAC Kullanıcı Yönetimi');
    await screen.findByText('ops@example.com');
  });

  it('hides privileged tabs for users without admin roles', () => {
    render(
      <RbacProvider roles={['risk:read']}>
        <App />
      </RbacProvider>,
    );

    expect(screen.queryByRole('button', { name: 'Gereksinim Editörü' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Yönetici Kullanıcılar' })).not.toBeInTheDocument();
  });

  it('surfaces an error when the license is missing', async () => {
    const user = userEvent.setup();
    render(<App />);

    const tokenInput = screen.getByPlaceholderText('Token girilmeden demo kilitli kalır');
    await act(async () => {
      await user.type(tokenInput, 'demo-token');
    });

    const file = new File(['reqif'], 'requirements.reqif', { type: 'application/xml' });
    const fileInput = screen.getByLabelText(/Dosyaları sürükleyip bırakın ya da seçin/i, { selector: 'input' });
    await act(async () => {
      await user.upload(fileInput, file);
    });

    const runButton = screen.getByRole('button', { name: 'Pipeline Başlat' });
    await act(async () => {
      await user.click(runButton);
    });

    await screen.findByText('Lütfen önce geçerli bir lisans yükleyin.');
    expect(jobStore.size).toBe(0);
    expect(capturedLicenses).toHaveLength(0);
  });
});
