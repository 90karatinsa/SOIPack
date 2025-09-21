import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { DefaultBodyType, ResponseComposition, RestContext, RestRequest } from 'msw';
import { rest } from 'msw';
import { setupServer } from 'msw/node';

import App from './App';
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

const saveAsMock = jest.requireMock('file-saver').saveAs as jest.Mock;

jest.setTimeout(15000);

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

    expect(capturedLicenses.length).toBeGreaterThan(0);
    capturedLicenses.forEach((value) => {
      expect(value).toBe(expectedLicenseHeader);
      expect(value).not.toMatch(/\s/);
    });
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
