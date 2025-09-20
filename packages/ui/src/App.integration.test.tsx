import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { rest } from 'msw';
import { setupServer } from 'msw/node';
import JSZip from 'jszip';

import App from './App';

jest.mock('file-saver', () => ({
  saveAs: jest.fn()
}));

const saveAsMock = jest.requireMock('file-saver').saveAs as jest.Mock;

jest.setTimeout(15000);

type JobStatus = 'queued' | 'running' | 'completed';

type JobKind = 'import' | 'analyze' | 'report';

interface JobState {
  id: string;
  kind: JobKind;
  createdAt: string;
  statuses: JobStatus[];
  cursor: number;
  result: any;
  hash: string;
}

const buildJob = (id: string, kind: JobKind, result: any): JobState => ({
  id,
  kind,
  createdAt: new Date().toISOString(),
  statuses: ['queued', 'completed'],
  cursor: 0,
  result,
  hash: `${kind}-${id}`
});

const compliancePayload = {
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

const tracesPayload = [
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

const jobStore = new Map<string, JobState>();

const server = setupServer(
  rest.post('/v1/import', async (_req, res, ctx) => {
    const jobId = 'job-import';
    const result = {
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
    const body = await req.json();
    if (!body.importId) {
      return res(ctx.status(400));
    }
    const jobId = 'job-analyze';
    const result = {
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
    const body = await req.json();
    if (!body.analysisId) {
      return res(ctx.status(400));
    }
    const jobId = 'job-report';
    const result = {
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
  rest.get('/v1/jobs/:id', (req, res, ctx) => {
    const { id } = req.params as { id: string };
    const job = jobStore.get(id);
    if (!job) {
      return res(ctx.status(404));
    }
    const index = Math.min(job.cursor, job.statuses.length - 1);
    const status = job.statuses[index];
    job.cursor = Math.min(job.cursor + 1, job.statuses.length - 1);
    const updatedAt = new Date(Date.parse(job.createdAt) + index * 500).toISOString();
    const payload: any = {
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
  rest.get('/v1/reports/:id/compliance.json', (_req, res, ctx) => {
    return res(ctx.status(200), ctx.json(compliancePayload));
  }),
  rest.get('/v1/reports/:id/traces.json', (_req, res, ctx) => {
    return res(ctx.status(200), ctx.json(tracesPayload));
  }),
  rest.get('/v1/reports/:id/:asset', (req, res, ctx) => {
    const { asset } = req.params as { asset: string };
    const content = reportAssets[asset];
    if (!content) {
      return res(ctx.status(404));
    }
    const isJson = asset.endsWith('.json');
    return isJson ? res(ctx.status(200), ctx.json(JSON.parse(content))) : res(ctx.status(200), ctx.text(content));
  })
);

beforeAll(() => server.listen());
afterEach(() => {
  server.resetHandlers();
  jobStore.clear();
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
    const zip = await JSZip.loadAsync(blob);
    expect(Object.keys(zip.files)).toEqual(
      expect.arrayContaining([
        'analysis.json',
        'snapshot.json',
        'traces.json',
        'compliance.json',
        'compliance.html',
        'trace.html',
        'gaps.html'
      ])
    );
    const complianceText = await zip.file('compliance.json')!.async('string');
    expect(complianceText).toContain('REQ-1');
  });
});
