import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import type { BuildInfo } from '@soipack/adapters';
import { createRequirement, TestCase } from '@soipack/core';
import htmlValidator from 'html-validator';

import { createReportFixture, coverageSummaryFixture } from './__fixtures__/snapshot';

import {
  ChangeRequestBacklogItem,
  HtmlReportOptions,
  LedgerAttestationDiffItem,
  renderComplianceCoverageReport,
  renderComplianceMatrix,
  renderGaps,
  renderHtmlReport,
  renderJsonReport,
  renderTraceMatrix,
  printToPDF,
} from './index';

jest.mock('html-validator', () => ({
  __esModule: true,
  default: jest.fn(async () => ({ messages: [] })),
}));

type PlaywrightModule = typeof import('playwright');

describe('@soipack/report', () => {
  const mockedValidator = htmlValidator as jest.MockedFunction<typeof htmlValidator>;
  const goldenDir = path.resolve(__dirname, '__fixtures__', 'goldens');
  const maybeUpdateGolden = (fileName: string, value: string) => {
    if (process.env.UPDATE_GOLDENS === '1') {
      writeFileSync(path.join(goldenDir, fileName), value, 'utf-8');
    }
  };
  const sanitizeHtml = (value: string): string => value.replace(/>\s+</g, '><').replace(/\s{2,}/g, ' ').trim();
  const hashHtml = (value: string): string => {
    const normalized = sanitizeHtml(value).replace(
      /<p class="report-meta">Snapshot:.*?<\/p>/,
      '',
    );
    return createHash('sha256').update(normalized).digest('hex');
  };
  const gitFixture: BuildInfo = {
    hash: '1234567890abcdef1234567890abcdef12345678',
    author: 'Example Dev',
    date: '2024-02-01T09:00:00Z',
    message: 'Add avionics tests',
    branches: ['main'],
    tags: ['v1.0.0'],
    dirty: false,
    remoteOrigins: ['https://example.com/repo.git'],
  };

  beforeEach(() => {
    mockedValidator.mockClear();
  });

  it('renders compliance matrix with JSON payload', () => {
    const fixture = createReportFixture();
    const result = renderComplianceMatrix(fixture.snapshot, {
      manifestId: fixture.manifestId,
      objectivesMetadata: fixture.objectives,
      title: 'Kurumsal Uyum Matrisi',
      git: gitFixture,
      signoffs: fixture.signoffs,
    });

    expect(result.json.manifestId).toBe(fixture.manifestId);
    expect(result.json.stats).toEqual(fixture.snapshot.stats);
    expect(result.json.objectives).toHaveLength(fixture.snapshot.objectives.length);
    expect(result.json.requirementCoverage).toHaveLength(
      fixture.snapshot.requirementCoverage.length,
    );
    expect(result.json.qualityFindings.length).toBeGreaterThan(0);
    expect(Array.isArray(result.json.traceSuggestions)).toBe(true);
    expect(result.json.git).toEqual(gitFixture);
    expect(result.json.snapshotId).toBe(fixture.snapshot.version.id);
    expect(result.json.snapshotVersion).toEqual(fixture.snapshot.version);
    expect(result.json.risk?.profile.score).toBeGreaterThan(0);
    expect(result.json.signoffs).toHaveLength(fixture.signoffs.length);

    maybeUpdateGolden('compliance-matrix.html', result.html);
    const goldenHtml = readFileSync(path.join(goldenDir, 'compliance-matrix.html'), 'utf-8');
    expect(hashHtml(result.html)).toBe(hashHtml(goldenHtml));
    expect(result.html).toContain('Kanıt Manifest ID');
    expect(result.html).toContain('Commit:');
    expect(result.html).toContain('Kalite Bulguları');
    expect(result.html).toContain(`Snapshot: <strong>${fixture.snapshot.version.id}</strong>`);
    expect(result.html).toContain('Risk Profili');
    expect(result.html).toContain('Signoff Zaman Çizelgesi');
  });

  it('renders combined compliance and coverage report with valid HTML', async () => {
    const fixture = createReportFixture();
    const coverage = coverageSummaryFixture();
    const coverageWarnings = ['MC/DC kapsam verisi eksik: src/legacy/logger.ts'];
    const backlog: ChangeRequestBacklogItem[] = [
      {
        key: 'CR-42',
        summary: 'Flight control gain update',
        status: 'In Progress',
        statusCategory: 'In Progress',
        assignee: 'Alex Pilot',
        updatedAt: '2024-09-01T11:00:00Z',
        priority: 'High',
        url: 'https://jira.example.com/browse/CR-42',
        transitions: [{ id: '1', name: 'Submit for Review', toStatus: 'Ready for Review' }],
        attachments: [
          {
            id: 'att-1',
            filename: 'impact-analysis.pdf',
            url: 'https://jira.example.com/secure/attachment/att-1',
            size: 4096,
          },
        ],
      },
    ];
    const ledgerDiffs: LedgerAttestationDiffItem[] = [
      {
        snapshotId: 'SNAP-20240901',
        ledgerRoot: 'abcd1234',
        attestedAt: '2024-09-01T12:30:00Z',
        manifestDigest: 'deadbeef',
        previousLedgerRoot: '0123ffff',
        addedEvidence: ['EV-100', 'EV-101'],
        removedEvidence: ['EV-050'],
      },
    ];

    const result = renderComplianceCoverageReport(fixture.snapshot, coverage, {
      manifestId: fixture.manifestId,
      objectivesMetadata: fixture.objectives,
      title: 'Uyum ve Kapsam Özeti',
      git: gitFixture,
      coverageWarnings,
      signoffs: fixture.signoffs,
      changeRequestBacklog: backlog,
      ledgerDiffs,
    });

    expect(result.coverageWarnings).toEqual(coverageWarnings);
    expect(result.coverage).toEqual(coverage);
    expect(result.html).toContain('Kapsam Özeti');
    expect(result.html).toContain('MC/DC');
    expect(result.html).toContain('Değişiklik Talepleri Birikimi');
    expect(result.html).toContain('CR-42');
    expect(result.html).toContain('impact-analysis.pdf');
    expect(result.html).toContain('Ledger Attestasyon Özeti');
    expect(result.html).toContain('SNAP-20240901');
    expect(result.json.coverage).toEqual(coverage);
    expect(result.json.coverageWarnings).toEqual(coverageWarnings);
    expect(result.json.changeRequestBacklog).toEqual(backlog);
    expect(result.json.ledgerDiffs).toEqual(ledgerDiffs);
    expect(result.json.snapshotId).toBe(fixture.snapshot.version.id);
    expect(result.json.snapshotVersion).toEqual(fixture.snapshot.version);
    expect(result.changeRequestBacklog).toEqual(backlog);
    expect(result.ledgerDiffs).toEqual(ledgerDiffs);
    expect(result.html).toContain('Risk Profili');
    expect(result.html).toContain('Signoff Zaman Çizelgesi');

    mockedValidator.mockResolvedValueOnce({ messages: [] });
    const validation = await htmlValidator({ data: result.html, format: 'json' });
    const errors = (validation.messages ?? []).filter((message) => message.type === 'error');
    expect(mockedValidator).toHaveBeenCalledWith(expect.objectContaining({ format: 'json' }));
    expect(errors).toHaveLength(0);
  });

  it('renders trace matrix with trace information', () => {
    const fixture = createReportFixture();
    const html = renderTraceMatrix(fixture.traces, {
      manifestId: fixture.manifestId,
      title: 'Kurumsal İzlenebilirlik Matrisi',
      generatedAt: fixture.snapshot.generatedAt,
      coverage: fixture.snapshot.requirementCoverage,
      git: gitFixture,
      snapshotId: fixture.snapshot.version.id,
      snapshotVersion: fixture.snapshot.version,
    });

    maybeUpdateGolden('trace-matrix.html', html);
    const goldenHtml = readFileSync(path.join(goldenDir, 'trace-matrix.html'), 'utf-8');
    expect(hashHtml(html)).toBe(hashHtml(goldenHtml));
    expect(html).toContain('Gereksinim → Test → Kod');
    expect(html).toContain(`Snapshot: <strong>${fixture.snapshot.version.id}</strong>`);
  });

  it('renders suggestion blocks when trace recommendations are present', () => {
    const fixture = createReportFixture();
    const html = renderTraceMatrix(fixture.traces, {
      manifestId: fixture.manifestId,
      generatedAt: fixture.snapshot.generatedAt,
      coverage: fixture.snapshot.requirementCoverage,
      git: gitFixture,
      snapshotId: fixture.snapshot.version.id,
      snapshotVersion: fixture.snapshot.version,
      suggestions: [
        {
          requirementId: fixture.traces[0].requirement.id,
          type: 'test' as const,
          targetId: 'TC-SUGGEST',
          targetName: 'TC-SUGGEST',
          confidence: 'high' as const,
          reason: 'Test kimliği gereksinim kodunu içeriyor.',
        },
      ],
    });

    expect(html).toContain('Önerilen İz Bağlantıları');
    expect(html).toContain('TC-SUGGEST');
  });

  it('renders gap analysis with objective metadata', () => {
    const fixture = createReportFixture();
    const html = renderGaps(fixture.snapshot, {
      manifestId: fixture.manifestId,
      objectivesMetadata: fixture.objectives,
      title: 'Uyum Boşlukları',
      git: gitFixture,
      snapshotId: fixture.snapshot.version.id,
      snapshotVersion: fixture.snapshot.version,
    });

    maybeUpdateGolden('gaps.html', html);
    const goldenHtml = readFileSync(path.join(goldenDir, 'gaps.html'), 'utf-8');
    expect(hashHtml(html)).toBe(hashHtml(goldenHtml));
    expect(html).toContain('Boşluk');
    expect(html).toContain(`Snapshot: <strong>${fixture.snapshot.version.id}</strong>`);
  });

  it('prints combined report PDF using Playwright with coverage warnings listed', async () => {
    const pdfBuffer = Buffer.from('pdf');
    const fixture = createReportFixture();
    const coverage = coverageSummaryFixture();
    const warnings = [
      'MC/DC kapsam verisi eksik: PDF-WARN-1',
      'Karar kapsamı verisi bulunamadı: PDF-WARN-2',
    ];
    const report = renderComplianceCoverageReport(fixture.snapshot, coverage, {
      manifestId: fixture.manifestId,
      objectivesMetadata: fixture.objectives,
      title: 'Uyum ve Kapsam Raporu',
      coverageWarnings: warnings,
      git: gitFixture,
      signoffs: fixture.signoffs,
    });
    const actions: string[] = [];

    const pageStub = {
      async setContent(content: string) {
        actions.push('setContent');
        expect(content).toContain('<h1>Uyum ve Kapsam Raporu</h1>');
        expect(content).toContain('Rapor Tarihi: 2024-02-01 12:00 UTC');
        expect(content).toContain('<li class="muted">MC/DC kapsam verisi eksik: PDF-WARN-1</li>');
        expect(content).toContain('Signoff Zaman Çizelgesi');
      },
      async pdf(options: {
        format: string;
        displayHeaderFooter: boolean;
        headerTemplate: string;
        footerTemplate: string;
      }) {
        actions.push('pdf');
        expect(options.format).toBe('A4');
        expect(options.displayHeaderFooter).toBe(true);
        expect(options.headerTemplate).toContain('Sürüm 9.9.9');
        expect(options.footerTemplate).toContain(fixture.manifestId);
        return pdfBuffer;
      },
      async close() {
        actions.push('pageClose');
      },
    };

    const browserStub = {
      async newPage() {
        actions.push('newPage');
        return pageStub;
      },
      async close() {
        actions.push('browserClose');
      },
    };

    const playwrightStub = {
      chromium: {
        async launch() {
          actions.push('launch');
          return browserStub;
        },
      },
    } as unknown as PlaywrightModule;

    mockedValidator.mockResolvedValueOnce({ messages: [] });
    await expect(
      printToPDF(report.html, {
        playwright: playwrightStub,
        version: '9.9.9',
        manifestId: fixture.manifestId,
        generatedAt: fixture.snapshot.generatedAt,
      }),
    ).resolves.toBe(pdfBuffer);

    expect(actions).toEqual(['launch', 'newPage', 'setContent', 'pdf', 'pageClose', 'browserClose']);
  });

  it('keeps legacy HTML and JSON helpers for CLI', () => {
    const requirement = createRequirement('REQ-1', 'Secure login', {
      status: 'approved',
      tags: ['security'],
    });
    const testCase: TestCase = {
      id: 'TC-1',
      name: 'should request 2FA',
      requirementId: 'REQ-1',
      status: 'pending',
    };

    const matrix = [{ requirementId: requirement.id, testCaseIds: [testCase.id] }];

    const html = renderHtmlReport(matrix, [requirement], [testCase], {
      title: 'Custom Report',
    } satisfies HtmlReportOptions);
    const json = renderJsonReport(matrix, [requirement], [testCase]);

    expect(html).toContain('<h1>Custom Report</h1>');
    expect(json).toEqual({
      generatedAt: expect.any(String),
      requirements: [
        {
          requirement,
          tests: [testCase],
        },
      ],
    });
  });
});
