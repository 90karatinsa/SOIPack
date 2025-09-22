import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';

import type { BuildInfo } from '@soipack/adapters';
import { createRequirement, TestCase } from '@soipack/core';
import htmlValidator from 'html-validator';

import { createReportFixture, coverageSummaryFixture } from './__fixtures__/snapshot';

import {
  HtmlReportOptions,
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
  const sanitizeHtml = (value: string): string => value.replace(/>\s+</g, '><').replace(/\s{2,}/g, ' ').trim();
  const hashHtml = (value: string): string => createHash('sha256').update(sanitizeHtml(value)).digest('hex');
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
    });

    expect(result.json.manifestId).toBe(fixture.manifestId);
    expect(result.json.stats).toEqual(fixture.snapshot.stats);
    expect(result.json.objectives).toHaveLength(fixture.snapshot.objectives.length);
    expect(result.json.requirementCoverage).toHaveLength(
      fixture.snapshot.requirementCoverage.length,
    );
    expect(result.json.qualityFindings.length).toBeGreaterThan(0);
    expect(result.json.git).toEqual(gitFixture);

    const goldenHtml = readFileSync(path.join(goldenDir, 'compliance-matrix.html'), 'utf-8');
    expect(hashHtml(result.html)).toBe(hashHtml(goldenHtml));
    expect(result.html).toContain('Kanıt Manifest ID');
    expect(result.html).toContain('Commit:');
    expect(result.html).toContain('Kalite Bulguları');
  });

  it('renders combined compliance and coverage report with valid HTML', async () => {
    const fixture = createReportFixture();
    const coverage = coverageSummaryFixture();
    const coverageWarnings = ['MC/DC kapsam verisi eksik: src/legacy/logger.ts'];

    const result = renderComplianceCoverageReport(fixture.snapshot, coverage, {
      manifestId: fixture.manifestId,
      objectivesMetadata: fixture.objectives,
      title: 'Uyum ve Kapsam Özeti',
      git: gitFixture,
      coverageWarnings,
    });

    expect(result.coverageWarnings).toEqual(coverageWarnings);
    expect(result.coverage).toEqual(coverage);
    expect(result.html).toContain('Kapsam Özeti');
    expect(result.html).toContain('MC/DC');
    expect(result.json.coverage).toEqual(coverage);
    expect(result.json.coverageWarnings).toEqual(coverageWarnings);

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
    });

    const goldenHtml = readFileSync(path.join(goldenDir, 'trace-matrix.html'), 'utf-8');
    expect(hashHtml(html)).toBe(hashHtml(goldenHtml));
    expect(html).toContain('Gereksinim → Test → Kod');
  });

  it('renders gap analysis with objective metadata', () => {
    const fixture = createReportFixture();
    const html = renderGaps(fixture.snapshot, {
      manifestId: fixture.manifestId,
      objectivesMetadata: fixture.objectives,
      title: 'Uyum Boşlukları',
      git: gitFixture,
    });

    const goldenHtml = readFileSync(path.join(goldenDir, 'gaps.html'), 'utf-8');
    expect(hashHtml(html)).toBe(hashHtml(goldenHtml));
    expect(html).toContain('Boşluk');
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
    });
    const actions: string[] = [];

    const pageStub = {
      async setContent(content: string) {
        actions.push('setContent');
        expect(content).toContain('<h1>Uyum ve Kapsam Raporu</h1>');
        expect(content).toContain('Rapor Tarihi: 2024-02-01 12:00 UTC');
        expect(content).toContain('<li class="muted">MC/DC kapsam verisi eksik: PDF-WARN-1</li>');
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
