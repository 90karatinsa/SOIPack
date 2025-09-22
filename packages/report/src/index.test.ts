import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';

import type { BuildInfo } from '@soipack/adapters';
import { createRequirement, TestCase } from '@soipack/core';

import { createReportFixture } from './__fixtures__/snapshot';

import {
  HtmlReportOptions,
  renderComplianceMatrix,
  renderGaps,
  renderHtmlReport,
  renderJsonReport,
  renderTraceMatrix,
  printToPDF,
} from './index';

type PlaywrightModule = typeof import('playwright');

describe('@soipack/report', () => {
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

  it('prints PDF using Playwright with metadata in header and footer', async () => {
    const pdfBuffer = Buffer.from('pdf');
    const html = '<html><body><main>report</main></body></html>';
    const actions: string[] = [];

    const pageStub = {
      async setContent(content: string) {
        actions.push('setContent');
        expect(content).toBe(html);
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
        expect(options.footerTemplate).toContain('MANIFEST-001');
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

    await expect(
      printToPDF(html, {
        playwright: playwrightStub,
        version: '9.9.9',
        manifestId: 'MANIFEST-001',
        generatedAt: '2024-02-01T12:00:00Z',
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
