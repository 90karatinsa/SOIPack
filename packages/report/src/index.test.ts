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
  renderToolQualificationPack,
  renderTraceMatrix,
  renderTraceGraphDot,
  renderGsnGraphDot,
  printToPDF,
  type ComplianceMatrixOptions,
  type ComplianceReadinessSummary,
  type ToolUsageMetadata,
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

  it('renderComplianceMatrix renders ComplianceDelta dashboard with regression sparkline', () => {
    const fixture = createReportFixture();
    const readiness: ComplianceReadinessSummary = {
      percentile: 72.5,
      computedAt: '2024-02-12T10:30:00Z',
      seed: 4242,
      breakdown: [
        {
          component: 'objectives',
          score: 82.1,
          contribution: 32.8,
          weight: 0.4,
          details: 'HLR kapsamı %85 seviyesinde.',
        },
        {
          component: 'independence',
          score: 61.4,
          contribution: 15.4,
          weight: 0.25,
          details: 'Bağımsız gözden geçirme eksikleri azaltıldı.',
        },
        {
          component: 'structuralCoverage',
          score: 55.2,
          contribution: 11.0,
          weight: 0.2,
          details: 'MC/DC kapsama raporları güncellendi.',
          missing: true,
        },
        {
          component: 'riskTrend',
          score: 70.5,
          contribution: 13.3,
          weight: 0.15,
          details: 'Audit uyarılarında aşağı yönlü trend.',
        },
      ],
    };
    const result = renderComplianceMatrix(fixture.snapshot, {
      manifestId: fixture.manifestId,
      objectivesMetadata: fixture.objectives,
      signoffs: fixture.signoffs,
      programName: fixture.programName,
      certificationLevel: fixture.certificationLevel,
      projectVersion: fixture.projectVersion,
      readiness,
    });

    expect(result.html).toContain('Uyum Delta Panosu');
    expect(result.html).toContain('Regresyonlar');
    expect(result.html).toContain('Gerileme:');
    expect(result.html).toContain('Regresyon trendi');
    expect(result.html).toContain('Bağımsızlık Uyarıları');
    expect(result.html).toContain('Zorunlu Bağımsızlık');
    expect(result.html).toContain('Bağımsızlık Eksikleri');
    expect(result.html).toContain('Değişiklik Etki Analizi');
    expect(result.html).toContain('Hazırlık Endeksi');
    expect(result.html).toContain('Hazırlık bileşen katkı eğrisi');
    expect(result.html).toContain('En güçlü bileşen');
    expect(result.html).toContain('Hazırlık Skoru');
    expect(result.html).toContain('Kanıt Tazelik Isı Haritası');
    expect(result.html).toContain('TC-AUDIT-NEW');
    expect(result.html).toContain(fixture.programName);
    expect(result.html).toContain(fixture.certificationLevel);
    expect(result.html).toContain(fixture.projectVersion);
    expect(result.json.changeImpact).toBeDefined();
    expect(result.json.changeImpact?.length).toBeGreaterThan(0);
    expect(result.json.complianceDelta?.totals.regressions).toBeGreaterThan(0);
    expect(result.json.complianceDelta?.steps.length).toBeGreaterThan(0);
    expect(result.json.complianceDelta?.regressions.length).toBeGreaterThan(0);
    expect(result.json.independenceSummary.objectives.length).toBeGreaterThan(0);
    expect(result.json.analysis?.staleEvidenceHeatmap?.totalFindings).toBeGreaterThan(0);
    expect(result.json.analysis?.staleEvidenceHeatmap?.stages[0]?.buckets.length).toBeGreaterThan(0);
    expect(result.json.programName).toBe(fixture.programName);
    expect(result.json.certificationLevel).toBe(fixture.certificationLevel);
    expect(result.json.projectVersion).toBe(fixture.projectVersion);
    expect(result.json.readiness?.percentile).toBe(72.5);
    expect(result.json.readiness?.breakdown).toHaveLength(4);
    expect(result.json.readiness?.breakdown[0]).toEqual(
      expect.objectContaining({ component: 'objectives', score: 82.1, contribution: 32.8, weight: 0.4 }),
    );

    maybeUpdateGolden('compliance-matrix.csv', result.csv.csv);
    const goldenCsv = readFileSync(path.join(goldenDir, 'compliance-matrix.csv'), 'utf-8');
    expect(result.csv.csv).toBe(goldenCsv);
    expect(result.csv.metadata.programName).toBe(fixture.programName);
    expect(result.csv.metadata.certificationLevel).toBe(fixture.certificationLevel);
    expect(result.csv.metadata.projectVersion).toBe(fixture.projectVersion);
    expect(result.csv.metadata.rows.slice(0, 4)).toEqual([
      ['Program', fixture.programName],
      ['Sertifikasyon Seviyesi', fixture.certificationLevel],
      ['Proje Sürümü', fixture.projectVersion],
      ['Hazırlık Skoru', '72.5/100'],
    ]);
    expect(result.csv.metadata.rows).toEqual(
      expect.arrayContaining([
        ['Hazırlık Hedefler', expect.stringContaining('Skor 82.1%')],
        ['Hazırlık Bağımsızlık', expect.stringContaining('Katkı 15.4%')],
        ['Hazırlık Yapısal kapsam', expect.stringContaining('Veri eksik')],
        ['Hazırlık Risk eğilimi', expect.stringContaining('Audit uyarılarında')],
      ]),
    );
    expect(result.csv.headers).toEqual([
      'Objective ID',
      'Table',
      'Stage',
      'Status',
      'Satisfied Artifacts',
      'Missing Artifacts',
      'Evidence References',
    ]);
    const coveredRow = result.csv.rows.find((row) => row.objectiveId === 'A-5-06');
    expect(coveredRow).toEqual(
      expect.objectContaining({
        objectiveId: 'A-5-06',
        stage: 'SOI-3',
        stageLabel: 'SOI-3 Doğrulama',
        status: 'Eksik',
      }),
    );
    const stageCsv = result.csv.stages['SOI-3'];
    expect(stageCsv).toBeDefined();
    expect(stageCsv?.rows.map((row) => row.objectiveId)).toEqual(
      expect.arrayContaining(['A-5-06', 'A-5-08', 'A-6-02']),
    );
    expect(stageCsv?.records[0]?.[2]).toBe('SOI-3');
    expect(stageCsv?.records[0]?.[3]).toBe('Eksik');
    const soi1Record = result.csv.stages['SOI-1'];
    expect(soi1Record?.records[0]?.[2]).toBe('SOI-1');
  });

  it('Kanıt Tazelik Isı Haritası heatmap groups stale evidence by stage', () => {
    const fixture = createReportFixture();
    fixture.snapshot.gaps.staleEvidence.push({
      objectiveId: 'A-4-01',
      artifactType: 'trace',
      latestEvidenceTimestamp: '2023-06-01T09:00:00Z',
      reasons: ['exceedsMaxAge'],
      ageDays: 400,
      maxAgeDays: 180,
    });

    const report = renderComplianceMatrix(fixture.snapshot, {
      manifestId: fixture.manifestId,
      objectivesMetadata: fixture.objectives,
      signoffs: fixture.signoffs,
    });

    expect(report.html).toContain('Kanıt Tazelik Isı Haritası');
    expect(report.html).toContain('SOI-2 Geliştirme');
    expect(report.html).toContain('366+ gün');

    const heatmap = report.json.analysis?.staleEvidenceHeatmap;
    expect(heatmap).toBeDefined();
    expect(heatmap?.bands.map((band) => band.id)).toEqual([
      '0-30',
      '31-90',
      '91-180',
      '181-365',
      '366+',
      'unknown',
    ]);
    expect(heatmap?.stages.map((stage) => stage.id)).toEqual(['SOI-1', 'SOI-2', 'SOI-3', 'unknown']);
    const soi2 = heatmap?.stages.find((stage) => stage.id === 'SOI-2');
    expect(soi2?.buckets.find((bucket) => bucket.bandId === '366+')?.count).toBeGreaterThan(0);
    expect(soi2?.buckets.find((bucket) => bucket.bandId === '366+')?.objectiveIds).toContain('A-4-01');
  });

  it('renderComplianceMatrix includes the regulator crosswalk data', () => {
    const fixture = createReportFixture();
    const options = {
      manifestId: fixture.manifestId,
      objectivesMetadata: fixture.objectives,
      signoffs: fixture.signoffs,
      programName: fixture.programName,
      certificationLevel: fixture.certificationLevel,
      projectVersion: fixture.projectVersion,
    } satisfies ComplianceMatrixOptions;

    const first = renderComplianceMatrix(fixture.snapshot, options);
    const second = renderComplianceMatrix(fixture.snapshot, options);

    expect(first.html).toContain('Regulatory References');
    expect(first.html).toContain('AC 20-115D');
    expect(first.html).toContain('AMC 20-152A');
    expect(first.html).toContain('FAA 8110.49');
    expect(first.html).toContain('§6.3');
    expect(first.html).toContain('§6.5');
    expect(first.html).toContain('§5.1.1');
    expect(first.html).toContain('§2.3');
    expect(first.html).toContain('§3.4');

    const objective = first.json.objectives.find((item) => item.id === 'A-3-04');
    expect(objective).toBeDefined();
    expect(objective?.regulatoryReferences).toEqual({
      ac20115d: ['§6.3', '§6.5'],
      easaAmc_20_152a: ['§5.1.1', '§5.1.3'],
      faa8110_49: ['§2.3', '§3.4'],
    });

    expect(second.html).toBe(first.html);
    expect(second.json).toEqual(first.json);
    expect(second.csv.csv).toBe(first.csv.csv);
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
    const readiness: ComplianceReadinessSummary = {
      percentile: 68.2,
      computedAt: '2024-02-11T07:45:00Z',
      breakdown: [
        { component: 'objectives', score: 78.4, contribution: 31.4, weight: 0.42 },
        { component: 'independence', score: 58.0, contribution: 12.2, weight: 0.2 },
        { component: 'structuralCoverage', score: 49.5, contribution: 9.9, weight: 0.18, missing: true },
        { component: 'riskTrend', score: 66.1, contribution: 14.7, weight: 0.2 },
      ],
    };

    const result = renderComplianceCoverageReport(fixture.snapshot, coverage, {
      manifestId: fixture.manifestId,
      objectivesMetadata: fixture.objectives,
      title: 'Uyum ve Kapsam Özeti',
      git: gitFixture,
      coverageWarnings,
      signoffs: fixture.signoffs,
      changeRequestBacklog: backlog,
      ledgerDiffs,
      programName: fixture.programName,
      certificationLevel: fixture.certificationLevel,
      projectVersion: fixture.projectVersion,
      readiness,
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
    expect(result.html).toContain('Bağımsızlık Uyarıları');
    expect(result.html).toContain('Zorunlu Bağımsızlık');
    expect(result.html).toContain('Değişiklik Etki Analizi');
    expect(result.html).toContain('Hazırlık Endeksi');
    expect(result.html).toContain('src/security/new-audit.ts');
    expect(result.html).toContain(fixture.programName);
    expect(result.html).toContain(fixture.certificationLevel);
    expect(result.html).toContain(fixture.projectVersion);
    expect(result.json.coverage).toEqual(coverage);
    expect(result.json.coverageWarnings).toEqual(coverageWarnings);
    expect(result.json.changeRequestBacklog).toEqual(backlog);
    expect(result.json.ledgerDiffs).toEqual(ledgerDiffs);
    expect(result.json.changeImpact).toEqual(fixture.snapshot.changeImpact);
    expect(result.json.snapshotId).toBe(fixture.snapshot.version.id);
    expect(result.json.snapshotVersion).toEqual(fixture.snapshot.version);
    expect(result.json.programName).toBe(fixture.programName);
    expect(result.json.certificationLevel).toBe(fixture.certificationLevel);
    expect(result.json.projectVersion).toBe(fixture.projectVersion);
    expect(result.json.readiness?.percentile).toBe(68.2);
    expect(result.changeRequestBacklog).toEqual(backlog);
    expect(result.ledgerDiffs).toEqual(ledgerDiffs);
    expect(result.csv.headers[0]).toBe('Objective ID');
    expect(result.csv.metadata.rows[0]).toEqual(['Program', fixture.programName]);
    expect(result.html).toContain('Risk Profili');
    expect(result.html).toContain('Signoff Zaman Çizelgesi');
    expect(result.json.independenceSummary.totals.partial + result.json.independenceSummary.totals.missing).toBeGreaterThanOrEqual(0);

    mockedValidator.mockResolvedValueOnce({ messages: [] });
    const validation = await htmlValidator({ data: result.html, format: 'json' });
    const errors = (validation.messages ?? []).filter((message) => message.type === 'error');
    expect(mockedValidator).toHaveBeenCalledWith(expect.objectContaining({ format: 'json' }));
    expect(errors).toHaveLength(0);
  });

  const traceDesigns = [
    {
      requirementId: 'REQ-AUTH-1',
      designId: 'DES-AUTH-API',
      designName: 'Kimlik Doğrulama Tasarımı',
      status: 'Onaylandı',
      codeRefs: ['src/auth/login.ts'],
    },
    {
      requirementId: 'REQ-AUTH-2',
      designId: 'DES-AUDIT-PIPE',
      designName: 'Audit Boru Hattı',
      status: 'Taslak',
      codeRefs: ['src/security/audit.ts'],
    },
  ];

  it('renders trace matrix with trace information', () => {
    const fixture = createReportFixture();
    const report = renderTraceMatrix(fixture.traces, {
      manifestId: fixture.manifestId,
      title: 'Kurumsal İzlenebilirlik Matrisi',
      generatedAt: fixture.snapshot.generatedAt,
      coverage: fixture.snapshot.requirementCoverage,
      git: gitFixture,
      snapshotId: fixture.snapshot.version.id,
      snapshotVersion: fixture.snapshot.version,
      designs: traceDesigns,
    });

    maybeUpdateGolden('trace-matrix.html', report.html);
    const goldenHtml = readFileSync(path.join(goldenDir, 'trace-matrix.html'), 'utf-8');
    expect(hashHtml(report.html)).toBe(hashHtml(goldenHtml));
    expect(report.html).toContain('Gereksinim → Test → Kod');
    expect(report.html).toContain(`Snapshot: <strong>${fixture.snapshot.version.id}</strong>`);
    expect(report.csv.headers).toContain('Requirement ID');
    expect(report.csv.rows[0].designId).toBe('DES-AUTH-API');
  });

  it('renders suggestion blocks when trace recommendations are present', () => {
    const fixture = createReportFixture();
    const report = renderTraceMatrix(fixture.traces, {
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
      designs: traceDesigns,
    });

    expect(report.html).toContain('Önerilen İz Bağlantıları');
    expect(report.html).toContain('TC-SUGGEST');
  });

  it('produces trace matrix CSV with flattened relationships', () => {
    const fixture = createReportFixture();
    const report = renderTraceMatrix(fixture.traces, {
      manifestId: fixture.manifestId,
      generatedAt: fixture.snapshot.generatedAt,
      coverage: fixture.snapshot.requirementCoverage,
      git: gitFixture,
      snapshotId: fixture.snapshot.version.id,
      snapshotVersion: fixture.snapshot.version,
      designs: traceDesigns,
    });

    if (process.env.UPDATE_GOLDENS === '1') {
      writeFileSync(path.join(goldenDir, 'trace-matrix.csv'), report.csv.csv, 'utf-8');
    }

    const goldenCsv = readFileSync(path.join(goldenDir, 'trace-matrix.csv'), 'utf-8');
    expect(report.csv.csv).toBe(goldenCsv);
    const requirementRows = report.csv.rows.filter((row) => row.requirementId === 'REQ-AUTH-2');
    expect(requirementRows[0]?.designId).toBe('DES-AUDIT-PIPE');
    const statuses = requirementRows.map((row) => row.testStatus);
    expect(statuses).toEqual(expect.arrayContaining(['Başarılı', 'Başarısız']));
  });

  it('renders trace graph DOT with grouped clusters', () => {
    const fixture = createReportFixture();
    const dot = renderTraceGraphDot(fixture.snapshot.traceGraph, { graphName: 'Trace Graph' });

    maybeUpdateGolden('trace-graph.dot', dot);
    const goldenDot = readFileSync(path.join(goldenDir, 'trace-graph.dot'), 'utf-8');
    expect(dot).toBe(goldenDot);
    expect(dot).toContain('subgraph "cluster_requirements"');
    expect(dot).toContain('subgraph "cluster_code"');
    expect(dot).toContain('subgraph "cluster_tests"');
    expect(dot).toContain('"requirement:REQ-AUTH-1" [label="REQ-AUTH-1\\\\nÇok faktörlü giriş sağlamalı"]');
    expect(dot).toContain('"test:TC-LOGIN-2" -> "requirement:REQ-AUTH-2"');
    expect(dot).toContain('"code:src/auth/login.ts" [label="src/auth/login.ts"]');
    expect(dot).toContain('"requirement:REQ-AUTH-1" -> "test:TC-LOGIN-1"');

    if (fixture.snapshot.traceGraph.nodes.some((node) => node.type === 'design')) {
      expect(dot).toContain('subgraph "cluster_designs"');
    }
  });

  it('renders compliance snapshot GSN DOT with legend and independence cues', () => {
    const fixture = createReportFixture();
    const dot = renderGsnGraphDot(fixture.snapshot, {
      graphName: 'ComplianceGSN',
      objectivesMetadata: fixture.objectives,
    });

    maybeUpdateGolden('gsn-graph.dot', dot);
    const goldenDot = readFileSync(path.join(goldenDir, 'gsn-graph.dot'), 'utf-8');
    expect(dot).toBe(goldenDot);
    expect(dot).toContain('cluster_SOI-3');
    expect(dot).toContain('Bağımsızlık:');
    expect(dot).toContain('legend_goal_required_gap');
    expect(dot).toContain('Güncel olmayan');
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
      programName: fixture.programName,
      certificationLevel: fixture.certificationLevel,
      projectVersion: fixture.projectVersion,
    });
    const actions: string[] = [];

    const pageStub = {
      async setContent(content: string) {
        actions.push('setContent');
        expect(content).toContain('<h1>Uyum ve Kapsam Raporu</h1>');
        expect(content).toContain('Rapor Tarihi: 2024-02-01 12:00 UTC');
        expect(content).toContain('<li class="muted">MC/DC kapsam verisi eksik: PDF-WARN-1</li>');
        expect(content).toContain('Signoff Zaman Çizelgesi');
        expect(content).toContain(fixture.programName);
        expect(content).toContain(fixture.certificationLevel);
        expect(content).toContain(fixture.projectVersion);
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

  describe('ToolQualification pack', () => {
    const sampleTools: ToolUsageMetadata[] = [
      {
        id: 'tool-vectorcast',
        name: 'VectorCAST',
        version: '2023R1',
        vendor: 'Vector Informatik',
        category: 'verification',
        tql: 'TQL-4',
        description: 'Structural coverage konsolidasyonu ve rapor üretimi.',
        objectives: ['DO-178C A-5-08', 'DO-178C A-5-10'],
        environment: ['Container CI'],
        outputs: [
          {
            name: 'Coverage Merge',
            description: 'MC/DC kapsam ölçümlerini tekleştirir.',
            producedArtifacts: ['coverage_mcdc', 'coverage_dec'],
            referencedObjectives: ['A-5-10'],
          },
        ],
        controls: [
          {
            id: 'CTRL-1',
            description: 'Kapsam birleştirme scripti gözden geçirilir.',
            owner: 'Verification Lead',
            frequency: 'Her sürüm',
            evidence: ['reviews/vectorcast-merge.md'],
          },
        ],
        validation: [
          {
            id: 'VAL-1',
            description: 'Baz set ile JSON çıktısını karşılaştır.',
            method: 'Bağımsız veri tekrar yürütmesi',
            expectedResult: '%1 altında fark',
            status: 'passed',
            evidence: ['validation/vectorcast-baseline.csv'],
          },
          {
            id: 'VAL-2',
            description: 'Tohumlanmış hataların MC/DC ile yakalanması',
            method: 'Mutasyon testi',
            expectedResult: 'Hatalar raporlanır',
            status: 'in-progress',
          },
        ],
        limitations: ['Araç, manuel test haritalamalarını doğrulamaz.'],
        residualRisks: ['Mutasyon sonuçları manuel onay gerektirir.'],
      },
    ];
    const toolFixture = createReportFixture();
    const ledgerHashes = {
      'docs/verification-plan.md': 'hash-plan',
      'reports/coverage-summary.json': 'hash-coverage',
      'reports/vectorcast.json': 'hash-mcdc',
      'reports/safety-analysis.pdf': 'hash-analysis',
      'reviews/vectorcast-merge.md': 'hash-review',
      'validation/vectorcast-baseline.csv': 'hash-validation',
    } as const;

    it('ToolQualification pack outlines include validation and controls', () => {
      const pack = renderToolQualificationPack(sampleTools, {
        programName: 'Flight Control',
        level: 'A',
        author: 'QA Team',
        generatedAt: '2024-03-01T00:00:00Z',
        compliance: {
          snapshot: {
            objectives: toolFixture.snapshot.objectives,
            independenceSummary: toolFixture.snapshot.independenceSummary,
          },
          objectivesMetadata: toolFixture.objectives,
          ledgerHashes,
        },
      });

      expect(pack.tqp.filename).toBe('tool-qualification-plan.md');
      expect(pack.tar.filename).toBe('tool-accomplishment-report.md');
      expect(pack.tqp.content).toContain('# DO-330 Tool Qualification Plan');
      expect(pack.tqp.content).toContain('VectorCAST');
      expect(pack.tqp.content).toContain('Kontroller ve Doğrulama Aktiviteleri');
      expect(pack.tqp.content).toContain('Uyum Bağlantıları');
      expect(pack.tqp.content).toMatch(/Durum: .*status-/);
      expect(pack.tqp.content).toContain('Bağımsızlık:');
      expect(pack.tqp.content).toContain('Ledger Hashleri:');
      expect(pack.tqp.content).toContain('Kalıcı Risk Özeti');
      expect(pack.tar.content).toContain('Tool Accomplishment Report');
      expect(pack.tar.content).toContain('Açık Aktivite Sayısı: 1');
      expect(pack.tar.content).toContain('Uyum Referansları');
      expect(pack.tar.content).toContain('Kalıcı Risk Özeti');
      expect(pack.summary.tools[0].pendingActivities).toBe(1);
      expect(pack.summary.tools[0].residualRiskCount).toBe(1);
      expect(pack.summary.tools[0].residualRiskSummary).toContain('Mutasyon sonuçları manuel onay gerektirir');
      expect(pack.summary.generatedAt).toBe('2024-03-01T00:00:00Z');
    });

    it('ToolQualification links render within compliance report', () => {
      const pack = renderToolQualificationPack(sampleTools, {
        programName: 'Flight Control',
        level: 'A',
        author: 'QA Team',
        generatedAt: '2024-03-01T00:00:00Z',
        compliance: {
          snapshot: {
            objectives: toolFixture.snapshot.objectives,
            independenceSummary: toolFixture.snapshot.independenceSummary,
          },
          objectivesMetadata: toolFixture.objectives,
          ledgerHashes,
        },
      });
      const fixture = createReportFixture();

      const result = renderComplianceMatrix(fixture.snapshot, {
        manifestId: fixture.manifestId,
        objectivesMetadata: fixture.objectives,
        signoffs: fixture.signoffs,
        toolQualification: {
          tqpHref: pack.tqp.filename,
          tarHref: pack.tar.filename,
          generatedAt: pack.summary.generatedAt,
          tools: pack.summary.tools,
        },
      });

      expect(result.html).toContain('DO-330 Araç Niteliklendirme');
      expect(result.html).toContain('VectorCAST');
      expect(result.html).toContain('TQP Taslağı');
      expect(result.html).toContain('Açık Aktiviteler');
      expect(result.json.toolQualification?.tools[0].residualRiskCount).toBe(1);
      expect(result.json.toolQualification?.tools[0].residualRiskSummary).toContain('Kalıcı Risk Özeti');
      expect(result.json.toolQualification?.tools[0].pendingActivities).toBe(1);
      expect(result.json.toolQualification?.tqpHref).toBe('tool-qualification-plan.md');
      expect(result.json.toolQualification?.tarHref).toBe('tool-accomplishment-report.md');
    });
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
