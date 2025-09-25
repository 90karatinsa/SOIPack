import type { BuildInfo, CoverageMetric, CoverageReport } from '@soipack/adapters';
import { Objective, ObjectiveArtifactType, Requirement, SnapshotVersion, TestCase } from '@soipack/core';
import {
  ComplianceSnapshot,
  ComplianceStatistics,
  RequirementTrace,
  RequirementCoverageStatus,
  CoverageStatus,
  type TraceSuggestion,
} from '@soipack/engine';
import nunjucks from 'nunjucks';
import type { Browser, Page } from 'playwright';

import packageInfo from '../package.json';

import { renderCoverageSummarySection } from './complianceReport.html';

type PlaywrightModule = typeof import('playwright');

type GapCategoryKey = keyof ComplianceSnapshot['gaps'];

interface LayoutSummaryMetric {
  label: string;
  value: string;
  accent?: boolean;
}

interface BaseReportOptions {
  title?: string;
  manifestId?: string;
  generatedAt?: string;
  version?: string;
  git?: BuildInfo | null;
  snapshotId?: string;
  snapshotVersion?: SnapshotVersion;
}

interface LayoutContext extends BaseReportOptions {
  summaryMetrics: LayoutSummaryMetric[];
  subtitle?: string;
  content: string;
}

export interface ComplianceMatrixOptions extends BaseReportOptions {
  objectivesMetadata?: Objective[];
  signoffs?: SignoffTimelineEntry[];
}

export interface TraceMatrixOptions extends BaseReportOptions {
  coverage?: RequirementCoverageStatus[];
  suggestions?: TraceSuggestion[];
}

export interface GapReportOptions extends BaseReportOptions {
  objectivesMetadata?: Objective[];
}

interface ComplianceMatrixRow {
  id: string;
  status: ComplianceSnapshot['objectives'][number]['status'];
  statusLabel: string;
  statusClass: string;
  table?: string;
  name?: string;
  desc?: string;
  satisfiedArtifacts: string[];
  missingArtifacts: string[];
  evidenceRefs: string[];
}

interface RequirementCoverageRow {
  requirementId: string;
  requirementTitle: string;
  statusLabel: string;
  statusClass: string;
  coverageLabel?: string;
  codePaths: string[];
}

interface QualityFindingRow {
  id: string;
  severityLabel: string;
  severityClass: string;
  message: string;
  requirementId?: string;
  recommendation?: string;
  relatedTests: string[];
}

export interface SignoffTimelineEntry {
  id: string;
  documentId: string;
  revisionId: string;
  revisionHash: string;
  requestedBy: string;
  requestedFor: string;
  requestedAt: string;
  status: 'pending' | 'approved' | string;
  approvedAt?: string | null;
  signerId?: string | null;
  signerPublicKey?: string | null;
  signature?: string | null;
  workspaceId?: string;
}

interface RiskBreakdownView {
  factorLabel: string;
  contributionLabel: string;
  weightLabel: string;
  severityClass: string;
  details: string;
}

interface RiskDriftView {
  classificationLabel: string;
  summary: string;
  slopeLabel: string;
  projectionLabel: string;
  confidenceLabel: string;
}

interface RiskView {
  score: number;
  scoreLabel: string;
  classification: string;
  classificationLabel: string;
  classificationClass: string;
  breakdown: RiskBreakdownView[];
  missingSignals: string[];
  drift?: RiskDriftView;
}

interface SignoffTimelineEventView {
  label: string;
  actor: string;
  timestamp: string;
  details?: string;
}

interface SignoffTimelineEntryView {
  id: string;
  documentId: string;
  revisionId: string;
  revisionHash: string;
  statusLabel: string;
  statusClass: string;
  events: SignoffTimelineEventView[];
}

interface SignoffTimelineView {
  entries: SignoffTimelineEntryView[];
}

interface ComplianceMatrixView {
  objectives: ComplianceMatrixRow[];
  requirementCoverage: RequirementCoverageRow[];
  qualityFindings: QualityFindingRow[];
  summaryMetrics: LayoutSummaryMetric[];
  risk?: RiskView;
  signoffs?: SignoffTimelineView;
}

interface TraceMatrixRow {
  requirementId: string;
  requirementTitle: string;
  requirementStatus?: Requirement['status'];
  tests: Array<{
    id: string;
    name: string;
    statusLabel: string;
    statusClass: string;
  }>;
  codePaths: Array<{
    path: string;
    coverageLabel?: string;
  }>;
  coverage?: {
    status: CoverageStatus;
    statusLabel: string;
    statusClass: string;
    coverageLabel?: string;
  };
}

interface TraceSuggestionEntryView {
  typeLabel: string;
  targetId: string;
  targetName: string;
  reason: string;
  confidenceLabel: string;
  confidenceClass: string;
}

interface TraceSuggestionGroup {
  requirementId: string;
  requirementTitle: string;
  entries: TraceSuggestionEntryView[];
}

interface GapReportRow {
  objectiveId: string;
  table?: string;
  name?: string;
  desc?: string;
  missingArtifacts: string[];
}

export interface ComplianceMatrixJson {
  manifestId?: string;
  generatedAt: string;
  version: string;
  snapshotId: string;
  snapshotVersion: SnapshotVersion;
  stats: ComplianceStatistics;
  objectives: Array<{
    id: string;
    status: ComplianceSnapshot['objectives'][number]['status'];
    table?: string;
    name?: string;
    desc?: string;
    satisfiedArtifacts: string[];
    missingArtifacts: string[];
    evidenceRefs: string[];
  }>;
  requirementCoverage: Array<{
    requirementId: string;
    title?: string;
    status: RequirementCoverageStatus['status'];
    coverage?: RequirementCoverageStatus['coverage'];
    codePaths: string[];
  }>;
  qualityFindings: Array<{
    id: string;
    severity: string;
    category: string;
    message: string;
    requirementId?: string;
    recommendation?: string;
    relatedTests?: string[];
  }>;
  traceSuggestions: Array<{
    requirementId: string;
    type: TraceSuggestion['type'];
    targetId: string;
    targetName?: string;
    confidence: TraceSuggestion['confidence'];
    reason: string;
    viaTestId?: string;
  }>;
  git?: BuildInfo | null;
  risk?: ComplianceSnapshot['risk'] | null;
  signoffs: SignoffTimelineEntry[];
}

export interface ComplianceMatrixResult {
  html: string;
  json: ComplianceMatrixJson;
}

export interface ComplianceCoverageReportOptions extends ComplianceMatrixOptions {
  coverageWarnings?: string[];
}

export interface ComplianceCoverageReportResult extends ComplianceMatrixResult {
  json: ComplianceMatrixJson & { coverage: CoverageReport; coverageWarnings: string[] };
  coverage: CoverageReport;
  coverageWarnings: string[];
}

export interface PrintToPdfOptions extends BaseReportOptions {
  playwright?: PlaywrightModule;
  margin?: {
    top?: string;
    bottom?: string;
    left?: string;
    right?: string;
  };
}

const env = new nunjucks.Environment(undefined, {
  autoescape: true,
  trimBlocks: true,
  lstripBlocks: true,
});

const statusLabels: Record<ComplianceSnapshot['objectives'][number]['status'], string> = {
  covered: 'Tam Karşılandı',
  partial: 'Kısmen Karşılandı',
  missing: 'Eksik',
};

const testStatusLabels: Record<string, { label: string; className: string }> = {
  passed: { label: 'Başarılı', className: 'status-covered' },
  failed: { label: 'Başarısız', className: 'status-missing' },
  skipped: { label: 'Atlandı', className: 'status-partial' },
};

const coverageStatusLabels: Record<CoverageStatus, { label: string; className: string }> = {
  covered: { label: 'Tam Kaplandı', className: 'status-covered' },
  partial: { label: 'Kısmen Kaplandı', className: 'status-partial' },
  missing: { label: 'Kapsam Yok', className: 'status-missing' },
};

const qualitySeverityLabels: Record<
  ComplianceSnapshot['qualityFindings'][number]['severity'],
  { label: string; className: string }
> = {
  error: { label: 'Kritik', className: 'status-missing' },
  warn: { label: 'Uyarı', className: 'status-partial' },
  info: { label: 'Bilgi', className: 'badge-soft' },
};

const suggestionConfidenceLabels: Record<TraceSuggestion['confidence'], { label: string; className: string }> = {
  high: { label: 'Yüksek', className: 'status-covered' },
  medium: { label: 'Orta', className: 'status-partial' },
  low: { label: 'Düşük', className: 'badge-soft' },
};

const suggestionTypeLabels: Record<TraceSuggestion['type'], string> = {
  test: 'Test',
  code: 'Kod',
};

const gapLabels: Record<GapCategoryKey, string> = {
  plans: 'Planlama Kanıtları',
  standards: 'Standart Referansları',
  reviews: 'Gözden Geçirme Kanıtları',
  analysis: 'Analiz Kanıtları',
  tests: 'Test Kanıtları',
  coverage: 'Kapsam Kanıtları',
  trace: 'İzlenebilirlik',
  configuration: 'Konfigürasyon Yönetimi',
  quality: 'Kalite Güvencesi',
  issues: 'Problem Takibi',
  conformity: 'Uygunluk Doğrulamaları',
};

const gapSummaryLabels: Record<GapCategoryKey, string> = {
  plans: 'Plan Boşlukları',
  standards: 'Standart Boşlukları',
  reviews: 'Gözden Geçirme Boşlukları',
  analysis: 'Analiz Boşlukları',
  tests: 'Test Boşlukları',
  coverage: 'Kapsam Boşlukları',
  trace: 'İzlenebilirlik Boşlukları',
  configuration: 'Konfigürasyon Boşlukları',
  quality: 'Kalite Boşlukları',
  issues: 'Problem Takibi Boşlukları',
  conformity: 'Uygunluk Boşlukları',
};

const artifactLabels: Partial<Record<ObjectiveArtifactType, string>> = {
  plan: 'Plan',
  standard: 'Standart',
  review: 'Gözden Geçirme',
  analysis: 'Analiz',
  test: 'Test',
  coverage_stmt: 'Satır Kapsamı',
  coverage_dec: 'Karar Kapsamı',
  coverage_mcdc: 'MC/DC Kapsamı',
  trace: 'İzlenebilirlik',
  cm_record: 'Konfigürasyon Kaydı',
  qa_record: 'QA Kaydı',
  problem_report: 'Problem Raporu',
  conformity: 'Uygunluk Desteği',
};

type RiskClassification = NonNullable<ComplianceSnapshot['risk']>['profile']['classification'];
type CoverageDriftClassification = NonNullable<
  NonNullable<ComplianceSnapshot['risk']>['coverageDrift']
>['classification'];

const riskClassificationMeta: Record<RiskClassification, { label: string; className: string }> = {
  low: { label: 'Düşük Risk', className: 'status-covered' },
  moderate: { label: 'Orta Risk', className: 'status-partial' },
  high: { label: 'Yüksek Risk', className: 'status-missing' },
  critical: { label: 'Kritik Risk', className: 'status-missing' },
};

const riskFactorLabels: Record<string, string> = {
  coverage: 'Kapsam',
  testing: 'Testler',
  analysis: 'Statik Analiz',
  audit: 'Denetim Bulguları',
};

const missingSignalLabels: Record<string, string> = {
  coverage: 'Kapsam Sinyali',
  testing: 'Test Sinyali',
  analysis: 'Analiz Sinyali',
  audit: 'Denetim Sinyali',
};

const coverageDriftLabels: Record<CoverageDriftClassification, string> = {
  improving: 'Kapsam İyileşiyor',
  declining: 'Kapsam Düşüşte',
  stable: 'Kapsam Stabil',
  unknown: 'Eğilim Bilinmiyor',
};

const signoffStatusLabels: Record<string, { label: string; className: string }> = {
  pending: { label: 'Onay Bekliyor', className: 'status-partial' },
  approved: { label: 'Onaylandı', className: 'status-covered' },
};

const formatCoverageMetrics = (
  coverage?: RequirementCoverageStatus['coverage'],
): string | undefined => {
  if (!coverage) {
    return undefined;
  }

  const segments: string[] = [];
  const statements = coverage.statements?.percentage;
  const branches = coverage.branches?.percentage;
  const functions = coverage.functions?.percentage;
  const mcdc = coverage.mcdc?.percentage;

  if (typeof statements === 'number') {
    segments.push(`Satır: ${statements}%`);
  }
  if (typeof branches === 'number') {
    segments.push(`Dallanma: ${branches}%`);
  }
  if (typeof functions === 'number') {
    segments.push(`Fonksiyon: ${functions}%`);
  }
  if (typeof mcdc === 'number') {
    segments.push(`MC/DC: ${mcdc}%`);
  }

  return segments.length ? segments.join(' | ') : undefined;
};

const aggregateCoverageFromCode = (
  code: RequirementTrace['code'],
): RequirementCoverageStatus['coverage'] => {
  const totals = {
    statements: { covered: 0, total: 0 },
    branches: { covered: 0, total: 0 },
    functions: { covered: 0, total: 0 },
    mcdc: { covered: 0, total: 0 },
  };

  code.forEach((entry) => {
    const coverage = entry.coverage;
    if (!coverage) {
      return;
    }
    if (coverage.statements) {
      totals.statements.covered += coverage.statements.covered;
      totals.statements.total += coverage.statements.total;
    }
    if (coverage.branches) {
      totals.branches.covered += coverage.branches.covered;
      totals.branches.total += coverage.branches.total;
    }
    if (coverage.functions) {
      totals.functions.covered += coverage.functions.covered;
      totals.functions.total += coverage.functions.total;
    }
    if (coverage.mcdc) {
      totals.mcdc.covered += coverage.mcdc.covered;
      totals.mcdc.total += coverage.mcdc.total;
    }
  });

  const finalize = ({ covered, total }: { covered: number; total: number }): CoverageMetric | undefined => {
    if (total === 0) {
      return undefined;
    }
    return {
      covered,
      total,
      percentage: Number(((covered / total) * 100).toFixed(2)),
    };
  };

  return {
    statements: finalize(totals.statements),
    branches: finalize(totals.branches),
    functions: finalize(totals.functions),
    mcdc: finalize(totals.mcdc),
  };
};

const determineCoverageStatus = (
  code: RequirementTrace['code'],
  coverage?: RequirementCoverageStatus['coverage'],
): CoverageStatus => {
  if (code.length === 0) {
    return 'missing';
  }
  const statements = coverage?.statements;
  if (!statements || statements.total === 0) {
    return 'missing';
  }
  if (statements.covered >= statements.total) {
    return 'covered';
  }
  return 'partial';
};

const baseStyles = `
  :root {
    color-scheme: light;
    font-family: 'Inter', 'Segoe UI', Arial, sans-serif;
  }

  body {
    margin: 0;
    background: #f3f5f9;
    color: #0f172a;
  }

  .report-header {
    background: linear-gradient(135deg, #0f172a, #1d2b64);
    color: #f8fafc;
    padding: 32px 48px;
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 24px;
  }

  .report-header h1 {
    margin: 0 0 8px;
    font-size: 28px;
    font-weight: 600;
  }

  .report-meta {
    margin: 0;
    font-size: 14px;
    opacity: 0.9;
    word-break: break-word;
    line-height: 1.4;
  }

  .report-meta + .report-meta {
    margin-top: 4px;
  }

  .report-meta-flag {
    display: inline-flex;
    align-items: center;
    margin-left: 8px;
    padding: 2px 8px;
    border-radius: 999px;
    background: rgba(248, 113, 113, 0.35);
    color: #fee2e2;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .git-meta {
    margin-top: 16px;
    display: grid;
    gap: 4px;
  }

  .summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 12px;
  }

  .summary-card {
    background: rgba(15, 23, 42, 0.35);
    border-radius: 12px;
    padding: 12px 16px;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .summary-card strong {
    font-size: 18px;
    font-weight: 600;
  }

  main {
    padding: 32px 48px 48px;
  }

  .section {
    background: #ffffff;
    border-radius: 16px;
    box-shadow: 0 12px 40px rgba(15, 23, 42, 0.08);
    padding: 24px 28px;
    margin-bottom: 32px;
  }

  .section h2 {
    margin-top: 0;
    font-size: 20px;
    color: #1e293b;
  }

  .section-lead {
    color: #475569;
    margin-bottom: 16px;
  }

  table {
    width: 100%;
    border-collapse: collapse;
  }

  th {
    text-align: left;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #475569;
    border-bottom: 2px solid #e2e8f0;
    padding: 12px;
  }

  td {
    border-bottom: 1px solid #e2e8f0;
    padding: 14px 12px;
    vertical-align: top;
  }

  .cell-title {
    font-weight: 600;
    color: #0f172a;
  }

  .cell-subtitle {
    font-size: 13px;
    color: #334155;
    margin-top: 4px;
  }

  .cell-description {
    color: #475569;
    font-size: 13px;
    margin-top: 8px;
  }

  .badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    border-radius: 999px;
    padding: 4px 12px;
    font-size: 12px;
    font-weight: 500;
    background: #e2e8f0;
    color: #0f172a;
    margin-right: 6px;
    margin-bottom: 6px;
  }

  .badge-soft {
    background: rgba(15, 23, 42, 0.08);
  }

  .badge-critical {
    background: #fee2e2;
    color: #991b1b;
  }

  .status-covered {
    background: #dcfce7;
    color: #166534;
  }

  .status-partial {
    background: #fef9c3;
    color: #854d0e;
  }

  .status-missing {
    background: #fee2e2;
    color: #991b1b;
  }

  .muted {
    color: #64748b;
    font-size: 13px;
  }

  .list {
    list-style: none;
    padding-left: 0;
    margin: 0;
    display: grid;
    gap: 12px;
  }

  .code-pill {
    display: inline-block;
    padding: 4px 10px;
    background: #eef2ff;
    color: #312e81;
    border-radius: 8px;
    font-size: 12px;
    margin-right: 6px;
    margin-bottom: 6px;
  }

  .gap-grid {
    display: grid;
    gap: 16px;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  }

  .gap-card {
    border: 1px solid #e2e8f0;
    border-radius: 12px;
    padding: 16px;
    min-height: 180px;
  }

  .gap-card h3 {
    margin-top: 0;
    font-size: 16px;
    color: #1e293b;
  }

  .risk-grid {
    display: grid;
    gap: 16px;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  }

  .risk-card {
    border: 1px solid #e2e8f0;
    border-radius: 12px;
    padding: 16px;
    background: #ffffff;
    min-height: 140px;
  }

  .risk-score {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .risk-score-value {
    font-size: 32px;
    font-weight: 600;
    color: #0f172a;
  }

  .risk-breakdown {
    margin-top: 24px;
  }

  .risk-breakdown-stats {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-top: 6px;
  }

  .timeline-grid {
    display: grid;
    gap: 16px;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  }

  .timeline-card {
    border: 1px solid #e2e8f0;
    border-radius: 12px;
    padding: 16px;
    background: #ffffff;
  }

  .timeline-status {
    margin-bottom: 12px;
  }

  .timeline-events li {
    position: relative;
    padding-left: 16px;
    border-left: 2px solid #e2e8f0;
    margin-left: 4px;
  }

  .timeline-events li::before {
    content: '';
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #3b82f6;
    position: absolute;
    left: -5px;
    top: 8px;
  }

  footer {
    padding: 0 48px 32px;
    color: #475569;
    font-size: 13px;
    display: flex;
    justify-content: space-between;
  }

  @media print {
    body {
      background: #ffffff;
    }

    footer {
      display: none;
    }
  }
`;

const layoutTemplate = nunjucks.compile(
  `<!DOCTYPE html>
<html lang="tr">
  <head>
    <meta charset="utf-8" />
    <title>{{ title }}</title>
    <style>
      ${baseStyles}
      @page {
        margin: 25mm 20mm;
        size: A4;
      }
    </style>
  </head>
  <body>
    <header class="report-header">
      <div>
        <h1>{{ title }}</h1>
        {% if subtitle %}
          <p class="report-meta">{{ subtitle }}</p>
        {% endif %}
        <p class="report-meta">Kanıt Manifest ID: <strong>{{ manifestId or 'N/A' }}</strong></p>
        <p class="report-meta">
          Snapshot: <strong>{{ snapshotId or 'N/A' }}</strong>
          {% if snapshotVersion and snapshotVersion.isFrozen %}
            <span class="report-meta-flag">Donduruldu</span>
          {% endif %}
        </p>
        <p class="report-meta">Rapor Tarihi: {{ generatedAt }}</p>
        {% if git %}
          <div class="git-meta">
            <p class="report-meta">
              Commit:
              <strong>
                <abbr title="{{ git.hash }}">{{ git.shortHash }}</abbr>
              </strong>
              {% if git.dirty %}
                <span class="report-meta-flag">Kirli</span>
              {% endif %}
            </p>
            {% if git.branches and git.branches.length %}
              <p class="report-meta">Dallar: {{ git.branches | join(', ') }}</p>
            {% endif %}
            {% if git.tags and git.tags.length %}
              <p class="report-meta">Etiketler: {{ git.tags | join(', ') }}</p>
            {% endif %}
            {% if git.remoteOrigins and git.remoteOrigins.length %}
              <p class="report-meta">Origin: {{ git.remoteOrigins | join(', ') }}</p>
            {% endif %}
            {% if git.author or git.formattedDate %}
              <p class="report-meta">{% if git.author %}Yazar: {{ git.author }}{% if git.formattedDate %} • {% endif %}{% endif %}{% if git.formattedDate %}{{ git.formattedDate }}{% endif %}</p>
            {% endif %}
            {% if git.message %}
              <p class="report-meta">Mesaj: {{ git.message }}</p>
            {% endif %}
          </div>
        {% endif %}
      </div>
      <div class="summary-grid">
        {% for metric in summaryMetrics %}
          <div class="summary-card">
            <span>{{ metric.label }}</span>
            <strong>{{ metric.value }}</strong>
          </div>
        {% endfor %}
      </div>
    </header>
    <main>
      {{ content | safe }}
    </main>
    <footer>
      <span>SOIPack Sürüm {{ version }}</span>
      <span>Sayfa numarası PDF çıktısında görüntülenecektir.</span>
    </footer>
  </body>
</html>`,
  env,
);

const riskTemplate = nunjucks.compile(
  `<section class="section">
    <h2>Risk Profili</h2>
    <p class="section-lead">
      Kanıt boşlukları, test sonuçları, statik analiz bulguları ve denetim uyarıları tek bir risk skorunda toplanır.
    </p>
    <div class="risk-grid">
      <article class="risk-card">
        <h3>Toplam Skor</h3>
        <div class="risk-score">
          <span class="risk-score-value">{{ score }}</span>
          <span class="badge {{ classificationClass }}">{{ classificationLabel }}</span>
        </div>
        <p class="muted">{{ scoreLabel }}</p>
      </article>
      {% if drift %}
        <article class="risk-card">
          <h3>Kapsam Eğilimi</h3>
          <div class="cell-title">{{ drift.classificationLabel }}</div>
          <div class="muted">{{ drift.summary }}</div>
          <div class="risk-breakdown-stats">
            <span class="badge badge-soft">{{ drift.slopeLabel }}</span>
            <span class="badge badge-soft">{{ drift.projectionLabel }}</span>
            <span class="badge badge-soft">{{ drift.confidenceLabel }}</span>
          </div>
        </article>
      {% endif %}
    </div>
    <div class="risk-breakdown">
      <h3>Faktör Katkıları</h3>
      <ul class="list">
        {% for entry in breakdown %}
          <li>
            <div class="cell-title">{{ entry.factorLabel }}</div>
            <div class="muted">{{ entry.details }}</div>
            <div class="risk-breakdown-stats">
              <span class="badge badge-soft">{{ entry.weightLabel }}</span>
              <span class="badge {{ entry.severityClass }}">{{ entry.contributionLabel }}</span>
            </div>
          </li>
        {% endfor %}
      </ul>
    </div>
    {% if missingSignals.length %}
      <p class="muted">Eksik sinyaller: {{ missingSignals | join(', ') }}</p>
    {% endif %}
  </section>`,
  env,
);

const complianceTemplate = nunjucks.compile(
  `<section class="section">
    <h2>Uyum Matrisi</h2>
    <p class="section-lead">
      Hedeflerin kanıt durumunu gösteren kurumsal görünüm. Her satır bir uyumluluk hedefini, sağlanan kanıtları ve açık kalan boşlukları özetler.
    </p>
    <table>
      <thead>
        <tr>
          <th>Hedef</th>
          <th>Durum</th>
          <th>Sağlanan Kanıtlar</th>
          <th>Eksik Kanıtlar</th>
          <th>Kanıt Referansları</th>
        </tr>
      </thead>
      <tbody>
        {% for row in objectives %}
          <tr>
            <td>
              <div class="cell-title">{{ row.id }}</div>
              {% if row.table or row.name %}
                <div class="cell-subtitle">
                  {% if row.table %}{{ row.table }}{% endif %}
                  {% if row.table and row.name %} • {% endif %}
                  {% if row.name %}{{ row.name }}{% endif %}
                </div>
              {% endif %}
              {% if row.desc %}
                <div class="cell-description">{{ row.desc }}</div>
              {% endif %}
            </td>
            <td><span class="badge {{ row.statusClass }}">{{ row.statusLabel }}</span></td>
            <td>
              {% if row.satisfiedArtifacts.length %}
                {% for artifact in row.satisfiedArtifacts %}
                  <span class="badge badge-soft">{{ artifact }}</span>
                {% endfor %}
              {% else %}
                <span class="muted">Kanıt bulunmuyor</span>
              {% endif %}
            </td>
            <td>
              {% if row.missingArtifacts.length %}
                {% for artifact in row.missingArtifacts %}
                  <span class="badge badge-critical">{{ artifact }}</span>
                {% endfor %}
              {% else %}
                <span class="muted">Eksik kanıt yok</span>
              {% endif %}
            </td>
            <td>
              {% if row.evidenceRefs.length %}
                <ul class="list">
                  {% for reference in row.evidenceRefs %}
                    <li class="muted">{{ reference }}</li>
                  {% endfor %}
                </ul>
              {% else %}
                <span class="muted">Referans bulunmuyor</span>
              {% endif %}
            </td>
          </tr>
        {% endfor %}
      </tbody>
    </table>
  </section>
  {% if qualityFindings.length %}
    <section class="section">
      <h2>Kalite Bulguları</h2>
      <p class="section-lead">
        Gereksinim durumu, test sonuçları ve kapsam verileri arasındaki tutarsızlıkları vurgular. Bulgular düzeltici eylem gerektiren alanları önceliklendirmenizi sağlar.
      </p>
      <ul class="list">
        {% for finding in qualityFindings %}
          <li>
            <div>
              <span class="badge {{ finding.severityClass }}">{{ finding.severityLabel }}</span>
              <span class="cell-title">{{ finding.message }}</span>
            </div>
            {% if finding.requirementId %}
              <div class="muted">Gereksinim: {{ finding.requirementId }}</div>
            {% endif %}
            {% if finding.relatedTests.length %}
              <div class="muted">İlgili Testler: {{ finding.relatedTests | join(', ') }}</div>
            {% endif %}
            {% if finding.recommendation %}
              <div class="cell-description">{{ finding.recommendation }}</div>
            {% endif %}
          </li>
        {% endfor %}
      </ul>
    </section>
  {% endif %}
  {% if requirementCoverage.length %}
    <section class="section">
      <h2>Gereksinim Kapsamı</h2>
      <p class="section-lead">
        Testler ve kod izleri ile ilişkilendirilen gereksinimlerin kapsam durumunu gösterir. Yetersiz kapsama sahip alanları hızla tespit etmeyi sağlar.
      </p>
      <table>
        <thead>
          <tr>
            <th>Gereksinim</th>
            <th>Kapsam Durumu</th>
            <th>Kod Dosyaları</th>
          </tr>
        </thead>
        <tbody>
          {% for row in requirementCoverage %}
            <tr>
              <td>
                <div class="cell-title">{{ row.requirementId }}</div>
                <div class="cell-description">{{ row.requirementTitle }}</div>
              </td>
              <td>
                <span class="badge {{ row.statusClass }}">{{ row.statusLabel }}</span>
                {% if row.coverageLabel %}
                  <div class="muted">{{ row.coverageLabel }}</div>
                {% endif %}
              </td>
              <td>
                {% if row.codePaths.length %}
                  <ul class="list">
                    {% for path in row.codePaths %}
                      <li><code class="code-pill">{{ path }}</code></li>
                    {% endfor %}
                  </ul>
                {% else %}
                  <span class="muted">Kod bağlantısı yok</span>
                {% endif %}
              </td>
            </tr>
          {% endfor %}
        </tbody>
      </table>
    </section>
  {% endif %}`,
  env,
);

const traceTemplate = nunjucks.compile(
  `<section class="section">
    <h2>İzlenebilirlik Matrisi</h2>
    <p class="section-lead">
      Gereksinimlerin testler ve kod yolları ile eşleşmesini gösteren izlenebilirlik tablosu. Denetlenebilirliği sağlamak için kanıt zincirini ortaya koyar.
    </p>
    <table>
      <thead>
        <tr>
          <th>Gereksinim</th>
          <th>Test Kanıtları</th>
          <th>Kod Yolları</th>
        </tr>
      </thead>
      <tbody>
        {% for row in rows %}
          <tr>
            <td>
              <div class="cell-title">{{ row.requirementId }}</div>
              <div class="cell-description">{{ row.requirementTitle }}</div>
              {% if row.requirementStatus %}
                <div class="muted">Durum: {{ row.requirementStatus }}</div>
              {% endif %}
              {% if row.coverage %}
                <div>
                  <span class="badge {{ row.coverage.statusClass }}">{{ row.coverage.statusLabel }}</span>
                  {% if row.coverage.coverageLabel %}
                    <div class="muted">{{ row.coverage.coverageLabel }}</div>
                  {% endif %}
                </div>
              {% endif %}
            </td>
            <td>
              {% if row.tests.length %}
                <ul class="list">
                  {% for test in row.tests %}
                    <li>
                      <span class="badge {{ test.statusClass }}">{{ test.statusLabel }}</span>
                      <div class="cell-title">{{ test.name }}</div>
                      <div class="muted">{{ test.id }}</div>
                    </li>
                  {% endfor %}
                </ul>
              {% else %}
                <span class="muted">Test kaydı yok</span>
              {% endif %}
            </td>
            <td>
              {% if row.codePaths.length %}
                <ul class="list">
                  {% for code in row.codePaths %}
                    <li>
                      <code class="code-pill">{{ code.path }}</code>
                      {% if code.coverageLabel %}
                        <div class="muted">{{ code.coverageLabel }}</div>
                      {% endif %}
                    </li>
                  {% endfor %}
                </ul>
              {% else %}
                <span class="muted">Kod bağlantısı yok</span>
              {% endif %}
            </td>
          </tr>
        {% endfor %}
      </tbody>
    </table>
    {% if suggestions.length %}
      <div class="suggestion-block">
        <h3>Önerilen İz Bağlantıları</h3>
        <p class="section-lead">
          Metin ve kapsam analizinden türetilen öneriler potansiyel eksik bağlantıları vurgular. Onaylanmadan önce proje ekipleri tarafından gözden geçirilmelidir.
        </p>
        <ul class="list">
          {% for group in suggestions %}
            <li>
              <div class="cell-title">{{ group.requirementId }}</div>
              <div class="cell-description">{{ group.requirementTitle }}</div>
              <ul class="list">
                {% for entry in group.entries %}
                  <li>
                    <span class="badge {{ entry.confidenceClass }}">{{ entry.confidenceLabel }}</span>
                    <div class="cell-title">{{ entry.typeLabel }} → {{ entry.targetName }}</div>
                    <div class="muted">{{ entry.targetId }}</div>
                    <div class="cell-description">{{ entry.reason }}</div>
                  </li>
                {% endfor %}
              </ul>
            </li>
          {% endfor %}
        </ul>
      </div>
    {% endif %}
  </section>`,
  env,
);

const signoffTimelineTemplate = nunjucks.compile(
  `<section class="section">
    <h2>Signoff Zaman Çizelgesi</h2>
    <p class="section-lead">
      Workspace belgelerindeki signoff istekleri ve imza onayları denetim izi için tutulur.
    </p>
    <div class="timeline-grid">
      {% for entry in entries %}
        <article class="timeline-card">
          <header>
            <div class="cell-title">{{ entry.documentId }}</div>
            <div class="muted">Revizyon: {{ entry.revisionId }}</div>
          </header>
          <div class="timeline-status">
            <span class="badge {{ entry.statusClass }}">{{ entry.statusLabel }}</span>
            <div class="muted">Revizyon Hash: {{ entry.revisionHash }}</div>
          </div>
          <ul class="list timeline-events">
            {% for event in entry.events %}
              <li>
                <div class="cell-title">{{ event.label }}</div>
                <div class="muted">{{ event.timestamp }}</div>
                <div class="muted">Aktör: {{ event.actor }}</div>
                {% if event.details %}
                  <div class="cell-description">{{ event.details }}</div>
                {% endif %}
              </li>
            {% endfor %}
          </ul>
        </article>
      {% endfor %}
    </div>
  </section>`,
  env,
);

const gapsTemplate = nunjucks.compile(
  `<section class="section">
    <h2>Uyum Boşlukları</h2>
    <p class="section-lead">
      Kanıt eksikliklerini kategori bazında gösterir. Boşluklar denetim öncesi tamamlanması gereken alanları belirtir.
    </p>
    <div class="gap-grid">
      {% for category in categories %}
        <article class="gap-card">
          <h3>{{ category.label }}</h3>
          {% if category.items.length %}
            <ul class="list">
              {% for item in category.items %}
                <li>
                  <div class="cell-title">{{ item.objectiveId }}</div>
                  {% if item.table or item.name %}
                    <div class="cell-subtitle">
                      {% if item.table %}{{ item.table }}{% endif %}
                      {% if item.table and item.name %} • {% endif %}
                      {% if item.name %}{{ item.name }}{% endif %}
                    </div>
                  {% endif %}
                  {% if item.desc %}
                    <div class="cell-description">{{ item.desc }}</div>
                  {% endif %}
                  <div>
                    {% for artifact in item.missingArtifacts %}
                      <span class="badge badge-critical">{{ artifact }}</span>
                    {% endfor %}
                  </div>
                </li>
              {% endfor %}
            </ul>
          {% else %}
            <p class="muted">Boşluk tespit edilmedi.</p>
          {% endif %}
        </article>
      {% endfor %}
    </div>
  </section>`,
  env,
);

const formatDate = (value: string): string => {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }

  const [isoDate, isoTime] = date.toISOString().split('T');
  const time = isoTime.slice(0, 5);
  return `${isoDate} ${time} UTC`;
};

const buildGitContext = (git?: BuildInfo | null) => {
  if (!git) {
    return undefined;
  }

  const shortHash = git.hash ? git.hash.slice(0, 12) : '';
  const formattedDate = git.date ? formatDate(git.date) : undefined;

  return {
    ...git,
    shortHash: shortHash || git.hash,
    formattedDate,
  };
};

const escapeHtml = (value: string): string =>
  value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

const formatArtifact = (artifact: ObjectiveArtifactType): string =>
  artifactLabels[artifact] ?? artifact.toUpperCase();

const contributionClass = (weight: number, contribution: number): string => {
  if (weight <= 0) {
    return 'badge-soft';
  }
  const ratio = contribution / weight;
  if (ratio >= 0.75) {
    return 'status-missing';
  }
  if (ratio >= 0.4) {
    return 'status-partial';
  }
  return 'status-covered';
};

const buildRiskView = (risk?: ComplianceSnapshot['risk']): RiskView | undefined => {
  if (!risk) {
    return undefined;
  }

  const classification = riskClassificationMeta[risk.profile.classification] ?? {
    label: risk.profile.classification,
    className: 'badge-soft',
  };

  const breakdown: RiskBreakdownView[] = risk.profile.breakdown.map((entry) => ({
    factorLabel: riskFactorLabels[entry.factor] ?? entry.factor,
    contributionLabel: `Katkı ${entry.contribution.toFixed(1)} puan`,
    weightLabel: `Ağırlık %${entry.weight.toFixed(0)}`,
    severityClass: contributionClass(entry.weight, entry.contribution),
    details: entry.details,
  }));

  const missingSignals = (risk.profile.missingSignals ?? []).map(
    (signal) => missingSignalLabels[signal] ?? signal,
  );

  let drift: RiskDriftView | undefined;
  if (risk.coverageDrift) {
    const driftMeta = coverageDriftLabels[risk.coverageDrift.classification] ?? 'Eğilim';
    drift = {
      classificationLabel: driftMeta,
      summary: `${risk.coverageDrift.horizonDays} günlük ufuk için projeksiyon.`,
      slopeLabel: `Eğim: ${risk.coverageDrift.slope.toFixed(2)} puan/gün`,
      projectionLabel: `Projeksiyon: ${risk.coverageDrift.projected.toFixed(1)}%`,
      confidenceLabel: `Güven: ${(risk.coverageDrift.confidence * 100).toFixed(0)}%`,
    };
  }

  return {
    score: Number(risk.profile.score.toFixed(1)),
    scoreLabel: '0 en düşük, 100 en yüksek riski temsil eder.',
    classification: risk.profile.classification,
    classificationLabel: classification.label,
    classificationClass: classification.className,
    breakdown,
    missingSignals,
    drift,
  };
};

const formatActor = (value?: string | null): string => {
  if (!value) {
    return 'Bilinmiyor';
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : 'Bilinmiyor';
};

const formatKeyFingerprint = (value?: string | null): string | undefined => {
  if (!value) {
    return undefined;
  }
  const normalized = value.replace(/\s+/g, '');
  const suffix = normalized.slice(-12) || normalized;
  return `Anahtar: …${suffix}`;
};

const formatSignaturePreview = (value?: string | null): string | undefined => {
  if (!value) {
    return undefined;
  }
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return undefined;
  }
  const preview = trimmed.length > 12 ? `${trimmed.slice(0, 12)}…` : trimmed;
  return `İmza: ${preview}`;
};

const buildSignoffTimelineView = (
  signoffs?: SignoffTimelineEntry[],
): SignoffTimelineView | undefined => {
  if (!signoffs || signoffs.length === 0) {
    return undefined;
  }

  const entries = [...signoffs]
    .map((entry) => ({
      ...entry,
      requestedTime: Date.parse(entry.requestedAt),
    }))
    .sort((a, b) => (a.requestedTime || 0) - (b.requestedTime || 0))
    .map((entry) => {
      const statusMeta = signoffStatusLabels[entry.status] ?? {
        label: entry.status,
        className: 'badge-soft',
      };

      const events: SignoffTimelineEventView[] = [
        {
          label: 'İstek Gönderildi',
          actor: formatActor(entry.requestedBy),
          timestamp: formatDate(entry.requestedAt),
          details: `Onay talep edilen kişi: ${formatActor(entry.requestedFor)}`,
        },
      ];

      if (entry.status === 'approved' && entry.approvedAt) {
        const details: string[] = [];
        const key = formatKeyFingerprint(entry.signerPublicKey);
        if (key) {
          details.push(key);
        }
        const signature = formatSignaturePreview(entry.signature);
        if (signature) {
          details.push(signature);
        }
        events.push({
          label: 'İmza Doğrulandı',
          actor: formatActor(entry.signerId ?? entry.requestedFor),
          timestamp: formatDate(entry.approvedAt),
          details: details.length ? details.join(' • ') : undefined,
        });
      }

      return {
        id: entry.id,
        documentId: entry.documentId,
        revisionId: entry.revisionId,
        revisionHash: entry.revisionHash,
        statusLabel: statusMeta.label,
        statusClass: statusMeta.className,
        events,
      };
    });

  return { entries };
};

const buildSummaryMetrics = (
  stats: ComplianceStatistics,
  requirementCoverage: RequirementCoverageStatus[] = [],
  qualityFindings: ComplianceSnapshot['qualityFindings'] = [],
  risk?: ComplianceSnapshot['risk'],
): LayoutSummaryMetric[] => {
  const metrics: LayoutSummaryMetric[] = [];

  if (risk) {
    const classification = riskClassificationMeta[risk.profile.classification] ?? {
      label: risk.profile.classification,
      className: 'badge-soft',
    };
    metrics.push({
      label: 'Risk Skoru',
      value: `${risk.profile.score.toFixed(1)}/100 (${classification.label})`,
      accent: risk.profile.classification === 'low',
    });
  }

  metrics.push(
    { label: 'Hedefler', value: stats.objectives.total.toString() },
    { label: 'Tamamlanan', value: stats.objectives.covered.toString() },
    { label: 'Kısmi', value: stats.objectives.partial.toString() },
    { label: 'Eksik', value: stats.objectives.missing.toString() },
    { label: 'Testler', value: stats.tests.total.toString() },
    { label: 'Kod Yolları', value: stats.codePaths.total.toString() },
  );

  if (requirementCoverage.length > 0) {
    const coverageCounts = requirementCoverage.reduce<Record<CoverageStatus, number>>(
      (acc, entry) => {
        acc[entry.status] += 1;
        return acc;
      },
      { covered: 0, partial: 0, missing: 0 },
    );

    metrics.push({
      label: 'Kapsamlı Gereksinimler',
      value: `${coverageCounts.covered}/${requirementCoverage.length}`,
      accent: coverageCounts.covered === requirementCoverage.length,
    });
    metrics.push({
      label: 'Eksik/Kısmi Kapsam',
      value: `${coverageCounts.partial}/${coverageCounts.missing}`,
      accent: coverageCounts.partial + coverageCounts.missing > 0,
    });
  }

  if (qualityFindings.length > 0) {
    const criticalCount = qualityFindings.filter((finding) => finding.severity === 'error').length;
    const warningCount = qualityFindings.filter((finding) => finding.severity === 'warn').length;
    metrics.push({
      label: 'Kalite Bulguları',
      value: qualityFindings.length.toString(),
      accent: true,
    });
    metrics.push({
      label: 'Kritik/Uyarı',
      value: `${criticalCount}/${warningCount}`,
      accent: criticalCount > 0,
    });
  }

  return metrics;
};

const buildComplianceMatrixView = (
  snapshot: ComplianceSnapshot,
  options: ComplianceMatrixOptions,
): ComplianceMatrixView => {
  const objectiveLookup = new Map(options.objectivesMetadata?.map((item) => [item.id, item]));

  const objectives: ComplianceMatrixRow[] = snapshot.objectives.map((objective) => {
    const metadata = objectiveLookup.get(objective.objectiveId);
    return {
      id: objective.objectiveId,
      status: objective.status,
      statusLabel: statusLabels[objective.status],
      statusClass:
        objective.status === 'covered'
          ? 'status-covered'
          : objective.status === 'partial'
            ? 'status-partial'
            : 'status-missing',
      table: metadata?.table,
      name: metadata?.name,
      desc: metadata?.desc,
      satisfiedArtifacts: objective.satisfiedArtifacts.map(formatArtifact),
      missingArtifacts: objective.missingArtifacts.map(formatArtifact),
      evidenceRefs: objective.evidenceRefs,
    };
  });

  const requirementCoverage: RequirementCoverageRow[] = snapshot.requirementCoverage.map((entry) => {
    const meta = coverageStatusLabels[entry.status];
    return {
      requirementId: entry.requirement.id,
      requirementTitle: entry.requirement.title,
      statusLabel: meta.label,
      statusClass: meta.className,
      coverageLabel: formatCoverageMetrics(entry.coverage),
      codePaths: entry.codePaths.map((code) => code.path),
    };
  });

  const qualityFindings: QualityFindingRow[] = snapshot.qualityFindings.map((finding) => {
    const meta = qualitySeverityLabels[finding.severity] ?? { label: finding.severity, className: 'badge-soft' };
    return {
      id: finding.id,
      severityLabel: meta.label,
      severityClass: meta.className,
      message: finding.message,
      requirementId: finding.requirementId,
      recommendation: finding.recommendation,
      relatedTests: finding.relatedTests ?? [],
    };
  });

  return {
    objectives,
    requirementCoverage,
    qualityFindings,
    summaryMetrics: buildSummaryMetrics(
      snapshot.stats,
      snapshot.requirementCoverage,
      snapshot.qualityFindings,
      snapshot.risk,
    ),
    risk: buildRiskView(snapshot.risk),
    signoffs: buildSignoffTimelineView(options.signoffs),
  };
};

const buildCoverageSummaryMetrics = (coverage: CoverageReport): LayoutSummaryMetric[] => {
  const metrics: LayoutSummaryMetric[] = [
    {
      label: 'Satır Kapsamı',
      value: `${coverage.totals.statements.percentage}%`,
      accent: coverage.totals.statements.percentage === 100,
    },
  ];

  if (coverage.totals.branches) {
    metrics.push({
      label: 'Dallanma',
      value: `${coverage.totals.branches.percentage}%`,
      accent: coverage.totals.branches.percentage === 100,
    });
  }

  if (coverage.totals.mcdc) {
    metrics.push({
      label: 'MC/DC',
      value: `${coverage.totals.mcdc.percentage}%`,
      accent: coverage.totals.mcdc.percentage === 100,
    });
  }

  return metrics;
};

const buildComplianceMatrixJson = (
  snapshot: ComplianceSnapshot,
  options: ComplianceMatrixOptions,
  view: ComplianceMatrixView,
): ComplianceMatrixJson => ({
  manifestId: options.manifestId,
  generatedAt: options.generatedAt ?? snapshot.generatedAt,
  version: options.version ?? packageInfo.version,
  snapshotId: options.snapshotId ?? snapshot.version.id,
  snapshotVersion: options.snapshotVersion ?? snapshot.version,
  stats: {
    objectives: { ...snapshot.stats.objectives },
    requirements: { ...snapshot.stats.requirements },
    tests: { ...snapshot.stats.tests },
    codePaths: { ...snapshot.stats.codePaths },
  },
  objectives: view.objectives.map((row) => ({
    id: row.id,
    status: row.status,
    table: row.table,
    name: row.name,
    desc: row.desc,
    satisfiedArtifacts: [...row.satisfiedArtifacts],
    missingArtifacts: [...row.missingArtifacts],
    evidenceRefs: [...row.evidenceRefs],
  })),
  requirementCoverage: snapshot.requirementCoverage.map((entry) => ({
    requirementId: entry.requirement.id,
    title: entry.requirement.title,
    status: entry.status,
    coverage: entry.coverage,
    codePaths: entry.codePaths.map((code) => code.path),
  })),
  qualityFindings: snapshot.qualityFindings.map((finding) => ({
    id: finding.id,
    severity: finding.severity,
    category: finding.category,
    message: finding.message,
    requirementId: finding.requirementId,
    recommendation: finding.recommendation,
    relatedTests: finding.relatedTests,
  })),
  traceSuggestions: snapshot.traceSuggestions.map((suggestion) => ({
    requirementId: suggestion.requirementId,
    type: suggestion.type,
    targetId: suggestion.targetId,
    targetName: suggestion.targetName,
    confidence: suggestion.confidence,
    reason: suggestion.reason,
    viaTestId: suggestion.viaTestId,
  })),
  git: options.git ?? null,
  risk: snapshot.risk ?? null,
  signoffs: (options.signoffs ?? []).map((signoff) => ({ ...signoff })),
});

const renderLayout = (context: LayoutContext): string => {
  const version = context.version ?? packageInfo.version;
  return layoutTemplate.render({
    ...context,
    generatedAt: formatDate(context.generatedAt ?? new Date().toISOString()),
    version,
    git: buildGitContext(context.git),
  });
};

export const renderComplianceMatrix = (
  snapshot: ComplianceSnapshot,
  options: ComplianceMatrixOptions = {},
): ComplianceMatrixResult => {
  const view = buildComplianceMatrixView(snapshot, options);

  const sections: string[] = [];
  if (view.risk) {
    sections.push(riskTemplate.render(view.risk));
  }
  sections.push(
    complianceTemplate.render({
      objectives: view.objectives,
      requirementCoverage: view.requirementCoverage,
      qualityFindings: view.qualityFindings,
    }),
  );
  if (view.signoffs) {
    sections.push(signoffTimelineTemplate.render(view.signoffs));
  }

  const html = renderLayout({
    title: options.title ?? 'SOIPack Uyum Matrisi',
    manifestId: options.manifestId ?? 'N/A',
    generatedAt: options.generatedAt ?? snapshot.generatedAt,
    version: options.version ?? packageInfo.version,
    snapshotId: options.snapshotId ?? snapshot.version.id,
    snapshotVersion: options.snapshotVersion ?? snapshot.version,
    summaryMetrics: view.summaryMetrics,
    content: sections.join(''),
    subtitle: 'Denetlenebilir uyum için kanıt özet matrisi',
    git: options.git,
  });

  const json = buildComplianceMatrixJson(snapshot, options, view);

  return { html, json };
};

export const renderComplianceCoverageReport = (
  snapshot: ComplianceSnapshot,
  coverage: CoverageReport,
  options: ComplianceCoverageReportOptions = {},
): ComplianceCoverageReportResult => {
  const view = buildComplianceMatrixView(snapshot, options);
  const coverageWarnings = options.coverageWarnings ?? [];

  const sections: string[] = [];
  if (view.risk) {
    sections.push(riskTemplate.render(view.risk));
  }
  sections.push(
    complianceTemplate.render({
      objectives: view.objectives,
      requirementCoverage: view.requirementCoverage,
      qualityFindings: view.qualityFindings,
    }),
  );
  if (view.signoffs) {
    sections.push(signoffTimelineTemplate.render(view.signoffs));
  }
  sections.push(renderCoverageSummarySection({ coverage, warnings: coverageWarnings }));
  const content = sections.join('');

  const html = renderLayout({
    title: options.title ?? 'SOIPack Uyum ve Kapsam Raporu',
    manifestId: options.manifestId ?? 'N/A',
    generatedAt: options.generatedAt ?? snapshot.generatedAt,
    version: options.version ?? packageInfo.version,
    snapshotId: options.snapshotId ?? snapshot.version.id,
    snapshotVersion: options.snapshotVersion ?? snapshot.version,
    summaryMetrics: [...view.summaryMetrics, ...buildCoverageSummaryMetrics(coverage)],
    content,
    subtitle: 'Uyumluluk hedefleri ve yapısal kapsam özetleri',
    git: options.git,
  });

  const json = {
    ...buildComplianceMatrixJson(snapshot, options, view),
    coverage,
    coverageWarnings,
  } as ComplianceCoverageReportResult['json'];

  return { html, json, coverage, coverageWarnings };
};

export const renderTraceMatrix = (
  trace: RequirementTrace[],
  options: TraceMatrixOptions = {},
): string => {
  const coverageLookup = new Map(
    (options.coverage ?? []).map((entry) => [entry.requirement.id, entry]),
  );

  const rows: TraceMatrixRow[] = trace.map((item) => {
    const coverageEntry = coverageLookup.get(item.requirement.id);
    const aggregatedCoverage = coverageEntry?.coverage ?? aggregateCoverageFromCode(item.code);
    const status = coverageEntry?.status ?? determineCoverageStatus(item.code, aggregatedCoverage);
    const statusMeta = coverageStatusLabels[status];

    return {
      requirementId: item.requirement.id,
      requirementTitle: item.requirement.title,
      requirementStatus: item.requirement.status,
      tests: item.tests.map((test) => {
        const meta = testStatusLabels[test.status] ?? { label: test.status ?? 'Bilinmiyor', className: 'badge-soft' };
        return {
          id: test.testId,
          name: test.name ?? test.testId,
          statusLabel: meta.label,
          statusClass: meta.className,
        };
      }),
      codePaths: item.code.map((code) => ({
        path: code.path,
        coverageLabel: formatCoverageMetrics({
          statements: code.coverage?.statements,
          branches: code.coverage?.branches,
          functions: code.coverage?.functions,
          mcdc: code.coverage?.mcdc,
        }),
      })),
      coverage: {
        status,
        statusLabel: statusMeta.label,
        statusClass: statusMeta.className,
        coverageLabel: formatCoverageMetrics(aggregatedCoverage),
      },
    };
  });

  const summaryMetrics: LayoutSummaryMetric[] = [
    { label: 'Gereksinimler', value: rows.length.toString() },
    {
      label: 'Bağlı Testler',
      value: rows.reduce((acc, row) => acc + row.tests.length, 0).toString(),
    },
    {
      label: 'Kod İzleri',
      value: rows.reduce((acc, row) => acc + row.codePaths.length, 0).toString(),
    },
  ];

  if (rows.length > 0) {
    const coverageCounts = rows.reduce<Record<CoverageStatus, number>>(
      (acc, row) => {
        acc[row.coverage?.status ?? 'missing'] += 1;
        return acc;
      },
      { covered: 0, partial: 0, missing: 0 },
    );
    summaryMetrics.push({
      label: 'Kapsamlı Gereksinimler',
      value: `${coverageCounts.covered}/${rows.length}`,
      accent: coverageCounts.covered === rows.length,
    });
    summaryMetrics.push({
      label: 'Eksik/Kısmi Kapsam',
      value: `${coverageCounts.partial}/${coverageCounts.missing}`,
      accent: coverageCounts.partial + coverageCounts.missing > 0,
    });
  }

  const suggestionGroups: TraceSuggestionGroup[] = (() => {
    const result: TraceSuggestionGroup[] = [];
    const suggestions = options.suggestions ?? [];
    if (suggestions.length === 0) {
      return result;
    }
    const requirementTitles = new Map(rows.map((row) => [row.requirementId, row.requirementTitle]));
    const grouped = new Map<string, TraceSuggestionGroup>();

    suggestions.forEach((suggestion) => {
      const existing = grouped.get(suggestion.requirementId);
      const confidenceMeta =
        suggestionConfidenceLabels[suggestion.confidence] ??
        ({ label: suggestion.confidence, className: 'badge-soft' } as const);
      const entry: TraceSuggestionEntryView = {
        typeLabel: suggestionTypeLabels[suggestion.type] ?? suggestion.type,
        targetId: suggestion.targetId,
        targetName: suggestion.targetName ?? suggestion.targetId,
        reason: suggestion.reason,
        confidenceLabel: confidenceMeta.label,
        confidenceClass: confidenceMeta.className,
      };
      if (existing) {
        existing.entries.push(entry);
        return;
      }
      grouped.set(suggestion.requirementId, {
        requirementId: suggestion.requirementId,
        requirementTitle:
          requirementTitles.get(suggestion.requirementId) ?? suggestion.requirementId,
        entries: [entry],
      });
    });

    grouped.forEach((group) => {
      group.entries.sort((a, b) => a.targetId.localeCompare(b.targetId));
      result.push(group);
    });

    result.sort((a, b) => a.requirementId.localeCompare(b.requirementId));
    return result;
  })();

  if (suggestionGroups.length > 0) {
    const totalSuggestions = suggestionGroups.reduce(
      (acc, group) => acc + group.entries.length,
      0,
    );
    summaryMetrics.push({
      label: 'Önerilen Bağlantılar',
      value: totalSuggestions.toString(),
      accent: true,
    });
  }

  return renderLayout({
    title: options.title ?? 'SOIPack İzlenebilirlik Matrisi',
    manifestId: options.manifestId ?? 'N/A',
    generatedAt: options.generatedAt ?? new Date().toISOString(),
    version: options.version ?? packageInfo.version,
    snapshotId: options.snapshotId,
    snapshotVersion: options.snapshotVersion,
    summaryMetrics,
    content: traceTemplate.render({ rows, suggestions: suggestionGroups }),
    subtitle: 'Gereksinim → Test → Kod eşleşmelerinin kurumsal görünümü',
    git: options.git,
  });
};

export const renderGaps = (
  snapshot: ComplianceSnapshot,
  options: GapReportOptions = {},
): string => {
  const objectiveLookup = new Map(options.objectivesMetadata?.map((objective) => [objective.id, objective]));

  const categories = (Object.keys(snapshot.gaps) as GapCategoryKey[]).map((key) => {
    const items: GapReportRow[] = snapshot.gaps[key].map((gap) => {
      const metadata = objectiveLookup.get(gap.objectiveId);
      return {
        objectiveId: gap.objectiveId,
        table: metadata?.table,
        name: metadata?.name,
        desc: metadata?.desc,
        missingArtifacts: gap.missingArtifacts.map(formatArtifact),
      };
    });

    return {
      key,
      label: gapLabels[key],
      items,
    };
  });

  const summaryMetrics: LayoutSummaryMetric[] = (Object.keys(snapshot.gaps) as GapCategoryKey[]).map((key) => ({
    label: gapSummaryLabels[key],
    value: snapshot.gaps[key].length.toString(),
  }));

  return renderLayout({
    title: options.title ?? 'SOIPack Uyumluluk Boşlukları',
    manifestId: options.manifestId ?? 'N/A',
    generatedAt: options.generatedAt ?? snapshot.generatedAt,
    version: options.version ?? packageInfo.version,
    snapshotId: options.snapshotId ?? snapshot.version.id,
    snapshotVersion: options.snapshotVersion ?? snapshot.version,
    summaryMetrics,
    content: gapsTemplate.render({ categories }),
    subtitle: 'Kanıt eksikliği bulunan alanların özet görünümü',
    git: options.git,
  });
};

const buildHeaderTemplate = (version: string, generatedAt: string): string => {
  const safeVersion = escapeHtml(version);
  const safeDate = escapeHtml(formatDate(generatedAt));
  return `<div style="font-family:Arial,Helvetica,sans-serif;font-size:9px;color:#0f172a;width:100%;padding:0 24px;display:flex;justify-content:space-between;align-items:center;">` +
    `<span>SOIPack Sürüm ${safeVersion}</span><span>${safeDate}</span></div>`;
};

const buildFooterTemplate = (manifestId: string): string => {
  const safeManifest = escapeHtml(manifestId);
  return `<div style="font-family:Arial,Helvetica,sans-serif;font-size:9px;color:#475569;width:100%;padding:0 24px;display:flex;justify-content:space-between;align-items:center;">` +
    `<span>Kanıt Manifest ID: ${safeManifest}</span><span>Sayfa <span class="pageNumber"></span> / <span class="totalPages"></span></span></div>`;
};

export const printToPDF = async (
  html: string,
  options: PrintToPdfOptions = {},
): Promise<Buffer> => {
  const playwright = options.playwright ?? (await import('playwright'));
  let browser: Browser | undefined;
  let page: Page | undefined;

  try {
    browser = await playwright.chromium.launch();
    page = await browser.newPage();
    await page.setContent(html, { waitUntil: 'load' });

    const pdf = await page.pdf({
      format: 'A4',
      printBackground: true,
      displayHeaderFooter: true,
      headerTemplate: buildHeaderTemplate(options.version ?? packageInfo.version, options.generatedAt ?? new Date().toISOString()),
      footerTemplate: buildFooterTemplate(options.manifestId ?? 'N/A'),
      margin: {
        top: options.margin?.top ?? '60px',
        bottom: options.margin?.bottom ?? '60px',
        left: options.margin?.left ?? '20mm',
        right: options.margin?.right ?? '20mm',
      },
    });

    return pdf;
  } finally {
    if (page) {
      await page.close().catch(() => undefined);
    }

    if (browser) {
      await browser.close().catch(() => undefined);
    }
  }
};

// Legacy exports kept for backward compatibility within the monorepo.
export interface HtmlReportOptions {
  title?: string;
}

export interface PdfPage {
  setContent: (html: string) => Promise<void>;
  pdf: (options: { printBackground: boolean }) => Promise<Buffer>;
}

interface LegacyTraceMatrixRow {
  requirementId: string;
  testCaseIds: string[];
}

export const renderHtmlReport = (
  matrix: LegacyTraceMatrixRow[],
  requirements: Requirement[],
  testCases: TestCase[],
  options: HtmlReportOptions = {},
): string => {
  const title = options.title ?? 'SOIPack Traceability Report';
  const requirementLookup = new Map(requirements.map((item) => [item.id, item]));
  const testLookup = new Map(testCases.map((item) => [item.id, item]));

  const rows = matrix
    .map((entry) => {
      const requirement = requirementLookup.get(entry.requirementId);
      const tests = entry.testCaseIds.map((id: string) => testLookup.get(id)?.name ?? id).join(', ');

      return `<tr><td>${requirement?.title ?? entry.requirementId}</td><td>${tests}</td></tr>`;
    })
    .join('');

  return `<!DOCTYPE html><html><head><meta charset="utf-8" /><title>${title}</title></head><body><h1>${title}</h1><table><thead>` +
    `<tr><th>Requirement</th><th>Test Cases</th></tr></thead><tbody>${rows}</tbody></table></body></html>`;
};

export const renderJsonReport = (
  matrix: LegacyTraceMatrixRow[],
  requirements: Requirement[],
  testCases: TestCase[],
): Record<string, unknown> => ({
  generatedAt: new Date().toISOString(),
  requirements: matrix.map((entry) => ({
    requirement: requirements.find((item) => item.id === entry.requirementId) ?? {
      id: entry.requirementId,
      title: entry.requirementId,
      status: 'draft',
      tags: [],
    },
    tests: entry.testCaseIds.map((id: string) =>
      testCases.find((test) => test.id === id) ?? { id, name: id },
    ),
  })),
});

export const generatePdf = async (page: PdfPage, html: string): Promise<Buffer> => {
  await page.setContent(html);
  return page.pdf({ printBackground: true });
};

export {
  renderPlanDocument,
  renderPlanPdf,
  planTemplateSections,
  planTemplateTitles,
  type PlanRenderOptions,
  type PlanRenderResult,
  type PlanTemplateId,
  type PlanOverrideConfig,
  type PlanSectionOverrides,
} from './plans';
