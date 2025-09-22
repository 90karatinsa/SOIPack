import type { BuildInfo, CoverageMetric } from '@soipack/adapters';
import { Objective, ObjectiveArtifactType, Requirement, TestCase } from '@soipack/core';
import {
  ComplianceSnapshot,
  ComplianceStatistics,
  RequirementTrace,
  RequirementCoverageStatus,
  CoverageStatus,
} from '@soipack/engine';
import nunjucks from 'nunjucks';
import type { Browser, Page } from 'playwright';

import packageInfo from '../package.json';

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
}

interface LayoutContext extends BaseReportOptions {
  summaryMetrics: LayoutSummaryMetric[];
  subtitle?: string;
  content: string;
}

export interface ComplianceMatrixOptions extends BaseReportOptions {
  objectivesMetadata?: Objective[];
}

export interface TraceMatrixOptions extends BaseReportOptions {
  coverage?: RequirementCoverageStatus[];
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
  git?: BuildInfo | null;
}

export interface ComplianceMatrixResult {
  html: string;
  json: ComplianceMatrixJson;
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

  if (typeof statements === 'number') {
    segments.push(`Satır: ${statements}%`);
  }
  if (typeof branches === 'number') {
    segments.push(`Dallanma: ${branches}%`);
  }
  if (typeof functions === 'number') {
    segments.push(`Fonksiyon: ${functions}%`);
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

const buildSummaryMetrics = (
  stats: ComplianceStatistics,
  requirementCoverage: RequirementCoverageStatus[] = [],
): LayoutSummaryMetric[] => {
  const metrics: LayoutSummaryMetric[] = [
    { label: 'Hedefler', value: stats.objectives.total.toString() },
    { label: 'Tamamlanan', value: stats.objectives.covered.toString() },
    { label: 'Kısmi', value: stats.objectives.partial.toString() },
    { label: 'Eksik', value: stats.objectives.missing.toString() },
    { label: 'Testler', value: stats.tests.total.toString() },
    { label: 'Kod Yolları', value: stats.codePaths.total.toString() },
  ];

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

  return metrics;
};

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
  const objectiveLookup = new Map(options.objectivesMetadata?.map((item) => [item.id, item]));

  const rows: ComplianceMatrixRow[] = snapshot.objectives.map((objective) => {
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

  const requirementCoverageRows: RequirementCoverageRow[] = snapshot.requirementCoverage.map((entry) => {
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

  const html = renderLayout({
    title: options.title ?? 'SOIPack Uyum Matrisi',
    manifestId: options.manifestId ?? 'N/A',
    generatedAt: options.generatedAt ?? snapshot.generatedAt,
    version: options.version ?? packageInfo.version,
    summaryMetrics: buildSummaryMetrics(snapshot.stats, snapshot.requirementCoverage),
    content: complianceTemplate.render({ objectives: rows, requirementCoverage: requirementCoverageRows }),
    subtitle: 'Denetlenebilir uyum için kanıt özet matrisi',
    git: options.git,
  });

  const json: ComplianceMatrixJson = {
    manifestId: options.manifestId,
    generatedAt: options.generatedAt ?? snapshot.generatedAt,
    version: options.version ?? packageInfo.version,
    stats: {
      objectives: { ...snapshot.stats.objectives },
      requirements: { ...snapshot.stats.requirements },
      tests: { ...snapshot.stats.tests },
      codePaths: { ...snapshot.stats.codePaths },
    },
    objectives: rows.map((row) => ({
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
    git: options.git ?? null,
  };

  return { html, json };
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

  return renderLayout({
    title: options.title ?? 'SOIPack İzlenebilirlik Matrisi',
    manifestId: options.manifestId ?? 'N/A',
    generatedAt: options.generatedAt ?? new Date().toISOString(),
    version: options.version ?? packageInfo.version,
    summaryMetrics,
    content: traceTemplate.render({ rows }),
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
  planTemplateSections,
  planTemplateTitles,
  type PlanRenderOptions,
  type PlanRenderResult,
  type PlanTemplateId,
  type PlanOverrideConfig,
  type PlanSectionOverrides,
} from './plans';
