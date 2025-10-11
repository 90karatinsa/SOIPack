import type { BuildInfo, CoverageMetric, CoverageReport } from '@soipack/adapters';
import {
  Objective,
  ObjectiveArtifactType,
  ObjectiveTable,
  Requirement,
  SnapshotVersion,
  SoiStage,
  TestCase,
  objectiveCatalog,
  soiStages,
} from '@soipack/core';
import {
  ComplianceSnapshot,
  ComplianceStatistics,
  RequirementTrace,
  RequirementCoverageStatus,
  CoverageStatus,
  type TraceSuggestion,
  type TraceGraph,
  type ChangeImpactScore,
  type StaleEvidenceFinding,
} from '@soipack/engine';
import nunjucks from './nunjucksLoader';
import type { Browser, Page } from 'playwright';

import packageInfo from '../package.json';

import {
  renderChangeImpactSection,
  renderChangeRequestBacklogSection,
  renderCoverageSummarySection,
  renderLedgerDiffSection,
  renderStaleEvidenceHeatmapSection,
  type ChangeImpactSectionContext,
  type ChangeRequestBacklogItem,
  type LedgerAttestationDiffItem,
} from './complianceReport.html';
import { buildStaleEvidenceHeatmap, type StaleEvidenceHeatmapView } from './staleHeatmap';

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
  programName?: string;
  certificationLevel?: string;
  projectVersion?: string;
}

interface LayoutContext extends BaseReportOptions {
  summaryMetrics: LayoutSummaryMetric[];
  subtitle?: string;
  content: string;
}

export interface ComplianceMatrixOptions extends BaseReportOptions {
  objectivesMetadata?: Objective[];
  signoffs?: SignoffTimelineEntry[];
  toolQualification?: ToolQualificationLinkOptions;
  readiness?: ComplianceReadinessSummary;
}

export type ReadinessComponentId =
  | 'objectives'
  | 'independence'
  | 'structuralCoverage'
  | 'riskTrend';

export interface ComplianceReadinessBreakdown {
  component: ReadinessComponentId;
  score: number;
  weight: number;
  contribution: number;
  details?: string;
  missing?: boolean;
}

export interface ComplianceReadinessSummary {
  percentile: number;
  computedAt?: string;
  seed?: number;
  breakdown: ComplianceReadinessBreakdown[];
}

export interface TraceMatrixOptions extends BaseReportOptions {
  coverage?: RequirementCoverageStatus[];
  suggestions?: TraceSuggestion[];
  designs?: TraceDesignLink[];
}

export interface TraceGraphDotOptions {
  graphName?: string;
}

export interface GsnGraphOptions {
  graphName?: string;
  objectivesMetadata?: Objective[];
  includeLegend?: boolean;
}

export interface GapReportOptions extends BaseReportOptions {
  objectivesMetadata?: Objective[];
}

interface ComplianceMatrixRow {
  id: string;
  status: ComplianceSnapshot['objectives'][number]['status'];
  statusLabel: string;
  statusClass: string;
  confidence?: number;
  confidenceLabel?: string;
  confidenceBadgeLabel?: string;
  confidenceClass?: string;
  table?: string;
  name?: string;
  desc?: string;
  stage?: SoiStage;
  satisfiedArtifacts: string[];
  missingArtifacts: string[];
  evidenceRefs: string[];
  regulatoryReferences: RegulatoryCrosswalkEntry;
}

interface StageComplianceSummary {
  total: number;
  covered: number;
  partial: number;
  missing: number;
}

interface StageComplianceTab {
  id: string;
  label: string;
  objectives: ComplianceMatrixRow[];
  summary: StageComplianceSummary;
  stage?: SoiStage;
}

interface ComplianceMatrixCsvRow {
  objectiveId: string;
  table: string;
  stage?: SoiStage;
  stageLabel?: string;
  status: string;
  confidence?: string;
  satisfiedArtifacts: string[];
  missingArtifacts: string[];
  evidenceRefs: string[];
}

interface ComplianceMatrixCsvStageExport {
  stage: SoiStage;
  label: string;
  headers: string[];
  rows: ComplianceMatrixCsvRow[];
  records: string[][];
  csv: string;
}

interface ComplianceMatrixCsvExport {
  headers: string[];
  rows: ComplianceMatrixCsvRow[];
  records: string[][];
  csv: string;
  metadata: {
    programName?: string;
    certificationLevel?: string;
    projectVersion?: string;
    rows: string[][];
  };
  stages: Partial<Record<SoiStage, ComplianceMatrixCsvStageExport>>;
}

const stageLabels: Record<SoiStage, string> = {
  'SOI-1': 'SOI-1 Planlama',
  'SOI-2': 'SOI-2 Geliştirme',
  'SOI-3': 'SOI-3 Doğrulama',
  'SOI-4': 'SOI-4 Sertifikasyon',
};

const readinessComponentLabels: Record<ReadinessComponentId, string> = {
  objectives: 'Hedefler',
  independence: 'Bağımsızlık',
  structuralCoverage: 'Yapısal kapsam',
  riskTrend: 'Risk eğilimi',
};

const readinessExplainer =
  'Hazırlık endeksi; hedef karşılanma oranı, bağımsızlık boşlukları, yapısal kapsam ve risk trendi bileşenlerini ağırlıklı bir yüzdelik skor olarak harmanlar.';

export type Do178cObjectiveId = Objective['id'];

interface RegulatoryCrosswalkEntry {
  ac20115d: string[];
  faa8110_49: string[];
  easaAmc_20_152a: string[];
}

const tableRegulatoryReferences: Record<ObjectiveTable, RegulatoryCrosswalkEntry> = {
  'A-3': {
    ac20115d: ['§6.3', '§6.5'],
    faa8110_49: ['§2.3', '§3.4'],
    easaAmc_20_152a: ['§5.1.1', '§5.1.3'],
  },
  'A-4': {
    ac20115d: ['§6.6', '§6.7'],
    faa8110_49: ['§5.4'],
    easaAmc_20_152a: ['§6.2.1', '§6.2.2'],
  },
  'A-5': {
    ac20115d: ['§7.1', '§7.2'],
    faa8110_49: ['§6.3', '§6.5'],
    easaAmc_20_152a: ['§6.3.1', '§6.3.3'],
  },
  'A-6': {
    ac20115d: ['§7.3', '§7.4'],
    faa8110_49: ['§7.4'],
    easaAmc_20_152a: ['§6.4.1', '§6.4.2'],
  },
  'A-7': {
    ac20115d: ['§8.1', '§8.4'],
    faa8110_49: ['§9.3', '§9.5'],
    easaAmc_20_152a: ['§6.6.1', '§6.6.2'],
  },
} as const;

const sortReferences = (references: string[]): string[] => [...references].sort((a, b) => a.localeCompare(b));

export const REGULATORY_CROSSWALK: Record<Do178cObjectiveId, RegulatoryCrosswalkEntry> =
  objectiveCatalog.reduce((acc, objective) => {
    const references = tableRegulatoryReferences[objective.table];
    acc[objective.id as Do178cObjectiveId] = references
      ? {
          ac20115d: sortReferences(references.ac20115d),
          faa8110_49: sortReferences(references.faa8110_49),
          easaAmc_20_152a: sortReferences(references.easaAmc_20_152a),
        }
      : { ac20115d: [], faa8110_49: [], easaAmc_20_152a: [] };
    return acc;
  }, {} as Record<Do178cObjectiveId, RegulatoryCrosswalkEntry>);

const getRegulatoryReferences = (objectiveId: string): RegulatoryCrosswalkEntry => {
  const references = REGULATORY_CROSSWALK[objectiveId as Do178cObjectiveId];
  if (!references) {
    return { ac20115d: [], faa8110_49: [], easaAmc_20_152a: [] };
  }
  return {
    ac20115d: [...references.ac20115d],
    faa8110_49: [...references.faa8110_49],
    easaAmc_20_152a: [...references.easaAmc_20_152a],
  };
};

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

interface ChangeImpactEntryView {
  key: string;
  id: string;
  typeLabel: string;
  severityLabel: string;
  severityClass: string;
  severityValue: string;
  stateLabel: string;
  stateClass: string;
  reasons: string;
}

interface ChangeImpactView {
  entries: ChangeImpactEntryView[];
  summaryBadges: ChangeImpactSectionContext['summaryBadges'];
  total: number;
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

interface RiskDeltaTrendEntryView {
  label: string;
  window?: string;
  improvements: number;
  regressions: number;
}

interface RiskDeltaRegressionView {
  objectiveId: string;
  changeLabel: string;
  stepLabel: string;
  badgeClass: string;
}

interface RiskDeltaSparklineView {
  svg: string;
  label: string;
}

interface RiskDeltaSummaryJson {
  totals: { improvements: number; regressions: number };
  steps: Array<{
    fromVersionId?: string;
    toVersionId: string;
    fromGeneratedAt?: string;
    toGeneratedAt?: string;
    improvements: number;
    regressions: number;
  }>;
  regressions: Array<{
    objectiveId: string;
    previousStatus: ComplianceSnapshot['objectives'][number]['status'];
    currentStatus: ComplianceSnapshot['objectives'][number]['status'];
    fromVersionId?: string;
    toVersionId: string;
  }>;
}

interface RiskDeltaView {
  totalsLabel: string;
  totals: { improvements: number; regressions: number };
  trend: RiskDeltaTrendEntryView[];
  regressions: RiskDeltaRegressionView[];
  sparkline?: RiskDeltaSparklineView;
  summary: RiskDeltaSummaryJson;
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
  delta?: RiskDeltaView;
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

interface IndependenceObjectiveView {
  id: string;
  table?: string;
  name?: string;
  desc?: string;
  independenceLabel: string;
  independenceClass: string;
  statusLabel: string;
  statusClass: string;
  missingArtifacts: string[];
}

interface IndependenceBadgeView {
  label: string;
  className: string;
}

interface IndependenceSummaryView {
  statusLabel: string;
  statusClass: string;
  totalsLabel: string;
  badges: IndependenceBadgeView[];
  objectives: IndependenceObjectiveView[];
  emptyLabel: string;
  lead: string;
}

interface ComplianceMatrixView {
  objectives: ComplianceMatrixRow[];
  requirementCoverage: RequirementCoverageRow[];
  qualityFindings: QualityFindingRow[];
  changeImpact?: ChangeImpactView;
  summaryMetrics: LayoutSummaryMetric[];
  stageTabs: StageComplianceTab[];
  risk?: RiskView;
  signoffs?: SignoffTimelineView;
  toolQualification?: ToolQualificationLinkView;
  independence: IndependenceSummaryView;
  readiness?: ReadinessView;
  staleEvidenceHeatmap?: StaleEvidenceHeatmapView;
}

interface ReadinessBadgeView {
  label: string;
  value: string;
  accent?: boolean;
  missing?: boolean;
}

interface ReadinessSparklineBarView {
  height: number;
  title: string;
  missing?: boolean;
}

interface ReadinessSparklineView {
  label: string;
  bars: ReadinessSparklineBarView[];
}

interface ReadinessComponentView {
  label: string;
  scoreLabel: string;
  contributionLabel: string;
  weightLabel: string;
  details?: string;
  missing?: boolean;
}

interface ReadinessView {
  percentile: string;
  percentileLabel: string;
  computedAtLabel?: string;
  badges: ReadinessBadgeView[];
  sparkline: ReadinessSparklineView;
  components: ReadinessComponentView[];
  explanation: string;
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

export interface TraceDesignLink {
  requirementId: string;
  designId: string;
  designName?: string;
  status?: string;
  codeRefs?: string[];
}

export interface TraceMatrixCsvRow {
  requirementId: string;
  requirementTitle: string;
  requirementStatus: string;
  requirementCoverageStatus: string;
  requirementCoverage: string;
  designId: string;
  designName: string;
  designStatus: string;
  codePath: string;
  codeCoverage: string;
  testId: string;
  testName: string;
  testStatus: string;
}

export interface TraceMatrixCsvExport {
  headers: string[];
  rows: TraceMatrixCsvRow[];
  records: string[][];
  csv: string;
}

export interface TraceMatrixRenderResult {
  html: string;
  csv: TraceMatrixCsvExport;
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

export interface ToolQualificationUsageOutput {
  name: string;
  description: string;
  producedArtifacts?: string[];
  referencedObjectives?: string[];
}

export interface ToolQualificationControl {
  id: string;
  description: string;
  owner?: string;
  frequency?: string;
  evidence?: string[];
}

export type ToolQualificationActivityStatus = 'planned' | 'in-progress' | 'passed' | 'blocked';

export interface ToolQualificationValidationActivity {
  id: string;
  description: string;
  method: string;
  expectedResult: string;
  status?: ToolQualificationActivityStatus;
  evidence?: string[];
  owner?: string;
}

export interface ToolUsageMetadata {
  id: string;
  name: string;
  version?: string;
  vendor?: string;
  category: 'development' | 'verification' | 'support';
  tql?: string;
  description?: string;
  objectives: string[];
  environment?: string[];
  outputs: ToolQualificationUsageOutput[];
  controls?: ToolQualificationControl[];
  validation?: ToolQualificationValidationActivity[];
  limitations?: string[];
  residualRisks?: string[];
}

export interface ToolQualificationPackComplianceOptions {
  snapshot: Pick<ComplianceSnapshot, 'objectives' | 'independenceSummary'>;
  objectivesMetadata?: Objective[];
  ledgerHashes?: Record<string, string>;
}

export interface ToolQualificationPackOptions {
  programName?: string;
  level?: string;
  generatedAt?: string;
  author?: string;
  compliance?: ToolQualificationPackComplianceOptions;
}

export interface ToolQualificationSummaryItem {
  id: string;
  name: string;
  version?: string;
  category: 'development' | 'verification' | 'support';
  tql?: string;
  outputs: string[];
  pendingActivities: number;
  residualRiskCount: number;
  residualRiskSummary: string;
}

export interface ToolQualificationPackResult {
  tqp: { filename: string; content: string };
  tar: { filename: string; content: string };
  summary: {
    generatedAt: string;
    programName?: string;
    level?: string;
    author?: string;
    tools: ToolQualificationSummaryItem[];
  };
}

export interface ToolQualificationLinkOptions {
  tqpHref?: string;
  tarHref?: string;
  generatedAt?: string;
  tools: ToolQualificationSummaryItem[];
}

interface ToolQualificationLinkView extends ToolQualificationLinkOptions {
  summaryLabel: string;
}

export interface ComplianceMatrixJson {
  manifestId?: string;
  generatedAt: string;
  version: string;
  programName?: string;
  certificationLevel?: string;
  projectVersion?: string;
  snapshotId: string;
  snapshotVersion: SnapshotVersion;
  stats: ComplianceStatistics;
  stages: Array<{
    id: string;
    label: string;
    summary: StageComplianceSummary;
    objectiveIds: string[];
  }>;
  objectives: Array<{
    id: string;
    status: ComplianceSnapshot['objectives'][number]['status'];
    table?: string;
    name?: string;
    desc?: string;
    satisfiedArtifacts: string[];
    missingArtifacts: string[];
    evidenceRefs: string[];
    regulatoryReferences: RegulatoryCrosswalkEntry;
  }>;
  requirementCoverage: Array<{
    requirementId: string;
    title?: string;
    status: RequirementCoverageStatus['status'];
    coverage?: RequirementCoverageStatus['coverage'];
    codePaths: string[];
    designs: string[];
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
  analysis?: {
    staleEvidenceHeatmap: StaleEvidenceHeatmapView | null;
  };
  changeImpact?: ChangeImpactScore[];
  traceSuggestions: Array<{
    requirementId: string;
    type: TraceSuggestion['type'];
    targetId: string;
    targetName?: string;
    confidence: TraceSuggestion['confidence'];
    reason: string;
    viaTestId?: string;
  }>;
  independenceSummary: ComplianceSnapshot['independenceSummary'];
  git?: BuildInfo | null;
  risk?: ComplianceSnapshot['risk'] | null;
  complianceDelta?: RiskDeltaSummaryJson;
  signoffs: SignoffTimelineEntry[];
  toolQualification?: ToolQualificationLinkOptions;
  readiness?: ComplianceReadinessSummary | null;
}

export interface ComplianceMatrixResult {
  html: string;
  json: ComplianceMatrixJson;
  csv: ComplianceMatrixCsvExport;
}

export interface ComplianceCoverageReportOptions extends ComplianceMatrixOptions {
  coverageWarnings?: string[];
  changeRequestBacklog?: ChangeRequestBacklogItem[];
  ledgerDiffs?: LedgerAttestationDiffItem[];
}

export interface ComplianceCoverageReportResult extends ComplianceMatrixResult {
  json: ComplianceMatrixJson & {
    coverage: CoverageReport;
    coverageWarnings: string[];
    changeRequestBacklog?: ChangeRequestBacklogItem[];
    ledgerDiffs?: LedgerAttestationDiffItem[];
  };
  coverage: CoverageReport;
  coverageWarnings: string[];
  changeRequestBacklog?: ChangeRequestBacklogItem[];
  ledgerDiffs?: LedgerAttestationDiffItem[];
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

if (typeof (nunjucks as { configure?: (options: Record<string, unknown>) => void }).configure === 'function') {
  nunjucks.configure({
    autoescape: true,
    trimBlocks: true,
    lstripBlocks: true,
  });
}

const statusLabels: Record<ComplianceSnapshot['objectives'][number]['status'], string> = {
  covered: 'Tam Karşılandı',
  partial: 'Kısmen Karşılandı',
  missing: 'Eksik',
};

const objectiveStatusBadgeClasses: Record<ComplianceSnapshot['objectives'][number]['status'], string> = {
  covered: 'status-covered',
  partial: 'status-partial',
  missing: 'status-missing',
};

const independenceLevelText: Record<Objective['independence'], string> = {
  required: 'Zorunlu',
  recommended: 'Önerilen',
  none: 'Gerekmiyor',
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

const independenceStatusLabels: Record<CoverageStatus, { label: string; className: string }> = {
  covered: { label: 'Bağımsızlık Sağlandı', className: 'status-covered' },
  partial: { label: 'Bağımsızlık Eksikleri Var', className: 'status-partial' },
  missing: { label: 'Bağımsızlık Sağlanamadı', className: 'status-missing' },
};

const independenceLevelLabels: Record<Objective['independence'], { label: string; className: string }> = {
  none: { label: 'Bağımsızlık gerekmiyor', className: 'badge-soft' },
  recommended: { label: 'Önerilen Bağımsızlık', className: 'status-partial' },
  required: { label: 'Zorunlu Bağımsızlık', className: 'status-missing' },
};

const qualitySeverityLabels: Record<
  ComplianceSnapshot['qualityFindings'][number]['severity'],
  { label: string; className: string }
> = {
  error: { label: 'Kritik', className: 'status-missing' },
  warn: { label: 'Uyarı', className: 'status-partial' },
  info: { label: 'Bilgi', className: 'badge-soft' },
};

const changeImpactSeverityBuckets = [
  { id: 'critical', label: 'Kritik', threshold: 12, className: 'status-missing' },
  { id: 'high', label: 'Yüksek', threshold: 8, className: 'status-partial' },
  { id: 'medium', label: 'Orta', threshold: 0, className: 'badge-soft' },
] as const;

type ChangeImpactSeverityKey = (typeof changeImpactSeverityBuckets)[number]['id'];

const changeImpactStateLabels: Record<
  ChangeImpactScore['state'],
  { label: string; className: string }
> = {
  added: { label: 'Eklendi', className: 'status-partial' },
  removed: { label: 'Kaldırıldı', className: 'status-missing' },
  modified: { label: 'Güncellendi', className: 'status-partial' },
  impacted: { label: 'Etkilendi', className: 'badge-soft' },
};

const changeImpactTypeLabels: Record<ChangeImpactScore['type'], string> = {
  requirement: 'Gereksinim',
  test: 'Test',
  code: 'Kod',
  design: 'Tasarım',
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

const resolveObjectiveConfidenceClass = (value: number): string => {
  if (value >= 0.85) {
    return 'status-covered';
  }
  if (value >= 0.6) {
    return 'status-partial';
  }
  if (value >= 0.35) {
    return 'badge-soft';
  }
  return 'status-missing';
};

const formatObjectiveConfidence = (
  value: number | undefined,
):
  | {
      value: number;
      label: string;
      badgeLabel: string;
      className: string;
    }
  | undefined => {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return undefined;
  }
  const normalized = Math.min(Math.max(value, 0), 1);
  const percentage = Math.round(normalized * 100);
  return {
    value: normalized,
    label: `${percentage}%`,
    badgeLabel: `Güven ${percentage}%`,
    className: resolveObjectiveConfidenceClass(normalized),
  };
};

const complianceCsvHeaders = [
  'Objective ID',
  'Table',
  'Stage',
  'Status',
  'Confidence',
  'Satisfied Artifacts',
  'Missing Artifacts',
  'Evidence References',
];

const traceCsvHeaders = [
  'Requirement ID',
  'Requirement Title',
  'Requirement Status',
  'Requirement Coverage Status',
  'Requirement Coverage',
  'Design ID',
  'Design Name',
  'Design Status',
  'Code Path',
  'Code Coverage',
  'Test ID',
  'Test Name',
  'Test Status',
];

const escapeCsvValue = (value: string): string => {
  const normalized = value ?? '';
  if (normalized.length === 0) {
    return '';
  }
  const needsQuotes = /[",\n]/.test(normalized);
  const escaped = normalized.replace(/"/g, '""');
  return needsQuotes ? `"${escaped}"` : escaped;
};

const normalizeDesignLinks = (designs: TraceDesignLink[] | undefined): Map<string, TraceDesignLink[]> => {
  const lookup = new Map<string, TraceDesignLink[]>();

  (designs ?? []).forEach((design) => {
    if (!lookup.has(design.requirementId)) {
      lookup.set(design.requirementId, []);
    }
    const normalized: TraceDesignLink = {
      requirementId: design.requirementId,
      designId: design.designId,
      designName: design.designName ?? design.designId,
      status: design.status ?? 'Tanımsız',
      codeRefs:
        design.codeRefs
          ?.map((ref) => ref.trim())
          .filter((ref) => ref.length > 0) ?? undefined,
    };
    lookup.get(design.requirementId)!.push(normalized);
  });

  lookup.forEach((entries) => {
    entries.sort((a, b) => a.designId.localeCompare(b.designId));
  });

  return lookup;
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
  staleEvidence: 'Güncelliğini Yitiren Kanıtlar',
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
  staleEvidence: 'Stale Kanıt Boşlukları',
};

const toolActivityStatusLabels: Record<ToolQualificationActivityStatus, string> = {
  planned: 'Planlandı',
  'in-progress': 'Devam ediyor',
  passed: 'Tamamlandı',
  blocked: 'Engellendi',
};

const defaultTqpFilename = 'tool-qualification-plan.md';
const defaultTarFilename = 'tool-accomplishment-report.md';

const formatBulletList = (items: string[], fallback: string): string => {
  if (!items.length) {
    return `- ${fallback}`;
  }
  return items.map((item) => `- ${item}`).join('\n');
};

const describeOutput = (output: ToolQualificationUsageOutput): string => {
  const parts = [`${output.name}: ${output.description}`];
  if (output.producedArtifacts && output.producedArtifacts.length > 0) {
    parts.push(`Kanıt: ${output.producedArtifacts.join(', ')}`);
  }
  if (output.referencedObjectives && output.referencedObjectives.length > 0) {
    parts.push(`Hedefler: ${output.referencedObjectives.join(', ')}`);
  }
  return parts.join(' • ');
};

const describeControl = (control: ToolQualificationControl): string => {
  const details = [control.description];
  if (control.owner) {
    details.push(`Sorumlu: ${control.owner}`);
  }
  if (control.frequency) {
    details.push(`Periyot: ${control.frequency}`);
  }
  if (control.evidence && control.evidence.length > 0) {
    details.push(`Kanıt: ${control.evidence.join(', ')}`);
  }
  return `${control.id}: ${details.join(' • ')}`;
};

const describeValidationActivity = (activity: ToolQualificationValidationActivity): string => {
  const statusLabel = toolActivityStatusLabels[activity.status ?? 'planned'] ?? activity.status ?? 'Durum bilinmiyor';
  const pieces = [
    `${activity.id}: ${activity.description}`,
    `Yöntem: ${activity.method}`,
    `Beklenen Sonuç: ${activity.expectedResult}`,
    `Durum: ${statusLabel}`,
  ];
  if (activity.owner) {
    pieces.push(`Sorumlu: ${activity.owner}`);
  }
  if (activity.evidence && activity.evidence.length > 0) {
    pieces.push(`Kanıt: ${activity.evidence.join(', ')}`);
  }
  return pieces.join(' • ');
};

export const renderToolQualificationPack = (
  toolUsage: ToolUsageMetadata[],
  options: ToolQualificationPackOptions = {},
): ToolQualificationPackResult => {
  const generatedAt = options.generatedAt ?? new Date().toISOString();
  const tqpLines: string[] = [
    '# DO-330 Tool Qualification Plan (TQP)',
    '',
    `Program: ${options.programName ?? 'TBD'}`,
    `Seviye: ${options.level ?? 'TBD'}`,
    `Oluşturan: ${options.author ?? 'Kalite Ekibi'}`,
    `Oluşturulma: ${generatedAt}`,
    '',
    'Bu plan, yazılım doğrulama sürecinde kullanılan araçların DO-330 kapsamında nasıl niteliklendirileceğini özetler.',
  ];

  const tarLines: string[] = [
    '# DO-330 Tool Accomplishment Report (TAR)',
    '',
    `Program: ${options.programName ?? 'TBD'}`,
    `Seviye: ${options.level ?? 'TBD'}`,
    `Hazırlayan: ${options.author ?? 'Kalite Ekibi'}`,
    `Oluşturulma: ${generatedAt}`,
    '',
    'Bu rapor, planlanan niteliklendirme aktivitelerinin yürütülmesini ve kalan riskleri özetler.',
  ];

  if (toolUsage.length === 0) {
    tqpLines.push('', '## Araç Verisi Sağlanmadı', '', 'Hiçbir araç kullanımı raporlanmadı.');
    tarLines.push('', '## Araç Verisi Sağlanmadı', '', 'Kapanacak aktivite yok.');
  }

  const complianceContext = options.compliance;
  const objectiveCoverageMap = new Map<string, ComplianceSnapshot['objectives'][number]>();
  const independenceMap = new Map<string, ComplianceSnapshot['independenceSummary']['objectives'][number]>();
  const objectiveMetadataMap = new Map<string, Objective>();
  if (complianceContext) {
    complianceContext.snapshot.objectives.forEach((objective) => {
      objectiveCoverageMap.set(objective.objectiveId, objective);
    });
    complianceContext.snapshot.independenceSummary.objectives.forEach((entry) => {
      independenceMap.set(entry.objectiveId, entry);
    });
    (complianceContext.objectivesMetadata ?? []).forEach((objective) => {
      objectiveMetadataMap.set(objective.id, objective);
    });
  }

  const ledgerHashMap = complianceContext?.ledgerHashes ?? {};

  const formatStatusBadge = (
    status: ComplianceSnapshot['objectives'][number]['status'],
  ): string => `${statusLabels[status] ?? status} (${objectiveStatusBadgeClasses[status] ?? status})`;

  const summarizeResidualRisks = (risks: string[] | undefined): { count: number; summary: string } => {
    if (!risks || risks.length === 0) {
      return { count: 0, summary: 'Kalıcı Risk Özeti: Risk kaydı bulunmuyor.' };
    }
    if (risks.length === 1) {
      return { count: 1, summary: `Kalıcı Risk Özeti: ${risks[0]}` };
    }
    return {
      count: risks.length,
      summary: `Kalıcı Risk Özeti (${risks.length} madde): ${risks.join('; ')}`,
    };
  };

  const buildObjectiveCrossLinks = (objectiveIds: string[]): string[] => {
    if (!complianceContext) {
      return [];
    }
    const sortedIds = [...new Set(objectiveIds)].sort((a, b) => a.localeCompare(b));
    return sortedIds.map((objectiveId) => {
      const metadata = objectiveMetadataMap.get(objectiveId);
      const coverage = objectiveCoverageMap.get(objectiveId);
      const independence = independenceMap.get(objectiveId);
      const nameSegment = metadata?.name ? ` — ${metadata.name}` : '';
      const details: string[] = [];
      if (metadata?.stage) {
        details.push(`Aşama: ${stageLabels[metadata.stage] ?? metadata.stage}`);
      }
      if (coverage) {
        details.push(`Durum: ${formatStatusBadge(coverage.status)}`);
      } else {
        details.push('Durum: Bilinmiyor');
      }
      if (independence) {
        const independenceLabel = independenceLevelText[independence.independence] ?? independence.independence;
        const independenceBadge = formatStatusBadge(independence.status);
        const missingSuffix = independence.missingArtifacts.length
          ? ` – Eksik: ${independence.missingArtifacts
              .map((artifact) => artifactLabels[artifact] ?? artifact)
              .join(', ')}`
          : ' – Eksik yok';
        details.push(`Bağımsızlık: ${independenceLabel} (${independenceBadge})${missingSuffix}`);
      } else if (metadata?.independence && metadata.independence !== 'none') {
        const fallbackLabel = independenceLevelText[metadata.independence] ?? metadata.independence;
        details.push(`Bağımsızlık: ${fallbackLabel}`);
      }
      if (coverage) {
        const ledgerEntries = Array.from(
          new Set(
            coverage.evidenceRefs
              .map((ref) => {
                const normalizedRef = ref.includes(':') ? ref.split(':', 2)[1] ?? ref : ref;
                return ledgerHashMap[normalizedRef] ?? ledgerHashMap[ref];
              })
              .filter((hash): hash is string => Boolean(hash)),
          ),
        );
        if (ledgerEntries.length > 0) {
          details.push(`Ledger Hashleri: ${ledgerEntries.join(', ')}`);
        }
      }
      const suffix = details.length > 0 ? ` • ${details.join(' • ')}` : '';
      return `- ${objectiveId}${nameSegment}${suffix}`;
    });
  };

  const normalizeObjectiveId = (objectiveId: string): string => {
    return objectiveId.replace(/^DO-178C\s+/i, '').trim();
  };

  const summaryTools: ToolQualificationSummaryItem[] = toolUsage.map((tool) => {
    const pendingActivities = (tool.validation ?? []).filter((activity) => activity.status !== 'passed').length;
    const residual = summarizeResidualRisks(tool.residualRisks);
    return {
      id: tool.id,
      name: tool.name,
      version: tool.version,
      category: tool.category,
      tql: tool.tql,
      outputs: tool.outputs.map((output) => output.name),
      pendingActivities,
      residualRiskCount: residual.count,
      residualRiskSummary: residual.summary,
    };
  });

  toolUsage.forEach((tool, index) => {
    const headerIndex = index + 1;
    const heading = `## ${headerIndex}. ${tool.name}${tool.version ? ` v${tool.version}` : ''}`;
    tqpLines.push('', heading, '');
    tqpLines.push(
      `- Tanım: ${tool.description ?? 'Açıklama sağlanmadı.'}`,
      `- Tedarikçi: ${tool.vendor ?? 'Bilinmiyor'}`,
      `- Kategori: ${tool.category}`,
      `- Önerilen TQL: ${tool.tql ?? 'TBD'}`,
      `- Çevre: ${(tool.environment ?? ['Çevre belirtilmedi.']).join(', ')}`,
    );
    tqpLines.push('', '### 1. Kullanım Kapsamı');
    tqpLines.push(formatBulletList(tool.objectives, 'Hedef belirtilmedi.'));
    tqpLines.push('', '### 2. Üretilen Çıktılar');
    tqpLines.push(formatBulletList(tool.outputs.map(describeOutput), 'Kayıtlı çıktı yok.'));
    tqpLines.push('', '### 3. Kontroller ve Doğrulama Aktiviteleri');
    const controlLines = (tool.controls ?? []).map(describeControl);
    const validationLines = (tool.validation ?? []).map(describeValidationActivity);
    const combined = [...controlLines, ...validationLines];
    tqpLines.push(formatBulletList(combined, 'Kontrol veya doğrulama adımı tanımlanmadı.'));
    let nextSectionIndex = 4;
    if (tool.limitations && tool.limitations.length > 0) {
      tqpLines.push('', '### 4. Bilinen Sınırlamalar');
      tqpLines.push(formatBulletList(tool.limitations, 'Sınırlama tanımlanmadı.'));
      nextSectionIndex = 5;
    }

    const linkedObjectives = new Set<string>();
    tool.objectives.forEach((objectiveId) => {
      const normalized = normalizeObjectiveId(objectiveId);
      if (normalized) {
        linkedObjectives.add(normalized);
      }
    });
    tool.outputs.forEach((output) => {
      (output.referencedObjectives ?? []).forEach((objectiveId) => {
        const normalized = normalizeObjectiveId(objectiveId);
        if (normalized) {
          linkedObjectives.add(normalized);
        }
      });
    });
    const crossLinks = buildObjectiveCrossLinks(Array.from(linkedObjectives));
    if (crossLinks.length > 0) {
      tqpLines.push('', `### ${nextSectionIndex}. Uyum Bağlantıları`);
      tqpLines.push(...crossLinks);
      nextSectionIndex += 1;
    }
    tqpLines.push('', `> ${summaryTools[index].residualRiskSummary}`);

    tarLines.push('', heading, '');
    tarLines.push('- Kullanım Özeti:');
    tarLines.push(formatBulletList(tool.outputs.map(describeOutput), 'Kayıtlı çıktı yok.'));
    tarLines.push('', '### Niteliklendirme Aktivite Durumu');
    tarLines.push(
      formatBulletList(
        validationLines.length > 0
          ? validationLines
          : [(tool.controls ?? []).length > 0 ? 'Planlanan kontroller yürütüldü.' : 'Aktivite kaydı yok.'],
        'Aktivite kaydı yok.',
      ),
    );
    if (crossLinks.length > 0) {
      tarLines.push('', '### Uyum Referansları');
      tarLines.push(...crossLinks);
    }
    if (tool.residualRisks && tool.residualRisks.length > 0) {
      tarLines.push('', '### Kalıcı Riskler');
      tarLines.push(formatBulletList(tool.residualRisks, 'Kalıcı risk tanımlanmadı.'));
    }
    tarLines.push('', `> ${summaryTools[index].residualRiskSummary}`);
    if (summaryTools[index].pendingActivities > 0) {
      tarLines.push('', `> Açık Aktivite Sayısı: ${summaryTools[index].pendingActivities}`);
    }
  });

  return {
    tqp: { filename: defaultTqpFilename, content: `${tqpLines.join('\n')}\n` },
    tar: { filename: defaultTarFilename, content: `${tarLines.join('\n')}` },
    summary: {
      generatedAt,
      programName: options.programName,
      level: options.level,
      author: options.author,
      tools: summaryTools,
    },
  };
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

const createTraceMatrixCsv = (
  rows: TraceMatrixRow[],
  options: TraceMatrixOptions,
): TraceMatrixCsvExport => {
  const designLookup = normalizeDesignLinks(options.designs);
  const csvRows: TraceMatrixCsvRow[] = [];

  rows.forEach((row) => {
    const requirementDesigns = designLookup.get(row.requirementId) ?? [];
    const requirementStatus = row.requirementStatus ?? '';
    const coverageStatusLabel = row.coverage?.statusLabel ?? coverageStatusLabels.missing.label;
    const coverageLabel = row.coverage?.coverageLabel ?? '';
    const codePaths = row.codePaths.length > 0 ? row.codePaths : [{ path: '', coverageLabel: '' }];
    const tests = row.tests.length > 0
      ? row.tests
      : [{ id: '', name: '', statusLabel: '', statusClass: '' }];

    const designs = requirementDesigns.length > 0
      ? requirementDesigns
      : [
          {
            requirementId: row.requirementId,
            designId: '',
            designName: '',
            status: '',
          },
        ];

    designs.forEach((design) => {
      const designCodeRefs = design.codeRefs;
      const matchedCodes = designCodeRefs && designCodeRefs.length > 0
        ? codePaths.filter((code) => designCodeRefs.includes(code.path))
        : codePaths;
      const codes = matchedCodes.length > 0 ? matchedCodes : [{ path: '', coverageLabel: '' }];

      codes.forEach((code) => {
        tests.forEach((test) => {
          csvRows.push({
            requirementId: row.requirementId,
            requirementTitle: row.requirementTitle,
            requirementStatus,
            requirementCoverageStatus: coverageStatusLabel,
            requirementCoverage: coverageLabel,
            designId: design.designId ?? '',
            designName: design.designName ?? design.designId ?? '',
            designStatus: design.designId ? design.status ?? 'Tanımsız' : '',
            codePath: code.path ?? '',
            codeCoverage: code.coverageLabel ?? '',
            testId: test.id ?? '',
            testName: test.name ?? '',
            testStatus: test.statusLabel ?? '',
          });
        });
      });
    });
  });

  const records = csvRows.map((row) => [
    row.requirementId,
    row.requirementTitle,
    row.requirementStatus,
    row.requirementCoverageStatus,
    row.requirementCoverage,
    row.designId,
    row.designName,
    row.designStatus,
    row.codePath,
    row.codeCoverage,
    row.testId,
    row.testName,
    row.testStatus,
  ]);

  const csvLines = [traceCsvHeaders, ...records].map((line) => line.map(escapeCsvValue).join(','));

  return {
    headers: [...traceCsvHeaders],
    rows: csvRows,
    records,
    csv: csvLines.join('\n'),
  };
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

  .summary-card--accent {
    box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.25);
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

  .heatmap-legend {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 16px;
    flex-wrap: wrap;
  }

  .heatmap-legend span {
    font-size: 12px;
    color: #475569;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }

  .heatmap-gradient {
    width: 200px;
    height: 14px;
    border-radius: 999px;
    overflow: hidden;
    box-shadow: inset 0 0 0 1px rgba(15, 23, 42, 0.08);
  }

  .heatmap-gradient svg {
    display: block;
    width: 100%;
    height: 100%;
  }

  .heatmap-table {
    width: 100%;
    border-collapse: separate;
    border-spacing: 8px;
    margin-bottom: 12px;
  }

  .heatmap-table th {
    text-align: center;
    border: none;
    background: none;
    color: #475569;
  }

  .heatmap-table th:first-child {
    text-align: left;
  }

  .heatmap-table td {
    border: none;
    padding: 0;
    background: none;
  }

  .heatmap-cell {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 4px;
    border-radius: 12px;
    padding: 12px 8px;
    min-height: 72px;
    background: linear-gradient(135deg, rgba(30, 64, 175, calc(var(--intensity, 0) * 0.55 + 0.05)), rgba(191, 219, 254, calc(var(--intensity, 0) * 0.85 + 0.15)));
    box-shadow: inset 0 0 0 1px rgba(15, 23, 42, 0.08);
    color: #0f172a;
    transition: transform 0.2s ease-in-out;
  }

  .heatmap-cell[data-empty='true'] {
    background: rgba(226, 232, 240, 0.6);
    color: #475569;
    box-shadow: inset 0 0 0 1px rgba(148, 163, 184, 0.45);
  }

  .heatmap-cell strong {
    font-size: 18px;
    font-weight: 700;
  }

  .heatmap-cell .muted {
    font-size: 12px;
    color: #475569;
  }

  .heatmap-footnote {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    gap: 8px;
    font-size: 13px;
    color: #475569;
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

  .independence-summary {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
    margin-bottom: 12px;
  }

  .independence-badges {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-bottom: 12px;
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

  .stage-tabs {
    margin-bottom: 24px;
  }

  .stage-tabs input[type='radio'] {
    display: none;
  }

  .stage-tabs-nav {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-bottom: 16px;
  }

  .stage-tab-label {
    display: inline-flex;
    flex-direction: column;
    gap: 4px;
    padding: 10px 16px;
    border-radius: 12px;
    background: rgba(15, 23, 42, 0.05);
    cursor: pointer;
    border: 1px solid transparent;
    transition: all 0.2s ease-in-out;
  }

  .stage-tab-label:hover {
    border-color: rgba(15, 23, 42, 0.12);
  }

  .stage-tab-title {
    font-weight: 600;
    color: #0f172a;
  }

  .stage-tab-summary {
    font-size: 12px;
    color: #475569;
  }

  .stage-panels {
    position: relative;
  }

  .stage-panel {
    display: none;
    animation: fadeIn 0.25s ease-in-out;
  }

  @keyframes fadeIn {
    from {
      opacity: 0;
      transform: translateY(6px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }

  .stage-tabs input:nth-of-type(1):checked ~ .stage-panels .stage-panel:nth-of-type(1),
  .stage-tabs input:nth-of-type(2):checked ~ .stage-panels .stage-panel:nth-of-type(2),
  .stage-tabs input:nth-of-type(3):checked ~ .stage-panels .stage-panel:nth-of-type(3),
  .stage-tabs input:nth-of-type(4):checked ~ .stage-panels .stage-panel:nth-of-type(4),
  .stage-tabs input:nth-of-type(5):checked ~ .stage-panels .stage-panel:nth-of-type(5),
  .stage-tabs input:nth-of-type(6):checked ~ .stage-panels .stage-panel:nth-of-type(6) {
    display: block;
  }

  .stage-tabs input:nth-of-type(1):checked ~ .stage-tabs-nav label:nth-of-type(1),
  .stage-tabs input:nth-of-type(2):checked ~ .stage-tabs-nav label:nth-of-type(2),
  .stage-tabs input:nth-of-type(3):checked ~ .stage-tabs-nav label:nth-of-type(3),
  .stage-tabs input:nth-of-type(4):checked ~ .stage-tabs-nav label:nth-of-type(4),
  .stage-tabs input:nth-of-type(5):checked ~ .stage-tabs-nav label:nth-of-type(5),
  .stage-tabs input:nth-of-type(6):checked ~ .stage-tabs-nav label:nth-of-type(6) {
    background: rgba(59, 130, 246, 0.12);
    border-color: rgba(59, 130, 246, 0.35);
    box-shadow: 0 4px 12px rgba(59, 130, 246, 0.18);
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

  .readiness-grid {
    display: grid;
    gap: 20px;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    align-items: stretch;
  }

  .readiness-score {
    border: 1px solid #e2e8f0;
    border-radius: 14px;
    padding: 20px;
    background: linear-gradient(135deg, rgba(59, 130, 246, 0.1), rgba(14, 116, 144, 0.08));
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .readiness-score-value {
    font-size: 40px;
    font-weight: 600;
    color: #0f172a;
  }

  .readiness-score-label {
    font-size: 13px;
    color: #1e293b;
  }

  .readiness-score-meta {
    font-size: 12px;
    color: #475569;
  }

  .readiness-badges {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }

  .readiness-badge {
    display: inline-flex;
    align-items: center;
    padding: 4px 12px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 500;
    background: rgba(15, 23, 42, 0.08);
    color: #0f172a;
  }

  .readiness-badge--accent {
    background: rgba(59, 130, 246, 0.2);
    color: #1d4ed8;
  }

  .readiness-badge--missing {
    background: #fee2e2;
    color: #991b1b;
  }

  .readiness-explainer {
    margin: 0;
    color: #475569;
    font-size: 13px;
  }

  .readiness-sparkline {
    display: flex;
    align-items: flex-end;
    gap: 8px;
    border: 1px solid #e2e8f0;
    border-radius: 14px;
    padding: 16px;
    background: #f8fafc;
  }

  .readiness-sparkline-bar {
    width: 22px;
    border-radius: 8px 8px 0 0;
    background: linear-gradient(180deg, rgba(59, 130, 246, 0.8), rgba(59, 130, 246, 0.35));
    transition: opacity 0.2s ease-in-out;
  }

  .readiness-sparkline-bar--missing {
    background: repeating-linear-gradient(
      180deg,
      rgba(248, 113, 113, 0.85),
      rgba(248, 113, 113, 0.85) 10px,
      rgba(254, 226, 226, 0.7) 10px,
      rgba(254, 226, 226, 0.7) 20px
    );
  }

  .readiness-breakdown {
    margin-top: 24px;
    display: grid;
    gap: 16px;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  }

  .readiness-component {
    border: 1px solid #e2e8f0;
    border-radius: 12px;
    padding: 18px;
    background: #ffffff;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .readiness-component header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 8px;
  }

  .readiness-component h3 {
    margin: 0;
    font-size: 16px;
    color: #1e293b;
  }

  .readiness-component dl {
    margin: 0;
    display: grid;
    gap: 6px;
  }

  .readiness-component dt {
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: #64748b;
  }

  .readiness-component dd {
    margin: 0;
    font-weight: 600;
    color: #0f172a;
  }

  .readiness-component p {
    margin: 0;
    color: #475569;
    font-size: 13px;
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
        {% if programName %}
          <p class="report-meta">Program: <strong>{{ programName }}</strong></p>
        {% endif %}
        {% if certificationLevel %}
          <p class="report-meta">Sertifikasyon Seviyesi: <strong>{{ certificationLevel }}</strong></p>
        {% endif %}
        {% if projectVersion %}
          <p class="report-meta">Proje Sürümü: <strong>{{ projectVersion }}</strong></p>
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
          <div class="summary-card{% if metric.accent %} summary-card--accent{% endif %}">
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
</html>`);

const readinessTemplate = nunjucks.compile(
  `<section class="section">
    <h2>Hazırlık Endeksi</h2>
    <p class="section-lead">{{ explanation }}</p>
    <div class="readiness-grid">
      <div class="readiness-score">
        <span class="readiness-score-value">{{ percentile }}</span>
        <span class="readiness-score-label">{{ percentileLabel }}</span>
        {% if computedAtLabel %}
          <span class="readiness-score-meta">{{ computedAtLabel }}</span>
        {% endif %}
        {% if badges.length %}
          <div class="readiness-badges">
            {% for badge in badges %}
              <span class="readiness-badge{% if badge.accent %} readiness-badge--accent{% endif %}{% if badge.missing %} readiness-badge--missing{% endif %}">
                {{ badge.label }}: {{ badge.value }}
              </span>
            {% endfor %}
          </div>
        {% endif %}
        <p class="readiness-explainer">${readinessExplainer}</p>
      </div>
      <div class="readiness-sparkline" role="img" aria-label="{{ sparkline.label }}">
        {% for bar in sparkline.bars %}
          <span class="readiness-sparkline-bar{% if bar.missing %} readiness-sparkline-bar--missing{% endif %}" style="height: {{ bar.height }}px" title="{{ bar.title }}"></span>
        {% endfor %}
      </div>
    </div>
    <div class="readiness-breakdown">
      {% for component in components %}
        <article class="readiness-component">
          <header>
            <h3>{{ component.label }}</h3>
            {% if component.missing %}
              <span class="readiness-badge readiness-badge--missing">Veri eksik</span>
            {% endif %}
          </header>
          <dl>
            <dt>Skor</dt>
            <dd>{{ component.scoreLabel }}</dd>
            <dt>Katkı</dt>
            <dd>{{ component.contributionLabel }}</dd>
            <dt>Ağırlık</dt>
            <dd>{{ component.weightLabel }}</dd>
          </dl>
          {% if component.details %}
            <p>{{ component.details }}</p>
          {% endif %}
        </article>
      {% endfor %}
    </div>
  </section>`
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
    {% if delta %}
      <div class="risk-breakdown">
        <h3>Uyum Delta Panosu</h3>
        <p class="muted">{{ delta.totalsLabel }}</p>
        {% if delta.sparkline %}
          <div class="risk-delta-sparkline" role="img" aria-label="{{ delta.sparkline.label }}">
            {{ delta.sparkline.svg | safe }}
          </div>
        {% endif %}
        <div class="risk-delta-panels">
          <div class="risk-delta-panel">
            <h4>Adım Özeti</h4>
            {% if delta.trend.length %}
              <table>
                <thead>
                  <tr>
                    <th>Dönem</th>
                    <th style="text-align:right;">İyileşme</th>
                    <th style="text-align:right;">Gerileme</th>
                  </tr>
                </thead>
                <tbody>
                  {% for entry in delta.trend %}
                    <tr>
                      <td>
                        <div class="cell-title">{{ entry.label }}</div>
                        {% if entry.window %}
                          <div class="muted">{{ entry.window }}</div>
                        {% endif %}
                      </td>
                      <td style="text-align:right;">{{ entry.improvements }}</td>
                      <td style="text-align:right;">{{ entry.regressions }}</td>
                    </tr>
                  {% endfor %}
                </tbody>
              </table>
            {% else %}
              <p class="muted">Delta adımı kaydedilmedi.</p>
            {% endif %}
          </div>
          <div class="risk-delta-panel">
            <h4>Regresyonlar</h4>
            {% if delta.regressions.length %}
              <table>
                <thead>
                  <tr>
                    <th>Hedef</th>
                    <th>Durum Değişimi</th>
                    <th>Dönem</th>
                  </tr>
                </thead>
                <tbody>
                  {% for regression in delta.regressions %}
                    <tr>
                      <td><span class="cell-title">{{ regression.objectiveId }}</span></td>
                      <td><span class="badge {{ regression.badgeClass }}">{{ regression.changeLabel }}</span></td>
                      <td><span class="muted">{{ regression.stepLabel }}</span></td>
                    </tr>
                  {% endfor %}
                </tbody>
              </table>
            {% else %}
              <p class="muted">Gerileme kaydı bulunmuyor.</p>
            {% endif %}
          </div>
        </div>
      </div>
    {% endif %}
    {% if missingSignals.length %}
      <p class="muted">Eksik sinyaller: {{ missingSignals | join(', ') }}</p>
    {% endif %}
  </section>`);

const toolQualificationTemplate = nunjucks.compile(
  `<section class="section">
    <h2>DO-330 Araç Niteliklendirme</h2>
    <p class="section-lead">{{ summaryLabel }}</p>
    {% if tqpHref or tarHref %}
      <div class="risk-breakdown-stats">
        {% if tqpHref %}
          <a class="badge badge-soft" href="{{ tqpHref }}">TQP Taslağı</a>
        {% endif %}
        {% if tarHref %}
          <a class="badge badge-soft" href="{{ tarHref }}">TAR Özeti</a>
        {% endif %}
      </div>
    {% endif %}
    {% if tools.length %}
      <table>
        <thead>
          <tr>
            <th>Araç</th>
            <th>Kategori</th>
            <th>TQL</th>
            <th>Üretilen Çıktılar</th>
            <th>Kalıcı Risk Özeti</th>
            <th>Açık Aktiviteler</th>
          </tr>
        </thead>
        <tbody>
          {% for tool in tools %}
            <tr>
              <td>
                <div class="cell-title">{{ tool.name }}</div>
                <div class="muted">{{ tool.id }}{% if tool.version %} • v{{ tool.version }}{% endif %}</div>
              </td>
              <td>{{ tool.category }}</td>
              <td>{{ tool.tql or 'TBD' }}</td>
              <td>
                {% if tool.outputs.length %}
                  <ul class="list">
                    {% for output in tool.outputs %}
                      <li class="muted">{{ output }}</li>
                    {% endfor %}
                  </ul>
                {% else %}
                  <span class="muted">Çıktı kaydı yok</span>
                {% endif %}
              </td>
              <td>
                <span class="muted">{{ tool.residualRiskSummary }}</span>
              </td>
              <td>
                {% if tool.pendingActivities > 0 %}
                  <span class="badge status-missing">{{ tool.pendingActivities }}</span>
                {% else %}
                  <span class="badge status-covered">0</span>
                {% endif %}
              </td>
            </tr>
          {% endfor %}
        </tbody>
      </table>
    {% else %}
      <p class="muted">Araç niteliklendirme verisi sağlanmadı.</p>
    {% endif %}
  </section>`);

const complianceTemplate = nunjucks.compile(
  `<section class="section">
    <h2>Uyum Matrisi</h2>
    <p class="section-lead">
      Hedeflerin kanıt durumunu gösteren kurumsal görünüm. Her satır bir uyumluluk hedefini, sağlanan kanıtları ve açık kalan boşlukları özetler.
    </p>
    <div class="stage-tabs">
      {% for tab in stageTabs %}
        <input
          type="radio"
          id="stage-tab-{{ loop.index0 }}"
          name="stage-tabs"
          {% if loop.first %}checked{% endif %}
        />
      {% endfor %}
      <div class="stage-tabs-nav">
        {% for tab in stageTabs %}
          <label class="stage-tab-label" for="stage-tab-{{ loop.index0 }}">
            <span class="stage-tab-title">{{ tab.label }}</span>
            <span class="stage-tab-summary">{{ tab.summary.covered }}/{{ tab.summary.total }} hedef tamamlandı</span>
          </label>
        {% endfor %}
      </div>
      <div class="stage-panels">
        {% for tab in stageTabs %}
          <div class="stage-panel">
            {% if tab.objectives.length %}
              <table>
                <thead>
                  <tr>
                    <th>Hedef</th>
                    <th>Durum</th>
                    <th>Güven</th>
                    <th>Sağlanan Kanıtlar</th>
                    <th>Eksik Kanıtlar</th>
                    <th>Kanıt Referansları</th>
                    <th>Regulatory References</th>
                  </tr>
                </thead>
                <tbody>
                  {% for row in tab.objectives %}
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
                        {% if row.confidenceBadgeLabel %}
                          <span class="badge {{ row.confidenceClass }}">{{ row.confidenceBadgeLabel }}</span>
                        {% else %}
                          <span class="muted">—</span>
                        {% endif %}
                      </td>
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
                      <td>
                        <div class="regulatory-group">
                          <div class="regulatory-item">
                            <div class="muted">AC 20-115D</div>
                            {% if row.regulatoryReferences.ac20115d.length %}
                              <ul class="list">
                                {% for reference in row.regulatoryReferences.ac20115d %}
                                  <li class="muted">{{ reference }}</li>
                                {% endfor %}
                              </ul>
                            {% else %}
                              <span class="muted">—</span>
                            {% endif %}
                          </div>
                          <div class="regulatory-item">
                            <div class="muted">AMC 20-152A</div>
                            {% if row.regulatoryReferences.easaAmc_20_152a.length %}
                              <ul class="list">
                                {% for reference in row.regulatoryReferences.easaAmc_20_152a %}
                                  <li class="muted">{{ reference }}</li>
                                {% endfor %}
                              </ul>
                            {% else %}
                              <span class="muted">—</span>
                            {% endif %}
                          </div>
                          <div class="regulatory-item">
                            <div class="muted">FAA 8110.49</div>
                            {% if row.regulatoryReferences.faa8110_49.length %}
                              <ul class="list">
                                {% for reference in row.regulatoryReferences.faa8110_49 %}
                                  <li class="muted">{{ reference }}</li>
                                {% endfor %}
                              </ul>
                            {% else %}
                              <span class="muted">—</span>
                            {% endif %}
                          </div>
                        </div>
                      </td>
                    </tr>
                  {% endfor %}
                </tbody>
              </table>
            {% else %}
              <p class="muted">Bu aşamada hedef bulunmuyor.</p>
            {% endif %}
          </div>
        {% endfor %}
      </div>
    </div>
  </section>
  {% if independence %}
    <section class="section" aria-labelledby="independence-summary">
      <h2 id="independence-summary">Bağımsızlık Uyarıları</h2>
      <p class="section-lead">{{ independence.lead }}</p>
      <div class="independence-summary">
        <span class="badge {{ independence.statusClass }}">{{ independence.statusLabel }}</span>
        <span class="muted">{{ independence.totalsLabel }}</span>
      </div>
      {% if independence.badges.length %}
        <div class="independence-badges">
          {% for badge in independence.badges %}
            <span class="badge {{ badge.className }}">{{ badge.label }}</span>
          {% endfor %}
        </div>
      {% endif %}
      {% if independence.objectives.length %}
        <table>
          <thead>
            <tr>
              <th>Hedef</th>
              <th>Bağımsızlık</th>
              <th>Durum</th>
              <th>Eksik Kanıtlar</th>
            </tr>
          </thead>
          <tbody>
            {% for row in independence.objectives %}
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
                <td><span class="badge {{ row.independenceClass }}">{{ row.independenceLabel }}</span></td>
                <td><span class="badge {{ row.statusClass }}">{{ row.statusLabel }}</span></td>
                <td>
                  {% if row.missingArtifacts.length %}
                    {% for artifact in row.missingArtifacts %}
                      <span class="badge badge-critical">{{ artifact }}</span>
                    {% endfor %}
                  {% else %}
                    <span class="muted">Eksik kanıt yok</span>
                  {% endif %}
                </td>
              </tr>
            {% endfor %}
          </tbody>
        </table>
      {% else %}
        <p class="muted">{{ independence.emptyLabel }}</p>
      {% endif %}
    </section>
  {% endif %}
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
  {% endif %}`);

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
  </section>`);

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
  </section>`);

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
  </section>`);

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

const formatArtifact = (artifact: ObjectiveArtifactType | 'design'): string => {
  if (artifact === 'design') {
    return 'DESIGN';
  }
  return artifactLabels[artifact] ?? artifact.toUpperCase();
};

const buildIndependenceSummaryView = (
  summary: ComplianceSnapshot['independenceSummary'],
  objectiveLookup?: Map<string, Objective>,
): IndependenceSummaryView => {
  const independenceSeverityRank: Record<Objective['independence'], number> = {
    required: 0,
    recommended: 1,
    none: 2,
  };
  const statusRank: Record<CoverageStatus, number> = {
    missing: 0,
    partial: 1,
    covered: 2,
  };

  const sortedObjectives = [...summary.objectives].sort((a, b) => {
    const severityDiff =
      independenceSeverityRank[a.independence] - independenceSeverityRank[b.independence];
    if (severityDiff !== 0) {
      return severityDiff;
    }
    const statusDiff = statusRank[a.status] - statusRank[b.status];
    if (statusDiff !== 0) {
      return statusDiff;
    }
    return a.objectiveId.localeCompare(b.objectiveId);
  });

  const objectives: IndependenceObjectiveView[] = sortedObjectives.map((entry) => {
    const meta = objectiveLookup?.get(entry.objectiveId);
    const levelMeta = independenceLevelLabels[entry.independence] ?? independenceLevelLabels.none;
    const statusMeta = statusLabels[entry.status] ?? entry.status;
    const statusClass =
      entry.status === 'covered'
        ? 'status-covered'
        : entry.status === 'partial'
          ? 'status-partial'
          : 'status-missing';

    return {
      id: entry.objectiveId,
      table: meta?.table,
      name: meta?.name,
      desc: meta?.desc,
      independenceLabel: levelMeta.label,
      independenceClass: levelMeta.className,
      statusLabel: statusMeta,
      statusClass,
      missingArtifacts: entry.missingArtifacts.map((artifact) => formatArtifact(artifact)),
    };
  });

  const totalsLabel = `Etkilenen hedef: ${summary.objectives.length} • Kısmi: ${summary.totals.partial} • Eksik: ${summary.totals.missing}`;
  const statusKey: CoverageStatus = summary.totals.missing > 0
    ? 'missing'
    : summary.totals.partial > 0
      ? 'partial'
      : 'covered';
  const statusMeta = independenceStatusLabels[statusKey];

  const levelCounts = summary.objectives.reduce(
    (acc, entry) => {
      if (entry.independence === 'required') {
        acc.required += 1;
      } else if (entry.independence === 'recommended') {
        acc.recommended += 1;
      }
      return acc;
    },
    { required: 0, recommended: 0 },
  );

  const badges: IndependenceBadgeView[] = [];
  if (levelCounts.required > 0) {
    badges.push({ label: `Zorunlu: ${levelCounts.required}`, className: 'status-missing' });
  }
  if (levelCounts.recommended > 0) {
    badges.push({ label: `Önerilen: ${levelCounts.recommended}`, className: 'status-partial' });
  }

  return {
    statusLabel: statusMeta.label,
    statusClass: statusMeta.className,
    totalsLabel,
    badges,
    objectives,
    emptyLabel: 'Bağımsızlık gerektiren hedeflerde eksik bulunamadı.',
    lead:
      'Bağımsız doğrulama gerektiren hedeflerde eksik veya bağımsız olmayan kanıtları vurgular. Zorunlu eksikler sertifikasyon için kritik kabul edilir.',
  };
};

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

const statusBadgeClasses: Record<
  ComplianceSnapshot['objectives'][number]['status'],
  string
> = {
  covered: 'status-covered',
  partial: 'status-partial',
  missing: 'status-missing',
};

const buildRegressionSparkline = (values: number[]): RiskDeltaSparklineView | undefined => {
  if (values.length === 0) {
    return undefined;
  }

  const maxValue = Math.max(...values);
  const width = Math.max(60, values.length * 18);
  const height = 32;
  const baseY = height - 4;
  const step = values.length > 1 ? width / (values.length - 1) : 0;

  if (maxValue === 0) {
    const svg = `<svg viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" xmlns="http://www.w3.org/2000/svg" class="sparkline-graph"><line x1="0" y1="${baseY}" x2="${width}" y2="${baseY}" stroke="#64748b" stroke-width="2" stroke-dasharray="4 4" /></svg>`;
    return { svg, label: `Regresyon trendi: ${values.join(', ')}` };
  }

  const points = values.map((value, index) => {
    const x = values.length === 1 ? width / 2 : index * step;
    const normalized = value / maxValue;
    const y = baseY - normalized * (height - 8);
    return { x, y };
  });

  const linePoints = points.map((point) => `${point.x.toFixed(1)},${point.y.toFixed(1)}`).join(' ');
  const areaPoints = [`0,${height}`, ...points.map((point) => `${point.x.toFixed(1)},${point.y.toFixed(1)}`), `${width.toFixed(1)},${height}`].join(' ');
  const svg = `<svg viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" xmlns="http://www.w3.org/2000/svg" class="sparkline-graph"><polygon points="${areaPoints}" fill="rgba(244,63,94,0.18)" /><polyline points="${linePoints}" fill="none" stroke="#f43f5e" stroke-width="2" stroke-linecap="round" /></svg>`;
  return { svg, label: `Regresyon trendi: ${values.join(', ')}` };
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

  let delta: RiskDeltaView | undefined;
  if (risk.complianceDelta && risk.complianceDelta.steps.length > 0) {
    const formatStatus = (status: ComplianceSnapshot['objectives'][number]['status']) =>
      statusLabels[status] ?? status;

    const trend: RiskDeltaTrendEntryView[] = risk.complianceDelta.steps.map((step) => {
      const fromId = step.from?.version.id ?? 'Önceki';
      const toId = step.to.version.id;
      const fromDate = step.from?.generatedAt ? formatDate(step.from.generatedAt) : undefined;
      const toDate = step.to.generatedAt ? formatDate(step.to.generatedAt) : undefined;
      const window = [fromDate, toDate].filter(Boolean).join(' → ') || undefined;
      return {
        label: `${fromId} → ${toId}`,
        window,
        improvements: step.improvements.length,
        regressions: step.regressions.length,
      };
    });

    const regressionEntries: RiskDeltaRegressionView[] = risk.complianceDelta.steps.flatMap((step) => {
      const labelParts = [`${step.from?.version.id ?? 'Önceki'} → ${step.to.version.id}`];
      const fromDate = step.from?.generatedAt ? formatDate(step.from.generatedAt) : undefined;
      const toDate = step.to.generatedAt ? formatDate(step.to.generatedAt) : undefined;
      const timeRange = [fromDate, toDate].filter(Boolean).join(' → ');
      if (timeRange) {
        labelParts.push(`(${timeRange})`);
      }
      const stepLabel = labelParts.join(' ');
      return step.regressions.map((change) => ({
        objectiveId: change.objectiveId,
        changeLabel: `${formatStatus(change.previousStatus)} → ${formatStatus(change.currentStatus)}`,
        stepLabel,
        badgeClass: statusBadgeClasses[change.currentStatus] ?? 'status-partial',
      }));
    });

    const summary: RiskDeltaSummaryJson = {
      totals: risk.complianceDelta.totals,
      steps: risk.complianceDelta.steps.map((step) => ({
        fromVersionId: step.from?.version.id,
        toVersionId: step.to.version.id,
        fromGeneratedAt: step.from?.generatedAt,
        toGeneratedAt: step.to.generatedAt,
        improvements: step.improvements.length,
        regressions: step.regressions.length,
      })),
      regressions: risk.complianceDelta.steps.flatMap((step) =>
        step.regressions.map((change) => ({
          objectiveId: change.objectiveId,
          previousStatus: change.previousStatus,
          currentStatus: change.currentStatus,
          fromVersionId: step.from?.version.id,
          toVersionId: step.to.version.id,
        })),
      ),
    };

    delta = {
      totalsLabel: `İyileşme: ${risk.complianceDelta.totals.improvements}, Gerileme: ${risk.complianceDelta.totals.regressions}`,
      totals: risk.complianceDelta.totals,
      trend,
      regressions: regressionEntries,
      sparkline: buildRegressionSparkline(trend.map((entry) => entry.regressions)),
      summary,
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
    delta,
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

const CHANGE_IMPACT_LIMIT = 25;

const getChangeImpactSeverityMeta = (severity: number) => {
  for (const bucket of changeImpactSeverityBuckets) {
    if (severity >= bucket.threshold) {
      return bucket;
    }
  }
  return changeImpactSeverityBuckets[changeImpactSeverityBuckets.length - 1];
};

const condenseChangeImpactReasons = (reasons: string[]): string => {
  const filtered = reasons.filter((reason) => reason && reason.trim().length > 0);
  if (filtered.length === 0) {
    return 'Gerekçe sağlanmadı.';
  }
  if (filtered.length === 1) {
    return filtered[0];
  }
  if (filtered.length === 2) {
    return `${filtered[0]} • ${filtered[1]}`;
  }
  const remaining = filtered.length - 2;
  return `${filtered[0]} • ${filtered[1]} (+${remaining} ek gerekçe)`;
};

const buildChangeImpactView = (
  changeImpact?: ChangeImpactScore[],
): ChangeImpactView | undefined => {
  if (!changeImpact || changeImpact.length === 0) {
    return undefined;
  }

  const sorted = [...changeImpact]
    .sort((a, b) => {
      if (b.severity === a.severity) {
        return a.id.localeCompare(b.id);
      }
      return b.severity - a.severity;
    })
    .slice(0, CHANGE_IMPACT_LIMIT);

  const severityCounts: Record<ChangeImpactSeverityKey, number> = {
    critical: 0,
    high: 0,
    medium: 0,
  };

  const entries = sorted.map<ChangeImpactEntryView>((entry) => {
    const severityMeta = getChangeImpactSeverityMeta(entry.severity);
    severityCounts[severityMeta.id] += 1;
    const stateMeta = changeImpactStateLabels[entry.state];
    return {
      key: entry.key,
      id: entry.id,
      typeLabel: changeImpactTypeLabels[entry.type],
      severityLabel: severityMeta.label,
      severityClass: severityMeta.className,
      severityValue: entry.severity.toFixed(1),
      stateLabel: stateMeta.label,
      stateClass: stateMeta.className,
      reasons: condenseChangeImpactReasons(entry.reasons),
    };
  });

  const displayedLabel =
    sorted.length === changeImpact.length
      ? `${sorted.length}`
      : `${sorted.length}/${changeImpact.length}`;

  const summaryBadges: ChangeImpactSectionContext['summaryBadges'] = [
    { label: 'Kayıtlar', className: 'badge-soft', value: displayedLabel },
  ];

  changeImpactSeverityBuckets.forEach((bucket) => {
    const count = severityCounts[bucket.id];
    if (count > 0) {
      summaryBadges.push({
        label: `${bucket.label} Seviyesi`,
        className: bucket.className,
        value: count.toString(),
      });
    }
  });

  return {
    entries,
    summaryBadges,
    total: changeImpact.length,
  };
};

const buildReadinessView = (
  readiness?: ComplianceReadinessSummary,
): ReadinessView | undefined => {
  if (!readiness) {
    return undefined;
  }

  const breakdown = readiness.breakdown ?? [];
  const maxContribution = breakdown.reduce(
    (max, entry) => Math.max(max, entry.contribution),
    0,
  );
  const missingEntries = breakdown.filter((entry) => entry.missing);
  const missingLabels = missingEntries
    .map((entry) => readinessComponentLabels[entry.component] ?? entry.component)
    .filter((label) => Boolean(label));
  const leadingComponent = breakdown.length
    ? breakdown.reduce((best, current) =>
        current.contribution > best.contribution ? current : best,
      breakdown[0])
    : undefined;

  const baseHeight = 28;
  const heightScale = 60;
  const sparklineBars: ReadinessSparklineBarView[] = breakdown.map((entry) => {
    const normalized = maxContribution > 0 ? entry.contribution / maxContribution : 0;
    const height = Math.round(baseHeight + normalized * heightScale);
    const label = readinessComponentLabels[entry.component] ?? entry.component;
    return {
      height,
      title: `${label}: skor ${entry.score.toFixed(1)}%, katkı ${entry.contribution.toFixed(1)}%, ağırlık ${(entry.weight * 100).toFixed(1)}%`,
      missing: Boolean(entry.missing),
    };
  });

  const badges: ReadinessBadgeView[] = [];
  if (leadingComponent) {
    badges.push({
      label: 'En güçlü bileşen',
      value: readinessComponentLabels[leadingComponent.component] ?? leadingComponent.component,
      accent: true,
    });
  } else {
    badges.push({ label: 'En güçlü bileşen', value: 'Veri yok' });
  }

  const missingCount = missingEntries.length;
  badges.push({
    label: 'Eksik veri',
    value:
      missingCount > 0
        ? missingLabels.length > 0
          ? missingLabels.join(', ')
          : `${missingCount} bileşen`
        : 'Yok',
    missing: missingCount > 0,
  });

  if (readiness.seed !== undefined) {
    badges.push({ label: 'Tohum', value: String(readiness.seed) });
  }

  const weightSummary = breakdown.length
    ? `Ağırlıklar: ${breakdown
        .map((entry) => `${readinessComponentLabels[entry.component] ?? entry.component} ${(entry.weight * 100).toFixed(0)}%`)
        .join(', ')}.`
    : 'Ağırlık bilgisi bulunamadı.';

  const missingSummary = missingCount
    ? `Eksik veri bulunan bileşenler: ${
        missingLabels.length > 0 ? missingLabels.join(', ') : `${missingCount} bileşen`
      }.`
    : 'Tüm bileşenler veri sağladı.';

  return {
    percentile: readiness.percentile.toFixed(1),
    percentileLabel: '0-100 arası yüzdelik skor',
    computedAtLabel: readiness.computedAt ? `Hesaplanma: ${formatDate(readiness.computedAt)}` : undefined,
    badges,
    sparkline: {
      label: 'Hazırlık bileşen katkı eğrisi',
      bars: sparklineBars,
    },
    components: breakdown.map((entry) => ({
      label: readinessComponentLabels[entry.component] ?? entry.component,
      scoreLabel: `${entry.score.toFixed(1)}%`,
      contributionLabel: `${entry.contribution.toFixed(1)}%`,
      weightLabel: `${(entry.weight * 100).toFixed(1)}%`,
      details: entry.details,
      missing: Boolean(entry.missing),
    })),
    explanation: `${readinessExplainer} ${weightSummary} ${missingSummary}`.trim(),
  };
};

const buildSummaryMetrics = (
  stats: ComplianceStatistics,
  requirementCoverage: RequirementCoverageStatus[] = [],
  qualityFindings: ComplianceSnapshot['qualityFindings'] = [],
  changeImpact?: ChangeImpactScore[],
  risk?: ComplianceSnapshot['risk'],
  independenceSummary?: ComplianceSnapshot['independenceSummary'],
  readiness?: ComplianceReadinessSummary,
): LayoutSummaryMetric[] => {
  const metrics: LayoutSummaryMetric[] = [];

  if (readiness) {
    metrics.push({
      label: 'Hazırlık Skoru',
      value: `${readiness.percentile.toFixed(1)}/100`,
      accent: readiness.percentile >= 75,
    });

    const missingCount = readiness.breakdown.filter((entry) => entry.missing).length;
    metrics.push({
      label: 'Hazırlık Eksikleri',
      value: missingCount > 0 ? `${missingCount} bileşen` : 'Yok',
      accent: missingCount === 0,
    });
  }

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
    { label: 'Tasarım Kayıtları', value: stats.designs.total.toString() },
  );

  if (changeImpact && changeImpact.length > 0) {
    metrics.push({
      label: 'Değişiklik Etkileri',
      value: changeImpact.length.toString(),
      accent: true,
    });
  }

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

  if (independenceSummary) {
    const affected = independenceSummary.objectives.length;
    metrics.push({
      label: 'Bağımsızlık Eksikleri',
      value: `${affected} hedef`,
      accent: affected > 0,
    });
    metrics.push({
      label: 'Kısmi/Eksik Bağımsızlık',
      value: `${independenceSummary.totals.partial}/${independenceSummary.totals.missing}`,
      accent: independenceSummary.totals.partial > 0 || independenceSummary.totals.missing > 0,
    });
  }

  return metrics;
};

const summarizeStageObjectives = (rows: ComplianceMatrixRow[]): StageComplianceSummary =>
  rows.reduce(
    (acc, row) => {
      acc.total += 1;
      if (row.status === 'covered') {
        acc.covered += 1;
      } else if (row.status === 'partial') {
        acc.partial += 1;
      } else {
        acc.missing += 1;
      }
      return acc;
    },
    { total: 0, covered: 0, partial: 0, missing: 0 },
  );

const buildComplianceMatrixView = (
  snapshot: ComplianceSnapshot,
  options: ComplianceMatrixOptions,
): ComplianceMatrixView => {
  const objectiveLookup = new Map(options.objectivesMetadata?.map((item) => [item.id, item]));
  const stageLookup = new Map<string, SoiStage | undefined>();
  options.objectivesMetadata?.forEach((item) => {
    stageLookup.set(item.id, item.stage);
  });

  const objectives: ComplianceMatrixRow[] = snapshot.objectives.map((objective) => {
    const metadata = objectiveLookup.get(objective.objectiveId);
    const confidenceMeta = formatObjectiveConfidence((objective as { confidence?: number }).confidence);
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
      ...(confidenceMeta
        ? {
            confidence: confidenceMeta.value,
            confidenceLabel: confidenceMeta.label,
            confidenceBadgeLabel: confidenceMeta.badgeLabel,
            confidenceClass: confidenceMeta.className,
          }
        : {}),
      table: metadata?.table,
      name: metadata?.name,
      desc: metadata?.desc,
      stage: metadata?.stage,
      satisfiedArtifacts: objective.satisfiedArtifacts.map(formatArtifact),
      missingArtifacts: objective.missingArtifacts.map(formatArtifact),
      evidenceRefs: objective.evidenceRefs,
      regulatoryReferences: getRegulatoryReferences(objective.objectiveId),
    };
  });

  const stageTabs: StageComplianceTab[] = [
    {
      id: 'all',
      label: 'Tüm Stajlar',
      objectives,
      summary: summarizeStageObjectives(objectives),
    },
  ];

  soiStages.forEach((stage) => {
    const stageObjectives = objectives.filter((row) => row.stage === stage);
    if (stageObjectives.length === 0) {
      return;
    }
    stageTabs.push({
      id: stage.toLowerCase(),
      label: stageLabels[stage],
      objectives: stageObjectives,
      summary: summarizeStageObjectives(stageObjectives),
      stage,
    });
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

  const toolQualification: ToolQualificationLinkView | undefined = options.toolQualification
    ? {
        ...options.toolQualification,
        summaryLabel: options.toolQualification.generatedAt
          ? `Son güncelleme: ${formatDate(options.toolQualification.generatedAt)}`
          : 'TQP/TAR bağlantıları',
      }
    : undefined;

  const changeImpact = buildChangeImpactView(snapshot.changeImpact);
  const staleEvidenceHeatmap = buildStaleEvidenceHeatmap(snapshot.gaps.staleEvidence ?? [], {
    stageLookup,
    stageLabels,
    unknownStageLabel: 'Bilinmeyen Aşama',
    unknownBandLabel: 'Yaş bilinmiyor',
  });

  return {
    objectives,
    requirementCoverage,
    qualityFindings,
    changeImpact,
    summaryMetrics: buildSummaryMetrics(
      snapshot.stats,
      snapshot.requirementCoverage,
      snapshot.qualityFindings,
      snapshot.changeImpact,
      snapshot.risk,
      snapshot.independenceSummary,
      options.readiness,
    ),
    stageTabs,
    risk: buildRiskView(snapshot.risk),
    signoffs: buildSignoffTimelineView(options.signoffs),
    toolQualification,
    independence: buildIndependenceSummaryView(snapshot.independenceSummary, objectiveLookup),
    readiness: buildReadinessView(options.readiness),
    staleEvidenceHeatmap,
  };
};

const createComplianceMatrixCsv = (
  rows: ComplianceMatrixRow[],
  stageTabs: StageComplianceTab[],
  options: ComplianceMatrixOptions,
): ComplianceMatrixCsvExport => {
  const normalizeRow = (row: ComplianceMatrixRow): ComplianceMatrixCsvRow => ({
    objectiveId: row.id,
    table: row.table ?? '',
    stage: row.stage,
    stageLabel: row.stage ? stageLabels[row.stage] ?? row.stage : undefined,
    status: row.statusLabel,
    confidence: row.confidenceLabel,
    satisfiedArtifacts: [...row.satisfiedArtifacts],
    missingArtifacts: [...row.missingArtifacts],
    evidenceRefs: [...row.evidenceRefs],
  });

  const joinValues = (values: string[]): string => (values.length > 0 ? values.join(' | ') : '');

  const toRecord = (row: ComplianceMatrixCsvRow): string[] => [
    row.objectiveId,
    row.table,
    row.stage ?? '',
    row.status,
    row.confidence ?? '',
    joinValues(row.satisfiedArtifacts),
    joinValues(row.missingArtifacts),
    joinValues(row.evidenceRefs),
  ];

  const normalizedRows = rows.map(normalizeRow);
  const records = normalizedRows.map(toRecord);
  const metadataRecords: string[][] = [];
  if (options.programName) {
    metadataRecords.push(['Program', options.programName]);
  }
  if (options.certificationLevel) {
    metadataRecords.push(['Sertifikasyon Seviyesi', options.certificationLevel]);
  }
  if (options.projectVersion) {
    metadataRecords.push(['Proje Sürümü', options.projectVersion]);
  }

  if (options.readiness) {
    metadataRecords.push(['Hazırlık Skoru', `${options.readiness.percentile.toFixed(1)}/100`]);
    options.readiness.breakdown.forEach((entry) => {
      const label = readinessComponentLabels[entry.component] ?? entry.component;
      const detailParts = [
        `Skor ${entry.score.toFixed(1)}%`,
        `Katkı ${entry.contribution.toFixed(1)}%`,
        `Ağırlık ${(entry.weight * 100).toFixed(1)}%`,
      ];
      if (entry.missing) {
        detailParts.push('Veri eksik');
      }
      if (entry.details) {
        detailParts.push(entry.details);
      }
      metadataRecords.push([`Hazırlık ${label}`, detailParts.join(' | ')]);
    });
  }

  const metadataLines = metadataRecords.map((row) => {
    const padded = Array.from({ length: complianceCsvHeaders.length }, () => '');
    padded[0] = row[0];
    padded[1] = row[1];
    return padded;
  });

  const csvLines = [
    ...metadataLines,
    complianceCsvHeaders,
    ...records,
  ].map((line) => line.map(escapeCsvValue).join(','));

  const stageExports: Partial<Record<SoiStage, ComplianceMatrixCsvStageExport>> = {};

  stageTabs.forEach((tab) => {
    if (!tab.stage) {
      return;
    }
    const stageRows = tab.objectives.map(normalizeRow);
    const stageRecords = stageRows.map(toRecord);
    const stageCsvLines = [complianceCsvHeaders, ...stageRecords].map((line) =>
      line.map(escapeCsvValue).join(','),
    );
    stageExports[tab.stage] = {
      stage: tab.stage,
      label: tab.label,
      headers: [...complianceCsvHeaders],
      rows: stageRows,
      records: stageRecords,
      csv: stageCsvLines.join('\n'),
    };
  });

  return {
    headers: [...complianceCsvHeaders],
    rows: normalizedRows,
    records,
    csv: csvLines.join('\n'),
    metadata: {
      programName: options.programName,
      certificationLevel: options.certificationLevel,
      projectVersion: options.projectVersion,
      rows: metadataRecords,
    },
    stages: stageExports,
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
  programName: options.programName,
  certificationLevel: options.certificationLevel,
  projectVersion: options.projectVersion,
  snapshotId: options.snapshotId ?? snapshot.version.id,
  snapshotVersion: options.snapshotVersion ?? snapshot.version,
  stages: view.stageTabs.map((tab) => ({
    id: tab.stage ?? tab.id,
    label: tab.label,
    summary: tab.summary,
    objectiveIds: tab.objectives.map((objective) => objective.id),
  })),
  stats: {
    objectives: { ...snapshot.stats.objectives },
    requirements: { ...snapshot.stats.requirements },
    tests: { ...snapshot.stats.tests },
    codePaths: { ...snapshot.stats.codePaths },
    designs: { ...snapshot.stats.designs },
  },
  objectives: view.objectives.map((row) => ({
    id: row.id,
    status: row.status,
    table: row.table,
    name: row.name,
    desc: row.desc,
    ...(row.confidence !== undefined
      ? { confidence: row.confidence, confidenceLabel: row.confidenceLabel }
      : {}),
    satisfiedArtifacts: [...row.satisfiedArtifacts],
    missingArtifacts: [...row.missingArtifacts],
    evidenceRefs: [...row.evidenceRefs],
    regulatoryReferences: {
      ac20115d: [...row.regulatoryReferences.ac20115d],
      easaAmc_20_152a: [...row.regulatoryReferences.easaAmc_20_152a],
      faa8110_49: [...row.regulatoryReferences.faa8110_49],
    },
  })),
  requirementCoverage: snapshot.requirementCoverage.map((entry) => ({
    requirementId: entry.requirement.id,
    title: entry.requirement.title,
    status: entry.status,
    coverage: entry.coverage,
    codePaths: entry.codePaths.map((code) => code.path),
    designs: entry.designs.map((design) => design.id),
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
  analysis: {
    staleEvidenceHeatmap: view.staleEvidenceHeatmap
      ? {
          totalFindings: view.staleEvidenceHeatmap.totalFindings,
          updatedAt: view.staleEvidenceHeatmap.updatedAt,
          maxBucketCount: view.staleEvidenceHeatmap.maxBucketCount,
          bands: view.staleEvidenceHeatmap.bands.map((band) => ({ ...band })),
          stages: view.staleEvidenceHeatmap.stages.map((stage) => ({
            id: stage.id,
            label: stage.label,
            stage: stage.stage,
            totals: stage.totals,
            buckets: stage.buckets.map((bucket) => ({
              bandId: bucket.bandId,
              label: bucket.label,
              count: bucket.count,
              objectiveIds: [...bucket.objectiveIds],
            })),
          })),
          stageTotals: { ...view.staleEvidenceHeatmap.stageTotals },
          bandTotals: { ...view.staleEvidenceHeatmap.bandTotals },
        }
      : null,
  },
  ...(snapshot.changeImpact && snapshot.changeImpact.length > 0
    ? {
        changeImpact: snapshot.changeImpact.map((entry) => ({
          key: entry.key,
          id: entry.id,
          type: entry.type,
          severity: entry.severity,
          state: entry.state,
          reasons: [...entry.reasons],
          base: entry.base,
          coverage: entry.coverage,
          ripple: entry.ripple,
        })),
      }
    : {}),
  traceSuggestions: snapshot.traceSuggestions.map((suggestion) => ({
    requirementId: suggestion.requirementId,
    type: suggestion.type,
    targetId: suggestion.targetId,
    targetName: suggestion.targetName,
    confidence: suggestion.confidence,
    reason: suggestion.reason,
    viaTestId: suggestion.viaTestId,
  })),
  independenceSummary: {
    totals: { ...snapshot.independenceSummary.totals },
    objectives: snapshot.independenceSummary.objectives.map((entry) => ({
      objectiveId: entry.objectiveId,
      independence: entry.independence,
      status: entry.status,
      missingArtifacts: [...entry.missingArtifacts],
    })),
  },
  git: options.git ?? null,
  risk: snapshot.risk ?? null,
  complianceDelta: view.risk?.delta?.summary,
  signoffs: (options.signoffs ?? []).map((signoff) => ({ ...signoff })),
  ...(options.toolQualification
    ? {
        toolQualification: {
          ...options.toolQualification,
          tools: options.toolQualification.tools.map((tool) => ({ ...tool })),
        },
      }
    : {}),
  readiness: options.readiness
    ? {
        percentile: options.readiness.percentile,
        computedAt: options.readiness.computedAt,
        seed: options.readiness.seed,
        breakdown: options.readiness.breakdown.map((entry) => ({
          component: entry.component,
          score: entry.score,
          weight: entry.weight,
          contribution: entry.contribution,
          ...(entry.details ? { details: entry.details } : {}),
          ...(entry.missing ? { missing: true } : {}),
        })),
      }
    : null,
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
  if (view.readiness) {
    sections.push(readinessTemplate.render(view.readiness));
  }
  if (view.risk) {
    sections.push(riskTemplate.render(view.risk));
  }
  if (view.toolQualification) {
    sections.push(toolQualificationTemplate.render(view.toolQualification));
  }
  sections.push(
    complianceTemplate.render({
      objectives: view.objectives,
      stageTabs: view.stageTabs,
      requirementCoverage: view.requirementCoverage,
      qualityFindings: view.qualityFindings,
      independence: view.independence,
    }),
  );
  if (view.staleEvidenceHeatmap) {
    sections.push(renderStaleEvidenceHeatmapSection(view.staleEvidenceHeatmap));
  }
  if (view.changeImpact) {
    sections.push(renderChangeImpactSection(view.changeImpact));
  }
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
    programName: options.programName,
    certificationLevel: options.certificationLevel,
    projectVersion: options.projectVersion,
  });

  const json = buildComplianceMatrixJson(snapshot, options, view);
  const csv = createComplianceMatrixCsv(view.objectives, view.stageTabs, options);

  return { html, json, csv };
};

export const renderComplianceCoverageReport = (
  snapshot: ComplianceSnapshot,
  coverage: CoverageReport,
  options: ComplianceCoverageReportOptions = {},
): ComplianceCoverageReportResult => {
  const view = buildComplianceMatrixView(snapshot, options);
  const coverageWarnings = options.coverageWarnings ?? [];
  const changeRequestBacklog = options.changeRequestBacklog ?? [];
  const ledgerDiffs = options.ledgerDiffs ?? [];

  const sections: string[] = [];
  if (view.readiness) {
    sections.push(readinessTemplate.render(view.readiness));
  }
  if (view.risk) {
    sections.push(riskTemplate.render(view.risk));
  }
  if (view.toolQualification) {
    sections.push(toolQualificationTemplate.render(view.toolQualification));
  }
  sections.push(
    complianceTemplate.render({
      objectives: view.objectives,
      stageTabs: view.stageTabs,
      requirementCoverage: view.requirementCoverage,
      qualityFindings: view.qualityFindings,
      independence: view.independence,
    }),
  );
  if (view.staleEvidenceHeatmap) {
    sections.push(renderStaleEvidenceHeatmapSection(view.staleEvidenceHeatmap));
  }
  if (view.changeImpact) {
    sections.push(renderChangeImpactSection(view.changeImpact));
  }
  if (view.signoffs) {
    sections.push(signoffTimelineTemplate.render(view.signoffs));
  }
  sections.push(renderCoverageSummarySection({ coverage, warnings: coverageWarnings }));
  if (changeRequestBacklog.length > 0) {
    sections.push(renderChangeRequestBacklogSection({ items: changeRequestBacklog }));
  }
  if (ledgerDiffs.length > 0) {
    sections.push(renderLedgerDiffSection({ diffs: ledgerDiffs }));
  }
  const content = sections.join('');

  const summaryMetrics = [...view.summaryMetrics, ...buildCoverageSummaryMetrics(coverage)];
  if (options.changeRequestBacklog !== undefined) {
    summaryMetrics.push({
      label: 'Açık Değişiklik Talepleri',
      value: changeRequestBacklog.length.toString(),
      accent: changeRequestBacklog.length > 0,
    });
  }
  if (options.ledgerDiffs !== undefined) {
    summaryMetrics.push({
      label: 'Ledger Attestasyonları',
      value: ledgerDiffs.length.toString(),
      accent: ledgerDiffs.length > 0,
    });
  }

  const html = renderLayout({
    title: options.title ?? 'SOIPack Uyum ve Kapsam Raporu',
    manifestId: options.manifestId ?? 'N/A',
    generatedAt: options.generatedAt ?? snapshot.generatedAt,
    version: options.version ?? packageInfo.version,
    snapshotId: options.snapshotId ?? snapshot.version.id,
    snapshotVersion: options.snapshotVersion ?? snapshot.version,
    summaryMetrics,
    content,
    subtitle: 'Uyumluluk hedefleri ve yapısal kapsam özetleri',
    git: options.git,
    programName: options.programName,
    certificationLevel: options.certificationLevel,
    projectVersion: options.projectVersion,
  });

  const json = {
    ...buildComplianceMatrixJson(snapshot, options, view),
    coverage,
    coverageWarnings,
    ...(changeRequestBacklog.length > 0 ? { changeRequestBacklog } : {}),
    ...(ledgerDiffs.length > 0 ? { ledgerDiffs } : {}),
  } as ComplianceCoverageReportResult['json'];
  const csv = createComplianceMatrixCsv(view.objectives, view.stageTabs, options);

  return {
    html,
    json,
    csv,
    coverage,
    coverageWarnings,
    changeRequestBacklog: changeRequestBacklog.length > 0 ? changeRequestBacklog : undefined,
    ledgerDiffs: ledgerDiffs.length > 0 ? ledgerDiffs : undefined,
  };
};

export const renderTraceMatrix = (
  trace: RequirementTrace[],
  options: TraceMatrixOptions = {},
): TraceMatrixRenderResult => {
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

  const html = renderLayout({
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
    programName: options.programName,
    certificationLevel: options.certificationLevel,
    projectVersion: options.projectVersion,
  });

  const csv = createTraceMatrixCsv(rows, options);

  return { html, csv };
};

const escapeDotId = (value: string): string => {
  const escaped = value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  return `"${escaped}"`;
};

const escapeDotLabel = (value: string): string => {
  const normalized = value.replace(/\r?\n/g, '\\n');
  return escapeDotId(normalized);
};

const formatDotAttributes = (attributes: Record<string, string | number | undefined>): string =>
  Object.entries(attributes)
    .filter((entry): entry is [string, string | number] => entry[1] !== undefined)
    .map(([key, value]) => `${key}=${typeof value === 'number' ? value : escapeDotLabel(value)}`)
    .join(' ');

const traceClusterMeta: Array<{
  type: TraceGraph['nodes'][number]['type'];
  id: string;
  label: string;
  color: string;
  fill: string;
  shape: string;
}> = [
  {
    type: 'requirement',
    id: 'requirements',
    label: 'Requirements',
    color: '#1d4ed8',
    fill: '#dbeafe',
    shape: 'rect',
  },
  {
    type: 'design',
    id: 'designs',
    label: 'Designs',
    color: '#7c3aed',
    fill: '#ede9fe',
    shape: 'component',
  },
  {
    type: 'code',
    id: 'code',
    label: 'Code',
    color: '#0f766e',
    fill: '#ccfbf1',
    shape: 'folder',
  },
  {
    type: 'test',
    id: 'tests',
    label: 'Tests',
    color: '#dc2626',
    fill: '#fee2e2',
    shape: 'ellipse',
  },
];

const formatTraceNodeLabel = (node: TraceGraph['nodes'][number]): string => {
  if (node.type === 'requirement') {
    return `${node.id}\n${node.data.title}`;
  }
  if (node.type === 'design') {
    return `${node.id}\n${node.data.title}`;
  }
  if (node.type === 'test') {
    return `${node.id}\n${node.data.name ?? node.id}`;
  }
  return node.data.path;
};

export const renderGsnGraphDot = (
  snapshot: ComplianceSnapshot,
  options: GsnGraphOptions = {},
): string => {
  const graphName = options.graphName ?? 'ComplianceGSN';
  const objectiveLookup = new Map(options.objectivesMetadata?.map((item) => [item.id, item]));
  const independenceLookup = new Map(
    snapshot.independenceSummary.objectives.map((entry) => [entry.objectiveId, entry]),
  );
  const objectiveGapDescriptions = new Map<string, Set<string>>();

  const addGapDescription = (objectiveId: string, description: string): void => {
    if (!description) {
      return;
    }
    if (!objectiveGapDescriptions.has(objectiveId)) {
      objectiveGapDescriptions.set(objectiveId, new Set());
    }
    objectiveGapDescriptions.get(objectiveId)!.add(description);
  };

  const formatTimestamp = (value?: string): string | undefined => {
    if (!value) {
      return undefined;
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return value;
    }
    const [isoDate, isoTime] = date.toISOString().split('T');
    return `${isoDate} ${isoTime.slice(0, 5)} UTC`;
  };

  const formatStaleFinding = (finding: StaleEvidenceFinding): string => {
    const labelLines = [`Güncel olmayan ${formatArtifact(finding.artifactType)}`];
    const metaParts: string[] = [];
    const formattedTimestamp = formatTimestamp(finding.latestEvidenceTimestamp);
    if (formattedTimestamp) {
      metaParts.push(formattedTimestamp);
    }
    const reasonLabels = finding.reasons
      .map((reason) =>
        reason === 'beforeSnapshot'
          ? 'Snapshot öncesi'
          : reason === 'exceedsMaxAge'
            ? 'Maksimum yaş aşıldı'
            : reason,
      )
      .filter((reason) => reason.length > 0);
    if (reasonLabels.length > 0) {
      metaParts.push(reasonLabels.join(' • '));
    }
    if (finding.ageDays !== undefined && finding.maxAgeDays !== undefined) {
      metaParts.push(`${finding.ageDays}g>${finding.maxAgeDays}g`);
    } else if (finding.ageDays !== undefined) {
      metaParts.push(`${finding.ageDays}g`);
    }
    if (metaParts.length > 0) {
      labelLines.push(metaParts.join(' • '));
    }
    return labelLines.join('\n');
  };

  (Object.keys(snapshot.gaps) as GapCategoryKey[]).forEach((key) => {
    if (key === 'staleEvidence') {
      snapshot.gaps.staleEvidence.forEach((finding) => {
        addGapDescription(finding.objectiveId, formatStaleFinding(finding));
      });
      return;
    }
    const categoryLabel = gapLabels[key] ?? key;
    const gaps = snapshot.gaps[key] as Array<{
      objectiveId: string;
      missingArtifacts: Array<ObjectiveArtifactType | 'design'>;
    }>;
    gaps.forEach((gap) => {
      gap.missingArtifacts.forEach((artifact) => {
        addGapDescription(gap.objectiveId, `Eksik ${formatArtifact(artifact)} (${categoryLabel})`);
      });
    });
  });

  snapshot.independenceSummary.objectives.forEach((entry) => {
    entry.missingArtifacts.forEach((artifact) => {
      addGapDescription(entry.objectiveId, `Bağımsız ${formatArtifact(artifact)} eksik`);
    });
  });

  const statusFillColors: Record<CoverageStatus, string> = {
    covered: '#dcfce7',
    partial: '#fef3c7',
    missing: '#fee2e2',
  };
  const statusBorderColors: Record<CoverageStatus, string> = {
    covered: '#15803d',
    partial: '#b45309',
    missing: '#b91c1c',
  };

  type ObjectiveNode = {
    id: string;
    objectiveId: string;
    stage?: SoiStage;
    attrs: Record<string, string | number | undefined>;
  };

  const objectiveNodes: ObjectiveNode[] = snapshot.objectives
    .slice()
    .sort((a, b) => a.objectiveId.localeCompare(b.objectiveId))
    .map((objective) => {
      const metadata = objectiveLookup.get(objective.objectiveId);
      const independenceEntry = independenceLookup.get(objective.objectiveId);
      const independenceLevel: Objective['independence'] =
        independenceEntry?.independence ?? metadata?.independence ?? 'none';
      const independenceStatus: CoverageStatus = independenceEntry?.status ?? 'covered';
      const independenceMissing = independenceStatus !== 'covered';
      let borderColor = statusBorderColors[objective.status];
      if (independenceLevel === 'required') {
        borderColor = independenceMissing ? '#b91c1c' : '#0f766e';
      } else if (independenceLevel === 'recommended') {
        borderColor = independenceMissing ? '#b45309' : '#1d4ed8';
      }
      let penwidth = 1.6;
      if (independenceLevel === 'required') {
        penwidth = independenceMissing ? 3 : 2.4;
      } else if (independenceLevel === 'recommended') {
        penwidth = independenceMissing ? 2.4 : 1.8;
      }
      const peripheries = independenceLevel === 'required' ? 2 : 1;
      const stageLabel = metadata?.stage ? stageLabels[metadata.stage] ?? metadata.stage : undefined;
      const statusLabel = statusLabels[objective.status] ?? objective.status;
      const labelLines = [
        metadata?.table ? `${objective.objectiveId} (${metadata.table})` : objective.objectiveId,
      ];
      if (metadata?.name) {
        labelLines.push(metadata.name);
      }
      if (stageLabel) {
        labelLines.push(`SOI: ${stageLabel}`);
      }
      labelLines.push(`Durum: ${statusLabel}`);
      if (independenceLevel !== 'none' || independenceMissing) {
        const independenceLabel = independenceLevelLabels[independenceLevel]?.label ?? independenceLevel;
        const statusMeta = independenceStatusLabels[independenceStatus]?.label ?? independenceStatus;
        const independenceParts = [independenceLabel];
        if (independenceMissing) {
          independenceParts.push(statusMeta);
        }
        labelLines.push(`Bağımsızlık: ${independenceParts.join(' • ')}`);
      }

      const node: ObjectiveNode = {
        id: `goal:${objective.objectiveId}`,
        objectiveId: objective.objectiveId,
        stage: metadata?.stage,
        attrs: {
          label: labelLines.join('\n'),
          shape: 'rect',
          style: 'rounded,filled',
          fillcolor: statusFillColors[objective.status],
          color: borderColor,
          penwidth,
          peripheries,
        },
      };
      return node;
    });

  const objectiveNodeIds = new Map(objectiveNodes.map((node) => [node.objectiveId, node.id]));

  type EvidenceNode = {
    id: string;
    objectiveId: string;
    attrs: Record<string, string | number | undefined>;
  };

  const evidenceNodes: EvidenceNode[] = snapshot.objectives.flatMap((objective) => {
    const uniqueRefs = Array.from(new Set(objective.evidenceRefs)).sort((a, b) => a.localeCompare(b));
    return uniqueRefs.map((ref, index) => {
      const separatorIndex = ref.indexOf(':');
      const artifactType =
        separatorIndex >= 0 ? (ref.slice(0, separatorIndex) as ObjectiveArtifactType) : undefined;
      const artifactLabel = artifactType ? formatArtifact(artifactType) : 'Kanıt';
      const path = separatorIndex >= 0 ? ref.slice(separatorIndex + 1) : ref;
      const node: EvidenceNode = {
        id: `evidence:${objective.objectiveId}:${index}`,
        objectiveId: objective.objectiveId,
        attrs: {
          label: `${artifactLabel}\n${path}`,
          shape: 'note',
          style: 'filled',
          fillcolor: '#e0f2fe',
          color: '#0c4a6e',
        },
      };
      return node;
    });
  });

  type GapNode = {
    id: string;
    objectiveId: string;
    attrs: Record<string, string | number | undefined>;
  };

  const gapNodes: GapNode[] = Array.from(objectiveGapDescriptions.entries()).flatMap(
    ([objectiveId, descriptions]) => {
      const sorted = Array.from(descriptions).sort((a, b) => a.localeCompare(b));
      return sorted.map((description, index) => {
        const node: GapNode = {
          id: `gap:${objectiveId}:${index}`,
          objectiveId,
          attrs: {
            label: description,
            shape: 'diamond',
            style: 'filled',
            fillcolor: '#fee2e2',
            color: '#b91c1c',
            fontcolor: '#7f1d1d',
            penwidth: 1.8,
          },
        };
        return node;
      });
    },
  );

  const renderNodeLine = (
    id: string,
    attrs: Record<string, string | number | undefined>,
    indent = '  ',
  ): string => {
    const attrText = formatDotAttributes(attrs);
    return `${indent}${escapeDotId(id)}${attrText.length > 0 ? ` [${attrText}]` : ''};`;
  };

  const stageGroupMap = new Map<string, { label: string; lines: string[] }>();
  const standaloneObjectiveLines: string[] = [];

  objectiveNodes.forEach((node) => {
    if (node.stage) {
      const stageKey = node.stage;
      if (!stageGroupMap.has(stageKey)) {
        stageGroupMap.set(stageKey, {
          label: stageLabels[stageKey] ?? stageKey,
          lines: [],
        });
      }
      stageGroupMap.get(stageKey)!.lines.push(renderNodeLine(node.id, node.attrs, '    '));
    } else {
      standaloneObjectiveLines.push(renderNodeLine(node.id, node.attrs));
    }
  });

  const stageSections: string[] = [];
  const orderedStages = [
    ...soiStages.filter((stage) => stageGroupMap.has(stage)),
    ...Array.from(stageGroupMap.keys())
      .filter((stage) => !soiStages.includes(stage as SoiStage))
      .sort((a, b) => a.localeCompare(b)),
  ];
  orderedStages.forEach((stage) => {
    const group = stageGroupMap.get(stage);
    if (!group) {
      return;
    }
    stageSections.push(`  subgraph ${escapeDotId(`cluster_${stage}`)} {`);
    stageSections.push(`    label=${escapeDotLabel(group.label)};`);
    stageSections.push('    style="rounded";');
    stageSections.push('    color="#94a3b8";');
    stageSections.push('    fontname="Inter";');
    stageSections.push('    node [fontname="Inter"];');
    group.lines.forEach((line) => stageSections.push(line));
    stageSections.push('  }');
  });

  const evidenceLines = [...evidenceNodes]
    .sort((a, b) =>
      a.objectiveId === b.objectiveId
        ? String(a.attrs.label ?? '').localeCompare(String(b.attrs.label ?? ''))
        : a.objectiveId.localeCompare(b.objectiveId),
    )
    .map((node) => renderNodeLine(node.id, node.attrs));

  const gapLines = [...gapNodes]
    .sort((a, b) =>
      a.objectiveId === b.objectiveId
        ? String(a.attrs.label ?? '').localeCompare(String(b.attrs.label ?? ''))
        : a.objectiveId.localeCompare(b.objectiveId),
    )
    .map((node) => renderNodeLine(node.id, node.attrs));

  interface DotEdge {
    from: string;
    to: string;
    attrs?: Record<string, string | number | undefined>;
  }

  const edges: DotEdge[] = [];

  evidenceNodes.forEach((node) => {
    const target = objectiveNodeIds.get(node.objectiveId);
    if (!target) {
      return;
    }
    edges.push({
      from: node.id,
      to: target,
      attrs: { color: '#0284c7', penwidth: 1.4 },
    });
  });

  gapNodes.forEach((node) => {
    const source = objectiveNodeIds.get(node.objectiveId);
    if (!source) {
      return;
    }
    edges.push({
      from: source,
      to: node.id,
      attrs: { color: '#b91c1c', style: 'dashed', penwidth: 1.4, arrowhead: 'vee' },
    });
  });

  const edgeLines = edges
    .sort((a, b) => {
      const fromDiff = a.from.localeCompare(b.from);
      if (fromDiff !== 0) {
        return fromDiff;
      }
      return a.to.localeCompare(b.to);
    })
    .map((edge) => {
      const attrText = formatDotAttributes(edge.attrs ?? {});
      return `  ${escapeDotId(edge.from)} -> ${escapeDotId(edge.to)}${attrText.length > 0 ? ` [${attrText}]` : ''};`;
    });

  const legendLines: string[] = [];
  if (options.includeLegend !== false) {
    legendLines.push('  subgraph "cluster_legend" {');
    legendLines.push('    label="Lejant";');
    legendLines.push('    style="rounded";');
    legendLines.push('    color="#94a3b8";');
    legendLines.push('    fontname="Inter";');
    legendLines.push('    node [fontname="Inter"];');
    legendLines.push(
      renderNodeLine(
        'legend_goal_covered',
        {
          label: 'Hedef • Tam Karşılandı',
          shape: 'rect',
          style: 'rounded,filled',
          fillcolor: statusFillColors.covered,
          color: '#15803d',
          penwidth: 1.6,
        },
        '    ',
      ),
    );
    legendLines.push(
      renderNodeLine(
        'legend_goal_partial',
        {
          label: 'Hedef • Kısmen Karşılandı',
          shape: 'rect',
          style: 'rounded,filled',
          fillcolor: statusFillColors.partial,
          color: '#b45309',
          penwidth: 1.8,
        },
        '    ',
      ),
    );
    legendLines.push(
      renderNodeLine(
        'legend_goal_missing',
        {
          label: 'Hedef • Eksik',
          shape: 'rect',
          style: 'rounded,filled',
          fillcolor: statusFillColors.missing,
          color: '#b91c1c',
          penwidth: 2,
        },
        '    ',
      ),
    );
    legendLines.push(
      renderNodeLine(
        'legend_goal_required',
        {
          label: 'Zorunlu Bağımsız Hedef',
          shape: 'rect',
          style: 'rounded,filled',
          fillcolor: statusFillColors.covered,
          color: '#0f766e',
          penwidth: 2.4,
          peripheries: 2,
        },
        '    ',
      ),
    );
    legendLines.push(
      renderNodeLine(
        'legend_goal_required_gap',
        {
          label: 'Bağımsızlık Eksikliği',
          shape: 'rect',
          style: 'rounded,filled',
          fillcolor: statusFillColors.partial,
          color: '#b91c1c',
          penwidth: 3,
          peripheries: 2,
        },
        '    ',
      ),
    );
    legendLines.push(
      renderNodeLine(
        'legend_evidence',
        {
          label: 'Kanıt (Solution)',
          shape: 'note',
          style: 'filled',
          fillcolor: '#e0f2fe',
          color: '#0c4a6e',
        },
        '    ',
      ),
    );
    legendLines.push(
      renderNodeLine(
        'legend_gap',
        {
          label: 'Boşluk/Kalıntı',
          shape: 'diamond',
          style: 'filled',
          fillcolor: '#fee2e2',
          color: '#b91c1c',
          penwidth: 1.8,
        },
        '    ',
      ),
    );
    legendLines.push('  }');
  }

  const lines = [
    `digraph ${escapeDotId(graphName)} {`,
    '  rankdir="TB";',
    '  nodesep="0.6";',
    '  ranksep="1.0";',
    '  fontname="Inter";',
    '  node [fontname="Inter"];',
    '  edge [fontname="Inter"];',
  ];

  const appendSection = (section: string[]): void => {
    if (section.length === 0) {
      return;
    }
    if (lines[lines.length - 1] !== '') {
      lines.push('');
    }
    lines.push(...section);
  };

  appendSection(stageSections);
  appendSection(standaloneObjectiveLines);
  appendSection(evidenceLines);
  appendSection(gapLines);
  appendSection(legendLines);
  appendSection(edgeLines);

  if (lines[lines.length - 1] !== '') {
    lines.push('');
  }
  lines.push('}');

  return `${lines.join('\n')}\n`;
};

export const renderTraceGraphDot = (
  graph: TraceGraph,
  options: TraceGraphDotOptions = {},
): string => {
  const graphName = options.graphName ?? 'TraceGraph';
  const nodesByKey = new Map(graph.nodes.map((node) => [node.key, node]));
  const lines: string[] = [];

  lines.push(`digraph ${escapeDotId(graphName)} {`);
  lines.push('  rankdir="LR";');
  lines.push('  splines="spline";');
  lines.push('  fontname="Inter";');
  lines.push('  node [fontname="Inter"];');
  lines.push('  edge [fontname="Inter"];');
  lines.push('');

  traceClusterMeta.forEach((cluster) => {
    const clusterNodes = graph.nodes
      .filter((node) => node.type === cluster.type)
      .sort((a, b) => a.id.localeCompare(b.id));
    if (clusterNodes.length === 0) {
      return;
    }

    lines.push(`  subgraph ${escapeDotId(`cluster_${cluster.id}`)} {`);
    lines.push(`    label=${escapeDotLabel(cluster.label)};`);
    lines.push(`    color=${escapeDotLabel(cluster.color)};`);
    lines.push('    style="rounded";');
    lines.push(
      `    node [shape=${escapeDotLabel(cluster.shape)} style="filled" color=${escapeDotLabel(cluster.color)} fillcolor=${escapeDotLabel(cluster.fill)} fontname="Inter"];`,
    );

    clusterNodes.forEach((node) => {
      lines.push(`    ${escapeDotId(node.key)} [label=${escapeDotLabel(formatTraceNodeLabel(node))}];`);
    });

    lines.push('  }');
    lines.push('');
  });

  const edges: Array<{ from: string; to: string }> = [];
  graph.nodes
    .slice()
    .sort((a, b) => a.key.localeCompare(b.key))
    .forEach((node) => {
      const targets = [...node.links].sort((a, b) => a.localeCompare(b));
      targets.forEach((targetKey) => {
        if (!nodesByKey.has(targetKey)) {
          return;
        }
        edges.push({ from: node.key, to: targetKey });
      });
    });

  edges
    .sort((a, b) => {
      if (a.from === b.from) {
        return a.to.localeCompare(b.to);
      }
      return a.from.localeCompare(b.from);
    })
    .forEach((edge) => {
      lines.push(`  ${escapeDotId(edge.from)} -> ${escapeDotId(edge.to)};`);
    });

  lines.push('}');
  return `${lines.join('\n')}\n`;
};

export const renderGaps = (
  snapshot: ComplianceSnapshot,
  options: GapReportOptions = {},
): string => {
  const objectiveLookup = new Map(options.objectivesMetadata?.map((objective) => [objective.id, objective]));

  const gapKeys = (Object.keys(snapshot.gaps) as GapCategoryKey[]).filter(
    (key): key is Exclude<GapCategoryKey, 'staleEvidence'> => key !== 'staleEvidence',
  );

  const categories = gapKeys.map((key) => {
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

  const summaryMetrics: LayoutSummaryMetric[] = gapKeys.map((key) => ({
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
    programName: options.programName,
    certificationLevel: options.certificationLevel,
    projectVersion: options.projectVersion,
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
export type { ChangeRequestBacklogItem, LedgerAttestationDiffItem } from './complianceReport.html';
