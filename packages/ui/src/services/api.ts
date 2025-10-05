import {
  type AnalyzeJobResult,
  type ApiJob,
  type ComplianceMatrixPayload,
  type ComplianceStagePayload,
  type ImportJobResult,
  type ReportAssetMap,
  type ReportJobResult,
  type RequirementTracePayload,
  type PackJobResult,
  type StageIdentifier,
  type CoverageStatus,
} from '../types/pipeline';
import { MANUAL_ARTIFACT_TYPES } from '../types/connectors';
import type { ManualArtifactType, ManualArtifactsSelection } from '../types/connectors';

export interface AuditLogEntry {
  id: string;
  tenantId: string;
  actor: string;
  action: string;
  target?: string | null;
  payload?: Record<string, unknown> | null;
  createdAt: string;
}

export interface AuditLogListResponse {
  items: AuditLogEntry[];
  hasMore: boolean;
  nextOffset: number | null;
}

export type ReviewStatus = 'draft' | 'pending' | 'approved' | 'rejected';

export interface ReviewTarget {
  kind: 'analyze' | 'report' | 'pack';
  reference: string | null;
}

export interface ReviewApprover {
  id: string;
  status: 'pending' | 'approved' | 'rejected';
  approvedAt: string | null;
  rejectedAt: string | null;
  note?: string | null;
}

export interface ReviewArtifact {
  id?: string;
  label: string;
  description?: string | null;
  provided?: boolean;
  providedBy?: string | null;
  providedAt?: string | null;
}

export interface ReviewChangeRequest {
  id: string;
  authorId: string;
  reason: string;
  createdAt: string;
}

export interface ReviewResource {
  id: string;
  tenantId: string;
  status: ReviewStatus;
  target: ReviewTarget;
  approvers: ReviewApprover[];
  requiredArtifacts: ReviewArtifact[];
  changeRequests: ReviewChangeRequest[];
  hash: string;
  notes?: string | null;
  reviewer?: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface ReviewListResponse {
  reviews: ReviewResource[];
  hasMore: boolean;
  nextOffset: number | null;
}

export interface WorkspaceRevision<TContent = unknown> {
  id: string;
  number: number;
  hash: string;
  authorId: string;
  createdAt: string;
  content: TContent;
}

export interface WorkspaceDocument<TContent = unknown> {
  id: string;
  tenantId: string;
  workspaceId: string;
  kind: 'requirements' | 'traceLinks' | 'evidence';
  title: string;
  createdAt: string;
  updatedAt: string;
  revision: WorkspaceRevision<TContent>;
}

export interface WorkspaceComment {
  id: string;
  documentId: string;
  revisionId: string;
  tenantId: string;
  workspaceId: string;
  authorId: string;
  body: string;
  createdAt: string;
}

export interface WorkspaceSignoff {
  id: string;
  documentId: string;
  revisionId: string;
  tenantId: string;
  workspaceId: string;
  revisionHash: string;
  status: 'pending' | 'approved' | 'rejected';
  requestedBy: string;
  requestedFor: string;
  createdAt: string;
  updatedAt: string;
  approvedAt?: string | null;
  rejectedAt?: string | null;
}

export interface WorkspaceDocumentThread<TContent = unknown> {
  document: WorkspaceDocument<TContent>;
  comments: WorkspaceComment[];
  signoffs: WorkspaceSignoff[];
  nextCursor: string | null;
}

export interface QueueJobSummary {
  id: string;
  kind: 'import' | 'analyze' | 'report' | 'pack';
  status: 'queued' | 'running' | 'completed' | 'failed';
  hash: string;
  createdAt: string;
  updatedAt: string;
}

export interface QueueMetricsResponse {
  jobs: QueueJobSummary[];
}

export interface ManifestMerkleProofPayload {
  algorithm: 'ledger-merkle-v1';
  merkleRoot: string;
  proof: string;
}

export interface ManifestMerkleSummaryPayload {
  algorithm: 'ledger-merkle-v1';
  root: string;
  manifestDigest: string;
  snapshotId: string;
}

export interface ManifestProofListResponse {
  manifestId: string;
  jobId?: string;
  merkle: ManifestMerkleSummaryPayload | null;
  files: Array<{
    path: string;
    sha256: string;
    proof: ManifestMerkleProofPayload | null;
    verified: boolean;
  }>;
}

export interface ManifestProofResponse {
  manifestId: string;
  jobId?: string;
  path: string;
  sha256: string;
  proof: ManifestMerkleProofPayload;
  merkle: ManifestMerkleSummaryPayload | null;
  verified: boolean;
}

export interface StageRiskSparklinePointPayload {
  timestamp: string;
  regressionRatio: number;
}

export interface StageRiskForecastEntry {
  stage: StageIdentifier;
  probability: number;
  classification: 'nominal' | 'guarded' | 'elevated' | 'critical' | string;
  horizonDays: number;
  credibleInterval: {
    lower: number;
    upper: number;
    confidence: number;
  };
  sparkline: StageRiskSparklinePointPayload[];
  updatedAt?: string;
}

export interface ComplianceCoverageSnapshot {
  statements?: number;
  branches?: number;
  functions?: number;
  lines?: number;
}

export interface ComplianceGapSummary {
  missingIds: string[];
  partialIds: string[];
  openObjectiveCount: number;
}

export interface ComplianceChangeImpactEntry {
  id: string;
  type: 'requirement' | 'test' | 'code' | 'design';
  severity: number;
  state: 'added' | 'removed' | 'modified' | 'impacted';
  reasons: string[];
}

export interface ComplianceIndependenceObjective {
  objectiveId: string;
  status: CoverageStatus;
  independence: 'none' | 'recommended' | 'required';
  missingArtifacts: string[];
}

export interface ComplianceIndependenceSummary {
  totals: {
    covered: number;
    partial: number;
    missing: number;
  };
  objectives: ComplianceIndependenceObjective[];
}

export interface ComplianceSummaryLatest {
  id: string;
  createdAt: string;
  project?: string;
  level?: string;
  generatedAt?: string;
  summary: ComplianceStagePayload['summary'];
  coverage: ComplianceCoverageSnapshot;
  gaps: ComplianceGapSummary;
  changeImpact: ComplianceChangeImpactEntry[];
  independence?: ComplianceIndependenceSummary | null;
}

export interface ComplianceSummaryResponse {
  computedAt: string;
  latest: ComplianceSummaryLatest | null;
}

export interface RemediationArtifactSummary {
  key: string;
  label: string;
  url?: string;
}

export type RemediationGapCategory =
  | 'analysis'
  | 'tests'
  | 'coverage'
  | 'trace'
  | 'reviews'
  | 'plans'
  | 'standards'
  | 'configuration'
  | 'quality'
  | 'issues'
  | 'conformity';

export type RemediationPlanPriority = 'critical' | 'high' | 'medium' | 'low';

export type RemediationPlanIssue =
  | {
      type: 'gap';
      category: RemediationGapCategory;
      missingArtifacts: RemediationArtifactSummary[];
    }
  | {
      type: 'independence';
      independence: 'none' | 'recommended' | 'required';
      missingArtifacts: RemediationArtifactSummary[];
    };

export interface RemediationPlanLink {
  label: string;
  url: string;
}

export interface RemediationPlanAction {
  objectiveId: string;
  objectiveName?: string;
  objectiveUrl?: string;
  stage?: string;
  table?: string;
  priority: RemediationPlanPriority;
  issues: RemediationPlanIssue[];
  links: RemediationPlanLink[];
}

export interface RemediationPlanSummary {
  generatedAt: string | null;
  actions: RemediationPlanAction[];
}

export interface StageRiskForecastResponse {
  generatedAt?: string;
  forecasts: StageRiskForecastEntry[];
}

export interface ChangeRequestAttachment {
  id: string;
  filename: string;
  url?: string;
  size?: number;
  mimeType?: string;
  createdAt?: string;
}

export interface ChangeRequestTransition {
  id: string;
  name: string;
  toStatus: string;
  category?: string;
}

export interface ChangeRequestItem {
  id: string;
  key: string;
  summary: string;
  status: string;
  statusCategory?: string;
  assignee?: string | null;
  updatedAt?: string;
  priority?: string | null;
  issueType?: string | null;
  url: string;
  transitions: ChangeRequestTransition[];
  attachments: ChangeRequestAttachment[];
}

export interface ChangeRequestListResponse {
  items: ChangeRequestItem[];
  fetchedAt: string;
}

type ImportMetaEnv = Record<string, string>;

const IMPORT_META_ENV_OVERRIDE_KEY = '__SOIPACK_IMPORT_META_ENV__';

declare const __VITE_ENV__: ImportMetaEnv | undefined;
const getImportMetaEnv = (): ImportMetaEnv | undefined => {
  const globalObject = globalThis as typeof globalThis & {
    __SOIPACK_IMPORT_META_ENV__?: ImportMetaEnv;
  };
  if (globalObject.__SOIPACK_IMPORT_META_ENV__ && typeof globalObject.__SOIPACK_IMPORT_META_ENV__ === 'object') {
    return globalObject.__SOIPACK_IMPORT_META_ENV__;
  }
  if (typeof __VITE_ENV__ !== 'undefined') {
    return __VITE_ENV__;
  }
  return undefined;
};

const resolveBaseUrl = (): string => {
  let base = '';
  const importMetaEnv = getImportMetaEnv();
  if (importMetaEnv?.VITE_API_BASE_URL) {
    base = importMetaEnv.VITE_API_BASE_URL;
  }

  if (!base && typeof process !== 'undefined' && process.env?.VITE_API_BASE_URL) {
    base = process.env.VITE_API_BASE_URL;
  }

  if (!base) {
    return '';
  }

  return base.endsWith('/') ? base.slice(0, -1) : base;
};

const API_BASE_URL = resolveBaseUrl();

export const getApiBaseUrl = (): string => API_BASE_URL;

export const resolveApiUrl = (path: string): string => {
  if (!API_BASE_URL) {
    return path;
  }
  return `${API_BASE_URL}${path}`;
};

export const __test__ = {
  resolveBaseUrl,
  getConfiguredBaseUrl: (): string => API_BASE_URL,
  importMetaOverrideKey: IMPORT_META_ENV_OVERRIDE_KEY,
  getImportMetaEnv,
};

const joinUrl = (path: string): string => resolveApiUrl(path);

const buildQueryString = (params: Record<string, unknown> | undefined): string => {
  if (!params) {
    return '';
  }
  const searchParams = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null) {
      continue;
    }
    if (Array.isArray(value)) {
      value.forEach((item) => {
        if (item !== undefined && item !== null) {
          searchParams.append(key, String(item));
        }
      });
      continue;
    }
    searchParams.append(key, String(value));
  }
  const query = searchParams.toString();
  return query ? `?${query}` : '';
};

const normalizeRevisionHash = (hash?: string | null): string => (hash ?? '').toLowerCase();

export class ApiError extends Error {
  public readonly status: number;
  public readonly code?: string;
  public readonly details?: unknown;

  constructor(status: number, message: string, code?: string, details?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export class JobFailedError<T = unknown> extends Error {
  constructor(public readonly job: ApiJob<T>) {
    super(job.error?.message ?? 'Sunucu işi başarısız oldu.');
    this.name = 'JobFailedError';
  }
}

export interface AuthCredentials {
  token: string;
  license: string;
}

const sanitizeLicense = (license: string): string => license.replace(/\s+/g, '').trim();

export const buildAuthHeaders = ({ token, license }: AuthCredentials): Record<string, string> => {
  const trimmedToken = token.trim();
  const trimmedLicense = license.trim();

  if (!trimmedToken) {
    throw new Error('Token gereklidir.');
  }
  if (!trimmedLicense) {
    throw new Error('Lisans gereklidir.');
  }

  const sanitizedLicense = sanitizeLicense(trimmedLicense);
  if (!sanitizedLicense) {
    throw new Error('Lisans gereklidir.');
  }

  return {
    Authorization: `Bearer ${trimmedToken}`,
    'X-SOIPACK-License': sanitizedLicense,
  };
};

const parseErrorPayload = async (response: Response): Promise<ApiError> => {
  let message = response.statusText || 'Sunucu hatası oluştu.';
  let code: string | undefined;
  let details: unknown;

  try {
    const payload = (await response.json()) as { error?: { code?: string; message?: string; details?: unknown } };
    if (payload?.error) {
      message = payload.error.message ?? message;
      code = payload.error.code ?? code;
      details = payload.error.details ?? details;
    }
  } catch {
    try {
      const text = await response.text();
      if (text) {
        message = text;
      }
    } catch {
      // ignore
    }
  }

  return new ApiError(response.status, message, code, details);
};

const ensureOk = async (response: Response): Promise<void> => {
  if (!response.ok) {
    throw await parseErrorPayload(response);
  }
};

const sanitizeStageRiskForecastEntry = (
  entry: StageRiskForecastEntry,
): StageRiskForecastEntry => {
  const stage = entry.stage ?? 'unknown';
  const probability = Number.isFinite(entry.probability)
    ? Math.max(0, Math.min(100, entry.probability))
    : 0;
  const classification = entry.classification ?? 'nominal';
  const horizonDays = Number.isFinite(entry.horizonDays)
    ? Math.max(1, Math.round(entry.horizonDays))
    : 30;
  const interval = entry.credibleInterval ?? { lower: 0, upper: 0, confidence: 0 };
  const lower = Number.isFinite(interval.lower) ? Math.max(0, interval.lower) : 0;
  const upper = Number.isFinite(interval.upper) ? Math.min(100, Math.max(interval.upper, lower)) : lower;
  const confidence = Number.isFinite(interval.confidence)
    ? Math.max(0, Math.min(100, interval.confidence))
    : 0;
  const sparkline = Array.isArray(entry.sparkline)
    ? entry.sparkline
        .map((point) => {
          if (!point || typeof point.timestamp !== 'string') {
            return null;
          }
          const ratio = Number.isFinite(point.regressionRatio) ? point.regressionRatio : 0;
          return { timestamp: point.timestamp, regressionRatio: ratio };
        })
        .filter((point): point is StageRiskSparklinePointPayload => point !== null)
    : [];

  return {
    stage,
    probability,
    classification,
    horizonDays,
    credibleInterval: { lower, upper, confidence },
    sparkline,
    updatedAt: entry.updatedAt,
  };
};

const normalizeCoverageStatus = (status: unknown): CoverageStatus => {
  if (status === 'covered' || status === 'partial' || status === 'missing') {
    return status;
  }
  return 'missing';
};

const normalizeIndependenceLevel = (value: unknown): 'none' | 'recommended' | 'required' => {
  if (typeof value !== 'string') {
    return 'none';
  }
  const normalized = value.trim().toLowerCase();
  if (normalized === 'recommended' || normalized === 'required') {
    return normalized;
  }
  return 'none';
};

const toSafeCount = (value: unknown): number => {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return Math.max(0, Math.trunc(value));
  }
  if (typeof value === 'string' && value.trim().length > 0) {
    const parsed = Number.parseInt(value.trim(), 10);
    if (Number.isFinite(parsed)) {
      return Math.max(0, Math.trunc(parsed));
    }
  }
  return 0;
};

const sanitizeStringArray = (value: unknown): string[] => {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .map((entry) => (typeof entry === 'string' ? entry.trim() : ''))
    .filter((entry) => entry.length > 0);
};

const allowedChangeImpactTypes: ReadonlyArray<ComplianceChangeImpactEntry['type']> = [
  'requirement',
  'test',
  'code',
  'design',
];

const allowedChangeImpactStates: ReadonlyArray<ComplianceChangeImpactEntry['state']> = [
  'added',
  'removed',
  'modified',
  'impacted',
];

const sanitizeComplianceChangeImpactEntries = (value: unknown): ComplianceChangeImpactEntry[] => {
  if (!Array.isArray(value)) {
    return [];
  }

  const entries: ComplianceChangeImpactEntry[] = [];

  value.forEach((raw) => {
    if (!raw || typeof raw !== 'object') {
      return;
    }

    const entry = raw as Record<string, unknown>;
    const idRaw = typeof entry.id === 'string' ? entry.id.trim() : '';
    if (!idRaw) {
      return;
    }

    const typeCandidate =
      typeof entry.type === 'string' ? entry.type.trim().toLowerCase() : '';
    if (!allowedChangeImpactTypes.includes(typeCandidate as ComplianceChangeImpactEntry['type'])) {
      return;
    }
    const type = typeCandidate as ComplianceChangeImpactEntry['type'];

    const stateCandidate =
      typeof entry.state === 'string' ? entry.state.trim().toLowerCase() : '';
    if (!allowedChangeImpactStates.includes(stateCandidate as ComplianceChangeImpactEntry['state'])) {
      return;
    }
    const state = stateCandidate as ComplianceChangeImpactEntry['state'];

    const severityNumeric = Number(entry.severity);
    if (!Number.isFinite(severityNumeric)) {
      return;
    }
    const normalizedSeverity = Math.max(0, Math.min(1, severityNumeric));
    const severity = Math.round(normalizedSeverity * 1000) / 1000;

    const reasons = Array.isArray(entry.reasons)
      ? (entry.reasons as unknown[])
          .map((reason) => (typeof reason === 'string' ? reason.trim() : ''))
          .filter((reason): reason is string => reason.length > 0)
      : [];

    entries.push({ id: idRaw, type, state, severity, reasons });
  });

  return entries;
};

const sanitizeComplianceIndependenceSummary = (
  summary: unknown,
): ComplianceIndependenceSummary | null => {
  if (!summary || typeof summary !== 'object') {
    return null;
  }

  const raw = summary as { totals?: Record<string, unknown>; objectives?: unknown };
  const totalsRaw = raw.totals ?? {};
  const totals = {
    covered: toSafeCount(totalsRaw.covered),
    partial: toSafeCount(totalsRaw.partial),
    missing: toSafeCount(totalsRaw.missing),
  };

  const objectivesRaw = Array.isArray(raw.objectives) ? raw.objectives : [];
  const objectives = objectivesRaw
    .map((entry) => {
      if (!entry || typeof entry !== 'object') {
        return null;
      }
      const record = entry as Record<string, unknown>;
      const objectiveIdRaw = record.objectiveId;
      const objectiveId =
        typeof objectiveIdRaw === 'string'
          ? objectiveIdRaw.trim()
          : objectiveIdRaw !== undefined
            ? String(objectiveIdRaw)
            : '';
      if (!objectiveId) {
        return null;
      }

      const status = normalizeCoverageStatus(record.status);
      const independence = normalizeIndependenceLevel(record.independence);
      const missingArtifacts = sanitizeStringArray(record.missingArtifacts);

      return { objectiveId, status, independence, missingArtifacts };
    })
    .filter((entry): entry is ComplianceIndependenceObjective => entry !== null);

  return { totals, objectives };
};

const allowedRemediationGapCategories: RemediationGapCategory[] = [
  'analysis',
  'tests',
  'coverage',
  'trace',
  'reviews',
  'plans',
  'standards',
  'configuration',
  'quality',
  'issues',
  'conformity',
];

const sanitizeRemediationPriority = (value: unknown): RemediationPlanPriority => {
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (
      normalized === 'critical' ||
      normalized === 'high' ||
      normalized === 'medium' ||
      normalized === 'low'
    ) {
      return normalized as RemediationPlanPriority;
    }
  }
  return 'low';
};

const sanitizeRemediationArtifact = (entry: unknown): RemediationArtifactSummary | null => {
  if (!entry) {
    return null;
  }
  if (typeof entry === 'string') {
    const key = entry.trim();
    if (!key) {
      return null;
    }
    return { key, label: key };
  }
  if (typeof entry === 'object') {
    const record = entry as Record<string, unknown>;
    const keySource = record.key ?? record.id ?? record.type ?? record.name;
    const labelSource = record.label ?? record.name ?? record.title ?? record.type ?? record.id;
    const urlSource = record.url ?? record.href ?? record.link;
    const keyCandidate =
      typeof keySource === 'string'
        ? keySource.trim()
        : keySource !== undefined
          ? String(keySource).trim()
          : '';
    const labelCandidate =
      typeof labelSource === 'string'
        ? labelSource.trim()
        : labelSource !== undefined
          ? String(labelSource).trim()
          : '';
    const key = keyCandidate || labelCandidate;
    if (!key) {
      return null;
    }
    const label = labelCandidate || key;
    const url = typeof urlSource === 'string' && urlSource.trim().length > 0 ? urlSource.trim() : undefined;
    return { key, label, ...(url ? { url } : {}) };
  }
  return null;
};

const sanitizeRemediationArtifacts = (value: unknown): RemediationArtifactSummary[] => {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .map((entry) => sanitizeRemediationArtifact(entry))
    .filter((artifact): artifact is RemediationArtifactSummary => artifact !== null)
    .map((artifact) => ({ ...artifact, label: artifact.label || artifact.key }));
};

const sanitizeRemediationIssue = (entry: unknown): RemediationPlanIssue | null => {
  if (!entry || typeof entry !== 'object') {
    return null;
  }
  const record = entry as Record<string, unknown>;
  const typeRaw = record.type;
  if (typeof typeRaw !== 'string') {
    return null;
  }
  const type = typeRaw.trim().toLowerCase();
  if (type === 'gap') {
    const categoryRaw = record.category;
    const categoryCandidate =
      typeof categoryRaw === 'string'
        ? categoryRaw.trim().toLowerCase()
        : categoryRaw !== undefined
          ? String(categoryRaw).trim().toLowerCase()
          : '';
    if (!allowedRemediationGapCategories.includes(categoryCandidate as RemediationGapCategory)) {
      return null;
    }
    const missingArtifacts = sanitizeRemediationArtifacts(record.missingArtifacts);
    return {
      type: 'gap',
      category: categoryCandidate as RemediationGapCategory,
      missingArtifacts,
    };
  }
  if (type === 'independence') {
    const independence = normalizeIndependenceLevel(record.independence);
    const missingArtifacts = sanitizeRemediationArtifacts(record.missingArtifacts);
    return {
      type: 'independence',
      independence,
      missingArtifacts,
    };
  }
  return null;
};

const sanitizeRemediationLink = (entry: unknown): RemediationPlanLink | null => {
  if (!entry) {
    return null;
  }
  if (typeof entry === 'string') {
    const value = entry.trim();
    if (!value) {
      return null;
    }
    return { label: value, url: value };
  }
  if (typeof entry === 'object') {
    const record = entry as Record<string, unknown>;
    const urlSource = record.url ?? record.href ?? record.link;
    const labelSource = record.label ?? record.title ?? record.name ?? record.id;
    const url = typeof urlSource === 'string' ? urlSource.trim() : '';
    const labelCandidate =
      typeof labelSource === 'string'
        ? labelSource.trim()
        : labelSource !== undefined
          ? String(labelSource).trim()
          : '';
    const resolvedUrl = url || labelCandidate;
    if (!resolvedUrl) {
      return null;
    }
    const label = labelCandidate || resolvedUrl;
    return { label, url: resolvedUrl };
  }
  return null;
};

const sanitizeRemediationPlanAction = (entry: unknown): RemediationPlanAction | null => {
  if (!entry || typeof entry !== 'object') {
    return null;
  }
  const record = entry as Record<string, unknown>;
  const objectiveIdRaw = record.objectiveId ?? record.id;
  const objectiveId =
    typeof objectiveIdRaw === 'string'
      ? objectiveIdRaw.trim()
      : objectiveIdRaw !== undefined
        ? String(objectiveIdRaw).trim()
        : '';
  if (!objectiveId) {
    return null;
  }

  const priority = sanitizeRemediationPriority(record.priority);
  const objectiveName =
    typeof record.objectiveName === 'string' && record.objectiveName.trim().length > 0
      ? record.objectiveName.trim()
      : undefined;
  const objectiveUrl =
    typeof record.objectiveUrl === 'string' && record.objectiveUrl.trim().length > 0
      ? record.objectiveUrl.trim()
      : undefined;
  const stage =
    typeof record.stage === 'string' && record.stage.trim().length > 0 ? record.stage.trim() : undefined;
  const table =
    typeof record.table === 'string' && record.table.trim().length > 0 ? record.table.trim() : undefined;

  const issuesRaw = Array.isArray(record.issues) ? record.issues : [];
  const issues = issuesRaw
    .map((issue) => sanitizeRemediationIssue(issue))
    .filter((issue): issue is RemediationPlanIssue => issue !== null);

  const linksRaw = Array.isArray(record.links) ? record.links : [];
  const links = linksRaw
    .map((link) => sanitizeRemediationLink(link))
    .filter((link): link is RemediationPlanLink => link !== null);

  return {
    objectiveId,
    priority,
    issues,
    links,
    ...(objectiveName ? { objectiveName } : {}),
    ...(objectiveUrl ? { objectiveUrl } : {}),
    ...(stage ? { stage } : {}),
    ...(table ? { table } : {}),
  };
};

const sanitizeRemediationPlanSummary = (value: unknown): RemediationPlanSummary => {
  if (!value || typeof value !== 'object') {
    return { generatedAt: null, actions: [] };
  }
  const record = value as Record<string, unknown>;
  const generatedAt =
    typeof record.generatedAt === 'string' && record.generatedAt.trim().length > 0
      ? record.generatedAt.trim()
      : null;
  const actionsRaw = Array.isArray(record.actions) ? record.actions : [];
  const actions = actionsRaw
    .map((entry) => sanitizeRemediationPlanAction(entry))
    .filter((action): action is RemediationPlanAction => action !== null);
  return { generatedAt, actions };
};

const sanitizeChangeRequestAttachment = (entry: unknown): ChangeRequestAttachment | null => {
  if (!entry || typeof entry !== 'object') {
    return null;
  }
  const record = entry as Record<string, unknown>;
  const idRaw = record.id;
  const filenameRaw = record.filename;
  const id =
    typeof idRaw === 'string'
      ? idRaw.trim()
      : idRaw !== undefined
        ? String(idRaw)
        : '';
  const filename = typeof filenameRaw === 'string' ? filenameRaw.trim() : '';
  if (!id || !filename) {
    return null;
  }

  const url = typeof record.url === 'string' && record.url.trim().length > 0 ? record.url.trim() : undefined;
  const size = typeof record.size === 'number' && Number.isFinite(record.size) ? record.size : undefined;
  const mimeType =
    typeof record.mimeType === 'string' && record.mimeType.trim().length > 0 ? record.mimeType.trim() : undefined;
  const createdAt =
    typeof record.createdAt === 'string' && record.createdAt.trim().length > 0
      ? record.createdAt.trim()
      : undefined;

  return {
    id,
    filename,
    ...(url ? { url } : {}),
    ...(size !== undefined ? { size } : {}),
    ...(mimeType ? { mimeType } : {}),
    ...(createdAt ? { createdAt } : {}),
  };
};

const sanitizeChangeRequestTransition = (entry: unknown): ChangeRequestTransition | null => {
  if (!entry || typeof entry !== 'object') {
    return null;
  }
  const record = entry as Record<string, unknown>;
  const idRaw = record.id;
  const nameRaw = record.name;
  const toStatusRaw = record.toStatus ?? record.to_status ?? record.to;
  const id =
    typeof idRaw === 'string'
      ? idRaw.trim()
      : idRaw !== undefined
        ? String(idRaw)
        : '';
  const name = typeof nameRaw === 'string' ? nameRaw.trim() : '';
  const toStatus = typeof toStatusRaw === 'string' ? toStatusRaw.trim() : '';
  if (!id || !name || !toStatus) {
    return null;
  }

  const category =
    typeof record.category === 'string' && record.category.trim().length > 0
      ? record.category.trim()
      : typeof record.statusCategory === 'string' && record.statusCategory.trim().length > 0
        ? record.statusCategory.trim()
        : undefined;

  return { id, name, toStatus, ...(category ? { category } : {}) };
};

const sanitizeChangeRequestItem = (entry: unknown): ChangeRequestItem | null => {
  if (!entry || typeof entry !== 'object') {
    return null;
  }

  const record = entry as Record<string, unknown>;
  const id = typeof record.id === 'string' ? record.id.trim() : '';
  const key = typeof record.key === 'string' ? record.key.trim() : '';
  const summary = typeof record.summary === 'string' ? record.summary.trim() : '';
  const status = typeof record.status === 'string' ? record.status.trim() : '';
  const url = typeof record.url === 'string' ? record.url.trim() : '';
  if (!id || !key || !summary || !status || !url) {
    return null;
  }

  const statusCategory =
    typeof record.statusCategory === 'string' && record.statusCategory.trim().length > 0
      ? record.statusCategory.trim()
      : undefined;

  let assignee: string | null | undefined;
  if (typeof record.assignee === 'string') {
    const trimmed = record.assignee.trim();
    assignee = trimmed.length > 0 ? trimmed : null;
  } else if (record.assignee === null) {
    assignee = null;
  }

  const updatedAt = typeof record.updatedAt === 'string' ? record.updatedAt.trim() : undefined;
  const priority = typeof record.priority === 'string' ? record.priority.trim() : undefined;
  const issueType = typeof record.issueType === 'string' ? record.issueType.trim() : undefined;

  const transitions = Array.isArray(record.transitions)
    ? record.transitions
        .map(sanitizeChangeRequestTransition)
        .filter((transition): transition is ChangeRequestTransition => transition !== null)
    : [];

  const attachments = Array.isArray(record.attachments)
    ? record.attachments
        .map(sanitizeChangeRequestAttachment)
        .filter((attachment): attachment is ChangeRequestAttachment => attachment !== null)
    : [];

  return {
    id,
    key,
    summary,
    status,
    ...(statusCategory ? { statusCategory } : {}),
    ...(assignee !== undefined ? { assignee } : {}),
    ...(updatedAt ? { updatedAt } : {}),
    ...(priority ? { priority } : {}),
    ...(issueType ? { issueType } : {}),
    url,
    transitions,
    attachments,
  };
};

const sanitizeChangeRequestListResponse = (
  payload: ChangeRequestListResponse,
): ChangeRequestListResponse => {
  const fetchedAt = typeof payload.fetchedAt === 'string' ? payload.fetchedAt : new Date().toISOString();
  const items = Array.isArray(payload.items)
    ? payload.items
        .map(sanitizeChangeRequestItem)
        .filter((item): item is ChangeRequestItem => item !== null)
    : [];

  return { fetchedAt, items };
};

const readJson = async <T>(response: Response): Promise<T> => {
  await ensureOk(response);
  return (await response.json()) as T;
};

export interface PolarionConnectorConfig {
  baseUrl: string;
  projectId: string;
  username?: string;
  password?: string;
  token?: string;
  requirementsEndpoint?: string;
  testsEndpoint?: string;
  buildsEndpoint?: string;
}

export interface JenkinsConnectorConfig {
  baseUrl: string;
  job: string;
  build?: string | number;
  username?: string;
  password?: string;
  token?: string;
  buildEndpoint?: string;
  testReportEndpoint?: string;
}

export interface DoorsNextConnectorConfig {
  baseUrl: string;
  projectArea: string;
  pageSize?: number;
  maxPages?: number;
  timeoutMs?: number;
  username?: string;
  password?: string;
  accessToken?: string;
}

export interface JamaConnectorConfig {
  baseUrl: string;
  projectId: string | number;
  token: string;
  pageSize?: number;
  maxPages?: number;
  timeoutMs?: number;
  rateLimitDelaysMs?: number[];
  requirementsEndpoint?: string;
  testCasesEndpoint?: string;
  relationshipsEndpoint?: string;
}

export interface JiraCloudConnectorConfig {
  baseUrl: string;
  projectKey: string;
  email: string;
  token: string;
  requirementsJql?: string;
  testsJql?: string;
  pageSize?: number;
  maxPages?: number;
  timeoutMs?: number;
}

interface ImportOptions {
  token: string;
  license: string;
  files: File[];
  projectName?: string;
  projectVersion?: string;
  level?: string;
  signal?: AbortSignal;
  independentSources?: string[];
  independentArtifacts?: string[];
  manualArtifacts?: ManualArtifactsSelection;
  polarion?: PolarionConnectorConfig;
  jenkins?: JenkinsConnectorConfig;
  doorsNext?: DoorsNextConnectorConfig;
  jama?: JamaConnectorConfig;
  jiraCloud?: JiraCloudConnectorConfig;
}

const isManualArtifactType = (value: string): value is ManualArtifactType =>
  MANUAL_ARTIFACT_TYPES.includes(value as ManualArtifactType);

const createManualArtifactBuckets = (
  manualArtifacts?: ManualArtifactsSelection,
): Map<string, ManualArtifactType[]> => {
  const buckets = new Map<string, ManualArtifactType[]>();
  if (!manualArtifacts) {
    return buckets;
  }
  for (const [typeKey, names] of Object.entries(manualArtifacts)) {
    if (!isManualArtifactType(typeKey) || !Array.isArray(names)) {
      continue;
    }
    names
      .map((name) => (typeof name === 'string' ? name.trim() : ''))
      .filter((name): name is string => name.length > 0)
      .forEach((name) => {
        const normalized = name.toLowerCase();
        const existing = buckets.get(normalized) ?? [];
        if (!existing.includes(typeKey)) {
          existing.push(typeKey);
        }
        buckets.set(normalized, existing);
      });
  }
  return buckets;
};

const takeManualArtifactForFile = (
  fileName: string,
  buckets: Map<string, ManualArtifactType[]>,
): ManualArtifactType | undefined => {
  const normalized = fileName.trim().toLowerCase();
  const existing = buckets.get(normalized);
  if (!existing || existing.length === 0) {
    return undefined;
  }
  const [next, ...rest] = existing;
  if (rest.length > 0) {
    buckets.set(normalized, rest);
  } else {
    buckets.delete(normalized);
  }
  return next;
};

const inferImportField = (file: File): string | undefined => {
  const name = file.name.toLowerCase();
  if (
    (name.endsWith('.json') || name.endsWith('.zip') || name.endsWith('.mldatx')) &&
    (name.includes('simulink') || name.includes('modelcov') || name.includes('model-cov') || name.includes('slcov'))
  ) {
    return 'simulink';
  }
  if (name.includes('polyspace')) {
    return 'polyspace';
  }
  if (name.includes('vectorcast')) {
    return 'vectorcast';
  }
  if (name.includes('ldra')) {
    return 'ldra';
  }
  if ((name.endsWith('.log') || name.endsWith('.txt') || name.endsWith('.csv')) && name.includes('qa')) {
    return 'qaLogs';
  }
  if ((name.endsWith('.csv') || name.endsWith('.xlsx')) && name.includes('defect')) {
    return 'jiraDefects';
  }
  if ((name.endsWith('.csv') || name.endsWith('.xlsx')) && name.includes('design')) {
    return 'designCsv';
  }
  if (name.endsWith('.reqif')) {
    return 'reqif';
  }
  if (name.endsWith('.xml')) {
    if (name.includes('coverage') || name.includes('cobertura')) {
      return 'cobertura';
    }
    if (name.includes('trace') || name.includes('lcov')) {
      return 'lcov';
    }
    return 'junit';
  }
  if (name.endsWith('.info')) {
    return 'lcov';
  }
  if (name.endsWith('.csv') || name.endsWith('.xlsx')) {
    return 'jira';
  }
  if (name.endsWith('.json')) {
    return 'objectives';
  }
  if (name.endsWith('.zip') || name.endsWith('.tar') || name.endsWith('.tgz')) {
    return 'git';
  }
  return undefined;
};

export const importArtifacts = async ({
  token,
  license,
  files,
  projectName = 'SOIPack UI Upload',
  projectVersion,
  level = 'C',
  signal,
  independentSources,
  independentArtifacts,
  manualArtifacts,
  polarion,
  jenkins,
  doorsNext,
  jama,
  jiraCloud,
}: ImportOptions): Promise<ApiJob<ImportJobResult>> => {
  const formData = new FormData();
  let appended = 0;

  const manualArtifactBuckets = createManualArtifactBuckets(manualArtifacts);

  files.forEach((file) => {
    const manualField = takeManualArtifactForFile(file.name, manualArtifactBuckets);
    const field = manualField ?? inferImportField(file) ?? 'objectives';
    formData.append(field, file);
    appended += 1;
  });

  if (appended === 0) {
    throw new Error('Lütfen en az bir veri dosyası seçin.');
  }

  formData.append('projectName', projectName);
  if (projectVersion) {
    formData.append('projectVersion', projectVersion);
  }
  if (level) {
    formData.append('level', level);
  }

  if (independentSources && independentSources.length > 0) {
    formData.append('independentSources', JSON.stringify(independentSources));
  }

  if (independentArtifacts && independentArtifacts.length > 0) {
    formData.append('independentArtifacts', JSON.stringify(independentArtifacts));
  }

  if (polarion) {
    formData.append('polarion', JSON.stringify(polarion));
  }

  if (jenkins) {
    formData.append('jenkins', JSON.stringify(jenkins));
  }

  if (doorsNext) {
    formData.append('doorsNext', JSON.stringify(doorsNext));
  }

  if (jama) {
    formData.append('jama', JSON.stringify(jama));
  }

  if (jiraCloud) {
    formData.append('jiraCloud', JSON.stringify(jiraCloud));
  }

  const response = await fetch(joinUrl('/v1/import'), {
    method: 'POST',
    headers: buildAuthHeaders({ token, license }),
    body: formData,
    signal,
  });

  return readJson<ApiJob<ImportJobResult>>(response);
};

interface AnalyzeOptions {
  token: string;
  license: string;
  importId: string;
  signal?: AbortSignal;
}

export const analyzeArtifacts = async ({
  token,
  license,
  importId,
  signal,
}: AnalyzeOptions): Promise<ApiJob<AnalyzeJobResult>> => {
  const response = await fetch(joinUrl('/v1/analyze'), {
    method: 'POST',
    headers: {
      ...buildAuthHeaders({ token, license }),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ importId }),
    signal,
  });

  return readJson<ApiJob<AnalyzeJobResult>>(response);
};

interface ReportOptions {
  token: string;
  license: string;
  analysisId: string;
  manifestId?: string;
  signal?: AbortSignal;
}

export const reportArtifacts = async ({
  token,
  license,
  analysisId,
  manifestId,
  signal,
}: ReportOptions): Promise<ApiJob<ReportJobResult>> => {
  const response = await fetch(joinUrl('/v1/report'), {
    method: 'POST',
    headers: {
      ...buildAuthHeaders({ token, license }),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ analysisId, manifestId }),
    signal,
  });

  return readJson<ApiJob<ReportJobResult>>(response);
};

interface PackOptions {
  token: string;
  license: string;
  reportId: string;
  packageName?: string;
  signal?: AbortSignal;
}

export const packArtifacts = async ({
  token,
  license,
  reportId,
  packageName,
  signal,
}: PackOptions): Promise<ApiJob<PackJobResult>> => {
  const response = await fetch(joinUrl('/v1/pack'), {
    method: 'POST',
    headers: {
      ...buildAuthHeaders({ token, license }),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ reportId, packageName }),
    signal,
  });

  return readJson<ApiJob<PackJobResult>>(response);
};

interface GetJobOptions {
  token: string;
  license: string;
  jobId: string;
  signal?: AbortSignal;
}

export const getJob = async <T>({ token, license, jobId, signal }: GetJobOptions): Promise<ApiJob<T>> => {
  const response = await fetch(joinUrl(`/v1/jobs/${jobId}`), {
    method: 'GET',
    headers: buildAuthHeaders({ token, license }),
    signal,
  });

  return readJson<ApiJob<T>>(response);
};

const wait = (ms: number, signal?: AbortSignal): Promise<void> =>
  new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new DOMException('Aborted', 'AbortError'));
      return;
    }

    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);

    const onAbort = () => {
      clearTimeout(timer);
      reject(new DOMException('Aborted', 'AbortError'));
    };

    signal?.addEventListener('abort', onAbort, { once: true });
  });

interface PollJobOptions<T> {
  token: string;
  license: string;
  jobId: string;
  signal?: AbortSignal;
  initial?: ApiJob<T>;
  onUpdate?: (job: ApiJob<T>) => void;
  pollIntervalMs?: number;
}

export const pollJob = async <T>({
  token,
  license,
  jobId,
  signal,
  initial,
  onUpdate,
  pollIntervalMs = 750,
}: PollJobOptions<T>): Promise<ApiJob<T>> => {
  let current = initial ?? (await getJob<T>({ token, license, jobId, signal }));
  onUpdate?.(current);

  if (current.status === 'completed') {
    return current;
  }
  if (current.status === 'failed') {
    throw new JobFailedError(current);
  }

  while (current.status === 'queued' || current.status === 'running') {
    await wait(pollIntervalMs, signal);
    current = await getJob<T>({ token, license, jobId, signal });
    onUpdate?.(current);

    if (current.status === 'completed') {
      return current;
    }
    if (current.status === 'failed') {
      throw new JobFailedError(current);
    }
  }

  throw new Error(`Bilinmeyen iş durumu: ${current.status}`);
};

interface FetchReportDataOptions {
  token: string;
  license: string;
  reportId: string;
  signal?: AbortSignal;
}

export const fetchComplianceMatrix = async ({
  token,
  license,
  reportId,
  signal,
}: FetchReportDataOptions): Promise<ComplianceMatrixPayload> => {
  const response = await fetch(joinUrl(`/v1/reports/${reportId}/compliance.json`), {
    method: 'GET',
    headers: buildAuthHeaders({ token, license }),
    signal,
  });

  return readJson<ComplianceMatrixPayload>(response);
};

interface ComplianceSummaryLatestPayload
  extends Omit<ComplianceSummaryLatest, 'independence' | 'changeImpact'> {
  independence?: unknown;
  changeImpact?: unknown;
}

interface ComplianceSummaryResponsePayload {
  computedAt: string;
  latest: ComplianceSummaryLatestPayload | null;
}

interface FetchComplianceSummaryOptions {
  token: string;
  license: string;
  signal?: AbortSignal;
}

export const fetchComplianceSummary = async ({
  token,
  license,
  signal,
}: FetchComplianceSummaryOptions): Promise<ComplianceSummaryResponse> => {
  const response = await fetch(joinUrl('/v1/compliance/summary'), {
    method: 'GET',
    headers: buildAuthHeaders({ token, license }),
    signal,
  });

  const payload = await readJson<ComplianceSummaryResponsePayload>(response);
  if (!payload.latest) {
    return { computedAt: payload.computedAt, latest: null };
  }

  const { changeImpact, independence, ...rest } = payload.latest;
  const normalized: ComplianceSummaryLatest = {
    ...(rest as Omit<ComplianceSummaryLatest, 'independence' | 'changeImpact'>),
    changeImpact: sanitizeComplianceChangeImpactEntries(changeImpact),
    independence: sanitizeComplianceIndependenceSummary(independence),
  };

  return { computedAt: payload.computedAt, latest: normalized };
};

interface FetchRemediationPlanOptions {
  token: string;
  license: string;
  signal?: AbortSignal;
}

export const fetchRemediationPlanSummary = async ({
  token,
  license,
  signal,
}: FetchRemediationPlanOptions): Promise<RemediationPlanSummary> => {
  const response = await fetch(joinUrl('/v1/compliance/remediation-plan'), {
    method: 'GET',
    headers: buildAuthHeaders({ token, license }),
    signal,
  });

  const payload = await readJson<unknown>(response);
  return sanitizeRemediationPlanSummary(payload);
};

interface FetchChangeRequestsOptions {
  token: string;
  license: string;
  projectKey?: string;
  jql?: string;
  signal?: AbortSignal;
}

export const fetchChangeRequests = async ({
  token,
  license,
  projectKey,
  jql,
  signal,
}: FetchChangeRequestsOptions): Promise<ChangeRequestListResponse> => {
  const params = new URLSearchParams();
  const trimmedProject = projectKey?.trim();
  if (trimmedProject) {
    params.set('projectKey', trimmedProject);
  }
  const trimmedJql = jql?.trim();
  if (trimmedJql) {
    params.set('jql', trimmedJql);
  }
  const query = params.toString();
  const response = await fetch(joinUrl(`/v1/change-requests${query ? `?${query}` : ''}`), {
    method: 'GET',
    headers: buildAuthHeaders({ token, license }),
    signal,
  });

  const payload = await readJson<ChangeRequestListResponse>(response);
  return sanitizeChangeRequestListResponse(payload);
};

export const fetchRequirementTraces = async ({
  token,
  license,
  reportId,
  signal,
}: FetchReportDataOptions): Promise<RequirementTracePayload[]> => {
  const response = await fetch(joinUrl(`/v1/reports/${reportId}/traces.json`), {
    method: 'GET',
    headers: buildAuthHeaders({ token, license }),
    signal,
  });

  return readJson<RequirementTracePayload[]>(response);
};

export const fetchReportGsnGraph = async ({
  token,
  license,
  reportId,
  signal,
}: FetchReportDataOptions): Promise<string> => {
  const response = await fetch(joinUrl(`/v1/reports/${reportId}/gsn-graph.dot`), {
    method: 'GET',
    headers: buildAuthHeaders({ token, license }),
    signal,
  });

  await ensureOk(response);
  return response.text();
};

interface FetchAssetOptions extends FetchReportDataOptions {
  asset: string;
}

export const fetchReportAsset = async ({
  token,
  license,
  reportId,
  asset,
  signal,
}: FetchAssetOptions): Promise<Response> => {
  const response = await fetch(joinUrl(`/v1/reports/${reportId}/${asset}`), {
    method: 'GET',
    headers: buildAuthHeaders({ token, license }),
    signal,
  });

  await ensureOk(response);
  return response;
};

interface FetchPackageOptions {
  token: string;
  license: string;
  packageId: string;
  signal?: AbortSignal;
}

export const fetchPackageArchive = async ({
  token,
  license,
  packageId,
  signal,
}: FetchPackageOptions): Promise<Response> => {
  const response = await fetch(joinUrl(`/v1/packages/${packageId}/archive`), {
    method: 'GET',
    headers: buildAuthHeaders({ token, license }),
    signal,
  });

  await ensureOk(response);
  return response;
};

export const fetchPackageManifest = async ({
  token,
  license,
  packageId,
  signal,
}: FetchPackageOptions): Promise<Response> => {
  const response = await fetch(joinUrl(`/v1/packages/${packageId}/manifest`), {
    method: 'GET',
    headers: buildAuthHeaders({ token, license }),
    signal,
  });

  await ensureOk(response);
  return response;
};

interface ListManifestProofsOptions extends AuthCredentials {
  manifestId: string;
  signal?: AbortSignal;
}

export const listManifestProofs = async ({
  token,
  license,
  manifestId,
  signal,
}: ListManifestProofsOptions): Promise<ManifestProofListResponse> => {
  const encodedManifestId = encodeURIComponent(manifestId);
  const response = await fetch(joinUrl(`/v1/manifests/${encodedManifestId}/proofs`), {
    method: 'GET',
    headers: buildAuthHeaders({ token, license }),
    signal,
  });

  return readJson<ManifestProofListResponse>(response);
};

interface GetManifestProofOptions extends AuthCredentials {
  manifestId: string;
  filePath: string;
  signal?: AbortSignal;
}

export const getManifestProof = async ({
  token,
  license,
  manifestId,
  filePath,
  signal,
}: GetManifestProofOptions): Promise<ManifestProofResponse> => {
  const encodedManifestId = encodeURIComponent(manifestId);
  const encodedPath = encodeURIComponent(filePath);
  const response = await fetch(joinUrl(`/v1/manifests/${encodedManifestId}/proofs/${encodedPath}`), {
    method: 'GET',
    headers: buildAuthHeaders({ token, license }),
    signal,
  });

  return readJson<ManifestProofResponse>(response);
};

interface FetchStageRiskForecastOptions extends AuthCredentials {
  signal?: AbortSignal;
}

export const fetchStageRiskForecast = async ({
  token,
  license,
  signal,
}: FetchStageRiskForecastOptions): Promise<StageRiskForecastResponse> => {
  const response = await fetch(joinUrl('/v1/risk/stage-forecast'), {
    method: 'GET',
    headers: buildAuthHeaders({ token, license }),
    signal,
  });

  if (!response.ok) {
    throw await parseErrorPayload(response);
  }

  const payload = (await response.json()) as Partial<StageRiskForecastResponse>;
  const generatedAt = typeof payload.generatedAt === 'string' ? payload.generatedAt : undefined;
  const forecasts = Array.isArray(payload.forecasts)
    ? payload.forecasts
        .map((entry) => sanitizeStageRiskForecastEntry(entry as StageRiskForecastEntry))
        .filter((entry) => typeof entry.stage === 'string')
        .sort((a, b) => String(a.stage).localeCompare(String(b.stage)))
    : [];

  return { generatedAt, forecasts };
};

interface ListAuditLogsOptions extends AuthCredentials {
  tenantId?: string;
  actor?: string;
  action?: string;
  target?: string;
  since?: string;
  until?: string;
  order?: 'asc' | 'desc';
  limit?: number;
  offset?: number;
  signal?: AbortSignal;
}

export const listAuditLogs = async ({
  token,
  license,
  signal,
  ...query
}: ListAuditLogsOptions): Promise<AuditLogListResponse> => {
  const response = await fetch(joinUrl(`/api/audit-logs${buildQueryString(query)}`), {
    method: 'GET',
    headers: buildAuthHeaders({ token, license }),
    signal,
  });

  return readJson<AuditLogListResponse>(response);
};

interface CreateReviewOptions extends AuthCredentials {
  target: ReviewTarget;
  approvers?: string[];
  requiredArtifacts?: Array<{ id?: string; label: string; description?: string | null }>;
  notes?: string | null;
  signal?: AbortSignal;
}

export const createReview = async ({
  token,
  license,
  signal,
  ...body
}: CreateReviewOptions): Promise<{ review: ReviewResource }> => {
  const response = await fetch(joinUrl('/v1/reviews'), {
    method: 'POST',
    headers: {
      ...buildAuthHeaders({ token, license }),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
    signal,
  });

  return readJson<{ review: ReviewResource }>(response);
};

interface UpdateReviewOptions extends AuthCredentials {
  id: string;
  action: 'configure' | 'submit' | 'approve' | 'reject';
  expectedHash: string;
  target?: ReviewTarget;
  approvers?: string[];
  requiredArtifacts?: Array<{ id?: string; label: string; description?: string | null }>;
  notes?: string | null;
  note?: string | null;
  reason?: string | null;
  signal?: AbortSignal;
}

export const updateReview = async ({
  token,
  license,
  id,
  signal,
  ...body
}: UpdateReviewOptions): Promise<{ review: ReviewResource }> => {
  const response = await fetch(joinUrl(`/v1/reviews/${id}`), {
    method: 'PATCH',
    headers: {
      ...buildAuthHeaders({ token, license }),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
    signal,
  });

  return readJson<{ review: ReviewResource }>(response);
};

interface ListReviewsOptions extends AuthCredentials {
  status?: ReviewStatus | ReviewStatus[];
  reviewer?: string;
  limit?: number;
  offset?: number;
  signal?: AbortSignal;
}

export const listReviews = async ({
  token,
  license,
  signal,
  ...query
}: ListReviewsOptions): Promise<ReviewListResponse> => {
  const response = await fetch(joinUrl(`/v1/reviews${buildQueryString(query)}`), {
    method: 'GET',
    headers: buildAuthHeaders({ token, license }),
    signal,
  });

  return readJson<ReviewListResponse>(response);
};

interface GetWorkspaceDocumentThreadOptions extends AuthCredentials {
  workspaceId: string;
  documentId: string;
  cursor?: string | null;
  limit?: number;
  signal?: AbortSignal;
}

export const getWorkspaceDocumentThread = async <TContent = unknown>({
  token,
  license,
  workspaceId,
  documentId,
  cursor,
  limit,
  signal,
}: GetWorkspaceDocumentThreadOptions): Promise<WorkspaceDocumentThread<TContent>> => {
  const response = await fetch(
    joinUrl(
      `/v1/workspaces/${workspaceId}/documents/${documentId}${buildQueryString({
        cursor: cursor ?? undefined,
        limit,
      })}`,
    ),
    {
      method: 'GET',
      headers: buildAuthHeaders({ token, license }),
      signal,
    },
  );

  const payload = await readJson<WorkspaceDocumentThread<TContent>>(response);
  const normalizedDocument: WorkspaceDocument<TContent> = {
    ...payload.document,
    revision: {
      ...payload.document.revision,
      hash: normalizeRevisionHash(payload.document.revision?.hash),
    },
  };
  const normalizedSignoffs = payload.signoffs.map((signoff) => ({
    ...signoff,
    revisionHash: normalizeRevisionHash(signoff.revisionHash),
  }));

  return {
    ...payload,
    document: normalizedDocument,
    signoffs: normalizedSignoffs,
  };
};

interface WorkspaceDocumentPayload<TContent = unknown> extends AuthCredentials {
  workspaceId: string;
  documentId: string;
  expectedHash: string;
  content: TContent;
  title?: string;
  signal?: AbortSignal;
}

export const updateWorkspaceDocument = async <TContent>({
  token,
  license,
  workspaceId,
  documentId,
  signal,
  ...body
}: WorkspaceDocumentPayload<TContent>): Promise<{ document: WorkspaceDocument<TContent> }> => {
  const response = await fetch(joinUrl(`/v1/workspaces/${workspaceId}/documents/${documentId}`), {
    method: 'PUT',
    headers: {
      ...buildAuthHeaders({ token, license }),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
    signal,
  });

  return readJson<{ document: WorkspaceDocument<TContent> }>(response);
};

interface CreateWorkspaceCommentOptions extends AuthCredentials {
  workspaceId: string;
  documentId: string;
  revisionId: string;
  body: string;
  signal?: AbortSignal;
}

export const createWorkspaceComment = async ({
  token,
  license,
  workspaceId,
  documentId,
  signal,
  ...body
}: CreateWorkspaceCommentOptions): Promise<{ comment: WorkspaceComment }> => {
  const response = await fetch(
    joinUrl(`/v1/workspaces/${workspaceId}/documents/${documentId}/comments`),
    {
      method: 'POST',
      headers: {
        ...buildAuthHeaders({ token, license }),
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
      signal,
    },
  );

  return readJson<{ comment: WorkspaceComment }>(response);
};

interface RequestWorkspaceSignoffOptions extends AuthCredentials {
  workspaceId: string;
  documentId: string;
  revisionId: string;
  requestedFor: string;
  signal?: AbortSignal;
}

export const requestWorkspaceSignoff = async ({
  token,
  license,
  workspaceId,
  signal,
  ...body
}: RequestWorkspaceSignoffOptions): Promise<{ signoff: WorkspaceSignoff }> => {
  const response = await fetch(joinUrl(`/v1/workspaces/${workspaceId}/signoffs`), {
    method: 'POST',
    headers: {
      ...buildAuthHeaders({ token, license }),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
    signal,
  });

  return readJson<{ signoff: WorkspaceSignoff }>(response);
};

interface ApproveWorkspaceSignoffOptions extends AuthCredentials {
  workspaceId: string;
  signoffId: string;
  signature: string;
  timestamp: string;
  signal?: AbortSignal;
}

export const approveWorkspaceSignoff = async ({
  token,
  license,
  workspaceId,
  signoffId,
  signal,
  ...body
}: ApproveWorkspaceSignoffOptions): Promise<{ signoff: WorkspaceSignoff }> => {
  const response = await fetch(joinUrl(`/v1/workspaces/${workspaceId}/signoffs/${signoffId}`), {
    method: 'PATCH',
    headers: {
      ...buildAuthHeaders({ token, license }),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
    signal,
  });

  return readJson<{ signoff: WorkspaceSignoff }>(response);
};

interface ListJobsOptions extends AuthCredentials {
  status?: Array<'queued' | 'running' | 'completed' | 'failed'> | 'queued' | 'running' | 'completed' | 'failed';
  kind?: Array<'import' | 'analyze' | 'report' | 'pack'> | 'import' | 'analyze' | 'report' | 'pack';
  limit?: number;
  offset?: number;
  signal?: AbortSignal;
}

export const listJobs = async ({
  token,
  license,
  signal,
  ...query
}: ListJobsOptions): Promise<QueueMetricsResponse> => {
  const response = await fetch(joinUrl(`/v1/jobs${buildQueryString(query)}`), {
    method: 'GET',
    headers: buildAuthHeaders({ token, license }),
    signal,
  });

  return readJson<QueueMetricsResponse>(response);
};

export interface AdminRole {
  name: string;
  description?: string | null;
  permissions: string[];
}

export interface AdminUser {
  id: string;
  email: string;
  roles: string[];
  displayName?: string | null;
  status?: 'active' | 'invited' | 'suspended';
  lastLoginAt?: string | null;
  createdAt?: string;
  updatedAt?: string;
}

interface AdminUserRequest {
  email: string;
  roles: string[];
  displayName?: string | null;
  password?: string | null;
  rotateSecret?: boolean;
}

interface AdminApiKeyPayload {
  name: string;
  scopes: string[];
  expiresAt?: string | null;
}

interface AdminAuthOptions extends AuthCredentials {
  signal?: AbortSignal;
}

export const listAdminRoles = async ({
  token,
  license,
  signal,
}: AdminAuthOptions): Promise<{ roles: AdminRole[] }> => {
  const response = await fetch(joinUrl('/v1/admin/roles'), {
    method: 'GET',
    headers: buildAuthHeaders({ token, license }),
    signal,
  });

  return readJson<{ roles: AdminRole[] }>(response);
};

export const createAdminRole = async ({
  token,
  license,
  signal,
  ...body
}: AdminAuthOptions & AdminRole): Promise<{ role: AdminRole }> => {
  const response = await fetch(joinUrl('/v1/admin/roles'), {
    method: 'POST',
    headers: {
      ...buildAuthHeaders({ token, license }),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
    signal,
  });

  return readJson<{ role: AdminRole }>(response);
};

export const updateAdminRole = async ({
  token,
  license,
  signal,
  ...body
}: AdminAuthOptions & AdminRole & { roleId: string }): Promise<{ role: AdminRole }> => {
  const { roleId, ...payload } = body;
  const response = await fetch(joinUrl(`/v1/admin/roles/${roleId}`), {
    method: 'PUT',
    headers: {
      ...buildAuthHeaders({ token, license }),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
    signal,
  });

  return readJson<{ role: AdminRole }>(response);
};

export const deleteAdminRole = async ({
  token,
  license,
  signal,
  roleId,
}: AdminAuthOptions & { roleId: string }): Promise<void> => {
  const response = await fetch(joinUrl(`/v1/admin/roles/${roleId}`), {
    method: 'DELETE',
    headers: buildAuthHeaders({ token, license }),
    signal,
  });

  await ensureOk(response);
};

export const listAdminUsers = async ({
  token,
  license,
  signal,
}: AdminAuthOptions): Promise<{ users: AdminUser[] }> => {
  const response = await fetch(joinUrl('/v1/admin/users'), {
    method: 'GET',
    headers: buildAuthHeaders({ token, license }),
    signal,
  });

  return readJson<{ users: AdminUser[] }>(response);
};

export const createAdminUser = async ({
  token,
  license,
  signal,
  ...body
}: AdminAuthOptions & AdminUserRequest): Promise<{ user: AdminUser; secret?: string }> => {
  const response = await fetch(joinUrl('/v1/admin/users'), {
    method: 'POST',
    headers: {
      ...buildAuthHeaders({ token, license }),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
    signal,
  });

  return readJson<{ user: AdminUser; secret?: string }>(response);
};

export const updateAdminUser = async ({
  token,
  license,
  signal,
  ...body
}: AdminAuthOptions & AdminUserRequest & { userId: string }): Promise<{ user: AdminUser; secret?: string }> => {
  const { userId, ...payload } = body;
  const response = await fetch(joinUrl(`/v1/admin/users/${userId}`), {
    method: 'PUT',
    headers: {
      ...buildAuthHeaders({ token, license }),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
    signal,
  });

  return readJson<{ user: AdminUser; secret?: string }>(response);
};

export const deleteAdminUser = async ({
  token,
  license,
  signal,
  userId,
}: AdminAuthOptions & { userId: string }): Promise<void> => {
  const response = await fetch(joinUrl(`/v1/admin/users/${userId}`), {
    method: 'DELETE',
    headers: buildAuthHeaders({ token, license }),
    signal,
  });

  await ensureOk(response);
};

export const listAdminApiKeys = async ({
  token,
  license,
  signal,
}: AdminAuthOptions): Promise<{ apiKeys: AdminApiKeyPayload[] }> => {
  const response = await fetch(joinUrl('/v1/admin/api-keys'), {
    method: 'GET',
    headers: buildAuthHeaders({ token, license }),
    signal,
  });

  return readJson<{ apiKeys: AdminApiKeyPayload[] }>(response);
};

export const createAdminApiKey = async ({
  token,
  license,
  signal,
  ...body
}: AdminAuthOptions & AdminApiKeyPayload): Promise<{ apiKey: AdminApiKeyPayload; secret?: string }> => {
  const response = await fetch(joinUrl('/v1/admin/api-keys'), {
    method: 'POST',
    headers: {
      ...buildAuthHeaders({ token, license }),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
    signal,
  });

  return readJson<{ apiKey: AdminApiKeyPayload; secret?: string }>(response);
};

export const getAdminApiKey = async ({
  token,
  license,
  signal,
  keyId,
}: AdminAuthOptions & { keyId: string }): Promise<{ apiKey: AdminApiKeyPayload }> => {
  const response = await fetch(joinUrl(`/v1/admin/api-keys/${keyId}`), {
    method: 'GET',
    headers: buildAuthHeaders({ token, license }),
    signal,
  });

  return readJson<{ apiKey: AdminApiKeyPayload }>(response);
};

export const rotateAdminApiKey = async ({
  token,
  license,
  signal,
  keyId,
  ...body
}: AdminAuthOptions & AdminApiKeyPayload & { keyId: string }): Promise<{ apiKey: AdminApiKeyPayload; secret?: string }> => {
  const response = await fetch(joinUrl(`/v1/admin/api-keys/${keyId}`), {
    method: 'PUT',
    headers: {
      ...buildAuthHeaders({ token, license }),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
    signal,
  });

  return readJson<{ apiKey: AdminApiKeyPayload; secret?: string }>(response);
};

export const deleteAdminApiKey = async ({
  token,
  license,
  signal,
  keyId,
}: AdminAuthOptions & { keyId: string }): Promise<void> => {
  const response = await fetch(joinUrl(`/v1/admin/api-keys/${keyId}`), {
    method: 'DELETE',
    headers: buildAuthHeaders({ token, license }),
    signal,
  });

  await ensureOk(response);
};

const extractAssetPath = (fullPath: string, reportId: string): string => {
  const normalized = fullPath.replace(/\\/g, '/');
  const marker = `/${reportId}/`;
  const index = normalized.lastIndexOf(marker);
  if (index !== -1) {
    return normalized.slice(index + marker.length);
  }
  const fallbackIndex = normalized.indexOf(reportId);
  if (fallbackIndex !== -1) {
    const sliceIndex = fallbackIndex + reportId.length + 1;
    return normalized.slice(sliceIndex);
  }
  const segments = normalized.split('/');
  return segments[segments.length - 1] ?? normalized;
};

export const buildReportAssets = (job: ApiJob<ReportJobResult>): ReportAssetMap => {
  const outputs = job.result?.outputs;
  if (!outputs) {
    throw new Error('Rapor çıktıları henüz hazır değil.');
  }

  return {
    reportId: job.id,
    assets: {
      complianceHtml: extractAssetPath(outputs.complianceHtml, job.id),
      complianceJson: extractAssetPath(outputs.complianceJson, job.id),
      complianceCsv: extractAssetPath(outputs.complianceCsv, job.id),
      traceCsv: extractAssetPath(outputs.traceCsv, job.id),
      traceHtml: extractAssetPath(outputs.traceHtml, job.id),
      gapsHtml: extractAssetPath(outputs.gapsHtml, job.id),
      analysis: extractAssetPath(outputs.analysis, job.id),
      snapshot: extractAssetPath(outputs.snapshot, job.id),
      traces: extractAssetPath(outputs.traces, job.id),
      ...(outputs.toolQualification
        ? {
            toolQualificationPlan: extractAssetPath(outputs.toolQualification.tqp, job.id),
            toolQualificationReport: extractAssetPath(outputs.toolQualification.tar, job.id),
          }
        : {}),
      ...(outputs.gsnGraphDot
        ? {
            gsnGraphDot: outputs.gsnGraphDot.href
              ? outputs.gsnGraphDot.href
              : extractAssetPath(outputs.gsnGraphDot.path, job.id),
          }
        : {}),
    },
  };
};
