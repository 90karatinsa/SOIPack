import {
  type AnalyzeJobResult,
  type ApiJob,
  type ComplianceMatrixPayload,
  type ImportJobResult,
  type ReportAssetMap,
  type ReportJobResult,
  type RequirementTracePayload,
  type PackJobResult,
} from '../types/pipeline';

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

const readJson = async <T>(response: Response): Promise<T> => {
  await ensureOk(response);
  return (await response.json()) as T;
};

interface ImportOptions {
  token: string;
  license: string;
  files: File[];
  projectName?: string;
  projectVersion?: string;
  level?: string;
  signal?: AbortSignal;
}

const inferImportField = (file: File): string | undefined => {
  const name = file.name.toLowerCase();
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
}: ImportOptions): Promise<ApiJob<ImportJobResult>> => {
  const formData = new FormData();
  let appended = 0;

  files.forEach((file) => {
    const field = inferImportField(file) ?? 'objectives';
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
      traceHtml: extractAssetPath(outputs.traceHtml, job.id),
      gapsHtml: extractAssetPath(outputs.gapsHtml, job.id),
      analysis: extractAssetPath(outputs.analysis, job.id),
      snapshot: extractAssetPath(outputs.snapshot, job.id),
      traces: extractAssetPath(outputs.traces, job.id),
    },
  };
};
