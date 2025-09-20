import {
  type AnalyzeJobResult,
  type ApiJob,
  type ComplianceMatrixPayload,
  type ImportJobResult,
  type ReportAssetMap,
  type ReportJobResult,
  type RequirementTracePayload,
} from '../types/pipeline';

// eslint-disable-next-line @typescript-eslint/no-implied-eval
const getImportMetaEnv = (): Record<string, string> | undefined => {
  try {
    return new Function('return typeof import.meta !== "undefined" ? import.meta.env : undefined;')() as
      | Record<string, string>
      | undefined;
  } catch {
    return undefined;
  }
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

const joinUrl = (path: string): string => {
  if (!API_BASE_URL) {
    return path;
  }
  return `${API_BASE_URL}${path}`;
};

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

const buildAuthHeaders = (token: string): Record<string, string> => ({
  Authorization: `Bearer ${token}`,
  'X-SOIPACK-License': token,
});

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
    headers: buildAuthHeaders(token),
    body: formData,
    signal,
  });

  return readJson<ApiJob<ImportJobResult>>(response);
};

interface AnalyzeOptions {
  token: string;
  importId: string;
  signal?: AbortSignal;
}

export const analyzeArtifacts = async ({
  token,
  importId,
  signal,
}: AnalyzeOptions): Promise<ApiJob<AnalyzeJobResult>> => {
  const response = await fetch(joinUrl('/v1/analyze'), {
    method: 'POST',
    headers: {
      ...buildAuthHeaders(token),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ importId }),
    signal,
  });

  return readJson<ApiJob<AnalyzeJobResult>>(response);
};

interface ReportOptions {
  token: string;
  analysisId: string;
  manifestId?: string;
  signal?: AbortSignal;
}

export const reportArtifacts = async ({
  token,
  analysisId,
  manifestId,
  signal,
}: ReportOptions): Promise<ApiJob<ReportJobResult>> => {
  const response = await fetch(joinUrl('/v1/report'), {
    method: 'POST',
    headers: {
      ...buildAuthHeaders(token),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ analysisId, manifestId }),
    signal,
  });

  return readJson<ApiJob<ReportJobResult>>(response);
};

interface GetJobOptions {
  token: string;
  jobId: string;
  signal?: AbortSignal;
}

export const getJob = async <T>({ token, jobId, signal }: GetJobOptions): Promise<ApiJob<T>> => {
  const response = await fetch(joinUrl(`/v1/jobs/${jobId}`), {
    method: 'GET',
    headers: buildAuthHeaders(token),
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
  jobId: string;
  signal?: AbortSignal;
  initial?: ApiJob<T>;
  onUpdate?: (job: ApiJob<T>) => void;
  pollIntervalMs?: number;
}

export const pollJob = async <T>({
  token,
  jobId,
  signal,
  initial,
  onUpdate,
  pollIntervalMs = 750,
}: PollJobOptions<T>): Promise<ApiJob<T>> => {
  let current = initial ?? (await getJob<T>({ token, jobId, signal }));
  onUpdate?.(current);

  if (current.status === 'completed') {
    return current;
  }
  if (current.status === 'failed') {
    throw new JobFailedError(current);
  }

  while (true) {
    await wait(pollIntervalMs, signal);
    current = await getJob<T>({ token, jobId, signal });
    onUpdate?.(current);

    if (current.status === 'completed') {
      return current;
    }
    if (current.status === 'failed') {
      throw new JobFailedError(current);
    }
  }
};

interface FetchReportDataOptions {
  token: string;
  reportId: string;
  signal?: AbortSignal;
}

export const fetchComplianceMatrix = async ({
  token,
  reportId,
  signal,
}: FetchReportDataOptions): Promise<ComplianceMatrixPayload> => {
  const response = await fetch(joinUrl(`/v1/reports/${reportId}/compliance.json`), {
    method: 'GET',
    headers: buildAuthHeaders(token),
    signal,
  });

  return readJson<ComplianceMatrixPayload>(response);
};

export const fetchRequirementTraces = async ({
  token,
  reportId,
  signal,
}: FetchReportDataOptions): Promise<RequirementTracePayload[]> => {
  const response = await fetch(joinUrl(`/v1/reports/${reportId}/traces.json`), {
    method: 'GET',
    headers: buildAuthHeaders(token),
    signal,
  });

  return readJson<RequirementTracePayload[]>(response);
};

interface FetchAssetOptions extends FetchReportDataOptions {
  asset: string;
}

export const fetchReportAsset = async ({
  token,
  reportId,
  asset,
  signal,
}: FetchAssetOptions): Promise<Response> => {
  const response = await fetch(joinUrl(`/v1/reports/${reportId}/${asset}`), {
    method: 'GET',
    headers: buildAuthHeaders(token),
    signal,
  });

  await ensureOk(response);
  return response;
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
