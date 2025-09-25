import http, { type IncomingHttpHeaders } from 'http';
import https from 'https';
import { setTimeout as delay } from 'timers/promises';

import { ParseResult, RemoteBuildRecord, RemoteTestRecord } from './types';
import { HttpError } from './utils/http';

export interface JenkinsClientOptions {
  baseUrl: string;
  job: string;
  build?: string | number;
  username?: string;
  password?: string;
  token?: string;
  buildEndpoint?: string;
  testReportEndpoint?: string;
  timeoutMs?: number;
  crumbIssuerEndpoint?: string;
  maxReportBytes?: number;
}

export interface JenkinsArtifactBundle {
  tests: RemoteTestRecord[];
  builds: RemoteBuildRecord[];
}

const defaultBuildEndpoint = '/:jobPath/:build/api/json';
const defaultTestEndpoint = '/:jobPath/:build/testReport/api/json';

const MAX_RETRIES = 3;
const BASE_RETRY_DELAY_MS = 250;
const DEFAULT_REPORT_LIMIT_BYTES = 5 * 1024 * 1024;
const RETRYABLE_STATUSES = new Set([429, 503]);

class ResponseSizeLimitError extends Error {
  constructor(public readonly limit: number) {
    super(`Response exceeded the maximum allowed size of ${limit} bytes.`);
    this.name = 'ResponseSizeLimitError';
  }
}

interface JenkinsCrumb {
  header: string;
  value: string;
}

interface JenkinsSession {
  crumb?: JenkinsCrumb | null;
}

const encodeSegment = (segment: string | number): string => encodeURIComponent(String(segment));

const buildJobPath = (job: string): string => {
  const segments = job
    .split('/')
    .map((segment) => segment.trim())
    .filter((segment) => segment.length > 0);

  if (segments.length === 0) {
    return `job/${encodeSegment(job)}`;
  }

  return segments.map((segment) => `job/${encodeSegment(segment)}`).join('/');
};

const applyTemplate = (template: string, options: JenkinsClientOptions): string => {
  const buildId = options.build ?? 'lastCompletedBuild';
  const jobPath = buildJobPath(options.job);
  return template
    .replace(/:jobPath/gu, jobPath)
    .replace(/:job/gu, encodeSegment(options.job))
    .replace(/:build/gu, encodeSegment(buildId));
};

const resolveUrl = (options: JenkinsClientOptions, template?: string): URL => {
  const resolved = applyTemplate(template ?? defaultBuildEndpoint, options);
  return new URL(resolved, options.baseUrl);
};

const buildAuthHeader = (options: JenkinsClientOptions): string | undefined => {
  if (options.token) {
    if (options.username) {
      const credentials = Buffer.from(`${options.username}:${options.token}`).toString('base64');
      return `Basic ${credentials}`;
    }
    return `Bearer ${options.token}`;
  }

  if (options.username && options.password) {
    const credentials = Buffer.from(`${options.username}:${options.password}`).toString('base64');
    return `Basic ${credentials}`;
  }

  return undefined;
};

const getHeaderValue = (headers: IncomingHttpHeaders | undefined, key: string): string | undefined => {
  if (!headers) {
    return undefined;
  }

  const value = headers[key];
  if (Array.isArray(value)) {
    return value[0];
  }
  if (typeof value === 'string') {
    return value;
  }
  return undefined;
};

const parseRetryAfter = (headers: IncomingHttpHeaders | undefined): number | undefined => {
  const raw = getHeaderValue(headers, 'retry-after');
  if (!raw) {
    return undefined;
  }

  const numeric = Number(raw);
  if (Number.isFinite(numeric)) {
    return Math.max(0, numeric * 1000);
  }

  const parsedDate = Date.parse(raw);
  if (!Number.isNaN(parsedDate)) {
    return Math.max(0, parsedDate - Date.now());
  }

  return undefined;
};

const computeRetryDelay = (attempt: number, headers: IncomingHttpHeaders | undefined): number => {
  const headerDelay = parseRetryAfter(headers);
  if (typeof headerDelay === 'number') {
    return headerDelay;
  }
  return BASE_RETRY_DELAY_MS * 2 ** attempt;
};

interface JsonRequestOptions {
  url: URL;
  headers: Record<string, string>;
  timeoutMs?: number;
  maxBytes?: number;
}

const requestJsonWithLimit = async <T>(
  options: JsonRequestOptions,
): Promise<{ payload: T; headers: IncomingHttpHeaders }> =>
  await new Promise((resolve, reject) => {
      const client = options.url.protocol === 'https:' ? https : http;
      const request = client.request(
        options.url,
        {
          method: 'GET',
          headers: { Accept: 'application/json', ...options.headers },
          timeout: options.timeoutMs ?? 15000,
        },
        (response) => {
          const { statusCode = 0, statusMessage = '' } = response;
          const chunks: Buffer[] = [];
          let totalBytes = 0;
          const maxBytes = options.maxBytes ?? 0;

          response.on('data', (chunk) => {
            const buffer = typeof chunk === 'string' ? Buffer.from(chunk) : chunk;
            totalBytes += buffer.length;
            if (maxBytes > 0 && totalBytes > maxBytes) {
              response.destroy(new ResponseSizeLimitError(maxBytes));
              return;
            }
            chunks.push(buffer);
          });

          response.on('error', (error) => {
            reject(error);
          });

          response.on('end', () => {
            const payload = Buffer.concat(chunks).toString('utf8');

            if (statusCode < 200 || statusCode >= 300) {
              reject(new HttpError(statusCode, statusMessage, payload || undefined, response.headers));
              return;
            }

            if (!payload) {
              resolve({ payload: {} as T, headers: response.headers });
              return;
            }

            try {
              const parsed = JSON.parse(payload) as T;
              resolve({ payload: parsed, headers: response.headers });
            } catch (error) {
              reject(
                new Error(
                  `Unable to parse JSON response from ${options.url.toString()}: ${(error as Error).message}`,
                ),
              );
            }
          });
        },
      );

      request.on('error', (error) => {
        reject(error);
      });

      request.end();
    });

interface JenkinsCrumbResponse {
  crumbRequestField?: string;
  crumb?: string;
}

const fetchCrumb = async (
  options: JenkinsClientOptions,
  warnings: string[],
): Promise<JenkinsCrumb | undefined> => {
  const endpoint = options.crumbIssuerEndpoint ?? '/crumbIssuer/api/json';
  const url = new URL(endpoint, options.baseUrl);
  const headers: Record<string, string> = {};
  const authHeader = buildAuthHeader(options);
  if (authHeader) {
    headers.Authorization = authHeader;
  }

  try {
    const { payload } = await requestJsonWithLimit<JenkinsCrumbResponse>({
      url,
      headers,
      timeoutMs: options.timeoutMs,
      maxBytes: 4096,
    });

    if (typeof payload.crumbRequestField !== 'string' || typeof payload.crumb !== 'string') {
      warnings.push('Jenkins crumbIssuer response was invalid; crumb fields were missing.');
      return undefined;
    }

    return { header: payload.crumbRequestField, value: payload.crumb };
  } catch (error) {
    if (error instanceof HttpError && error.statusCode === 404) {
      return undefined;
    }
    warnings.push(`Jenkins crumbIssuer request failed: ${(error as Error).message}`);
    return undefined;
  }
};

const ensureCrumb = async (
  session: JenkinsSession,
  options: JenkinsClientOptions,
  warnings: string[],
  force = false,
): Promise<JenkinsCrumb | undefined> => {
  if (!force && session.crumb !== undefined) {
    return session.crumb ?? undefined;
  }

  const crumb = await fetchCrumb(options, warnings);
  session.crumb = crumb ?? null;
  return crumb;
};

const requestWithRetries = async <T>(
  requestOptions: JsonRequestOptions,
  warnings: string[],
): Promise<{ payload: T; headers: IncomingHttpHeaders }> => {
  let attempt = 0;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    try {
      return await requestJsonWithLimit<T>(requestOptions);
    } catch (error) {
      if (error instanceof HttpError && RETRYABLE_STATUSES.has(error.statusCode) && attempt < MAX_RETRIES) {
        const delayMs = computeRetryDelay(attempt, error.headers);
        warnings.push(
          `Jenkins API returned ${error.statusCode}; retrying in ${delayMs}ms (attempt ${
            attempt + 1
          }/${MAX_RETRIES}).`,
        );
        attempt += 1;
        await delay(delayMs);
        continue;
      }
      throw error;
    }
  }
};

const performJenkinsRequest = async <T>(
  url: URL,
  session: JenkinsSession,
  options: JenkinsClientOptions,
  warnings: string[],
  requestOptions: { maxBytes?: number } = {},
): Promise<T> => {
  let crumbRefreshed = false;

  while (true) {
    const headers: Record<string, string> = {};
    const authHeader = buildAuthHeader(options);
    if (authHeader) {
      headers.Authorization = authHeader;
    }

    const crumb = await ensureCrumb(session, options, warnings);
    if (crumb) {
      headers[crumb.header] = crumb.value;
    }

    try {
      const { payload } = await requestWithRetries<T>(
        {
          url,
          headers,
          timeoutMs: options.timeoutMs,
          maxBytes: requestOptions.maxBytes,
        },
        warnings,
      );
      return payload;
    } catch (error) {
      if (error instanceof HttpError && error.statusCode === 403 && !crumbRefreshed) {
        session.crumb = undefined;
        const refreshed = await ensureCrumb(session, options, warnings, true);
        if (refreshed) {
          warnings.push('Jenkins crumb refreshed; retrying request.');
        } else {
          warnings.push('Jenkins crumb refresh failed; proceeding without crumb.');
        }
        crumbRefreshed = true;
        continue;
      }
      throw error;
    }
  }
};

interface JenkinsBuildAction {
  lastBuiltRevision?: {
    SHA1?: string;
    branch?: Array<{ name: string }>;
  };
  parameters?: Array<{ name: string; value?: string }>;
}

interface JenkinsBuildResponse {
  id?: string;
  number?: number;
  url?: string;
  result?: string;
  timestamp?: number;
  duration?: number;
  fullDisplayName?: string;
  displayName?: string;
  actions?: JenkinsBuildAction[];
}

interface JenkinsTestCase {
  className?: string;
  name?: string;
  status?: string;
  duration?: number;
  errorDetails?: string;
  errorStackTrace?: string;
}

interface JenkinsTestSuite {
  name?: string;
  duration?: number;
  cases?: JenkinsTestCase[];
}

interface JenkinsTestReportResponse {
  suites?: JenkinsTestSuite[];
}

const extractBuildMetadata = (payload: JenkinsBuildResponse, options: JenkinsClientOptions): RemoteBuildRecord => {
  const startedAt = typeof payload.timestamp === 'number' ? new Date(payload.timestamp).toISOString() : undefined;
  const completedAt =
    typeof payload.timestamp === 'number' && typeof payload.duration === 'number'
      ? new Date(payload.timestamp + payload.duration).toISOString()
      : undefined;

  let revision: string | undefined;
  let branch: string | undefined;

  for (const action of payload.actions ?? []) {
    if (action.lastBuiltRevision?.SHA1 && !revision) {
      revision = action.lastBuiltRevision.SHA1;
    }
    if (action.lastBuiltRevision?.branch && action.lastBuiltRevision.branch.length > 0 && !branch) {
      branch = action.lastBuiltRevision.branch[0]?.name;
    }
  }

  return {
    id: payload.id ?? String(payload.number ?? options.build ?? ''),
    name: payload.fullDisplayName ?? payload.displayName,
    url: payload.url,
    status: payload.result,
    branch,
    revision,
    startedAt,
    completedAt,
  };
};

const mapTestCases = (report: JenkinsTestReportResponse): RemoteTestRecord[] => {
  const records: RemoteTestRecord[] = [];
  for (const suite of report.suites ?? []) {
    for (const testCase of suite.cases ?? []) {
      const status = testCase.status ?? 'UNKNOWN';
      records.push({
        id: `${testCase.className ?? 'jenkins'}::${testCase.name ?? 'unnamed'}`,
        name: testCase.name ?? 'unnamed',
        className: testCase.className,
        status,
        durationMs:
          typeof testCase.duration === 'number' && Number.isFinite(testCase.duration)
            ? Math.max(0, testCase.duration * 1000)
            : undefined,
        errorMessage: testCase.errorDetails ?? testCase.errorStackTrace,
      });
    }
  }
  return records;
};

const fetchBuild = async (
  options: JenkinsClientOptions,
  session: JenkinsSession,
  warnings: string[],
): Promise<RemoteBuildRecord | undefined> => {
  try {
    const url = resolveUrl(options, options.buildEndpoint ?? defaultBuildEndpoint);
    const payload = await performJenkinsRequest<JenkinsBuildResponse>(url, session, options, warnings);
    return extractBuildMetadata(payload, options);
  } catch (error) {
    if (error instanceof HttpError) {
      warnings.push(
        `Jenkins build request returned ${error.statusCode} ${error.statusMessage}. ${error.message ?? ''}`.trim(),
      );
    } else {
      warnings.push(`Jenkins build request failed: ${(error as Error).message}`);
    }
    return undefined;
  }
};

const fetchTests = async (
  options: JenkinsClientOptions,
  session: JenkinsSession,
  warnings: string[],
): Promise<RemoteTestRecord[]> => {
  try {
    const url = resolveUrl(options, options.testReportEndpoint ?? defaultTestEndpoint);
    const payload = await performJenkinsRequest<JenkinsTestReportResponse>(
      url,
      session,
      options,
      warnings,
      { maxBytes: options.maxReportBytes ?? DEFAULT_REPORT_LIMIT_BYTES },
    );
    return mapTestCases(payload);
  } catch (error) {
    if (error instanceof ResponseSizeLimitError) {
      warnings.push(
        `Jenkins test report response exceeded the ${error.limit} byte limit; report skipped.`,
      );
      return [];
    }
    if (error instanceof HttpError) {
      warnings.push(
        `Jenkins test report returned ${error.statusCode} ${error.statusMessage}. ${error.message ?? ''}`.trim(),
      );
    } else {
      warnings.push(`Jenkins test report request failed: ${(error as Error).message}`);
    }
    return [];
  }
};

export const fetchJenkinsArtifacts = async (
  options: JenkinsClientOptions,
): Promise<ParseResult<JenkinsArtifactBundle>> => {
  const warnings: string[] = [];
  const session: JenkinsSession = {};
  await ensureCrumb(session, options, warnings);

  const build = await fetchBuild(options, session, warnings);
  const tests = await fetchTests(options, session, warnings);

  return {
    data: {
      builds: build ? [build] : [],
      tests,
    },
    warnings,
  };
};
