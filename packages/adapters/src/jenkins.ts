import { createWriteStream } from 'fs';
import { promises as fsPromises } from 'fs';
import http, { type IncomingHttpHeaders } from 'http';
import https from 'https';
import path from 'path';
import { createHash } from 'crypto';
import { Transform } from 'stream';
import { pipeline as streamPipeline } from 'stream/promises';
import { setTimeout as delay } from 'timers/promises';

import { parseLcovStream } from './adapters/lcov';
import { importCobertura } from './cobertura';
import { CoverageReport, ParseResult, RemoteBuildRecord, RemoteTestRecord } from './types';
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
  artifactsDir?: string;
  coverageArtifacts?: JenkinsCoverageArtifactOptions[];
  maxCoverageArtifactBytes?: number;
}

export interface JenkinsArtifactBundle {
  tests: RemoteTestRecord[];
  builds: RemoteBuildRecord[];
  coverage?: JenkinsCoverageArtifactMetadata[];
}

export interface JenkinsCoverageArtifactOptions {
  type: 'lcov' | 'cobertura';
  path: string;
  maxBytes?: number;
}

export interface JenkinsCoverageArtifactMetadata {
  type: 'lcov' | 'cobertura';
  path: string;
  localPath: string;
  sha256: string;
  report: CoverageReport;
}

const defaultBuildEndpoint = '/:jobPath/:build/api/json';
const defaultTestEndpoint = '/:jobPath/:build/testReport/api/json';
const ERROR_PAYLOAD_LIMIT_BYTES = 4096;

const MAX_RETRIES = 3;
const BASE_RETRY_DELAY_MS = 250;
const DEFAULT_REPORT_LIMIT_BYTES = 5 * 1024 * 1024;
const DEFAULT_COVERAGE_ARTIFACT_LIMIT_BYTES = 10 * 1024 * 1024;
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

const normalizeArtifactPath = (value: string): string | undefined => {
  const trimmed = value.trim();
  if (!trimmed) {
    return undefined;
  }
  const segments = trimmed.split(/[\\/]+/u).filter((segment) => segment.length > 0);
  if (segments.length === 0) {
    return undefined;
  }
  if (segments.some((segment) => segment === '..')) {
    return undefined;
  }
  return segments.join('/');
};

const ensureTrailingSlash = (value: string): string => (value.endsWith('/') ? value : `${value}/`);

const encodeArtifactPath = (artifactPath: string): string =>
  artifactPath
    .split('/')
    .map((segment) => encodeURIComponent(segment))
    .join('/');

const resolveArtifactTargetPath = (baseDir: string, relativePath: string): string | undefined => {
  const normalized = normalizeArtifactPath(relativePath);
  if (!normalized) {
    return undefined;
  }
  const segments = normalized.split('/');
  const resolved = path.resolve(baseDir, ...segments);
  const normalizedBase = path.resolve(baseDir);
  if (resolved === normalizedBase || resolved.startsWith(`${normalizedBase}${path.sep}`)) {
    return resolved;
  }
  return undefined;
};

const removeIfExists = async (targetPath: string): Promise<void> => {
  try {
    await fsPromises.rm(targetPath, { force: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
      throw error;
    }
  }
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

const executeWithRetries = async <T>(
  operation: () => Promise<T>,
  warnings: string[],
  context: string,
): Promise<T> => {
  let attempt = 0;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    try {
      return await operation();
    } catch (error) {
      if (error instanceof HttpError && RETRYABLE_STATUSES.has(error.statusCode) && attempt < MAX_RETRIES) {
        const delayMs = computeRetryDelay(attempt, error.headers);
        warnings.push(
          `Jenkins ${context} returned ${error.statusCode}; retrying in ${delayMs}ms (attempt ${
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

interface JsonRequestOptions {
  url: URL;
  headers: Record<string, string>;
  timeoutMs?: number;
  maxBytes?: number;
}

interface BinaryDownloadOptions {
  url: URL;
  headers: Record<string, string>;
  timeoutMs?: number;
  maxBytes?: number;
  targetPath: string;
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

const downloadBinaryWithLimit = async (
  options: BinaryDownloadOptions,
): Promise<{ sha256: string; bytes: number; headers: IncomingHttpHeaders }> =>
  await new Promise((resolve, reject) => {
      const client = options.url.protocol === 'https:' ? https : http;
      const request = client.request(
        options.url,
        {
          method: 'GET',
          headers: options.headers,
          timeout: options.timeoutMs ?? 15000,
        },
        (response) => {
          const { statusCode = 0, statusMessage = '' } = response;

          if (statusCode < 200 || statusCode >= 300) {
            const errorChunks: Buffer[] = [];
            let collected = 0;
            response.on('data', (chunk) => {
              const buffer = typeof chunk === 'string' ? Buffer.from(chunk) : (chunk as Buffer);
              if (collected >= ERROR_PAYLOAD_LIMIT_BYTES) {
                return;
              }
              const remaining = ERROR_PAYLOAD_LIMIT_BYTES - collected;
              const slice = buffer.length > remaining ? buffer.subarray(0, remaining) : buffer;
              errorChunks.push(slice);
              collected += slice.length;
            });
            response.on('error', (error) => {
              reject(error);
            });
            response.on('end', () => {
              const message = Buffer.concat(errorChunks).toString('utf8');
              reject(new HttpError(statusCode, statusMessage, message || undefined, response.headers));
            });
            return;
          }

          const hash = createHash('sha256');
          let totalBytes = 0;
          const maxBytes = options.maxBytes ?? 0;
          const transform = new Transform({
            transform(chunk, encoding, callback) {
              const buffer = typeof chunk === 'string' ? Buffer.from(chunk, encoding as BufferEncoding) : (chunk as Buffer);
              totalBytes += buffer.length;
              if (maxBytes > 0 && totalBytes > maxBytes) {
                callback(new ResponseSizeLimitError(maxBytes));
                return;
              }
              hash.update(buffer);
              callback(null, buffer);
            },
          });

          const fileStream = createWriteStream(options.targetPath);

          streamPipeline(response, transform, fileStream)
            .then(() => {
              resolve({ sha256: hash.digest('hex'), bytes: totalBytes, headers: response.headers });
            })
            .catch((error) => {
              reject(error);
            });
        },
      );

      request.on('timeout', () => {
        request.destroy(
          new Error(`Request to ${options.url.toString()} timed out after ${options.timeoutMs ?? 15000}ms.`),
        );
      });

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
): Promise<{ payload: T; headers: IncomingHttpHeaders }> =>
  executeWithRetries(() => requestJsonWithLimit<T>(requestOptions), warnings, 'API');

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

const downloadJenkinsArtifact = async (
  url: URL,
  session: JenkinsSession,
  options: JenkinsClientOptions,
  warnings: string[],
  downloadOptions: { targetPath: string; maxBytes?: number; context: string },
): Promise<{ sha256: string; bytes: number }> => {
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
      const result = await executeWithRetries(
        () =>
          downloadBinaryWithLimit({
            url,
            headers,
            timeoutMs: options.timeoutMs,
            maxBytes: downloadOptions.maxBytes,
            targetPath: downloadOptions.targetPath,
          }),
        warnings,
        downloadOptions.context,
      );
      return { sha256: result.sha256, bytes: result.bytes };
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

      await removeIfExists(downloadOptions.targetPath);
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
  artifacts?: Array<{ fileName?: string; relativePath?: string }>;
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

interface JenkinsBuildResult {
  record?: RemoteBuildRecord;
  payload?: JenkinsBuildResponse;
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
): Promise<JenkinsBuildResult> => {
  try {
    const url = resolveUrl(options, options.buildEndpoint ?? defaultBuildEndpoint);
    const payload = await performJenkinsRequest<JenkinsBuildResponse>(url, session, options, warnings);
    return { record: extractBuildMetadata(payload, options), payload };
  } catch (error) {
    if (error instanceof HttpError) {
      warnings.push(
        `Jenkins build request returned ${error.statusCode} ${error.statusMessage}. ${error.message ?? ''}`.trim(),
      );
    } else {
      warnings.push(`Jenkins build request failed: ${(error as Error).message}`);
    }
    return {};
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

const fetchCoverageArtifacts = async (
  options: JenkinsClientOptions,
  session: JenkinsSession,
  warnings: string[],
  buildResult: JenkinsBuildResult,
): Promise<JenkinsCoverageArtifactMetadata[]> => {
  const coverageOptions = options.coverageArtifacts;
  if (!coverageOptions || coverageOptions.length === 0) {
    return [];
  }

  const baseDir = options.artifactsDir ? path.resolve(options.artifactsDir) : process.cwd();
  const availableArtifacts = new Set<string>();
  for (const artifact of buildResult.payload?.artifacts ?? []) {
    if (artifact.relativePath) {
      const normalized = normalizeArtifactPath(artifact.relativePath);
      if (normalized) {
        availableArtifacts.add(normalized);
      }
    }
    if (artifact.fileName) {
      const normalized = normalizeArtifactPath(artifact.fileName);
      if (normalized) {
        availableArtifacts.add(normalized);
      }
    }
  }

  const coverage: JenkinsCoverageArtifactMetadata[] = [];

  for (const artifactOptions of coverageOptions) {
    const normalizedPath = normalizeArtifactPath(artifactOptions.path);
    if (!normalizedPath) {
      warnings.push(`Jenkins coverage artifact path "${artifactOptions.path}" is invalid; skipping.`);
      continue;
    }

    const targetPath = resolveArtifactTargetPath(baseDir, normalizedPath);
    if (!targetPath) {
      warnings.push(
        `Jenkins coverage artifact "${artifactOptions.path}" resolves outside of the artifacts directory; skipping.`,
      );
      continue;
    }

    try {
      await fsPromises.mkdir(path.dirname(targetPath), { recursive: true });
    } catch (error) {
      warnings.push(
        `Failed to prepare directory for Jenkins coverage artifact ${normalizedPath}: ${(error as Error).message}.`,
      );
      continue;
    }

    const encodedPath = encodeArtifactPath(normalizedPath);
    const baseUrl = buildResult.payload?.url
      ? ensureTrailingSlash(buildResult.payload.url)
      : new URL('/', options.baseUrl).toString();

    let artifactUrl: URL;
    if (buildResult.payload?.url) {
      artifactUrl = new URL(`artifact/${encodedPath}`, baseUrl);
    } else {
      const buildId = buildResult.payload?.number ?? buildResult.payload?.id ?? options.build ?? 'lastCompletedBuild';
      const buildPath = `${buildJobPath(options.job)}/${encodeSegment(buildId)}`;
      artifactUrl = new URL(`${ensureTrailingSlash(buildPath)}artifact/${encodedPath}`, options.baseUrl);
    }

    if (availableArtifacts.size > 0 && !availableArtifacts.has(normalizedPath)) {
      warnings.push(
        `Jenkins coverage artifact "${normalizedPath}" was not listed in build metadata; attempting download anyway.`,
      );
    }

    const maxBytes =
      artifactOptions.maxBytes ?? options.maxCoverageArtifactBytes ?? DEFAULT_COVERAGE_ARTIFACT_LIMIT_BYTES;

    try {
      const { sha256 } = await downloadJenkinsArtifact(
        artifactUrl,
        session,
        options,
        warnings,
        {
          targetPath,
          maxBytes,
          context: `artifact download (${normalizedPath})`,
        },
      );

      let coverageResult: ParseResult<CoverageReport>;
      if (artifactOptions.type === 'lcov') {
        try {
          coverageResult = await parseLcovStream(targetPath);
        } catch (error) {
          warnings.push(
            `Failed to parse LCOV coverage from Jenkins artifact ${normalizedPath}: ${(error as Error).message}.`,
          );
          continue;
        }
      } else {
        const result = await importCobertura(targetPath);
        coverageResult = result;
      }

      if (coverageResult.warnings.length > 0) {
        coverageResult.warnings.forEach((warning) => {
          warnings.push(`Jenkins ${artifactOptions.type} artifact ${normalizedPath}: ${warning}`);
        });
      }

      coverage.push({
        type: artifactOptions.type,
        path: normalizedPath,
        localPath: targetPath,
        sha256,
        report: coverageResult.data,
      });
    } catch (error) {
      if (error instanceof ResponseSizeLimitError) {
        warnings.push(
          `Jenkins coverage artifact ${normalizedPath} exceeded the ${error.limit} byte limit; download skipped.`,
        );
      } else if (error instanceof HttpError) {
        warnings.push(
          `Jenkins coverage artifact ${normalizedPath} returned ${error.statusCode} ${
            error.statusMessage
          }. ${error.message ?? ''}`.trim(),
        );
      } else {
        warnings.push(`Failed to download Jenkins coverage artifact ${normalizedPath}: ${(error as Error).message}`);
      }
    }
  }

  return coverage;
};

export const fetchJenkinsArtifacts = async (
  options: JenkinsClientOptions,
): Promise<ParseResult<JenkinsArtifactBundle>> => {
  const warnings: string[] = [];
  const session: JenkinsSession = {};
  await ensureCrumb(session, options, warnings);

  const buildResult = await fetchBuild(options, session, warnings);
  const build = buildResult.record;
  const tests = await fetchTests(options, session, warnings);
  const coverageArtifacts = await fetchCoverageArtifacts(options, session, warnings, buildResult);

  return {
    data: {
      builds: build ? [build] : [],
      tests,
      coverage: coverageArtifacts.length > 0 ? coverageArtifacts : undefined,
    },
    warnings,
  };
};
