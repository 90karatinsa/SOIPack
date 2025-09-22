import { ParseResult, RemoteBuildRecord, RemoteTestRecord } from './types';
import { HttpError, requestJson } from './utils/http';

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
}

export interface JenkinsArtifactBundle {
  tests: RemoteTestRecord[];
  builds: RemoteBuildRecord[];
}

const defaultBuildEndpoint = '/:jobPath/:build/api/json';
const defaultTestEndpoint = '/:jobPath/:build/testReport/api/json';

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
  warnings: string[],
): Promise<RemoteBuildRecord | undefined> => {
  try {
    const url = resolveUrl(options, options.buildEndpoint ?? defaultBuildEndpoint);
    const authHeader = buildAuthHeader(options);
    const payload = await requestJson<JenkinsBuildResponse>({
      url,
      headers: authHeader ? { Authorization: authHeader } : undefined,
      timeoutMs: options.timeoutMs,
    });
    return extractBuildMetadata(payload, options);
  } catch (error) {
    if (error instanceof HttpError) {
      warnings.push(`Jenkins build isteği ${error.statusCode} ${error.statusMessage} ile sonuçlandı. ${error.message ?? ''}`.trim());
    } else {
      warnings.push(`Jenkins build isteği başarısız oldu: ${(error as Error).message}`);
    }
    return undefined;
  }
};

const fetchTests = async (
  options: JenkinsClientOptions,
  warnings: string[],
): Promise<RemoteTestRecord[]> => {
  try {
    const url = resolveUrl(options, options.testReportEndpoint ?? defaultTestEndpoint);
    const authHeader = buildAuthHeader(options);
    const payload = await requestJson<JenkinsTestReportResponse>({
      url,
      headers: authHeader ? { Authorization: authHeader } : undefined,
      timeoutMs: options.timeoutMs,
    });
    return mapTestCases(payload);
  } catch (error) {
    if (error instanceof HttpError) {
      warnings.push(`Jenkins test raporu ${error.statusCode} ${error.statusMessage} ile sonuçlandı. ${error.message ?? ''}`.trim());
    } else {
      warnings.push(`Jenkins test raporu isteği başarısız oldu: ${(error as Error).message}`);
    }
    return [];
  }
};

export const fetchJenkinsArtifacts = async (
  options: JenkinsClientOptions,
): Promise<ParseResult<JenkinsArtifactBundle>> => {
  const warnings: string[] = [];
  const build = await fetchBuild(options, warnings);
  const tests = await fetchTests(options, warnings);

  return {
    data: {
      builds: build ? [build] : [],
      tests,
    },
    warnings,
  };
};
