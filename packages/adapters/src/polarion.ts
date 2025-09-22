import { ParseResult, RemoteBuildRecord, RemoteRequirementRecord, RemoteTestRecord } from './types';
import { HttpError, requestJson } from './utils/http';

export interface PolarionClientOptions {
  baseUrl: string;
  projectId: string;
  username?: string;
  password?: string;
  token?: string;
  requirementsEndpoint?: string;
  testRunsEndpoint?: string;
  buildsEndpoint?: string;
  timeoutMs?: number;
}

export interface PolarionArtifactBundle {
  requirements: RemoteRequirementRecord[];
  tests: RemoteTestRecord[];
  builds: RemoteBuildRecord[];
}

const defaultEndpoints = {
  requirements: '/polarion/api/v2/projects/:projectId/workitems',
  testRuns: '/polarion/api/v2/projects/:projectId/test-runs',
  builds: '/polarion/api/v2/projects/:projectId/builds',
} as const;

const applyProjectTemplate = (template: string, projectId: string): string => {
  if (!template.includes(':projectId')) {
    return template;
  }
  return template.replace(/:projectId/gu, encodeURIComponent(projectId));
};

const resolveEndpointUrl = (options: PolarionClientOptions, key: keyof typeof defaultEndpoints): URL => {
  const optionKey =
    key === 'testRuns' ? 'testRunsEndpoint' : (`${key}Endpoint` as keyof PolarionClientOptions);
  const template = (options[optionKey] as string | undefined) ?? defaultEndpoints[key];
  const resolvedPath = applyProjectTemplate(template, options.projectId);
  const url = new URL(resolvedPath, options.baseUrl);

  if (!template.includes(':projectId')) {
    const hasProjectParam = ['project', 'projectId', 'project_id'].some((param) => url.searchParams.has(param));
    if (!hasProjectParam) {
      url.searchParams.set('projectId', options.projectId);
    }
  }

  return url;
};

const buildAuthHeader = (options: PolarionClientOptions): string | undefined => {
  if (options.token) {
    return `Bearer ${options.token}`;
  }
  if (options.username && options.password) {
    const credentials = Buffer.from(`${options.username}:${options.password}`).toString('base64');
    return `Basic ${credentials}`;
  }
  return undefined;
};

const extractList = <T>(payload: unknown): T[] => {
  if (!payload) {
    return [];
  }

  if (Array.isArray(payload)) {
    return payload as T[];
  }

  if (typeof payload === 'object' && Array.isArray((payload as { items?: unknown }).items)) {
    return ((payload as { items?: unknown }).items ?? []) as T[];
  }

  return [];
};

const fetchCollection = async <T>(
  options: PolarionClientOptions,
  key: keyof typeof defaultEndpoints,
  warnings: string[],
): Promise<T[]> => {
  try {
    const url = resolveEndpointUrl(options, key);
    const authHeader = buildAuthHeader(options);
    const payload = await requestJson<unknown>({
      url,
      headers: authHeader ? { Authorization: authHeader } : undefined,
      timeoutMs: options.timeoutMs,
    });
    return extractList<T>(payload);
  } catch (error) {
    if (error instanceof HttpError) {
      warnings.push(
        `Polarion ${key} isteği ${error.statusCode} ${error.statusMessage} ile sonuçlandı. ${error.message ?? ''}`.trim(),
      );
    } else {
      warnings.push(`Polarion ${key} isteği başarısız oldu: ${(error as Error).message}`);
    }
    return [];
  }
};

export const fetchPolarionArtifacts = async (
  options: PolarionClientOptions,
): Promise<ParseResult<PolarionArtifactBundle>> => {
  const warnings: string[] = [];

  const requirements = await fetchCollection<RemoteRequirementRecord>(options, 'requirements', warnings);
  const tests = await fetchCollection<RemoteTestRecord>(options, 'testRuns', warnings);
  const builds = await fetchCollection<RemoteBuildRecord>(options, 'builds', warnings);

  return {
    data: {
      requirements,
      tests,
      builds,
    },
    warnings,
  };
};
