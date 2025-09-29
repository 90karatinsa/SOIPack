import http, { IncomingHttpHeaders } from 'http';
import https from 'https';
import { setTimeout as delay } from 'timers/promises';

import {
  ParseResult,
  RemoteBuildRecord,
  RemoteRequirementRecord,
  RemoteTestRecord,
  RemoteTraceLink,
} from './types';
import { HttpError } from './utils/http';

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
  pageSize?: number;
}

export interface PolarionArtifactBundle {
  requirements: RemoteRequirementRecord[];
  tests: RemoteTestRecord[];
  builds: RemoteBuildRecord[];
  relationships: RemoteTraceLink[];
}

const defaultEndpoints = {
  requirements: '/polarion/api/v2/projects/:projectId/workitems',
  testRuns: '/polarion/api/v2/projects/:projectId/test-runs',
  builds: '/polarion/api/v2/projects/:projectId/builds',
} as const;

const DEFAULT_PAGE_SIZE = 200;
const MAX_PAGINATION_DEPTH = 500;
const MAX_RETRIES = 3;
const RETRY_BASE_DELAY_MS = 250;

const pageCache = new Map<string, { etag?: string; payload: unknown }>();

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

const extractCursor = (payload: unknown): string | undefined => {
  if (!payload || typeof payload !== 'object') {
    return undefined;
  }
  const container = payload as Record<string, unknown>;
  const pageInfo = (container.pageInfo ?? container.page_info) as Record<string, unknown> | undefined;

  const candidates = [
    container.nextCursor,
    container.next,
    container.cursor,
    container.nextPageToken,
    container.after,
    pageInfo?.nextCursor,
    pageInfo?.endCursor,
  ];

  for (const candidate of candidates) {
    if (typeof candidate === 'string' && candidate.trim().length > 0) {
      return candidate;
    }
  }

  if (pageInfo && pageInfo.hasNextPage === true && typeof pageInfo.endCursor === 'string') {
    return pageInfo.endCursor;
  }

  const links = container._links as Record<string, unknown> | undefined;
  if (links && typeof links === 'object') {
    const nextLink = links.next as { href?: string } | undefined;
    if (nextLink && typeof nextLink.href === 'string' && nextLink.href.trim().length > 0) {
      return nextLink.href;
    }
  }

  return undefined;
};

const toUrl = (target: URL | string): URL => (target instanceof URL ? new URL(target.toString()) : new URL(target));

const requestJsonWithMetadata = async (
  target: URL | string,
  headers: Record<string, string>,
  timeoutMs: number | undefined,
): Promise<{ statusCode: number; headers: IncomingHttpHeaders; payload?: unknown }> =>
  await new Promise((resolve, reject) => {
      const url = toUrl(target);
      const client = url.protocol === 'https:' ? https : http;
      const request = client.request(
        url,
        {
          method: 'GET',
          headers: { Accept: 'application/json', ...headers },
          timeout: timeoutMs ?? 15000,
        },
        (response) => {
          const { statusCode = 0, statusMessage = '' } = response;
          const chunks: Buffer[] = [];

          response.on('data', (chunk) => {
            chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
          });

          response.on('end', () => {
            if (statusCode === 304) {
              resolve({ statusCode, headers: response.headers });
              return;
            }

            const buffer = Buffer.concat(chunks).toString('utf8');
            if (statusCode < 200 || statusCode >= 300) {
              reject(new HttpError(statusCode, statusMessage, buffer || undefined, response.headers));
              return;
            }

            if (!buffer) {
              resolve({ statusCode, headers: response.headers });
              return;
            }

            try {
              const parsed = JSON.parse(buffer) as unknown;
              resolve({ statusCode, headers: response.headers, payload: parsed });
            } catch (error) {
              reject(
                new Error(
                  `Unable to parse JSON response from ${url.toString()}: ${(error as Error).message}`,
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

const getEtagHeader = (headers: IncomingHttpHeaders): string | undefined => {
  const value = headers.etag;
  if (!value) {
    return undefined;
  }
  if (Array.isArray(value)) {
    return value[0];
  }
  return value;
};

const fetchPage = async (
  url: URL,
  authHeader: string | undefined,
  cacheKey: string,
  timeoutMs: number | undefined,
  onThrottle?: () => void,
): Promise<{ payload: unknown } | undefined> => {
  const cached = pageCache.get(cacheKey);

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt += 1) {
    const headers: Record<string, string> = {};
    if (authHeader) {
      headers.Authorization = authHeader;
    }
    if (cached?.etag) {
      headers['If-None-Match'] = cached.etag;
    }

    try {
      const response = await requestJsonWithMetadata(url, headers, timeoutMs);
      if (response.statusCode === 304 && cached) {
        return { payload: cached.payload };
      }

      if (response.payload === undefined) {
        return { payload: undefined };
      }

      const etag = getEtagHeader(response.headers);
      if (etag) {
        pageCache.set(cacheKey, { etag, payload: response.payload });
      } else {
        pageCache.set(cacheKey, { payload: response.payload });
      }
      return { payload: response.payload };
    } catch (error) {
      if (error instanceof HttpError && error.statusCode === 429) {
        onThrottle?.();
        if (attempt >= MAX_RETRIES) {
          throw error;
        }
        const retryAfterHeader = error.headers?.['retry-after'];
        let waitMs: number | undefined;
        if (typeof retryAfterHeader === 'string') {
          const parsed = Number.parseFloat(retryAfterHeader);
          if (!Number.isNaN(parsed)) {
            waitMs = parsed * 1000;
          }
        }
        if (!waitMs) {
          waitMs = Math.pow(2, attempt) * RETRY_BASE_DELAY_MS;
        }
        await delay(waitMs);
        continue;
      }
      throw error;
    }
  }

  return undefined;
};

const fetchCollection = async <T>(
  options: PolarionClientOptions,
  key: keyof typeof defaultEndpoints,
  warnings: string[],
): Promise<T[]> => {
  const url = resolveEndpointUrl(options, key);
  const authHeader = buildAuthHeader(options);
  const items: T[] = [];
  const visitedCursors = new Set<string>();
  const throttleWarningIssued = { value: false };
  const ensureThrottleWarning = (): void => {
    if (!throttleWarningIssued.value) {
      warnings.push(`Polarion ${key} request was throttled (HTTP 429). Retrying with backoff.`);
      throttleWarningIssued.value = true;
    }
  };
  let cursor: string | undefined;
  let pageCount = 0;

  while (pageCount < MAX_PAGINATION_DEPTH) {
    let pageUrl = new URL(url.toString());
    const pageSize = options.pageSize ?? DEFAULT_PAGE_SIZE;
    if (cursor) {
      if (/^https?:\/\//iu.test(cursor)) {
        pageUrl = new URL(cursor, url);
      } else {
        pageUrl.searchParams.set('cursor', cursor);
      }
    }
    if (pageSize > 0) {
      pageUrl.searchParams.set('pageSize', String(pageSize));
    }

    const cacheKey = `${key}:${pageUrl.toString()}`;
    try {
      const result = await fetchPage(pageUrl, authHeader, cacheKey, options.timeoutMs, ensureThrottleWarning);
      if (!result) {
        break;
      }
      const payload = result.payload;
      items.push(...extractList<T>(payload));
      const nextCursor = extractCursor(payload);
      if (!nextCursor || visitedCursors.has(nextCursor)) {
        break;
      }
      visitedCursors.add(nextCursor);
      cursor = nextCursor;
      pageCount += 1;
    } catch (error) {
      if (error instanceof HttpError) {
        if (error.statusCode === 429) {
          ensureThrottleWarning();
          break;
        } else {
          warnings.push(
            `Polarion ${key} isteği ${error.statusCode} ${error.statusMessage} ile sonuçlandı. ${
              error.message ?? ''
            }`.trim(),
          );
          break;
        }
      } else {
        warnings.push(`Polarion ${key} isteği başarısız oldu: ${(error as Error).message}`);
        break;
      }
    }
  }

  if (pageCount >= MAX_PAGINATION_DEPTH) {
    warnings.push(`Polarion ${key} pagination aborted after ${MAX_PAGINATION_DEPTH} pages.`);
  }

  return items;
};

const toStringId = (value: unknown): string | undefined => {
  if (typeof value === 'string') {
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    return String(value);
  }
  if (value && typeof value === 'object') {
    const source = value as Record<string, unknown>;
    if ('id' in source) {
      return toStringId(source.id);
    }
    if ('workItemId' in source) {
      return toStringId(source.workItemId);
    }
    if ('workItem' in source) {
      return toStringId(source.workItem);
    }
    if ('targetId' in source) {
      return toStringId(source.targetId);
    }
    if ('key' in source) {
      return toStringId(source.key);
    }
  }
  return undefined;
};

const normalizeTraceType = (role: string | undefined): RemoteTraceLink['type'] => {
  const normalized = role?.toLowerCase() ?? '';
  if (normalized.includes('implement')) {
    return 'implements';
  }
  if (normalized.includes('satisf')) {
    return 'satisfies';
  }
  return 'verifies';
};

const extractLinkedEntries = (value: unknown): Array<{ id: string; role?: string }> => {
  if (!value) {
    return [];
  }

  const entries: Array<{ id: string; role?: string }> = [];

  if (Array.isArray(value)) {
    value.forEach((item) => {
      if (item === null || item === undefined) {
        return;
      }
      if (typeof item === 'string' || typeof item === 'number') {
        const id = toStringId(item);
        if (id) {
          entries.push({ id });
        }
        return;
      }
      if (typeof item === 'object') {
        const source = item as Record<string, unknown>;
        const id = toStringId(source.id ?? source.workItemId ?? source.workItem ?? source.targetId ?? source.key);
        if (!id) {
          return;
        }
        const roleValue = source.role ?? source.type ?? source.linkRole ?? source.relationType;
        const role = typeof roleValue === 'string' ? roleValue : undefined;
        entries.push({ id, role });
      }
    });
    return entries;
  }

  if (typeof value === 'object') {
    const container = value as Record<string, unknown>;
    if (Array.isArray(container.items)) {
      entries.push(...extractLinkedEntries(container.items));
      return entries;
    }
  }

  const id = toStringId(value);
  if (id) {
    entries.push({ id });
  }

  return entries;
};

const gatherLinksFromRecord = (
  record: Record<string, unknown>,
  keys: string[],
): Array<{ id: string; role?: string }> => {
  const results: Array<{ id: string; role?: string }> = [];
  keys.forEach((key) => {
    if (Object.prototype.hasOwnProperty.call(record, key)) {
      results.push(...extractLinkedEntries(record[key]));
    }
  });
  return results;
};

const collectPolarionRelationships = (
  requirements: Array<RemoteRequirementRecord & Record<string, unknown>>,
  tests: Array<RemoteTestRecord & Record<string, unknown>>,
): RemoteTraceLink[] => {
  const links: RemoteTraceLink[] = [];
  const seen = new Set<string>();
  const requirementIds = new Set(requirements.map((item) => item.id));
  const testIds = new Set(tests.map((item) => item.id));

  const register = (fromId: string | undefined, toId: string | undefined, role?: string) => {
    if (!fromId || !toId) {
      return;
    }
    const type = normalizeTraceType(role);
    const key = `${fromId}::${toId}::${type}`;
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    links.push({ fromId, toId, type });
  };

  requirements.forEach((requirement) => {
    const fields = requirement as Record<string, unknown>;
    const related = gatherLinksFromRecord(fields, [
      'linkedWorkItems',
      'linkedItems',
      'linkedTests',
      'relatedWorkItems',
      'verifies',
      'validatedBy',
    ]);
    related.forEach(({ id, role }) => {
      if (testIds.has(id)) {
        register(requirement.id, id, role);
      }
    });
  });

  tests.forEach((test) => {
    const fields = test as Record<string, unknown>;
    const requirementRefs = Array.isArray(test.requirementIds) ? test.requirementIds : [];
    requirementRefs.forEach((reqId) => {
      if (requirementIds.has(reqId)) {
        register(reqId, test.id);
      }
    });

    const additional = gatherLinksFromRecord(fields, [
      'linkedWorkItems',
      'linkedItems',
      'relatedWorkItems',
      'requirements',
      'requirementIds',
    ]);
    additional.forEach(({ id, role }) => {
      if (requirementIds.has(id)) {
        register(id, test.id, role);
      }
    });
  });

  return links;
};

export const fetchPolarionArtifacts = async (
  options: PolarionClientOptions,
): Promise<ParseResult<PolarionArtifactBundle>> => {
  const warnings: string[] = [];

  const requirements = await fetchCollection<RemoteRequirementRecord>(options, 'requirements', warnings);
  const tests = await fetchCollection<RemoteTestRecord>(options, 'testRuns', warnings);
  const builds = await fetchCollection<RemoteBuildRecord>(options, 'builds', warnings);
  const relationships = collectPolarionRelationships(
    requirements as Array<RemoteRequirementRecord & Record<string, unknown>>,
    tests as Array<RemoteTestRecord & Record<string, unknown>>,
  );

  return {
    data: {
      requirements,
      tests,
      builds,
      relationships,
    },
    warnings,
  };
};
