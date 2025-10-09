import http, { type IncomingHttpHeaders } from 'http';
import https from 'https';
import { createHash } from 'crypto';
import { setTimeout as delay } from 'timers/promises';

import {
  ParseResult,
  RemoteBuildRecord,
  RemoteRequirementRecord,
  RemoteTestRecord,
  RemoteTraceLink,
} from './types';
import { HttpError } from './utils/http';

const DEFAULT_API_VERSION = '7.1-preview.1';
const DEFAULT_PAGE_SIZE = 200;
const DEFAULT_MAX_PAGES = 50;
const DEFAULT_TIMEOUT_MS = 15000;
const DEFAULT_RATE_LIMIT_DELAYS_MS = [250, 500, 1000, 2000];
const DEFAULT_MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024;

const attachmentCache = new Map<string, { sha256: string; bytes: number; contentType?: string }>();

export type AzureDevOpsArtifactScope = 'requirement' | 'test';

interface AttachmentDescriptor {
  id: string;
  artifactId: string;
  artifactType: AzureDevOpsArtifactScope;
  filename: string;
  url?: string;
  contentType?: string;
  bytes?: number;
}

export interface AzureDevOpsAttachmentMetadata {
  id: string;
  artifactId: string;
  artifactType: AzureDevOpsArtifactScope;
  filename: string;
  url: string;
  bytes?: number;
  contentType?: string;
  sha256: string;
}

export interface AzureDevOpsArtifactBundle {
  requirements: RemoteRequirementRecord[];
  tests: RemoteTestRecord[];
  builds: RemoteBuildRecord[];
  traces: RemoteTraceLink[];
  attachments: AzureDevOpsAttachmentMetadata[];
}

export interface AzureDevOpsClientOptions {
  baseUrl: string;
  organization: string;
  project: string;
  personalAccessToken: string;
  requirementsEndpoint?: string;
  testsEndpoint?: string;
  buildsEndpoint?: string;
  attachmentsEndpoint?: string;
  timeoutMs?: number;
  pageSize?: number;
  maxPages?: number;
  apiVersion?: string;
  rateLimitDelaysMs?: number[];
  maxAttachmentBytes?: number;
  requirementsQuery?: string;
  testOutcomeFilter?: string;
  testPlanId?: string;
  testSuiteId?: string;
  testRunId?: string;
  buildDefinitionId?: string;
}

const defaultEndpoints = {
  requirements: '/:organization/:project/_apis/wit/workitems',
  tests: '/:organization/:project/_apis/test/Runs',
  builds: '/:organization/:project/_apis/build/builds',
  attachments:
    '/:organization/:project/_apis/wit/workitems/:workItemId/attachments/:attachmentId',
} as const;

const buildAuthHeader = (token: string): string => {
  const encoded = Buffer.from(`:${token}`).toString('base64');
  return `Basic ${encoded}`;
};

const toSingleHeaderValue = (value: string | string[] | undefined): string | undefined => {
  if (typeof value === 'string') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.find((entry) => typeof entry === 'string' && entry.trim().length > 0);
  }
  return undefined;
};

const applyTemplate = (template: string, replacements: Record<string, string | undefined>): string => {
  let result = template;
  for (const [key, rawValue] of Object.entries(replacements)) {
    if (!rawValue) {
      continue;
    }
    const value = encodeURIComponent(rawValue);
    result = result.replace(new RegExp(`:${key}`, 'gu'), value);
  }
  return result;
};

const collectTemplateVariables = (options: AzureDevOpsClientOptions): Record<string, string> => {
  const entries: Record<string, string> = {
    organization: options.organization,
    project: options.project,
  };
  if (options.testPlanId) {
    entries.planId = options.testPlanId;
  }
  if (options.testSuiteId) {
    entries.suiteId = options.testSuiteId;
  }
  if (options.testRunId) {
    entries.runId = options.testRunId;
  }
  if (options.buildDefinitionId) {
    entries.definitionId = options.buildDefinitionId;
  }
  return entries;
};

const resolveEndpointUrl = (options: AzureDevOpsClientOptions, template: string): URL => {
  const variables = collectTemplateVariables(options);
  const resolved = applyTemplate(template, variables);
  return new URL(resolved, options.baseUrl);
};

const ensureApiVersion = (url: URL, apiVersion: string): void => {
  if (!url.searchParams.has('api-version')) {
    url.searchParams.set('api-version', apiVersion);
  }
};

const parseRetryAfterHeader = (header: string | undefined): number | undefined => {
  if (!header) {
    return undefined;
  }
  const trimmed = header.trim();
  if (!trimmed) {
    return undefined;
  }
  const seconds = Number.parseFloat(trimmed);
  if (Number.isFinite(seconds) && seconds >= 0) {
    return seconds * 1000;
  }
  const absolute = Date.parse(trimmed);
  if (!Number.isNaN(absolute)) {
    const delta = absolute - Date.now();
    return delta > 0 ? delta : undefined;
  }
  return undefined;
};

const requestJsonWithHeaders = async (
  url: URL,
  options: AzureDevOpsClientOptions,
): Promise<{ payload: unknown; headers: IncomingHttpHeaders }> =>
  await new Promise((resolve, reject) => {
    const client = url.protocol === 'https:' ? https : http;
    const request = client.request(
      url,
      {
        method: 'GET',
        headers: {
          Accept: 'application/json',
          Authorization: buildAuthHeader(options.personalAccessToken),
          'User-Agent': 'soipack-adapters',
        },
        timeout: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      },
      (response) => {
        const { statusCode = 0, statusMessage = '' } = response;
        const chunks: Buffer[] = [];

        response.on('data', (chunk) => {
          chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
        });

        response.on('end', () => {
          const body = Buffer.concat(chunks).toString('utf8');
          if (statusCode < 200 || statusCode >= 300) {
            reject(new HttpError(statusCode, statusMessage, body || undefined, response.headers));
            return;
          }
          if (!body) {
            resolve({ payload: {}, headers: response.headers });
            return;
          }
          try {
            const parsed = JSON.parse(body) as unknown;
            resolve({ payload: parsed, headers: response.headers });
          } catch (error) {
            reject(new Error(`Unable to parse JSON response from ${url.toString()}: ${(error as Error).message}`));
          }
        });
      },
    );

    request.on('error', (error) => {
      reject(error);
    });

    request.end();
  });

const requestWithThrottling = async (
  url: URL,
  options: AzureDevOpsClientOptions,
  attempt = 0,
): Promise<{ payload: unknown; headers: IncomingHttpHeaders }> => {
  const rateLimitDelays = options.rateLimitDelaysMs ?? DEFAULT_RATE_LIMIT_DELAYS_MS;
  try {
    return await requestJsonWithHeaders(url, options);
  } catch (error) {
    if (
      error instanceof HttpError &&
      (error.statusCode === 429 || error.statusCode === 503) &&
      attempt < rateLimitDelays.length
    ) {
      const header = toSingleHeaderValue(error.headers?.['retry-after']);
      const retryDelay = parseRetryAfterHeader(header) ?? rateLimitDelays[attempt];
      if (retryDelay > 0) {
        await delay(retryDelay);
      }
      return requestWithThrottling(url, options, attempt + 1);
    }
    throw error;
  }
};

const extractCollectionItems = (payload: unknown): unknown[] => {
  if (!payload) {
    return [];
  }
  if (Array.isArray(payload)) {
    return payload as unknown[];
  }
  if (typeof payload === 'object') {
    const container = payload as Record<string, unknown>;
    const candidates = ['value', 'items', 'results'];
    for (const key of candidates) {
      const candidate = container[key];
      if (Array.isArray(candidate)) {
        return candidate as unknown[];
      }
    }
  }
  return [];
};

const extractContinuation = (
  headers: IncomingHttpHeaders | undefined,
  payload: unknown,
): { token?: string; url?: string } => {
  const headerToken = toSingleHeaderValue(headers?.['x-ms-continuationtoken']);
  if (headerToken && headerToken.trim().length > 0) {
    if (/^https?:/iu.test(headerToken)) {
      return { url: headerToken };
    }
    return { token: headerToken };
  }

  if (payload && typeof payload === 'object') {
    const container = payload as Record<string, unknown>;
    const candidates = [
      container.continuationToken,
      container.nextLink,
      container.nextPageLink,
      container.nextUrl,
      container['@odata.nextLink'],
    ];

    for (const candidate of candidates) {
      if (typeof candidate === 'string' && candidate.trim().length > 0) {
        if (/^https?:/iu.test(candidate)) {
          return { url: candidate };
        }
        return { token: candidate };
      }
    }
  }

  return {};
};

const iteratePaginatedCollection = async (
  options: AzureDevOpsClientOptions,
  endpoint: string,
  warnings: string[],
  onItems: (items: unknown[], headers: IncomingHttpHeaders | undefined) => void,
  customizeUrl?: (url: URL, pageIndex: number) => void,
): Promise<void> => {
  const pageSize = options.pageSize ?? DEFAULT_PAGE_SIZE;
  const maxPages = options.maxPages ?? DEFAULT_MAX_PAGES;
  const apiVersion = options.apiVersion ?? DEFAULT_API_VERSION;

  let continuationToken: string | undefined;
  let nextPageUrl: string | undefined;
  const seenTokens = new Set<string>();

  for (let pageIndex = 0; pageIndex < maxPages; pageIndex += 1) {
    let url: URL;

    if (nextPageUrl) {
      url = new URL(nextPageUrl, options.baseUrl);
      nextPageUrl = undefined;
    } else {
      url = resolveEndpointUrl(options, endpoint);
      url.searchParams.set('$top', String(pageSize));
      if (pageIndex > 0 && !continuationToken) {
        url.searchParams.set('$skip', String(pageIndex * pageSize));
      }
      if (continuationToken) {
        url.searchParams.set('continuationToken', continuationToken);
      }
    }

    ensureApiVersion(url, apiVersion);
    if (customizeUrl) {
      customizeUrl(url, pageIndex);
    }

    const { payload, headers } = await requestWithThrottling(url, options);
    const items = extractCollectionItems(payload);
    onItems(items, headers);

    const continuation = extractContinuation(headers, payload);
    continuationToken = continuation.token;
    nextPageUrl = continuation.url;

    if (continuationToken) {
      if (seenTokens.has(continuationToken)) {
        break;
      }
      seenTokens.add(continuationToken);
    }

    if (!continuationToken && !nextPageUrl) {
      break;
    }
  }
};

const toStringValue = (value: unknown): string | undefined => {
  if (value === null || value === undefined) {
    return undefined;
  }
  if (typeof value === 'string') {
    return value;
  }
  if (typeof value === 'number') {
    return Number.isFinite(value) ? value.toString(10) : undefined;
  }
  if (typeof value === 'boolean') {
    return value ? 'true' : 'false';
  }
  return undefined;
};

const normalizeRequirement = (item: unknown): RemoteRequirementRecord | undefined => {
  if (!item || typeof item !== 'object') {
    return undefined;
  }
  const container = item as Record<string, unknown>;
  const fields = (container.fields as Record<string, unknown> | undefined) ?? {};
  const id = toStringValue(container.id ?? container.workItemId ?? container.workItemID);
  const title = toStringValue(fields['System.Title'] ?? container.title);

  if (!id || !title) {
    return undefined;
  }

  let linkUrl: string | undefined;
  const rawLinks = container._links;
  if (rawLinks && typeof rawLinks === 'object') {
    const htmlLink = (rawLinks as Record<string, unknown>).html;
    if (htmlLink && typeof htmlLink === 'object') {
      linkUrl = toStringValue((htmlLink as Record<string, unknown>).href);
    }
  }

  return {
    id,
    title,
    description: toStringValue(fields['System.Description'] ?? container.description),
    status: toStringValue(fields['System.State'] ?? container.state),
    type: toStringValue(fields['System.WorkItemType'] ?? container.type),
    url: toStringValue(container.url ?? container.webUrl) ?? linkUrl,
  };
};

const normalizeTestRecord = (item: unknown): RemoteTestRecord | undefined => {
  if (!item || typeof item !== 'object') {
    return undefined;
  }
  const container = item as Record<string, unknown>;
  const id = toStringValue(container.id ?? container.testCaseId ?? container.testPointId);
  const name = toStringValue(container.name ?? (container.testCase as Record<string, unknown> | undefined)?.name);

  if (!id || !name) {
    return undefined;
  }

  const requirementIds = Array.isArray(container.associatedRequirementIds)
    ? (container.associatedRequirementIds as unknown[])
        .map((value) => toStringValue(value))
        .filter((value): value is string => Boolean(value))
    : undefined;

  const durationMsCandidates = [
    container.durationInMs,
    container.durationMs,
    container.duration,
  ];
  let durationMs: number | undefined;
  for (const candidate of durationMsCandidates) {
    if (typeof candidate === 'number' && Number.isFinite(candidate)) {
      durationMs = candidate;
      break;
    }
  }

  return {
    id,
    name,
    className: toStringValue(
      container.automatedTestStorage ??
        (container.testCase as Record<string, unknown> | undefined)?.suiteName ??
        container.className,
    ),
    status: toStringValue(container.outcome ?? container.status ?? container.result) ?? 'unknown',
    durationMs,
    errorMessage: toStringValue(container.errorMessage ?? container.comment ?? container.message),
    requirementIds,
    startedAt: toStringValue(container.startedDate ?? container.startedAt ?? container.startTime),
    finishedAt: toStringValue(container.completedDate ?? container.completedAt ?? container.finishTime),
  };
};

const normalizeBuildRecord = (item: unknown): RemoteBuildRecord | undefined => {
  if (!item || typeof item !== 'object') {
    return undefined;
  }
  const container = item as Record<string, unknown>;
  const id = toStringValue(container.id ?? container.buildId ?? container.identifier);
  if (!id) {
    return undefined;
  }

  const links = (container._links as Record<string, unknown> | undefined) ?? {};
  const webLink = (links.web as Record<string, unknown> | undefined)?.href;

  return {
    id,
    name: toStringValue(container.buildNumber ?? container.name),
    url: toStringValue(container.url ?? webLink ?? container.webUrl),
    status: toStringValue(container.result ?? container.status ?? container.state),
    branch: toStringValue(container.sourceBranch ?? container.branch),
    revision: toStringValue(container.sourceVersion ?? container.revision ?? container.commitId),
    startedAt: toStringValue(container.startTime ?? container.queueTime ?? container.startedAt),
    completedAt: toStringValue(container.finishTime ?? container.completedTime ?? container.completedAt),
  };
};

const extractRequirementAttachments = (
  item: unknown,
  requirementId: string,
): AttachmentDescriptor[] => {
  if (!item || typeof item !== 'object') {
    return [];
  }
  const descriptors: AttachmentDescriptor[] = [];
  const container = item as Record<string, unknown>;
  const attachments = container.attachments;
  if (Array.isArray(attachments)) {
    for (const entry of attachments) {
      if (!entry || typeof entry !== 'object') {
        continue;
      }
      const attachment = entry as Record<string, unknown>;
      const url = toStringValue(attachment.url ?? attachment.href);
      const id = toStringValue(attachment.id ?? attachment.attachmentId ?? url);
      const filename =
        toStringValue(attachment.name ?? attachment.fileName ?? attachment.filename) ?? `attachment-${requirementId}`;
      if (!id || !url) {
        continue;
      }
      descriptors.push({
        id,
        artifactId: requirementId,
        artifactType: 'requirement',
        filename,
        url,
        contentType: toStringValue(attachment.contentType),
        bytes: typeof attachment.size === 'number' ? attachment.size : undefined,
      });
    }
  }

  const relations = container.relations;
  if (Array.isArray(relations)) {
    for (const relation of relations) {
      if (!relation || typeof relation !== 'object') {
        continue;
      }
      const relationRecord = relation as Record<string, unknown>;
      const relType = toStringValue(relationRecord.rel);
      if (!relType || !relType.toLowerCase().includes('attachment')) {
        continue;
      }
      const relationUrl = toStringValue(relationRecord.url ?? relationRecord.href);
      const relationId = toStringValue(relationRecord.id ?? relationUrl);
      if (!relationUrl || !relationId) {
        continue;
      }
      const attributes = (relationRecord.attributes as Record<string, unknown> | undefined) ?? {};
      const filename =
        toStringValue(attributes.name ?? relationRecord.name ?? relationRecord.title) ?? `attachment-${requirementId}`;
      descriptors.push({
        id: relationId,
        artifactId: requirementId,
        artifactType: 'requirement',
        filename,
        url: relationUrl,
        contentType: toStringValue(attributes.contentType ?? relationRecord.contentType),
        bytes: typeof attributes.length === 'number' ? attributes.length : undefined,
      });
    }
  }

  return descriptors;
};

const extractTestAttachments = (item: unknown, testId: string): AttachmentDescriptor[] => {
  if (!item || typeof item !== 'object') {
    return [];
  }
  const descriptors: AttachmentDescriptor[] = [];
  const container = item as Record<string, unknown>;
  const attachments = container.attachments ?? container.testAttachments;
  if (Array.isArray(attachments)) {
    for (const entry of attachments) {
      if (!entry || typeof entry !== 'object') {
        continue;
      }
      const attachment = entry as Record<string, unknown>;
      const url = toStringValue(attachment.url ?? attachment.href);
      const id = toStringValue(attachment.id ?? attachment.attachmentId ?? url);
      if (!id || !url) {
        continue;
      }
      const filename =
        toStringValue(attachment.name ?? attachment.fileName ?? attachment.filename) ?? `attachment-${testId}`;
      descriptors.push({
        id,
        artifactId: testId,
        artifactType: 'test',
        filename,
        url,
        contentType: toStringValue(attachment.contentType),
        bytes: typeof attachment.size === 'number' ? attachment.size : undefined,
      });
    }
  }
  return descriptors;
};

const resolveAttachmentUrl = (
  options: AzureDevOpsClientOptions,
  descriptor: AttachmentDescriptor,
): URL => {
  const template = options.attachmentsEndpoint ?? defaultEndpoints.attachments;
  const baseVariables = collectTemplateVariables(options);
  const resolved = applyTemplate(template, {
    ...baseVariables,
    workItemId: descriptor.artifactId,
    attachmentId: descriptor.id,
  });
  return new URL(resolved, options.baseUrl);
};

const downloadAttachment = async (
  absoluteUrl: string,
  descriptor: AttachmentDescriptor,
  options: AzureDevOpsClientOptions,
  warnings: string[],
): Promise<{ sha256: string; bytes: number; contentType?: string } | undefined> => {
  const cacheKey = absoluteUrl;
  const cached = attachmentCache.get(cacheKey);
  if (cached) {
    return cached;
  }

  const rateLimitDelays = options.rateLimitDelaysMs ?? DEFAULT_RATE_LIMIT_DELAYS_MS;
  const maxAttachmentBytes = options.maxAttachmentBytes ?? DEFAULT_MAX_ATTACHMENT_BYTES;
  const apiVersion = options.apiVersion ?? DEFAULT_API_VERSION;

  let attempt = 0;

  while (attempt <= rateLimitDelays.length) {
    const outcome: {
      status: 'ok';
      value: { sha256: string; bytes: number; contentType?: string };
    } | { status: 'retry'; delayMs?: number } | { status: 'error' } = await new Promise((resolve) => {
      const url = new URL(absoluteUrl);
      if (!url.searchParams.has('api-version')) {
        url.searchParams.set('api-version', apiVersion);
      }

      const client = url.protocol === 'https:' ? https : http;
      const request = client.request(
        url,
        {
          method: 'GET',
          headers: {
            Accept: '*/*',
            Authorization: buildAuthHeader(options.personalAccessToken),
            'User-Agent': 'soipack-adapters',
          },
          timeout: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
        },
        (response) => {
          const { statusCode = 0 } = response;

          if (statusCode === 429 || statusCode === 503) {
            const retryHeader = toSingleHeaderValue(response.headers['retry-after']);
            const retryDelay = parseRetryAfterHeader(retryHeader);
            response.resume();
            resolve({ status: 'retry', delayMs: retryDelay });
            return;
          }

          if (statusCode < 200 || statusCode >= 300) {
            warnings.push(
              `Attachment ${descriptor.filename} from ${absoluteUrl} returned ${statusCode} ${response.statusMessage ?? ''}`.trim(),
            );
            response.resume();
            resolve({ status: 'error' });
            return;
          }

          const lengthHeader = toSingleHeaderValue(response.headers['content-length']);
          if (lengthHeader) {
            const lengthValue = Number.parseInt(lengthHeader, 10);
            if (Number.isFinite(lengthValue) && lengthValue > maxAttachmentBytes) {
              warnings.push(
                `Attachment ${descriptor.filename} from ${absoluteUrl} exceeds the ${maxAttachmentBytes} byte limit; skipping download.`,
              );
              response.resume();
              resolve({ status: 'error' });
              return;
            }
          }

          const hash = createHash('sha256');
          let totalBytes = 0;
          let settled = false;
          let aborted = false;

          const finish = (result: { status: 'ok'; value: { sha256: string; bytes: number; contentType?: string } } | { status: 'error' }) => {
            if (!settled) {
              settled = true;
              resolve(result);
            }
          };

          response.on('data', (chunk) => {
            if (settled) {
              return;
            }
            const buffer = typeof chunk === 'string' ? Buffer.from(chunk) : chunk;
            totalBytes += buffer.length;
            if (totalBytes > maxAttachmentBytes) {
              aborted = true;
              warnings.push(
                `Attachment ${descriptor.filename} from ${absoluteUrl} exceeded the ${maxAttachmentBytes} byte limit while streaming; download aborted.`,
              );
              response.destroy();
              return;
            }
            hash.update(buffer);
          });

          response.on('error', (error) => {
            if (!settled) {
              warnings.push(
                `Error while downloading attachment ${descriptor.filename} from ${absoluteUrl}: ${(error as Error).message}`,
              );
              finish({ status: 'error' });
            }
          });

          response.on('close', () => {
            if (aborted && !settled) {
              finish({ status: 'error' });
            }
          });

          response.on('end', () => {
            if (aborted) {
              return;
            }
            const sha256 = hash.digest('hex');
            const contentType = toSingleHeaderValue(response.headers['content-type']) ?? descriptor.contentType;
            finish({ status: 'ok', value: { sha256, bytes: totalBytes, contentType } });
          });
        },
      );

      request.on('error', (error) => {
        warnings.push(
          `Unable to download attachment ${descriptor.filename} from ${absoluteUrl}: ${(error as Error).message}`,
        );
        resolve({ status: 'error' });
      });

      request.end();
    });

    if (outcome.status === 'ok') {
      attachmentCache.set(cacheKey, outcome.value);
      return outcome.value;
    }

    if (outcome.status === 'error') {
      return undefined;
    }

    if (attempt >= rateLimitDelays.length) {
      return undefined;
    }

    const waitMs = outcome.delayMs ?? rateLimitDelays[attempt];
    attempt += 1;
    if (waitMs > 0) {
      await delay(waitMs);
    }
  }

  return undefined;
};

const fetchRequirements = async (
  options: AzureDevOpsClientOptions,
  warnings: string[],
  attachmentDescriptors: AttachmentDescriptor[],
): Promise<RemoteRequirementRecord[]> => {
  const endpoint = options.requirementsEndpoint ?? defaultEndpoints.requirements;
  const requirements: RemoteRequirementRecord[] = [];

  await iteratePaginatedCollection(
    options,
    endpoint,
    warnings,
    (items) => {
      for (const item of items) {
        const requirement = normalizeRequirement(item);
        if (!requirement) {
          continue;
        }
        requirements.push(requirement);
        attachmentDescriptors.push(...extractRequirementAttachments(item, requirement.id));
      }
    },
    (url) => {
      if (options.requirementsQuery && !url.searchParams.has('query')) {
        url.searchParams.set('query', options.requirementsQuery);
      }
    },
  );

  return requirements;
};

const fetchTests = async (
  options: AzureDevOpsClientOptions,
  warnings: string[],
  attachmentDescriptors: AttachmentDescriptor[],
): Promise<{ tests: RemoteTestRecord[]; traces: RemoteTraceLink[] }> => {
  const endpoint = options.testsEndpoint ?? defaultEndpoints.tests;
  const tests: RemoteTestRecord[] = [];
  const traces: RemoteTraceLink[] = [];

  await iteratePaginatedCollection(
    options,
    endpoint,
    warnings,
    (items) => {
      for (const item of items) {
        const testRecord = normalizeTestRecord(item);
        if (!testRecord) {
          continue;
        }
        tests.push(testRecord);
        if (testRecord.requirementIds) {
          for (const requirementId of testRecord.requirementIds) {
            traces.push({ fromId: testRecord.id, toId: requirementId, type: 'verifies' });
          }
        }
        attachmentDescriptors.push(...extractTestAttachments(item, testRecord.id));
      }
    },
    (url) => {
      if (options.testOutcomeFilter && !url.searchParams.has('outcome')) {
        url.searchParams.set('outcome', options.testOutcomeFilter);
      }
    },
  );

  return { tests, traces };
};

const fetchBuilds = async (
  options: AzureDevOpsClientOptions,
  warnings: string[],
): Promise<RemoteBuildRecord[]> => {
  const endpoint = options.buildsEndpoint ?? defaultEndpoints.builds;
  const builds: RemoteBuildRecord[] = [];

  await iteratePaginatedCollection(options, endpoint, warnings, (items) => {
    for (const item of items) {
      const build = normalizeBuildRecord(item);
      if (build) {
        builds.push(build);
      }
    }
  });

  return builds;
};

export const fetchAzureDevOpsArtifacts = async (
  options: AzureDevOpsClientOptions,
): Promise<ParseResult<AzureDevOpsArtifactBundle>> => {
  const warnings: string[] = [];
  const attachmentDescriptors: AttachmentDescriptor[] = [];

  const [requirements, { tests, traces }, builds] = await Promise.all([
    fetchRequirements(options, warnings, attachmentDescriptors),
    fetchTests(options, warnings, attachmentDescriptors),
    fetchBuilds(options, warnings),
  ]);

  const attachments: AzureDevOpsAttachmentMetadata[] = [];
  const seenAttachmentKeys = new Set<string>();

  for (const descriptor of attachmentDescriptors) {
    const key = `${descriptor.artifactType}:${descriptor.artifactId}:${descriptor.id}`;
    if (seenAttachmentKeys.has(key)) {
      continue;
    }
    seenAttachmentKeys.add(key);

    const absoluteUrl = descriptor.url
      ? new URL(descriptor.url, options.baseUrl).toString()
      : resolveAttachmentUrl(options, descriptor).toString();

    const metadata = await downloadAttachment(absoluteUrl, descriptor, options, warnings);
    if (!metadata) {
      continue;
    }

    attachments.push({
      id: descriptor.id,
      artifactId: descriptor.artifactId,
      artifactType: descriptor.artifactType,
      filename: descriptor.filename,
      url: absoluteUrl,
      bytes: metadata.bytes,
      contentType: metadata.contentType,
      sha256: metadata.sha256,
    });
  }

  return {
    data: { requirements, tests, builds, traces, attachments },
    warnings,
  };
};

