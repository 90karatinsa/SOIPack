import { createWriteStream } from 'fs';
import { promises as fsPromises } from 'fs';
import http from 'http';
import https from 'https';
import path from 'path';
import { createHash, randomUUID } from 'crypto';
import { Readable, Transform } from 'stream';
import { pipeline as streamPipeline } from 'stream/promises';
import { setTimeout as delay } from 'timers/promises';

import type {
  ParseResult,
  RemoteRequirementRecord,
  RemoteTestRecord,
  RemoteDesignRecord,
} from './types';

export interface DoorsNextRelationship {
  fromId: string;
  toId: string;
  type: string;
}

export interface DoorsNextArtifactBundle {
  requirements: RemoteRequirementRecord[];
  tests: RemoteTestRecord[];
  designs: RemoteDesignRecord[];
  relationships: DoorsNextRelationship[];
  attachments: DoorsNextAttachmentMetadata[];
  etagCache: Record<string, string>;
}

export interface DoorsNextHttpRequest {
  url: URL | string;
  method?: 'GET' | 'POST';
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
}

export interface DoorsNextHttpResponse {
  status: number;
  headers: Record<string, string>;
  body?: unknown;
}

export type DoorsNextRequestHandler = (options: DoorsNextHttpRequest) => Promise<DoorsNextHttpResponse>;

export interface DoorsNextOAuthOptions {
  tokenUrl: string;
  clientId: string;
  clientSecret: string;
  scope?: string;
}

export interface DoorsNextClientOptions {
  baseUrl: string;
  projectArea: string;
  pageSize?: number;
  maxPages?: number;
  timeoutMs?: number;
  username?: string;
  password?: string;
  accessToken?: string;
  oauth?: DoorsNextOAuthOptions;
  request?: DoorsNextRequestHandler;
  etagCache?: Map<string, string> | Record<string, string>;
  attachmentsDir?: string;
  attachmentPageSize?: number;
  attachmentMaxPages?: number;
  maxAttachmentBytes?: number;
  rateLimitDelaysMs?: number[];
  attachmentDownload?: DoorsNextAttachmentDownloadHandler;
}

const DEFAULT_PAGE_SIZE = 200;
const DEFAULT_MAX_PAGES = 50;
const JSON_CONTENT_TYPE = /application\/(json|ld\+json)/iu;
const DEFAULT_ATTACHMENT_PAGE_SIZE = 50;
const DEFAULT_ATTACHMENT_MAX_PAGES = 25;
const DEFAULT_ATTACHMENT_MAX_BYTES = 25 * 1024 * 1024;
const DEFAULT_RATE_LIMIT_DELAYS_MS = [250, 500, 1000, 2000];

const sanitizeSegment = (value: string, fallback: string): string => {
  const normalized = value.replace(/[^A-Za-z0-9._-]/gu, '_');
  return normalized.length > 0 ? normalized : fallback;
};

const normalizeRelativePath = (filePath: string): string => {
  const absolute = path.resolve(filePath);
  const relative = path.relative(process.cwd(), absolute);
  const normalized = relative.length > 0 ? relative : '.';
  return normalized.split(path.sep).join('/');
};

const ensureDirectory = async (directory: string): Promise<void> => {
  await fsPromises.mkdir(directory, { recursive: true });
};

const parseRetryAfterHeader = (headers: Record<string, string>): number | undefined => {
  const value = headers['retry-after'];
  if (!value) {
    return undefined;
  }
  const numeric = Number.parseFloat(value);
  if (Number.isFinite(numeric) && numeric >= 0) {
    return numeric * 1000;
  }
  const absolute = Date.parse(value);
  if (!Number.isNaN(absolute)) {
    const delta = absolute - Date.now();
    return delta > 0 ? delta : undefined;
  }
  return undefined;
};

export interface DoorsNextAttachmentMetadata {
  id?: string;
  artifactId: string;
  title?: string;
  filename: string;
  contentType?: string;
  size?: number;
  path: string;
  sha256: string;
}

interface DoorsNextAttachmentDescriptor {
  id?: string;
  title?: string;
  filename: string;
  url: string;
  contentType?: string;
  size?: number;
}

export interface DoorsNextAttachmentDownloadOptions {
  url: URL;
  headers: Record<string, string>;
  timeoutMs?: number;
}

export interface DoorsNextAttachmentDownloadResult {
  status: number;
  headers: Record<string, string>;
  stream?: NodeJS.ReadableStream;
  body?: Buffer | string;
}

export type DoorsNextAttachmentDownloadHandler = (
  options: DoorsNextAttachmentDownloadOptions,
) => Promise<DoorsNextAttachmentDownloadResult>;

const toUrl = (target: URL | string): URL => (target instanceof URL ? target : new URL(target));

const normalizeHeaders = (headers: http.IncomingHttpHeaders): Record<string, string> => {
  const normalized: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (Array.isArray(value)) {
      if (value.length > 0 && value[0]) {
        normalized[key.toLowerCase()] = value[0];
      }
      continue;
    }
    if (typeof value === 'string' && value) {
      normalized[key.toLowerCase()] = value;
    }
  }
  return normalized;
};

const defaultRequest: DoorsNextRequestHandler = async (options: DoorsNextHttpRequest) =>
  await new Promise<DoorsNextHttpResponse>((resolve, reject) => {
    const url = toUrl(options.url);
    const client = url.protocol === 'https:' ? https : http;
    const request = client.request(
      url,
      {
        method: options.method ?? 'GET',
        headers: options.headers,
        timeout: options.timeoutMs ?? 15000,
      },
      (response) => {
        const { statusCode = 0 } = response;
        const chunks: Buffer[] = [];

        response.on('data', (chunk) => {
          chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
        });

        response.on('end', () => {
          const headers: Record<string, string> = {};
          for (const [name, value] of Object.entries(response.headers)) {
            if (Array.isArray(value)) {
              if (value.length > 0 && value[0]) {
                headers[name.toLowerCase()] = value[0];
              }
            } else if (typeof value === 'string' && value) {
              headers[name.toLowerCase()] = value;
            }
          }

          const payload = Buffer.concat(chunks).toString('utf8');
          const contentType = headers['content-type'] ?? '';
          let body: unknown;

          if (payload) {
            if (JSON_CONTENT_TYPE.test(contentType)) {
              try {
                body = JSON.parse(payload) as unknown;
              } catch (error) {
                reject(new Error(`Unable to parse JSON response from ${url.toString()}: ${(error as Error).message}`));
                return;
              }
            } else {
              body = payload;
            }
          }

          resolve({ status: statusCode, headers, body });
        });
      },
    );

    request.on('error', (error) => {
      reject(error);
    });

    if (options.body) {
      request.write(options.body);
    }

    request.end();
  });

class AttachmentSizeLimitError extends Error {
  constructor(public readonly limit: number) {
    super(`Attachment exceeded the maximum allowed size of ${limit} bytes.`);
    this.name = 'AttachmentSizeLimitError';
  }
}

const defaultAttachmentDownload: DoorsNextAttachmentDownloadHandler = async (
  options: DoorsNextAttachmentDownloadOptions,
): Promise<DoorsNextAttachmentDownloadResult> =>
  await new Promise<DoorsNextAttachmentDownloadResult>((resolve, reject) => {
    const client = options.url.protocol === 'https:' ? https : http;
    const request = client.request(
      options.url,
      {
        method: 'GET',
        headers: options.headers,
        timeout: options.timeoutMs ?? 15000,
      },
      (response) => {
        const status = response.statusCode ?? 0;
        const headers = normalizeHeaders(response.headers);
        if (status < 200 || status >= 300) {
          response.resume();
          resolve({ status, headers });
          return;
        }
        resolve({ status, headers, stream: response });
      },
    );

    request.on('error', (error) => {
      reject(error);
    });

    request.end();
  });

const removeIfExists = async (targetPath: string): Promise<void> => {
  try {
    await fsPromises.rm(targetPath, { force: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
      throw error;
    }
  }
};

const writeAttachmentToFile = async (
  stream: NodeJS.ReadableStream,
  targetPath: string,
  maxBytes: number,
): Promise<{ sha256: string; bytes: number }> => {
  const tempPath = `${targetPath}.${randomUUID()}.tmp`;
  await ensureDirectory(path.dirname(targetPath));
  await removeIfExists(tempPath);
  const hash = createHash('sha256');
  let totalBytes = 0;
  const tee = new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      hash.update(chunk);
      totalBytes += chunk.length;
      if (totalBytes > maxBytes) {
        callback(new AttachmentSizeLimitError(maxBytes));
        return;
      }
      callback(undefined, chunk);
    },
  });

  try {
    await streamPipeline(stream, tee, createWriteStream(tempPath));
    await removeIfExists(targetPath);
    await fsPromises.rename(tempPath, targetPath);
    return { sha256: hash.digest('hex'), bytes: totalBytes };
  } catch (error) {
    await removeIfExists(tempPath).catch(() => undefined);
    throw error;
  }
};

const toHeaderValue = (headers: Record<string, string>, key: string): string | undefined => {
  const normalizedKey = key.toLowerCase();
  return headers[normalizedKey];
};

const toMap = (
  cache: Map<string, string> | Record<string, string> | undefined,
): { map: Map<string, string>; provided: Map<string, string> | Record<string, string> | undefined } => {
  if (!cache) {
    return { map: new Map<string, string>(), provided: undefined };
  }
  if (cache instanceof Map) {
    return { map: cache, provided: cache };
  }
  return { map: new Map(Object.entries(cache)), provided: cache };
};

const flushMapToRecord = (
  source: Map<string, string>,
  target: Record<string, string> | undefined,
): Record<string, string> => {
  const snapshot = Object.fromEntries(source.entries());
  if (target) {
    for (const [key, value] of Object.entries(snapshot)) {
      target[key] = value;
    }
  }
  return snapshot;
};

const normalizeIdentifier = (value: string): string => {
  const trimmed = value.trim();
  if (!trimmed) {
    return '';
  }
  const hashIndex = trimmed.lastIndexOf('#');
  if (hashIndex >= 0 && hashIndex < trimmed.length - 1) {
    return trimmed.slice(hashIndex + 1);
  }
  const isUrlLike = trimmed.includes('://') || trimmed.startsWith('urn:');
  if (isUrlLike) {
    const slashIndex = trimmed.lastIndexOf('/');
    if (slashIndex >= 0 && slashIndex < trimmed.length - 1) {
      return trimmed.slice(slashIndex + 1);
    }
  }
  return trimmed;
};

const extractString = (value: unknown): string | undefined => {
  if (typeof value === 'string') {
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  }
  return undefined;
};

const extractNumber = (value: unknown): number | undefined => {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === 'string') {
    const parsed = Number.parseFloat(value);
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }
  return undefined;
};

const extractTargets = (value: unknown): string[] => {
  const values = Array.isArray(value) ? value : value ? [value] : [];
  const targets: string[] = [];
  for (const entry of values) {
    if (!entry) {
      continue;
    }
    if (typeof entry === 'string') {
      const normalized = normalizeIdentifier(entry);
      if (normalized) {
        targets.push(normalized);
      }
      continue;
    }
    if (typeof entry === 'object') {
      const candidate =
        extractString((entry as Record<string, unknown>).id) ??
        extractString((entry as Record<string, unknown>).identifier) ??
        extractString((entry as Record<string, unknown>).resource) ??
        extractString((entry as Record<string, unknown>).uri) ??
        extractString((entry as Record<string, unknown>).about) ??
        extractString((entry as Record<string, unknown>)['rdf:resource']);
      if (candidate) {
        targets.push(normalizeIdentifier(candidate));
      }
    }
  }
  return targets;
};

const extractMembers = (payload: unknown): Record<string, unknown>[] => {
  if (!payload) {
    return [];
  }
  if (Array.isArray(payload)) {
    return payload as Record<string, unknown>[];
  }
  if (typeof payload === 'object') {
    const container = payload as Record<string, unknown>;
    for (const key of ['members', 'member', 'resources', 'rdf:member']) {
      const value = container[key];
      if (Array.isArray(value)) {
        return value as Record<string, unknown>[];
      }
    }
  }
  return [];
};

const extractNextLink = (payload: unknown): string | undefined => {
  if (!payload || typeof payload !== 'object') {
    return undefined;
  }
  const container = payload as Record<string, unknown>;
  const candidates = [
    container.next,
    container.nextPage,
    container.nextPageUrl,
    container['oslc:nextPage'],
    container['oslc:next'],
  ];
  for (const candidate of candidates) {
    const value = extractString(candidate);
    if (value) {
      return value;
    }
  }
  const links = container.links as Record<string, unknown> | undefined;
  if (links) {
    const next = extractString(links.next) ?? extractString(links.nextPage);
    if (next) {
      return next;
    }
  }
  return undefined;
};

const classifyResource = (resource: Record<string, unknown>): 'requirement' | 'test' | 'design' | undefined => {
  const rawType =
    extractString(resource.type) ??
    extractString(resource.kind) ??
    extractString(resource.category) ??
    extractString(resource['dcterms:type']) ??
    extractString(resource['oslc:shortTitle']);

  if (rawType) {
    const normalized = rawType.toLowerCase();
    if (normalized.includes('test')) {
      return 'test';
    }
    if (normalized.includes('design') || normalized.includes('model')) {
      return 'design';
    }
    if (normalized.includes('require')) {
      return 'requirement';
    }
  }

  const resourceTypes = resource['rdf:type'];
  if (resourceTypes) {
    const candidates = Array.isArray(resourceTypes) ? resourceTypes : [resourceTypes];
    for (const candidate of candidates) {
      const value = extractString(candidate);
      if (!value) {
        continue;
      }
      const normalized = value.toLowerCase();
      if (normalized.includes('test')) {
        return 'test';
      }
      if (normalized.includes('design') || normalized.includes('model')) {
        return 'design';
      }
      if (normalized.includes('require')) {
        return 'requirement';
      }
    }
  }

  return undefined;
};

const collectRelationships = (
  resourceId: string,
  rawLinks: Record<string, unknown> | undefined,
  accumulator: DoorsNextRelationship[],
  requirementTargets: Set<string>,
  codeTargets: Set<string>,
): void => {
  if (!rawLinks) {
    return;
  }

  for (const [key, value] of Object.entries(rawLinks)) {
    const targets = extractTargets(value);
    if (targets.length === 0) {
      continue;
    }

    const linkType = key.replace(/^oslc:/u, '');
    targets.forEach((target) => {
      accumulator.push({ fromId: resourceId, toId: target, type: linkType });
    });

    const lower = linkType.toLowerCase();
    if (lower.includes('require') || lower.includes('satisf') || lower.includes('verify') || lower.includes('validate')) {
      targets.forEach((target) => requirementTargets.add(target));
    }
    if (lower.includes('implement') || lower.includes('code') || lower.includes('model')) {
      targets.forEach((target) => codeTargets.add(target));
    }
  }
};

const toRequirementRecord = (resource: Record<string, unknown>, warnings: string[]): RemoteRequirementRecord | undefined => {
  const id = extractString(resource.id) ?? extractString(resource.identifier);
  if (!id) {
    warnings.push('Skipping DOORS Next artifact with missing identifier.');
    return undefined;
  }
  const title = extractString(resource.title) ?? extractString(resource.name) ?? id;
  const description = extractString(resource.description) ?? extractString(resource['dcterms:description']);
  const status = extractString(resource.status) ?? extractString(resource['oslc_rm:status']);
  const type = extractString(resource.type) ?? extractString(resource.kind);
  const url = extractString(resource.about) ?? extractString(resource.resource) ?? extractString(resource.uri);

  return {
    id,
    title,
    description,
    status,
    type,
    url,
  };
};

const toTestRecord = (resource: Record<string, unknown>, warnings: string[]): RemoteTestRecord | undefined => {
  const id = extractString(resource.id) ?? extractString(resource.identifier);
  if (!id) {
    warnings.push('Skipping DOORS Next test artifact with missing identifier.');
    return undefined;
  }
  const name = extractString(resource.title) ?? extractString(resource.name) ?? id;
  const status = extractString(resource.status) ?? 'unknown';
  const className = extractString(resource.className) ?? extractString(resource.category);
  const duration = extractNumber(resource.durationMs ?? resource.duration ?? resource.elapsedMs);
  const errorMessage = extractString(resource.errorMessage ?? resource['oslc:testError']);
  const requirementIds = extractTargets(resource.requirements ?? resource.validates ?? resource.verifies);
  const startedAt = extractString(resource.startedAt ?? resource['dcterms:created']);
  const finishedAt = extractString(resource.finishedAt ?? resource['dcterms:modified']);

  return {
    id,
    name,
    className,
    status,
    durationMs: duration,
    errorMessage,
    requirementIds: requirementIds.length > 0 ? requirementIds : undefined,
    startedAt,
    finishedAt,
  };
};

const toDesignRecord = (
  resource: Record<string, unknown>,
  warnings: string[],
  relationships: DoorsNextRelationship[],
): RemoteDesignRecord | undefined => {
  const id = extractString(resource.id) ?? extractString(resource.identifier);
  if (!id) {
    warnings.push('Skipping DOORS Next design artifact with missing identifier.');
    return undefined;
  }
  const title = extractString(resource.title) ?? extractString(resource.name) ?? id;
  const description = extractString(resource.description) ?? extractString(resource['dcterms:description']);
  const status = extractString(resource.status) ?? extractString(resource['oslc:status']);
  const type = extractString(resource.type) ?? extractString(resource.kind);
  const url = extractString(resource.about) ?? extractString(resource.resource) ?? extractString(resource.uri);

  const requirementTargets = new Set<string>(
    extractTargets(
      resource.requirements ?? resource.requirementRefs ?? resource.satisfies ?? resource.implementsRequirements,
    ),
  );
  const codeTargets = new Set<string>(
    extractTargets(resource.codeRefs ?? resource.codeLinks ?? resource.implements ?? resource.executes),
  );

  collectRelationships(id, resource.links as Record<string, unknown> | undefined, relationships, requirementTargets, codeTargets);

  return {
    id,
    title,
    description,
    status,
    type,
    url,
    requirementIds: requirementTargets.size > 0 ? Array.from(requirementTargets) : undefined,
    codeRefs: codeTargets.size > 0 ? Array.from(codeTargets) : undefined,
  };
};

const toAttachmentDescriptor = (
  artifactId: string,
  resource: Record<string, unknown>,
  warnings: string[],
): DoorsNextAttachmentDescriptor | undefined => {
  const id =
    extractString(resource.id) ??
    extractString(resource.identifier) ??
    extractString(resource['dcterms:identifier']);

  const title =
    extractString(resource.title) ??
    extractString(resource.name) ??
    extractString(resource.label) ??
    extractString(resource['dcterms:title']);

  const rawFileName =
    extractString(resource.fileName) ??
    extractString(resource.filename) ??
    extractString(resource.file) ??
    extractString(resource.label) ??
    title ??
    id ??
    undefined;

  const filename = rawFileName && rawFileName.trim().length > 0 ? rawFileName.trim() : `${artifactId}-attachment`;

  const url =
    extractString(resource.url) ??
    extractString(resource.contentUrl) ??
    extractString(resource.downloadUrl) ??
    extractString(resource.location) ??
    extractString(resource['oslc:download']) ??
    extractString(resource['rdf:resource']);

  if (!url) {
    const label = id ?? title ?? filename;
    warnings.push(`DOORS Next attachment ${label} for artifact ${artifactId} skipped due to missing download URL.`);
    return undefined;
  }

  const contentType =
    extractString(resource.contentType) ??
    extractString(resource.mimeType) ??
    extractString(resource['dcterms:format']) ??
    extractString(resource['oslc:mediaType']);

  const size = extractNumber(resource.size ?? resource.length ?? resource.bytes ?? resource['oslc:size']);

  return {
    id,
    title,
    filename,
    url,
    contentType,
    size: size && size >= 0 ? size : undefined,
  };
};

const createCollectionUrl = (options: DoorsNextClientOptions): URL => {
  const path = `/rm/${encodeURIComponent(options.projectArea)}/artifacts`;
  const url = new URL(path, options.baseUrl);
  url.searchParams.set('oslc.pageSize', String(options.pageSize ?? DEFAULT_PAGE_SIZE));
  return url;
};

const createAttachmentCollectionUrl = (
  options: DoorsNextClientOptions,
  artifactId: string,
): URL => {
  const basePath = `/rm/${encodeURIComponent(options.projectArea)}/artifacts/${encodeURIComponent(artifactId)}/attachments`;
  const url = new URL(basePath, options.baseUrl);
  url.searchParams.set('oslc.pageSize', String(options.attachmentPageSize ?? DEFAULT_ATTACHMENT_PAGE_SIZE));
  return url;
};

const encodeBasicAuth = (username: string, password: string): string =>
  Buffer.from(`${username}:${password}`).toString('base64');

const requestAccessToken = async (
  request: DoorsNextRequestHandler,
  oauth: DoorsNextOAuthOptions,
  timeoutMs: number | undefined,
): Promise<string | undefined> => {
  const body = new URLSearchParams({ grant_type: 'client_credentials' });
  if (oauth.scope) {
    body.set('scope', oauth.scope);
  }

  const response = await request({
    url: oauth.tokenUrl,
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: `Basic ${encodeBasicAuth(oauth.clientId, oauth.clientSecret)}`,
    },
    body: body.toString(),
    timeoutMs,
  });

  if (response.status < 200 || response.status >= 300) {
    return undefined;
  }

  if (!response.body || typeof response.body !== 'object') {
    return undefined;
  }

  const token = extractString((response.body as Record<string, unknown>).access_token);
  return token;
};

export const fetchDoorsNextArtifacts = async (
  options: DoorsNextClientOptions,
): Promise<ParseResult<DoorsNextArtifactBundle>> => {
  const warnings: string[] = [];
  const { map: etagMap, provided: providedCache } = toMap(options.etagCache);
  const request = options.request ?? defaultRequest;
  const relationships: DoorsNextRelationship[] = [];
  const requirements: RemoteRequirementRecord[] = [];
  const tests: RemoteTestRecord[] = [];
  const designs: RemoteDesignRecord[] = [];
  const attachments: DoorsNextAttachmentMetadata[] = [];
  const seenAttachmentIds = new Set<string>();
  const processedAttachmentArtifacts = new Set<string>();
  const rateLimitDelays = options.rateLimitDelaysMs ?? DEFAULT_RATE_LIMIT_DELAYS_MS;
  const attachmentDownload = options.attachmentDownload ?? defaultAttachmentDownload;
  const attachmentsDir = path.resolve(options.attachmentsDir ?? path.join(process.cwd(), 'attachments', 'doorsNext'));
  const attachmentMaxPages = options.attachmentMaxPages ?? DEFAULT_ATTACHMENT_MAX_PAGES;
  const maxAttachmentBytes = options.maxAttachmentBytes ?? DEFAULT_ATTACHMENT_MAX_BYTES;
  let warnedBearerFallback = false;
  let warnedBearerMissingFallback = false;

  let bearerToken = options.accessToken;
  if (!bearerToken && options.oauth) {
    bearerToken = await requestAccessToken(request, options.oauth, options.timeoutMs);
    if (!bearerToken && options.username && options.password) {
      if (!warnedBearerFallback) {
        warnings.push('DOORS Next OAuth token request failed, falling back to basic authentication.');
        warnedBearerFallback = true;
      }
    }
  }

  const applyAuthHeader = (headers: Record<string, string>): void => {
    if (bearerToken) {
      headers.Authorization = `Bearer ${bearerToken}`;
    } else if (options.username && options.password) {
      headers.Authorization = `Basic ${encodeBasicAuth(options.username, options.password)}`;
    }
  };

  const handleUnauthorized = async (): Promise<boolean> => {
    if (bearerToken && options.oauth) {
      const refreshed = await requestAccessToken(request, options.oauth, options.timeoutMs);
      if (refreshed) {
        bearerToken = refreshed;
        return true;
      }
    }

    if (bearerToken && options.username && options.password) {
      if (!warnedBearerFallback) {
        warnings.push('DOORS Next bearer token rejected, retrying with basic authentication.');
        warnedBearerFallback = true;
      }
      bearerToken = undefined;
      return true;
    }

    if (bearerToken && !warnedBearerMissingFallback) {
      warnings.push('DOORS Next bearer token rejected and no fallback authentication configured.');
      warnedBearerMissingFallback = true;
      bearerToken = undefined;
      return false;
    }

    return false;
  };

  const downloadAttachmentDescriptor = async (
    artifactId: string,
    descriptor: DoorsNextAttachmentDescriptor,
  ): Promise<DoorsNextAttachmentMetadata | undefined> => {
    let downloadUrl: URL;
    try {
      downloadUrl = new URL(descriptor.url, options.baseUrl);
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      warnings.push(
        `Skipping DOORS Next attachment ${descriptor.filename} for artifact ${artifactId}: invalid URL (${reason}).`,
      );
      return undefined;
    }

    const sanitizedArtifact = sanitizeSegment(artifactId, 'artifact');
    const sanitizedFilename = sanitizeSegment(descriptor.filename, 'attachment');
    const targetDir = path.resolve(attachmentsDir, sanitizedArtifact);
    const targetPath = path.resolve(targetDir, sanitizedFilename);

    let attempts = 0;
    let lastError: unknown;

    while (attempts < rateLimitDelays.length + 3) {
      const headers: Record<string, string> = {};
      applyAuthHeader(headers);

      let result: DoorsNextAttachmentDownloadResult;
      try {
        result = await attachmentDownload({ url: downloadUrl, headers, timeoutMs: options.timeoutMs });
      } catch (error) {
        lastError = error;
        attempts += 1;
        const delayMs = rateLimitDelays[Math.min(attempts - 1, rateLimitDelays.length - 1)] ?? 0;
        if (delayMs > 0) {
          await delay(delayMs);
        }
        continue;
      }

      if (result.status === 401) {
        attempts += 1;
        const retried = await handleUnauthorized();
        if (retried) {
          continue;
        }
        warnings.push(
          `DOORS Next attachment ${descriptor.filename} for artifact ${artifactId} returned 401 and could not be downloaded.`,
        );
        return undefined;
      }

      if (result.status === 429) {
        attempts += 1;
        const retryDelay =
          parseRetryAfterHeader(result.headers) ?? rateLimitDelays[Math.min(attempts - 1, rateLimitDelays.length - 1)] ?? 0;
        if (retryDelay > 0) {
          await delay(retryDelay);
        }
        continue;
      }

      if (result.status < 200 || result.status >= 300) {
        warnings.push(
          `DOORS Next attachment ${descriptor.filename} for artifact ${artifactId} failed with status ${result.status}.`,
        );
        return undefined;
      }

      const stream =
        result.stream ??
        (result.body !== undefined
          ? Readable.from([Buffer.isBuffer(result.body) ? result.body : Buffer.from(result.body)])
          : undefined);

      if (!stream) {
        warnings.push(
          `DOORS Next attachment ${descriptor.filename} for artifact ${artifactId} did not include a response body.`,
        );
        return undefined;
      }

      const contentLengthHeader = result.headers['content-length'];
      if (contentLengthHeader) {
        const contentLength = Number.parseInt(contentLengthHeader, 10);
        if (Number.isFinite(contentLength) && contentLength > maxAttachmentBytes) {
          stream.resume();
          warnings.push(
            `DOORS Next attachment ${descriptor.filename} for artifact ${artifactId} exceeds the ${maxAttachmentBytes} byte limit; download skipped.`,
          );
          return undefined;
        }
      }

      try {
        const { sha256, bytes } = await writeAttachmentToFile(stream, targetPath, maxAttachmentBytes);
        return {
          id: descriptor.id,
          artifactId,
          title: descriptor.title,
          filename: descriptor.filename,
          contentType: descriptor.contentType,
          size: bytes,
          path: normalizeRelativePath(targetPath),
          sha256,
        };
      } catch (error) {
        if (error instanceof AttachmentSizeLimitError) {
          warnings.push(
            `DOORS Next attachment ${descriptor.filename} for artifact ${artifactId} exceeded the ${error.limit} byte limit; download skipped.`,
          );
          return undefined;
        }

        lastError = error;
        attempts += 1;
        const delayMs = rateLimitDelays[Math.min(attempts - 1, rateLimitDelays.length - 1)] ?? 0;
        if (delayMs > 0) {
          await delay(delayMs);
        }
      }
    }

    if (lastError) {
      const reason = lastError instanceof Error ? lastError.message : String(lastError);
      warnings.push(
        `Failed to download DOORS Next attachment ${descriptor.filename} for artifact ${artifactId}: ${reason}.`,
      );
    }

    return undefined;
  };

  const fetchAttachmentsForArtifact = async (artifactId: string): Promise<void> => {
    let currentUrl: URL | undefined = createAttachmentCollectionUrl(options, artifactId);
    let page = 0;

    while (currentUrl && page < attachmentMaxPages) {
      let response: DoorsNextHttpResponse;
      let attempts = 0;

      while (true) {
        const headers: Record<string, string> = { Accept: 'application/json' };
        applyAuthHeader(headers);

        response = await request({ url: currentUrl, headers, timeoutMs: options.timeoutMs });

        if (response.status === 401) {
          attempts += 1;
          const retried = await handleUnauthorized();
          if (retried && attempts < 3) {
            continue;
          }
        }

        if (response.status === 429) {
          attempts += 1;
          const retryDelay =
            parseRetryAfterHeader(response.headers) ??
            rateLimitDelays[Math.min(attempts - 1, rateLimitDelays.length - 1)] ??
            0;
          if (retryDelay > 0) {
            await delay(retryDelay);
          }
          if (attempts < rateLimitDelays.length + 3) {
            continue;
          }
        }

        break;
      }

      if (response.status === 401) {
        warnings.push(`DOORS Next attachments for artifact ${artifactId} failed with status 401.`);
        return;
      }

      if (response.status === 429) {
        warnings.push(`DOORS Next attachments for artifact ${artifactId} returned repeated 429 responses; aborting.`);
        return;
      }

      if (response.status < 200 || response.status >= 300) {
        warnings.push(
          `DOORS Next attachments for artifact ${artifactId} request failed with status ${response.status}.`,
        );
        return;
      }

      const members = extractMembers(response.body);
      if (members.length === 0) {
        break;
      }

      for (const entry of members) {
        if (!entry || typeof entry !== 'object') {
          continue;
        }
        const descriptor = toAttachmentDescriptor(artifactId, entry as Record<string, unknown>, warnings);
        if (!descriptor) {
          continue;
        }
        if (descriptor.id && seenAttachmentIds.has(descriptor.id)) {
          continue;
        }

        const metadata = await downloadAttachmentDescriptor(artifactId, descriptor);
        if (!metadata) {
          continue;
        }

        if (descriptor.id) {
          seenAttachmentIds.add(descriptor.id);
        }

        attachments.push(metadata);
      }

      const next = extractNextLink(response.body);
      if (!next) {
        break;
      }
      currentUrl = new URL(next, currentUrl);
      page += 1;
    }

    if (page >= attachmentMaxPages) {
      warnings.push(
        `DOORS Next attachments for artifact ${artifactId} truncated after ${attachmentMaxPages} pages.`,
      );
    }
  };

  let currentUrl: URL | undefined = createCollectionUrl(options);
  let pageCount = 0;
  const maxPages = options.maxPages ?? DEFAULT_MAX_PAGES;

  while (currentUrl && pageCount < maxPages) {
    const cacheKey = currentUrl.toString();
    const cachedEtag = etagMap.get(cacheKey);
    let response: DoorsNextHttpResponse;
    let attempts = 0;

    while (true) {
      const headers: Record<string, string> = { Accept: 'application/json' };
      if (cachedEtag) {
        headers['If-None-Match'] = cachedEtag;
      }
      applyAuthHeader(headers);

      response = await request({ url: currentUrl, headers, timeoutMs: options.timeoutMs });

      if (response.status === 401) {
        attempts += 1;
        const retried = await handleUnauthorized();
        if (retried && attempts < 3) {
          continue;
        }
      }

      break;
    }

    if (response.status === 401) {
      warnings.push(`DOORS Next request for ${currentUrl.toString()} failed with status 401.`);
      break;
    }

    if (response.status === 304) {
      break;
    }

    if (response.status < 200 || response.status >= 300) {
      warnings.push(`DOORS Next request failed with status ${response.status}.`);
      break;
    }

    const etag = toHeaderValue(response.headers, 'etag');
    if (etag) {
      etagMap.set(cacheKey, etag);
    }

    const members = extractMembers(response.body);
    if (members.length === 0) {
      break;
    }

    for (const resource of members) {
      if (!resource || typeof resource !== 'object') {
        continue;
      }
      const record = resource as Record<string, unknown>;
      const resourceType = classifyResource(record);

      if (resourceType === 'requirement') {
        const requirement = toRequirementRecord(record, warnings);
        if (requirement) {
          collectRelationships(requirement.id, record.links as Record<string, unknown> | undefined, relationships, new Set(), new Set());
          requirements.push(requirement);
          if (!processedAttachmentArtifacts.has(requirement.id)) {
            await fetchAttachmentsForArtifact(requirement.id);
            processedAttachmentArtifacts.add(requirement.id);
          }
        }
        continue;
      }

      if (resourceType === 'test') {
        const testRecord = toTestRecord(record, warnings);
        if (testRecord) {
          collectRelationships(testRecord.id, record.links as Record<string, unknown> | undefined, relationships, new Set(), new Set());
          tests.push(testRecord);
          if (!processedAttachmentArtifacts.has(testRecord.id)) {
            await fetchAttachmentsForArtifact(testRecord.id);
            processedAttachmentArtifacts.add(testRecord.id);
          }
        }
        continue;
      }

      if (resourceType === 'design') {
        const designRecord = toDesignRecord(record, warnings, relationships);
        if (designRecord) {
          designs.push(designRecord);
        }
        continue;
      }
    }

    const next = extractNextLink(response.body);
    if (!next) {
      break;
    }
    currentUrl = new URL(next, currentUrl);
    pageCount += 1;
  }

  if (pageCount >= maxPages) {
    warnings.push(`DOORS Next pagination aborted after ${maxPages} pages.`);
  }

  const etagCache = flushMapToRecord(etagMap, providedCache instanceof Map ? undefined : (providedCache as Record<string, string> | undefined));

  return {
    data: {
      requirements,
      tests,
      designs,
      relationships,
      attachments,
      etagCache,
    },
    warnings,
  };
};
