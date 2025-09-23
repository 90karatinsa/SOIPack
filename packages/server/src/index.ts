import { constants as cryptoConstants, createHash, randomUUID } from 'crypto';
import fs, { promises as fsPromises } from 'fs';
import https from 'https';
import os from 'os';
import path from 'path';
import { pipeline as streamPipeline } from 'stream/promises';
import { TLSSocket } from 'tls';

import {
  AnalyzeOptions,
  ImportOptions,
  ImportWorkspace,
  LicenseError,
  normalizePackageName,
  PackOptions,
  ReportOptions,
  runAnalyze,
  runImport,
  runPack,
  runReport,
  verifyLicenseFile,
  type LicensePayload,
} from '@soipack/cli';
import {
  CertificationLevel,
  DEFAULT_LOCALE,
  SnapshotVersion,
  createSnapshotIdentifier,
  createSnapshotVersion,
  deriveFingerprint,
  freezeSnapshotVersion,
  resolveLocale,
  translate,
} from '@soipack/core';
import express, { Express, NextFunction, Request, Response } from 'express';
import expressRateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { JWTPayload, createLocalJWKSet, createRemoteJWKSet, jwtVerify } from 'jose';
import type { JSONWebKeySet } from 'jose';
import multer from 'multer';
import pino, { type Logger } from 'pino';
import { Counter, Gauge, Histogram, Registry, collectDefaultMetrics } from 'prom-client';


import { HttpError, toHttpError } from './errors';
import { createApiKeyAuthorizer } from './middleware/auth';
import { JobDetails, JobExecutionContext, JobKind, JobQueue, JobStatus, JobSummary } from './queue';
import { FileScanner, FileScanResult, createNoopScanner } from './scanner';
import {
  FileSystemStorage,
  PipelineDirectories,
  StorageProvider,
  UploadedFileMap,
} from './storage';

type FileMap = Record<string, Express.Multer.File[]>;

const sanitizeUploadFileName = (fileName: string): string => {
  const baseName = path.basename(fileName || 'upload');
  const normalized = baseName.replace(/[^a-zA-Z0-9._-]/g, '_');
  return normalized || 'upload';
};

const sanitizeDownloadFileName = (fileName: string, fallback: string): string => {
  const baseName = path.basename(fileName || fallback);
  const normalized = baseName.replace(/[^a-zA-Z0-9._-]/g, '_');
  return normalized || fallback;
};

const JOB_ID_PATTERN = /^[a-f0-9]{16}$/;

const assertJobId = (id: string): void => {
  if (!JOB_ID_PATTERN.test(id)) {
    throw new HttpError(
      400,
      'INVALID_REQUEST',
      translate('errors.request.invalidId', { locale: DEFAULT_LOCALE }),
      undefined,
      { messageKey: 'errors.request.invalidId' },
    );
  }
};

const buildContentDisposition = (fileName: string): string => {
  const fallback = fileName.replace(/"/g, "'");
  const encoded = encodeURIComponent(fileName);
  return `attachment; filename="${fallback}"; filename*=UTF-8''${encoded}`;
};

interface AuthContext {
  token: string;
  tenantId: string;
  subject: string;
  claims: JWTPayload;
  hasAdminScope: boolean;
}

const AUTH_CONTEXT_SYMBOL = Symbol('soipack:auth');

const setAuthContext = (req: Request, context: AuthContext): void => {
  Reflect.set(req, AUTH_CONTEXT_SYMBOL, context);
};

const getAuthContext = (req: Request): AuthContext => {
  const context = Reflect.get(req, AUTH_CONTEXT_SYMBOL) as AuthContext | undefined;
  if (!context) {
    throw new HttpError(500, 'AUTH_CONTEXT_MISSING', 'Kimlik doğrulama bağlamı bulunamadı.');
  }
  return context;
};

const REQUEST_CONTEXT_SYMBOL = Symbol('soipack:request');

interface RequestContext {
  id: string;
  startedAtNs: bigint;
}

const REQUEST_LOCALE_SYMBOL = Symbol('soipack:locale');

const SERVER_CONTEXT_SYMBOL = Symbol('soipack:server');

export interface ServerLifecycle {
  waitForIdle: () => Promise<void>;
  shutdown: () => Promise<void>;
  runTenantRetention: (tenantId: string) => Promise<RetentionStats[]>;
  runAllTenantRetention: () => Promise<Record<string, RetentionStats[]>>;
  logger: Logger;
}

const setRequestContext = (req: Request, context: RequestContext): void => {
  Reflect.set(req, REQUEST_CONTEXT_SYMBOL, context);
};

const getRequestContext = (req: Request): RequestContext | undefined =>
  Reflect.get(req, REQUEST_CONTEXT_SYMBOL) as RequestContext | undefined;

const setRequestLocale = (req: Request, locale: string): void => {
  Reflect.set(req, REQUEST_LOCALE_SYMBOL, locale);
};

const getRequestLocale = (req: Request): string => {
  const locale = Reflect.get(req, REQUEST_LOCALE_SYMBOL) as string | undefined;
  return locale ?? DEFAULT_LOCALE;
};

export const getServerLifecycle = (app: Express): ServerLifecycle => {
  const context = Reflect.get(app, SERVER_CONTEXT_SYMBOL) as ServerLifecycle | undefined;
  if (!context) {
    throw new Error('Sunucu yaşam döngüsü bağlamı henüz yapılandırılmadı.');
  }
  return context;
};

const getRouteLabel = (req: Request): string => {
  if (req.route && req.route.path) {
    const base = req.baseUrl ?? '';
    return `${base}${req.route.path}` || req.route.path;
  }
  if (req.baseUrl) {
    return req.baseUrl;
  }
  if (req.originalUrl) {
    return req.originalUrl.split('?')[0];
  }
  if (req.path) {
    return req.path;
  }
  return req.url ?? 'unknown';
};

const parseAcceptLanguage = (header: string | string[] | undefined): string | undefined => {
  if (!header) {
    return undefined;
  }
  const raw = Array.isArray(header) ? header.join(',') : header;
  const candidates = raw
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0)
    .map((entry) => {
      const [tag] = entry.split(';', 1);
      return tag?.trim();
    })
    .filter((entry): entry is string => Boolean(entry && entry.length > 0));
  return candidates[0];
};

const createScopedJobKey = (tenantId: string, jobId: string): string => `${tenantId}:${jobId}`;

const normalizeScopeList = (scopes?: string[]): string[] =>
  (scopes ?? []).map((scope) => scope.trim()).filter((scope) => scope.length > 0);

const DEFAULT_JSON_BODY_LIMIT_BYTES = 1 * 1024 * 1024;
const DEFAULT_LICENSE_MAX_BYTES = 512 * 1024;
const DEFAULT_LICENSE_HEADER_MAX_BYTES = Math.ceil((DEFAULT_LICENSE_MAX_BYTES * 4) / 3);
const DEFAULT_LICENSE_CACHE_MAX_ENTRIES = 1024;
const DEFAULT_LICENSE_CACHE_MAX_AGE_MS = 60 * 60 * 1000;
const DEFAULT_JWKS_TIMEOUT_MS = 5000;
const DEFAULT_JWKS_BACKOFF_MS = 250;
const DEFAULT_JWKS_MAX_RETRIES = 2;
const DEFAULT_JWKS_CACHE_MAX_AGE_MS = 5 * 60 * 1000;
const DEFAULT_JWKS_COOLDOWN_MS = 1000;
const PLAINTEXT_LISTEN_ERROR_MESSAGE =
  'SOIPack sunucusu yalnızca HTTPS ile başlatılabilir. createHttpsServer kullanın.';

const wait = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

class JwksFetchError extends Error {
  public readonly cause?: unknown;

  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = 'JwksFetchError';
    this.cause = cause;
  }
}

const findJwksFetchError = (error: unknown): JwksFetchError | undefined => {
  if (error instanceof JwksFetchError) {
    return error;
  }
  if (error && typeof error === 'object' && 'cause' in error) {
    const nested = (error as { cause?: unknown }).cause;
    if (nested) {
      return findJwksFetchError(nested);
    }
  }
  return undefined;
};

const KNOWN_TLS_ERROR_CODES = new Set([
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'SELF_SIGNED_CERT_IN_CHAIN',
  'CERT_HAS_EXPIRED',
  'DEPTH_ZERO_SELF_SIGNED_CERT',
]);

const KNOWN_TLS_ERROR_MESSAGE_PATTERNS = [
  'unable to verify the first certificate',
  'self signed certificate',
  'certificate has expired',
  'unable to get local issuer certificate',
];

interface TlsErrorInfo {
  code?: string;
  message: string;
}

const findTlsError = (error: unknown): TlsErrorInfo | undefined => {
  if (!error || typeof error !== 'object') {
    return undefined;
  }

  const candidate = error as { code?: unknown; message?: unknown; cause?: unknown };
  const code = typeof candidate.code === 'string' ? candidate.code : undefined;
  const message =
    typeof candidate.message === 'string'
      ? candidate.message
      : candidate instanceof Error
        ? candidate.message
        : undefined;

  if (code && (code.startsWith('ERR_TLS_') || KNOWN_TLS_ERROR_CODES.has(code))) {
    return { code, message: message ?? code };
  }

  if (typeof message === 'string') {
    const normalized = message.toLowerCase();
    if (KNOWN_TLS_ERROR_MESSAGE_PATTERNS.some((pattern) => normalized.includes(pattern))) {
      return { code, message };
    }
  }

  if ('cause' in candidate && candidate.cause) {
    return findTlsError(candidate.cause);
  }

  return undefined;
};

const DEFAULT_RATE_LIMIT_MAX_ENTRIES = 10_000;
const RATE_LIMIT_CLEANUP_INTERVAL_MS = 60_000;

const createSlidingWindowRateLimiter = (
  scope: 'ip' | 'tenant',
  options: RateLimitWindowConfig,
): ((key: string) => void) => {
  const counters = new Map<string, { count: number; resetAt: number }>();
  const maxEntries = Math.max(1, options.maxEntries ?? DEFAULT_RATE_LIMIT_MAX_ENTRIES);
  const cleanupInterval = Math.max(1, Math.min(options.windowMs, RATE_LIMIT_CLEANUP_INTERVAL_MS));
  let nextCleanupAt = Date.now() + cleanupInterval;

  const purgeExpired = (now: number) => {
    if (now < nextCleanupAt) {
      return;
    }
    for (const [key, entry] of counters) {
      if (entry.resetAt <= now) {
        counters.delete(key);
      }
    }
    nextCleanupAt = now + cleanupInterval;
  };

  const evictOldestEntry = () => {
    if (counters.size < maxEntries) {
      return;
    }
    let oldestKey: string | undefined;
    let oldestResetAt = Number.POSITIVE_INFINITY;
    for (const [key, entry] of counters) {
      if (entry.resetAt < oldestResetAt) {
        oldestResetAt = entry.resetAt;
        oldestKey = key;
      }
    }
    if (oldestKey !== undefined) {
      counters.delete(oldestKey);
    }
  };

  return (key: string) => {
    const now = Date.now();
    purgeExpired(now);

    const existing = counters.get(key);
    if (!existing || existing.resetAt <= now) {
      if (!existing) {
        evictOldestEntry();
      }
      counters.set(key, { count: 1, resetAt: now + options.windowMs });
      return;
    }

    if (existing.count >= options.max) {
      const retryAfterSeconds = Math.max(1, Math.ceil((existing.resetAt - now) / 1000));
      const details = {
        scope,
        retryAfterSeconds,
        limit: options.max,
        windowMs: options.windowMs,
      };
      if (scope === 'ip') {
        throw new HttpError(429, 'IP_RATE_LIMIT_EXCEEDED', 'Bu IP adresi için istek limiti aşıldı.', details);
      }
      throw new HttpError(429, 'TENANT_RATE_LIMIT_EXCEEDED', 'Kiracı için istek limiti aşıldı.', details);
    }

    existing.count += 1;
  };
};

const createRemoteJwkSetWithBounds = (config: JwtAuthConfig): ReturnType<typeof createRemoteJWKSet> => {
  if (!config.jwksUri) {
    throw new Error('jwksUri tanımlanmadan uzak JWKS yapılandırılamaz.');
  }
  const jwksUrl = new URL(config.jwksUri);
  if (jwksUrl.protocol !== 'https:') {
    throw new Error('jwksUri HTTPS protokolü kullanmalıdır.');
  }

  const remoteOptions = config.remoteJwks ?? {};
  const timeoutMs = remoteOptions.timeoutMs ?? DEFAULT_JWKS_TIMEOUT_MS;
  const maxRetries = remoteOptions.maxRetries ?? DEFAULT_JWKS_MAX_RETRIES;
  const backoffMs = remoteOptions.backoffMs ?? DEFAULT_JWKS_BACKOFF_MS;
  const cacheMaxAgeMs = remoteOptions.cacheMaxAgeMs ?? DEFAULT_JWKS_CACHE_MAX_AGE_MS;
  const cooldownMs = remoteOptions.cooldownMs ?? DEFAULT_JWKS_COOLDOWN_MS;

  const globalFetch = globalThis.fetch?.bind(globalThis);
  if (!globalFetch) {
    throw new Error('Küresel fetch API kullanılamıyor.');
  }

  const boundedFetch: typeof globalFetch = async (input, init) => {
    let attempt = 0;
    let lastError: unknown;

    while (attempt <= maxRetries) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const response = await globalFetch(input, { ...init, signal: controller.signal });
        clearTimeout(timeout);
        return response;
      } catch (error) {
        clearTimeout(timeout);
        lastError = error;
        if (attempt >= maxRetries) {
          throw new JwksFetchError('JWKS kaynağına ulaşılamadı.', error);
        }
        await wait(backoffMs * Math.max(1, attempt + 1));
      }
      attempt += 1;
    }

    throw new JwksFetchError('JWKS kaynağına ulaşılamadı.', lastError);
  };

  const remote = createRemoteJWKSet(jwksUrl, {
    cooldownDuration: cooldownMs,
    cacheMaxAge: cacheMaxAgeMs,
    timeoutDuration: timeoutMs,
  });

  return (async (protectedHeader, token) => {
    const previousFetch = globalThis.fetch;
    try {
      (globalThis as typeof globalThis & { fetch: typeof fetch }).fetch = boundedFetch as typeof fetch;
      return await remote(protectedHeader, token);
    } catch (error) {
      const jwksError = findJwksFetchError(error);
      if (jwksError) {
        throw jwksError;
      }
      throw error;
    } finally {
      (globalThis as typeof globalThis & { fetch: typeof fetch }).fetch = previousFetch;
    }
  }) as ReturnType<typeof createRemoteJWKSet>;
};

interface JobLicenseMetadata {
  hash: string;
  licenseId: string;
  issuedTo: string;
  issuedAt: string;
  expiresAt?: string | null;
  features?: string[];
}

interface HashEntry {
  key: string;
  value: string;
}

interface BaseJobMetadata {
  tenantId: string;
  id: string;
  hash: string;
  kind: 'import' | 'analyze' | 'report' | 'pack';
  createdAt: string;
  directory: string;
  params: Record<string, unknown>;
  license: JobLicenseMetadata;
}

interface ImportJobMetadata extends BaseJobMetadata {
  kind: 'import';
  warnings: string[];
  outputs: {
    workspacePath: string;
  };
}

interface AnalyzeJobMetadata extends BaseJobMetadata {
  kind: 'analyze';
  exitCode: number;
  outputs: {
    snapshotPath: string;
    tracePath: string;
    analysisPath: string;
  };
}

interface ReportJobMetadata extends BaseJobMetadata {
  kind: 'report';
  outputs: {
    directory: string;
    complianceHtml: string;
    complianceJson: string;
    traceHtml: string;
    gapsHtml: string;
    analysisPath: string;
    snapshotPath: string;
    tracesPath: string;
  };
}

interface PackJobMetadata extends BaseJobMetadata {
  kind: 'pack';
  outputs: {
    manifestPath: string;
    archivePath: string;
    manifestId: string;
  };
}

type JobMetadata = ImportJobMetadata | AnalyzeJobMetadata | ReportJobMetadata | PackJobMetadata;

interface ImportJobResult {
  warnings: string[];
  outputs: {
    directory: string;
    workspace: string;
  };
}

interface AnalyzeJobResult {
  exitCode: number;
  outputs: {
    directory: string;
    snapshot: string;
    traces: string;
    analysis: string;
  };
}

interface ReportJobResult {
  outputs: {
    directory: string;
    complianceHtml: string;
    complianceJson: string;
    traceHtml: string;
    gapsHtml: string;
    analysis: string;
    snapshot: string;
    traces: string;
  };
}

interface PackJobResult {
  manifestId: string;
  outputs: {
    directory: string;
    manifest: string;
    archive: string;
  };
}

const METADATA_FILE = 'job.json';
const LICENSE_HEADER = 'x-soipack-license';
const LICENSE_FILE_FIELD = 'license';

const DEFAULT_METRICS_MARK = Symbol('soipack:defaultMetricsRegistered');

const getFieldValue = (value: unknown): string | undefined => {
  if (Array.isArray(value)) {
    const [first] = value;
    return first !== undefined ? String(first) : undefined;
  }
  if (value === undefined || value === null) {
    return undefined;
  }
  return String(value);
};

const computeHash = (entries: HashEntry[]): string => {
  const sorted = [...entries].sort((a, b) => a.key.localeCompare(b.key));
  const hash = createHash('sha256');
  sorted.forEach((entry) => {
    hash.update(entry.key);
    hash.update('\0');
    hash.update(entry.value);
    hash.update('\0');
  });
  return hash.digest('hex');
};

const createJobId = (hash: string): string => hash.slice(0, 16);

const JOB_KINDS: readonly JobKind[] = ['import', 'analyze', 'report', 'pack'];
const JOB_STATUSES: readonly JobStatus[] = ['queued', 'running', 'completed', 'failed'];

const parseFilterParam = <T extends string>(
  value: unknown,
  allowed: readonly T[],
  label: string,
): T[] | undefined => {
  if (value === undefined) {
    return undefined;
  }

  const inputs = Array.isArray(value) ? (value as unknown[]) : [value];
  const collected: string[] = [];
  inputs.forEach((entry) => {
    const segments = String(entry)
      .split(',')
      .map((segment) => segment.trim())
      .filter((segment) => segment.length > 0);
    collected.push(...segments);
  });

  if (collected.length === 0) {
    throw new HttpError(400, 'INVALID_REQUEST', `${label} için en az bir değer belirtilmelidir.`);
  }

  const allowedSet = new Set(allowed);
  collected.forEach((entry) => {
    if (!allowedSet.has(entry as T)) {
      throw new HttpError(400, 'INVALID_REQUEST', `${label} değeri geçerli değil: ${entry}`);
    }
  });

  return collected as T[];
};

const jobMatchesFilters = (
  job: JobSummary,
  kinds?: readonly JobKind[],
  statuses?: readonly JobStatus[],
): boolean => {
  if (kinds && kinds.length > 0 && !kinds.includes(job.kind)) {
    return false;
  }
  if (statuses && statuses.length > 0 && !statuses.includes(job.status)) {
    return false;
  }
  return true;
};

interface VerifiedLicense {
  hash: string;
  payload: LicensePayload;
}

const asCertificationLevel = (value: string | undefined): CertificationLevel | undefined => {
  if (!value) {
    return undefined;
  }
  const upper = value.trim().toUpperCase();
  if (['A', 'B', 'C', 'D', 'E'].includes(upper)) {
    return upper as CertificationLevel;
  }
  throw new HttpError(
    400,
    'INVALID_LEVEL',
    'Geçersiz seviye değeri. Geçerli değerler A-E aralığındadır.',
  );
};

const assertDirectoryExists = async (
  storage: StorageProvider,
  directory: string,
  kind: string,
): Promise<void> => {
  if (!(await storage.fileExists(directory))) {
    throw new HttpError(404, 'NOT_FOUND', `${kind} bulunamadı.`);
  }
};

const convertFileMap = (fileMap: FileMap): UploadedFileMap => {
  const result: UploadedFileMap = {};
  Object.entries(fileMap).forEach(([field, files]) => {
    result[field] = files.map((file) => ({
      originalname: file.originalname,
      path: file.path,
    }));
  });
  return result;
};

export interface UploadFieldPolicy {
  maxSizeBytes: number;
  allowedMimeTypes: string[];
}

type UploadPolicyMap = Record<string, UploadFieldPolicy>;

export type UploadPolicyOverrides = Partial<Record<string, Partial<UploadFieldPolicy>>>;

const matchesMimeType = (value: string, pattern: string): boolean => {
  const [rawType] = value.split(';', 1);
  const normalizedValue = rawType.trim().toLowerCase();
  const normalizedPattern = pattern.trim().toLowerCase();
  if (normalizedPattern === '*') {
    return true;
  }
  if (normalizedPattern.endsWith('/*')) {
    const [type] = normalizedPattern.split('/', 1);
    return normalizedValue.startsWith(`${type}/`);
  }
  return normalizedValue === normalizedPattern;
};

const createDefaultUploadPolicies = (maxUploadSize: number): UploadPolicyMap => ({
  [LICENSE_FILE_FIELD]: {
    maxSizeBytes: Math.min(maxUploadSize, 512 * 1024),
    allowedMimeTypes: ['*'],
  },
  jira: {
    maxSizeBytes: maxUploadSize,
    allowedMimeTypes: [
      'application/json',
      'application/zip',
      'application/x-zip-compressed',
      'application/octet-stream',
      'text/*',
    ],
  },
  reqif: {
    maxSizeBytes: maxUploadSize,
    allowedMimeTypes: [
      'application/xml',
      'text/xml',
      'application/zip',
      'application/x-zip-compressed',
      'application/octet-stream',
    ],
  },
  junit: {
    maxSizeBytes: maxUploadSize,
    allowedMimeTypes: ['application/xml', 'text/xml', 'application/octet-stream'],
  },
  lcov: {
    maxSizeBytes: maxUploadSize,
    allowedMimeTypes: ['text/*', 'application/octet-stream'],
  },
  cobertura: {
    maxSizeBytes: maxUploadSize,
    allowedMimeTypes: ['application/xml', 'text/xml', 'application/octet-stream'],
  },
  git: {
    maxSizeBytes: maxUploadSize,
    allowedMimeTypes: [
      'application/zip',
      'application/x-zip-compressed',
      'application/x-tar',
      'application/gzip',
      'application/x-gzip',
      'application/octet-stream',
    ],
  },
  objectives: {
    maxSizeBytes: maxUploadSize,
    allowedMimeTypes: [
      'application/json',
      'text/*',
      'application/zip',
      'application/x-zip-compressed',
    ],
  },
  traceLinksCsv: {
    maxSizeBytes: maxUploadSize,
    allowedMimeTypes: ['text/csv', 'text/plain', 'application/octet-stream'],
  },
  traceLinksJson: {
    maxSizeBytes: maxUploadSize,
    allowedMimeTypes: ['application/json', 'text/*', 'application/octet-stream'],
  },
});

const mergeUploadPolicies = (
  maxUploadSize: number,
  overrides?: UploadPolicyOverrides,
): UploadPolicyMap => {
  const base = createDefaultUploadPolicies(maxUploadSize);
  if (!overrides) {
    return base;
  }

  Object.entries(overrides).forEach(([field, override]) => {
    if (!override) {
      return;
    }
    if (!base[field]) {
      base[field] = {
        maxSizeBytes: override.maxSizeBytes ?? maxUploadSize,
        allowedMimeTypes: override.allowedMimeTypes ?? ['*'],
      };
      return;
    }
    if (override.maxSizeBytes !== undefined) {
      base[field].maxSizeBytes = Math.min(override.maxSizeBytes, maxUploadSize);
    }
    if (override.allowedMimeTypes !== undefined) {
      base[field].allowedMimeTypes = override.allowedMimeTypes;
    }
  });

  return base;
};

const ensureFileWithinPolicy = (
  field: string,
  file: Express.Multer.File,
  policy: UploadFieldPolicy,
): void => {
  if (file.size > policy.maxSizeBytes) {
    throw new HttpError(
      413,
      'FILE_TOO_LARGE',
      `${field} alanı için dosya boyutu sınırı aşıldı. Maksimum: ${policy.maxSizeBytes} bayt.`,
      { field, limit: policy.maxSizeBytes, size: file.size },
    );
  }

  if (policy.allowedMimeTypes.length > 0) {
    const mimetype = file.mimetype || 'application/octet-stream';
    const allowed = policy.allowedMimeTypes.some((pattern) => matchesMimeType(mimetype, pattern));
    if (!allowed) {
      throw new HttpError(
        415,
        'UNSUPPORTED_MEDIA_TYPE',
        `${field} alanı için içerik türü kabul edilmiyor: ${mimetype}.`,
        { field, mimetype },
      );
    }
  }
};

const cleanupUploadedFiles = async (fileMap: FileMap): Promise<void> => {
  const tasks: Promise<unknown>[] = [];
  Object.values(fileMap).forEach((files) => {
    files.forEach((file) => {
      tasks.push(fsPromises.rm(file.path, { force: true }));
    });
  });
  await Promise.allSettled(tasks);
};

const hashFileAtPath = (filePath: string): Promise<string> =>
  new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('error', reject);
    stream.on('data', (chunk) => {
      const buffer = typeof chunk === 'string' ? Buffer.from(chunk) : chunk;
      hash.update(buffer);
    });
    stream.on('end', () => resolve(hash.digest('hex')));
  });

const scanUploadedFiles = async (scanner: FileScanner, fileMap: FileMap): Promise<void> => {
  for (const [field, files] of Object.entries(fileMap)) {
    for (const file of files) {
      let result: FileScanResult;
      try {
        result = await scanner.scan({
          field,
          path: file.path,
          originalname: file.originalname,
          mimetype: file.mimetype,
          size: file.size,
        });
      } catch (error) {
        const message =
          error instanceof Error
            ? error.message
            : 'Dosya tarama servisine ulaşılamadı veya hata verdi.';
        throw new HttpError(502, 'FILE_SCAN_ERROR', `${file.originalname} taranamadı: ${message}`, {
          field,
          originalname: file.originalname,
          mimetype: file.mimetype,
          error: message,
        });
      }

      if (!result.clean) {
        const threat = result.threat ?? 'Belirsiz tehdit';
        throw new HttpError(
          422,
          'FILE_SCAN_FAILED',
          `${file.originalname} yüklemesi reddedildi: ${threat}.`,
          {
            field,
            originalname: file.originalname,
            mimetype: file.mimetype,
            threat,
            engine: result.engine,
            details: result.details,
          },
        );
      }
    }
  }
};

const sanitizeBase64 = (value: string): string => value.replace(/\s+/g, '').trim();

const decodeBase64Strict = (value: string, description: string): Buffer => {
  const normalized = sanitizeBase64(value);
  if (!normalized) {
    throw new HttpError(402, 'LICENSE_INVALID', `${description} boş olamaz.`);
  }
  if (!/^[A-Za-z0-9+/=]+$/.test(normalized)) {
    throw new HttpError(402, 'LICENSE_INVALID', `${description} base64 formatında olmalıdır.`);
  }
  const decoded = Buffer.from(normalized, 'base64');
  if (decoded.length === 0) {
    throw new HttpError(402, 'LICENSE_INVALID', `${description} çözümlenemedi.`);
  }
  return decoded;
};

const loadLicensePublicKey = (filePath: string): string => {
  const raw = fs.readFileSync(filePath, 'utf8');
  const withoutPem = raw
    .replace(/-----BEGIN [^-]+-----/g, '')
    .replace(/-----END [^-]+-----/g, '')
    .replace(/\r?\n/g, '')
    .trim();
  const normalized = sanitizeBase64(withoutPem);
  if (!normalized) {
    throw new Error(`Lisans kamu anahtarı dosyası boş: ${filePath}`);
  }
  if (!/^[A-Za-z0-9+/=]+$/.test(normalized)) {
    throw new Error('Lisans kamu anahtarı base64 formatında olmalıdır.');
  }
  let decoded: Buffer;
  try {
    decoded = Buffer.from(normalized, 'base64');
  } catch (error) {
    throw new Error('Lisans kamu anahtarı base64 olarak çözülemedi.');
  }
  if (decoded.length !== 32) {
    throw new Error('Lisans kamu anahtarı Ed25519 formatında olmalıdır (32 bayt).');
  }
  return normalized;
};

const toLicenseMetadata = (license: VerifiedLicense): JobLicenseMetadata => ({
  hash: license.hash,
  licenseId: license.payload.licenseId,
  issuedTo: license.payload.issuedTo,
  issuedAt: license.payload.issuedAt,
  expiresAt: license.payload.expiresAt ?? null,
  features: license.payload.features,
});

const toLicensePayloadFromMetadata = (metadata: JobLicenseMetadata): LicensePayload => ({
  licenseId: metadata.licenseId,
  issuedTo: metadata.issuedTo,
  issuedAt: metadata.issuedAt,
  expiresAt: metadata.expiresAt ?? undefined,
  features: metadata.features?.length ? metadata.features : undefined,
});

export interface JwtAuthConfig {
  issuer: string;
  audience: string;
  tenantClaim: string;
  userClaim?: string;
  scopeClaim?: string;
  requiredScopes?: string[];
  adminScopes?: string[];
  jwksUri?: string;
  jwks?: JSONWebKeySet;
  clockToleranceSeconds?: number;
  remoteJwks?: RemoteJwksConfig;
}

export interface ServerConfig {
  auth: JwtAuthConfig;
  storageDir: string;
  signingKeyPath: string;
  licensePublicKeyPath: string;
  maxUploadSizeBytes?: number;
  jsonBodyLimitBytes?: number;
  maxQueuedJobsPerTenant?: number;
  maxQueuedJobsTotal?: number;
  workerConcurrency?: number;
  storageProvider?: StorageProvider;
  retention?: RetentionConfig;
  uploadPolicies?: UploadPolicyOverrides;
  scanner?: FileScanner;
  logger?: Logger;
  metricsRegistry?: Registry;
  healthcheckToken?: string;
  rateLimit?: RateLimitConfig;
  requireAdminClientCertificate?: boolean;
  trustProxy?: boolean | number | string;
  licenseLimits?: LicenseLimitsConfig;
  licenseCache?: LicenseCacheConfig;
  retentionScheduler?: RetentionSchedulerConfig;
}

export interface LicenseLimitsConfig {
  maxBytes?: number;
  headerMaxBytes?: number;
}

export interface LicenseCacheConfig {
  maxEntries?: number;
  maxAgeMs?: number;
}

export interface RetentionSchedulerConfig {
  intervalMs: number;
}

export interface RemoteJwksConfig {
  timeoutMs?: number;
  maxRetries?: number;
  backoffMs?: number;
  cacheMaxAgeMs?: number;
  cooldownMs?: number;
}

export interface RateLimitWindowConfig {
  windowMs: number;
  max: number;
  maxEntries?: number;
}

export interface RateLimitConfig {
  global?: RateLimitWindowConfig;
  ip?: RateLimitWindowConfig;
  tenant?: RateLimitWindowConfig;
}

const PIPELINE_LICENSE_FEATURES = {
  import: 'import',
  analyze: 'analyze',
  report: 'report',
  pack: 'pack',
} as const;

export interface HttpsServerOptions {
  requireClientCertificate?: boolean;
}

export interface HttpsListenerConfig {
  key: string | Buffer;
  cert: string | Buffer;
  clientCa?: string | Buffer;
}

const SECURE_TLS_CIPHERS = [
  'TLS_AES_256_GCM_SHA384',
  'TLS_AES_128_GCM_SHA256',
  'TLS_CHACHA20_POLY1305_SHA256',
  'ECDHE-ECDSA-AES256-GCM-SHA384',
  'ECDHE-RSA-AES256-GCM-SHA384',
  'ECDHE-ECDSA-AES128-GCM-SHA256',
  'ECDHE-RSA-AES128-GCM-SHA256',
].join(':');

export const createHttpsServer = (
  app: Express,
  tls: HttpsListenerConfig,
  options: HttpsServerOptions = {},
): https.Server => {
  if (!tls.key) {
    throw new Error('TLS özel anahtar dosyası sağlanmalıdır.');
  }
  if (!tls.cert) {
    throw new Error('TLS sertifika dosyası sağlanmalıdır.');
  }

  const serverOptions: https.ServerOptions = {
    key: tls.key,
    cert: tls.cert,
    minVersion: 'TLSv1.2',
    ciphers: SECURE_TLS_CIPHERS,
    honorCipherOrder: true,
    secureOptions: cryptoConstants.SSL_OP_NO_RENEGOTIATION,
  };

  if (tls.clientCa) {
    serverOptions.ca = tls.clientCa;
    serverOptions.requestCert = true;
    serverOptions.rejectUnauthorized = true;
  } else if (options.requireClientCertificate) {
    throw new Error('İstemci sertifikası gerektirildiğinde istemci CA demeti sağlanmalıdır.');
  }

  const server = https.createServer(serverOptions, app);

  server.on('secureConnection', (socket) => {
    if (typeof socket.disableRenegotiation === 'function') {
      try {
        socket.disableRenegotiation();
      } catch {
        socket.destroy();
        return;
      }
    }

    if (options.requireClientCertificate && !socket.authorized) {
      socket.destroy(new Error('TLS_CLIENT_CERT_REQUIRED'));
    }
  });

  return server;
};

type RetentionTarget = 'uploads' | 'analyses' | 'reports' | 'packages';

export interface RetentionPolicy {
  maxAgeMs: number;
}

export type RetentionConfig = Partial<Record<RetentionTarget, RetentionPolicy>>;

export interface RetentionStats {
  target: RetentionTarget;
  removed: number;
  retained: number;
  skipped: number;
  configured: boolean;
}

const readJobMetadata = async <T extends JobMetadata>(
  storage: StorageProvider,
  directory: string,
): Promise<T> => {
  const metadataPath = path.join(directory, METADATA_FILE);
  return storage.readJson<T>(metadataPath);
};

const writeJobMetadata = async (
  storage: StorageProvider,
  directory: string,
  metadata: JobMetadata,
): Promise<void> => {
  const metadataPath = path.join(directory, METADATA_FILE);
  await storage.writeJson(metadataPath, metadata);
};

const createPipelineError = (error: unknown, message: string): HttpError => {
  if (error instanceof HttpError) {
    return error;
  }
  const description = error instanceof Error ? error.message : String(error);
  return new HttpError(500, 'PIPELINE_ERROR', message, { cause: description });
};

const toImportResult = (
  storage: StorageProvider,
  metadata: ImportJobMetadata,
): ImportJobResult => ({
  warnings: metadata.warnings,
  outputs: {
    directory: storage.toRelativePath(metadata.directory),
    workspace: storage.toRelativePath(metadata.outputs.workspacePath),
  },
});

const toAnalyzeResult = (
  storage: StorageProvider,
  metadata: AnalyzeJobMetadata,
): AnalyzeJobResult => ({
  exitCode: metadata.exitCode,
  outputs: {
    directory: storage.toRelativePath(metadata.directory),
    snapshot: storage.toRelativePath(metadata.outputs.snapshotPath),
    traces: storage.toRelativePath(metadata.outputs.tracePath),
    analysis: storage.toRelativePath(metadata.outputs.analysisPath),
  },
});

const toReportResult = (
  storage: StorageProvider,
  metadata: ReportJobMetadata,
): ReportJobResult => ({
  outputs: {
    directory: storage.toRelativePath(metadata.directory),
    complianceHtml: storage.toRelativePath(metadata.outputs.complianceHtml),
    complianceJson: storage.toRelativePath(metadata.outputs.complianceJson),
    traceHtml: storage.toRelativePath(metadata.outputs.traceHtml),
    gapsHtml: storage.toRelativePath(metadata.outputs.gapsHtml),
    analysis: storage.toRelativePath(metadata.outputs.analysisPath),
    snapshot: storage.toRelativePath(metadata.outputs.snapshotPath),
    traces: storage.toRelativePath(metadata.outputs.tracesPath),
  },
});

const toPackResult = (storage: StorageProvider, metadata: PackJobMetadata): PackJobResult => ({
  manifestId: metadata.outputs.manifestId,
  outputs: {
    directory: storage.toRelativePath(metadata.directory),
    manifest: storage.toRelativePath(metadata.outputs.manifestPath),
    archive: storage.toRelativePath(metadata.outputs.archivePath),
  },
});

interface ImportJobPayload {
  workspaceDir: string;
  uploads: Record<string, string[]>;
  level?: CertificationLevel | null;
  projectName?: string | null;
  projectVersion?: string | null;
  license: JobLicenseMetadata;
}

interface AnalyzeJobPayload {
  workspaceDir: string;
  analysisDir: string;
  analyzeOptions: AnalyzeOptions;
  importId: string;
  license: JobLicenseMetadata;
}

interface ReportJobPayload {
  analysisDir: string;
  reportDir: string;
  reportOptions: ReportOptions;
  analysisId: string;
  manifestId?: string | null;
  license: JobLicenseMetadata;
}

interface PackJobPayload {
  reportDir: string;
  packageDir: string;
  packageName?: string;
  signingKeyPath: string;
  reportId: string;
  license: JobLicenseMetadata;
}

type JobPayloadMap = {
  import: ImportJobPayload;
  analyze: AnalyzeJobPayload;
  report: ReportJobPayload;
  pack: PackJobPayload;
};

type JobResultMap = {
  import: ImportJobResult;
  analyze: AnalyzeJobResult;
  report: ReportJobResult;
  pack: PackJobResult;
};

type JobHandler<K extends JobKind> = (
  context: JobExecutionContext<JobPayloadMap[K]>,
) => Promise<JobResultMap[K]>;

type JobHandlers = {
  [K in JobKind]: JobHandler<K>;
};

const serializeJobSummary = (summary: JobSummary) => ({
  id: summary.id,
  kind: summary.kind,
  hash: summary.hash,
  status: summary.status,
  createdAt: summary.createdAt.toISOString(),
  updatedAt: summary.updatedAt.toISOString(),
});

const serializeJobDetails = <T>(job: JobDetails<T>) => ({
  ...serializeJobSummary(job),
  result: job.result ?? undefined,
  error: job.error ?? undefined,
});

const respondWithJob = <T>(
  res: Response,
  job: JobDetails<T>,
  options?: { reused?: boolean },
): void => {
  const payload = {
    ...serializeJobDetails(job),
    ...(options?.reused !== undefined ? { reused: options.reused } : {}),
  };
  const statusCode =
    job.status === 'completed'
      ? 200
      : job.status === 'failed'
        ? (job.error?.statusCode ?? 500)
        : 202;
  res.status(statusCode).json(payload);
};

const adoptJobFromMetadata = (
  storage: StorageProvider,
  queue: JobQueue,
  metadata: JobMetadata,
): JobDetails<unknown> => {
  switch (metadata.kind) {
    case 'import':
      return queue.adoptCompleted<ImportJobResult>({
        tenantId: metadata.tenantId,
        id: metadata.id,
        kind: metadata.kind,
        hash: metadata.hash,
        createdAt: metadata.createdAt,
        updatedAt: metadata.createdAt,
        result: toImportResult(storage, metadata),
      });
    case 'analyze':
      return queue.adoptCompleted<AnalyzeJobResult>({
        tenantId: metadata.tenantId,
        id: metadata.id,
        kind: metadata.kind,
        hash: metadata.hash,
        createdAt: metadata.createdAt,
        updatedAt: metadata.createdAt,
        result: toAnalyzeResult(storage, metadata),
      });
    case 'report':
      return queue.adoptCompleted<ReportJobResult>({
        tenantId: metadata.tenantId,
        id: metadata.id,
        kind: metadata.kind,
        hash: metadata.hash,
        createdAt: metadata.createdAt,
        updatedAt: metadata.createdAt,
        result: toReportResult(storage, metadata),
      });
    case 'pack':
      return queue.adoptCompleted<PackJobResult>({
        tenantId: metadata.tenantId,
        id: metadata.id,
        kind: metadata.kind,
        hash: metadata.hash,
        createdAt: metadata.createdAt,
        updatedAt: metadata.createdAt,
        result: toPackResult(storage, metadata),
      });
    default:
      throw new HttpError(
        500,
        'UNKNOWN_JOB_KIND',
        `Bilinmeyen iş türü: ${(metadata as JobMetadata).kind}`,
      );
  }
};

const locateJobMetadata = async (
  storage: StorageProvider,
  queue: JobQueue,
  tenantId: string,
  jobId: string,
  onMetadata?: (metadata: JobMetadata) => void,
): Promise<JobDetails<unknown> | undefined> => {
  assertJobId(jobId);
  const locations: Array<{ dir: string; kind: JobMetadata['kind'] }> = [
    { dir: storage.directories.workspaces, kind: 'import' },
    { dir: storage.directories.analyses, kind: 'analyze' },
    { dir: storage.directories.reports, kind: 'report' },
    { dir: storage.directories.packages, kind: 'pack' },
  ];

  for (const location of locations) {
    const tenantDir = path.join(location.dir, tenantId);
    const candidateDir = path.join(tenantDir, jobId);
    const metadataPath = path.join(candidateDir, METADATA_FILE);
    if (await storage.fileExists(metadataPath)) {
      const metadata = await readJobMetadata<JobMetadata>(storage, candidateDir);
      if (metadata.tenantId !== tenantId) {
        throw new HttpError(403, 'TENANT_MISMATCH', 'İstenen iş bu kiracıya ait değil.');
      }
      if (onMetadata) {
        onMetadata(metadata);
      }
      return adoptJobFromMetadata(storage, queue, metadata);
    }
  }

  return undefined;
};

const removeJobArtifacts = async (
  storage: StorageProvider,
  directories: PipelineDirectories,
  tenantId: string,
  jobId: string,
  kind: JobKind,
): Promise<void> => {
  switch (kind) {
    case 'import':
      await Promise.all([
        storage.removeDirectory(path.join(directories.workspaces, tenantId, jobId)),
        storage.removeDirectory(path.join(directories.uploads, tenantId, jobId)),
      ]);
      return;
    case 'analyze':
      await storage.removeDirectory(path.join(directories.analyses, tenantId, jobId));
      return;
    case 'report':
      await storage.removeDirectory(path.join(directories.reports, tenantId, jobId));
      return;
    case 'pack':
      await storage.removeDirectory(path.join(directories.packages, tenantId, jobId));
      return;
    default:
      throw new HttpError(500, 'UNKNOWN_JOB_KIND', `Bilinmeyen iş türü: ${kind}`);
  }
};

const findPackMetadataByManifestId = async (
  storage: StorageProvider,
  directories: PipelineDirectories,
  tenantId: string,
  manifestId: string,
): Promise<PackJobMetadata | undefined> => {
  const tenantPackagesDir = path.join(directories.packages, tenantId);
  if (!(await storage.fileExists(tenantPackagesDir))) {
    return undefined;
  }

  const jobIds = await storage.listSubdirectories(tenantPackagesDir);
  for (const jobId of jobIds) {
    const jobDir = path.join(tenantPackagesDir, jobId);
    const metadataPath = path.join(jobDir, METADATA_FILE);
    if (!(await storage.fileExists(metadataPath))) {
      continue;
    }

    let metadata: PackJobMetadata;
    try {
      metadata = await storage.readJson<PackJobMetadata>(metadataPath);
    } catch {
      continue;
    }

    if (metadata.tenantId !== tenantId) {
      continue;
    }

    if (metadata.outputs?.manifestId === manifestId) {
      return metadata;
    }
  }

  return undefined;
};

const resolvePackageMetadata = async (
  storage: StorageProvider,
  directories: PipelineDirectories,
  tenantId: string,
  packageId: string | undefined,
): Promise<{ metadata: PackJobMetadata; directory: string }> => {
  if (!packageId) {
    throw new HttpError(400, 'INVALID_REQUEST', 'Paket kimliği belirtilmelidir.');
  }

  assertJobId(packageId);

  const packageDir = path.join(directories.packages, tenantId, packageId);
  const metadataPath = path.join(packageDir, METADATA_FILE);
  if (!(await storage.fileExists(metadataPath))) {
    throw new HttpError(404, 'PACKAGE_NOT_FOUND', 'İstenen paket bulunamadı.');
  }

  const metadata = await storage.readJson<PackJobMetadata>(metadataPath);
  if (metadata.tenantId !== tenantId) {
    throw new HttpError(403, 'TENANT_MISMATCH', 'İstenen paket bu kiracıya ait değil.');
  }

  return { metadata, directory: packageDir };
};

const streamStorageFile = async (
  res: Response,
  storage: StorageProvider,
  filePath: string,
  options: { contentType: string; fallbackName: string },
): Promise<void> => {
  const info = await storage.getFileInfo(filePath).catch(() => undefined);
  const fileName = sanitizeDownloadFileName(path.basename(filePath), options.fallbackName);
  res.setHeader('Content-Type', options.contentType);
  res.setHeader('Content-Disposition', buildContentDisposition(fileName));
  res.setHeader('Cache-Control', 'private, no-store, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  if (info?.size !== undefined) {
    res.setHeader('Content-Length', info.size.toString());
  }

  const stream = await storage.openReadStream(filePath);
  stream.once('error', (error) => {
    if (!res.headersSent) {
      res.removeHeader('Content-Length');
    }
    res.destroy(error);
  });

  await streamPipeline(stream, res);
};

const streamPackageArtifact = async (
  res: Response,
  storage: StorageProvider,
  artifactPath: string | undefined,
  notFoundCode: string,
  notFoundMessage: string,
  options: { contentType: string; fallbackName: string },
): Promise<void> => {
  if (!artifactPath || !(await storage.fileExists(artifactPath))) {
    throw new HttpError(404, notFoundCode, notFoundMessage);
  }

  await streamStorageFile(res, storage, artifactPath, options);
};

const runRetentionSweep = async (
  storage: StorageProvider,
  queue: JobQueue,
  tenantId: string,
  retention: RetentionConfig,
  jobLicenses: Map<string, VerifiedLicense>,
  now: Date = new Date(),
): Promise<RetentionStats[]> => {
  const descriptors: Array<{
    target: RetentionTarget;
    baseDirectory: string;
    cleanup: (tenant: string, id: string) => Promise<void>;
  }> = [
    {
      target: 'uploads',
      baseDirectory: storage.directories.workspaces,
      cleanup: async (tenant: string, id: string) => {
        await storage.removeDirectory(path.join(storage.directories.workspaces, tenant, id));
        await storage.removeDirectory(path.join(storage.directories.uploads, tenant, id));
      },
    },
    {
      target: 'analyses',
      baseDirectory: storage.directories.analyses,
      cleanup: async (tenant: string, id: string) => {
        await storage.removeDirectory(path.join(storage.directories.analyses, tenant, id));
      },
    },
    {
      target: 'reports',
      baseDirectory: storage.directories.reports,
      cleanup: async (tenant: string, id: string) => {
        await storage.removeDirectory(path.join(storage.directories.reports, tenant, id));
      },
    },
    {
      target: 'packages',
      baseDirectory: storage.directories.packages,
      cleanup: async (tenant: string, id: string) => {
        await storage.removeDirectory(path.join(storage.directories.packages, tenant, id));
      },
    },
  ];

  const results: RetentionStats[] = [];

  for (const descriptor of descriptors) {
    const policy = retention[descriptor.target];
    if (!policy || policy.maxAgeMs === undefined || policy.maxAgeMs < 0) {
      results.push({
        target: descriptor.target,
        removed: 0,
        retained: 0,
        skipped: 0,
        configured: false,
      });
      continue;
    }

    const tenantDirectory = path.join(descriptor.baseDirectory, tenantId);
    const hasTenantDirectory = await storage.fileExists(tenantDirectory);
    const ids = hasTenantDirectory ? await storage.listSubdirectories(tenantDirectory) : [];
    let removed = 0;
    let retained = 0;
    let skipped = 0;

    for (const id of ids) {
      const job = queue.get(tenantId, id);
      if (job && (job.status === 'queued' || job.status === 'running')) {
        skipped += 1;
        continue;
      }

      const jobDir = path.join(tenantDirectory, id);
      const metadataPath = path.join(jobDir, METADATA_FILE);
      if (!(await storage.fileExists(metadataPath))) {
        skipped += 1;
        continue;
      }

      let metadata: JobMetadata;
      try {
        metadata = await storage.readJson<JobMetadata>(metadataPath);
      } catch {
        skipped += 1;
        continue;
      }

      const createdAt = new Date(metadata.createdAt);
      if (Number.isNaN(createdAt.getTime())) {
        skipped += 1;
        continue;
      }

      const ageMs = now.getTime() - createdAt.getTime();
      if (ageMs < policy.maxAgeMs) {
        retained += 1;
        continue;
      }

      try {
        await descriptor.cleanup(tenantId, id);
        jobLicenses.delete(createScopedJobKey(tenantId, id));
        removed += 1;
      } catch {
        skipped += 1;
      }
    }

    results.push({ target: descriptor.target, removed, retained, skipped, configured: true });
  }

  return results;
};

const createAsyncHandler =
  <T extends Request>(handler: (req: T, res: Response) => Promise<void>) =>
  async (req: T, res: Response, next: NextFunction): Promise<void> => {
    try {
      await handler(req, res);
    } catch (error) {
      next(error);
    }
  };

const createAuthMiddleware = (
  config: JwtAuthConfig,
  options?: { tenantRateLimiter?: (tenantId: string) => void; onAuthenticated?: (tenantId: string) => void },
) => {
  const { jwks, jwksUri } = config;
  const keyStore = jwks
    ? createLocalJWKSet(jwks)
    : jwksUri
      ? createRemoteJwkSetWithBounds(config)
      : null;

  if (!keyStore) {
    throw new Error('Kimlik doğrulama yapılandırmasında jwksUri veya jwks tanımlanmalıdır.');
  }

  const tenantClaim = config.tenantClaim;
  const userClaim = config.userClaim ?? 'sub';
  const scopeClaim = config.scopeClaim ?? 'scope';
  const requiredScopes = normalizeScopeList(config.requiredScopes);
  const requiredScopeSet = new Set(requiredScopes);
  const adminScopes = normalizeScopeList(config.adminScopes);
  const adminScopeSet = new Set(adminScopes);
  const clockTolerance = config.clockToleranceSeconds ?? 5;
  const tenantPattern = /^[A-Za-z0-9._-]+$/;

  const collectScopes = (payload: JWTPayload): string[] => {
    const scopeSources: unknown[] = [payload[scopeClaim]];
    if (scopeClaim !== 'scope') {
      scopeSources.push(payload.scope);
    }
    if (scopeClaim !== 'scp') {
      scopeSources.push(payload.scp);
    }

    const scopes = new Set<string>();
    scopeSources.forEach((value) => {
      if (typeof value === 'string') {
        value
          .split(/\s+/u)
          .map((entry) => entry.trim())
          .filter(Boolean)
          .forEach((entry) => scopes.add(entry));
      } else if (Array.isArray(value)) {
        value.forEach((entry) => {
          if (typeof entry === 'string') {
            entry
              .split(/\s+/u)
              .map((token) => token.trim())
              .filter(Boolean)
              .forEach((token) => scopes.add(token));
          }
        });
      }
    });

    return [...scopes];
  };

  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      const header = req.get('authorization');
      if (!header || !header.startsWith('Bearer ')) {
        throw new HttpError(401, 'UNAUTHORIZED', 'Bearer kimlik doğrulaması gerekiyor.');
      }

      const token = header.slice('Bearer '.length).trim();
      if (!token) {
        throw new HttpError(401, 'UNAUTHORIZED', 'Geçersiz kimlik doğrulama belirteci.');
      }

      let payload: JWTPayload;
      try {
        const result = await jwtVerify(token, keyStore, {
          issuer: config.issuer,
          audience: config.audience,
          clockTolerance,
        });
        payload = result.payload;
      } catch (error) {
        const jwksError = findJwksFetchError(error);
        if (jwksError) {
          const causeMessage = jwksError.cause instanceof Error ? jwksError.cause.message : undefined;
          throw new HttpError(
            503,
            'JWKS_UNAVAILABLE',
            'Kimlik doğrulama anahtarları şu anda getirilemiyor.',
            { cause: causeMessage ?? jwksError.message },
          );
        }

        const tlsError = findTlsError(error);
        if (tlsError) {
          throw new HttpError(
            503,
            'JWKS_UNAVAILABLE',
            'Kimlik doğrulama anahtarları şu anda getirilemiyor.',
            {
              cause: tlsError.code ?? tlsError.message,
              message: tlsError.message,
            },
          );
        }

        const cause = error instanceof Error ? error.message : String(error);
        throw new HttpError(401, 'UNAUTHORIZED', 'Geçersiz kimlik doğrulama belirteci.', { cause });
      }

      const tenantValue = payload[tenantClaim];
      if (typeof tenantValue !== 'string' || tenantValue.trim() === '') {
        throw new HttpError(
          403,
          'TENANT_REQUIRED',
          'Belirteç geçerli bir tenant kimliği içermiyor.',
        );
      }

      if (!tenantPattern.test(tenantValue)) {
        throw new HttpError(
          403,
          'TENANT_INVALID',
          'Tenant kimliği yalnızca harf, sayı, nokta, alt çizgi ve tire içerebilir.',
        );
      }

      const tenantId = tenantValue;

      if (options?.tenantRateLimiter) {
        options.tenantRateLimiter(tenantId);
      }

      options?.onAuthenticated?.(tenantId);

      const userValue = payload[userClaim] ?? payload.sub;
      if (typeof userValue !== 'string' || userValue.trim() === '') {
        throw new HttpError(
          403,
          'USER_REQUIRED',
          'Belirteç geçerli bir kullanıcı kimliği içermiyor.',
        );
      }
      const subject = userValue;

      const scopes = collectScopes(payload);

      if (requiredScopeSet.size > 0) {
        const scopeValues = new Set(scopes);
        const missing = [...requiredScopeSet].filter((scope) => !scopeValues.has(scope));
        if (missing.length > 0) {
          throw new HttpError(
            403,
            'INSUFFICIENT_SCOPE',
            `Belirteç gerekli yetkileri içermiyor: ${missing.join(', ')}`,
          );
        }
      }

      const hasAdminScope = adminScopeSet.size > 0 && scopes.some((scope) => adminScopeSet.has(scope));

      setAuthContext(req, { token, tenantId, subject, claims: payload, hasAdminScope });
      next();
    } catch (error) {
      next(error);
    }
  };
};

export const createServer = (config: ServerConfig): Express => {
  const storage = config.storageProvider ?? new FileSystemStorage(path.resolve(config.storageDir));
  const directories = storage.directories;
  const signingKeyPath = path.resolve(config.signingKeyPath);
  const licensePublicKeyPath = path.resolve(config.licensePublicKeyPath);
  const queueDirectory = path.join(directories.base, '.queue');
  const licensePublicKey = loadLicensePublicKey(licensePublicKeyPath);
  const expectedHealthcheckAuthorization = config.healthcheckToken
    ? `Bearer ${config.healthcheckToken}`
    : null;
  interface LicenseCacheEntry {
    payload: LicensePayload;
    expiresAtMs: number | null;
    addedAtMs: number;
  }

  const licenseMaxBytes = Math.max(1, config.licenseLimits?.maxBytes ?? DEFAULT_LICENSE_MAX_BYTES);
  const licenseHeaderMaxBytes = Math.max(
    1,
    config.licenseLimits?.headerMaxBytes ?? DEFAULT_LICENSE_HEADER_MAX_BYTES,
  );
  const licenseCacheMaxEntries = Math.max(
    1,
    config.licenseCache?.maxEntries ?? DEFAULT_LICENSE_CACHE_MAX_ENTRIES,
  );
  const licenseCacheMaxAgeMs = Math.max(0, config.licenseCache?.maxAgeMs ?? DEFAULT_LICENSE_CACHE_MAX_AGE_MS);

  const toLicenseCacheEntry = (payload: LicensePayload, addedAtMs: number): LicenseCacheEntry => {
    const expiresAt = payload.expiresAt ?? null;
    if (!expiresAt) {
      return { payload, expiresAtMs: null, addedAtMs };
    }
    const parsed = Date.parse(expiresAt);
    return {
      payload,
      expiresAtMs: Number.isNaN(parsed) ? null : parsed,
      addedAtMs,
    };
  };

  const licenseCache = new Map<string, LicenseCacheEntry>();
  const jobLicenses = new Map<string, VerifiedLicense>();
  const knownTenants = new Set<string>();
  const logger: Logger = config.logger ?? pino({ name: 'soipack-server' });

  interface EvidenceRecord {
    id: string;
    tenantId: string;
    filename: string;
    sha256: string;
    size: number;
    uploadedAt: string;
    metadata: Record<string, unknown>;
    contentEncoding: 'base64';
    content: string;
    snapshotId: string;
    snapshotVersion: SnapshotVersion;
  }

  interface ComplianceRequirementEntry {
    id: string;
    status: 'covered' | 'partial' | 'missing';
    title?: string;
    evidenceIds: string[];
  }

  interface ComplianceSummary {
    total: number;
    covered: number;
    partial: number;
    missing: number;
  }

  interface ComplianceMatrixPayload {
    project?: string;
    level?: string;
    generatedAt?: string;
    requirements: ComplianceRequirementEntry[];
    summary: ComplianceSummary;
  }

  interface CoverageSummaryPayload {
    statements?: number;
    branches?: number;
    functions?: number;
    lines?: number;
  }

  interface ComplianceRecord {
    id: string;
    tenantId: string;
    sha256: string;
    createdAt: string;
    matrix: ComplianceMatrixPayload;
    coverage: CoverageSummaryPayload;
    metadata?: Record<string, unknown>;
  }

  const evidenceStore = new Map<string, Map<string, EvidenceRecord>>();
  const evidenceHashIndex = new Map<string, Map<string, string>>();
  const complianceStore = new Map<string, Map<string, ComplianceRecord>>();
  const tenantSnapshotVersions = new Map<string, SnapshotVersion>();
  const tenantDataRoot = path.join(directories.base, 'tenants');
  const TENANT_EVIDENCE_FILE = 'evidence.json';
  const TENANT_COMPLIANCE_FILE = 'compliance.json';
  const TENANT_SNAPSHOT_FILE = 'snapshot.json';

  const readPersistedJson = <T>(filePath: string): T | undefined => {
    try {
      if (!fs.existsSync(filePath)) {
        return undefined;
      }
      const content = fs.readFileSync(filePath, 'utf8');
      return JSON.parse(content) as T;
    } catch (error) {
      logger.warn({ err: error, filePath }, 'Persisted tenant data could not be read.');
      return undefined;
    }
  };

  const writePersistedJson = (tenantId: string, fileName: string, data: unknown): void => {
    const tenantDir = path.join(tenantDataRoot, tenantId);
    fs.mkdirSync(tenantDir, { recursive: true });
    const targetPath = path.join(tenantDir, fileName);
    fs.writeFileSync(targetPath, `${JSON.stringify(data, null, 2)}\n`, 'utf8');
  };

  const persistTenantEvidence = (tenantId: string): void => {
    const store = evidenceStore.get(tenantId);
    if (!store) {
      return;
    }
    writePersistedJson(tenantId, TENANT_EVIDENCE_FILE, Array.from(store.values()));
  };

  const persistTenantCompliance = (tenantId: string): void => {
    const store = complianceStore.get(tenantId);
    if (!store) {
      return;
    }
    writePersistedJson(tenantId, TENANT_COMPLIANCE_FILE, Array.from(store.values()));
  };

  const persistTenantSnapshotVersion = (tenantId: string, version: SnapshotVersion): void => {
    writePersistedJson(tenantId, TENANT_SNAPSHOT_FILE, version);
  };
  const isValidSha256Hex = (value: string): boolean => /^[a-f0-9]{64}$/i.test(value);
  const computeObjectSha256 = (value: unknown): string =>
    createHash('sha256').update(JSON.stringify(value)).digest('hex');

  const getTenantEvidenceMap = (tenantId: string): Map<string, EvidenceRecord> => {
    let store = evidenceStore.get(tenantId);
    if (!store) {
      store = new Map();
      evidenceStore.set(tenantId, store);
    }
    return store;
  };

  const getTenantEvidenceHashIndex = (tenantId: string): Map<string, string> => {
    let index = evidenceHashIndex.get(tenantId);
    if (!index) {
      index = new Map();
      evidenceHashIndex.set(tenantId, index);
    }
    return index;
  };

  const computeTenantEvidenceFingerprint = (tenantId: string): string => {
    const store = evidenceStore.get(tenantId);
    if (!store || store.size === 0) {
      return deriveFingerprint([]);
    }
    const hashes = Array.from(store.values()).map((record) => record.sha256);
    return deriveFingerprint(hashes);
  };

  const updateTenantSnapshotVersion = (tenantId: string, timestamp: string): SnapshotVersion => {
    const fingerprint = computeTenantEvidenceFingerprint(tenantId);
    const existing = tenantSnapshotVersions.get(tenantId);
    if (existing && existing.fingerprint === fingerprint) {
      return existing;
    }
    const version = createSnapshotVersion(fingerprint, { createdAt: timestamp });
    tenantSnapshotVersions.set(tenantId, version);
    return version;
  };

  const ensureTenantSnapshotVersion = (tenantId: string): SnapshotVersion => {
    const existing = tenantSnapshotVersions.get(tenantId);
    if (existing) {
      return existing;
    }
    const now = new Date().toISOString();
    const version = createSnapshotVersion(computeTenantEvidenceFingerprint(tenantId), { createdAt: now });
    tenantSnapshotVersions.set(tenantId, version);
    persistTenantSnapshotVersion(tenantId, version);
    return version;
  };

  const loadPersistedTenantData = (): void => {
    try {
      fs.mkdirSync(tenantDataRoot, { recursive: true });
    } catch (error) {
      logger.error({ err: error }, 'Failed to ensure tenant data directory.');
      throw error;
    }

    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(tenantDataRoot, { withFileTypes: true });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return;
      }
      throw error;
    }

    for (const entry of entries) {
      if (!entry.isDirectory()) {
        continue;
      }
      const tenantId = entry.name;
      const tenantDir = path.join(tenantDataRoot, tenantId);
      try {
        const evidenceRecords =
          readPersistedJson<EvidenceRecord[]>(path.join(tenantDir, TENANT_EVIDENCE_FILE)) ?? [];
        if (evidenceRecords.length > 0) {
          const store = new Map<string, EvidenceRecord>();
          const hashIndex = new Map<string, string>();
          evidenceRecords.forEach((record) => {
            store.set(record.id, record);
            hashIndex.set(record.sha256, record.id);
          });
          evidenceStore.set(tenantId, store);
          evidenceHashIndex.set(tenantId, hashIndex);
        }

        const complianceRecords =
          readPersistedJson<ComplianceRecord[]>(path.join(tenantDir, TENANT_COMPLIANCE_FILE)) ?? [];
        if (complianceRecords.length > 0) {
          const store = new Map<string, ComplianceRecord>();
          complianceRecords.forEach((record) => {
            store.set(record.id, record);
          });
          complianceStore.set(tenantId, store);
        }

        const persistedVersion = readPersistedJson<SnapshotVersion>(
          path.join(tenantDir, TENANT_SNAPSHOT_FILE),
        );
        if (persistedVersion) {
          tenantSnapshotVersions.set(tenantId, persistedVersion);
        } else if (evidenceRecords.length > 0) {
          const fingerprint = deriveFingerprint(evidenceRecords.map((record) => record.sha256));
          const fallbackVersion = createSnapshotVersion(fingerprint, { createdAt: new Date().toISOString() });
          tenantSnapshotVersions.set(tenantId, fallbackVersion);
          persistTenantSnapshotVersion(tenantId, fallbackVersion);
        }

        knownTenants.add(tenantId);
      } catch (error) {
        logger.error({ err: error, tenantId }, 'Failed to load persisted tenant data.');
      }
    }
  };

  loadPersistedTenantData();

  const getTenantComplianceMap = (tenantId: string): Map<string, ComplianceRecord> => {
    let store = complianceStore.get(tenantId);
    if (!store) {
      store = new Map();
      complianceStore.set(tenantId, store);
    }
    return store;
  };

  const serializeEvidenceRecord = (
    record: EvidenceRecord,
    options?: { includeContent?: boolean },
  ): Record<string, unknown> => {
    const base: Record<string, unknown> = {
      id: record.id,
      filename: record.filename,
      sha256: record.sha256,
      size: record.size,
      uploadedAt: record.uploadedAt,
      metadata: record.metadata,
      contentEncoding: record.contentEncoding,
      snapshotId: record.snapshotId,
      snapshotVersion: record.snapshotVersion,
    };
    if (options?.includeContent) {
      base.content = record.content;
    }
    return base;
  };

  const serializeComplianceRecord = (record: ComplianceRecord): Record<string, unknown> => ({
    id: record.id,
    sha256: record.sha256,
    createdAt: record.createdAt,
    matrix: record.matrix,
    coverage: record.coverage,
    metadata: record.metadata ?? {},
  });

  const pruneLicenseCache = (nowMs: number): void => {
    for (const [hash, entry] of licenseCache) {
      if (entry.expiresAtMs !== null && entry.expiresAtMs <= nowMs) {
        licenseCache.delete(hash);
        continue;
      }
      if (licenseCacheMaxAgeMs > 0 && nowMs - entry.addedAtMs >= licenseCacheMaxAgeMs) {
        licenseCache.delete(hash);
      }
    }
    while (licenseCache.size > licenseCacheMaxEntries) {
      const oldest = licenseCache.keys().next();
      if (oldest.done) {
        break;
      }
      licenseCache.delete(oldest.value);
    }
  };

  const getCachedLicense = (hash: string, nowMs: number): LicenseCacheEntry | undefined => {
    const entry = licenseCache.get(hash);
    if (!entry) {
      return undefined;
    }
    if (entry.expiresAtMs !== null && entry.expiresAtMs <= nowMs) {
      licenseCache.delete(hash);
      throw new HttpError(402, 'LICENSE_INVALID', 'Lisans süresi dolmuş.');
    }
    if (licenseCacheMaxAgeMs > 0 && nowMs - entry.addedAtMs >= licenseCacheMaxAgeMs) {
      licenseCache.delete(hash);
      return undefined;
    }
    licenseCache.delete(hash);
    licenseCache.set(hash, entry);
    return entry;
  };

  const storeLicenseCacheEntry = (hash: string, payload: LicensePayload, nowMs: number): void => {
    licenseCache.set(hash, toLicenseCacheEntry(payload, nowMs));
    pruneLicenseCache(nowMs);
  };

  const normalizeLicenseError = (error: unknown): HttpError => {
    if (error instanceof HttpError) {
      return error;
    }
    if (error instanceof LicenseError) {
      return new HttpError(402, 'LICENSE_INVALID', error.message);
    }
    const message = error instanceof Error ? error.message : 'Lisans doğrulaması tamamlanamadı.';
    return new HttpError(500, 'LICENSE_VERIFY_FAILED', message);
  };

  const resolveLicenseWithCache = async (
    hash: string,
    nowMs: number,
    loader: () => Promise<LicensePayload>,
  ): Promise<VerifiedLicense> => {
    const cached = getCachedLicense(hash, nowMs);
    if (cached) {
      return { hash, payload: cached.payload };
    }

    try {
      const payload = await loader();
      storeLicenseCacheEntry(hash, payload, nowMs);
      return { hash, payload };
    } catch (error) {
      throw normalizeLicenseError(error);
    }
  };

  const computeFileHash = async (filePath: string): Promise<string> => {
    const hash = createHash('sha256');
    return new Promise<string>((resolve, reject) => {
      const stream = fs.createReadStream(filePath);
      stream.on('data', (chunk: Buffer | string) => {
        if (typeof chunk === 'string') {
          hash.update(Buffer.from(chunk));
        } else {
          hash.update(chunk);
        }
      });
      stream.on('error', reject);
      stream.on('end', () => {
        resolve(hash.digest('hex'));
      });
    });
  };

  const ensureLicenseWithinLimit = (size: number): void => {
    if (size > licenseMaxBytes) {
      throw new HttpError(413, 'LICENSE_TOO_LARGE', 'Lisans dosyası izin verilen boyutu aşıyor.', {
        limit: licenseMaxBytes,
      });
    }
  };

  const estimateBase64DecodedSize = (value: string): number => {
    if (!value) {
      return 0;
    }
    const length = Buffer.byteLength(value, 'utf8');
    return Math.floor((length * 3) / 4);
  };

  const metricsRegistry = config.metricsRegistry ?? new Registry();
  const registryWithMark = metricsRegistry as Registry & { [DEFAULT_METRICS_MARK]?: boolean };
  if (!registryWithMark[DEFAULT_METRICS_MARK]) {
    collectDefaultMetrics({ register: metricsRegistry });
    registryWithMark[DEFAULT_METRICS_MARK] = true;
  }

  const jobDurationHistogram = new Histogram({
    name: 'soipack_job_duration_seconds',
    help: 'SOIPack işlerinin çalışma süreleri (saniye cinsinden).',
    labelNames: ['tenantId', 'kind', 'status'] as const,
    buckets: [0.1, 0.5, 1, 2, 5, 10, 30, 60, 120, 300],
    registers: [metricsRegistry],
  });

  const jobErrorCounter = new Counter({
    name: 'soipack_job_errors_total',
    help: 'Başarısız SOIPack işlerinin toplam sayısı.',
    labelNames: ['tenantId', 'kind', 'code'] as const,
    registers: [metricsRegistry],
  });

  const jobQueueDepthGauge = new Gauge({
    name: 'soipack_job_queue_depth',
    help: 'Kiracı başına kuyruğa alınmış veya çalışan işlerin sayısı.',
    labelNames: ['tenantId'] as const,
    registers: [metricsRegistry],
  });

  const jobQueueTotalGauge = new Gauge({
    name: 'soipack_job_queue_total',
    help: 'Sunucu genelinde kuyruğa alınmış veya çalışan işlerin sayısı.',
    registers: [metricsRegistry],
  });
  jobQueueTotalGauge.set(0);

  const httpRequestCounter = new Counter({
    name: 'soipack_http_requests_total',
    help: 'HTTP isteklerinin toplam sayısı.',
    labelNames: ['method', 'route', 'status'] as const,
    registers: [metricsRegistry],
  });

  const httpRequestDurationHistogram = new Histogram({
    name: 'soipack_http_request_duration_seconds',
    help: 'HTTP isteklerinin tamamlanma süreleri (saniye).',
    labelNames: ['method', 'route', 'status'] as const,
    buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10],
    registers: [metricsRegistry],
  });

  const verifyLicenseFromBuffer = async (content: Buffer): Promise<VerifiedLicense> => {
    ensureLicenseWithinLimit(content.byteLength);
    const hash = createHash('sha256').update(content).digest('hex');
    const nowMs = Date.now();
    return resolveLicenseWithCache(hash, nowMs, async () => {
      const tempDir = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'soipack-license-'));
      const tempPath = path.join(tempDir, 'license.key');
      try {
        await fsPromises.writeFile(tempPath, content);
        return await verifyLicenseFile(tempPath, { publicKey: licensePublicKey });
      } finally {
        await fsPromises.rm(tempDir, { recursive: true, force: true }).catch(() => undefined);
      }
    });
  };

  const verifyLicenseFromFile = async (filePath: string): Promise<VerifiedLicense> => {
    let size: number;
    try {
      const stats = await fsPromises.stat(filePath);
      size = stats.size;
    } catch (error) {
      throw new HttpError(400, 'LICENSE_INVALID', 'Lisans dosyası okunamadı.', {
        cause: error instanceof Error ? error.message : String(error),
      });
    }
    ensureLicenseWithinLimit(size);
    const hash = await computeFileHash(filePath);
    const nowMs = Date.now();
    return resolveLicenseWithCache(hash, nowMs, () =>
      verifyLicenseFile(filePath, { publicKey: licensePublicKey }),
    );
  };

  const registerJobLicense = (tenantId: string, jobId: string, license: VerifiedLicense): void => {
    storeLicenseCacheEntry(license.hash, license.payload, Date.now());
    jobLicenses.set(createScopedJobKey(tenantId, jobId), license);
  };

  const ensureJobLicense = (tenantId: string, jobId: string, license: VerifiedLicense): void => {
    const key = createScopedJobKey(tenantId, jobId);
    const existing = jobLicenses.get(key);
    if (existing) {
      if (existing.hash !== license.hash) {
        throw new HttpError(401, 'LICENSE_MISMATCH', 'İş mevcut lisansla eşleşmiyor.');
      }
      return;
    }
    registerJobLicense(tenantId, jobId, license);
  };

  const hydrateJobLicense = (metadata: JobMetadata, expectedTenantId?: string): void => {
    if (!metadata.license) {
      throw new HttpError(500, 'LICENSE_METADATA_MISSING', 'İş lisans bilgisi eksik.');
    }
    if (!metadata.tenantId) {
      throw new HttpError(500, 'TENANT_METADATA_MISSING', 'İş tenant bilgisi eksik.');
    }
    if (expectedTenantId && metadata.tenantId !== expectedTenantId) {
      throw new HttpError(403, 'TENANT_MISMATCH', 'İstenen iş bu kiracıya ait değil.');
    }
    const payload = toLicensePayloadFromMetadata(metadata.license);
    registerJobLicense(metadata.tenantId, metadata.id, { hash: metadata.license.hash, payload });
  };

  const requireJobPayload = <K extends JobKind>(
    context: JobExecutionContext<JobPayloadMap[K]>,
  ): JobPayloadMap[K] => {
    if (context.payload === undefined) {
      throw new HttpError(500, 'JOB_PAYLOAD_MISSING', 'İş için kalıcı yük bulunamadı.');
    }
    return context.payload as JobPayloadMap[K];
  };

  const jobHandlers: JobHandlers = {
    import: async (context) => {
      const payload = requireJobPayload<'import'>(context);
      await storage.ensureDirectory(payload.workspaceDir);
      try {
        const importOptions: ImportOptions = {
          output: payload.workspaceDir,
          jira: payload.uploads.jira?.[0],
          reqif: payload.uploads.reqif?.[0],
          junit: payload.uploads.junit?.[0],
          lcov: payload.uploads.lcov?.[0],
          cobertura: payload.uploads.cobertura?.[0],
          git: payload.uploads.git?.[0],
          traceLinksCsv: payload.uploads.traceLinksCsv?.[0],
          traceLinksJson: payload.uploads.traceLinksJson?.[0],
          objectives: payload.uploads.objectives?.[0],
          level: payload.level ?? undefined,
          projectName: payload.projectName ?? undefined,
          projectVersion: payload.projectVersion ?? undefined,
        };

        const result = await runImport(importOptions);
        const metadata: ImportJobMetadata = {
          tenantId: context.tenantId,
          id: context.id,
          hash: context.hash,
          kind: 'import',
          createdAt: new Date().toISOString(),
          directory: payload.workspaceDir,
          params: {
            level: payload.level ?? null,
            projectName: payload.projectName ?? null,
            projectVersion: payload.projectVersion ?? null,
            files: Object.fromEntries(
              Object.entries(payload.uploads).map(([key, values]) => [
                key,
                values.map((value) => path.basename(value)),
              ]),
            ),
          },
          license: payload.license,
          warnings: result.warnings,
          outputs: {
            workspacePath: path.join(payload.workspaceDir, 'workspace.json'),
          },
        };

        await writeJobMetadata(storage, payload.workspaceDir, metadata);

        await storage
          .removeDirectory(path.join(directories.uploads, context.tenantId, context.id))
          .catch(() => undefined);

        return toImportResult(storage, metadata);
      } catch (error) {
        await storage.removeDirectory(payload.workspaceDir);
        await storage.removeDirectory(path.join(directories.uploads, context.tenantId, context.id));
        throw createPipelineError(error, 'Import işlemi sırasında bir hata oluştu.');
      }
    },
    analyze: async (context) => {
      const payload = requireJobPayload<'analyze'>(context);
      await storage.ensureDirectory(payload.analysisDir);
      try {
        const result = await runAnalyze(payload.analyzeOptions);
        const metadata: AnalyzeJobMetadata = {
          tenantId: context.tenantId,
          id: context.id,
          hash: context.hash,
          kind: 'analyze',
          createdAt: new Date().toISOString(),
          directory: payload.analysisDir,
          params: {
            importId: payload.importId,
            level: payload.analyzeOptions.level ?? null,
            projectName: payload.analyzeOptions.projectName ?? null,
            projectVersion: payload.analyzeOptions.projectVersion ?? null,
            objectivesPath: payload.analyzeOptions.objectives,
          },
          license: payload.license,
          exitCode: result.exitCode,
          outputs: {
            snapshotPath: path.join(payload.analysisDir, 'snapshot.json'),
            tracePath: path.join(payload.analysisDir, 'traces.json'),
            analysisPath: path.join(payload.analysisDir, 'analysis.json'),
          },
        };

        await writeJobMetadata(storage, payload.analysisDir, metadata);

        return toAnalyzeResult(storage, metadata);
      } catch (error) {
        await storage.removeDirectory(payload.analysisDir);
        throw createPipelineError(error, 'Analiz işlemi başarısız oldu.');
      }
    },
    report: async (context) => {
      const payload = requireJobPayload<'report'>(context);
      await storage.ensureDirectory(payload.reportDir);
      try {
        const result = await runReport(payload.reportOptions);
        const metadata: ReportJobMetadata = {
          tenantId: context.tenantId,
          id: context.id,
          hash: context.hash,
          kind: 'report',
          createdAt: new Date().toISOString(),
          directory: payload.reportDir,
          params: {
            analysisId: payload.analysisId,
            manifestId: payload.manifestId ?? null,
          },
          license: payload.license,
          outputs: {
            directory: payload.reportDir,
            complianceHtml: result.complianceHtml,
            complianceJson: result.complianceJson,
            traceHtml: result.traceHtml,
            gapsHtml: result.gapsHtml,
            analysisPath: path.join(payload.reportDir, 'analysis.json'),
            snapshotPath: path.join(payload.reportDir, 'snapshot.json'),
            tracesPath: path.join(payload.reportDir, 'traces.json'),
          },
        };

        await writeJobMetadata(storage, payload.reportDir, metadata);

        return toReportResult(storage, metadata);
      } catch (error) {
        await storage.removeDirectory(payload.reportDir);
        throw createPipelineError(error, 'Rapor oluşturma işlemi başarısız oldu.');
      }
    },
    pack: async (context) => {
      const payload = requireJobPayload<'pack'>(context);
      await storage.ensureDirectory(payload.packageDir);
      try {
        const signingKey = await fsPromises.readFile(payload.signingKeyPath, 'utf8');
        const packOptions: PackOptions = {
          input: payload.reportDir,
          output: payload.packageDir,
          packageName: payload.packageName,
          signingKey,
        };
        const result = await runPack(packOptions);

        const metadata: PackJobMetadata = {
          tenantId: context.tenantId,
          id: context.id,
          hash: context.hash,
          kind: 'pack',
          createdAt: new Date().toISOString(),
          directory: payload.packageDir,
          params: {
            reportId: payload.reportId,
            packageName: payload.packageName ?? null,
          },
          license: payload.license,
          outputs: {
            manifestPath: result.manifestPath,
            archivePath: result.archivePath,
            manifestId: result.manifestId,
          },
        };

        await writeJobMetadata(storage, payload.packageDir, metadata);

        return toPackResult(storage, metadata);
      } catch (error) {
        await storage.removeDirectory(payload.packageDir);
        throw createPipelineError(error, 'Paket oluşturma işlemi başarısız oldu.');
      }
    },
  };

  const collectTenantIdsForRetention = async (): Promise<string[]> => {
    const tenants = new Set<string>(knownTenants);
    const directoriesToScan = [
      storage.directories.workspaces,
      storage.directories.analyses,
      storage.directories.reports,
      storage.directories.packages,
    ];
    for (const directory of directoriesToScan) {
      try {
        const exists = await storage.fileExists(directory);
        if (!exists) {
          continue;
        }
        const entries = await storage.listSubdirectories(directory);
        entries.forEach((entry) => tenants.add(entry));
      } catch (error) {
        logger.warn(
          {
            event: 'retention_scan_skipped',
            directory,
            error: error instanceof Error ? error.message : String(error),
          },
          'Saklama taraması sırasında dizin okunamadı.',
        );
      }
    }
    return [...tenants];
  };

  type RetentionSource = 'manual' | 'scheduler';

  const runTenantRetention = async (
    tenantId: string,
    source: RetentionSource = 'manual',
  ): Promise<RetentionStats[]> => {
    try {
      const summary = await runRetentionSweep(
        storage,
        queue,
        tenantId,
        config.retention ?? {},
        jobLicenses,
      );
      logger.info({ event: 'retention_sweep', tenantId, source, summary });
      return summary;
    } catch (error) {
      logger.error(
        {
          event: 'retention_sweep_failed',
          tenantId,
          source,
          error: error instanceof Error ? error.message : String(error),
        },
        'Saklama temizliği tamamlanamadı.',
      );
      throw error;
    }
  };

  const runAllTenantRetention = async (
    source: RetentionSource = 'scheduler',
  ): Promise<Record<string, RetentionStats[]>> => {
    const tenantIds = await collectTenantIdsForRetention();
    const results: Record<string, RetentionStats[]> = {};
    for (const tenantId of tenantIds) {
      try {
        results[tenantId] = await runTenantRetention(tenantId, source);
      } catch (error) {
        logger.warn(
          {
            event: 'retention_sweep_tenant_skipped',
            tenantId,
            source,
            error: error instanceof Error ? error.message : String(error),
          },
          'Kiracı saklama temizliği bir hata nedeniyle atlandı.',
        );
      }
    }
    return results;
  };

  let retentionSweepTimer: NodeJS.Timeout | undefined;
  let retentionSweepPromise: Promise<void> | null = null;
  let retentionSweepRunning = false;

  const hasConfiguredRetention = Object.values(config.retention ?? {}).some(
    (policy) => policy && policy.maxAgeMs !== undefined,
  );

  const triggerScheduledRetention = (): Promise<void> => {
    if (retentionSweepRunning) {
      return retentionSweepPromise ?? Promise.resolve();
    }
    retentionSweepRunning = true;
    const execution = runAllTenantRetention('scheduler')
      .then(() => undefined)
      .catch((error) => {
        logger.error(
          {
            event: 'retention_scheduler_failed',
            error: error instanceof Error ? error.message : String(error),
          },
          'Planlı saklama temizliği sırasında hata oluştu.',
        );
      })
      .finally(() => {
        retentionSweepRunning = false;
        retentionSweepPromise = null;
      });
    retentionSweepPromise = execution;
    return execution;
  };

  if (
    config.retentionScheduler?.intervalMs &&
    config.retentionScheduler.intervalMs > 0 &&
    hasConfiguredRetention
  ) {
    retentionSweepTimer = setInterval(() => {
      void triggerScheduledRetention();
    }, config.retentionScheduler.intervalMs);
    logger.info(
      {
        event: 'retention_scheduler_started',
        intervalMs: config.retentionScheduler.intervalMs,
      },
      'Saklama temizliği zamanlayıcısı etkinleştirildi.',
    );
  }

  const requireLicenseToken = async (req: Request, fileMap?: FileMap): Promise<VerifiedLicense> => {
    const headerValue = req.get(LICENSE_HEADER);
    if (headerValue) {
      const estimatedSize = estimateBase64DecodedSize(headerValue);
      if (Buffer.byteLength(headerValue, 'utf8') > licenseHeaderMaxBytes || estimatedSize > licenseMaxBytes) {
        throw new HttpError(413, 'LICENSE_TOO_LARGE', 'Lisans belirteci izin verilen boyutu aşıyor.', {
          limit: licenseMaxBytes,
        });
      }
      const decoded = decodeBase64Strict(headerValue, 'Lisans belirteci');
      ensureLicenseWithinLimit(decoded.byteLength);
      return verifyLicenseFromBuffer(decoded);
    }

    if (fileMap) {
      const licenseFiles = fileMap[LICENSE_FILE_FIELD];
      if (licenseFiles && licenseFiles[0]) {
        const [licenseFile] = licenseFiles;
        delete fileMap[LICENSE_FILE_FIELD];
        try {
          const license = await verifyLicenseFromFile(licenseFile.path);
          return license;
        } finally {
          await fsPromises.rm(licenseFile.path, { force: true }).catch(() => undefined);
        }
      }
    }

    throw new HttpError(401, 'LICENSE_REQUIRED', 'Geçerli bir lisans anahtarı sağlanmalıdır.');
  };

  const requireLicenseFeature = (license: VerifiedLicense, feature: string): void => {
    const features = Array.isArray(license.payload.features) ? license.payload.features : [];
    if (!features.includes(feature)) {
      throw new HttpError(
        403,
        'LICENSE_FEATURE_REQUIRED',
        'Bu işlem için gerekli lisans özelliği etkin değil.',
        { requiredFeature: feature },
      );
    }
  };

  const maxUploadSize = config.maxUploadSizeBytes ?? 25 * 1024 * 1024;
  const uploadPolicies = mergeUploadPolicies(maxUploadSize, config.uploadPolicies);
  const scanner = config.scanner ?? createNoopScanner();
  const uploadTempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'soipack-upload-'));

  const upload = multer({
    storage: multer.diskStorage({
      destination: (_req, _file, cb) => {
        cb(null, uploadTempDir);
      },
      filename: (_req, file, cb) => {
        const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1_000_000_000)}`;
        const safeName = sanitizeUploadFileName(file.originalname);
        cb(null, `${uniqueSuffix}-${safeName}`);
      },
    }),
    limits: {
      fileSize: maxUploadSize,
    },
  });

  const jsonBodyLimit = Math.max(1, config.jsonBodyLimitBytes ?? DEFAULT_JSON_BODY_LIMIT_BYTES);
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', config.trustProxy ?? false);
  app.use(
    helmet({
      hsts: {
        maxAge: 31_536_000,
        includeSubDomains: true,
        preload: true,
      },
    }),
  );
  app.listen = (((...args: Parameters<typeof app.listen>) => {
    void args;
    throw new Error(PLAINTEXT_LISTEN_ERROR_MESSAGE);
  }) as unknown as typeof app.listen);

  app.use((req, _res, next) => {
    const preferred = parseAcceptLanguage(req.headers['accept-language']);
    const locale = resolveLocale(preferred);
    setRequestLocale(req, locale);
    next();
  });

  app.use((req, res, next) => {
    const requestContext = { id: randomUUID(), startedAtNs: process.hrtime.bigint() };
    setRequestContext(req, requestContext);
    res.setHeader('X-Request-Id', requestContext.id);

    let completed = false;
    const finalize = (result: 'finish' | 'close') => {
      if (completed) {
        return;
      }
      completed = true;

      const storedContext = getRequestContext(req);
      const startedAtNs = storedContext?.startedAtNs ?? requestContext.startedAtNs;
      const requestId = storedContext?.id ?? requestContext.id;
      const durationSeconds = Number(process.hrtime.bigint() - startedAtNs) / 1_000_000_000;
      const method = req.method?.toUpperCase() ?? 'UNKNOWN';
      const status = res.statusCode;
      let tenantId: string | undefined;
      try {
        tenantId = getAuthContext(req).tenantId;
      } catch {
        tenantId = undefined;
      }
      const route = getRouteLabel(req);
      const labels = { method, route, status: `${status}` } as const;
      httpRequestCounter.inc(labels);
      httpRequestDurationHistogram.observe(labels, durationSeconds);

      logger.info({
        event: 'http_request',
        requestId,
        method,
        route,
        status,
        durationMs: durationSeconds * 1000,
        tenantId,
        remoteAddress: req.ip || req.socket.remoteAddress || 'unknown',
        result,
      });
    };

    res.on('finish', () => finalize('finish'));
    res.on('close', () => finalize('close'));

    next();
  });

  const globalRateLimiter = config.rateLimit?.global;
  if (globalRateLimiter) {
    const windowMs = Math.max(1, globalRateLimiter.windowMs);
    const max = Math.max(1, globalRateLimiter.max);
    app.use(
      expressRateLimit({
        windowMs,
        max,
        standardHeaders: true,
        legacyHeaders: false,
        handler: (_req, _res, nextHandler, options) => {
          const retryAfterSeconds = Math.max(1, Math.ceil(options.windowMs / 1000));
          nextHandler(
            new HttpError(
              429,
              'GLOBAL_RATE_LIMIT_EXCEEDED',
              translate('errors.server.globalRateLimitExceeded', { locale: DEFAULT_LOCALE }),
              {
                scope: 'global',
                windowMs: options.windowMs,
                limit: options.max,
                retryAfterSeconds,
              },
              { messageKey: 'errors.server.globalRateLimitExceeded' },
            ),
          );
        },
      }),
    );
  }

  const ipRateLimiter = config.rateLimit?.ip
    ? createSlidingWindowRateLimiter('ip', config.rateLimit.ip)
    : undefined;
  if (ipRateLimiter) {
    app.use((req, _res, next) => {
      try {
        const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
        ipRateLimiter(clientIp);
        next();
      } catch (error) {
        next(error);
      }
    });
  }

  app.use(express.json({ limit: jsonBodyLimit }));

  const apiKeyAuthorizer = createApiKeyAuthorizer();
  if (apiKeyAuthorizer.isEnabled()) {
    app.use(apiKeyAuthorizer.require());
  }

  const tenantRateLimiter = config.rateLimit?.tenant
    ? createSlidingWindowRateLimiter('tenant', config.rateLimit.tenant)
    : undefined;

  const adminScopes = normalizeScopeList(config.auth.adminScopes);
  const requireAuth = createAuthMiddleware(config.auth, {
    tenantRateLimiter,
    onAuthenticated: (tenantId: string) => {
      knownTenants.add(tenantId);
    },
  });
  const ensureAdminScope = (req: Request): void => {
    const { hasAdminScope } = getAuthContext(req);
    if (adminScopes.length > 0 && !hasAdminScope) {
      throw new HttpError(
        403,
        'INSUFFICIENT_SCOPE',
        'Bu uç nokta yönetici yetkisi gerektirir.',
        { requiredScopes: adminScopes },
      );
    }
    if (config.requireAdminClientCertificate) {
      const socket = req.socket;
      if (!(socket instanceof TLSSocket) || !socket.authorized) {
        const reason =
          socket instanceof TLSSocket
            ? socket.authorizationError ?? 'TLS_CLIENT_CERT_REQUIRED'
            : 'NON_TLS_CONNECTION';
        throw new HttpError(
          403,
          'ADMIN_CLIENT_CERT_REQUIRED',
          'Yönetici işlemleri için geçerli istemci sertifikası gerekiyor.',
          { reason },
        );
      }
    }
  };
  const maxQueuedJobsPerTenant = Math.max(1, config.maxQueuedJobsPerTenant ?? 5);
  const maxQueuedJobsTotal =
    config.maxQueuedJobsTotal !== undefined ? Math.max(1, config.maxQueuedJobsTotal) : undefined;
  const workerConcurrency = Math.max(1, config.workerConcurrency ?? 1);
  const queue = new JobQueue(workerConcurrency, {
    directory: queueDirectory,
    createRunner: (context) => {
      const handler = jobHandlers[context.kind] as JobHandler<JobKind>;
      const run = () => handler(context as JobExecutionContext<JobPayloadMap[JobKind]>);
      return instrumentJobRun(
        {
          tenantId: context.tenantId,
          id: context.id,
          kind: context.kind,
          hash: context.hash,
        },
        run,
      );
    },
  });

  const getActiveJobCount = (tenantId: string): number =>
    queue
      .list(tenantId)
      .filter((job) => job.status === 'queued' || job.status === 'running').length;

  const getTotalActiveJobCount = (): number => {
    let total = 0;
    for (const tenant of knownTenants) {
      total += getActiveJobCount(tenant);
    }
    return total;
  };

  const updateQueueDepth = (tenantId: string): void => {
    const activeJobs = getActiveJobCount(tenantId);
    jobQueueDepthGauge.set({ tenantId }, activeJobs);
    jobQueueTotalGauge.set(getTotalActiveJobCount());
  };

  const ensureQueueWithinLimit = (tenantId: string): void => {
    const activeJobs = getActiveJobCount(tenantId);
    if (activeJobs >= maxQueuedJobsPerTenant) {
      throw new HttpError(
        429,
        'QUEUE_LIMIT_EXCEEDED',
        'Kiracı için kuyrukta bekleyen iş limiti aşıldı.',
        { limit: maxQueuedJobsPerTenant, scope: 'tenant' },
      );
    }
    if (maxQueuedJobsTotal !== undefined) {
      const totalActiveJobs = getTotalActiveJobCount();
      if (totalActiveJobs >= maxQueuedJobsTotal) {
        throw new HttpError(
          429,
          'QUEUE_LIMIT_EXCEEDED',
          'Sunucu genelinde kuyrukta bekleyen iş limiti aşıldı.',
          { limit: maxQueuedJobsTotal, scope: 'global' },
        );
      }
    }
  };

  function instrumentJobRun<T>(
    context: { tenantId: string; id: string; kind: JobKind; hash: string },
    run: () => Promise<T>,
  ): () => Promise<T> {
    return async () => {
      const startedAt = process.hrtime.bigint();
      try {
        const result = await run();
        const durationNs = process.hrtime.bigint() - startedAt;
        const durationSeconds = Number(durationNs) / 1_000_000_000;
        jobDurationHistogram.observe(
          { tenantId: context.tenantId, kind: context.kind, status: 'completed' },
          durationSeconds,
        );
        logger.info({
          event: 'job_completed',
          tenantId: context.tenantId,
          jobId: context.id,
          kind: context.kind,
          hash: context.hash,
          durationMs: durationSeconds * 1000,
        });
        setImmediate(() => updateQueueDepth(context.tenantId));
        return result;
      } catch (error) {
        const durationNs = process.hrtime.bigint() - startedAt;
        const durationSeconds = Number(durationNs) / 1_000_000_000;
        const normalized = toHttpError(error, {
          code: 'JOB_FAILED',
          message: 'İş başarısız oldu.',
          statusCode: 500,
        });
        jobDurationHistogram.observe(
          { tenantId: context.tenantId, kind: context.kind, status: 'failed' },
          durationSeconds,
        );
        jobErrorCounter.inc({
          tenantId: context.tenantId,
          kind: context.kind,
          code: normalized.code,
        });
        logger.error(
          {
            event: 'job_failed',
            tenantId: context.tenantId,
            jobId: context.id,
            kind: context.kind,
            hash: context.hash,
            durationMs: durationSeconds * 1000,
            error: {
              code: normalized.code,
              message: normalized.message,
              details: normalized.details ?? undefined,
            },
          },
          normalized.message,
        );
        setImmediate(() => updateQueueDepth(context.tenantId));
        throw error;
      }
    };
  }

  const enqueueObservedJob = <TResult, TPayload>(options: {
    tenantId: string;
    id: string;
    kind: JobKind;
    hash: string;
    payload: TPayload;
  }): JobDetails<TResult> => {
    ensureQueueWithinLimit(options.tenantId);
    const job = queue.enqueue<TPayload, TResult>({
      tenantId: options.tenantId,
      id: options.id,
      kind: options.kind,
      hash: options.hash,
      payload: options.payload,
    });
    logger.info({
      event: 'job_created',
      tenantId: options.tenantId,
      jobId: options.id,
      kind: options.kind,
      hash: options.hash,
    });
    updateQueueDepth(options.tenantId);
    return job;
  };

  const sendJobResponse = <T>(
    res: Response,
    job: JobDetails<T>,
    tenantId: string,
    options?: { reused?: boolean },
  ): void => {
    respondWithJob(res, job, options);
    if (options?.reused) {
      logger.info({
        event: 'job_reused',
        tenantId,
        jobId: job.id,
        kind: job.kind,
        hash: job.hash,
        status: job.status,
      });
    }
  };

  app.get(
    '/health',
    createAsyncHandler(async (req, res) => {
      if (expectedHealthcheckAuthorization) {
        const authorization = req.get('Authorization');
        if (authorization !== expectedHealthcheckAuthorization) {
          throw new HttpError(
            401,
            'UNAUTHORIZED',
            'Sağlık kontrolü için bearer kimlik doğrulaması gerekiyor.',
          );
        }
      }
      res.json({ status: 'ok' });
    }),
  );

  app.get(
    '/evidence',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId } = getAuthContext(req);
      const store = evidenceStore.get(tenantId);
      const items = store ? Array.from(store.values()).map((record) => serializeEvidenceRecord(record)) : [];
      res.json({ items });
    }),
  );

  app.get(
    '/evidence/:id',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId } = getAuthContext(req);
      const { id } = req.params as { id?: string };
      if (!id) {
        throw new HttpError(400, 'INVALID_REQUEST', 'Kanıt kimliği belirtilmelidir.');
      }
      const record = getTenantEvidenceMap(tenantId).get(id);
      if (!record) {
        throw new HttpError(404, 'EVIDENCE_NOT_FOUND', 'İstenen kanıt bulunamadı.');
      }
      res.json(serializeEvidenceRecord(record, { includeContent: true }));
    }),
  );

  app.post(
    '/evidence/upload',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId } = getAuthContext(req);
      const body = req.body as { filename?: unknown; content?: unknown; metadata?: unknown };
      if (!body || typeof body !== 'object') {
        throw new HttpError(400, 'INVALID_REQUEST', 'Geçerli bir JSON gövdesi gereklidir.');
      }

      const filenameRaw = body.filename;
      if (typeof filenameRaw !== 'string' || filenameRaw.trim().length === 0) {
        throw new HttpError(400, 'INVALID_REQUEST', 'filename alanı zorunludur.');
      }

      const contentRaw = body.content;
      if (typeof contentRaw !== 'string' || contentRaw.trim().length === 0) {
        throw new HttpError(400, 'INVALID_REQUEST', 'content alanı base64 kodlu olmalıdır.');
      }

      const metadataRaw = body.metadata;
      if (!metadataRaw || typeof metadataRaw !== 'object') {
        throw new HttpError(400, 'INVALID_REQUEST', 'metadata alanı zorunludur.');
      }

      const metadata = metadataRaw as Record<string, unknown>;
      const shaValue = metadata.sha256;
      if (typeof shaValue !== 'string' || !isValidSha256Hex(shaValue)) {
        throw new HttpError(400, 'INVALID_HASH', 'metadata.sha256 geçerli bir SHA-256 hex değeri olmalıdır.');
      }

      let buffer: Buffer;
      try {
        buffer = Buffer.from(contentRaw, 'base64');
      } catch {
        throw new HttpError(400, 'INVALID_CONTENT', 'content alanı base64 kodlu olmalıdır.');
      }

      const normalizedContent = contentRaw.replace(/\s+/g, '');
      if (buffer.toString('base64') !== normalizedContent) {
        throw new HttpError(400, 'INVALID_CONTENT', 'content alanı base64 kodlu olmalıdır.');
      }

      if (buffer.length === 0) {
        throw new HttpError(400, 'INVALID_CONTENT', 'Boş kanıt yüklenemez.');
      }

      const computedHash = createHash('sha256').update(buffer).digest('hex');
      const providedHash = shaValue.toLowerCase();
      if (computedHash !== providedHash) {
        throw new HttpError(400, 'HASH_MISMATCH', 'Gönderilen SHA-256 değeri içerikle eşleşmiyor.', {
          expected: computedHash,
          provided: providedHash,
        });
      }

      if (metadata.size !== undefined) {
        const sizeNumber = Number(metadata.size);
        if (!Number.isFinite(sizeNumber) || sizeNumber < 0) {
          throw new HttpError(400, 'INVALID_METADATA', 'metadata.size sayısal bir değer olmalıdır.');
        }
        if (Math.trunc(sizeNumber) !== buffer.length) {
          throw new HttpError(400, 'SIZE_MISMATCH', 'metadata.size değeri içerik boyutu ile eşleşmiyor.', {
            expected: Math.trunc(sizeNumber),
            actual: buffer.length,
          });
        }
      }

      const normalizedMetadata: Record<string, unknown> = { ...metadata };
      normalizedMetadata.sha256 = computedHash;
      normalizedMetadata.size = buffer.length;

      const currentVersion = tenantSnapshotVersions.get(tenantId);
      if (currentVersion?.isFrozen) {
        throw new HttpError(409, 'CONFIG_FROZEN', 'Kiracı konfigürasyonu donduruldu.');
      }

      const hashIndex = getTenantEvidenceHashIndex(tenantId);
      const existingId = hashIndex.get(computedHash);
      if (existingId) {
        const existingRecord = getTenantEvidenceMap(tenantId).get(existingId);
        if (existingRecord) {
          res.status(200).json(serializeEvidenceRecord(existingRecord));
          return;
        }
      }

      const uploadedAt = new Date().toISOString();
      const snapshotVersion = createSnapshotVersion(computedHash, { createdAt: uploadedAt });
      const snapshotId = createSnapshotIdentifier(uploadedAt, computedHash);
      normalizedMetadata.snapshotId = snapshotId;

      const record: EvidenceRecord = {
        id: randomUUID(),
        tenantId,
        filename: sanitizeUploadFileName(filenameRaw),
        sha256: computedHash,
        size: buffer.length,
        uploadedAt,
        metadata: normalizedMetadata,
        contentEncoding: 'base64',
        content: buffer.toString('base64'),
        snapshotId,
        snapshotVersion,
      };

      const tenantEvidence = getTenantEvidenceMap(tenantId);
      tenantEvidence.set(record.id, record);
      hashIndex.set(computedHash, record.id);
      const version = updateTenantSnapshotVersion(tenantId, uploadedAt);
      persistTenantEvidence(tenantId);
      persistTenantSnapshotVersion(tenantId, version);

      res.status(201).json(serializeEvidenceRecord(record));
    }),
  );

  app.post(
    '/v1/config/freeze',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId } = getAuthContext(req);
      const current = ensureTenantSnapshotVersion(tenantId);
      if (current.isFrozen) {
        res.json({ version: current });
        return;
      }
      const frozen = freezeSnapshotVersion(current, { frozenAt: new Date().toISOString() });
      tenantSnapshotVersions.set(tenantId, frozen);
      persistTenantSnapshotVersion(tenantId, frozen);
      res.json({ version: frozen });
    }),
  );

  app.get(
    '/compliance',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId } = getAuthContext(req);
      const store = complianceStore.get(tenantId);
      const items = store ? Array.from(store.values()).map((record) => serializeComplianceRecord(record)) : [];
      res.json({ items });
    }),
  );

  app.get(
    '/compliance/:id',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId } = getAuthContext(req);
      const { id } = req.params as { id?: string };
      if (!id) {
        throw new HttpError(400, 'INVALID_REQUEST', 'Uyum kaydı kimliği belirtilmelidir.');
      }
      const record = getTenantComplianceMap(tenantId).get(id);
      if (!record) {
        throw new HttpError(404, 'COMPLIANCE_NOT_FOUND', 'İstenen uyum kaydı bulunamadı.');
      }
      res.json(serializeComplianceRecord(record));
    }),
  );

  app.post(
    '/compliance',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId } = getAuthContext(req);
      const body = req.body as {
        matrix?: unknown;
        coverage?: unknown;
        metadata?: unknown;
        sha256?: unknown;
      };

      if (!body || typeof body !== 'object') {
        throw new HttpError(400, 'INVALID_REQUEST', 'Geçerli bir JSON gövdesi gereklidir.');
      }

      if (typeof body.sha256 !== 'string' || !isValidSha256Hex(body.sha256)) {
        throw new HttpError(400, 'INVALID_HASH', 'sha256 alanı geçerli bir SHA-256 hex değeri olmalıdır.');
      }
      const providedHash = body.sha256.toLowerCase();

      if (!body.matrix || typeof body.matrix !== 'object') {
        throw new HttpError(400, 'INVALID_REQUEST', 'matrix alanı zorunludur.');
      }

      const matrixRaw = body.matrix as Record<string, unknown>;
      const summaryRaw = matrixRaw.summary;
      if (!summaryRaw || typeof summaryRaw !== 'object') {
        throw new HttpError(400, 'INVALID_REQUEST', 'matrix.summary alanı zorunludur.');
      }

      const summaryRecord = summaryRaw as Record<string, unknown>;
      const parseSummaryValue = (key: keyof ComplianceSummary): number => {
        const value = summaryRecord[key];
        const numeric = Number(value);
        if (!Number.isFinite(numeric)) {
          throw new HttpError(400, 'INVALID_SUMMARY', `matrix.summary.${key} sayısal olmalıdır.`);
        }
        const normalized = Math.trunc(numeric);
        if (normalized < 0) {
          throw new HttpError(400, 'INVALID_SUMMARY', `matrix.summary.${key} negatif olamaz.`);
        }
        return normalized;
      };

      const summary: ComplianceSummary = {
        total: parseSummaryValue('total'),
        covered: parseSummaryValue('covered'),
        partial: parseSummaryValue('partial'),
        missing: parseSummaryValue('missing'),
      };

      if (!Array.isArray(matrixRaw.requirements) || matrixRaw.requirements.length === 0) {
        throw new HttpError(400, 'INVALID_REQUEST', 'matrix.requirements en az bir öğe içermelidir.');
      }

      const allowedStatuses = new Set<ComplianceRequirementEntry['status']>(['covered', 'partial', 'missing']);
      const tenantEvidence = getTenantEvidenceMap(tenantId);
      const requirements: ComplianceRequirementEntry[] = matrixRaw.requirements.map((entry, index) => {
        if (!entry || typeof entry !== 'object') {
          throw new HttpError(400, 'INVALID_REQUEST', `matrix.requirements[${index}] geçerli bir nesne olmalıdır.`);
        }
        const record = entry as Record<string, unknown>;
        const idValue = record.id;
        if (typeof idValue !== 'string' || idValue.trim().length === 0) {
          throw new HttpError(400, 'INVALID_REQUEST', `matrix.requirements[${index}].id zorunludur.`);
        }
        const statusValue = record.status;
        if (typeof statusValue !== 'string' || !allowedStatuses.has(statusValue as ComplianceRequirementEntry['status'])) {
          throw new HttpError(400, 'INVALID_REQUEST', `matrix.requirements[${index}].status geçerli değil.`);
        }
        const evidenceIdsRaw = record.evidenceIds;
        const evidenceIds = Array.isArray(evidenceIdsRaw)
          ? (evidenceIdsRaw as unknown[])
              .map((value) => (typeof value === 'string' ? value.trim() : ''))
              .filter((value): value is string => value.length > 0)
          : [];
        evidenceIds.forEach((evidenceId) => {
          if (!tenantEvidence.has(evidenceId)) {
            throw new HttpError(
              400,
              'EVIDENCE_NOT_FOUND',
              `matrix.requirements[${index}].evidenceIds bilinmeyen kanıt içeriyor: ${evidenceId}.`,
            );
          }
        });
        const requirement: ComplianceRequirementEntry = {
          id: idValue.trim(),
          status: statusValue as ComplianceRequirementEntry['status'],
          evidenceIds,
        };
        if (typeof record.title === 'string' && record.title.trim().length > 0) {
          requirement.title = record.title.trim();
        }
        return requirement;
      });

      if (summary.total !== requirements.length) {
        throw new HttpError(400, 'INVALID_SUMMARY', 'matrix.summary.total gereksinim sayısı ile eşleşmelidir.');
      }

      if (summary.covered + summary.partial + summary.missing > summary.total) {
        throw new HttpError(
          400,
          'INVALID_SUMMARY',
          'matrix.summary değerlerinin toplamı toplam sayısını aşamaz.',
        );
      }

      if (!body.coverage || typeof body.coverage !== 'object') {
        throw new HttpError(400, 'INVALID_REQUEST', 'coverage alanı zorunludur.');
      }

      const coverageRaw = body.coverage as Record<string, unknown>;
      const parseCoverageValue = (key: keyof CoverageSummaryPayload): number | undefined => {
        const value = coverageRaw[key as string];
        if (value === undefined || value === null) {
          return undefined;
        }
        const numeric = Number(value);
        if (!Number.isFinite(numeric) || numeric < 0) {
          throw new HttpError(400, 'INVALID_COVERAGE', `coverage.${String(key)} değeri geçerli bir sayı olmalıdır.`);
        }
        return Math.round(numeric * 1000) / 1000;
      };

      const coverage: CoverageSummaryPayload = {};
      (['statements', 'branches', 'functions', 'lines'] as Array<keyof CoverageSummaryPayload>).forEach((key) => {
        const value = parseCoverageValue(key);
        if (value !== undefined) {
          coverage[key] = value;
        }
      });

      const metadataRaw = body.metadata;
      const metadata =
        metadataRaw && typeof metadataRaw === 'object'
          ? (metadataRaw as Record<string, unknown>)
          : undefined;

      const project = typeof matrixRaw.project === 'string' ? matrixRaw.project : undefined;
      const level = typeof matrixRaw.level === 'string' ? matrixRaw.level : undefined;
      const generatedAt =
        typeof matrixRaw.generatedAt === 'string' ? matrixRaw.generatedAt : undefined;

      const canonicalMetadata: Record<string, unknown> = {};
      if (metadata) {
        Object.entries(metadata).forEach(([key, value]) => {
          if (value !== undefined) {
            canonicalMetadata[key] = value;
          }
        });
      }

      const canonicalPayload = {
        matrix: {
          project,
          level,
          generatedAt,
          requirements,
          summary,
        },
        coverage,
        metadata: canonicalMetadata,
      } satisfies {
        matrix: ComplianceMatrixPayload;
        coverage: CoverageSummaryPayload;
        metadata: Record<string, unknown>;
      };

      const computedHash = computeObjectSha256(canonicalPayload);
      if (computedHash !== providedHash) {
        throw new HttpError(400, 'COMPLIANCE_HASH_MISMATCH', 'Gönderilen sha256 değeri hesaplanan özet ile eşleşmiyor.', {
          expected: computedHash,
          provided: providedHash,
        });
      }

      const record: ComplianceRecord = {
        id: randomUUID(),
        tenantId,
        sha256: computedHash,
        createdAt: new Date().toISOString(),
        matrix: { project, level, generatedAt, requirements, summary },
        coverage,
        metadata: Object.keys(canonicalMetadata).length > 0 ? canonicalMetadata : undefined,
      };

      getTenantComplianceMap(tenantId).set(record.id, record);
      persistTenantCompliance(tenantId);

      res.status(201).json(serializeComplianceRecord(record));
    }),
  );

  app.get(
    '/v1/jobs',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId } = getAuthContext(req);
      const kinds = parseFilterParam<JobKind>(req.query.kind as unknown, JOB_KINDS, 'İş türü');
      const statuses = parseFilterParam<JobStatus>(
        req.query.status as unknown,
        JOB_STATUSES,
        'İş durumu',
      );
      const jobs = queue
        .list(tenantId)
        .filter((job) => jobMatchesFilters(job, kinds, statuses))
        .map(serializeJobSummary);
      res.json({ jobs });
    }),
  );

  app.get(
    '/v1/jobs/:id(*)',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId } = getAuthContext(req);
      const { id } = req.params as { id?: string };
      if (!id) {
        throw new HttpError(400, 'INVALID_REQUEST', 'İş kimliği belirtilmelidir.');
      }
      assertJobId(id);
      const job =
        queue.get(tenantId, id) ??
        (await locateJobMetadata(storage, queue, tenantId, id, (metadata) =>
          hydrateJobLicense(metadata, tenantId),
        ));
      if (!job) {
        throw new HttpError(404, 'JOB_NOT_FOUND', 'İstenen iş bulunamadı.');
      }
      res.json(serializeJobDetails(job));
    }),
  );

  app.get(
    '/v1/manifests/:manifestId',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId } = getAuthContext(req);
      const { manifestId } = req.params as { manifestId?: string };
      if (!manifestId) {
        throw new HttpError(400, 'INVALID_REQUEST', 'manifestId belirtilmelidir.');
      }
      if (!/^[A-Za-z0-9._-]+$/.test(manifestId)) {
        throw new HttpError(400, 'INVALID_REQUEST', 'manifestId değeri geçerli değil.');
      }

      const metadata = await findPackMetadataByManifestId(
        storage,
        directories,
        tenantId,
        manifestId,
      );
      if (!metadata) {
        throw new HttpError(404, 'MANIFEST_NOT_FOUND', 'İstenen manifest bulunamadı.');
      }

      const manifestPath = metadata.outputs?.manifestPath;
      if (!manifestPath || !(await storage.fileExists(manifestPath))) {
        throw new HttpError(404, 'MANIFEST_NOT_FOUND', 'Manifest dosyası bulunamadı.');
      }

      const manifest = await storage.readJson<Record<string, unknown>>(manifestPath);
      res.json({
        manifestId: metadata.outputs.manifestId,
        jobId: metadata.id,
        manifest,
      });
    }),
  );

  const createPackageStreamHandler = (
    selector: (metadata: PackJobMetadata) => string | undefined,
    notFoundCode: string,
    notFoundMessage: string,
    options: { contentType: string; fallbackName: string },
  ) =>
    createAsyncHandler(async (req: Request, res: Response) => {
      const { tenantId } = getAuthContext(req);
      const { id } = req.params as { id?: string };
      const { metadata } = await resolvePackageMetadata(storage, directories, tenantId, id);

      await streamPackageArtifact(res, storage, selector(metadata), notFoundCode, notFoundMessage, options);
    });

  app.get(
    '/v1/packages/:id(*)/archive',
    requireAuth,
    createPackageStreamHandler(
      (metadata) => metadata.outputs?.archivePath,
      'PACKAGE_NOT_FOUND',
      'Paket arşiv dosyası bulunamadı.',
      { contentType: 'application/zip', fallbackName: 'package.zip' },
    ),
  );

  app.get(
    '/v1/packages/:id(*)/manifest',
    requireAuth,
    createPackageStreamHandler(
      (metadata) => metadata.outputs?.manifestPath,
      'MANIFEST_NOT_FOUND',
      'Manifest dosyası bulunamadı.',
      { contentType: 'application/json; charset=utf-8', fallbackName: 'manifest.json' },
    ),
  );

  app.get('/v1/packages/:id(*)', requireAuth, createPackageStreamHandler(
    (metadata) => metadata.outputs?.archivePath,
    'PACKAGE_NOT_FOUND',
    'Paket arşiv dosyası bulunamadı.',
    { contentType: 'application/zip', fallbackName: 'package.zip' },
  ));

  app.post(
    '/v1/admin/cleanup',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      ensureAdminScope(req);
      const { tenantId } = getAuthContext(req);
      const summary = await runTenantRetention(tenantId, 'manual');
      res.json({ status: 'ok', summary });
    }),
  );

  app.post(
    '/v1/jobs/:id(*)/cancel',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId } = getAuthContext(req);
      const { id } = req.params as { id?: string };
      if (!id) {
        throw new HttpError(400, 'INVALID_REQUEST', 'İş kimliği belirtilmelidir.');
      }
      assertJobId(id);

      const job = queue.get(tenantId, id);
      if (!job) {
        throw new HttpError(404, 'JOB_NOT_FOUND', 'İstenen iş bulunamadı.');
      }
      if (job.status === 'running') {
        throw new HttpError(409, 'JOB_RUNNING', 'Çalışan işler iptal edilemez.');
      }
      if (job.status !== 'queued') {
        throw new HttpError(
          409,
          'JOB_NOT_CANCELLABLE',
          'Yalnızca kuyruğa alınmış işler iptal edilebilir.',
        );
      }

      queue.remove(tenantId, id);
      await removeJobArtifacts(storage, directories, tenantId, id, job.kind);
      jobLicenses.delete(createScopedJobKey(tenantId, id));
      updateQueueDepth(tenantId);

      res.json({ status: 'cancelled', id, kind: job.kind });
    }),
  );

  app.delete(
    '/v1/jobs/:id(*)',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId } = getAuthContext(req);
      const { id } = req.params as { id?: string };
      if (!id) {
        throw new HttpError(400, 'INVALID_REQUEST', 'İş kimliği belirtilmelidir.');
      }
      assertJobId(id);

      let job = queue.get(tenantId, id);
      if (!job) {
        const adopted = await locateJobMetadata(storage, queue, tenantId, id);
        if (!adopted) {
          throw new HttpError(404, 'JOB_NOT_FOUND', 'İstenen iş bulunamadı.');
        }
        job = adopted as JobDetails<unknown>;
      }

      if (job.status === 'running') {
        throw new HttpError(409, 'JOB_RUNNING', 'Çalışan işler silinemez.');
      }
      if (job.status === 'queued') {
        throw new HttpError(409, 'JOB_NOT_FINISHED', 'Önce işi iptal etmelisiniz.');
      }

      queue.remove(tenantId, id);
      await removeJobArtifacts(storage, directories, tenantId, id, job.kind);
      jobLicenses.delete(createScopedJobKey(tenantId, id));
      updateQueueDepth(tenantId);

      res.json({ status: 'deleted', id, kind: job.kind });
    }),
  );

  const importFields = upload.fields([
    { name: LICENSE_FILE_FIELD, maxCount: 1 },
    { name: 'jira', maxCount: 1 },
    { name: 'reqif', maxCount: 1 },
    { name: 'junit', maxCount: 1 },
    { name: 'lcov', maxCount: 1 },
    { name: 'cobertura', maxCount: 1 },
    { name: 'git', maxCount: 1 },
    { name: 'objectives', maxCount: 1 },
    { name: 'traceLinksCsv', maxCount: 1 },
    { name: 'traceLinksJson', maxCount: 1 },
  ]);

  app.post(
    '/v1/import',
    requireAuth,
    importFields,
    createAsyncHandler(async (req, res) => {
      const { tenantId } = getAuthContext(req);
      const fileMap = (req.files as FileMap) ?? {};
      let cleaned = false;
      const ensureCleanup = async () => {
        if (!cleaned) {
          cleaned = true;
          await cleanupUploadedFiles(fileMap);
        }
      };

      try {
        Object.entries(fileMap).forEach(([field, files]) => {
          const policy = uploadPolicies[field] ?? {
            maxSizeBytes: maxUploadSize,
            allowedMimeTypes: ['*'],
          };
          files.forEach((file) => ensureFileWithinPolicy(field, file, policy));
        });

        await scanUploadedFiles(scanner, fileMap);

        const license = await requireLicenseToken(req, fileMap);
        requireLicenseFeature(license, PIPELINE_LICENSE_FEATURES.import);
        const body = req.body as Record<string, unknown>;

        const availableFiles = Object.values(fileMap).reduce((sum, files) => sum + files.length, 0);
        if (availableFiles === 0) {
          throw new HttpError(400, 'NO_INPUT_FILES', 'En az bir veri dosyası yüklenmelidir.');
        }

        const stringFields: Record<string, string> = {};
        ['projectName', 'projectVersion', 'level'].forEach((field) => {
          const value = getFieldValue(body[field]);
          if (value !== undefined) {
            stringFields[field] = value;
          }
        });

        const hashEntries: HashEntry[] = [];
        Object.entries(stringFields).forEach(([key, value]) => {
          hashEntries.push({ key: `field:${key}`, value });
        });
        for (const [field, files] of Object.entries(fileMap)) {
          for (const [index, file] of files.entries()) {
            const fileHash = await hashFileAtPath(file.path);
            hashEntries.push({ key: `file:${field}:${index}`, value: fileHash });
          }
        }

        const hash = computeHash(hashEntries);
        const importId = createJobId(hash);
        const workspaceDir = path.join(directories.workspaces, tenantId, importId);
        const metadataPath = path.join(workspaceDir, METADATA_FILE);

        const existingJob = queue.get<ImportJobResult>(tenantId, importId);
        if (existingJob) {
          ensureJobLicense(tenantId, importId, license);
          await ensureCleanup();
          sendJobResponse(res, existingJob, tenantId, {
            reused: existingJob.status === 'completed',
          });
          return;
        }

        if (await storage.fileExists(metadataPath)) {
          const metadata = await readJobMetadata<ImportJobMetadata>(storage, workspaceDir);
          hydrateJobLicense(metadata, tenantId);
          ensureJobLicense(tenantId, metadata.id, license);
          const adopted = adoptJobFromMetadata(
            storage,
            queue,
            metadata,
          ) as JobDetails<ImportJobResult>;
          await ensureCleanup();
          sendJobResponse(res, adopted, tenantId, { reused: true });
          return;
        }

        const uploadedFiles = convertFileMap(fileMap);
        const level = asCertificationLevel(stringFields.level);

        let persistedUploads: Record<string, string[]>;
        try {
          persistedUploads = await storage.persistUploads(
            path.join(tenantId, importId),
            uploadedFiles,
          );
        } catch (error) {
          await ensureCleanup();
          throw error;
        }

        try {
          const job = enqueueObservedJob<ImportJobResult, ImportJobPayload>({
            tenantId,
            id: importId,
            kind: 'import',
            hash,
            payload: {
              workspaceDir,
              uploads: persistedUploads,
              level: level ?? null,
              projectName: stringFields.projectName ?? null,
              projectVersion: stringFields.projectVersion ?? null,
              license: toLicenseMetadata(license),
            },
          });

          registerJobLicense(tenantId, importId, license);
          sendJobResponse(res, job, tenantId);
        } catch (error) {
          await storage.removeDirectory(path.join(directories.uploads, tenantId, importId));
          throw error;
        }
      } catch (error) {
        await ensureCleanup();
        throw error;
      }
    }),
  );

  app.post(
    '/v1/analyze',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId } = getAuthContext(req);
      const license = await requireLicenseToken(req);
      requireLicenseFeature(license, PIPELINE_LICENSE_FEATURES.analyze);
      const body = req.body as {
        importId?: string;
        level?: string;
        projectName?: string;
        projectVersion?: string;
      };

      if (!body.importId) {
        throw new HttpError(400, 'INVALID_REQUEST', 'importId alanı zorunludur.');
      }

      assertJobId(body.importId);

      const workspaceDir = path.join(directories.workspaces, tenantId, body.importId);
      await assertDirectoryExists(storage, workspaceDir, 'Çalışma alanı');

      const workspace = await storage.readJson<ImportWorkspace>(
        path.join(workspaceDir, 'workspace.json'),
      );
      const effectiveLevel =
        asCertificationLevel(body.level) ?? workspace.metadata.targetLevel ?? 'C';
      const effectiveProjectName = body.projectName ?? workspace.metadata.project?.name;
      const effectiveProjectVersion = body.projectVersion ?? workspace.metadata.project?.version;

      const fallbackObjectivesPath = path.resolve(
        __dirname,
        '../../../data/objectives/do178c_objectives.min.json',
      );
      const objectivesPathRaw = workspace.metadata.objectivesPath ?? fallbackObjectivesPath;
      const repositoryRoot = path.resolve(__dirname, '../../../');
      let objectivesPath = path.isAbsolute(objectivesPathRaw)
        ? objectivesPathRaw
        : path.resolve(repositoryRoot, objectivesPathRaw);
      try {
        await fsPromises.access(objectivesPath, fs.constants.R_OK);
      } catch {
        objectivesPath = fallbackObjectivesPath;
      }

      const hash = computeHash(
        [
          { key: 'importId', value: body.importId },
          { key: 'level', value: effectiveLevel },
          { key: 'projectName', value: effectiveProjectName ?? '' },
          { key: 'projectVersion', value: effectiveProjectVersion ?? '' },
          { key: 'objectives', value: objectivesPath },
        ].filter((entry) => entry.value !== undefined) as HashEntry[],
      );
      const analyzeId = createJobId(hash);
      const analysisDir = path.join(directories.analyses, tenantId, analyzeId);
      const metadataPath = path.join(analysisDir, METADATA_FILE);

      const existingJob = queue.get<AnalyzeJobResult>(tenantId, analyzeId);
      if (existingJob) {
        ensureJobLicense(tenantId, analyzeId, license);
        sendJobResponse(res, existingJob, tenantId, {
          reused: existingJob.status === 'completed',
        });
        return;
      }

      if (await storage.fileExists(metadataPath)) {
        const metadata = await readJobMetadata<AnalyzeJobMetadata>(storage, analysisDir);
        hydrateJobLicense(metadata, tenantId);
        ensureJobLicense(tenantId, metadata.id, license);
        const adopted = adoptJobFromMetadata(
          storage,
          queue,
          metadata,
        ) as JobDetails<AnalyzeJobResult>;
        sendJobResponse(res, adopted, tenantId, { reused: true });
        return;
      }

      const analyzeOptions: AnalyzeOptions = {
        input: workspaceDir,
        output: analysisDir,
        level: effectiveLevel,
        objectives: objectivesPath,
        projectName: effectiveProjectName,
        projectVersion: effectiveProjectVersion,
      };

      const job = enqueueObservedJob<AnalyzeJobResult, AnalyzeJobPayload>({
        tenantId,
        id: analyzeId,
        kind: 'analyze',
        hash,
        payload: {
          workspaceDir,
          analysisDir,
          analyzeOptions,
          importId: body.importId,
          license: toLicenseMetadata(license),
        },
      });

      registerJobLicense(tenantId, analyzeId, license);
      sendJobResponse(res, job, tenantId);
    }),
  );

  app.post(
    '/v1/report',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId } = getAuthContext(req);
      const license = await requireLicenseToken(req);
      requireLicenseFeature(license, PIPELINE_LICENSE_FEATURES.report);
      const body = req.body as { analysisId?: string; manifestId?: string };
      if (!body.analysisId) {
        throw new HttpError(400, 'INVALID_REQUEST', 'analysisId alanı zorunludur.');
      }

      assertJobId(body.analysisId);

      const analysisDir = path.join(directories.analyses, tenantId, body.analysisId);
      await assertDirectoryExists(storage, analysisDir, 'Analiz çıktısı');

      const hashEntries: HashEntry[] = [{ key: 'analysisId', value: body.analysisId }];
      if (body.manifestId) {
        hashEntries.push({ key: 'manifestId', value: body.manifestId });
      }
      const hash = computeHash(hashEntries);
      const reportId = createJobId(hash);
      const reportDir = path.join(directories.reports, tenantId, reportId);
      const metadataPath = path.join(reportDir, METADATA_FILE);

      const existingJob = queue.get<ReportJobResult>(tenantId, reportId);
      if (existingJob) {
        ensureJobLicense(tenantId, reportId, license);
        sendJobResponse(res, existingJob, tenantId, {
          reused: existingJob.status === 'completed',
        });
        return;
      }

      if (await storage.fileExists(metadataPath)) {
        const metadata = await readJobMetadata<ReportJobMetadata>(storage, reportDir);
        hydrateJobLicense(metadata, tenantId);
        ensureJobLicense(tenantId, metadata.id, license);
        const adopted = adoptJobFromMetadata(
          storage,
          queue,
          metadata,
        ) as JobDetails<ReportJobResult>;
        sendJobResponse(res, adopted, tenantId, { reused: true });
        return;
      }

      const reportOptions: ReportOptions = {
        input: analysisDir,
        output: reportDir,
        manifestId: body.manifestId,
      };

      const job = enqueueObservedJob<ReportJobResult, ReportJobPayload>({
        tenantId,
        id: reportId,
        kind: 'report',
        hash,
        payload: {
          analysisDir,
          reportDir,
          reportOptions,
          analysisId: body.analysisId,
          manifestId: body.manifestId ?? null,
          license: toLicenseMetadata(license),
        },
      });

      registerJobLicense(tenantId, reportId, license);
      sendJobResponse(res, job, tenantId);
    }),
  );

  app.post(
    '/v1/pack',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId } = getAuthContext(req);
      const license = await requireLicenseToken(req);
      requireLicenseFeature(license, PIPELINE_LICENSE_FEATURES.pack);
      const body = req.body as { reportId?: string; packageName?: string };
      if (!body.reportId) {
        throw new HttpError(400, 'INVALID_REQUEST', 'reportId alanı zorunludur.');
      }

      assertJobId(body.reportId);

      let packageName: string | undefined;
      if (body.packageName !== undefined) {
        try {
          packageName = normalizePackageName(body.packageName);
        } catch (error) {
          const message =
            error instanceof Error
              ? error.message
              : 'packageName değeri geçersiz.';
          throw new HttpError(400, 'INVALID_REQUEST', message);
        }
      }

      const reportDir = path.join(directories.reports, tenantId, body.reportId);
      await assertDirectoryExists(storage, reportDir, 'Rapor çıktısı');

      const hashEntries: HashEntry[] = [
        { key: 'reportId', value: body.reportId },
        { key: 'packageName', value: packageName ?? '' },
      ];
      const hash = computeHash(hashEntries);
      const packId = createJobId(hash);
      const packageDir = path.join(directories.packages, tenantId, packId);
      const metadataPath = path.join(packageDir, METADATA_FILE);

      const existingJob = queue.get<PackJobResult>(tenantId, packId);
      if (existingJob) {
        ensureJobLicense(tenantId, packId, license);
        sendJobResponse(res, existingJob, tenantId, {
          reused: existingJob.status === 'completed',
        });
        return;
      }

      if (await storage.fileExists(metadataPath)) {
        const metadata = await readJobMetadata<PackJobMetadata>(storage, packageDir);
        hydrateJobLicense(metadata, tenantId);
        ensureJobLicense(tenantId, metadata.id, license);
        const adopted = adoptJobFromMetadata(storage, queue, metadata) as JobDetails<PackJobResult>;
        sendJobResponse(res, adopted, tenantId, { reused: true });
        return;
      }

      const job = enqueueObservedJob<PackJobResult, PackJobPayload>({
        tenantId,
        id: packId,
        kind: 'pack',
        hash,
        payload: {
          reportDir,
          packageDir,
          packageName,
          signingKeyPath,
          reportId: body.reportId,
          license: toLicenseMetadata(license),
        },
      });

      registerJobLicense(tenantId, packId, license);
      sendJobResponse(res, job, tenantId);
    }),
  );

  app.get(
    '/v1/reports/:id/:asset(*)',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId } = getAuthContext(req);
      const { id, asset } = req.params as { id?: string; asset?: string };
      if (!id || !asset) {
        throw new HttpError(400, 'INVALID_REQUEST', 'Rapor kimliği ve dosya yolu belirtilmelidir.');
      }

      const reportDir = path.join(directories.reports, tenantId, id);
      await assertDirectoryExists(storage, reportDir, 'Rapor çıktısı');

      const metadataPath = path.join(reportDir, METADATA_FILE);
      if (!(await storage.fileExists(metadataPath))) {
        throw new HttpError(404, 'NOT_FOUND', 'İstenen rapor bulunamadı.');
      }

      const metadata = await storage.readJson<ReportJobMetadata>(metadataPath);
      if (metadata.tenantId !== tenantId) {
        throw new HttpError(403, 'TENANT_MISMATCH', 'İstenen rapor bu kiracıya ait değil.');
      }

      const safeAsset = asset.replace(/^\/+/, '');
      const targetPath = path.resolve(reportDir, safeAsset);
      const relative = path.relative(reportDir, targetPath);
      if (relative.startsWith('..') || path.isAbsolute(relative)) {
        throw new HttpError(400, 'INVALID_PATH', 'İstenen dosya yolu izin verilen dizin dışında.');
      }

      if (!(await storage.fileExists(targetPath))) {
        throw new HttpError(404, 'NOT_FOUND', 'Rapor dosyası bulunamadı.');
      }

      await new Promise<void>((resolve, reject) => {
        res.sendFile(targetPath, (error) => {
          if (error) {
            reject(error);
          } else {
            resolve();
          }
        });
      });
    }),
  );

  app.get(
    '/metrics',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      ensureAdminScope(req);
      res.set('Content-Type', metricsRegistry.contentType);
      res.send(await metricsRegistry.metrics());
    }),
  );

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  app.use((error: unknown, req: Request, res: Response, _next: NextFunction) => {
    const isPayloadTooLargeError =
      error !== null &&
      typeof error === 'object' &&
      'type' in error &&
      (error as { type?: unknown }).type === 'entity.too.large';

    const normalized =
      error instanceof HttpError
        ? error
        : isPayloadTooLargeError
          ? new HttpError(
              413,
              'PAYLOAD_TOO_LARGE',
              translate('errors.server.payloadTooLarge', { locale: DEFAULT_LOCALE }),
              { limit: jsonBodyLimit },
              { messageKey: 'errors.server.payloadTooLarge' },
            )
          : new HttpError(
              500,
              'UNEXPECTED_ERROR',
              translate('errors.server.unexpected', { locale: DEFAULT_LOCALE }),
              {
                cause: error instanceof Error ? error.message : String(error),
              },
              { messageKey: 'errors.server.unexpected' },
            );

    const locale = getRequestLocale(req);

    if (normalized.statusCode === 429 && normalized.details && typeof normalized.details === 'object') {
      const retryAfterSeconds = (normalized.details as { retryAfterSeconds?: unknown }).retryAfterSeconds;
      if (typeof retryAfterSeconds === 'number' && Number.isFinite(retryAfterSeconds) && retryAfterSeconds > 0) {
        res.set('Retry-After', `${Math.ceil(retryAfterSeconds)}`);
      }
    }
    const localizedMessage =
      normalized.messageKey
        ? translate(normalized.messageKey, {
            locale,
            values: normalized.messageParams,
          })
        : normalized.message;
    res.status(normalized.statusCode).json({
      error: {
        code: normalized.code,
        message: localizedMessage,
        details: normalized.details ?? undefined,
      },
    });
  });

  const lifecycle: ServerLifecycle = {
    waitForIdle: () => queue.waitForIdle(),
    shutdown: async () => {
      if (retentionSweepTimer) {
        clearInterval(retentionSweepTimer);
        retentionSweepTimer = undefined;
      }
      if (retentionSweepPromise) {
        await retentionSweepPromise.catch(() => undefined);
      }
      await fsPromises.rm(uploadTempDir, { recursive: true, force: true }).catch(() => undefined);
    },
    runTenantRetention: (tenantId: string) => runTenantRetention(tenantId, 'manual'),
    runAllTenantRetention: () => runAllTenantRetention('manual'),
    logger,
  };

  Reflect.set(app, SERVER_CONTEXT_SYMBOL, lifecycle);

  return app;
};
