import { createHash, randomUUID } from 'crypto';
import fs, { promises as fsPromises } from 'fs';
import https from 'https';
import os from 'os';
import path from 'path';
import { pipeline as streamPipeline } from 'stream/promises';

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
import { CertificationLevel } from '@soipack/core';
import express, { Express, NextFunction, Request, Response } from 'express';
import multer from 'multer';
import { JWTPayload, createLocalJWKSet, createRemoteJWKSet, jwtVerify } from 'jose';
import type { JSONWebKeySet } from 'jose';

import pino, { type Logger } from 'pino';
import { Counter, Gauge, Histogram, Registry, collectDefaultMetrics } from 'prom-client';

import { TLSSocket } from 'tls';

import { HttpError, toHttpError } from './errors';
import { JobDetails, JobKind, JobQueue, JobStatus, JobSummary } from './queue';
import {
  FileSystemStorage,
  PipelineDirectories,
  StorageProvider,
  UploadedFileMap,
} from './storage';
import { FileScanner, FileScanResult, createNoopScanner } from './scanner';

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
    throw new HttpError(400, 'INVALID_REQUEST', 'Kimlik değeri geçerli değil.');
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

const createSlidingWindowRateLimiter = (
  scope: 'ip' | 'tenant',
  options: RateLimitWindowConfig,
): ((key: string) => void) => {
  const counters = new Map<string, { count: number; resetAt: number }>();
  return (key: string) => {
    const now = Date.now();
    const existing = counters.get(key);
    if (!existing || existing.resetAt <= now) {
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
  storageProvider?: StorageProvider;
  retention?: RetentionConfig;
  uploadPolicies?: UploadPolicyOverrides;
  scanner?: FileScanner;
  logger?: Logger;
  metricsRegistry?: Registry;
  healthcheckToken?: string;
  rateLimit?: RateLimitConfig;
  requireAdminClientCertificate?: boolean;
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
}

export interface RateLimitConfig {
  ip?: RateLimitWindowConfig;
  tenant?: RateLimitWindowConfig;
}

export interface HttpsListenerConfig {
  key: string | Buffer;
  cert: string | Buffer;
  clientCa?: string | Buffer;
}

export const createHttpsServer = (app: Express, tls: HttpsListenerConfig): https.Server => {
  if (!tls.key) {
    throw new Error('TLS özel anahtar dosyası sağlanmalıdır.');
  }
  if (!tls.cert) {
    throw new Error('TLS sertifika dosyası sağlanmalıdır.');
  }

  const options: https.ServerOptions = {
    key: tls.key,
    cert: tls.cert,
  };

  if (tls.clientCa) {
    options.ca = tls.clientCa;
    options.requestCert = true;
    options.rejectUnauthorized = false;
  }

  return https.createServer(options, app);
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

  const logger: Logger = config.logger ?? pino({ name: 'soipack-server' });
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
  app.listen = (((..._args: Parameters<typeof app.listen>) => {
    throw new Error(PLAINTEXT_LISTEN_ERROR_MESSAGE);
  }) as unknown as typeof app.listen);

  app.use((req, res, next) => {
    const requestId = randomUUID();
    const startedAtNs = process.hrtime.bigint();
    setRequestContext(req, { id: requestId, startedAtNs });
    res.setHeader('X-Request-Id', requestId);

    let completed = false;
    const finalize = (result: 'finish' | 'close') => {
      if (completed) {
        return;
      }
      completed = true;

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
  const queue = new JobQueue();

  const getActiveJobCount = (tenantId: string): number =>
    queue
      .list(tenantId)
      .filter((job) => job.status === 'queued' || job.status === 'running').length;

  const updateQueueDepth = (tenantId: string): void => {
    const activeJobs = getActiveJobCount(tenantId);
    jobQueueDepthGauge.set({ tenantId }, activeJobs);
  };

  const ensureQueueWithinLimit = (tenantId: string): void => {
    const activeJobs = getActiveJobCount(tenantId);
    if (activeJobs >= maxQueuedJobsPerTenant) {
      throw new HttpError(
        429,
        'QUEUE_LIMIT_EXCEEDED',
        'Kiracı için kuyrukta bekleyen iş limiti aşıldı.',
        { limit: maxQueuedJobsPerTenant },
      );
    }
  };

  const instrumentJobRun = <T>(
    context: { tenantId: string; id: string; kind: JobKind; hash: string },
    run: () => Promise<T>,
  ): (() => Promise<T>) => {
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
  };

  const enqueueObservedJob = <T>(options: {
    tenantId: string;
    id: string;
    kind: JobKind;
    hash: string;
    run: () => Promise<T>;
  }): JobDetails<T> => {
    ensureQueueWithinLimit(options.tenantId);
    const job = queue.enqueue<T>({
      tenantId: options.tenantId,
      id: options.id,
      kind: options.kind,
      hash: options.hash,
      run: instrumentJobRun(options, options.run),
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

        const job = enqueueObservedJob<ImportJobResult>({
          tenantId,
          id: importId,
          kind: 'import',
          hash,
          run: async () => {
            await storage.ensureDirectory(workspaceDir);

            try {
              const persisted = await storage.persistUploads(
                path.join(tenantId, importId),
                uploadedFiles,
              );
              const importOptions: ImportOptions = {
                output: workspaceDir,
                jira: persisted.jira?.[0],
                reqif: persisted.reqif?.[0],
                junit: persisted.junit?.[0],
                lcov: persisted.lcov?.[0],
                cobertura: persisted.cobertura?.[0],
                git: persisted.git?.[0],
                traceLinksCsv: persisted.traceLinksCsv?.[0],
                traceLinksJson: persisted.traceLinksJson?.[0],
                objectives: persisted.objectives?.[0],
                level,
                projectName: stringFields.projectName,
                projectVersion: stringFields.projectVersion,
              };

              const result = await runImport(importOptions);
              const metadata: ImportJobMetadata = {
                tenantId,
                id: importId,
                hash,
                kind: 'import',
                createdAt: new Date().toISOString(),
                directory: workspaceDir,
                params: {
                  level: level ?? null,
                  projectName: stringFields.projectName ?? null,
                  projectVersion: stringFields.projectVersion ?? null,
                  files: Object.fromEntries(
                    Object.entries(persisted).map(([key, values]) => [
                      key,
                      values.map((value) => path.basename(value)),
                    ]),
                  ),
                },
                license: toLicenseMetadata(license),
                warnings: result.warnings,
                outputs: {
                  workspacePath: path.join(workspaceDir, 'workspace.json'),
                },
              };

              await writeJobMetadata(storage, workspaceDir, metadata);

              return toImportResult(storage, metadata);
            } catch (error) {
              await storage.removeDirectory(workspaceDir);
              await storage.removeDirectory(path.join(directories.uploads, tenantId, importId));
              throw createPipelineError(error, 'Import işlemi sırasında bir hata oluştu.');
            }
          },
        });

        registerJobLicense(tenantId, importId, license);
        sendJobResponse(res, job, tenantId);
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

      const job = enqueueObservedJob<AnalyzeJobResult>({
        tenantId,
        id: analyzeId,
        kind: 'analyze',
        hash,
        run: async () => {
          await storage.ensureDirectory(analysisDir);
          try {
            const analyzeOptions: AnalyzeOptions = {
              input: workspaceDir,
              output: analysisDir,
              level: effectiveLevel,
              objectives: objectivesPath,
              projectName: effectiveProjectName,
              projectVersion: effectiveProjectVersion,
            };
            const result = await runAnalyze(analyzeOptions);

            const metadata: AnalyzeJobMetadata = {
              tenantId,
              id: analyzeId,
              hash,
              kind: 'analyze',
              createdAt: new Date().toISOString(),
              directory: analysisDir,
              params: {
                importId: body.importId,
                level: effectiveLevel,
                projectName: effectiveProjectName ?? null,
                projectVersion: effectiveProjectVersion ?? null,
                objectivesPath,
              },
              license: toLicenseMetadata(license),
              exitCode: result.exitCode,
              outputs: {
                snapshotPath: path.join(analysisDir, 'snapshot.json'),
                tracePath: path.join(analysisDir, 'traces.json'),
                analysisPath: path.join(analysisDir, 'analysis.json'),
              },
            };

            await writeJobMetadata(storage, analysisDir, metadata);

            return toAnalyzeResult(storage, metadata);
          } catch (error) {
            await storage.removeDirectory(analysisDir);
            throw createPipelineError(error, 'Analiz işlemi başarısız oldu.');
          }
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

      const job = enqueueObservedJob<ReportJobResult>({
        tenantId,
        id: reportId,
        kind: 'report',
        hash,
        run: async () => {
          await storage.ensureDirectory(reportDir);
          try {
            const reportOptions: ReportOptions = {
              input: analysisDir,
              output: reportDir,
              manifestId: body.manifestId,
            };
            const result = await runReport(reportOptions);

            const metadata: ReportJobMetadata = {
              tenantId,
              id: reportId,
              hash,
              kind: 'report',
              createdAt: new Date().toISOString(),
              directory: reportDir,
              params: {
                analysisId: body.analysisId,
                manifestId: body.manifestId ?? null,
              },
              license: toLicenseMetadata(license),
              outputs: {
                directory: reportDir,
                complianceHtml: result.complianceHtml,
                complianceJson: result.complianceJson,
                traceHtml: result.traceHtml,
                gapsHtml: result.gapsHtml,
                analysisPath: path.join(reportDir, 'analysis.json'),
                snapshotPath: path.join(reportDir, 'snapshot.json'),
                tracesPath: path.join(reportDir, 'traces.json'),
              },
            };

            await writeJobMetadata(storage, reportDir, metadata);

            return toReportResult(storage, metadata);
          } catch (error) {
            await storage.removeDirectory(reportDir);
            throw createPipelineError(error, 'Rapor oluşturma işlemi başarısız oldu.');
          }
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

      const job = enqueueObservedJob<PackJobResult>({
        tenantId,
        id: packId,
        kind: 'pack',
        hash,
        run: async () => {
          await storage.ensureDirectory(packageDir);
          try {
            const signingKey = await fsPromises.readFile(signingKeyPath, 'utf8');
            const packOptions: PackOptions = {
              input: reportDir,
              output: packageDir,
              packageName,
              signingKey,
            };
            const result = await runPack(packOptions);

            const metadata: PackJobMetadata = {
              tenantId,
              id: packId,
              hash,
              kind: 'pack',
              createdAt: new Date().toISOString(),
              directory: packageDir,
              params: {
                reportId: body.reportId,
                packageName: packageName ?? null,
              },
              license: toLicenseMetadata(license),
              outputs: {
                manifestPath: result.manifestPath,
                archivePath: result.archivePath,
                manifestId: result.manifestId,
              },
            };

            await writeJobMetadata(storage, packageDir, metadata);

            return toPackResult(storage, metadata);
          } catch (error) {
            await storage.removeDirectory(packageDir);
            throw createPipelineError(error, 'Paket oluşturma işlemi başarısız oldu.');
          }
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
  app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
    const isPayloadTooLargeError =
      error !== null &&
      typeof error === 'object' &&
      'type' in error &&
      (error as { type?: unknown }).type === 'entity.too.large';

    const normalized =
      error instanceof HttpError
        ? error
        : isPayloadTooLargeError
          ? new HttpError(413, 'PAYLOAD_TOO_LARGE', 'JSON gövde boyutu sınırını aştı.', {
              limit: jsonBodyLimit,
            })
          : new HttpError(500, 'UNEXPECTED_ERROR', 'Beklenmeyen bir sunucu hatası oluştu.', {
              cause: error instanceof Error ? error.message : String(error),
            });

    if (normalized.statusCode === 429 && normalized.details && typeof normalized.details === 'object') {
      const retryAfterSeconds = (normalized.details as { retryAfterSeconds?: unknown }).retryAfterSeconds;
      if (typeof retryAfterSeconds === 'number' && Number.isFinite(retryAfterSeconds) && retryAfterSeconds > 0) {
        res.set('Retry-After', `${Math.ceil(retryAfterSeconds)}`);
      }
    }
    res.status(normalized.statusCode).json({
      error: {
        code: normalized.code,
        message: normalized.message,
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
