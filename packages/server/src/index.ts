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
  PackCmsOptions,
  PackOptions,
  PackPostQuantumOptions,
  ReportOptions,
  runAnalyze,
  runImport,
  runPack,
  runReport,
  verifyLicenseFile,
  type LicensePayload,
} from '@soipack/cli';
import {
  fetchJiraChangeRequests,
  type JiraChangeRequest,
} from '@soipack/adapters';
import {
  CertificationLevel,
  DEFAULT_LOCALE,
  LedgerProofError,
  Manifest,
  ManifestFileEntry,
  ManifestMerkleSummary,
  SnapshotVersion,
  SoiStage,
  createSnapshotIdentifier,
  createSnapshotVersion,
  deriveFingerprint,
  deserializeLedgerProof,
  freezeSnapshotVersion,
  resolveLocale,
  soiStages,
  translate,
  verifyLedgerProof,
} from '@soipack/core';
import express, { Express, NextFunction, Request, Response } from 'express';
import expressRateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { JWTPayload, createLocalJWKSet, createRemoteJWKSet, jwtVerify } from 'jose';
import type { JSONWebKeySet } from 'jose';
import multer from 'multer';
import pino, { type Logger } from 'pino';
import { Counter, Gauge, Histogram, Registry, collectDefaultMetrics } from 'prom-client';

import { AuditLogStore, type AppendAuditLogInput, type AuditLogQueryOptions } from './audit';
import type { DatabaseManager } from './database';


import { HttpError, toHttpError } from './errors';
import {
  ApiPrincipal,
  UserRole,
  createApiKeyAuthorizer,
  createJwtPrincipalResolver,
  type JwtUserLoader,
} from './middleware/auth';
import { JobDetails, JobExecutionContext, JobKind, JobQueue, JobStatus, JobSummary } from './queue';
import { FileScanner, FileScanResult, createNoopScanner } from './scanner';
import {
  FileSystemStorage,
  PipelineDirectories,
  StorageProvider,
  UploadedFileMap,
} from './storage';
import { RbacStore, type RbacApiKey, type RbacRole, type RbacUser } from './rbac';
import {
  ReviewStore,
  ReviewConflictError,
  ReviewNotFoundError,
  ReviewPermissionError,
  ReviewTransitionError,
  type Review,
  type ReviewTargetKind,
} from './reviews';
import {
  WorkspaceService,
  WorkspaceDocumentConflictError,
  WorkspaceDocumentNotFoundError,
  WorkspaceDocumentValidationError,
  WorkspaceRevisionNotFoundError,
  WorkspaceSignoffConflictError,
  WorkspaceSignoffNotFoundError,
  WorkspaceSignoffPermissionError,
  WorkspaceSignoffVerificationError,
  workspaceDocumentSchemas,
  type WorkspaceComment,
  type WorkspaceDocument,
  type WorkspaceDocumentKind,
  type WorkspaceSignoff,
} from './workspaces/service';
import { ComplianceEventStream } from './events';
import { verifyManifestSignatureWithSecuritySigner } from './security/signer';

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

export const writePersistedJson = async (
  tenantDir: string,
  fileName: string,
  data: unknown,
): Promise<void> => {
  await fsPromises.mkdir(tenantDir, { recursive: true });
  const targetPath = path.join(tenantDir, fileName);
  const serialized = `${JSON.stringify(data, null, 2)}\n`;
  const tempPath = path.join(
    tenantDir,
    `${fileName}.${process.pid}.${Date.now()}.tmp`,
  );

  let existingMode: number | undefined;
  try {
    const stats = await fsPromises.stat(targetPath);
    existingMode = stats.mode;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
      throw error;
    }
  }

  let handle: fsPromises.FileHandle | undefined;
  try {
    handle = await fsPromises.open(tempPath, 'w');
    await handle.writeFile(serialized, 'utf8');
    await handle.sync();
  } catch (error) {
    await fsPromises.rm(tempPath, { force: true });
    throw error;
  } finally {
    if (handle) {
      await handle.close();
    }
  }

  try {
    await fsPromises.rename(tempPath, targetPath);
  } catch (error) {
    await fsPromises.rm(tempPath, { force: true });
    throw error;
  }

  if (existingMode !== undefined) {
    try {
      await fsPromises.chmod(targetPath, existingMode);
    } catch {
      // ignore permission normalization failures to match prior behavior
    }
  }
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

const toReportAssetHref = (reportDir: string, assetPath: string): string => {
  const relative = path.relative(reportDir, assetPath);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new HttpError(
      500,
      'REPORT_ASSET_OUT_OF_SCOPE',
      'Rapor çıktısı beklenen dizin dışında oluşturuldu.',
    );
  }
  const normalized = relative.split(path.sep).join('/');
  return normalized;
};

const PEM_BLOCK_PATTERN = /-----BEGIN [^-]+-----|-----END [^-]+-----/g;

const extractPemBody = (pem: string): string => pem.replace(PEM_BLOCK_PATTERN, '').replace(/\s+/g, '');

const CERTIFICATE_PEM_PATTERN = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/;

const extractFirstCertificate = (pem: string): string | undefined => {
  const match = pem.match(CERTIFICATE_PEM_PATTERN);
  return match ? match[0] : undefined;
};

const CHANGE_REQUEST_CACHE_TTL_MS = 300_000;

interface ChangeRequestCacheEntry {
  payload: { items: JiraChangeRequest[]; fetchedAt: string };
  etag: string;
  expiresAt: number;
}

const changeRequestCache = new Map<string, ChangeRequestCacheEntry>();

export const __clearChangeRequestCacheForTesting = (): void => {
  changeRequestCache.clear();
};

type CoverageSummaryPayload = Partial<Record<'statements' | 'branches' | 'functions' | 'lines', number>>;

interface ComplianceSummaryResponsePayload {
  computedAt: string;
  latest: {
    id: string;
    createdAt: string;
    project?: string;
    level?: string;
    generatedAt?: string;
    summary: {
      total: number;
      covered: number;
      partial: number;
      missing: number;
    };
    coverage: CoverageSummaryPayload;
    gaps: {
      missingIds: string[];
      partialIds: string[];
      openObjectiveCount: number;
    };
  } | null;
}

interface ComplianceSummaryCacheEntry {
  recordId?: string;
  recordCreatedAt?: string;
  payload: ComplianceSummaryResponsePayload;
  expiresAt: number;
}

const COMPLIANCE_SUMMARY_CACHE_TTL_MS = 60_000;

const complianceSummaryCacheRegistry = new Set<Map<string, ComplianceSummaryCacheEntry>>();

export const __clearComplianceSummaryCacheForTesting = (): void => {
  complianceSummaryCacheRegistry.forEach((cache) => cache.clear());
};

interface AuthContext {
  token: string;
  tenantId: string;
  subject: string;
  claims: JWTPayload;
  hasAdminScope: boolean;
  principal?: ApiPrincipal;
  roles?: UserRole[];
  permissions?: string[];
  actorLabel?: string;
  userId?: string;
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
  events: ComplianceEventStream;
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

interface JobErrorState {
  statusCode: number;
  code: string;
  message: string;
  details?: unknown;
}

interface StoredJobRecord<TResult = unknown, TPayload = unknown> {
  tenantId: string;
  id: string;
  kind: JobKind;
  hash: string;
  status: JobStatus;
  createdAt: Date;
  updatedAt: Date;
  result?: TResult;
  error?: JobErrorState;
  payload?: TPayload;
}

class JobStore {
  constructor(private readonly database: DatabaseManager, private readonly logger: Logger) {}

  private get pool() {
    return this.database.getPool();
  }

  private toScopedId(tenantId: string, jobId: string): string {
    return createScopedJobKey(tenantId, jobId);
  }

  private extractJobId(scopedId: string, tenantId: string): string {
    const prefix = `${tenantId}:`;
    return scopedId.startsWith(prefix) ? scopedId.slice(prefix.length) : scopedId;
  }

  private parseDate(value: unknown): Date {
    if (value instanceof Date) {
      return value;
    }
    if (typeof value === 'string') {
      const parsed = new Date(value);
      if (!Number.isNaN(parsed.getTime())) {
        return parsed;
      }
    }
    return new Date();
  }

  private parseJson<T>(value: unknown): T | undefined {
    if (value === null || value === undefined) {
      return undefined;
    }
    if (typeof value === 'string') {
      try {
        return JSON.parse(value) as T;
      } catch {
        return undefined;
      }
    }
    return value as T;
  }

  private fromRow<TResult = unknown, TPayload = unknown>(
    row: {
      id: string;
      tenant_id: string;
      kind: JobKind;
      status: JobStatus;
      hash?: string | null;
      payload?: unknown;
      result?: unknown;
      error?: unknown;
      created_at: unknown;
      updated_at: unknown;
    },
  ): StoredJobRecord<TResult, TPayload> {
    const tenantId = row.tenant_id;
    const id = this.extractJobId(row.id, tenantId);
    const error = this.parseJson<JobErrorState>(row.error);
    return {
      tenantId,
      id,
      kind: row.kind,
      hash: typeof row.hash === 'string' ? row.hash : '',
      status: row.status,
      createdAt: this.parseDate(row.created_at),
      updatedAt: this.parseDate(row.updated_at),
      result: this.parseJson<TResult>(row.result),
      error: error ?? undefined,
      payload: this.parseJson<TPayload>(row.payload),
    };
  }

  private toJobDetails<TResult>(record: StoredJobRecord<TResult>): JobDetails<TResult> {
    return {
      id: record.id,
      kind: record.kind,
      hash: record.hash,
      status: record.status,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
      result: record.result,
      error: record.error,
    };
  }

  public async restore(queue: JobQueue, knownTenants: Set<string>): Promise<void> {
    const { rows } = await this.pool.query(
      'SELECT id, tenant_id, kind, status, hash, payload, result, error, created_at, updated_at FROM jobs ORDER BY created_at ASC',
    );
    for (const row of rows as Array<Record<string, unknown>>) {
      const record = this.fromRow(row as never);
      knownTenants.add(record.tenantId);
      switch (record.status) {
        case 'queued':
          if (record.payload === undefined) {
            this.logger.warn(
              {
                event: 'job_restore_skipped',
                tenantId: record.tenantId,
                jobId: record.id,
                reason: 'payload_missing',
              },
              'Kuyrukta bekleyen iş kalıcı yük olmadığı için yeniden kuyruğa alınamadı.',
            );
            break;
          }
          queue.enqueue({
            tenantId: record.tenantId,
            id: record.id,
            kind: record.kind,
            hash: record.hash,
            payload: record.payload,
            createdAt: record.createdAt,
            updatedAt: record.updatedAt,
          });
          break;
        case 'running':
          if (record.payload === undefined) {
            this.logger.warn(
              {
                event: 'job_restore_skipped',
                tenantId: record.tenantId,
                jobId: record.id,
                reason: 'payload_missing',
              },
              'Çalışmakta olan iş kalıcı yük olmadığı için tekrar kuyruğa alınamadı.',
            );
            break;
          }
          queue.enqueue({
            tenantId: record.tenantId,
            id: record.id,
            kind: record.kind,
            hash: record.hash,
            payload: record.payload,
            createdAt: record.createdAt,
            updatedAt: record.updatedAt,
          });
          await this.markQueued(record.tenantId, record.id);
          break;
        case 'completed':
          queue.adoptCompleted({
            tenantId: record.tenantId,
            id: record.id,
            kind: record.kind,
            hash: record.hash,
            createdAt: record.createdAt.toISOString(),
            updatedAt: record.updatedAt.toISOString(),
            result: record.result,
          });
          break;
        case 'failed':
          if (record.error) {
            queue.adoptFailed({
              tenantId: record.tenantId,
              id: record.id,
              kind: record.kind,
              hash: record.hash,
              createdAt: record.createdAt.toISOString(),
              updatedAt: record.updatedAt.toISOString(),
              result: undefined,
              error: record.error,
            });
          }
          break;
        default:
          break;
      }
    }
  }

  private async getRecord<TResult = unknown, TPayload = unknown>(
    tenantId: string,
    jobId: string,
    options: { includePayload?: boolean } = {},
  ): Promise<StoredJobRecord<TResult, TPayload> | undefined> {
    const columns = options.includePayload
      ? 'id, tenant_id, kind, status, hash, payload, result, error, created_at, updated_at'
      : 'id, tenant_id, kind, status, hash, result, error, created_at, updated_at';
    const { rows } = await this.pool.query(
      `SELECT ${columns} FROM jobs WHERE id = $1 AND tenant_id = $2 LIMIT 1`,
      [this.toScopedId(tenantId, jobId), tenantId],
    );
    if (rows.length === 0) {
      return undefined;
    }
    const row = rows[0] as Record<string, unknown>;
    if (!options.includePayload && !(row as { payload?: unknown }).payload) {
      (row as { payload?: unknown }).payload = undefined;
    }
    return this.fromRow(row as never);
  }

  public async findJob<TResult = unknown>(
    tenantId: string,
    jobId: string,
  ): Promise<JobDetails<TResult> | undefined> {
    const record = await this.getRecord<TResult>(tenantId, jobId);
    return record ? this.toJobDetails(record) : undefined;
  }

  public async getJobWithPayload<TResult = unknown, TPayload = unknown>(
    tenantId: string,
    jobId: string,
  ): Promise<StoredJobRecord<TResult, TPayload> | undefined> {
    return this.getRecord<TResult, TPayload>(tenantId, jobId, { includePayload: true });
  }

  public async listJobs<TResult = unknown>(tenantId: string): Promise<JobDetails<TResult>[]> {
    const { rows } = await this.pool.query(
      'SELECT id, tenant_id, kind, status, hash, payload, result, error, created_at, updated_at FROM jobs WHERE tenant_id = $1 ORDER BY created_at DESC',
      [tenantId],
    );
    return (rows as Array<Record<string, unknown>>)
      .map((row) => this.toJobDetails(this.fromRow(row as never)));
  }

  public async insertQueuedJob<TPayload>(options: {
    tenantId: string;
    id: string;
    kind: JobKind;
    hash: string;
    payload: TPayload;
    createdAt: Date;
    updatedAt: Date;
  }): Promise<{ inserted: boolean; job?: JobDetails<unknown> }> {
    const scopedId = this.toScopedId(options.tenantId, options.id);
    const createdAtIso = options.createdAt.toISOString();
    const updatedAtIso = options.updatedAt.toISOString();
    const payloadValue = options.payload === undefined ? null : JSON.stringify(options.payload);
    const result = await this.pool.query(
      `INSERT INTO jobs (id, tenant_id, kind, status, hash, payload, result, error, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       ON CONFLICT (id) DO NOTHING`,
      [
        scopedId,
        options.tenantId,
        options.kind,
        'queued',
        options.hash,
        payloadValue,
        null,
        null,
        createdAtIso,
        updatedAtIso,
      ],
    );
    if (result.rowCount === 0) {
      const existing = await this.findJob(options.tenantId, options.id);
      return { inserted: false, job: existing };
    }
    return { inserted: true };
  }

  public async markRunning(tenantId: string, jobId: string): Promise<void> {
    const nowIso = new Date().toISOString();
    await this.pool.query(
      'UPDATE jobs SET status = $1, updated_at = $2, error = NULL WHERE id = $3 AND tenant_id = $4',
      ['running', nowIso, this.toScopedId(tenantId, jobId), tenantId],
    );
  }

  public async markCompleted<TResult>(tenantId: string, jobId: string, result: TResult): Promise<void> {
    const nowIso = new Date().toISOString();
    const serializedResult = result === undefined ? null : JSON.stringify(result);
    await this.pool.query(
      'UPDATE jobs SET status = $1, updated_at = $2, result = $3, error = NULL WHERE id = $4 AND tenant_id = $5',
      ['completed', nowIso, serializedResult, this.toScopedId(tenantId, jobId), tenantId],
    );
  }

  public async markFailed(tenantId: string, jobId: string, error: JobErrorState): Promise<void> {
    const nowIso = new Date().toISOString();
    await this.pool.query(
      'UPDATE jobs SET status = $1, updated_at = $2, error = $3 WHERE id = $4 AND tenant_id = $5',
      ['failed', nowIso, JSON.stringify(error), this.toScopedId(tenantId, jobId), tenantId],
    );
  }

  public async deleteJob(tenantId: string, jobId: string): Promise<void> {
    await this.pool.query('DELETE FROM jobs WHERE id = $1 AND tenant_id = $2', [
      this.toScopedId(tenantId, jobId),
      tenantId,
    ]);
  }

  public async countActiveJobs(tenantId: string): Promise<number> {
    const { rows } = await this.pool.query(
      'SELECT COUNT(*)::int AS count FROM jobs WHERE tenant_id = $1 AND status IN ($2, $3)',
      [tenantId, 'queued', 'running'],
    );
    const [first] = rows as Array<{ count: number } | { count: string }>;
    if (!first) {
      return 0;
    }
    const value = (first as { count: number }).count ?? Number((first as { count: string }).count);
    return Number.isNaN(value) ? 0 : value;
  }

  public async countTotalActiveJobs(): Promise<number> {
    const { rows } = await this.pool.query(
      'SELECT COUNT(*)::int AS count FROM jobs WHERE status IN ($1, $2)',
      ['queued', 'running'],
    );
    const [first] = rows as Array<{ count: number } | { count: string }>;
    if (!first) {
      return 0;
    }
    const value = (first as { count: number }).count ?? Number((first as { count: string }).count);
    return Number.isNaN(value) ? 0 : value;
  }

  private async markQueued(tenantId: string, jobId: string): Promise<void> {
    const nowIso = new Date().toISOString();
    await this.pool.query(
      'UPDATE jobs SET status = $1, updated_at = $2 WHERE id = $3 AND tenant_id = $4',
      ['queued', nowIso, this.toScopedId(tenantId, jobId), tenantId],
    );
  }
}

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

interface ToolQualificationSummaryItem {
  id: string;
  name: string;
  version?: string;
  category: 'development' | 'verification' | 'support';
  tql?: string;
  outputs: string[];
  pendingActivities: number;
}

interface ToolQualificationSummary {
  generatedAt: string;
  programName?: string | null;
  level?: string | null;
  author?: string | null;
  tools: ToolQualificationSummaryItem[];
}

interface ToolQualificationMetadata {
  summary: ToolQualificationSummary;
  tqpPath: string;
  tarPath: string;
  tqpHref: string;
  tarHref: string;
}

interface ReportJobMetadata extends BaseJobMetadata {
  kind: 'report';
  outputs: {
    directory: string;
    complianceHtml: string;
    complianceJson: string;
    complianceCsv: string;
    traceHtml: string;
    gapsHtml: string;
    analysisPath: string;
    snapshotPath: string;
    tracesPath: string;
    toolQualification?: ToolQualificationMetadata;
  };
}

interface CmsSignatureMetadata {
  path: string;
  sha256: string;
  der: string;
  digestAlgorithm: string;
  verified: boolean;
  digestVerified: boolean;
  signerSerialNumber?: string | null;
  signerIssuer?: string | null;
  signerSubject?: string | null;
  signatureAlgorithm?: string | null;
}

interface PostQuantumSignatureMetadata {
  algorithm: string;
  publicKey: string;
  signature: string;
}

interface PackJobMetadata extends BaseJobMetadata {
  kind: 'pack';
  outputs: {
    manifestPath: string;
    archivePath: string;
    manifestId: string;
    manifestDigest: string;
    ledgerPath?: string;
    ledgerRoot?: string;
    previousLedgerRoot?: string | null;
    cmsSignature?: CmsSignatureMetadata;
    postQuantumSignature?: PostQuantumSignatureMetadata;
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
    complianceCsv: string;
    traceHtml: string;
    gapsHtml: string;
    analysis: string;
    snapshot: string;
    traces: string;
    toolQualification?: {
      summary: ToolQualificationSummary;
      tqp: string;
      tar: string;
      tqpHref: string;
      tarHref: string;
    };
  };
}

interface PackJobResult {
  manifestId: string;
  manifestDigest: string;
  ledgerRoot?: string;
  previousLedgerRoot?: string | null;
  cmsSignature?: CmsSignatureMetadata;
  postQuantumSignature?: PostQuantumSignatureMetadata;
  outputs: {
    directory: string;
    manifest: string;
    archive: string;
    ledger?: string;
    cmsSignature?: CmsSignatureMetadata;
    postQuantumSignature?: PostQuantumSignatureMetadata;
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

const parseStringArrayField = (value: unknown, field: string): string[] | undefined => {
  if (value === undefined || value === null) {
    return undefined;
  }

  let raw: unknown = value;
  if (Array.isArray(raw)) {
    if (raw.length === 0) {
      return [];
    }
    if (raw.length === 1) {
      raw = raw[0];
    }
  }

  if (typeof raw === 'string') {
    const trimmed = raw.trim();
    if (trimmed.length === 0) {
      return [];
    }
    try {
      raw = JSON.parse(trimmed);
    } catch {
      throw new HttpError(400, 'INVALID_REQUEST', `${field} alanı geçerli JSON içermelidir.`);
    }
  }

  if (!Array.isArray(raw)) {
    throw new HttpError(400, 'INVALID_REQUEST', `${field} alanı için dizi bekleniyor.`);
  }

  const normalized: string[] = [];
  raw.forEach((entry, index) => {
    if (typeof entry !== 'string') {
      throw new HttpError(
        400,
        'INVALID_REQUEST',
        `${field}[${index}] değeri metin olmalıdır.`,
      );
    }
    const trimmed = entry.trim();
    if (!trimmed) {
      throw new HttpError(400, 'INVALID_REQUEST', `${field}[${index}] boş olamaz.`);
    }
    normalized.push(trimmed);
  });

  return normalized;
};

const parsePackPostQuantumOptions = (
  value: unknown,
): PackPostQuantumOptions | false | undefined => {
  if (value === undefined) {
    return undefined;
  }

  if (value === false) {
    return false;
  }

  if (value === null) {
    throw new HttpError(400, 'INVALID_REQUEST', 'postQuantum alanı için nesne bekleniyor.');
  }

  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new HttpError(400, 'INVALID_REQUEST', 'postQuantum alanı için nesne bekleniyor.');
  }

  const raw = value as Record<string, unknown>;
  const normalize = (input: unknown, field: string): string => {
    if (typeof input !== 'string') {
      throw new HttpError(400, 'INVALID_REQUEST', `${field} alanı metin olmalıdır.`);
    }
    const trimmed = input.trim();
    if (trimmed.length === 0) {
      throw new HttpError(400, 'INVALID_REQUEST', `${field} alanı boş olamaz.`);
    }
    return trimmed;
  };

  const options: PackPostQuantumOptions = {};

  if (raw.privateKey !== undefined) {
    options.privateKey = normalize(raw.privateKey, 'postQuantum.privateKey');
  }
  if (raw.privateKeyPath !== undefined) {
    options.privateKeyPath = normalize(raw.privateKeyPath, 'postQuantum.privateKeyPath');
  }
  if (raw.publicKey !== undefined) {
    options.publicKey = normalize(raw.publicKey, 'postQuantum.publicKey');
  }
  if (raw.publicKeyPath !== undefined) {
    options.publicKeyPath = normalize(raw.publicKeyPath, 'postQuantum.publicKeyPath');
  }
  if (raw.algorithm !== undefined) {
    options.algorithm = normalize(raw.algorithm, 'postQuantum.algorithm');
  }

  if (
    options.algorithm === undefined &&
    options.privateKey === undefined &&
    options.privateKeyPath === undefined &&
    options.publicKey === undefined &&
    options.publicKeyPath === undefined
  ) {
    throw new HttpError(
      400,
      'INVALID_REQUEST',
      'postQuantum alanı en az bir anahtar veya algoritma değeri içermelidir.',
    );
  }

  return options;
};

const parseJsonObjectField = (
  value: unknown,
  field: string,
): Record<string, unknown> | undefined => {
  if (value === undefined || value === null) {
    return undefined;
  }

  let raw: unknown = value;
  if (Array.isArray(raw)) {
    if (raw.length === 0) {
      return {};
    }
    if (raw.length === 1) {
      raw = raw[0];
    }
  }

  if (typeof raw === 'string') {
    const trimmed = raw.trim();
    if (trimmed.length === 0) {
      return {};
    }
    try {
      raw = JSON.parse(trimmed);
    } catch {
      throw new HttpError(400, 'INVALID_REQUEST', `${field} alanı geçerli JSON içermelidir.`);
    }
  }

  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new HttpError(400, 'INVALID_REQUEST', `${field} alanı için nesne bekleniyor.`);
  }

  return raw as Record<string, unknown>;
};

const toStableJson = (value: unknown): string => {
  const normalize = (input: unknown): unknown => {
    if (Array.isArray(input)) {
      return input.map((item) => normalize(item));
    }
    if (input && typeof input === 'object') {
      return Object.keys(input as Record<string, unknown>)
        .sort()
        .reduce<Record<string, unknown>>((acc, key) => {
          acc[key] = normalize((input as Record<string, unknown>)[key]);
          return acc;
        }, {});
    }
    return input;
  };

  return JSON.stringify(normalize(value));
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

const SOI_STAGE_SET = new Set<string>(soiStages);

const isSoiStage = (value: string): value is SoiStage => SOI_STAGE_SET.has(value);

const parseSoiStage = (value: unknown): SoiStage | undefined => {
  if (value === undefined || value === null || value === '') {
    return undefined;
  }
  if (typeof value !== 'string') {
    throw new HttpError(
      400,
      'INVALID_REQUEST',
      `Geçersiz SOI aşaması. Geçerli değerler: ${soiStages.join(', ')}.`,
    );
  }
  const normalized = value.trim().toUpperCase();
  if (isSoiStage(normalized)) {
    return normalized;
  }
  throw new HttpError(400, 'INVALID_REQUEST', `Geçersiz SOI aşaması. Geçerli değerler: ${soiStages.join(', ')}.`);
};

const buildStageScopedDirectory = (
  baseDir: string,
  tenantId: string,
  jobId: string,
  stage?: SoiStage | null,
): string => (stage ? path.join(baseDir, tenantId, stage, jobId) : path.join(baseDir, tenantId, jobId));

const findStageAwareJobDirectory = async (
  storage: StorageProvider,
  baseDir: string,
  tenantId: string,
  jobId: string,
  stage?: SoiStage | null,
): Promise<string | undefined> => {
  const tryDirectory = async (candidateStage?: SoiStage | null): Promise<string | undefined> => {
    const directory = buildStageScopedDirectory(baseDir, tenantId, jobId, candidateStage ?? undefined);
    const metadataPath = path.join(directory, METADATA_FILE);
    return (await storage.fileExists(metadataPath)) ? directory : undefined;
  };

  if (stage) {
    return tryDirectory(stage);
  }

  const direct = await tryDirectory();
  if (direct) {
    return direct;
  }

  const tenantDir = path.join(baseDir, tenantId);
  if (!(await storage.fileExists(tenantDir))) {
    return undefined;
  }

  let entries: string[] = [];
  try {
    entries = await storage.listSubdirectories(tenantDir);
  } catch {
    return undefined;
  }

  for (const entry of entries) {
    if (!isSoiStage(entry)) {
      continue;
    }
    const resolved = await tryDirectory(entry);
    if (resolved) {
      return resolved;
    }
  }

  return undefined;
};

const removeStageAwareJobDirectories = async (
  storage: StorageProvider,
  baseDir: string,
  tenantId: string,
  jobId: string,
  stage?: SoiStage | null,
): Promise<void> => {
  const targets = new Set<string>();
  targets.add(buildStageScopedDirectory(baseDir, tenantId, jobId));
  if (stage) {
    targets.add(buildStageScopedDirectory(baseDir, tenantId, jobId, stage));
  } else {
    soiStages.forEach((candidate) => {
      targets.add(buildStageScopedDirectory(baseDir, tenantId, jobId, candidate));
    });
  }

  await Promise.all([...targets].map((target) => storage.removeDirectory(target)));
};

const listStageAwareJobEntries = async (
  storage: StorageProvider,
  baseDir: string,
  tenantId: string,
): Promise<Array<{ id: string; directory: string; stage?: SoiStage | null }>> => {
  const tenantDir = path.join(baseDir, tenantId);
  const results: Array<{ id: string; directory: string; stage?: SoiStage | null }> = [];
  if (!(await storage.fileExists(tenantDir))) {
    return results;
  }

  let entries: string[] = [];
  try {
    entries = await storage.listSubdirectories(tenantDir);
  } catch {
    return results;
  }

  for (const entry of entries) {
    if (isSoiStage(entry)) {
      const stageDir = path.join(tenantDir, entry);
      let jobIds: string[] = [];
      try {
        jobIds = await storage.listSubdirectories(stageDir);
      } catch {
        continue;
      }
      jobIds.forEach((jobId) => {
        results.push({
          id: jobId,
          directory: path.join(stageDir, jobId),
          stage: entry,
        });
      });
    } else {
      results.push({ id: entry, directory: path.join(tenantDir, entry), stage: null });
    }
  }

  return results;
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
  designCsv: {
    maxSizeBytes: maxUploadSize,
    allowedMimeTypes: ['text/csv', 'text/plain', 'application/octet-stream'],
  },
  jiraDefects: {
    maxSizeBytes: maxUploadSize,
    allowedMimeTypes: ['text/csv', 'text/plain', 'application/octet-stream'],
  },
  polyspace: {
    maxSizeBytes: maxUploadSize,
    allowedMimeTypes: [
      'application/zip',
      'application/x-zip-compressed',
      'application/octet-stream',
    ],
  },
  ldra: {
    maxSizeBytes: maxUploadSize,
    allowedMimeTypes: [
      'application/zip',
      'application/x-zip-compressed',
      'application/xml',
      'text/xml',
      'text/*',
      'application/octet-stream',
    ],
  },
  vectorcast: {
    maxSizeBytes: maxUploadSize,
    allowedMimeTypes: [
      'application/zip',
      'application/x-zip-compressed',
      'application/octet-stream',
    ],
  },
  qaLogs: {
    maxSizeBytes: maxUploadSize,
    allowedMimeTypes: [
      'text/*',
      'application/zip',
      'application/x-zip-compressed',
      'application/octet-stream',
    ],
  },
  planConfig: {
    maxSizeBytes: maxUploadSize,
    allowedMimeTypes: [
      'application/json',
      'text/*',
      'application/zip',
      'application/x-zip-compressed',
      'application/octet-stream',
    ],
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

type AuditLogAdapter = Pick<AuditLogStore, 'append' | 'query'>;

export interface ServerCmsSigningConfig {
  bundlePath?: string;
  certificatePath?: string;
  privateKeyPath?: string;
  chainPath?: string;
}

export interface ServerConfig {
  auth: JwtAuthConfig;
  storageDir: string;
  signingKeyPath: string;
  licensePublicKeyPath: string;
  database: DatabaseManager;
  auditLogStore?: AuditLogAdapter;
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
  events?: EventStreamConfig;
  cmsSigning?: ServerCmsSigningConfig;
}

export interface EventStreamConfig {
  heartbeatMs?: number;
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
    complianceCsv: storage.toRelativePath(metadata.outputs.complianceCsv),
    traceHtml: storage.toRelativePath(metadata.outputs.traceHtml),
    gapsHtml: storage.toRelativePath(metadata.outputs.gapsHtml),
    analysis: storage.toRelativePath(metadata.outputs.analysisPath),
    snapshot: storage.toRelativePath(metadata.outputs.snapshotPath),
    traces: storage.toRelativePath(metadata.outputs.tracesPath),
    ...(metadata.outputs.toolQualification
      ? {
          toolQualification: {
            summary: metadata.outputs.toolQualification.summary,
            tqp: storage.toRelativePath(metadata.outputs.toolQualification.tqpPath),
            tar: storage.toRelativePath(metadata.outputs.toolQualification.tarPath),
            tqpHref: metadata.outputs.toolQualification.tqpHref,
            tarHref: metadata.outputs.toolQualification.tarHref,
          },
        }
      : {}),
  },
});

const toPackResult = (storage: StorageProvider, metadata: PackJobMetadata): PackJobResult => {
  const cmsSignature = metadata.outputs.cmsSignature
    ? {
        ...metadata.outputs.cmsSignature,
        path: storage.toRelativePath(metadata.outputs.cmsSignature.path),
        signerSerialNumber: metadata.outputs.cmsSignature.signerSerialNumber ?? null,
        signerIssuer: metadata.outputs.cmsSignature.signerIssuer ?? null,
        signerSubject: metadata.outputs.cmsSignature.signerSubject ?? null,
        signatureAlgorithm: metadata.outputs.cmsSignature.signatureAlgorithm ?? null,
      }
    : undefined;

  const postQuantumSignature = metadata.outputs.postQuantumSignature;

  return {
    manifestId: metadata.outputs.manifestId,
    manifestDigest: metadata.outputs.manifestDigest,
    ledgerRoot: metadata.outputs.ledgerRoot,
    previousLedgerRoot: metadata.outputs.previousLedgerRoot,
    ...(cmsSignature ? { cmsSignature } : {}),
    ...(postQuantumSignature ? { postQuantumSignature } : {}),
    outputs: {
      directory: storage.toRelativePath(metadata.directory),
      manifest: storage.toRelativePath(metadata.outputs.manifestPath),
      archive: storage.toRelativePath(metadata.outputs.archivePath),
      ...(metadata.outputs.ledgerPath
        ? { ledger: storage.toRelativePath(metadata.outputs.ledgerPath) }
        : {}),
      ...(cmsSignature ? { cmsSignature } : {}),
      ...(postQuantumSignature ? { postQuantumSignature } : {}),
    },
  };
};

interface ImportJobPayload {
  workspaceDir: string;
  uploads: Record<string, string[]>;
  level?: CertificationLevel | null;
  projectName?: string | null;
  projectVersion?: string | null;
  independentSources?: string[] | null;
  independentArtifacts?: string[] | null;
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
  soiStage?: SoiStage | null;
  planConfigPath?: string | null;
  planOverrides?: Record<string, unknown> | null;
  license: JobLicenseMetadata;
}

interface PackJobPayload {
  reportDir: string;
  packageDir: string;
  packageName?: string;
  signingKeyPath: string;
  reportId: string;
  soiStage?: SoiStage | null;
  postQuantum?: PackPostQuantumOptions | false;
  license: JobLicenseMetadata;
}

type StageAwareReportOptions = ReportOptions & { soiStage?: SoiStage };

type StageAwarePackOptions = PackOptions & { soiStage?: SoiStage };

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
    const candidateDir = await findStageAwareJobDirectory(storage, location.dir, tenantId, jobId);
    if (!candidateDir) {
      continue;
    }
    const metadata = await readJobMetadata<JobMetadata>(storage, candidateDir);
    if (metadata.tenantId !== tenantId) {
      throw new HttpError(403, 'TENANT_MISMATCH', 'İstenen iş bu kiracıya ait değil.');
    }
    if (onMetadata) {
      onMetadata(metadata);
    }
    return adoptJobFromMetadata(storage, queue, metadata);
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
      await removeStageAwareJobDirectories(storage, directories.reports, tenantId, jobId);
      return;
    case 'pack':
      await removeStageAwareJobDirectories(storage, directories.packages, tenantId, jobId);
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
  const entries = await listStageAwareJobEntries(storage, directories.packages, tenantId);
  for (const entry of entries) {
    const metadataPath = path.join(entry.directory, METADATA_FILE);
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

const evaluateManifestProofs = (
  manifest: Manifest,
): { merkle: ManifestMerkleSummary | null; files: Array<{ file: ManifestFileEntry; verified: boolean }> } => {
  const merkle = manifest.merkle ?? null;
  const merkleRoot = merkle?.root ?? null;

  return {
    merkle,
    files: manifest.files.map((file) => {
      if (file.proof) {
        if (!merkleRoot) {
          throw new LedgerProofError('Manifest merkle kökü kanıt doğrulaması için gerekli.');
        }
        const parsed = deserializeLedgerProof(file.proof.proof);
        verifyLedgerProof(parsed, { expectedMerkleRoot: merkleRoot });
        return { file, verified: true };
      }
      return { file, verified: false };
    }),
  };
};

const resolveManifestRecord = async (
  storage: StorageProvider,
  directories: PipelineDirectories,
  tenantId: string,
  manifestId: string,
): Promise<{ metadata: PackJobMetadata; manifest: Manifest; manifestPath: string }> => {
  const metadata = await findPackMetadataByManifestId(storage, directories, tenantId, manifestId);
  if (!metadata) {
    throw new HttpError(404, 'MANIFEST_NOT_FOUND', 'İstenen manifest bulunamadı.');
  }

  const manifestPath = metadata.outputs?.manifestPath;
  if (!manifestPath || !(await storage.fileExists(manifestPath))) {
    throw new HttpError(404, 'MANIFEST_NOT_FOUND', 'Manifest dosyası bulunamadı.');
  }

  const manifest = await storage.readJson<Manifest>(manifestPath);
  return { metadata, manifest, manifestPath };
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

  const packageDir = await findStageAwareJobDirectory(storage, directories.packages, tenantId, packageId);
  if (!packageDir) {
    throw new HttpError(404, 'PACKAGE_NOT_FOUND', 'İstenen paket bulunamadı.');
  }

  const metadataPath = path.join(packageDir, METADATA_FILE);
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
    cleanup: (tenant: string, id: string, stage?: SoiStage | null) => Promise<void>;
    stageAware?: boolean;
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
      cleanup: async (tenant: string, id: string, stage?: SoiStage | null) => {
        await removeStageAwareJobDirectories(storage, storage.directories.reports, tenant, id, stage ?? undefined);
      },
      stageAware: true,
    },
    {
      target: 'packages',
      baseDirectory: storage.directories.packages,
      cleanup: async (tenant: string, id: string, stage?: SoiStage | null) => {
        await removeStageAwareJobDirectories(storage, storage.directories.packages, tenant, id, stage ?? undefined);
      },
      stageAware: true,
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
    let entries: Array<{ id: string; directory: string; stage?: SoiStage | null }> = [];
    if (descriptor.stageAware) {
      entries = await listStageAwareJobEntries(storage, descriptor.baseDirectory, tenantId);
    } else {
      const hasTenantDirectory = await storage.fileExists(tenantDirectory);
      const ids = hasTenantDirectory ? await storage.listSubdirectories(tenantDirectory) : [];
      entries = ids.map((id) => ({ id, directory: path.join(tenantDirectory, id), stage: null }));
    }
    let removed = 0;
    let retained = 0;
    let skipped = 0;

    for (const entry of entries) {
      const job = queue.get(tenantId, entry.id);
      if (job && (job.status === 'queued' || job.status === 'running')) {
        skipped += 1;
        continue;
      }

      const metadataPath = path.join(entry.directory, METADATA_FILE);
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
        await descriptor.cleanup(tenantId, entry.id, entry.stage);
        jobLicenses.delete(createScopedJobKey(tenantId, entry.id));
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

  const resolvePemFile = (targetPath?: string): string | undefined => {
    if (!targetPath) {
      return undefined;
    }
    return fs.readFileSync(path.resolve(targetPath), 'utf8');
  };

  const cmsSigningConfig = config.cmsSigning;
  const cmsSigningMaterial = cmsSigningConfig
    ? {
        bundlePem: resolvePemFile(cmsSigningConfig.bundlePath),
        certificatePem: resolvePemFile(cmsSigningConfig.certificatePath),
        privateKeyPem: resolvePemFile(cmsSigningConfig.privateKeyPath),
        chainPem: resolvePemFile(cmsSigningConfig.chainPath),
      }
    : undefined;

  const cmsSigningOptions: PackCmsOptions | undefined =
    cmsSigningMaterial &&
    (cmsSigningMaterial.bundlePem ||
      cmsSigningMaterial.certificatePem ||
      cmsSigningMaterial.privateKeyPem ||
      cmsSigningMaterial.chainPem)
      ? {
          bundlePem: cmsSigningMaterial.bundlePem,
          certificatePem: cmsSigningMaterial.certificatePem,
          privateKeyPem: cmsSigningMaterial.privateKeyPem,
          chainPem: cmsSigningMaterial.chainPem,
        }
      : undefined;

  const cmsVerificationCertificate =
    cmsSigningMaterial?.certificatePem ??
    (cmsSigningMaterial?.bundlePem ? extractFirstCertificate(cmsSigningMaterial.bundlePem) : undefined) ??
    (cmsSigningMaterial?.chainPem ? extractFirstCertificate(cmsSigningMaterial.chainPem) : undefined);
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
  const auditLogStore: AuditLogAdapter = config.auditLogStore ?? new AuditLogStore(config.database);
  const jobLicenses = new Map<string, VerifiedLicense>();
  const knownTenants = new Set<string>();
  const logger: Logger = config.logger ?? pino({ name: 'soipack-server' });
  const events = new ComplianceEventStream({ heartbeatMs: config.events?.heartbeatMs });

  const rbacStore = new RbacStore(config.database);
  const reviewStore = new ReviewStore(config.database);
  const workspaceService = new WorkspaceService(config.database);

  const jwtUserLoader: JwtUserLoader = {
    loadUser: async (tenantId, subject) => {
      const user = await rbacStore.getUser(tenantId, subject);
      if (!user) {
        return null;
      }
      return {
        id: user.id,
        tenantId: user.tenantId,
        displayName: user.displayName,
      };
    },
    loadRoles: async (tenantId, userId) => {
      const roles = await rbacStore.listUserRoles(tenantId, userId);
      return roles
        .map((role) => role.name)
        .filter((name): name is UserRole => name === 'admin' || name === 'maintainer' || name === 'reader');
    },
  };

  const resolveJwtPrincipal = createJwtPrincipalResolver(jwtUserLoader);

  const ensurePrincipal = async (req: Request): Promise<ApiPrincipal> => {
    const context = getAuthContext(req);
    if (context.principal) {
      return context.principal;
    }
    const principal = await resolveJwtPrincipal({
      token: context.token,
      tenantId: context.tenantId,
      subject: context.subject,
    });
    context.principal = principal;
    context.roles = principal.roles;
    context.permissions = principal.permissions;
    context.actorLabel = principal.label;
    context.userId = principal.userId;
    return principal;
  };

  const ensureRole = async (req: Request, allowed: UserRole[]): Promise<ApiPrincipal> => {
    const principal = await ensurePrincipal(req);
    if (!allowed.some((role) => principal.roles.includes(role))) {
      throw new HttpError(
        403,
        'FORBIDDEN_ROLE',
        'Bu işlem için gerekli role sahip değilsiniz.',
        { requiredRoles: allowed },
      );
    }
    return principal;
  };

  const appendAuditLog = async (entry: AppendAuditLogInput): Promise<void> => {
    try {
      await auditLogStore.append({ ...entry, createdAt: entry.createdAt ?? new Date() });
    } catch (error) {
      logger.warn(
        {
          err: error,
          tenantId: entry.tenantId,
          action: entry.action,
        },
        'Audit log entry could not be persisted.',
      );
    }
  };

  const toJobTarget = (jobId: string): string => `job:${jobId}`;

  const toLicenseAuditPayload = (license: VerifiedLicense): Record<string, unknown> => ({
    licenseId: license.payload.licenseId,
    issuedTo: license.payload.issuedTo,
    hash: license.hash,
    expiresAt: license.payload.expiresAt ?? null,
  });

  const toReviewResponse = (review: Review): Record<string, unknown> => ({
    id: review.id,
    tenantId: review.tenantId,
    status: review.status,
    target: {
      kind: review.target.kind,
      reference: review.target.reference ?? null,
    },
    approvers: review.approvers.map((approver) => ({
      userId: approver.userId,
      status: approver.status,
      decidedAt: approver.decidedAt ? approver.decidedAt.toISOString() : null,
      note: approver.note ?? null,
    })),
    requiredArtifacts: review.requiredArtifacts.map((artifact) => ({
      id: artifact.id,
      label: artifact.label,
      description: artifact.description ?? null,
      provided: artifact.provided,
      providedBy: artifact.providedBy ?? null,
      providedAt: artifact.providedAt ? artifact.providedAt.toISOString() : null,
    })),
    changeRequests: review.changeRequests.map((entry) => ({
      id: entry.id,
      authorId: entry.authorId,
      reason: entry.reason,
      createdAt: entry.createdAt.toISOString(),
    })),
    hash: review.hash,
    notes: review.notes ?? null,
    reviewer: review.reviewer ?? null,
    createdAt: review.createdAt.toISOString(),
    updatedAt: review.updatedAt.toISOString(),
  });

  const allowedWorkspaceKinds = new Set(
    Object.keys(workspaceDocumentSchemas) as WorkspaceDocumentKind[],
  );

  const isWorkspaceKind = (value: string): value is WorkspaceDocumentKind =>
    allowedWorkspaceKinds.has(value as WorkspaceDocumentKind);

  const toWorkspaceDocumentResponse = (document: WorkspaceDocument): Record<string, unknown> => ({
    id: document.id,
    tenantId: document.tenantId,
    workspaceId: document.workspaceId,
    kind: document.kind,
    title: document.title,
    createdAt: document.createdAt.toISOString(),
    updatedAt: document.updatedAt.toISOString(),
    revision: {
      id: document.latestRevision.id,
      number: document.latestRevision.revision,
      hash: document.latestRevision.hash,
      authorId: document.latestRevision.authorId,
      createdAt: document.latestRevision.createdAt.toISOString(),
      content: document.latestRevision.content,
    },
  });

  const toWorkspaceCommentResponse = (comment: WorkspaceComment): Record<string, unknown> => ({
    id: comment.id,
    documentId: comment.documentId,
    revisionId: comment.revisionId,
    tenantId: comment.tenantId,
    workspaceId: comment.workspaceId,
    authorId: comment.authorId,
    body: comment.body,
    createdAt: comment.createdAt.toISOString(),
  });

  const toWorkspaceSignoffResponse = (signoff: WorkspaceSignoff): Record<string, unknown> => ({
    id: signoff.id,
    documentId: signoff.documentId,
    revisionId: signoff.revisionId,
    tenantId: signoff.tenantId,
    workspaceId: signoff.workspaceId,
    revisionHash: signoff.revisionHash,
    status: signoff.status,
    requestedBy: signoff.requestedBy,
    requestedFor: signoff.requestedFor,
    signerId: signoff.signerId ?? null,
    signerPublicKey: signoff.signerPublicKey ?? null,
    signature: signoff.signature ?? null,
    signedAt: signoff.signedAt ? signoff.signedAt.toISOString() : null,
    createdAt: signoff.createdAt.toISOString(),
    updatedAt: signoff.updatedAt.toISOString(),
  });

  const handleWorkspaceError = (error: unknown): never => {
    if (error instanceof WorkspaceDocumentValidationError) {
      throw new HttpError(400, 'INVALID_REQUEST', error.message, { issues: error.issues });
    }
    if (
      error instanceof WorkspaceDocumentConflictError ||
      error instanceof WorkspaceSignoffConflictError
    ) {
      throw new HttpError(409, 'CONFLICT', error.message);
    }
    if (
      error instanceof WorkspaceDocumentNotFoundError ||
      error instanceof WorkspaceRevisionNotFoundError ||
      error instanceof WorkspaceSignoffNotFoundError
    ) {
      throw new HttpError(404, 'NOT_FOUND', error.message);
    }
    if (error instanceof WorkspaceSignoffVerificationError) {
      throw new HttpError(400, 'INVALID_SIGNATURE', error.message);
    }
    if (error instanceof WorkspaceSignoffPermissionError) {
      throw new HttpError(403, 'FORBIDDEN_ROLE', error.message);
    }
    throw error;
  };

  const handleReviewError = (error: unknown): never => {
    if (error instanceof ReviewNotFoundError) {
      throw new HttpError(404, 'REVIEW_NOT_FOUND', 'İnceleme kaydı bulunamadı.');
    }
    if (error instanceof ReviewConflictError) {
      throw new HttpError(409, 'REVIEW_CONFLICT', 'İnceleme başka bir işlem tarafından güncellendi.');
    }
    if (error instanceof ReviewPermissionError) {
      throw new HttpError(403, 'REVIEW_FORBIDDEN', 'Bu inceleme için gerekli yetkiye sahip değilsiniz.');
    }
    if (error instanceof ReviewTransitionError) {
      throw new HttpError(400, 'REVIEW_INVALID_TRANSITION', error.message);
    }
    throw error;
  };

  const requireApprovedReviewForRequest = async (
    req: Request,
    reviewId: string | undefined,
    targetKind: ReviewTargetKind,
    reference?: string,
  ): Promise<void> => {
    const { tenantId, hasAdminScope } = getAuthContext(req);
    if (hasAdminScope) {
      return;
    }
    if (!reviewId || typeof reviewId !== 'string' || reviewId.trim().length === 0) {
      throw new HttpError(403, 'REVIEW_REQUIRED', 'Bu işlem için onaylanmış bir inceleme gereklidir.');
    }
    const review = await reviewStore.getReview(tenantId, reviewId);
    if (!review) {
      throw new HttpError(404, 'REVIEW_NOT_FOUND', 'İnceleme kaydı bulunamadı.');
    }
    if (review.status !== 'approved') {
      throw new HttpError(409, 'REVIEW_NOT_APPROVED', 'İnceleme henüz onaylanmadı.', {
        status: review.status,
      });
    }
    if (review.target.kind !== targetKind) {
      throw new HttpError(400, 'REVIEW_TARGET_MISMATCH', 'İnceleme bu işlem için geçerli değil.', {
        expected: targetKind,
        actual: review.target.kind,
      });
    }
    if (reference && review.target.reference && review.target.reference !== reference) {
      throw new HttpError(400, 'REVIEW_REFERENCE_MISMATCH', 'İnceleme farklı bir hedef için geçerlidir.', {
        expected: reference,
        actual: review.target.reference,
      });
    }
  };

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
  const complianceSummaryCache = new Map<string, ComplianceSummaryCacheEntry>();
  complianceSummaryCacheRegistry.add(complianceSummaryCache);
  const tenantSnapshotVersions = new Map<string, SnapshotVersion>();
  const tenantDataRoot = path.join(directories.base, 'tenants');
  const TENANT_EVIDENCE_FILE = 'evidence.json';
  const TENANT_COMPLIANCE_FILE = 'compliance.json';
  const TENANT_SNAPSHOT_FILE = 'snapshot.json';

  interface RoleSummary {
    id: string;
    name: string;
    description?: string | null;
    createdAt: string;
  }

  interface UserSummary {
    id: string;
    tenantId: string;
    email: string;
    displayName?: string | null;
    createdAt: string;
    updatedAt: string;
    roles: RoleSummary[];
  }

  interface ApiKeySummary {
    id: string;
    tenantId: string;
    label?: string | null;
    fingerprint: string;
    createdAt: string;
    lastUsedAt?: string | null;
    roles: UserRole[];
    permissions: string[];
    preview?: string;
    expiresAt?: string | null;
  }

  interface ApiKeyMetadataEntry {
    label?: string | null;
    roles: UserRole[];
    permissions: string[];
    preview?: string;
    expiresAt?: string | null;
  }

  const apiKeyMetadata = new Map<string, ApiKeyMetadataEntry>();

  const toRoleSummary = (role: RbacRole): RoleSummary => ({
    id: role.id,
    name: role.name,
    description: role.description ?? null,
    createdAt: role.createdAt.toISOString(),
  });

  const buildUserSummary = async (user: RbacUser): Promise<UserSummary> => {
    const roles = await rbacStore.listUserRoles(user.tenantId, user.id);
    return {
      id: user.id,
      tenantId: user.tenantId,
      email: user.email,
      displayName: user.displayName ?? null,
      createdAt: user.createdAt.toISOString(),
      updatedAt: user.updatedAt.toISOString(),
      roles: roles.map((role) => toRoleSummary(role)),
    };
  };

  const getApiKeySummary = (key: RbacApiKey): ApiKeySummary => {
    const metadata = apiKeyMetadata.get(key.id);
    return {
      id: key.id,
      tenantId: key.tenantId,
      label: metadata?.label ?? key.label ?? null,
      fingerprint: key.fingerprint,
      createdAt: key.createdAt.toISOString(),
      lastUsedAt: key.lastUsedAt ? key.lastUsedAt.toISOString() : null,
      roles: metadata?.roles ?? [],
      permissions: metadata?.permissions ?? [],
      preview: metadata?.preview,
      expiresAt: metadata?.expiresAt ?? null,
    };
  };

  const getActorIdentifier = (principal: ApiPrincipal, fallback: string): string => {
    if (principal.userId) {
      return principal.userId;
    }
    if (principal.preview) {
      return principal.preview;
    }
    return fallback;
  };

  const validRoles: UserRole[] = ['admin', 'maintainer', 'reader'];

  const parseRoleIdentifiers = (input: unknown, fieldName: string): UserRole[] => {
    if (input === undefined) {
      return [];
    }
    if (!Array.isArray(input)) {
      throw new HttpError(400, 'INVALID_REQUEST', `${fieldName} dizisi gereklidir.`);
    }
    const roles = input.map((value) => {
      if (typeof value !== 'string' || value.trim().length === 0) {
        throw new HttpError(400, 'INVALID_REQUEST', `${fieldName} değerleri metin olmalıdır.`);
      }
      const normalized = value.trim().toLowerCase();
      if (!validRoles.includes(normalized as UserRole)) {
        throw new HttpError(400, 'INVALID_REQUEST', `${fieldName} değeri desteklenmiyor: ${value}`);
      }
      return normalized as UserRole;
    });
    return Array.from(new Set(roles));
  };

  const parsePermissionList = (input: unknown, fieldName: string): string[] => {
    if (input === undefined) {
      return [];
    }
    if (!Array.isArray(input)) {
      throw new HttpError(400, 'INVALID_REQUEST', `${fieldName} dizisi gereklidir.`);
    }
    const permissions = input.map((value) => {
      if (typeof value !== 'string' || value.trim().length === 0) {
        throw new HttpError(400, 'INVALID_REQUEST', `${fieldName} değerleri metin olmalıdır.`);
      }
      return value.trim();
    });
    return Array.from(new Set(permissions));
  };

  const toOptionalIsoString = (value: Date | null | undefined): string | null | undefined => {
    if (value === undefined) {
      return undefined;
    }
    if (value === null) {
      return null;
    }
    return value.toISOString();
  };

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

  const writeTenantJson = async (
    tenantId: string,
    fileName: string,
    data: unknown,
  ): Promise<void> => {
    const tenantDir = path.join(tenantDataRoot, tenantId);
    await writePersistedJson(tenantDir, fileName, data);
  };

  const persistTenantEvidence = async (tenantId: string): Promise<void> => {
    const store = evidenceStore.get(tenantId);
    if (!store) {
      return;
    }
    await writeTenantJson(tenantId, TENANT_EVIDENCE_FILE, Array.from(store.values()));
  };

  const persistTenantCompliance = async (tenantId: string): Promise<void> => {
    complianceSummaryCache.delete(tenantId);
    const store = complianceStore.get(tenantId);
    if (!store) {
      return;
    }
    await writeTenantJson(tenantId, TENANT_COMPLIANCE_FILE, Array.from(store.values()));
  };

  const persistTenantSnapshotVersion = async (
    tenantId: string,
    version: SnapshotVersion,
  ): Promise<void> => {
    await writeTenantJson(tenantId, TENANT_SNAPSHOT_FILE, version);
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

  const ensureTenantSnapshotVersion = async (tenantId: string): Promise<SnapshotVersion> => {
    const existing = tenantSnapshotVersions.get(tenantId);
    if (existing) {
      return existing;
    }
    const now = new Date().toISOString();
    const version = createSnapshotVersion(computeTenantEvidenceFingerprint(tenantId), { createdAt: now });
    tenantSnapshotVersions.set(tenantId, version);
    await persistTenantSnapshotVersion(tenantId, version);
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
          void persistTenantSnapshotVersion(tenantId, fallbackVersion).catch((error) => {
            logger.error({ err: error, tenantId }, 'Failed to persist fallback snapshot version.');
          });
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

  const getLatestComplianceRecord = (tenantId: string): ComplianceRecord | undefined => {
    const store = complianceStore.get(tenantId);
    if (!store || store.size === 0) {
      return undefined;
    }
    let latest: ComplianceRecord | undefined;
    store.forEach((record) => {
      if (!latest || latest.createdAt < record.createdAt) {
        latest = record;
      }
    });
    return latest;
  };

  const buildComplianceSummaryPayload = (
    record: ComplianceRecord | undefined,
    computedAtIso: string,
  ): ComplianceSummaryResponsePayload => {
    if (!record) {
      return { computedAt: computedAtIso, latest: null };
    }

    const missingIds: string[] = [];
    const partialIds: string[] = [];

    record.matrix.requirements.forEach((requirement) => {
      if (requirement.status === 'missing') {
        missingIds.push(requirement.id);
        return;
      }
      if (requirement.status === 'partial') {
        partialIds.push(requirement.id);
      }
    });

    const coverage: CoverageSummaryPayload = {};
    (['statements', 'branches', 'functions', 'lines'] as Array<keyof CoverageSummaryPayload>).forEach((key) => {
      const value = record.coverage[key];
      if (value !== undefined) {
        coverage[key] = value;
      }
    });

    return {
      computedAt: computedAtIso,
      latest: {
        id: record.id,
        createdAt: record.createdAt,
        project: record.matrix.project,
        level: record.matrix.level,
        generatedAt: record.matrix.generatedAt,
        summary: record.matrix.summary,
        coverage,
        gaps: {
          missingIds,
          partialIds,
          openObjectiveCount: missingIds.length + partialIds.length,
        },
      },
    };
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
        const qaLogUploads = payload.uploads.qaLogs ?? [];
        const jiraDefectUploads = payload.uploads.jiraDefects ?? [];
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
          designCsv: payload.uploads.designCsv?.[0],
          jiraDefects: jiraDefectUploads.length > 0 ? [...jiraDefectUploads] : undefined,
          polyspace: payload.uploads.polyspace?.[0],
          ldra: payload.uploads.ldra?.[0],
          vectorcast: payload.uploads.vectorcast?.[0],
          qaLogs: qaLogUploads.length > 0 ? [...qaLogUploads] : undefined,
          objectives: payload.uploads.objectives?.[0],
          level: payload.level ?? undefined,
          projectName: payload.projectName ?? undefined,
          projectVersion: payload.projectVersion ?? undefined,
          independentSources:
            payload.independentSources && payload.independentSources.length > 0
              ? [...payload.independentSources]
              : payload.independentSources === null
                ? undefined
                : payload.independentSources,
          independentArtifacts:
            payload.independentArtifacts && payload.independentArtifacts.length > 0
              ? [...payload.independentArtifacts]
              : payload.independentArtifacts === null
                ? undefined
                : payload.independentArtifacts,
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
            independentSources: payload.independentSources ?? null,
            independentArtifacts: payload.independentArtifacts ?? null,
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
        const toolQualificationMetadata = result.toolQualification
          ? {
              summary: result.toolQualification.summary,
              tqpPath: result.toolQualification.tqp,
              tarPath: result.toolQualification.tar,
              tqpHref: toReportAssetHref(payload.reportDir, result.toolQualification.tqp),
              tarHref: toReportAssetHref(payload.reportDir, result.toolQualification.tar),
            }
          : undefined;
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
            soiStage: payload.soiStage ?? null,
            planConfig: payload.planConfigPath ? path.basename(payload.planConfigPath) : null,
            planOverrides: payload.planOverrides ?? null,
          },
          license: payload.license,
          outputs: {
            directory: payload.reportDir,
            complianceHtml: result.complianceHtml,
            complianceJson: result.complianceJson,
            complianceCsv: result.complianceCsv,
            traceHtml: result.traceHtml,
            gapsHtml: result.gapsHtml,
            analysisPath: path.join(payload.reportDir, 'analysis.json'),
            snapshotPath: path.join(payload.reportDir, 'snapshot.json'),
            tracesPath: path.join(payload.reportDir, 'traces.json'),
            ...(toolQualificationMetadata
              ? { toolQualification: toolQualificationMetadata }
              : {}),
          },
        };

        await writeJobMetadata(storage, payload.reportDir, metadata);

        await storage
          .removeDirectory(path.join(directories.uploads, context.tenantId, context.id))
          .catch(() => undefined);

        return toReportResult(storage, metadata);
      } catch (error) {
        await storage.removeDirectory(payload.reportDir);
        await storage
          .removeDirectory(path.join(directories.uploads, context.tenantId, context.id))
          .catch(() => undefined);
        throw createPipelineError(error, 'Rapor oluşturma işlemi başarısız oldu.');
      }
    },
    pack: async (context) => {
      const payload = requireJobPayload<'pack'>(context);
      await storage.ensureDirectory(payload.packageDir);
      try {
        const signingKey = await fsPromises.readFile(payload.signingKeyPath, 'utf8');
        const tenantLedgerDir = path.join(storage.directories.ledgers, context.tenantId);
        await storage.ensureDirectory(tenantLedgerDir);
        const tenantLedgerPath = path.join(tenantLedgerDir, 'ledger.json');
        const packageLedgerPath = path.join(payload.packageDir, 'ledger.json');
        const packOptions: StageAwarePackOptions = {
          input: payload.reportDir,
          output: payload.packageDir,
          packageName: payload.packageName,
          signingKey,
          ledger: { path: tenantLedgerPath },
          ...(cmsSigningOptions
            ? {
                cms: {
                  bundlePem: cmsSigningOptions.bundlePem,
                  certificatePem: cmsSigningOptions.certificatePem,
                  privateKeyPem: cmsSigningOptions.privateKeyPem,
                  chainPem: cmsSigningOptions.chainPem,
                },
              }
            : {}),
          ...(payload.soiStage ? { soiStage: payload.soiStage } : {}),
          ...(payload.postQuantum !== undefined ? { postQuantum: payload.postQuantum } : {}),
        };
        const result = await runPack(packOptions);

        const manifestContent = await fsPromises.readFile(result.manifestPath, 'utf8');
        let manifest: Manifest;
        try {
          manifest = JSON.parse(manifestContent) as Manifest;
        } catch (error) {
          throw new Error(`Manifest JSON parse edilemedi: ${(error as Error).message}`);
        }

        let proofEvaluation: ReturnType<typeof evaluateManifestProofs>;
        try {
          proofEvaluation = evaluateManifestProofs(manifest);
        } catch (error) {
          throw new Error(`Manifest Merkle kanıtları doğrulanamadı: ${(error as Error).message}`);
        }

        if (result.ledger) {
          await storage.writeJson(packageLedgerPath, result.ledger);
        }

        if (cmsSigningOptions && !result.cmsSignaturePath) {
          throw new Error('CMS signature output missing for pack job.');
        }

        let cmsSignatureMetadata: CmsSignatureMetadata | undefined;
        if (result.cmsSignaturePath) {
          const [cmsPem, signatureContent] = await Promise.all([
            fsPromises.readFile(result.cmsSignaturePath, 'utf8'),
            fsPromises.readFile(path.join(path.dirname(result.manifestPath), 'manifest.sig'), 'utf8'),
          ]);
          const signature = signatureContent.trim();
          const verification = verifyManifestSignatureWithSecuritySigner(manifest, signature, {
            cms: {
              signaturePem: cmsPem,
              required: Boolean(cmsSigningOptions),
              ...(cmsVerificationCertificate ? { certificatePem: cmsVerificationCertificate } : {}),
            },
          });
          if (!verification.valid || !verification.cms) {
            const reason = verification.reason ?? 'unknown';
            throw new Error(`CMS signature verification failed: ${reason}`);
          }
          if (!verification.cms.verified || !verification.cms.digestVerified) {
            const reason = verification.reason ?? 'CMS_DIGEST_MISMATCH';
            throw new Error(`CMS signature verification failed: ${reason}`);
          }
          const cmsSha256 =
            result.cmsSignatureSha256 ?? createHash('sha256').update(cmsPem).digest('hex');
          cmsSignatureMetadata = {
            path: result.cmsSignaturePath,
            sha256: cmsSha256,
            der: extractPemBody(cmsPem),
            digestAlgorithm: verification.digest?.algorithm ?? 'SHA-256',
            verified: verification.cms.verified,
            digestVerified: verification.cms.digestVerified,
            signerSerialNumber: verification.cms.signerSerialNumber ?? null,
            signerIssuer: verification.cms.signerIssuer ?? null,
            signerSubject: verification.cms.signerSubject ?? null,
            signatureAlgorithm: verification.cms.signatureAlgorithm ?? null,
          };
        }

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
            soiStage: payload.soiStage ?? null,
            postQuantumAlgorithm:
              payload.postQuantum && payload.postQuantum !== false
                ? payload.postQuantum.algorithm ?? null
                : null,
          },
          license: payload.license,
          outputs: {
            manifestPath: result.manifestPath,
            archivePath: result.archivePath,
            manifestId: result.manifestId,
            manifestDigest: result.manifestDigest,
            ledgerPath: result.ledger ? packageLedgerPath : undefined,
            ledgerRoot: result.ledgerEntry?.ledgerRoot,
            previousLedgerRoot: result.ledgerEntry?.previousRoot ?? null,
            ...(cmsSignatureMetadata ? { cmsSignature: cmsSignatureMetadata } : {}),
            ...(result.signatureMetadata?.postQuantumSignature
              ? { postQuantumSignature: result.signatureMetadata.postQuantumSignature }
              : {}),
          },
        };

        await writeJobMetadata(storage, payload.packageDir, metadata);

        if (result.ledgerEntry) {
          events.publishLedgerEntry(context.tenantId, result.ledgerEntry, {
            id: `ledger-${context.id}-${result.ledgerEntry.index}`,
          });
        }

        events.publishManifestProof(
          context.tenantId,
          {
            manifestId: metadata.outputs.manifestId,
            jobId: metadata.id,
            merkle: proofEvaluation.merkle,
            files: proofEvaluation.files.map(({ file, verified }) => ({
              path: file.path,
              sha256: file.sha256,
              hasProof: Boolean(file.proof),
              verified,
            })),
          },
          { id: `manifest-proof-${context.id}` },
        );

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
      await ensureJobsRestored();
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
  const contentSecurityPolicyDirectives = {
    'default-src': ["'self'"],
    'base-uri': ["'none'"],
    'form-action': ["'self'"],
    'frame-ancestors': ["'none'"],
    'connect-src': ["'self'"],
    'font-src': ["'self'"],
    'img-src': ["'self'", 'data:'],
    'manifest-src': ["'self'"],
    'media-src': ["'self'"],
    'object-src': ["'none'"],
    'script-src': ["'self'"],
    'style-src': ["'self'"],
    'worker-src': ["'self'"],
  } as const;

  const restrictedPermissionsPolicy: Record<string, string[]> = {
    accelerometer: [],
    autoplay: [],
    camera: [],
    'display-capture': [],
    'document-domain': [],
    'encrypted-media': [],
    fullscreen: [],
    geolocation: [],
    gyroscope: [],
    magnetometer: [],
    microphone: [],
    midi: [],
    payment: [],
    'picture-in-picture': [],
    'publickey-credentials-get': [],
    'sync-xhr': [],
    usb: [],
    'xr-spatial-tracking': [],
  };

  const permissionsPolicyHeader = Object.entries(restrictedPermissionsPolicy)
    .map(([feature, allowlist]) => `${feature}=(${allowlist.join(' ')})`)
    .join(', ');

  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: false,
        directives: contentSecurityPolicyDirectives,
      },
      crossOriginEmbedderPolicy: true,
      crossOriginOpenerPolicy: { policy: 'same-origin' },
      crossOriginResourcePolicy: { policy: 'same-origin' },
      referrerPolicy: { policy: 'no-referrer' },
      hsts: {
        maxAge: 31_536_000,
        includeSubDomains: true,
        preload: true,
      },
      permittedCrossDomainPolicies: { permittedPolicies: 'none' },
    }),
  );
  app.use((_req, res, next) => {
    res.setHeader('Permissions-Policy', permissionsPolicyHeader);
    next();
  });
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
  const jobStore = new JobStore(config.database, logger);
  const queue = new JobQueue(workerConcurrency, {
    directory: queueDirectory,
    persistJobs: false,
    createRunner: (context) => {
      const handler = jobHandlers[context.kind] as JobHandler<JobKind>;
      const run = async () => {
        try {
          await jobStore.markRunning(context.tenantId, context.id);
          await appendAuditLog({
            tenantId: context.tenantId,
            actor: 'system',
            action: 'job.started',
            target: toJobTarget(context.id),
            payload: { kind: context.kind, hash: context.hash },
          });
        } catch (error) {
          logger.error(
            {
              event: 'job_store_mark_running_failed',
              tenantId: context.tenantId,
              jobId: context.id,
              error: error instanceof Error ? error.message : String(error),
            },
            'İş durumu "running" olarak güncellenemedi.',
          );
          throw error;
        }
        try {
          const result = await handler(context as JobExecutionContext<JobPayloadMap[JobKind]>);
          await jobStore.markCompleted(context.tenantId, context.id, result);
          await appendAuditLog({
            tenantId: context.tenantId,
            actor: 'system',
            action: 'job.completed',
            target: toJobTarget(context.id),
            payload: { kind: context.kind, hash: context.hash },
          });
          return result;
        } catch (error) {
          const normalized = toHttpError(error, {
            code: 'JOB_FAILED',
            message: 'İş başarısız oldu.',
            statusCode: 500,
          });
          const payload: JobErrorState = {
            statusCode: normalized.statusCode,
            code: normalized.code,
            message: normalized.message,
            details: normalized.details,
          };
          try {
            await jobStore.markFailed(context.tenantId, context.id, payload);
            await appendAuditLog({
              tenantId: context.tenantId,
              actor: 'system',
              action: 'job.failed',
              target: toJobTarget(context.id),
              payload: {
                kind: context.kind,
                hash: context.hash,
                error: { code: payload.code, statusCode: payload.statusCode },
              },
            });
          } catch (storeError) {
            logger.error(
              {
                event: 'job_store_mark_failed_error',
                tenantId: context.tenantId,
                jobId: context.id,
                error: storeError instanceof Error ? storeError.message : String(storeError),
              },
              'İş başarısız durumu kaydedilemedi.',
            );
          }
          throw error;
        }
      };
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

  let restoreError: unknown;
  const restorePromise = jobStore
    .restore(queue, knownTenants)
    .catch((error) => {
      restoreError = error;
      logger.error(
        {
          event: 'job_restore_failed',
          error: error instanceof Error ? error.message : String(error),
        },
        'Kuyruk iş durumu veritabanından yüklenemedi.',
      );
      throw error;
    });

  const ensureJobsRestored = async (): Promise<void> => {
    if (restoreError) {
      throw restoreError;
    }
    await restorePromise;
  };

  const getActiveJobCount = async (tenantId: string): Promise<number> =>
    jobStore.countActiveJobs(tenantId);

  const getTotalActiveJobCount = async (): Promise<number> => jobStore.countTotalActiveJobs();

  const updateQueueDepth = async (tenantId: string): Promise<void> => {
    const [tenantCount, totalCount, jobs] = await Promise.all([
      getActiveJobCount(tenantId),
      getTotalActiveJobCount(),
      jobStore.listJobs(tenantId),
    ]);
    jobQueueDepthGauge.set({ tenantId }, tenantCount);
    jobQueueTotalGauge.set(totalCount);
    events.publishQueueState(tenantId, jobs);
  };

  const ensureQueueWithinLimit = async (tenantId: string): Promise<void> => {
    const activeJobs = await getActiveJobCount(tenantId);
    if (activeJobs >= maxQueuedJobsPerTenant) {
      throw new HttpError(
        429,
        'QUEUE_LIMIT_EXCEEDED',
        'Kiracı için kuyrukta bekleyen iş limiti aşıldı.',
        { limit: maxQueuedJobsPerTenant, scope: 'tenant' },
      );
    }
    if (maxQueuedJobsTotal !== undefined) {
      const totalActiveJobs = await getTotalActiveJobCount();
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
        setImmediate(() => {
          void updateQueueDepth(context.tenantId);
        });
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
        setImmediate(() => {
          void updateQueueDepth(context.tenantId);
        });
        throw error;
      }
    };
  }

  const enqueueObservedJob = async <TResult, TPayload>(options: {
    tenantId: string;
    actor: string;
    id: string;
    kind: JobKind;
    hash: string;
    payload: TPayload;
  }): Promise<JobDetails<TResult>> => {
    await ensureJobsRestored();
    await ensureQueueWithinLimit(options.tenantId);
    const existing = await jobStore.findJob<TResult>(options.tenantId, options.id);
    if (existing) {
      await appendAuditLog({
        tenantId: options.tenantId,
        actor: options.actor,
        action: 'job.reused',
        target: toJobTarget(existing.id),
        payload: { kind: existing.kind, hash: existing.hash, status: existing.status },
      });
      return existing;
    }

    const createdAt = new Date();
    const insertResult = await jobStore.insertQueuedJob({
      tenantId: options.tenantId,
      id: options.id,
      kind: options.kind,
      hash: options.hash,
      payload: options.payload,
      createdAt,
      updatedAt: createdAt,
    });

    if (!insertResult.inserted) {
      if (insertResult.job) {
        await appendAuditLog({
          tenantId: options.tenantId,
          actor: options.actor,
          action: 'job.reused',
          target: toJobTarget(insertResult.job.id),
          payload: {
            kind: insertResult.job.kind,
            hash: insertResult.job.hash,
            status: insertResult.job.status,
          },
        });
        return insertResult.job as JobDetails<TResult>;
      }
      const fallback = await jobStore.findJob<TResult>(options.tenantId, options.id);
      if (fallback) {
        await appendAuditLog({
          tenantId: options.tenantId,
          actor: options.actor,
          action: 'job.reused',
          target: toJobTarget(fallback.id),
          payload: { kind: fallback.kind, hash: fallback.hash, status: fallback.status },
        });
        return fallback;
      }
    }

    await appendAuditLog({
      tenantId: options.tenantId,
      actor: options.actor,
      action: 'job.created',
      target: toJobTarget(options.id),
      payload: { kind: options.kind, hash: options.hash },
    });

    const job = queue.enqueue<TPayload, TResult>({
      tenantId: options.tenantId,
      id: options.id,
      kind: options.kind,
      hash: options.hash,
      payload: options.payload,
      createdAt,
      updatedAt: createdAt,
    });
    knownTenants.add(options.tenantId);
    logger.info({
      event: 'job_created',
      tenantId: options.tenantId,
      jobId: options.id,
      kind: options.kind,
      hash: options.hash,
    });
    await updateQueueDepth(options.tenantId);
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
      const { tenantId, subject } = getAuthContext(req);
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

  app.get('/v1/stream/compliance', requireAuth, (req, res, next) => {
    ensureRole(req, ['reader', 'maintainer', 'admin'])
      .then((principal) => {
        const { tenantId } = getAuthContext(req);
        try {
          events.connect({
            tenantId,
            actorTenantId: principal.tenantId ?? tenantId,
            response: res,
            request: req,
            heartbeatMs: config.events?.heartbeatMs,
            actorLabel: principal.label ?? principal.preview,
          });
        } catch (error) {
          next(error);
        }
      })
      .catch(next);
  });

  app.get(
    '/v1/admin/storage/health',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      ensureAdminScope(req);
      const providerName = storage.constructor?.name ?? 'UnknownStorage';

      try {
        await storage.listSubdirectories(directories.base);
      } catch (error) {
        const reason = error instanceof Error ? error.message : String(error);
        throw new HttpError(
          500,
          'STORAGE_HEALTH_FAILED',
          'Depolama sağlayıcısı doğrulanamadı.',
          { provider: providerName, reason },
        );
      }

      const startedAt = process.hrtime.bigint();
      let latencyMs = 0;
      try {
        await config.database.getPool().query('SELECT 1');
        const elapsed = Number(process.hrtime.bigint() - startedAt);
        latencyMs = elapsed < 0 ? 0 : elapsed / 1_000_000;
      } catch (error) {
        const elapsed = Number(process.hrtime.bigint() - startedAt);
        latencyMs = elapsed < 0 ? 0 : elapsed / 1_000_000;
        const reason = error instanceof Error ? error.message : String(error);
        throw new HttpError(
          500,
          'STORAGE_HEALTH_FAILED',
          'Depolama sağlığı doğrulanamadı.',
          { provider: providerName, reason, databaseLatencyMs: latencyMs },
        );
      }

      res.json({
        provider: providerName,
        status: 'ok',
        database: {
          latencyMs,
        },
      });
    }),
  );

  app.get(
    '/v1/admin/roles',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      ensureAdminScope(req);
      await ensureRole(req, ['admin', 'maintainer']);
      const { tenantId } = getAuthContext(req);
      const roles = await rbacStore.listRoles(tenantId);
      res.json({ items: roles.map((role) => toRoleSummary(role)) });
    }),
  );

  app.post(
    '/v1/admin/roles',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      ensureAdminScope(req);
      const principal = await ensureRole(req, ['admin']);
      const context = getAuthContext(req);
      const body = req.body as { id?: unknown; name?: unknown; description?: unknown };
      if (!body || typeof body !== 'object') {
        throw new HttpError(400, 'INVALID_REQUEST', 'Geçerli bir JSON gövdesi gereklidir.');
      }
      const name = typeof body.name === 'string' ? body.name.trim() : '';
      if (!name) {
        throw new HttpError(400, 'INVALID_REQUEST', 'Rol adı belirtilmelidir.');
      }
      const descriptionRaw = body.description;
      let description: string | null | undefined;
      if (descriptionRaw === null) {
        description = null;
      } else if (descriptionRaw === undefined) {
        description = undefined;
      } else if (typeof descriptionRaw === 'string') {
        description = descriptionRaw.trim();
      } else {
        throw new HttpError(400, 'INVALID_REQUEST', 'Rol açıklaması metin olmalıdır.');
      }
      const id = typeof body.id === 'string' && body.id.trim().length > 0 ? body.id.trim() : undefined;
      const role = await rbacStore.createRole({
        tenantId: context.tenantId,
        id,
        name,
        description: description ?? undefined,
      });
      await appendAuditLog({
        tenantId: context.tenantId,
        actor: getActorIdentifier(principal, context.subject),
        action: 'admin.role.created',
        target: `role:${role.id}`,
        payload: {
          id: role.id,
          name: role.name,
          description: role.description ?? null,
        },
      });
      res.status(201).json({ role: toRoleSummary(role) });
    }),
  );

  app.put(
    '/v1/admin/roles/:roleId',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      ensureAdminScope(req);
      const principal = await ensureRole(req, ['admin']);
      const context = getAuthContext(req);
      const { roleId } = req.params as { roleId?: string };
      if (!roleId) {
        throw new HttpError(400, 'INVALID_REQUEST', 'Rol kimliği belirtilmelidir.');
      }
      const body = req.body as { name?: unknown; description?: unknown };
      if (!body || typeof body !== 'object') {
        throw new HttpError(400, 'INVALID_REQUEST', 'Geçerli bir JSON gövdesi gereklidir.');
      }
      const name = typeof body.name === 'string' ? body.name.trim() : '';
      if (!name) {
        throw new HttpError(400, 'INVALID_REQUEST', 'Rol adı belirtilmelidir.');
      }
      const descriptionRaw = body.description;
      let description: string | null | undefined;
      if (descriptionRaw === null) {
        description = null;
      } else if (descriptionRaw === undefined) {
        description = undefined;
      } else if (typeof descriptionRaw === 'string') {
        description = descriptionRaw.trim();
      } else {
        throw new HttpError(400, 'INVALID_REQUEST', 'Rol açıklaması metin olmalıdır.');
      }
      const role = await rbacStore.createRole({
        tenantId: context.tenantId,
        id: roleId,
        name,
        description: description ?? undefined,
      });
      await appendAuditLog({
        tenantId: context.tenantId,
        actor: getActorIdentifier(principal, context.subject),
        action: 'admin.role.updated',
        target: `role:${role.id}`,
        payload: {
          id: role.id,
          name: role.name,
          description: role.description ?? null,
        },
      });
      res.json({ role: toRoleSummary(role) });
    }),
  );

  app.delete(
    '/v1/admin/roles/:roleId',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      ensureAdminScope(req);
      const principal = await ensureRole(req, ['admin']);
      const context = getAuthContext(req);
      const { roleId } = req.params as { roleId?: string };
      if (!roleId) {
        throw new HttpError(400, 'INVALID_REQUEST', 'Rol kimliği belirtilmelidir.');
      }
      const pool = config.database.getPool();
      await pool.query('DELETE FROM rbac_user_roles WHERE tenant_id = $1 AND role_id = $2', [
        context.tenantId,
        roleId,
      ]);
      const result = await pool.query('DELETE FROM rbac_roles WHERE tenant_id = $1 AND id = $2', [
        context.tenantId,
        roleId,
      ]);
      if (result.rowCount === 0) {
        throw new HttpError(404, 'ROLE_NOT_FOUND', 'Silinecek rol bulunamadı.');
      }
      await appendAuditLog({
        tenantId: context.tenantId,
        actor: getActorIdentifier(principal, context.subject),
        action: 'admin.role.deleted',
        target: `role:${roleId}`,
      });
      res.status(204).end();
    }),
  );

  app.get(
    '/v1/admin/users',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      ensureAdminScope(req);
      await ensureRole(req, ['admin', 'maintainer']);
      const { tenantId } = getAuthContext(req);
      const users = await rbacStore.listUsers(tenantId);
      const items = await Promise.all(users.map((user) => buildUserSummary(user)));
      res.json({ items });
    }),
  );

  app.post(
    '/v1/admin/users',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      ensureAdminScope(req);
      const principal = await ensureRole(req, ['admin']);
      const context = getAuthContext(req);
      const body = req.body as {
        id?: unknown;
        email?: unknown;
        secret?: unknown;
        displayName?: unknown;
        roleIds?: unknown;
      };
      if (!body || typeof body !== 'object') {
        throw new HttpError(400, 'INVALID_REQUEST', 'Geçerli bir JSON gövdesi gereklidir.');
      }
      const email = typeof body.email === 'string' ? body.email.trim() : '';
      if (!email) {
        throw new HttpError(400, 'INVALID_REQUEST', 'Kullanıcı e-posta adresi zorunludur.');
      }
      const secret = typeof body.secret === 'string' ? body.secret : '';
      if (!secret) {
        throw new HttpError(400, 'INVALID_REQUEST', 'Kullanıcı parolası zorunludur.');
      }
      const displayName =
        typeof body.displayName === 'string'
          ? body.displayName.trim()
          : body.displayName === null
            ? null
            : undefined;
      const roleIdsRaw = Array.isArray(body.roleIds) ? body.roleIds : [];
      const roleIds = roleIdsRaw.map((value) => {
        if (typeof value !== 'string' || value.trim().length === 0) {
          throw new HttpError(400, 'INVALID_REQUEST', 'Rol kimlikleri metin olarak sağlanmalıdır.');
        }
        return value.trim();
      });
      const availableRoles = await rbacStore.listRoles(context.tenantId);
      const availableRoleIds = new Set(availableRoles.map((role) => role.id));
      roleIds.forEach((roleId) => {
        if (!availableRoleIds.has(roleId)) {
          throw new HttpError(400, 'ROLE_NOT_FOUND', `Rol bulunamadı: ${roleId}`);
        }
      });
      const id = typeof body.id === 'string' && body.id.trim().length > 0 ? body.id.trim() : undefined;
      const user = await rbacStore.createUser({
        tenantId: context.tenantId,
        id,
        email,
        secret,
        displayName: displayName ?? undefined,
      });
      await Promise.all(roleIds.map((roleId) => rbacStore.assignRole(context.tenantId, user.id, roleId)));
      const summary = await buildUserSummary(user);
      await appendAuditLog({
        tenantId: context.tenantId,
        actor: getActorIdentifier(principal, context.subject),
        action: 'admin.user.created',
        target: `user:${summary.id}`,
        payload: {
          email: summary.email,
          roles: summary.roles.map((role) => role.id),
          displayName: summary.displayName ?? null,
        },
      });
      res.status(201).json({ user: summary });
    }),
  );

  app.get(
    '/v1/admin/users/:userId',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      ensureAdminScope(req);
      await ensureRole(req, ['admin', 'maintainer']);
      const context = getAuthContext(req);
      const { userId } = req.params as { userId?: string };
      if (!userId) {
        throw new HttpError(400, 'INVALID_REQUEST', 'Kullanıcı kimliği belirtilmelidir.');
      }
      const user = await rbacStore.getUser(context.tenantId, userId);
      if (!user) {
        throw new HttpError(404, 'USER_NOT_FOUND', 'Kullanıcı kaydı bulunamadı.');
      }
      const summary = await buildUserSummary(user);
      res.json({ user: summary });
    }),
  );

  app.put(
    '/v1/admin/users/:userId',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      ensureAdminScope(req);
      const principal = await ensureRole(req, ['admin']);
      const context = getAuthContext(req);
      const { userId } = req.params as { userId?: string };
      if (!userId) {
        throw new HttpError(400, 'INVALID_REQUEST', 'Kullanıcı kimliği belirtilmelidir.');
      }
      const existing = await rbacStore.getUser(context.tenantId, userId);
      if (!existing) {
        throw new HttpError(404, 'USER_NOT_FOUND', 'Kullanıcı kaydı bulunamadı.');
      }
      const body = req.body as {
        displayName?: unknown;
        secret?: unknown;
        roleIds?: unknown;
      };
      if (!body || typeof body !== 'object') {
        throw new HttpError(400, 'INVALID_REQUEST', 'Geçerli bir JSON gövdesi gereklidir.');
      }
      if (body.secret !== undefined) {
        if (typeof body.secret !== 'string' || body.secret.length === 0) {
          throw new HttpError(400, 'INVALID_REQUEST', 'Parola metin olarak sağlanmalıdır.');
        }
        await rbacStore.updateUserSecret(context.tenantId, userId, body.secret);
      }
      if (body.displayName !== undefined) {
        let normalizedDisplayName: string | null;
        if (body.displayName === null) {
          normalizedDisplayName = null;
        } else if (typeof body.displayName === 'string') {
          normalizedDisplayName = body.displayName.trim();
        } else {
          throw new HttpError(400, 'INVALID_REQUEST', 'Görünen ad metin olmalıdır.');
        }
        await config.database
          .getPool()
          .query(
            `UPDATE rbac_users SET display_name = $1, updated_at = $2 WHERE tenant_id = $3 AND id = $4`,
            [normalizedDisplayName, new Date().toISOString(), context.tenantId, userId],
          );
      }
      if (Array.isArray(body.roleIds)) {
        const desiredRoleIds = body.roleIds.map((value) => {
          if (typeof value !== 'string' || value.trim().length === 0) {
            throw new HttpError(400, 'INVALID_REQUEST', 'Rol kimlikleri metin olarak sağlanmalıdır.');
          }
          return value.trim();
        });
        const availableRoles = await rbacStore.listRoles(context.tenantId);
        const availableRoleIds = new Set(availableRoles.map((role) => role.id));
        desiredRoleIds.forEach((roleId) => {
          if (!availableRoleIds.has(roleId)) {
            throw new HttpError(400, 'ROLE_NOT_FOUND', `Rol bulunamadı: ${roleId}`);
          }
        });
        const currentRoles = await rbacStore.listUserRoles(context.tenantId, userId);
        const currentRoleIds = new Set(currentRoles.map((role) => role.id));
        const desiredSet = new Set(desiredRoleIds);
        const toAssign = desiredRoleIds.filter((roleId) => !currentRoleIds.has(roleId));
        const toRevoke = currentRoles.filter((role) => !desiredSet.has(role.id));
        await Promise.all([
          ...toAssign.map((roleId) => rbacStore.assignRole(context.tenantId, userId, roleId)),
          ...toRevoke.map((role) => rbacStore.revokeRole(context.tenantId, userId, role.id)),
        ]);
      }
      const updated = await rbacStore.getUser(context.tenantId, userId);
      if (!updated) {
        throw new HttpError(500, 'USER_NOT_FOUND', 'Kullanıcı güncelleme sonrası bulunamadı.');
      }
      const summary = await buildUserSummary(updated);
      await appendAuditLog({
        tenantId: context.tenantId,
        actor: getActorIdentifier(principal, context.subject),
        action: 'admin.user.updated',
        target: `user:${summary.id}`,
        payload: {
          roles: summary.roles.map((role) => role.id),
          displayName: summary.displayName ?? null,
        },
      });
      res.json({ user: summary });
    }),
  );

  app.delete(
    '/v1/admin/users/:userId',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      ensureAdminScope(req);
      const principal = await ensureRole(req, ['admin']);
      const context = getAuthContext(req);
      const { userId } = req.params as { userId?: string };
      if (!userId) {
        throw new HttpError(400, 'INVALID_REQUEST', 'Kullanıcı kimliği belirtilmelidir.');
      }
      const existing = await rbacStore.getUser(context.tenantId, userId);
      if (!existing) {
        throw new HttpError(404, 'USER_NOT_FOUND', 'Kullanıcı kaydı bulunamadı.');
      }
      const pool = config.database.getPool();
      await pool.query('DELETE FROM rbac_user_roles WHERE tenant_id = $1 AND user_id = $2', [
        context.tenantId,
        userId,
      ]);
      await rbacStore.deleteUser(context.tenantId, userId);
      await appendAuditLog({
        tenantId: context.tenantId,
        actor: getActorIdentifier(principal, context.subject),
        action: 'admin.user.deleted',
        target: `user:${userId}`,
      });
      res.status(204).end();
    }),
  );

  app.get(
    '/v1/admin/api-keys',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      ensureAdminScope(req);
      await ensureRole(req, ['admin', 'maintainer']);
      const { tenantId } = getAuthContext(req);
      const keys = await rbacStore.listApiKeys(tenantId);
      res.json({ items: keys.map((key) => getApiKeySummary(key)) });
    }),
  );

  app.post(
    '/v1/admin/api-keys',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      ensureAdminScope(req);
      const principal = await ensureRole(req, ['admin']);
      const context = getAuthContext(req);
      const body = req.body as {
        id?: unknown;
        label?: unknown;
        secret?: unknown;
        roles?: unknown;
        permissions?: unknown;
        expiresAt?: unknown;
      };
      if (!body || typeof body !== 'object') {
        throw new HttpError(400, 'INVALID_REQUEST', 'Geçerli bir JSON gövdesi gereklidir.');
      }
      const label =
        typeof body.label === 'string'
          ? body.label.trim()
          : body.label === null
            ? null
            : undefined;
      const secret = typeof body.secret === 'string' && body.secret.trim().length > 0
        ? body.secret
        : randomUUID().replace(/-/g, '');
      const roles = parseRoleIdentifiers(body.roles, 'roles');
      const permissions = parsePermissionList(body.permissions, 'permissions');
      const expiresAtValue = body.expiresAt;
      let expiresAt: string | null | undefined;
      if (expiresAtValue === null) {
        expiresAt = null;
      } else if (expiresAtValue === undefined) {
        expiresAt = undefined;
      } else if (typeof expiresAtValue === 'string') {
        expiresAt = expiresAtValue;
      } else if (typeof expiresAtValue === 'number') {
        expiresAt = new Date(expiresAtValue).toISOString();
      } else {
        throw new HttpError(400, 'INVALID_REQUEST', 'expiresAt alanı metin veya sayı olmalıdır.');
      }
      const id = typeof body.id === 'string' && body.id.trim().length > 0 ? body.id.trim() : undefined;
      const apiKey = await rbacStore.createApiKey({
        tenantId: context.tenantId,
        id,
        label: label ?? undefined,
        secret,
      });
      const registered = apiKeyAuthorizer.register({
        key: secret,
        label: label ?? undefined,
        roles: roles.length > 0 ? roles : ['reader'],
        tenantId: context.tenantId,
        permissions,
        expiresAt,
      });
      apiKeyMetadata.set(apiKey.id, {
        label: registered.label ?? label ?? null,
        roles: registered.roles,
        permissions: registered.permissions,
        preview: registered.preview,
        expiresAt: toOptionalIsoString(registered.expiresAt),
      });
      const summary = getApiKeySummary(apiKey);
      await appendAuditLog({
        tenantId: context.tenantId,
        actor: getActorIdentifier(principal, context.subject),
        action: 'admin.api-key.created',
        target: `api-key:${summary.id}`,
        payload: {
          label: summary.label ?? null,
          roles: summary.roles,
          permissions: summary.permissions,
        },
      });
      res.status(201).json({ apiKey: summary, secret });
    }),
  );

  app.get(
    '/v1/admin/api-keys/:keyId',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      ensureAdminScope(req);
      await ensureRole(req, ['admin', 'maintainer']);
      const context = getAuthContext(req);
      const { keyId } = req.params as { keyId?: string };
      if (!keyId) {
        throw new HttpError(400, 'INVALID_REQUEST', 'API anahtarı kimliği belirtilmelidir.');
      }
      const keys = await rbacStore.listApiKeys(context.tenantId);
      const apiKey = keys.find((entry) => entry.id === keyId);
      if (!apiKey) {
        throw new HttpError(404, 'API_KEY_NOT_FOUND', 'API anahtarı bulunamadı.');
      }
      res.json({ apiKey: getApiKeySummary(apiKey) });
    }),
  );

  app.put(
    '/v1/admin/api-keys/:keyId',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      ensureAdminScope(req);
      const principal = await ensureRole(req, ['admin']);
      const context = getAuthContext(req);
      const { keyId } = req.params as { keyId?: string };
      if (!keyId) {
        throw new HttpError(400, 'INVALID_REQUEST', 'API anahtarı kimliği belirtilmelidir.');
      }
      const keys = await rbacStore.listApiKeys(context.tenantId);
      const existing = keys.find((entry) => entry.id === keyId);
      if (!existing) {
        throw new HttpError(404, 'API_KEY_NOT_FOUND', 'API anahtarı bulunamadı.');
      }
      const body = req.body as {
        label?: unknown;
        secret?: unknown;
        roles?: unknown;
        permissions?: unknown;
        expiresAt?: unknown;
      };
      if (!body || typeof body !== 'object') {
        throw new HttpError(400, 'INVALID_REQUEST', 'Geçerli bir JSON gövdesi gereklidir.');
      }
      if (body.secret === undefined || typeof body.secret !== 'string' || body.secret.trim().length === 0) {
        throw new HttpError(400, 'INVALID_REQUEST', 'Güncelleme için yeni bir API anahtarı gizli değeri zorunludur.');
      }
      const label =
        typeof body.label === 'string'
          ? body.label.trim()
          : body.label === null
            ? null
            : apiKeyMetadata.get(existing.id)?.label ?? existing.label ?? undefined;
      const roles =
        body.roles === undefined
          ? apiKeyMetadata.get(existing.id)?.roles ?? ['reader']
          : parseRoleIdentifiers(body.roles, 'roles');
      const permissions =
        body.permissions === undefined
          ? apiKeyMetadata.get(existing.id)?.permissions ?? []
          : parsePermissionList(body.permissions, 'permissions');
      const expiresAtValue = body.expiresAt;
      let expiresAt: string | null | undefined;
      if (expiresAtValue === undefined) {
        expiresAt = apiKeyMetadata.get(existing.id)?.expiresAt;
      } else if (expiresAtValue === null) {
        expiresAt = null;
      } else if (typeof expiresAtValue === 'string') {
        expiresAt = expiresAtValue;
      } else if (typeof expiresAtValue === 'number') {
        expiresAt = new Date(expiresAtValue).toISOString();
      } else {
        throw new HttpError(400, 'INVALID_REQUEST', 'expiresAt alanı metin veya sayı olmalıdır.');
      }
      const apiKey = await rbacStore.createApiKey({
        tenantId: context.tenantId,
        id: existing.id,
        label: label ?? undefined,
        secret: body.secret,
      });
      const registered = apiKeyAuthorizer.register({
        key: body.secret,
        label: label ?? undefined,
        roles,
        tenantId: context.tenantId,
        permissions,
        expiresAt,
      });
      apiKeyMetadata.set(apiKey.id, {
        label: registered.label ?? label ?? null,
        roles: registered.roles,
        permissions: registered.permissions,
        preview: registered.preview,
        expiresAt: toOptionalIsoString(registered.expiresAt),
      });
      const summary = getApiKeySummary(apiKey);
      await appendAuditLog({
        tenantId: context.tenantId,
        actor: getActorIdentifier(principal, context.subject),
        action: 'admin.api-key.updated',
        target: `api-key:${summary.id}`,
        payload: {
          label: summary.label ?? null,
          roles: summary.roles,
          permissions: summary.permissions,
        },
      });
      res.json({ apiKey: summary, secret: body.secret });
    }),
  );

  app.delete(
    '/v1/admin/api-keys/:keyId',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      ensureAdminScope(req);
      const principal = await ensureRole(req, ['admin']);
      const context = getAuthContext(req);
      const { keyId } = req.params as { keyId?: string };
      if (!keyId) {
        throw new HttpError(400, 'INVALID_REQUEST', 'API anahtarı kimliği belirtilmelidir.');
      }
      const keys = await rbacStore.listApiKeys(context.tenantId);
      const existing = keys.find((entry) => entry.id === keyId);
      if (!existing) {
        throw new HttpError(404, 'API_KEY_NOT_FOUND', 'API anahtarı bulunamadı.');
      }
      apiKeyAuthorizer.revoke(existing.fingerprint);
      await rbacStore.deleteApiKey(context.tenantId, keyId);
      apiKeyMetadata.delete(keyId);
      await appendAuditLog({
        tenantId: context.tenantId,
        actor: getActorIdentifier(principal, context.subject),
        action: 'admin.api-key.deleted',
        target: `api-key:${keyId}`,
      });
      res.status(204).end();
    }),
  );

  app.post(
    '/evidence/upload',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId, subject } = getAuthContext(req);
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
      const previousVersion = tenantSnapshotVersions.get(tenantId);
      const version = updateTenantSnapshotVersion(tenantId, uploadedAt);
      const snapshotVersionChanged = version !== previousVersion;

      try {
        await persistTenantEvidence(tenantId);
      } catch (error) {
        tenantEvidence.delete(record.id);
        hashIndex.delete(computedHash);
        if (snapshotVersionChanged) {
          if (previousVersion) {
            tenantSnapshotVersions.set(tenantId, previousVersion);
          } else {
            tenantSnapshotVersions.delete(tenantId);
          }
        }
        throw error;
      }

      try {
        await persistTenantSnapshotVersion(tenantId, version);
      } catch (error) {
        if (snapshotVersionChanged) {
          if (previousVersion) {
            tenantSnapshotVersions.set(tenantId, previousVersion);
          } else {
            tenantSnapshotVersions.delete(tenantId);
          }
        }
        throw error;
      }

      res.status(201).json(serializeEvidenceRecord(record));
    }),
  );

  app.post(
    '/v1/config/freeze',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId, subject } = getAuthContext(req);
      const current = await ensureTenantSnapshotVersion(tenantId);
      if (current.isFrozen) {
        res.json({ version: current });
        return;
      }
      const frozen = freezeSnapshotVersion(current, { frozenAt: new Date().toISOString() });
      tenantSnapshotVersions.set(tenantId, frozen);
      await persistTenantSnapshotVersion(tenantId, frozen);
      res.json({ version: frozen });
    }),
  );

  app.get(
    '/v1/compliance/summary',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId } = getAuthContext(req);
      await ensureRole(req, ['reader', 'maintainer', 'admin']);

      const now = Date.now();
      const ttlSeconds = Math.floor(COMPLIANCE_SUMMARY_CACHE_TTL_MS / 1000);
      const latest = getLatestComplianceRecord(tenantId);
      const cached = complianceSummaryCache.get(tenantId);

      if (
        cached &&
        cached.expiresAt > now &&
        ((latest && cached.recordId === latest.id && cached.recordCreatedAt === latest.createdAt) ||
          (!latest && cached.recordId === undefined))
      ) {
        res.status(200).set('Cache-Control', `private, max-age=${ttlSeconds}`).json(cached.payload);
        return;
      }

      const payload = buildComplianceSummaryPayload(latest, new Date(now).toISOString());
      complianceSummaryCache.set(tenantId, {
        recordId: latest?.id,
        recordCreatedAt: latest?.createdAt,
        payload,
        expiresAt: now + COMPLIANCE_SUMMARY_CACHE_TTL_MS,
      });

      res.status(200).set('Cache-Control', `private, max-age=${ttlSeconds}`).json(payload);
    }),
  );

  app.get(
    '/compliance',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId, subject } = getAuthContext(req);
      const store = complianceStore.get(tenantId);
      const items = store ? Array.from(store.values()).map((record) => serializeComplianceRecord(record)) : [];
      res.json({ items });
    }),
  );

  app.get(
    '/compliance/:id',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId, subject } = getAuthContext(req);
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
      const { tenantId, subject } = getAuthContext(req);
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

      const tenantCompliance = getTenantComplianceMap(tenantId);
      tenantCompliance.set(record.id, record);
      try {
        await persistTenantCompliance(tenantId);
      } catch (error) {
        tenantCompliance.delete(record.id);
        throw error;
      }

      res.status(201).json(serializeComplianceRecord(record));
    }),
  );

  const parseReviewTarget = (value: unknown): { kind: ReviewTargetKind; reference?: string | null } | undefined => {
    if (value === undefined) {
      return undefined;
    }
    if (!value || typeof value !== 'object') {
      throw new HttpError(400, 'INVALID_REQUEST', 'target alanı nesne olmalıdır.');
    }
    const record = value as { kind?: unknown; reference?: unknown };
    if (typeof record.kind !== 'string') {
      throw new HttpError(400, 'INVALID_REQUEST', 'target.kind alanı zorunludur.');
    }
    const reference =
      record.reference === undefined || record.reference === null
        ? null
        : typeof record.reference === 'string'
          ? record.reference
          : (() => {
              throw new HttpError(400, 'INVALID_REQUEST', 'target.reference değeri metin olmalıdır.');
            })();
    return { kind: record.kind as ReviewTargetKind, reference };
  };

  const parseReviewApprovers = (value: unknown): string[] | undefined => {
    if (value === undefined) {
      return undefined;
    }
    if (!Array.isArray(value)) {
      throw new HttpError(400, 'INVALID_REQUEST', 'approvers alanı bir dizi olmalıdır.');
    }
    return value.map((entry) => {
      if (typeof entry !== 'string' || entry.trim().length === 0) {
        throw new HttpError(400, 'INVALID_REQUEST', 'approvers dizisi yalnızca metin değerleri içerebilir.');
      }
      return entry;
    });
  };

  const parseReviewArtifacts = (
    value: unknown,
  ): Array<{ id?: string; label: string; description?: string | null }> | undefined => {
    if (value === undefined) {
      return undefined;
    }
    if (!Array.isArray(value)) {
      throw new HttpError(400, 'INVALID_REQUEST', 'requiredArtifacts alanı bir dizi olmalıdır.');
    }
    return value.map((entry, index) => {
      if (!entry || typeof entry !== 'object') {
        throw new HttpError(400, 'INVALID_REQUEST', `requiredArtifacts[${index}] geçerli bir nesne olmalıdır.`);
      }
      const record = entry as { id?: unknown; label?: unknown; description?: unknown };
      if (typeof record.label !== 'string' || record.label.trim().length === 0) {
        throw new HttpError(400, 'INVALID_REQUEST', `requiredArtifacts[${index}].label zorunludur.`);
      }
      const id = record.id === undefined ? undefined : String(record.id);
      const description =
        record.description === undefined || record.description === null
          ? null
          : typeof record.description === 'string'
            ? record.description
            : (() => {
                throw new HttpError(400, 'INVALID_REQUEST', `requiredArtifacts[${index}].description metin olmalıdır.`);
              })();
      return { id, label: record.label, description };
    });
  };

  app.get(
    '/v1/change-requests',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId } = getAuthContext(req);
      await ensureRole(req, ['reader', 'maintainer', 'admin']);

      const baseUrl = process.env.JIRA_BASE_URL;
      const token = process.env.JIRA_TOKEN;

      if (!baseUrl || !token) {
        throw new HttpError(503, 'UPSTREAM_UNAVAILABLE', 'Jira entegrasyonu yapılandırılmamış.');
      }

      const query = req.query as { projectKey?: string | string[]; jql?: string | string[] };
      const projectParam = Array.isArray(query.projectKey) ? query.projectKey[0] : query.projectKey;
      const envProject = process.env.JIRA_PROJECT_KEY;
      const projectKey = (projectParam ?? envProject ?? '').trim();
      if (!projectKey) {
        throw new HttpError(400, 'INVALID_REQUEST', 'projectKey parametresi zorunludur.');
      }

      const jqlParam = Array.isArray(query.jql) ? query.jql[0] : query.jql;
      const jql = jqlParam && jqlParam.trim().length > 0 ? jqlParam : undefined;

      const credentialsKey = `${baseUrl}::${token}`;
      const cacheKey = `${tenantId}:${credentialsKey}:${projectKey}:${jql ?? ''}`;
      const cached = changeRequestCache.get(cacheKey);
      const now = Date.now();
      const ttlSeconds = Math.floor(CHANGE_REQUEST_CACHE_TTL_MS / 1000);

      if (cached && cached.expiresAt > now) {
        const ifNoneMatch = req.headers['if-none-match'];
        const headerValues = Array.isArray(ifNoneMatch) ? ifNoneMatch : ifNoneMatch ? [ifNoneMatch] : [];
        const tokens = headerValues.flatMap((raw) =>
          raw
            .split(',')
            .map((entry: string) => entry.trim())
            .filter((entry: string) => entry.length > 0),
        );

        if (tokens.includes('*') || tokens.includes(cached.etag)) {
          res
            .status(304)
            .set('Cache-Control', `private, max-age=${ttlSeconds}`)
            .set('ETag', cached.etag)
            .end();
          return;
        }

        res
          .status(200)
          .set('Cache-Control', `private, max-age=${ttlSeconds}`)
          .set('ETag', cached.etag)
          .json(cached.payload);
        return;
      }

      let items: JiraChangeRequest[];
      try {
        items = await fetchJiraChangeRequests({
          baseUrl,
          projectKey,
          authToken: token,
          jql,
        });
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Bilinmeyen hata';
        throw new HttpError(502, 'JIRA_FETCH_FAILED', `Jira change request isteği başarısız: ${message}`);
      }

      const payload = { items, fetchedAt: new Date().toISOString() };
      const serialized = JSON.stringify(payload);
      const etag = `"${createHash('sha256').update(serialized).digest('hex')}"`;
      changeRequestCache.set(cacheKey, {
        payload,
        etag,
        expiresAt: now + CHANGE_REQUEST_CACHE_TTL_MS,
      });

      res
        .status(200)
        .set('Cache-Control', `private, max-age=${ttlSeconds}`)
        .set('ETag', etag)
        .json(payload);
    }),
  );

  app.get(
    '/v1/workspaces/:id/documents/:documentId',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId } = getAuthContext(req);
      const { id: workspaceId, documentId } = req.params as { id?: string; documentId?: string };
      if (!workspaceId || !documentId) {
        throw new HttpError(400, 'INVALID_REQUEST', 'Workspace ve belge kimliği belirtilmelidir.');
      }
      await ensureRole(req, ['reader', 'maintainer', 'admin']);

      const query = req.query as { cursor?: string | string[]; limit?: string | string[] };
      const cursorValue = Array.isArray(query.cursor) ? query.cursor[0] : query.cursor;
      const limitValue = Array.isArray(query.limit) ? query.limit[0] : query.limit;
      const cursor = cursorValue && cursorValue.trim().length > 0 ? cursorValue : undefined;
      let limit: number | undefined;
      if (limitValue !== undefined) {
        const parsed = Number.parseInt(limitValue, 10);
        if (!Number.isFinite(parsed) || parsed <= 0) {
          throw new HttpError(400, 'INVALID_REQUEST', 'limit parametresi pozitif bir tam sayı olmalıdır.');
        }
        limit = parsed;
      }

      try {
        const thread = await workspaceService.getDocumentThread(tenantId, workspaceId, documentId, {
          cursor: cursor ?? null,
          limit,
        });
        if (!thread) {
          throw new WorkspaceDocumentNotFoundError();
        }

        const etag = `"${thread.document.latestRevision.hash}"`;
        const ifNoneMatchHeader = req.headers['if-none-match'];
        const headerValues = Array.isArray(ifNoneMatchHeader)
          ? ifNoneMatchHeader
          : ifNoneMatchHeader
            ? [ifNoneMatchHeader]
            : [];
        const tokens = headerValues.flatMap((raw: string) => {
          const segments = raw.split(',').map((segment: string) => segment.trim());
          return segments.filter((segment: string) => segment.length > 0);
        });
        if (tokens.includes('*') || tokens.includes(etag)) {
          res.status(304).set('ETag', etag).end();
          return;
        }

        res
          .status(200)
          .set('ETag', etag)
          .json({
            document: toWorkspaceDocumentResponse(thread.document),
            comments: thread.comments.map((comment) => toWorkspaceCommentResponse(comment)),
            signoffs: thread.signoffs.map((signoff) => toWorkspaceSignoffResponse(signoff)),
            nextCursor: thread.nextCursor,
          });
      } catch (error) {
        handleWorkspaceError(error);
      }
    }),
  );

  app.put(
    '/v1/workspaces/:id/documents/:documentId',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId, subject } = getAuthContext(req);
      const { id: workspaceId, documentId } = req.params as { id?: string; documentId?: string };
      if (!workspaceId || !documentId) {
        throw new HttpError(400, 'INVALID_REQUEST', 'Workspace ve belge kimliği belirtilmelidir.');
      }
      await ensureRole(req, ['maintainer', 'admin']);
      const body = req.body as Record<string, unknown> | undefined;
      if (!body || typeof body !== 'object') {
        throw new HttpError(400, 'INVALID_REQUEST', 'Geçerli bir JSON gövdesi gereklidir.');
      }
      const kindRaw = body.kind;
      if (typeof kindRaw !== 'string' || !isWorkspaceKind(kindRaw)) {
        throw new HttpError(400, 'INVALID_REQUEST', 'kind alanı desteklenmeyen bir belge türü.');
      }
      const titleRaw = body.title;
      if (typeof titleRaw !== 'string' || titleRaw.trim().length === 0) {
        throw new HttpError(400, 'INVALID_REQUEST', 'title alanı zorunludur.');
      }
      if (!('content' in body)) {
        throw new HttpError(400, 'INVALID_REQUEST', 'content alanı zorunludur.');
      }
      const expectedHashRaw = body.expectedHash;
      let expectedHash: string | undefined;
      if (expectedHashRaw !== undefined && expectedHashRaw !== null) {
        if (typeof expectedHashRaw !== 'string' || expectedHashRaw.trim().length === 0) {
          throw new HttpError(400, 'INVALID_REQUEST', 'expectedHash metin olmalıdır.');
        }
        expectedHash = expectedHashRaw;
      }
      try {
        const document = await workspaceService.saveRevision({
          tenantId,
          workspaceId,
          documentId,
          kind: kindRaw,
          title: titleRaw,
          authorId: subject,
          content: (body as { content: unknown }).content,
          expectedHash: expectedHash ?? null,
        });
        res.json({ document: toWorkspaceDocumentResponse(document) });
      } catch (error) {
        handleWorkspaceError(error);
      }
    }),
  );

  app.post(
    '/v1/workspaces/:id/documents/:documentId/comments',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId, subject } = getAuthContext(req);
      const { id: workspaceId, documentId } = req.params as { id?: string; documentId?: string };
      if (!workspaceId || !documentId) {
        throw new HttpError(400, 'INVALID_REQUEST', 'Workspace ve belge kimliği belirtilmelidir.');
      }
      await ensureRole(req, ['reader', 'maintainer', 'admin']);
      const body = req.body as Record<string, unknown> | undefined;
      if (!body || typeof body !== 'object') {
        throw new HttpError(400, 'INVALID_REQUEST', 'Geçerli bir JSON gövdesi gereklidir.');
      }
      const messageRaw = body.body;
      if (typeof messageRaw !== 'string' || messageRaw.trim().length === 0) {
        throw new HttpError(400, 'INVALID_REQUEST', 'body alanı zorunludur.');
      }
      const revisionIdRaw = body.revisionId;
      const revisionHashRaw = body.revisionHash;
      const revisionId = typeof revisionIdRaw === 'string' && revisionIdRaw.trim().length > 0 ? revisionIdRaw : undefined;
      const revisionHash =
        typeof revisionHashRaw === 'string' && revisionHashRaw.trim().length > 0 ? revisionHashRaw : undefined;
      try {
        const comment = await workspaceService.addComment({
          tenantId,
          workspaceId,
          documentId,
          authorId: subject,
          body: messageRaw,
          revisionId,
          revisionHash,
        });
        res.status(201).json({ comment: toWorkspaceCommentResponse(comment) });
      } catch (error) {
        handleWorkspaceError(error);
      }
    }),
  );

  app.post(
    '/v1/workspaces/:id/signoffs',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId, subject } = getAuthContext(req);
      const { id: workspaceId } = req.params as { id?: string };
      if (!workspaceId) {
        throw new HttpError(400, 'INVALID_REQUEST', 'Workspace kimliği belirtilmelidir.');
      }
      await ensureRole(req, ['maintainer', 'admin']);
      const body = req.body as Record<string, unknown> | undefined;
      if (!body || typeof body !== 'object') {
        throw new HttpError(400, 'INVALID_REQUEST', 'Geçerli bir JSON gövdesi gereklidir.');
      }
      const documentIdRaw = body.documentId;
      if (typeof documentIdRaw !== 'string' || documentIdRaw.trim().length === 0) {
        throw new HttpError(400, 'INVALID_REQUEST', 'documentId alanı zorunludur.');
      }
      const revisionHashRaw = body.revisionHash;
      if (typeof revisionHashRaw !== 'string' || revisionHashRaw.trim().length === 0) {
        throw new HttpError(400, 'INVALID_REQUEST', 'revisionHash alanı zorunludur.');
      }
      const requestedForRaw = body.requestedFor;
      if (typeof requestedForRaw !== 'string' || requestedForRaw.trim().length === 0) {
        throw new HttpError(400, 'INVALID_REQUEST', 'requestedFor alanı zorunludur.');
      }
      try {
        const signoff = await workspaceService.requestSignoff({
          tenantId,
          workspaceId,
          documentId: documentIdRaw,
          revisionHash: revisionHashRaw,
          requestedBy: subject,
          requestedFor: requestedForRaw,
        });
        res.status(201).json({ signoff: toWorkspaceSignoffResponse(signoff) });
      } catch (error) {
        handleWorkspaceError(error);
      }
    }),
  );

  app.patch(
    '/v1/workspaces/:id/signoffs/:signoffId',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId, subject } = getAuthContext(req);
      const { id: workspaceId, signoffId } = req.params as { id?: string; signoffId?: string };
      if (!workspaceId || !signoffId) {
        throw new HttpError(400, 'INVALID_REQUEST', 'Workspace ve signoff kimliği belirtilmelidir.');
      }
      const principal = await ensureRole(req, ['maintainer', 'admin']);
      const body = req.body as Record<string, unknown> | undefined;
      if (!body || typeof body !== 'object') {
        throw new HttpError(400, 'INVALID_REQUEST', 'Geçerli bir JSON gövdesi gereklidir.');
      }
      const actionRaw = body.action;
      if (typeof actionRaw !== 'string' || actionRaw.trim() !== 'approve') {
        throw new HttpError(400, 'INVALID_REQUEST', 'action alanı desteklenmiyor.');
      }
      const expectedHashRaw = body.expectedRevisionHash;
      if (typeof expectedHashRaw !== 'string' || expectedHashRaw.trim().length === 0) {
        throw new HttpError(400, 'INVALID_REQUEST', 'expectedRevisionHash alanı zorunludur.');
      }
      const publicKeyRaw = body.publicKey;
      if (typeof publicKeyRaw !== 'string' || publicKeyRaw.trim().length === 0) {
        throw new HttpError(400, 'INVALID_REQUEST', 'publicKey alanı zorunludur.');
      }
      const signatureRaw = body.signature;
      if (typeof signatureRaw !== 'string' || signatureRaw.trim().length === 0) {
        throw new HttpError(400, 'INVALID_REQUEST', 'signature alanı zorunludur.');
      }
      const signedAtRaw = body.signedAt;
      if (typeof signedAtRaw !== 'string' || signedAtRaw.trim().length === 0) {
        throw new HttpError(400, 'INVALID_REQUEST', 'signedAt alanı zorunludur.');
      }
      try {
        const signoff = await workspaceService.approveSignoff({
          tenantId,
          workspaceId,
          signoffId,
          actorId: subject,
          expectedRevisionHash: expectedHashRaw,
          publicKey: publicKeyRaw,
          signature: signatureRaw,
          signedAt: signedAtRaw,
          allowBypass: principal.roles.includes('admin'),
        });
        res.json({ signoff: toWorkspaceSignoffResponse(signoff) });
      } catch (error) {
        handleWorkspaceError(error);
      }
    }),
  );

  app.post(
    '/v1/reviews',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId, subject } = getAuthContext(req);
      const body = req.body as Record<string, unknown> | undefined;
      if (!body || typeof body !== 'object') {
        throw new HttpError(400, 'INVALID_REQUEST', 'Geçerli bir JSON gövdesi gereklidir.');
      }

      const target = parseReviewTarget(body.target);
      const approvers = parseReviewApprovers(body.approvers);
      const requiredArtifacts = parseReviewArtifacts(body.requiredArtifacts);
      let notes: string | null | undefined;
      if (body.notes !== undefined) {
        if (body.notes === null) {
          notes = null;
        } else if (typeof body.notes === 'string') {
          notes = body.notes;
        } else {
          throw new HttpError(400, 'INVALID_REQUEST', 'notes alanı metin olmalıdır.');
        }
      }

      try {
        const review = await reviewStore.createReview({
          tenantId,
          authorId: subject,
          target: target ?? { kind: 'analyze', reference: null },
          approvers,
          requiredArtifacts,
          notes: notes ?? null,
        });
        res.status(201).json({ review: toReviewResponse(review) });
      } catch (error) {
        handleReviewError(error);
      }
    }),
  );

  app.patch(
    '/v1/reviews/:id',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId, subject } = getAuthContext(req);
      const { id } = req.params as { id?: string };
      if (!id) {
        throw new HttpError(400, 'INVALID_REQUEST', 'Review kimliği belirtilmelidir.');
      }
      const body = req.body as Record<string, unknown> | undefined;
      if (!body || typeof body !== 'object') {
        throw new HttpError(400, 'INVALID_REQUEST', 'Geçerli bir JSON gövdesi gereklidir.');
      }
      const actionRaw = body.action;
      if (typeof actionRaw !== 'string' || actionRaw.trim().length === 0) {
        throw new HttpError(400, 'INVALID_REQUEST', 'action alanı zorunludur.');
      }
      const expectedHashRaw = body.expectedHash;
      if (typeof expectedHashRaw !== 'string' || expectedHashRaw.trim().length === 0) {
        throw new HttpError(400, 'INVALID_REQUEST', 'expectedHash alanı zorunludur.');
      }
      const expectedHash = expectedHashRaw;
      const action = actionRaw.trim();

      try {
        let review: Review;
        switch (action) {
          case 'configure': {
            const target = parseReviewTarget(body.target);
            const approvers = parseReviewApprovers(body.approvers);
            const requiredArtifacts = parseReviewArtifacts(body.requiredArtifacts);
            let notes: string | null | undefined;
            if (body.notes !== undefined) {
              if (body.notes === null) {
                notes = null;
              } else if (typeof body.notes === 'string') {
                notes = body.notes;
              } else {
                throw new HttpError(400, 'INVALID_REQUEST', 'notes alanı metin olmalıdır.');
              }
            }
            review = await reviewStore.updateConfiguration({
              tenantId,
              reviewId: id,
              expectedHash,
              target,
              approvers,
              requiredArtifacts,
              notes,
            });
            break;
          }
          case 'submit': {
            review = await reviewStore.submitReview({
              tenantId,
              reviewId: id,
              expectedHash,
              actorId: subject,
            });
            break;
          }
          case 'approve': {
            let note: string | null | undefined;
            if (body.note !== undefined) {
              if (body.note === null) {
                note = null;
              } else if (typeof body.note === 'string') {
                note = body.note;
              } else {
                throw new HttpError(400, 'INVALID_REQUEST', 'note alanı metin olmalıdır.');
              }
            }
            review = await reviewStore.approveReview({
              tenantId,
              reviewId: id,
              expectedHash,
              approverId: subject,
              note: note ?? null,
            });
            break;
          }
          case 'reject': {
            const reasonRaw = body.reason;
            if (typeof reasonRaw !== 'string' || reasonRaw.trim().length === 0) {
              throw new HttpError(400, 'INVALID_REQUEST', 'reason alanı zorunludur.');
            }
            review = await reviewStore.rejectReview({
              tenantId,
              reviewId: id,
              expectedHash,
              approverId: subject,
              reason: reasonRaw,
            });
            break;
          }
          default:
            throw new HttpError(400, 'INVALID_REQUEST', 'action alanı desteklenmiyor.');
        }
        res.json({ review: toReviewResponse(review) });
      } catch (error) {
        handleReviewError(error);
      }
    }),
  );

  app.get(
    '/api/audit-logs',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId: contextTenantId } = getAuthContext(req);
      const query = req.query as Record<string, unknown>;
      const tenantParam = typeof query.tenantId === 'string' ? query.tenantId.trim() : '';
      const tenantId = tenantParam.length > 0 ? tenantParam : contextTenantId;
      if (tenantId !== contextTenantId) {
        ensureAdminScope(req);
      }

      const options: AuditLogQueryOptions = { tenantId };

      const actor = typeof query.actor === 'string' ? query.actor.trim() : '';
      if (actor) {
        options.actor = actor;
      }
      const action = typeof query.action === 'string' ? query.action.trim() : '';
      if (action) {
        options.action = action;
      }
      const target = typeof query.target === 'string' ? query.target.trim() : '';
      if (target) {
        options.target = target;
      }
      const since = typeof query.since === 'string' ? query.since.trim() : '';
      if (since) {
        options.since = since;
      }
      const until = typeof query.until === 'string' ? query.until.trim() : '';
      if (until) {
        options.until = until;
      }

      const order = typeof query.order === 'string' ? query.order.trim().toLowerCase() : '';
      if (order === 'asc' || order === 'desc') {
        options.order = order;
      }

      const limitRaw = typeof query.limit === 'string' ? query.limit.trim() : '';
      if (limitRaw) {
        const parsed = Number.parseInt(limitRaw, 10);
        if (Number.isFinite(parsed)) {
          options.limit = parsed;
        }
      }
      const offsetRaw = typeof query.offset === 'string' ? query.offset.trim() : '';
      if (offsetRaw) {
        const parsed = Number.parseInt(offsetRaw, 10);
        if (Number.isFinite(parsed)) {
          options.offset = parsed;
        }
      }

      const result = await auditLogStore.query(options);
      res.json({
        items: result.items.map((item) => ({
          id: item.id,
          tenantId: item.tenantId,
          actor: item.actor,
          action: item.action,
          target: item.target ?? null,
          payload: item.payload ?? null,
          createdAt: item.createdAt.toISOString(),
        })),
        hasMore: result.hasMore,
        nextOffset: result.nextOffset ?? null,
      });
    }),
  );

  app.get(
    '/v1/jobs',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId, subject } = getAuthContext(req);
      const kinds = parseFilterParam<JobKind>(req.query.kind as unknown, JOB_KINDS, 'İş türü');
      const statuses = parseFilterParam<JobStatus>(
        req.query.status as unknown,
        JOB_STATUSES,
        'İş durumu',
      );
      await ensureJobsRestored();
      const jobs = (await jobStore.listJobs(tenantId))
        .filter((job) => jobMatchesFilters(job, kinds, statuses))
        .map(serializeJobSummary);
      res.json({ jobs });
    }),
  );

  app.get(
    '/v1/jobs/:id(*)',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId, subject } = getAuthContext(req);
      const { id } = req.params as { id?: string };
      if (!id) {
        throw new HttpError(400, 'INVALID_REQUEST', 'İş kimliği belirtilmelidir.');
      }
      assertJobId(id);
      await ensureJobsRestored();
      const job =
        (await jobStore.findJob(tenantId, id)) ??
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
      const { tenantId, subject } = getAuthContext(req);
      const { manifestId } = req.params as { manifestId?: string };
      if (!manifestId) {
        throw new HttpError(400, 'INVALID_REQUEST', 'manifestId belirtilmelidir.');
      }
      if (!/^[A-Za-z0-9._-]+$/.test(manifestId)) {
        throw new HttpError(400, 'INVALID_REQUEST', 'manifestId değeri geçerli değil.');
      }

      const { metadata, manifest } = await resolveManifestRecord(
        storage,
        directories,
        tenantId,
        manifestId,
      );
      res.json({
        manifestId: metadata.outputs.manifestId,
        jobId: metadata.id,
        manifest,
        ...(metadata.outputs.cmsSignature
          ? {
              cmsSignature: {
                ...metadata.outputs.cmsSignature,
                path: storage.toRelativePath(metadata.outputs.cmsSignature.path),
                signerSerialNumber: metadata.outputs.cmsSignature.signerSerialNumber ?? null,
                signerIssuer: metadata.outputs.cmsSignature.signerIssuer ?? null,
                signerSubject: metadata.outputs.cmsSignature.signerSubject ?? null,
                signatureAlgorithm: metadata.outputs.cmsSignature.signatureAlgorithm ?? null,
              },
            }
          : {}),
      });
    }),
  );

  app.get(
    '/v1/manifests/:manifestId/proofs',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId } = getAuthContext(req);
      await ensureRole(req, ['reader', 'maintainer', 'admin']);
      const { manifestId } = req.params as { manifestId?: string };
      if (!manifestId) {
        throw new HttpError(400, 'INVALID_REQUEST', 'manifestId belirtilmelidir.');
      }
      if (!/^[A-Za-z0-9._-]+$/.test(manifestId)) {
        throw new HttpError(400, 'INVALID_REQUEST', 'manifestId değeri geçerli değil.');
      }

      const { metadata, manifest } = await resolveManifestRecord(
        storage,
        directories,
        tenantId,
        manifestId,
      );

      let evaluation;
      try {
        evaluation = evaluateManifestProofs(manifest);
      } catch (error) {
        const message = error instanceof Error ? error.message : 'bilinmeyen';
        throw new HttpError(500, 'PROOF_INVALID', `Manifest kanıtları doğrulanamadı: ${message}`);
      }

      res.json({
        manifestId: metadata.outputs.manifestId,
        jobId: metadata.id,
        merkle: evaluation.merkle,
        files: evaluation.files.map(({ file, verified }) => ({
          path: file.path,
          sha256: file.sha256,
          proof: file.proof ?? null,
          verified,
        })),
      });
    }),
  );

  app.get(
    '/v1/manifests/:manifestId/proofs/:filePath(*)',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId } = getAuthContext(req);
      await ensureRole(req, ['reader', 'maintainer', 'admin']);
      const { manifestId, filePath } = req.params as { manifestId?: string; filePath?: string };
      if (!manifestId) {
        throw new HttpError(400, 'INVALID_REQUEST', 'manifestId belirtilmelidir.');
      }
      if (!/^[A-Za-z0-9._-]+$/.test(manifestId)) {
        throw new HttpError(400, 'INVALID_REQUEST', 'manifestId değeri geçerli değil.');
      }
      if (!filePath || filePath.trim().length === 0) {
        throw new HttpError(400, 'INVALID_REQUEST', 'Dosya yolu belirtilmelidir.');
      }

      const { metadata, manifest } = await resolveManifestRecord(
        storage,
        directories,
        tenantId,
        manifestId,
      );

      const entry = manifest.files.find((file) => file.path === filePath);
      if (!entry) {
        throw new HttpError(404, 'MANIFEST_FILE_NOT_FOUND', 'İstenen dosya manifestte bulunamadı.');
      }
      if (!entry.proof) {
        throw new HttpError(404, 'PROOF_NOT_AVAILABLE', 'İstenen dosya için Merkle kanıtı bulunamadı.');
      }

      const merkleRoot = manifest.merkle?.root;
      if (!merkleRoot) {
        throw new HttpError(500, 'PROOF_INVALID', 'Manifest Merkle kökü eksik.');
      }

      try {
        const parsed = deserializeLedgerProof(entry.proof.proof);
        verifyLedgerProof(parsed, { expectedMerkleRoot: merkleRoot });
      } catch (error) {
        const message = error instanceof Error ? error.message : 'bilinmeyen';
        throw new HttpError(500, 'PROOF_INVALID', `Merkle kanıtı doğrulanamadı: ${message}`);
      }

      res.json({
        manifestId: metadata.outputs.manifestId,
        jobId: metadata.id,
        path: entry.path,
        sha256: entry.sha256,
        proof: entry.proof,
        merkle: manifest.merkle ?? null,
        verified: true,
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

  app.get(
    '/v1/packages/:id(*)/manifest.cms',
    requireAuth,
    createPackageStreamHandler(
      (metadata) => metadata.outputs?.cmsSignature?.path,
      'MANIFEST_NOT_FOUND',
      'PKCS#7 imza dosyası bulunamadı.',
      { contentType: 'application/pkcs7-signature', fallbackName: 'manifest.cms' },
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
      const { tenantId, subject } = getAuthContext(req);
      const { id } = req.params as { id?: string };
      if (!id) {
        throw new HttpError(400, 'INVALID_REQUEST', 'İş kimliği belirtilmelidir.');
      }
      assertJobId(id);

      await ensureJobsRestored();
      const job = await jobStore.findJob(tenantId, id);
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

      const removed = queue.remove(tenantId, id);
      await jobStore.deleteJob(tenantId, id);
      const kind = removed?.kind ?? job.kind;
      await removeJobArtifacts(storage, directories, tenantId, id, kind);
      jobLicenses.delete(createScopedJobKey(tenantId, id));
      await updateQueueDepth(tenantId);

      await appendAuditLog({
        tenantId,
        actor: subject,
        action: 'job.cancelled',
        target: toJobTarget(id),
        payload: { kind },
      });

      res.json({ status: 'cancelled', id, kind });
    }),
  );

  app.delete(
    '/v1/jobs/:id(*)',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId, subject } = getAuthContext(req);
      const { id } = req.params as { id?: string };
      if (!id) {
        throw new HttpError(400, 'INVALID_REQUEST', 'İş kimliği belirtilmelidir.');
      }
      assertJobId(id);

      await ensureJobsRestored();
      let job = await jobStore.findJob(tenantId, id);
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

      const removed = queue.remove(tenantId, id);
      await jobStore.deleteJob(tenantId, id);
      const kind = removed?.kind ?? job.kind;
      await removeJobArtifacts(storage, directories, tenantId, id, kind);
      jobLicenses.delete(createScopedJobKey(tenantId, id));
      await updateQueueDepth(tenantId);

      await appendAuditLog({
        tenantId,
        actor: subject,
        action: 'job.deleted',
        target: toJobTarget(id),
        payload: { kind },
      });

      res.json({ status: 'deleted', id, kind });
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
    { name: 'designCsv', maxCount: 1 },
    { name: 'jiraDefects', maxCount: 25 },
    { name: 'polyspace', maxCount: 1 },
    { name: 'ldra', maxCount: 1 },
    { name: 'vectorcast', maxCount: 1 },
    { name: 'qaLogs', maxCount: 25 },
  ]);

  const reportFields = upload.fields([
    { name: LICENSE_FILE_FIELD, maxCount: 1 },
    { name: 'planConfig', maxCount: 1 },
  ]);

  app.post(
    '/v1/import',
    requireAuth,
    importFields,
    createAsyncHandler(async (req, res) => {
      const { tenantId, subject } = getAuthContext(req);
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

        const independentSources = parseStringArrayField(
          body.independentSources,
          'independentSources',
        );
        const independentArtifacts = parseStringArrayField(
          body.independentArtifacts,
          'independentArtifacts',
        );

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

        if (independentSources) {
          hashEntries.push({
            key: 'field:independentSources',
            value: JSON.stringify(independentSources),
          });
        }
        if (independentArtifacts) {
          hashEntries.push({
            key: 'field:independentArtifacts',
            value: JSON.stringify(independentArtifacts),
          });
        }

        const hash = computeHash(hashEntries);
        const importId = createJobId(hash);
        const workspaceDir = path.join(directories.workspaces, tenantId, importId);
        const metadataPath = path.join(workspaceDir, METADATA_FILE);

        await ensureJobsRestored();
        const existingJob = await jobStore.findJob<ImportJobResult>(tenantId, importId);
        if (existingJob) {
          ensureJobLicense(tenantId, importId, license);
          await appendAuditLog({
            tenantId,
            actor: subject,
            action: 'license.revalidated',
            target: toJobTarget(existingJob.id),
            payload: toLicenseAuditPayload(license),
          });
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
          await appendAuditLog({
            tenantId,
            actor: subject,
            action: 'license.revalidated',
            target: toJobTarget(metadata.id),
            payload: toLicenseAuditPayload(license),
          });
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
          const job = await enqueueObservedJob<ImportJobResult, ImportJobPayload>({
            tenantId,
            actor: subject,
            id: importId,
            kind: 'import',
            hash,
            payload: {
              workspaceDir,
              uploads: persistedUploads,
              level: level ?? null,
              projectName: stringFields.projectName ?? null,
              projectVersion: stringFields.projectVersion ?? null,
              independentSources: independentSources ?? null,
              independentArtifacts: independentArtifacts ?? null,
              license: toLicenseMetadata(license),
            },
          });

          registerJobLicense(tenantId, importId, license);
          await appendAuditLog({
            tenantId,
            actor: subject,
            action: 'license.attached',
            target: toJobTarget(importId),
            payload: toLicenseAuditPayload(license),
          });
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
      const { tenantId, subject } = getAuthContext(req);
      const license = await requireLicenseToken(req);
      requireLicenseFeature(license, PIPELINE_LICENSE_FEATURES.analyze);
      const body = req.body as {
        importId?: string;
        level?: string;
        projectName?: string;
        projectVersion?: string;
        reviewId?: string;
      };

      if (!body.importId) {
        throw new HttpError(400, 'INVALID_REQUEST', 'importId alanı zorunludur.');
      }

      assertJobId(body.importId);

      await requireApprovedReviewForRequest(req, body.reviewId, 'analyze', body.importId);

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

      await ensureJobsRestored();
      const existingJob = await jobStore.findJob<AnalyzeJobResult>(tenantId, analyzeId);
      if (existingJob) {
        ensureJobLicense(tenantId, analyzeId, license);
        await appendAuditLog({
          tenantId,
          actor: subject,
          action: 'license.revalidated',
          target: toJobTarget(existingJob.id),
          payload: toLicenseAuditPayload(license),
        });
        sendJobResponse(res, existingJob, tenantId, {
          reused: existingJob.status === 'completed',
        });
        return;
      }

      if (await storage.fileExists(metadataPath)) {
        const metadata = await readJobMetadata<AnalyzeJobMetadata>(storage, analysisDir);
        hydrateJobLicense(metadata, tenantId);
        ensureJobLicense(tenantId, metadata.id, license);
        await appendAuditLog({
          tenantId,
          actor: subject,
          action: 'license.revalidated',
          target: toJobTarget(metadata.id),
          payload: toLicenseAuditPayload(license),
        });
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

      const job = await enqueueObservedJob<AnalyzeJobResult, AnalyzeJobPayload>({
        tenantId,
        actor: subject,
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
      await appendAuditLog({
        tenantId,
        actor: subject,
        action: 'license.attached',
        target: toJobTarget(analyzeId),
        payload: toLicenseAuditPayload(license),
      });
      sendJobResponse(res, job, tenantId);
    }),
  );

  app.post(
    '/v1/report',
    requireAuth,
    reportFields,
    createAsyncHandler(async (req, res) => {
      const { tenantId, subject } = getAuthContext(req);
      const fileMap = (req.files as FileMap) ?? {};
      let cleaned = false;
      const ensureCleanup = async () => {
        if (!cleaned) {
          cleaned = true;
          await cleanupUploadedFiles(fileMap);
        }
      };

      let reportId: string | undefined;
      let planConfigPath: string | undefined;

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
      requireLicenseFeature(license, PIPELINE_LICENSE_FEATURES.report);
      const body = req.body as {
        analysisId?: string;
        manifestId?: string;
        reviewId?: string;
        soiStage?: string;
        planOverrides?: unknown;
      };
      if (!body.analysisId) {
        throw new HttpError(400, 'INVALID_REQUEST', 'analysisId alanı zorunludur.');
      }

      assertJobId(body.analysisId);

      await requireApprovedReviewForRequest(req, body.reviewId, 'report', body.analysisId);

      const analysisDir = path.join(directories.analyses, tenantId, body.analysisId);
      await assertDirectoryExists(storage, analysisDir, 'Analiz çıktısı');

      const soiStage = parseSoiStage(body.soiStage);

        const planOverrides = parseJsonObjectField(body.planOverrides, 'planOverrides');
        const planConfigUploads = fileMap.planConfig ?? [];

      const hashEntries: HashEntry[] = [
        { key: 'analysisId', value: body.analysisId },
        { key: 'soiStage', value: soiStage ?? '' },
      ];
      if (body.manifestId) {
        hashEntries.push({ key: 'manifestId', value: body.manifestId });
      }
        if (planOverrides) {
          hashEntries.push({ key: 'planOverrides', value: toStableJson(planOverrides) });
        }
        const hash = computeHash(hashEntries);
        reportId = createJobId(hash);
        const reportDir = buildStageScopedDirectory(directories.reports, tenantId, reportId, soiStage);
        const metadataPath = path.join(reportDir, METADATA_FILE);

      await ensureJobsRestored();
      const existingJob = await jobStore.findJob<ReportJobResult>(tenantId, reportId);
      if (existingJob) {
        ensureJobLicense(tenantId, reportId, license);
        await appendAuditLog({
          tenantId,
          actor: subject,
          action: 'license.revalidated',
          target: toJobTarget(existingJob.id),
          payload: toLicenseAuditPayload(license),
        });
        await ensureCleanup();
        sendJobResponse(res, existingJob, tenantId, {
          reused: existingJob.status === 'completed',
        });
        return;
      }

      if (await storage.fileExists(metadataPath)) {
        const metadata = await readJobMetadata<ReportJobMetadata>(storage, reportDir);
        hydrateJobLicense(metadata, tenantId);
        ensureJobLicense(tenantId, metadata.id, license);
        await appendAuditLog({
          tenantId,
          actor: subject,
          action: 'license.revalidated',
          target: toJobTarget(metadata.id),
          payload: toLicenseAuditPayload(license),
        });
        const adopted = adoptJobFromMetadata(
          storage,
          queue,
          metadata,
        ) as JobDetails<ReportJobResult>;
        await ensureCleanup();
        sendJobResponse(res, adopted, tenantId, { reused: true });
        return;
      }

      const reportOptions: StageAwareReportOptions = {
        input: analysisDir,
        output: reportDir,
        manifestId: body.manifestId,
        ...(soiStage ? { soiStage } : {}),
      };

        if (planConfigUploads.length > 0) {
          const planConfigMap: FileMap = { planConfig: planConfigUploads };
          try {
            const persisted = await storage.persistUploads(
              path.join(tenantId, reportId),
              convertFileMap(planConfigMap),
            );
            planConfigPath = persisted.planConfig?.[0];
          } catch (error) {
            await ensureCleanup();
            throw error;
          }
        }

        if (planConfigPath) {
          reportOptions.planConfig = planConfigPath;
        }
        if (planOverrides) {
          reportOptions.planOverrides = planOverrides;
        }

      const job = await enqueueObservedJob<ReportJobResult, ReportJobPayload>({
        tenantId,
        actor: subject,
        id: reportId,
        kind: 'report',
        hash,
        payload: {
          analysisDir,
          reportDir,
          reportOptions,
          analysisId: body.analysisId,
          manifestId: body.manifestId ?? null,
          soiStage: soiStage ?? null,
          planConfigPath: planConfigPath ?? null,
          planOverrides: planOverrides ?? null,
          license: toLicenseMetadata(license),
        },
      });

      registerJobLicense(tenantId, reportId, license);
      await appendAuditLog({
        tenantId,
        actor: subject,
        action: 'license.attached',
        target: toJobTarget(reportId),
        payload: toLicenseAuditPayload(license),
      });
        await ensureCleanup();
        sendJobResponse(res, job, tenantId);
      } catch (error) {
        await ensureCleanup();
        if (reportId && planConfigPath) {
          await storage
            .removeDirectory(path.join(directories.uploads, tenantId, reportId))
            .catch(() => undefined);
        }
        throw error;
      }
    }),
  );

  app.post(
    '/v1/pack',
    requireAuth,
    createAsyncHandler(async (req, res) => {
      const { tenantId, subject } = getAuthContext(req);
      const license = await requireLicenseToken(req);
      requireLicenseFeature(license, PIPELINE_LICENSE_FEATURES.pack);
      const body = req.body as {
        reportId?: string;
        packageName?: string;
        reviewId?: string;
        soiStage?: string;
        postQuantum?: unknown;
      };
      if (!body.reportId) {
        throw new HttpError(400, 'INVALID_REQUEST', 'reportId alanı zorunludur.');
      }

      assertJobId(body.reportId);

      await requireApprovedReviewForRequest(req, body.reviewId, 'pack', body.reportId);

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

      const requestedStage = parseSoiStage(body.soiStage);
      const postQuantumOptions = parsePackPostQuantumOptions(body.postQuantum);
      const resolvedReportDir = await findStageAwareJobDirectory(
        storage,
        directories.reports,
        tenantId,
        body.reportId,
        requestedStage,
      );
      if (!resolvedReportDir) {
        throw new HttpError(404, 'NOT_FOUND', 'Rapor çıktısı bulunamadı.');
      }

      const reportMetadata = await readJobMetadata<ReportJobMetadata>(storage, resolvedReportDir).catch(() =>
        undefined,
      );
      const derivedStage = (() => {
        const tenantBase = path.join(directories.reports, tenantId);
        const relative = path.relative(tenantBase, resolvedReportDir);
        const segments = relative.split(path.sep).filter((segment) => segment.length > 0);
        if (segments.length === 2) {
          const [stageCandidate] = segments;
          if (stageCandidate && isSoiStage(stageCandidate)) {
            return stageCandidate;
          }
        }
        return null;
      })();
      const metadataStage = (() => {
        if (!reportMetadata) {
          return derivedStage;
        }
        const stageValue = reportMetadata.params?.soiStage;
        return typeof stageValue === 'string' && isSoiStage(stageValue) ? stageValue : derivedStage;
      })();
      const effectiveStage = requestedStage ?? metadataStage ?? null;

      const hashEntries: HashEntry[] = [
        { key: 'reportId', value: body.reportId },
        { key: 'packageName', value: packageName ?? '' },
        { key: 'soiStage', value: effectiveStage ?? '' },
      ];
      if (postQuantumOptions !== undefined) {
        if (postQuantumOptions === false) {
          hashEntries.push({ key: 'postQuantum', value: 'false' });
        } else {
          const fingerprint = toStableJson({
            algorithm: postQuantumOptions.algorithm ?? null,
            privateKey:
              postQuantumOptions.privateKey !== undefined
                ? createHash('sha256').update(postQuantumOptions.privateKey).digest('hex')
                : undefined,
            privateKeyPath: postQuantumOptions.privateKeyPath ?? null,
            publicKey:
              postQuantumOptions.publicKey !== undefined
                ? createHash('sha256').update(postQuantumOptions.publicKey).digest('hex')
                : undefined,
            publicKeyPath: postQuantumOptions.publicKeyPath ?? null,
          });
          hashEntries.push({ key: 'postQuantum', value: fingerprint });
        }
      }
      const hash = computeHash(hashEntries);
      const packId = createJobId(hash);
      const reportDir = resolvedReportDir;
      const packageDir = buildStageScopedDirectory(directories.packages, tenantId, packId, effectiveStage);
      const metadataPath = path.join(packageDir, METADATA_FILE);

      await ensureJobsRestored();
      const existingJob = await jobStore.findJob<PackJobResult>(tenantId, packId);
      if (existingJob) {
        ensureJobLicense(tenantId, packId, license);
        await appendAuditLog({
          tenantId,
          actor: subject,
          action: 'license.revalidated',
          target: toJobTarget(existingJob.id),
          payload: toLicenseAuditPayload(license),
        });
        sendJobResponse(res, existingJob, tenantId, {
          reused: existingJob.status === 'completed',
        });
        return;
      }

      if (await storage.fileExists(metadataPath)) {
        const metadata = await readJobMetadata<PackJobMetadata>(storage, packageDir);
        hydrateJobLicense(metadata, tenantId);
        ensureJobLicense(tenantId, metadata.id, license);
        await appendAuditLog({
          tenantId,
          actor: subject,
          action: 'license.revalidated',
          target: toJobTarget(metadata.id),
          payload: toLicenseAuditPayload(license),
        });
        const adopted = adoptJobFromMetadata(storage, queue, metadata) as JobDetails<PackJobResult>;
        sendJobResponse(res, adopted, tenantId, { reused: true });
        return;
      }

      const job = await enqueueObservedJob<PackJobResult, PackJobPayload>({
        tenantId,
        actor: subject,
        id: packId,
        kind: 'pack',
        hash,
        payload: {
          reportDir,
          packageDir,
          packageName,
          signingKeyPath,
          reportId: body.reportId,
          soiStage: effectiveStage,
          ...(postQuantumOptions !== undefined ? { postQuantum: postQuantumOptions } : {}),
          license: toLicenseMetadata(license),
        },
      });

      registerJobLicense(tenantId, packId, license);
      await appendAuditLog({
        tenantId,
        actor: subject,
        action: 'license.attached',
        target: toJobTarget(packId),
        payload: toLicenseAuditPayload(license),
      });
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

      const reportDir = await findStageAwareJobDirectory(storage, directories.reports, tenantId, id);
      if (!reportDir) {
        throw new HttpError(404, 'NOT_FOUND', 'İstenen rapor bulunamadı.');
      }

      const metadataPath = path.join(reportDir, METADATA_FILE);
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
      events.closeAll();
    },
    runTenantRetention: (tenantId: string) => runTenantRetention(tenantId, 'manual'),
    runAllTenantRetention: () => runAllTenantRetention('manual'),
    logger,
    events,
  };

  Reflect.set(app, SERVER_CONTEXT_SYMBOL, lifecycle);

  return app;
};
