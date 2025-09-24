import fs from 'fs';
import path from 'path';
import process from 'process';

import dotenv from 'dotenv';
import type { JSONWebKeySet } from 'jose';

import { DatabaseManager } from './database';
import { createCommandScanner } from './scanner';
import type { FileScanner } from './scanner';

import {
  JwtAuthConfig,
  LicenseCacheConfig,
  LicenseLimitsConfig,
  RateLimitConfig,
  RetentionConfig,
  RetentionSchedulerConfig,
  createHttpsServer,
  createServer,
  getServerLifecycle,
} from './index';

dotenv.config();

const DEFAULT_IP_RATE_LIMIT_WINDOW_MS = 60_000;
const DEFAULT_IP_RATE_LIMIT_MAX = 300;
const DEFAULT_TENANT_RATE_LIMIT_WINDOW_MS = 60_000;
const DEFAULT_TENANT_RATE_LIMIT_MAX = 150;

export const resolveSigningKeyPath = async (): Promise<string> => {
  const signingKeyPathSource = process.env.SOIPACK_SIGNING_KEY_PATH;
  if (!signingKeyPathSource) {
    // eslint-disable-next-line no-console
    console.error('SOIPACK_SIGNING_KEY_PATH ortam değişkeni tanımlanmalıdır.');
    process.exit(1);
  }

  const signingKeyPath = path.resolve(signingKeyPathSource);

  try {
    await fs.promises.access(signingKeyPath, fs.constants.R_OK);
  } catch {
    // eslint-disable-next-line no-console
    console.error(`SOIPACK_SIGNING_KEY_PATH ile belirtilen anahtar dosyasına erişilemiyor: ${signingKeyPath}`);
    process.exit(1);
  }

  return signingKeyPath;
};

const parseRetentionDays = (value: string | undefined, label: string): number | undefined => {
  if (!value) {
    return undefined;
  }
  const parsed = Number.parseFloat(value);
  if (!Number.isFinite(parsed) || parsed < 0) {
    // eslint-disable-next-line no-console
    console.error(`${label} değeri sıfır veya pozitif bir sayı olmalıdır.`);
    process.exit(1);
  }
  return parsed * 24 * 60 * 60 * 1000;
};

const parsePositiveInteger = (value: string, label: string): number => {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    // eslint-disable-next-line no-console
    console.error(`${label} pozitif bir tam sayı olmalıdır.`);
    process.exit(1);
  }
  return parsed;
};

const parseNonNegativeInteger = (value: string, label: string): number => {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed < 0) {
    // eslint-disable-next-line no-console
    console.error(`${label} negatif olmayan bir tam sayı olmalıdır.`);
    process.exit(1);
  }
  return parsed;
};

const DEFAULT_MAX_QUEUED_JOBS_PER_TENANT = 5;
const DEFAULT_HTTP_REQUEST_TIMEOUT_MS = 5 * 60 * 1000;
const DEFAULT_HTTP_HEADERS_TIMEOUT_MS = 60 * 1000;
const DEFAULT_HTTP_KEEP_ALIVE_TIMEOUT_MS = 5 * 1000;
const DEFAULT_SHUTDOWN_TIMEOUT_MS = 30 * 1000;

export const start = async (): Promise<void> => {
  const authIssuer = process.env.SOIPACK_AUTH_ISSUER;
  if (!authIssuer) {
    // eslint-disable-next-line no-console
    console.error('SOIPACK_AUTH_ISSUER ortam değişkeni tanımlanmalıdır.');
    process.exit(1);
  }

  const authAudience = process.env.SOIPACK_AUTH_AUDIENCE;
  if (!authAudience) {
    // eslint-disable-next-line no-console
    console.error('SOIPACK_AUTH_AUDIENCE ortam değişkeni tanımlanmalıdır.');
    process.exit(1);
  }

  const authJwksUri = process.env.SOIPACK_AUTH_JWKS_URI;
  const authJwksPath = process.env.SOIPACK_AUTH_JWKS_PATH;
  if (authJwksUri && authJwksPath) {
    // eslint-disable-next-line no-console
    console.error('SOIPACK_AUTH_JWKS_URI ve SOIPACK_AUTH_JWKS_PATH aynı anda tanımlanamaz.');
    process.exit(1);
  }
  if (!authJwksUri && !authJwksPath) {
    // eslint-disable-next-line no-console
    console.error('SOIPACK_AUTH_JWKS_URI veya SOIPACK_AUTH_JWKS_PATH ortam değişkenlerinden biri tanımlanmalıdır.');
    process.exit(1);
  }

  let authJwksFromFile: JSONWebKeySet | undefined;
  if (authJwksPath) {
    const resolved = path.resolve(authJwksPath);
    try {
      await fs.promises.access(resolved, fs.constants.R_OK);
    } catch {
      // eslint-disable-next-line no-console
      console.error(`SOIPACK_AUTH_JWKS_PATH ile belirtilen dosyaya erişilemiyor: ${resolved}`);
      process.exit(1);
    }
    try {
      const raw = await fs.promises.readFile(resolved, 'utf8');
      authJwksFromFile = JSON.parse(raw) as JSONWebKeySet;
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error(`SOIPACK_AUTH_JWKS_PATH altındaki JWKS dosyası okunamadı: ${
        error instanceof Error ? error.message : String(error)
      }`);
      process.exit(1);
    }
  }

  if (authJwksUri) {
    if (!authJwksUri.startsWith('https://')) {
      // eslint-disable-next-line no-console
      console.error('SOIPACK_AUTH_JWKS_URI yalnızca HTTPS protokolüyle kullanılabilir.');
      process.exit(1);
    }
  }

  const authTenantClaim = process.env.SOIPACK_AUTH_TENANT_CLAIM ?? 'tenant';
  const authUserClaim = process.env.SOIPACK_AUTH_USER_CLAIM;
  const authScopeClaim = process.env.SOIPACK_AUTH_SCOPE_CLAIM;
  const authRequiredScopes = process.env.SOIPACK_AUTH_REQUIRED_SCOPES
    ?.split(',')
    .map((scope) => scope.trim())
    .filter((scope) => scope.length > 0);
  const authAdminScopes = process.env.SOIPACK_AUTH_ADMIN_SCOPES
    ?.split(',')
    .map((scope) => scope.trim())
    .filter((scope) => scope.length > 0);

  const clockToleranceSource = process.env.SOIPACK_AUTH_CLOCK_TOLERANCE_SECONDS;
  let authClockToleranceSeconds: number | undefined;
  if (clockToleranceSource) {
    const parsed = Number.parseFloat(clockToleranceSource);
    if (!Number.isFinite(parsed) || parsed < 0) {
      // eslint-disable-next-line no-console
      console.error('SOIPACK_AUTH_CLOCK_TOLERANCE_SECONDS sıfır veya pozitif bir sayı olmalıdır.');
      process.exit(1);
    }
    authClockToleranceSeconds = parsed;
  }

  const authConfig: JwtAuthConfig = {
    issuer: authIssuer,
    audience: authAudience,
    tenantClaim: authTenantClaim,
  };

  if (authJwksUri) {
    authConfig.jwksUri = authJwksUri;
  }
  if (authJwksFromFile) {
    authConfig.jwks = authJwksFromFile;
  }

  const jwksTimeoutSource = process.env.SOIPACK_AUTH_JWKS_TIMEOUT_MS;
  const jwksMaxRetriesSource = process.env.SOIPACK_AUTH_JWKS_MAX_RETRIES;
  const jwksBackoffSource = process.env.SOIPACK_AUTH_JWKS_BACKOFF_MS;
  const jwksCacheSource = process.env.SOIPACK_AUTH_JWKS_CACHE_MS;
  const jwksCooldownSource = process.env.SOIPACK_AUTH_JWKS_COOLDOWN_MS;

  const remoteJwksConfig: NonNullable<JwtAuthConfig['remoteJwks']> = {};
  if (jwksTimeoutSource) {
    remoteJwksConfig.timeoutMs = parsePositiveInteger(
      jwksTimeoutSource,
      'SOIPACK_AUTH_JWKS_TIMEOUT_MS',
    );
  }
  if (jwksMaxRetriesSource) {
    remoteJwksConfig.maxRetries = parseNonNegativeInteger(
      jwksMaxRetriesSource,
      'SOIPACK_AUTH_JWKS_MAX_RETRIES',
    );
  }
  if (jwksBackoffSource) {
    remoteJwksConfig.backoffMs = parseNonNegativeInteger(
      jwksBackoffSource,
      'SOIPACK_AUTH_JWKS_BACKOFF_MS',
    );
  }
  if (jwksCacheSource) {
    remoteJwksConfig.cacheMaxAgeMs = parseNonNegativeInteger(
      jwksCacheSource,
      'SOIPACK_AUTH_JWKS_CACHE_MS',
    );
  }
  if (jwksCooldownSource) {
    remoteJwksConfig.cooldownMs = parseNonNegativeInteger(
      jwksCooldownSource,
      'SOIPACK_AUTH_JWKS_COOLDOWN_MS',
    );
  }
  if (Object.keys(remoteJwksConfig).length > 0) {
    authConfig.remoteJwks = remoteJwksConfig;
  }

  if (authUserClaim) {
    authConfig.userClaim = authUserClaim;
  }
  if (authScopeClaim) {
    authConfig.scopeClaim = authScopeClaim;
  }
  if (authRequiredScopes && authRequiredScopes.length > 0) {
    authConfig.requiredScopes = authRequiredScopes;
  }
  if (authAdminScopes && authAdminScopes.length > 0) {
    authConfig.adminScopes = authAdminScopes;
  }
  if (authClockToleranceSeconds !== undefined) {
    authConfig.clockToleranceSeconds = authClockToleranceSeconds;
  }

  const storageDir = process.env.SOIPACK_STORAGE_DIR
    ? path.resolve(process.env.SOIPACK_STORAGE_DIR)
    : path.resolve('.soipack/server');

  const signingKeyPath = await resolveSigningKeyPath();

  const licensePublicKeyPathSource = process.env.SOIPACK_LICENSE_PUBLIC_KEY_PATH;
  if (!licensePublicKeyPathSource) {
    // eslint-disable-next-line no-console
    console.error('SOIPACK_LICENSE_PUBLIC_KEY_PATH ortam değişkeni tanımlanmalıdır.');
    process.exit(1);
  }
  const licensePublicKeyPath = path.resolve(licensePublicKeyPathSource);

  const portSource = process.env.PORT ?? '3000';
  const port = Number.parseInt(portSource, 10);

  if (Number.isNaN(port) || port <= 0) {
    // eslint-disable-next-line no-console
    console.error('Geçerli bir PORT değeri belirtilmelidir.');
    process.exit(1);
  }

  let database: DatabaseManager;
  try {
    database = DatabaseManager.fromEnv();
  } catch {
    // eslint-disable-next-line no-console
    console.error('SOIPACK_DATABASE_URL ortam değişkeni tanımlanmalıdır.');
    process.exit(1);
  }

  try {
    await database.initialize();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    // eslint-disable-next-line no-console
    console.error(`Veritabanı şeması uygulanamadı: ${message}`);
    process.exit(1);
  }

  const tlsKeyPathSource = process.env.SOIPACK_TLS_KEY_PATH;
  if (!tlsKeyPathSource) {
    // eslint-disable-next-line no-console
    console.error('SOIPACK_TLS_KEY_PATH ortam değişkeni tanımlanmalıdır.');
    process.exit(1);
  }
  const tlsKeyPath = path.resolve(tlsKeyPathSource);
  try {
    await fs.promises.access(tlsKeyPath, fs.constants.R_OK);
  } catch {
    // eslint-disable-next-line no-console
    console.error(`SOIPACK_TLS_KEY_PATH ile belirtilen dosyaya erişilemiyor: ${tlsKeyPath}`);
    process.exit(1);
  }

  const tlsCertPathSource = process.env.SOIPACK_TLS_CERT_PATH;
  if (!tlsCertPathSource) {
    // eslint-disable-next-line no-console
    console.error('SOIPACK_TLS_CERT_PATH ortam değişkeni tanımlanmalıdır.');
    process.exit(1);
  }
  const tlsCertPath = path.resolve(tlsCertPathSource);
  try {
    await fs.promises.access(tlsCertPath, fs.constants.R_OK);
  } catch {
    // eslint-disable-next-line no-console
    console.error(`SOIPACK_TLS_CERT_PATH ile belirtilen dosyaya erişilemiyor: ${tlsCertPath}`);
    process.exit(1);
  }

  const tlsKey = await fs.promises.readFile(tlsKeyPath, 'utf8');
  const tlsCert = await fs.promises.readFile(tlsCertPath, 'utf8');

  const tlsClientCaPathSource = process.env.SOIPACK_TLS_CLIENT_CA_PATH;
  let tlsClientCa: string | undefined;
  let requireAdminClientCertificate = false;
  if (tlsClientCaPathSource) {
    const tlsClientCaPath = path.resolve(tlsClientCaPathSource);
    try {
      await fs.promises.access(tlsClientCaPath, fs.constants.R_OK);
    } catch {
      // eslint-disable-next-line no-console
      console.error(`SOIPACK_TLS_CLIENT_CA_PATH ile belirtilen dosyaya erişilemiyor: ${tlsClientCaPath}`);
      process.exit(1);
    }
    tlsClientCa = await fs.promises.readFile(tlsClientCaPath, 'utf8');
    requireAdminClientCertificate = true;
  }

  const healthcheckToken = process.env.SOIPACK_HEALTHCHECK_TOKEN;

  const maxQueuedJobsSource = process.env.SOIPACK_MAX_QUEUED_JOBS;
  let maxQueuedJobsPerTenant = DEFAULT_MAX_QUEUED_JOBS_PER_TENANT;
  if (maxQueuedJobsSource !== undefined) {
    const parsed = Number.parseInt(maxQueuedJobsSource, 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      // eslint-disable-next-line no-console
      console.error('SOIPACK_MAX_QUEUED_JOBS pozitif bir tam sayı olmalıdır.');
      process.exit(1);
    }
    maxQueuedJobsPerTenant = parsed;
  }

  const maxQueuedJobsTotalSource = process.env.SOIPACK_MAX_QUEUED_JOBS_TOTAL;
  let maxQueuedJobsTotal: number | undefined;
  if (maxQueuedJobsTotalSource !== undefined) {
    maxQueuedJobsTotal = parsePositiveInteger(
      maxQueuedJobsTotalSource,
      'SOIPACK_MAX_QUEUED_JOBS_TOTAL',
    );
  }

  const workerConcurrencySource = process.env.SOIPACK_WORKER_CONCURRENCY;
  let workerConcurrency: number | undefined;
  if (workerConcurrencySource !== undefined) {
    workerConcurrency = parsePositiveInteger(
      workerConcurrencySource,
      'SOIPACK_WORKER_CONCURRENCY',
    );
  }

  const retention: RetentionConfig = {};

  const uploadsDays = parseRetentionDays(
    process.env.SOIPACK_RETENTION_UPLOADS_DAYS,
    'SOIPACK_RETENTION_UPLOADS_DAYS',
  );
  if (uploadsDays !== undefined) {
    retention.uploads = { maxAgeMs: uploadsDays };
  }

  const analysesDays = parseRetentionDays(
    process.env.SOIPACK_RETENTION_ANALYSES_DAYS,
    'SOIPACK_RETENTION_ANALYSES_DAYS',
  );
  if (analysesDays !== undefined) {
    retention.analyses = { maxAgeMs: analysesDays };
  }

  const reportsDays = parseRetentionDays(
    process.env.SOIPACK_RETENTION_REPORTS_DAYS,
    'SOIPACK_RETENTION_REPORTS_DAYS',
  );
  if (reportsDays !== undefined) {
    retention.reports = { maxAgeMs: reportsDays };
  }

  const packagesDays = parseRetentionDays(
    process.env.SOIPACK_RETENTION_PACKAGES_DAYS,
    'SOIPACK_RETENTION_PACKAGES_DAYS',
  );
  if (packagesDays !== undefined) {
    retention.packages = { maxAgeMs: packagesDays };
  }

  const licenseMaxBytesSource = process.env.SOIPACK_LICENSE_MAX_BYTES;
  let licenseMaxBytes: number | undefined;
  if (licenseMaxBytesSource) {
    licenseMaxBytes = parsePositiveInteger(licenseMaxBytesSource, 'SOIPACK_LICENSE_MAX_BYTES');
  }

  const licenseHeaderMaxBytesSource = process.env.SOIPACK_LICENSE_HEADER_MAX_BYTES;
  let licenseHeaderMaxBytes: number | undefined;
  if (licenseHeaderMaxBytesSource) {
    licenseHeaderMaxBytes = parsePositiveInteger(
      licenseHeaderMaxBytesSource,
      'SOIPACK_LICENSE_HEADER_MAX_BYTES',
    );
  } else if (licenseMaxBytes !== undefined) {
    licenseHeaderMaxBytes = Math.ceil((licenseMaxBytes * 4) / 3);
  }

  let licenseLimits: LicenseLimitsConfig | undefined;
  if (licenseMaxBytes !== undefined || licenseHeaderMaxBytes !== undefined) {
    licenseLimits = {};
    if (licenseMaxBytes !== undefined) {
      licenseLimits.maxBytes = licenseMaxBytes;
    }
    if (licenseHeaderMaxBytes !== undefined) {
      licenseLimits.headerMaxBytes = licenseHeaderMaxBytes;
    }
  }

  const licenseCacheMaxEntriesSource = process.env.SOIPACK_LICENSE_CACHE_MAX_ENTRIES;
  const licenseCacheMaxAgeSource = process.env.SOIPACK_LICENSE_CACHE_MAX_AGE_MS;
  let licenseCache: LicenseCacheConfig | undefined;
  const licenseCacheCandidate: LicenseCacheConfig = {};
  if (licenseCacheMaxEntriesSource) {
    licenseCacheCandidate.maxEntries = parsePositiveInteger(
      licenseCacheMaxEntriesSource,
      'SOIPACK_LICENSE_CACHE_MAX_ENTRIES',
    );
  }
  if (licenseCacheMaxAgeSource) {
    licenseCacheCandidate.maxAgeMs = parseNonNegativeInteger(
      licenseCacheMaxAgeSource,
      'SOIPACK_LICENSE_CACHE_MAX_AGE_MS',
    );
  }
  if (Object.keys(licenseCacheCandidate).length > 0) {
    licenseCache = licenseCacheCandidate;
  }

  const retentionSweepIntervalSource = process.env.SOIPACK_RETENTION_SWEEP_INTERVAL_MS;
  let retentionScheduler: RetentionSchedulerConfig | undefined;
  if (retentionSweepIntervalSource) {
    const intervalMs = parsePositiveInteger(
      retentionSweepIntervalSource,
      'SOIPACK_RETENTION_SWEEP_INTERVAL_MS',
    );
    retentionScheduler = { intervalMs };
  }

  const requestTimeoutSource = process.env.SOIPACK_HTTP_REQUEST_TIMEOUT_MS;
  const headersTimeoutSource = process.env.SOIPACK_HTTP_HEADERS_TIMEOUT_MS;
  const keepAliveTimeoutSource = process.env.SOIPACK_HTTP_KEEP_ALIVE_TIMEOUT_MS;
  const shutdownTimeoutSource = process.env.SOIPACK_SHUTDOWN_TIMEOUT_MS;

  const requestTimeoutMs = requestTimeoutSource
    ? parsePositiveInteger(requestTimeoutSource, 'SOIPACK_HTTP_REQUEST_TIMEOUT_MS')
    : DEFAULT_HTTP_REQUEST_TIMEOUT_MS;
  const headersTimeoutMs = headersTimeoutSource
    ? parsePositiveInteger(headersTimeoutSource, 'SOIPACK_HTTP_HEADERS_TIMEOUT_MS')
    : DEFAULT_HTTP_HEADERS_TIMEOUT_MS;
  const keepAliveTimeoutMs = keepAliveTimeoutSource
    ? parsePositiveInteger(keepAliveTimeoutSource, 'SOIPACK_HTTP_KEEP_ALIVE_TIMEOUT_MS')
    : DEFAULT_HTTP_KEEP_ALIVE_TIMEOUT_MS;
  const shutdownTimeoutMs = shutdownTimeoutSource
    ? parsePositiveInteger(shutdownTimeoutSource, 'SOIPACK_SHUTDOWN_TIMEOUT_MS')
    : DEFAULT_SHUTDOWN_TIMEOUT_MS;

  const jsonBodyLimitSource = process.env.SOIPACK_MAX_JSON_BODY_BYTES;
  let jsonBodyLimitBytes: number | undefined;
  if (jsonBodyLimitSource) {
    jsonBodyLimitBytes = parsePositiveInteger(jsonBodyLimitSource, 'SOIPACK_MAX_JSON_BODY_BYTES');
  }

  const rateLimit: RateLimitConfig = {
    ip: {
      windowMs: DEFAULT_IP_RATE_LIMIT_WINDOW_MS,
      max: DEFAULT_IP_RATE_LIMIT_MAX,
    },
    tenant: {
      windowMs: DEFAULT_TENANT_RATE_LIMIT_WINDOW_MS,
      max: DEFAULT_TENANT_RATE_LIMIT_MAX,
    },
  };

  const rateLimitIpWindowSource = process.env.SOIPACK_RATE_LIMIT_IP_WINDOW_MS;
  const rateLimitIpMaxSource = process.env.SOIPACK_RATE_LIMIT_IP_MAX_REQUESTS;
  if (rateLimitIpWindowSource || rateLimitIpMaxSource) {
    if (!rateLimitIpWindowSource || !rateLimitIpMaxSource) {
      // eslint-disable-next-line no-console
      console.error('IP oran limiti için hem SOIPACK_RATE_LIMIT_IP_WINDOW_MS hem de SOIPACK_RATE_LIMIT_IP_MAX_REQUESTS tanımlanmalıdır.');
      process.exit(1);
    }
    rateLimit.ip = {
      windowMs: parsePositiveInteger(rateLimitIpWindowSource, 'SOIPACK_RATE_LIMIT_IP_WINDOW_MS'),
      max: parsePositiveInteger(rateLimitIpMaxSource, 'SOIPACK_RATE_LIMIT_IP_MAX_REQUESTS'),
    };
  }

  const rateLimitIpMaxKeysSource = process.env.SOIPACK_RATE_LIMIT_IP_MAX_KEYS;
  if (rateLimitIpMaxKeysSource !== undefined) {
    rateLimit.ip = {
      ...rateLimit.ip!,
      maxEntries: parsePositiveInteger(
        rateLimitIpMaxKeysSource,
        'SOIPACK_RATE_LIMIT_IP_MAX_KEYS',
      ),
    };
  }

  const rateLimitTenantWindowSource = process.env.SOIPACK_RATE_LIMIT_TENANT_WINDOW_MS;
  const rateLimitTenantMaxSource = process.env.SOIPACK_RATE_LIMIT_TENANT_MAX_REQUESTS;
  if (rateLimitTenantWindowSource || rateLimitTenantMaxSource) {
    if (!rateLimitTenantWindowSource || !rateLimitTenantMaxSource) {
      // eslint-disable-next-line no-console
      console.error('Tenant oran limiti için hem SOIPACK_RATE_LIMIT_TENANT_WINDOW_MS hem de SOIPACK_RATE_LIMIT_TENANT_MAX_REQUESTS tanımlanmalıdır.');
      process.exit(1);
    }
    rateLimit.tenant = {
      windowMs: parsePositiveInteger(
        rateLimitTenantWindowSource,
        'SOIPACK_RATE_LIMIT_TENANT_WINDOW_MS',
      ),
      max: parsePositiveInteger(
        rateLimitTenantMaxSource,
        'SOIPACK_RATE_LIMIT_TENANT_MAX_REQUESTS',
      ),
    };
  }

  const rateLimitTenantMaxKeysSource = process.env.SOIPACK_RATE_LIMIT_TENANT_MAX_KEYS;
  if (rateLimitTenantMaxKeysSource !== undefined) {
    rateLimit.tenant = {
      ...rateLimit.tenant!,
      maxEntries: parsePositiveInteger(
        rateLimitTenantMaxKeysSource,
        'SOIPACK_RATE_LIMIT_TENANT_MAX_KEYS',
      ),
    };
  }

  let scanner: FileScanner | undefined;
  const scanCommand = process.env.SOIPACK_SCAN_COMMAND;
  if (scanCommand) {
    const scanArgs = process.env.SOIPACK_SCAN_ARGS
      ?.split(',')
      .map((arg) => arg.trim())
      .filter((arg) => arg.length > 0);
    const timeoutSource = process.env.SOIPACK_SCAN_TIMEOUT_MS;
    let timeoutMs: number | undefined;
    if (timeoutSource) {
      const parsed = Number.parseInt(timeoutSource, 10);
      if (!Number.isFinite(parsed) || parsed <= 0) {
        // eslint-disable-next-line no-console
        console.error('SOIPACK_SCAN_TIMEOUT_MS pozitif bir tam sayı olmalıdır.');
        process.exit(1);
      }
      timeoutMs = parsed;
    }

    const infectedCodesSource = process.env.SOIPACK_SCAN_INFECTED_EXIT_CODES;
    let infectedExitCodes: number[] | undefined;
    if (infectedCodesSource) {
      const parsed = infectedCodesSource
        .split(',')
        .map((value) => Number.parseInt(value.trim(), 10))
        .filter((value) => Number.isFinite(value));
      if (parsed.length === 0) {
        // eslint-disable-next-line no-console
        console.error('SOIPACK_SCAN_INFECTED_EXIT_CODES en az bir tamsayı içermelidir.');
        process.exit(1);
      }
      infectedExitCodes = parsed;
    }

    scanner = createCommandScanner(scanCommand, {
      args: scanArgs,
      timeoutMs,
      infectedExitCodes,
    });
  }

  const trustProxySource = process.env.SOIPACK_TRUST_PROXY;
  let trustProxy: boolean | number | string | undefined;
  if (trustProxySource !== undefined) {
    const normalized = trustProxySource.trim();
    const lower = normalized.toLowerCase();
    if (lower === 'true') {
      trustProxy = true;
    } else if (lower === 'false') {
      trustProxy = false;
    } else if (/^\d+$/.test(normalized)) {
      trustProxy = Number.parseInt(normalized, 10);
    } else {
      trustProxy = normalized;
    }
  }

  const app = createServer({
    auth: authConfig,
    storageDir,
    signingKeyPath,
    licensePublicKeyPath,
    database,
    maxQueuedJobsPerTenant,
    maxQueuedJobsTotal,
    workerConcurrency,
    retention,
    scanner,
    healthcheckToken,
    jsonBodyLimitBytes,
    rateLimit,
    requireAdminClientCertificate,
    trustProxy,
    licenseLimits,
    licenseCache,
    retentionScheduler,
  });

  const httpsServer = createHttpsServer(app, {
    key: tlsKey,
    cert: tlsCert,
    clientCa: tlsClientCa,
  }, { requireClientCertificate: requireAdminClientCertificate });

  httpsServer.requestTimeout = requestTimeoutMs;
  httpsServer.headersTimeout = headersTimeoutMs;
  httpsServer.keepAliveTimeout = keepAliveTimeoutMs;

  const lifecycle = getServerLifecycle(app);

  const closeServer = (): Promise<void> =>
    new Promise((resolve, reject) => {
      httpsServer.close((error) => {
        if (error) {
          reject(error);
        } else {
          resolve();
        }
      });
    });

  const signals: NodeJS.Signals[] = ['SIGTERM', 'SIGINT'];
  let shuttingDown = false;

  const initiateShutdown = (signal: NodeJS.Signals): void => {
    if (shuttingDown) {
      return;
    }
    shuttingDown = true;

    lifecycle.logger.info({ event: 'shutdown_signal', signal }, 'Kapatma sinyali alındı.');
    const timeout = setTimeout(() => {
      lifecycle.logger.error(
        { event: 'shutdown_timeout', timeoutMs: shutdownTimeoutMs },
        'Graceful shutdown zaman aşımına uğradı; süreç sonlandırılıyor.',
      );
      process.exit(1);
    }, shutdownTimeoutMs);

    const closePromise = closeServer().catch((error) => {
      lifecycle.logger.error(
        {
          event: 'shutdown_close_failed',
          error: error instanceof Error ? error.message : String(error),
        },
        'HTTPS sunucusu kapatılamadı.',
      );
      throw error;
    });

    const drainPromise = lifecycle.waitForIdle().catch((error) => {
      lifecycle.logger.error(
        {
          event: 'shutdown_queue_failed',
          error: error instanceof Error ? error.message : String(error),
        },
        'İş kuyruğu boşaltılamadı.',
      );
      throw error;
    });

    const cleanupPromise = lifecycle
      .shutdown()
      .catch(async (error) => {
        lifecycle.logger.error(
          {
            event: 'shutdown_cleanup_failed',
            error: error instanceof Error ? error.message : String(error),
          },
          'Sunucu kapanış temizliği tamamlanamadı.',
        );
        try {
          await database.close();
        } catch (closeError) {
          lifecycle.logger.error(
            {
              event: 'shutdown_database_close_failed',
              error: closeError instanceof Error ? closeError.message : String(closeError),
            },
            'Veritabanı bağlantısı kapatılamadı.',
          );
        }
        throw error;
      })
      .then(async () => {
        try {
          await database.close();
        } catch (error) {
          lifecycle.logger.error(
            {
              event: 'shutdown_database_close_failed',
              error: error instanceof Error ? error.message : String(error),
            },
            'Veritabanı bağlantısı kapatılamadı.',
          );
          throw error;
        }
      });

    Promise.all([closePromise, drainPromise, cleanupPromise])
      .then(() => {
        clearTimeout(timeout);
        lifecycle.logger.info({ event: 'shutdown_complete' }, 'Sunucu başarıyla kapatıldı.');
        process.exit(0);
      })
      .catch(() => {
        clearTimeout(timeout);
        lifecycle.logger.error({ event: 'shutdown_failed' }, 'Sunucu kapatma işlemi tamamlanamadı.');
        process.exit(1);
      });
  };

  signals.forEach((signal) => {
    process.on(signal, () => initiateShutdown(signal));
  });

  httpsServer.listen(port, () => {
    // eslint-disable-next-line no-console
    console.log(`SOIPack API HTTPS olarak ${port} portunda dinliyor.`);
    lifecycle.logger.info(
      {
        event: 'server_listening',
        port,
        requestTimeoutMs,
        headersTimeoutMs,
        keepAliveTimeoutMs,
      },
      'SOIPack API HTTPS dinleyicisi başlatıldı.',
    );
  });
};

if (require.main === module && process.env.JEST_WORKER_ID === undefined) {
  void start();
}

