import fs from 'fs';
import path from 'path';
import process from 'process';

import dotenv from 'dotenv';

import { JwtAuthConfig, RetentionConfig, createServer } from './index';
import { createCommandScanner } from './scanner';
import type { FileScanner } from './scanner';

dotenv.config();

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

const DEFAULT_MAX_QUEUED_JOBS_PER_TENANT = 5;

const start = async (): Promise<void> => {
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
  if (!authJwksUri) {
    // eslint-disable-next-line no-console
    console.error('SOIPACK_AUTH_JWKS_URI ortam değişkeni tanımlanmalıdır.');
    process.exit(1);
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
    jwksUri: authJwksUri,
  };

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

  const app = createServer({
    auth: authConfig,
    storageDir,
    signingKeyPath,
    licensePublicKeyPath,
    maxQueuedJobsPerTenant,
    retention,
    scanner,
  });

  app.listen(port, () => {
    // eslint-disable-next-line no-console
    console.log(`SOIPack API ${port} portunda çalışıyor.`);
  });
};

if (require.main === module) {
  void start();
}

