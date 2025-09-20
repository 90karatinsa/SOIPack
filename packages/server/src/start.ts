import path from 'path';
import process from 'process';

import dotenv from 'dotenv';

import { RetentionConfig, createServer } from './index';

dotenv.config();

const token = process.env.SOIPACK_API_TOKEN;

if (!token) {
  // eslint-disable-next-line no-console
  console.error('SOIPACK_API_TOKEN ortam değişkeni tanımlanmalıdır.');
  process.exit(1);
}

const storageDir = process.env.SOIPACK_STORAGE_DIR
  ? path.resolve(process.env.SOIPACK_STORAGE_DIR)
  : path.resolve('.soipack/server');
const signingKeyPathSource = process.env.SOIPACK_SIGNING_KEY_PATH;
if (!signingKeyPathSource) {
  // eslint-disable-next-line no-console
  console.error('SOIPACK_SIGNING_KEY_PATH ortam değişkeni tanımlanmalıdır.');
  process.exit(1);
}
const signingKeyPath = path.resolve(signingKeyPathSource);
const portSource = process.env.PORT ?? '3000';
const port = Number.parseInt(portSource, 10);

if (Number.isNaN(port) || port <= 0) {
  // eslint-disable-next-line no-console
  console.error('Geçerli bir PORT değeri belirtilmelidir.');
  process.exit(1);
}

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

const retention: RetentionConfig = {};

const uploadsDays = parseRetentionDays(process.env.SOIPACK_RETENTION_UPLOADS_DAYS, 'SOIPACK_RETENTION_UPLOADS_DAYS');
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

const reportsDays = parseRetentionDays(process.env.SOIPACK_RETENTION_REPORTS_DAYS, 'SOIPACK_RETENTION_REPORTS_DAYS');
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

const app = createServer({ token, storageDir, signingKeyPath, retention });

app.listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`SOIPack API ${port} portunda çalışıyor.`);
});

