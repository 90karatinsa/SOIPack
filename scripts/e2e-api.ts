/// <reference lib="dom" />
import { promises as fsPromises } from 'fs';
import type { Server as HttpsServer } from 'https';
import os from 'os';
import path from 'path';
import process from 'process';
import { once } from 'events';
import { AddressInfo } from 'net';
import { Agent, setGlobalDispatcher } from 'undici';
import { newDb } from 'pg-mem';

import { generateKeyPair, SignJWT, exportJWK, type JWK, type JSONWebKeySet } from 'jose';

import { DatabaseManager } from '../packages/server/src/database';
import { createHttpsServer, createServer } from '../packages/server/src/index';

const LICENSE_PUBLIC_KEY_BASE64 = 'mXRQccwM4wyv+mmIQZjJWAqDDvD6wYn+c/DpB1w/x20=';
const DEMO_LICENSE_PATH = path.resolve('data', 'licenses', 'demo-license.key');

const example = (...segments: string[]): string => path.resolve('examples', 'minimal', ...segments);

const DEV_TLS_BUNDLE_PATH = path.resolve('test', 'certs', 'dev.pem');
const CMS_SIGNING_BUNDLE_PATH = path.resolve('test', 'certs', 'cms-test.pem');
const PRIVATE_KEY_PATTERN = /-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----/;
const CERTIFICATE_PATTERN = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/;

const ensureOk = async <T>(response: Response): Promise<T> => {
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`HTTP ${response.status}: ${text}`);
  }
  return (await response.json()) as T;
};

type JobStatus = 'queued' | 'running' | 'completed' | 'failed';

interface JobError {
  code: string;
  message: string;
  details?: unknown;
}

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

interface JobResponse<T> {
  id: string;
  kind: string;
  hash: string;
  status: JobStatus;
  createdAt: string;
  updatedAt: string;
  reused?: boolean;
  result?: T;
  error?: JobError;
}

const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => {
    setTimeout(resolve, ms);
  });

const waitForJobCompletion = async <T>(
  baseUrl: string,
  token: string,
  jobId: string,
): Promise<JobResponse<T>> => {
  let lastBody: JobResponse<T> | undefined;
  let lastError: unknown;
  for (let attempt = 0; attempt < 120; attempt += 1) {
    let response: Response;
    try {
      response = await fetch(`${baseUrl}/v1/jobs/${jobId}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
    } catch (error) {
      lastError = error;
      await sleep(250);
      continue;
    }
    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Job durumu alınamadı (${response.status}): ${text}`);
    }
    const body = (await response.json()) as JobResponse<T>;
    lastBody = body;
    if (body.status === 'completed') {
      return body;
    }
    if (body.status === 'failed') {
      throw new Error(`İş ${jobId} başarısız: ${JSON.stringify(body.error)}`);
    }
    await sleep(250);
  }
  throw new Error(
    `İş ${jobId} zaman aşımına uğradı: ${JSON.stringify(lastBody)}${
      lastError ? ` (last error: ${String(lastError)})` : ''
    }`,
  );
};

const main = async (): Promise<void> => {
  const storageDir = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'soipack-api-e2e-'));
  const signingKeyPath = path.join(storageDir, 'signing-key.pem');
  const licensePublicKeyPath = path.join(storageDir, 'license.pub');
  await fsPromises.writeFile(licensePublicKeyPath, LICENSE_PUBLIC_KEY_BASE64, 'utf8');
  const licenseContent = await fsPromises.readFile(DEMO_LICENSE_PATH, 'utf8');
  const licenseHeader = Buffer.from(licenseContent, 'utf8').toString('base64');
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const publicJwk = (await exportJWK(publicKey)) as JWK;
  publicJwk.use = 'sig';
  publicJwk.alg = 'RS256';
  publicJwk.kid = 'e2e-key';

  const issuer = 'https://demo-auth.soipack';
  const audience = 'soipack-api';
  const tenantId = process.env.SOIPACK_E2E_TENANT ?? 'demo-tenant';

  const jwks: JSONWebKeySet = { keys: [publicJwk] };

  const mem = newDb();
  const { Pool } = mem.adapters.createPg();
  const databaseManager = new DatabaseManager('pg-mem', () => new Pool());
  await databaseManager.initialize();

  const tlsBundle = await fsPromises.readFile(DEV_TLS_BUNDLE_PATH, 'utf8');
  const privateKeyMatch = tlsBundle.match(PRIVATE_KEY_PATTERN);
  if (!privateKeyMatch) {
    throw new Error('Dev TLS private key not found in bundle.');
  }
  const certificateMatch = tlsBundle.match(CERTIFICATE_PATTERN);
  if (!certificateMatch) {
    throw new Error('Dev TLS certificate not found in bundle.');
  }
  const devPrivateKey = privateKeyMatch[0];
  const devCertificate = certificateMatch[0];

  const cmsBundle = await fsPromises.readFile(CMS_SIGNING_BUNDLE_PATH, 'utf8');
  const cmsPrivateKeyMatch = cmsBundle.match(PRIVATE_KEY_PATTERN);
  if (!cmsPrivateKeyMatch) {
    throw new Error('CMS signing private key not found in bundle.');
  }
  const cmsCertificateMatch = cmsBundle.match(CERTIFICATE_PATTERN);
  if (!cmsCertificateMatch) {
    throw new Error('CMS signing certificate not found in bundle.');
  }
  const cmsPrivateKey = cmsPrivateKeyMatch[0];
  const cmsCertificate = cmsCertificateMatch[0];

  const signingKeyBundle = `${cmsPrivateKey.trim()}\n${cmsCertificate.trim()}\n`;
  await fsPromises.writeFile(signingKeyPath, signingKeyBundle, 'utf8');

  const cmsPrivateKeyPath = path.join(storageDir, 'cms-dev-key.pem');
  const cmsCertificatePath = path.join(storageDir, 'cms-dev-cert.pem');
  await fsPromises.writeFile(cmsPrivateKeyPath, cmsPrivateKey, 'utf8');
  await fsPromises.writeFile(cmsCertificatePath, cmsCertificate, 'utf8');

  setGlobalDispatcher(
    new Agent({
      connect: {
        ca: devCertificate,
        checkServerIdentity: () => undefined,
      },
    }),
  );

  const app = createServer({
    auth: {
      issuer,
      audience,
      tenantClaim: 'tenant',
      jwks,
      requiredScopes: ['soipack.api'],
      adminScopes: ['soipack.api.admin'],
    },
    storageDir,
    signingKeyPath,
    licensePublicKeyPath,
    database: databaseManager,
    cmsSigning: {
      privateKeyPath: cmsPrivateKeyPath,
      certificatePath: cmsCertificatePath,
    },
  });
  let server: HttpsServer | undefined;
    try {
      server = createHttpsServer(app, { key: devPrivateKey, cert: devCertificate }).listen(0);
      await once(server, 'listening');
      const address = server.address() as AddressInfo;
      const baseUrl = `https://127.0.0.1:${address.port}`;

      const token = await new SignJWT({ tenant: tenantId, scope: 'soipack.api soipack.api.admin' })
        .setProtectedHeader({ alg: 'RS256', kid: publicJwk.kid })
        .setIssuer(issuer)
        .setAudience(audience)
        .setSubject('e2e-user')
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(privateKey);

      const baseHeaders = { Authorization: `Bearer ${token}`, 'X-SOIPACK-License': licenseHeader };

      try {
        const formData = new FormData();
        formData.set('projectName', 'Minimal Project');
        formData.set('projectVersion', '1.0.0');
        formData.append('reqif', new Blob([await fsPromises.readFile(example('spec.reqif'))]), 'spec.reqif');
        formData.append('junit', new Blob([await fsPromises.readFile(example('results.xml'))]), 'results.xml');
        formData.append('lcov', new Blob([await fsPromises.readFile(example('lcov.info'))]), 'lcov.info');

        const importResponse = await fetch(`${baseUrl}/v1/import`, {
          method: 'POST',
          headers: baseHeaders,
          body: formData,
        });
        const importQueued = await ensureOk<JobResponse<ImportJobResult>>(importResponse);
        const importJob =
          importQueued.status === 'completed'
            ? importQueued
            : await waitForJobCompletion<ImportJobResult>(baseUrl, token, importQueued.id);
        console.log(`Import tamamlandı: ${importJob.id}`);

        const analyzeResponse = await fetch(`${baseUrl}/v1/analyze`, {
          method: 'POST',
          headers: { ...baseHeaders, 'Content-Type': 'application/json' },
          body: JSON.stringify({ importId: importJob.id }),
        });
        const analyzeQueued = await ensureOk<JobResponse<AnalyzeJobResult>>(analyzeResponse);
        const analyzeJob =
          analyzeQueued.status === 'completed'
            ? analyzeQueued
            : await waitForJobCompletion<AnalyzeJobResult>(baseUrl, token, analyzeQueued.id);
        console.log(
          `Analyze tamamlandı: ${analyzeJob.id} (exitCode=${analyzeJob.result?.exitCode ?? 'unknown'})`,
        );

        const reportResponse = await fetch(`${baseUrl}/v1/report`, {
          method: 'POST',
          headers: { ...baseHeaders, 'Content-Type': 'application/json' },
          body: JSON.stringify({ analysisId: analyzeJob.id }),
        });
        const reportQueued = await ensureOk<JobResponse<ReportJobResult>>(reportResponse);
        const reportJob =
          reportQueued.status === 'completed'
            ? reportQueued
            : await waitForJobCompletion<ReportJobResult>(baseUrl, token, reportQueued.id);
        console.log(`Report üretildi: ${reportJob.id}`);

        const reportOutputDir = reportJob.result?.outputs?.directory
          ? path.resolve(storageDir, reportJob.result.outputs.directory)
          : undefined;
        if (!reportOutputDir) {
          throw new Error('Report output directory not available.');
        }
        const expectedAnalysisPath = path.join(reportOutputDir, 'analysis.json');
        try {
          await fsPromises.access(expectedAnalysisPath);
        } catch {
          const analysisResponse = await fetch(`${baseUrl}/v1/reports/${reportJob.id}/analysis.json`, {
            headers: baseHeaders,
          });
          if (!analysisResponse.ok) {
            throw new Error(`analysis.json indirilemedi: ${analysisResponse.status}`);
          }
          const analysisContent = await analysisResponse.text();
          await fsPromises.mkdir(path.dirname(expectedAnalysisPath), { recursive: true });
          await fsPromises.writeFile(expectedAnalysisPath, analysisContent, 'utf8');
        }

        const packResponse = await fetch(`${baseUrl}/v1/pack`, {
          method: 'POST',
          headers: { ...baseHeaders, 'Content-Type': 'application/json' },
          body: JSON.stringify({ reportId: reportJob.id }),
        });
        const packQueued = await ensureOk<JobResponse<PackJobResult>>(packResponse);
        const packJob =
          packQueued.status === 'completed'
            ? packQueued
            : await waitForJobCompletion<PackJobResult>(baseUrl, token, packQueued.id);
        console.log(`Pack tamamlandı: ${packJob.id} (manifest=${packJob.result?.manifestId ?? 'n/a'})`);

        const archiveResponse = await fetch(`${baseUrl}/v1/packages/${packJob.id}/archive`, {
          headers: { Authorization: baseHeaders.Authorization },
        });
        if (!archiveResponse.ok) {
          throw new Error(`Paket arşivi indirilemedi: ${archiveResponse.status}`);
        }
        const archiveBytes = await archiveResponse.arrayBuffer();
        console.log(`Paket arşivi ${archiveBytes.byteLength} bayt indirildi.`);

        const manifestResponse = await fetch(`${baseUrl}/v1/packages/${packJob.id}/manifest`, {
          headers: { Authorization: baseHeaders.Authorization },
        });
        if (!manifestResponse.ok) {
          throw new Error(`Manifest indirilemedi: ${manifestResponse.status}`);
        }
        const manifestContent = await manifestResponse.json();
        console.log(`Manifest ${Object.keys(manifestContent).length} anahtar içeriyor.`);

        const assetResponse = await fetch(`${baseUrl}/v1/reports/${reportJob.id}/compliance.html`, {
          headers: baseHeaders,
        });
        if (!assetResponse.ok) {
          throw new Error(`Rapor dosyası okunamadı: ${assetResponse.status}`);
        }
        const html = await assetResponse.text();
        console.log(`Compliance raporu ${html.length} karakter.`);
      } finally {
        if (server) {
          await new Promise<void>((resolve, reject) => {
            server!.close((error) => {
            if (error) {
              reject(error);
              return;
            }
            resolve();
          });
        });
      }
    }
  } finally {
    await databaseManager.close().catch(() => undefined);
    await fsPromises.rm(storageDir, { recursive: true, force: true }).catch(() => undefined);
  }
};

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
