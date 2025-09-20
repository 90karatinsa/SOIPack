/// <reference lib="dom" />
import fs from 'fs';
import { promises as fsPromises } from 'fs';
import os from 'os';
import path from 'path';
import process from 'process';
import { once } from 'events';
import { AddressInfo } from 'net';

import { generateKeyPair, SignJWT, exportJWK, type JWK, type JSONWebKeySet } from 'jose';

import { createServer } from '../packages/server/src/index';

const DEMO_SIGNING_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEICiI0Jsw2AjCiWk2uBb89bIQkOH18XHytA2TtblwFzgQ
-----END PRIVATE KEY-----
`;

const LICENSE_PUBLIC_KEY_BASE64 = 'mXRQccwM4wyv+mmIQZjJWAqDDvD6wYn+c/DpB1w/x20=';
const DEMO_LICENSE_PATH = path.resolve('data', 'licenses', 'demo-license.key');

const example = (...segments: string[]): string => path.resolve('examples', 'minimal', ...segments);

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
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const response = await fetch(`${baseUrl}/v1/jobs/${jobId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
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
  throw new Error(`İş ${jobId} zaman aşımına uğradı: ${JSON.stringify(lastBody)}`);
};

const main = async (): Promise<void> => {
  const storageDir = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'soipack-api-e2e-'));
  const signingKeyPath = path.join(storageDir, 'signing-key.pem');
  await fsPromises.writeFile(signingKeyPath, DEMO_SIGNING_PRIVATE_KEY, 'utf8');
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

  const app = createServer({
    auth: {
      issuer,
      audience,
      tenantClaim: 'tenant',
      jwks,
      requiredScopes: ['soipack.api'],
    },
    storageDir,
    signingKeyPath,
    licensePublicKeyPath,
  });
  const server = app.listen(0);
  await once(server, 'listening');
  const address = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const token = await new SignJWT({ tenant: tenantId, scope: 'soipack.api' })
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
    console.log(`Analyze tamamlandı: ${analyzeJob.id} (exitCode=${analyzeJob.result?.exitCode ?? 'unknown'})`);

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
    server.close();
    await new Promise<void>((resolve) => server.once('close', () => resolve()));
    await fsPromises.rm(storageDir, { recursive: true, force: true });
  }
};

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
