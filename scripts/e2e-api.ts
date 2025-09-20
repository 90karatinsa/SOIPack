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

interface ImportResultBody {
  id: string;
}

interface AnalyzeResultBody {
  id: string;
  exitCode: number;
}

interface ReportResultBody {
  id: string;
  outputs: { complianceHtml: string };
}

interface PackResultBody {
  id: string;
  manifestId: string;
  outputs: { archive: string };
}

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
    const importResult = await ensureOk<ImportResultBody>(importResponse);
    console.log(`Import tamamlandı: ${importResult.id}`);

    const analyzeResponse = await fetch(`${baseUrl}/v1/analyze`, {
      method: 'POST',
      headers: { ...baseHeaders, 'Content-Type': 'application/json' },
      body: JSON.stringify({ importId: importResult.id }),
    });
    const analyzeResult = await ensureOk<AnalyzeResultBody>(analyzeResponse);
    console.log(`Analyze tamamlandı: ${analyzeResult.id} (exitCode=${analyzeResult.exitCode})`);

    const reportResponse = await fetch(`${baseUrl}/v1/report`, {
      method: 'POST',
      headers: { ...baseHeaders, 'Content-Type': 'application/json' },
      body: JSON.stringify({ analysisId: analyzeResult.id }),
    });
    const reportResult = await ensureOk<ReportResultBody>(reportResponse);
    console.log(`Report üretildi: ${reportResult.id}`);

    const packResponse = await fetch(`${baseUrl}/v1/pack`, {
      method: 'POST',
      headers: { ...baseHeaders, 'Content-Type': 'application/json' },
      body: JSON.stringify({ reportId: reportResult.id }),
    });
    const packResult = await ensureOk<PackResultBody>(packResponse);
    console.log(`Pack tamamlandı: ${packResult.id} (manifest=${packResult.manifestId})`);

    const assetResponse = await fetch(`${baseUrl}/v1/reports/${reportResult.id}/compliance.html`, {
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
