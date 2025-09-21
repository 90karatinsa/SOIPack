import fs, { promises as fsPromises } from 'fs';
import os from 'os';
import path from 'path';
import { Writable } from 'stream';

import { generateKeyPair, SignJWT, exportJWK, type JWK, type JSONWebKeySet, type KeyLike } from 'jose';
import request from 'supertest';
import pino from 'pino';

import { Registry } from 'prom-client';

import { Manifest } from '@soipack/core';
import { verifyManifestSignature } from '@soipack/packager';

import { createServer, type ServerConfig } from './index';
import type { FileScanner } from './scanner';

const TEST_SIGNING_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEICiI0Jsw2AjCiWk2uBb89bIQkOH18XHytA2TtblwFzgQ
-----END PRIVATE KEY-----
`;

const TEST_SIGNING_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAOCPbC2Pxenbum50JoDbus/HoZnN2okit05G+z44CvK8=
-----END PUBLIC KEY-----
`;

const LICENSE_PUBLIC_KEY_BASE64 = 'mXRQccwM4wyv+mmIQZjJWAqDDvD6wYn+c/DpB1w/x20=';

const minimalExample = (...segments: string[]): string =>
  path.resolve(__dirname, '../../..', 'examples', 'minimal', ...segments);

const demoLicensePath = path.resolve(__dirname, '../../..', 'data', 'licenses', 'demo-license.key');

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const createLogCapture = () => {
  const entries: Array<Record<string, unknown>> = [];
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      const lines = chunk
        .toString()
        .split(/\n/u)
        .map((line: string) => line.trim())
        .filter((line: string) => line.length > 0);
      lines.forEach((line: string) => {
        try {
          entries.push(JSON.parse(line));
        } catch {
          // Ignore malformed log lines.
        }
      });
      callback();
    },
  });
  const logger = pino({ level: 'info', base: undefined }, stream);
  return { logger, entries };
};

const flushLogs = async () => new Promise((resolve) => setImmediate(resolve));

const waitForJobCompletion = async (
  app: ReturnType<typeof createServer>,
  token: string,
  jobId: string,
) => {
  let lastResponse: request.Response | undefined;
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const response = await request(app)
      .get(`/v1/jobs/${jobId}`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    lastResponse = response;
    if (response.body.status === 'completed') {
      return response.body;
    }
    if (response.body.status === 'failed') {
      throw new Error(`Job ${jobId} failed: ${JSON.stringify(response.body.error)}`);
    }
    await delay(250);
  }
  throw new Error(`Job ${jobId} did not complete in time: ${JSON.stringify(lastResponse?.body)}`);
};

const waitForJobFailure = async (
  app: ReturnType<typeof createServer>,
  token: string,
  jobId: string,
) => {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const response = await request(app)
      .get(`/v1/jobs/${jobId}`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    if (response.body.status === 'failed') {
      return response.body;
    }
    if (response.body.status === 'completed') {
      throw new Error(`Job ${jobId} unexpectedly completed.`);
    }
    await delay(250);
  }
  throw new Error(`Job ${jobId} did not fail in time.`);
};

jest.setTimeout(60000);

describe('@soipack/server REST API', () => {
  const tenantId = 'tenant-a';
  const issuer = 'https://auth.test';
  const audience = 'soipack-api';
  const tenantClaim = 'tenant';
  const requiredScope = 'soipack.api';
  let token: string;
  let storageDir: string;
  let app: ReturnType<typeof createServer>;
  let signingKeyPath: string;
  let licensePublicKeyPath: string;
  let licenseHeader: string;
  let licenseExpiresAt: Date | undefined;
  let privateKey: KeyLike;
  let jwks: JSONWebKeySet;
  let baseConfig: ServerConfig;
  let metricsRegistry: Registry;
  let logEntries: Array<Record<string, unknown>>;

  const createAccessToken = async ({
    tenant = tenantId,
    subject = 'user-1',
    scope = requiredScope,
    expiresIn = '2h',
  }: {
    tenant?: string;
    subject?: string;
    scope?: string | null;
    expiresIn?: string | number;
  } = {}): Promise<string> => {
    const payload: Record<string, unknown> = { [tenantClaim]: tenant };
    if (scope) {
      payload.scope = scope;
    }

    return new SignJWT(payload)
      .setProtectedHeader({ alg: 'RS256', kid: jwks.keys[0].kid })
      .setIssuer(issuer)
      .setAudience(audience)
      .setSubject(subject)
      .setIssuedAt()
      .setExpirationTime(expiresIn)
      .sign(privateKey);
  };

  beforeAll(async () => {
    storageDir = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'soipack-server-test-'));
    signingKeyPath = path.join(storageDir, 'signing-key.pem');
    await fsPromises.writeFile(signingKeyPath, TEST_SIGNING_PRIVATE_KEY, 'utf8');
    licensePublicKeyPath = path.join(storageDir, 'license.pub');
    await fsPromises.writeFile(licensePublicKeyPath, LICENSE_PUBLIC_KEY_BASE64, 'utf8');
    const licenseContent = await fsPromises.readFile(demoLicensePath, 'utf8');
    licenseHeader = Buffer.from(licenseContent, 'utf8').toString('base64');
    const parsedLicense = JSON.parse(licenseContent) as { payload: string };
    const decodedPayload = JSON.parse(
      Buffer.from(parsedLicense.payload, 'base64').toString('utf8'),
    ) as { expiresAt?: string };
    licenseExpiresAt = decodedPayload.expiresAt ? new Date(decodedPayload.expiresAt) : undefined;

    const { publicKey, privateKey: generatedPrivateKey } = await generateKeyPair('RS256');
    privateKey = generatedPrivateKey;
    const publicJwk = (await exportJWK(publicKey)) as JWK;
    publicJwk.use = 'sig';
    publicJwk.alg = 'RS256';
    publicJwk.kid = 'test-key';
    jwks = { keys: [publicJwk] };

    const logCapture = createLogCapture();
    logEntries = logCapture.entries;
    metricsRegistry = new Registry();

    baseConfig = {
      auth: {
        issuer,
        audience,
        tenantClaim,
        jwks,
        requiredScopes: [requiredScope],
        clockToleranceSeconds: 0,
      },
      storageDir,
      signingKeyPath,
      licensePublicKeyPath,
      retention: {
        uploads: { maxAgeMs: 0 },
        analyses: { maxAgeMs: 0 },
        reports: { maxAgeMs: 0 },
        packages: { maxAgeMs: 0 },
      },
      logger: logCapture.logger,
      metricsRegistry,
    };

    app = createServer(baseConfig);

    token = await createAccessToken();
  });

  beforeEach(() => {
    metricsRegistry?.resetMetrics();
    if (logEntries) {
      logEntries.length = 0;
    }
  });

  afterAll(async () => {
    await fsPromises.rm(storageDir, { recursive: true, force: true });
  });

  it('rejects unauthorized requests', async () => {
    const response = await request(app).post('/v1/import').expect(401);
    expect(response.body.error.code).toBe('UNAUTHORIZED');
  });

  it('requires authorization for job and artifact endpoints', async () => {
    const jobList = await request(app).get('/v1/jobs').expect(401);
    expect(jobList.body.error.code).toBe('UNAUTHORIZED');

    const jobDetail = await request(app).get('/v1/jobs/test-job').expect(401);
    expect(jobDetail.body.error.code).toBe('UNAUTHORIZED');

    const manifestResponse = await request(app).get('/v1/manifests/abcd1234').expect(401);
    expect(manifestResponse.body.error.code).toBe('UNAUTHORIZED');

    const packageResponse = await request(app).get('/v1/packages/abcd1234').expect(401);
    expect(packageResponse.body.error.code).toBe('UNAUTHORIZED');

    const reportAsset = await request(app)
      .get('/v1/reports/abcd1234/compliance.html')
      .expect(401);
    expect(reportAsset.body.error.code).toBe('UNAUTHORIZED');
  });

  it('rejects tokens missing required scopes', async () => {
    const otherScopeToken = await createAccessToken({ scope: 'other.scope' });
    const response = await request(app)
      .get('/v1/jobs')
      .set('Authorization', `Bearer ${otherScopeToken}`)
      .expect(403);
    expect(response.body.error.code).toBe('INSUFFICIENT_SCOPE');
  });

  it('rejects expired tokens', async () => {
    const shortLivedToken = await createAccessToken({ expiresIn: '1s' });
    await delay(1600);
    const response = await request(app)
      .get('/v1/jobs')
      .set('Authorization', `Bearer ${shortLivedToken}`)
      .expect(401);
    expect(response.body.error.code).toBe('UNAUTHORIZED');
  });

  it('requires a license token for import requests', async () => {
    const response = await request(app)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
      .attach('reqif', minimalExample('spec.reqif'))
      .expect(401);

    expect(response.body.error.code).toBe('LICENSE_REQUIRED');
  });

  it('rejects invalid license tokens', async () => {
    const licenseJson = JSON.parse(Buffer.from(licenseHeader, 'base64').toString('utf8')) as {
      payload: string;
      signature: string;
    };
    const signatureBytes = Buffer.from(licenseJson.signature, 'base64');
    signatureBytes[0] ^= 0xff;
    licenseJson.signature = Buffer.from(signatureBytes).toString('base64');
    const tamperedHeader = Buffer.from(JSON.stringify(licenseJson), 'utf8').toString('base64');

    const response = await request(app)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', tamperedHeader)
      .attach('reqif', minimalExample('spec.reqif'))
      .expect(402);

    expect(response.body.error.code).toBe('LICENSE_INVALID');
  });

  it('rejects cached licenses once they expire', async () => {
    if (!licenseExpiresAt) {
      throw new Error('Demo lisansının son kullanma tarihi yok.');
    }
    const beforeExpiry = new Date(licenseExpiresAt.getTime() - 60_000);
    const afterExpiry = new Date(licenseExpiresAt.getTime() + 1_000);

    jest.useFakeTimers({
      now: beforeExpiry,
      doNotFake: ['setTimeout', 'setInterval', 'setImmediate'],
    });
    try {
      const futureToken = await createAccessToken();
      const projectBase = `license-expiry-${Date.now()}`;
      const primeResponse = await request(app)
        .post('/v1/import')
        .set('Authorization', `Bearer ${futureToken}`)
        .set('X-SOIPACK-License', licenseHeader)
        .attach('reqif', minimalExample('spec.reqif'))
        .attach('junit', minimalExample('results.xml'))
        .attach('lcov', minimalExample('lcov.info'))
        .field('projectName', 'Expiry Cache Project')
        .field('projectVersion', projectBase)
        .expect((response) => {
          if (![200, 202].includes(response.status)) {
            throw new Error(`Unexpected status while priming license cache: ${response.status}`);
          }
        });

      if (primeResponse.status === 202) {
        expect(primeResponse.body.error).toBeUndefined();
      }

      jest.setSystemTime(afterExpiry);

      const expiredResponse = await request(app)
        .post('/v1/import')
        .set('Authorization', `Bearer ${futureToken}`)
        .set('X-SOIPACK-License', licenseHeader)
        .attach('reqif', minimalExample('spec.reqif'))
        .attach('junit', minimalExample('results.xml'))
        .attach('lcov', minimalExample('lcov.info'))
        .field('projectName', 'Expiry Cache Project')
        .field('projectVersion', `${projectBase}-retry`)
        .expect(402);

      expect(expiredResponse.body.error.code).toBe('LICENSE_INVALID');
      expect(expiredResponse.body.error.message).toBe('Lisans süresi dolmuş.');
    } finally {
      jest.useRealTimers();
    }
  });

  it('requires a license token for analyze, report, and pack requests', async () => {
    const analyzeResponse = await request(app)
      .post('/v1/analyze')
      .set('Authorization', `Bearer ${token}`)
      .send({ importId: 'missing-import' })
      .expect(401);
    expect(analyzeResponse.body.error.code).toBe('LICENSE_REQUIRED');

    const reportResponse = await request(app)
      .post('/v1/report')
      .set('Authorization', `Bearer ${token}`)
      .send({ analysisId: 'missing-analysis' })
      .expect(401);
    expect(reportResponse.body.error.code).toBe('LICENSE_REQUIRED');

    const packResponse = await request(app)
      .post('/v1/pack')
      .set('Authorization', `Bearer ${token}`)
      .send({ reportId: 'missing-report' })
      .expect(401);
    expect(packResponse.body.error.code).toBe('LICENSE_REQUIRED');
  });

  it('enforces per-field size limits before queuing import jobs', async () => {
    const limitedStorageDir = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'soipack-limit-test-'));
    const limitedApp = createServer({
      ...baseConfig,
      storageDir: limitedStorageDir,
      maxUploadSizeBytes: 1024,
      uploadPolicies: {
        jira: { maxSizeBytes: 32, allowedMimeTypes: ['application/json'] },
      },
      metricsRegistry: new Registry(),
    });

    try {
      const response = await request(limitedApp)
        .post('/v1/import')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', licenseHeader)
        .attach('jira', Buffer.from('a'.repeat(64)), {
          filename: 'jira.json',
          contentType: 'application/json',
        })
        .expect(413);

      expect(response.body.error.code).toBe('FILE_TOO_LARGE');
      expect(response.body.error.details.limit).toBe(32);
    } finally {
      await fsPromises.rm(limitedStorageDir, { recursive: true, force: true });
    }
  });

  it('enforces the global upload size limit before processing files', async () => {
    const limitedStorageDir = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'soipack-global-limit-'));
    const limitedApp = createServer({
      ...baseConfig,
      storageDir: limitedStorageDir,
      maxUploadSizeBytes: 32,
      metricsRegistry: new Registry(),
    });

    try {
      const response = await request(limitedApp)
        .post('/v1/import')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', licenseHeader)
        .attach('reqif', Buffer.from('a'.repeat(128)), {
          filename: 'spec.reqif',
          contentType: 'application/xml',
        })
        .expect(500);

      expect(response.body.error.code).toBe('UNEXPECTED_ERROR');
      expect(response.body.error.details?.cause).toBe('File too large');
    } finally {
      await fsPromises.rm(limitedStorageDir, { recursive: true, force: true });
    }
  });

  it('rejects malicious uploads flagged by the scanning service', async () => {
    const scanningStorageDir = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'soipack-scan-test-'));
    const scanningScanner: FileScanner = {
      async scan(target) {
        if (target.field === 'jira') {
          return { clean: false, threat: 'EICAR-Test-File', engine: 'ClamAV' };
        }
        return { clean: true };
      },
    };
    const scanningApp = createServer({
      ...baseConfig,
      storageDir: scanningStorageDir,
      scanner: scanningScanner,
      metricsRegistry: new Registry(),
    });

    try {
      const response = await request(scanningApp)
        .post('/v1/import')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', licenseHeader)
        .attach('jira', Buffer.from('dummy content'), {
          filename: 'bad.zip',
          contentType: 'application/zip',
        })
        .expect(422);

      expect(response.body.error.code).toBe('FILE_SCAN_FAILED');
      expect(response.body.error.details.threat).toBe('EICAR-Test-File');
      expect(response.body.error.details.field).toBe('jira');
    } finally {
      await fsPromises.rm(scanningStorageDir, { recursive: true, force: true });
    }
  });

  it('rejects malformed import and pipeline payloads', async () => {
    const noFilesResponse = await request(app)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .field('projectName', 'No Files Project')
      .expect(400);
    expect(noFilesResponse.body.error.code).toBe('NO_INPUT_FILES');

    const invalidAnalyze = await request(app)
      .post('/v1/analyze')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .send({})
      .expect(400);
    expect(invalidAnalyze.body.error.code).toBe('INVALID_REQUEST');

    const invalidReport = await request(app)
      .post('/v1/report')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .send({})
      .expect(400);
    expect(invalidReport.body.error.code).toBe('INVALID_REQUEST');

    const invalidPack = await request(app)
      .post('/v1/pack')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .send({})
      .expect(400);
    expect(invalidPack.body.error.code).toBe('INVALID_REQUEST');
  });

  it('prevents path traversal when serving report assets', async () => {
    const importResponse = await request(app)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .attach('reqif', minimalExample('spec.reqif'))
      .attach('junit', minimalExample('results.xml'))
      .attach('lcov', minimalExample('lcov.info'))
      .field('projectName', 'Traversal Project')
      .field('projectVersion', '1.0.0')
      .expect(202);

    const importJob = await waitForJobCompletion(app, token, importResponse.body.id);

    const analyzeResponse = await request(app)
      .post('/v1/analyze')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .send({ importId: importJob.id })
      .expect(202);
    const analyzeJob = await waitForJobCompletion(app, token, analyzeResponse.body.id);

    const reportResponse = await request(app)
      .post('/v1/report')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .send({ analysisId: analyzeJob.id })
      .expect(202);
    await waitForJobCompletion(app, token, reportResponse.body.id);

    const traversalAttempt = await request(app)
      .get(`/v1/reports/${reportResponse.body.id}/../secrets.txt`)
      .set('Authorization', `Bearer ${token}`)
      .expect(400);

    expect(traversalAttempt.body.error.code).toBe('INVALID_PATH');
  });

  it('deduplicates concurrent import submissions targeting the same payload', async () => {
    const projectVersion = `concurrent-${Date.now()}`;

    const submitImport = () =>
      request(app)
        .post('/v1/import')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', licenseHeader)
        .attach('reqif', minimalExample('spec.reqif'))
        .attach('junit', minimalExample('results.xml'))
        .attach('lcov', minimalExample('lcov.info'))
        .field('projectName', 'Concurrent Project')
        .field('projectVersion', projectVersion);

    const [firstResponse, secondResponse, thirdResponse] = await Promise.all([
      submitImport(),
      submitImport(),
      submitImport(),
    ]);

    expect(firstResponse.body.id).toHaveLength(16);
    expect([200, 202]).toContain(firstResponse.status);
    if (firstResponse.status === 200) {
      expect(firstResponse.body.reused).toBe(false);
      expect(firstResponse.body.status).toBe('completed');
    }

    const ids = new Set([firstResponse.body.id, secondResponse.body.id, thirdResponse.body.id]);
    expect(ids.size).toBe(1);

    [secondResponse, thirdResponse].forEach((response) => {
      expect([200, 202]).toContain(response.status);
      if (response.status === 202) {
        expect(response.body.reused === undefined || response.body.reused === false).toBe(true);
        expect(response.body.status === 'queued' || response.body.status === 'running').toBe(true);
      } else {
        expect(response.body.reused).toBe(true);
      }
    });

    const jobId = firstResponse.body.id;
    const job = await waitForJobCompletion(app, token, jobId);
    expect(job.status).toBe('completed');

    const reuseResponse = await submitImport().expect(200);
    expect(reuseResponse.body.id).toBe(jobId);
    expect(reuseResponse.body.reused).toBe(true);
    expect(reuseResponse.body.result.outputs.workspace).toBe(job.result.outputs.workspace);
  });

  it('processes pipeline jobs asynchronously with idempotent reuse', async () => {
    const importResponse = await request(app)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .attach('reqif', minimalExample('spec.reqif'))
      .attach('junit', minimalExample('results.xml'))
      .attach('lcov', minimalExample('lcov.info'))
      .field('projectName', 'Minimal Project')
      .field('projectVersion', '1.0.0')
      .expect(202);

    expect(importResponse.body.id).toHaveLength(16);
    expect(importResponse.body.kind).toBe('import');
    expect(['queued', 'running']).toContain(importResponse.body.status);
    expect(importResponse.body.result).toBeUndefined();

    const importJob = await waitForJobCompletion(app, token, importResponse.body.id);
    expect(importJob.hash).toMatch(/^[a-f0-9]{64}$/u);
    expect(new Date(importJob.createdAt).getTime()).not.toBeNaN();
    expect(new Date(importJob.updatedAt).getTime()).not.toBeNaN();
    expect(importJob.result.outputs.workspace).toMatch(/^workspaces\//);
    expect(Array.isArray(importJob.result.warnings)).toBe(true);

    const uploadDir = path.join(storageDir, 'uploads', tenantId, importResponse.body.id);
    await expect(fsPromises.access(uploadDir, fs.constants.F_OK)).resolves.toBeUndefined();

    const importList = await request(app)
      .get('/v1/jobs')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    const importSummary = importList.body.jobs.find(
      (job: { id: string }) => job.id === importResponse.body.id,
    );
    expect(importSummary).toBeDefined();
    expect(importSummary.hash).toBe(importJob.hash);
    expect(new Date(importSummary.createdAt).getTime()).not.toBeNaN();
    expect(new Date(importSummary.updatedAt).getTime()).not.toBeNaN();

    const importReuse = await request(app)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .attach('reqif', minimalExample('spec.reqif'))
      .attach('junit', minimalExample('results.xml'))
      .attach('lcov', minimalExample('lcov.info'))
      .field('projectName', 'Minimal Project')
      .field('projectVersion', '1.0.0')
      .expect(200);

    expect(importReuse.body.id).toBe(importResponse.body.id);
    expect(importReuse.body.reused).toBe(true);
    expect(importReuse.body.result.outputs.workspace).toBe(importJob.result.outputs.workspace);

    const analyzeQueued = await request(app)
      .post('/v1/analyze')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .send({ importId: importResponse.body.id })
      .expect(202);

    expect(analyzeQueued.body.kind).toBe('analyze');
    expect(analyzeQueued.body.result).toBeUndefined();

    const analyzeJob = await waitForJobCompletion(app, token, analyzeQueued.body.id);
    expect(analyzeJob.result.outputs.snapshot).toMatch(/^analyses\//);
    expect(typeof analyzeJob.result.exitCode).toBe('number');

    const analyzeDetails = await request(app)
      .get(`/v1/jobs/${analyzeQueued.body.id}`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    expect(analyzeDetails.body.hash).toBe(analyzeJob.hash);
    expect(analyzeDetails.body.result.outputs.directory).toBe(analyzeJob.result.outputs.directory);

    const analyzeReuse = await request(app)
      .post('/v1/analyze')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .send({ importId: importResponse.body.id })
      .expect(200);
    expect(analyzeReuse.body.reused).toBe(true);
    expect(analyzeReuse.body.id).toBe(analyzeQueued.body.id);

    const reportQueued = await request(app)
      .post('/v1/report')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .send({ analysisId: analyzeQueued.body.id })
      .expect(202);

    const reportJob = await waitForJobCompletion(app, token, reportQueued.body.id);
    expect(reportJob.result.outputs.complianceHtml).toMatch(/^reports\//);

    const otherTenantToken = await createAccessToken({ tenant: 'tenant-b' });
    const crossTenantJob = await request(app)
      .get(`/v1/jobs/${importResponse.body.id}`)
      .set('Authorization', `Bearer ${otherTenantToken}`)
      .expect(404);
    expect(crossTenantJob.body.error.code).toBe('JOB_NOT_FOUND');

    const reportReuse = await request(app)
      .post('/v1/report')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .send({ analysisId: analyzeQueued.body.id })
      .expect(200);
    expect(reportReuse.body.reused).toBe(true);
    expect(reportReuse.body.id).toBe(reportQueued.body.id);

    const packQueued = await request(app)
      .post('/v1/pack')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .send({ reportId: reportQueued.body.id })
      .expect(202);

    const packJob = await waitForJobCompletion(app, token, packQueued.body.id);
    expect(packJob.result.outputs.archive).toMatch(/^packages\//);
    expect(packJob.result.manifestId).toHaveLength(12);

    const packDetails = await request(app)
      .get(`/v1/jobs/${packQueued.body.id}`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    expect(packDetails.body.result.outputs.archive).toBe(packJob.result.outputs.archive);
    expect(packDetails.body.result.manifestId).toBe(packJob.result.manifestId);

    const packReuse = await request(app)
      .post('/v1/pack')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .send({ reportId: reportQueued.body.id })
      .expect(200);
    expect(packReuse.body.reused).toBe(true);
    expect(packReuse.body.id).toBe(packQueued.body.id);

    const archivePath = path.resolve(storageDir, packJob.result.outputs.archive);
    await expect(fsPromises.access(archivePath, fs.constants.F_OK)).resolves.toBeUndefined();

    const manifestPath = path.resolve(storageDir, packJob.result.outputs.manifest);
    const manifestDir = path.dirname(manifestPath);
    const signaturePath = path.join(manifestDir, 'manifest.sig');
    const manifest = JSON.parse(await fsPromises.readFile(manifestPath, 'utf8')) as Manifest;
    const signature = (await fsPromises.readFile(signaturePath, 'utf8')).trim();
    expect(verifyManifestSignature(manifest, signature, TEST_SIGNING_PUBLIC_KEY)).toBe(true);

    const packFilter = await request(app)
      .get('/v1/jobs')
      .query({ kind: 'pack' })
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    expect(packFilter.body.jobs.some((job: { id: string }) => job.id === packQueued.body.id)).toBe(true);
    expect(packFilter.body.jobs.every((job: { kind: string }) => job.kind === 'pack')).toBe(true);

    const completedFilter = await request(app)
      .get('/v1/jobs')
      .query({ status: 'completed' })
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    expect(completedFilter.body.jobs.every((job: { status: string }) => job.status === 'completed')).toBe(true);

    const combinedFilter = await request(app)
      .get('/v1/jobs')
      .query({ kind: 'pack', status: 'completed' })
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    expect(combinedFilter.body.jobs).toHaveLength(1);
    expect(combinedFilter.body.jobs[0].id).toBe(packQueued.body.id);

    const manifestResponse = await request(app)
      .get(`/v1/manifests/${packJob.result.manifestId}`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    expect(manifestResponse.body.manifestId).toBe(packJob.result.manifestId);
    expect(manifestResponse.body.jobId).toBe(packQueued.body.id);
    expect(manifestResponse.body.manifest).toEqual(manifest);

    const manifestForbidden = await request(app)
      .get(`/v1/manifests/${packJob.result.manifestId}`)
      .set('Authorization', `Bearer ${otherTenantToken}`)
      .expect(404);
    expect(manifestForbidden.body.error.code).toBe('MANIFEST_NOT_FOUND');

    const packageDownload = await request(app)
      .get(`/v1/packages/${packQueued.body.id}/archive`)
      .set('Authorization', `Bearer ${token}`)
      .buffer(true)
      .parse((res, callback) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => callback(null, Buffer.concat(chunks)));
      })
      .expect('Content-Type', /zip|octet-stream/)
      .expect(200);
    expect(packageDownload.headers['content-disposition']).toContain('.zip');
    expect(Buffer.isBuffer(packageDownload.body)).toBe(true);
    expect((packageDownload.body as Buffer).length).toBeGreaterThan(0);

    const manifestDownload = await request(app)
      .get(`/v1/packages/${packQueued.body.id}/manifest`)
      .set('Authorization', `Bearer ${token}`)
      .buffer(true)
      .parse((res, callback) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
        res.on('end', () => callback(null, Buffer.concat(chunks)));
      })
      .expect('Content-Type', /application\/json/)
      .expect(200);
    expect(manifestDownload.headers['content-disposition']).toContain('.json');
    const downloadedManifest = JSON.parse((manifestDownload.body as Buffer).toString('utf8')) as Manifest;
    expect(downloadedManifest).toEqual(manifest);

    const packageForbidden = await request(app)
      .get(`/v1/packages/${packQueued.body.id}/archive`)
      .set('Authorization', `Bearer ${otherTenantToken}`)
      .expect(404);
    expect(packageForbidden.body.error.code).toBe('PACKAGE_NOT_FOUND');

    const manifestForbiddenDownload = await request(app)
      .get(`/v1/packages/${packQueued.body.id}/manifest`)
      .set('Authorization', `Bearer ${otherTenantToken}`)
      .expect(404);
    expect(manifestForbiddenDownload.body.error.code).toBe('PACKAGE_NOT_FOUND');

    const reportAsset = await request(app)
      .get(`/v1/reports/${reportQueued.body.id}/compliance.html`)
      .set('Authorization', `Bearer ${token}`)
      .expect('Content-Type', /html/)
      .expect(200);

    expect(reportAsset.text).toContain('<html');

    const reportDetails = await request(app)
      .get(`/v1/jobs/${reportQueued.body.id}`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    expect(reportDetails.body.result.outputs.complianceHtml).toBe(
      reportJob.result.outputs.complianceHtml,
    );

    const forbiddenAsset = await request(app)
      .get(`/v1/reports/${reportQueued.body.id}/compliance.html`)
      .set('Authorization', `Bearer ${otherTenantToken}`)
      .expect(404);
    expect(forbiddenAsset.body.error.code).toBe('NOT_FOUND');

    const cleanupResponse = await request(app)
      .post('/v1/admin/cleanup')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    expect(cleanupResponse.body.status).toBe('ok');
    expect(Array.isArray(cleanupResponse.body.summary)).toBe(true);
    const summaryByTarget = Object.fromEntries(
      cleanupResponse.body.summary.map((entry: { target: string }) => [entry.target, entry]),
    );

    (['uploads', 'analyses', 'reports', 'packages'] as const).forEach((target) => {
      expect(summaryByTarget[target]).toMatchObject({
        configured: true,
        retained: 0,
        skipped: 0,
      });
      expect(summaryByTarget[target].removed).toBeGreaterThanOrEqual(1);
    });

    await expect(fsPromises.access(uploadDir, fs.constants.F_OK)).rejects.toThrow();
    await expect(
      fsPromises.access(
        path.join(storageDir, 'workspaces', tenantId, importResponse.body.id),
        fs.constants.F_OK,
      ),
    ).rejects.toThrow();
    await expect(
      fsPromises.access(
        path.join(storageDir, 'analyses', tenantId, analyzeQueued.body.id),
        fs.constants.F_OK,
      ),
    ).rejects.toThrow();
    await expect(
      fsPromises.access(path.join(storageDir, 'reports', tenantId, reportQueued.body.id), fs.constants.F_OK),
    ).rejects.toThrow();
    await expect(
      fsPromises.access(path.join(storageDir, 'packages', tenantId, packQueued.body.id), fs.constants.F_OK),
    ).rejects.toThrow();

    await request(app)
      .get(`/v1/manifests/${packJob.result.manifestId}`)
      .set('Authorization', `Bearer ${token}`)
      .expect(404);

    await request(app)
      .get(`/v1/packages/${packQueued.body.id}/archive`)
      .set('Authorization', `Bearer ${token}`)
      .expect(404);

    await request(app)
      .get(`/v1/packages/${packQueued.body.id}/manifest`)
      .set('Authorization', `Bearer ${token}`)
      .expect(404);
  });

  it('supports cancelling queued jobs and deleting finished jobs', async () => {
    const firstImport = await request(app)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .attach('reqif', minimalExample('spec.reqif'))
      .attach('junit', minimalExample('results.xml'))
      .attach('lcov', minimalExample('lcov.info'))
      .field('projectName', 'Queued Project')
      .field('projectVersion', '1.0.0')
      .expect(202);

    let firstJobRunning = false;
    for (let attempt = 0; attempt < 20; attempt += 1) {
      const statusResponse = await request(app)
        .get(`/v1/jobs/${firstImport.body.id}`)
        .set('Authorization', `Bearer ${token}`)
        .expect(200);
      if (statusResponse.body.status === 'running') {
        firstJobRunning = true;
        break;
      }
      await delay(50);
    }
    expect(firstJobRunning).toBe(true);

    const secondImport = await request(app)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .attach('reqif', minimalExample('spec.reqif'))
      .attach('junit', minimalExample('results.xml'))
      .attach('lcov', minimalExample('lcov.info'))
      .field('projectName', 'Queued Project')
      .field('projectVersion', '2.0.0')
      .expect(202);

    expect(secondImport.body.status).toBe('queued');
    expect(secondImport.body.id).not.toBe(firstImport.body.id);

    const cancelResponse = await request(app)
      .post(`/v1/jobs/${secondImport.body.id}/cancel`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    expect(cancelResponse.body.status).toBe('cancelled');

    await request(app)
      .get(`/v1/jobs/${secondImport.body.id}`)
      .set('Authorization', `Bearer ${token}`)
      .expect(404);

    const cancelledWorkspace = path.join(storageDir, 'workspaces', tenantId, secondImport.body.id);
    await expect(fsPromises.access(cancelledWorkspace, fs.constants.F_OK)).rejects.toThrow();
    const cancelledUploads = path.join(storageDir, 'uploads', tenantId, secondImport.body.id);
    await expect(fsPromises.access(cancelledUploads, fs.constants.F_OK)).rejects.toThrow();

    await waitForJobCompletion(app, token, firstImport.body.id);

    const deleteResponse = await request(app)
      .delete(`/v1/jobs/${firstImport.body.id}`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    expect(deleteResponse.body.status).toBe('deleted');

    await request(app)
      .get(`/v1/jobs/${firstImport.body.id}`)
      .set('Authorization', `Bearer ${token}`)
      .expect(404);

    const deletedWorkspace = path.join(storageDir, 'workspaces', tenantId, firstImport.body.id);
    await expect(fsPromises.access(deletedWorkspace, fs.constants.F_OK)).rejects.toThrow();
    const deletedUploads = path.join(storageDir, 'uploads', tenantId, firstImport.body.id);
    await expect(fsPromises.access(deletedUploads, fs.constants.F_OK)).rejects.toThrow();
  });

  it('emits structured logs and metrics for successful jobs', async () => {
    const projectVersion = `1.0.${Date.now()}`;
    const importResponse = await request(app)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .attach('reqif', minimalExample('spec.reqif'))
      .attach('junit', minimalExample('results.xml'))
      .attach('lcov', minimalExample('lcov.info'))
      .field('projectName', 'Observability Project')
      .field('projectVersion', projectVersion)
      .expect(202);

    const importId: string = importResponse.body.id;
    await waitForJobCompletion(app, token, importId);

    const reuseResponse = await request(app)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
      .set('X-SOIPACK-License', licenseHeader)
      .attach('reqif', minimalExample('spec.reqif'))
      .attach('junit', minimalExample('results.xml'))
      .attach('lcov', minimalExample('lcov.info'))
      .field('projectName', 'Observability Project')
      .field('projectVersion', projectVersion)
      .expect(200);

    expect(reuseResponse.body.reused).toBe(true);

    await flushLogs();

    const creationLog = logEntries.find(
      (entry) => entry.event === 'job_created' && entry.jobId === importId,
    ) as Record<string, unknown> | undefined;
    expect(creationLog).toMatchObject({ tenantId, kind: 'import' });

    const completionLog = logEntries.find(
      (entry) => entry.event === 'job_completed' && entry.jobId === importId,
    ) as Record<string, unknown> | undefined;
    expect(completionLog).toBeDefined();
    expect(typeof completionLog?.durationMs).toBe('number');

    const reuseLog = logEntries.find(
      (entry) => entry.event === 'job_reused' && entry.jobId === importId,
    ) as Record<string, unknown> | undefined;
    expect(reuseLog).toMatchObject({ tenantId, kind: 'import', status: 'completed' });

    const metricsResponse = await request(app)
      .get('/metrics')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    const metricsLines = metricsResponse.text.split('\n');

    const durationLine = metricsLines.find((line) =>
      line.startsWith(
        `soipack_job_duration_seconds_count{tenantId="${tenantId}",kind="import",status="completed"}`,
      ),
    );
    expect(durationLine).toBe(
      `soipack_job_duration_seconds_count{tenantId="${tenantId}",kind="import",status="completed"} 1`,
    );

    const queueLine = metricsLines.find((line) =>
      line.startsWith(`soipack_job_queue_depth{tenantId="${tenantId}"}`),
    );
    expect(queueLine).toBe(`soipack_job_queue_depth{tenantId="${tenantId}"} 0`);

    const errorLine = metricsLines.find((line) =>
      line.startsWith(`soipack_job_errors_total{tenantId="${tenantId}",kind="import"`),
    );
    if (errorLine) {
      expect(errorLine.endsWith(' 0')).toBe(true);
    }
  });

  it('emits metrics and logs when a job fails', async () => {
    const failingStorageDir = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'soipack-fail-test-'));
    const failingSigningKeyPath = path.join(failingStorageDir, 'signing-key.pem');
    await fsPromises.writeFile(failingSigningKeyPath, TEST_SIGNING_PRIVATE_KEY, 'utf8');

    const failingLogCapture = createLogCapture();
    const failingRegistry = new Registry();

    const failingApp = createServer({
      ...baseConfig,
      storageDir: failingStorageDir,
      signingKeyPath: failingSigningKeyPath,
      logger: failingLogCapture.logger,
      metricsRegistry: failingRegistry,
    });

    try {
      const importResponse = await request(failingApp)
        .post('/v1/import')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', licenseHeader)
        .attach('reqif', minimalExample('spec.reqif'))
        .attach('junit', minimalExample('results.xml'))
        .attach('lcov', minimalExample('lcov.info'))
        .field('projectName', 'Failing Project')
        .field('projectVersion', '1.0.0')
        .expect(202);
      const importId: string = importResponse.body.id;
      await waitForJobCompletion(failingApp, token, importId);

      const analyzeResponse = await request(failingApp)
        .post('/v1/analyze')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', licenseHeader)
        .send({ importId })
        .expect(202);
      const analyzeId: string = analyzeResponse.body.id;
      await waitForJobCompletion(failingApp, token, analyzeId);

      const reportResponse = await request(failingApp)
        .post('/v1/report')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', licenseHeader)
        .send({ analysisId: analyzeId })
        .expect(202);
      const reportId: string = reportResponse.body.id;
      await waitForJobCompletion(failingApp, token, reportId);

      await fsPromises.rm(failingSigningKeyPath);

      const packResponse = await request(failingApp)
        .post('/v1/pack')
        .set('Authorization', `Bearer ${token}`)
        .set('X-SOIPACK-License', licenseHeader)
        .send({ reportId })
        .expect(202);

      const failedJob = await waitForJobFailure(failingApp, token, packResponse.body.id);
      expect(failedJob.status).toBe('failed');

      await flushLogs();

      const packCreationLog = failingLogCapture.entries.find(
        (entry) => entry.event === 'job_created' && entry.jobId === packResponse.body.id,
      ) as Record<string, unknown> | undefined;
      expect(packCreationLog).toMatchObject({ tenantId, kind: 'pack' });

      const failureLog = failingLogCapture.entries.find(
        (entry) => entry.event === 'job_failed' && entry.jobId === packResponse.body.id,
      ) as Record<string, unknown> | undefined;
      expect(failureLog).toMatchObject({ tenantId, kind: 'pack' });
      expect((failureLog?.error as { code?: string } | undefined)?.code).toBe('PIPELINE_ERROR');

      const metricsResponse = await request(failingApp)
        .get('/metrics')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);
      const metricsLines = metricsResponse.text.split('\n');

      const failureDurationLine = metricsLines.find((line) =>
        line.startsWith(
          `soipack_job_duration_seconds_count{tenantId="${tenantId}",kind="pack",status="failed"}`,
        ),
      );
      expect(failureDurationLine).toBe(
        `soipack_job_duration_seconds_count{tenantId="${tenantId}",kind="pack",status="failed"} 1`,
      );

      const errorLine = metricsLines.find((line) =>
        line.startsWith(
          `soipack_job_errors_total{tenantId="${tenantId}",kind="pack",code="PIPELINE_ERROR"}`,
        ),
      );
      expect(errorLine).toBe(
        `soipack_job_errors_total{tenantId="${tenantId}",kind="pack",code="PIPELINE_ERROR"} 1`,
      );

      const queueDepthLine = metricsLines.find((line) =>
        line.startsWith(`soipack_job_queue_depth{tenantId="${tenantId}"}`),
      );
      expect(queueDepthLine).toBe(`soipack_job_queue_depth{tenantId="${tenantId}"} 0`);
    } finally {
      await fsPromises.rm(failingStorageDir, { recursive: true, force: true });
    }
  });
});

