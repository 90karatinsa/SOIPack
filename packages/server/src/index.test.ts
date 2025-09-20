import fs, { promises as fsPromises } from 'fs';
import os from 'os';
import path from 'path';

import request from 'supertest';

import { Manifest } from '@soipack/core';
import { verifyManifestSignature } from '@soipack/packager';

import { createServer } from './index';

const TEST_SIGNING_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEICiI0Jsw2AjCiWk2uBb89bIQkOH18XHytA2TtblwFzgQ
-----END PRIVATE KEY-----
`;

const TEST_SIGNING_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAOCPbC2Pxenbum50JoDbus/HoZnN2okit05G+z44CvK8=
-----END PUBLIC KEY-----
`;

const minimalExample = (...segments: string[]): string =>
  path.resolve(__dirname, '../../..', 'examples', 'minimal', ...segments);

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

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

jest.setTimeout(60000);

describe('@soipack/server REST API', () => {
  const token = 'test-token';
  let storageDir: string;
  let app: ReturnType<typeof createServer>;
  let signingKeyPath: string;

  beforeAll(async () => {
    storageDir = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'soipack-server-test-'));
    signingKeyPath = path.join(storageDir, 'signing-key.pem');
    await fsPromises.writeFile(signingKeyPath, TEST_SIGNING_PRIVATE_KEY, 'utf8');
    app = createServer({ token, storageDir, signingKeyPath });
  });

  afterAll(async () => {
    await fsPromises.rm(storageDir, { recursive: true, force: true });
  });

  it('rejects unauthorized requests', async () => {
    const response = await request(app).post('/v1/import').expect(401);
    expect(response.body.error.code).toBe('UNAUTHORIZED');
  });

  it('processes pipeline jobs asynchronously with idempotent reuse', async () => {
    const importResponse = await request(app)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
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
    expect(importJob.result.outputs.workspace).toMatch(/^workspaces\//);
    expect(Array.isArray(importJob.result.warnings)).toBe(true);

    const importList = await request(app)
      .get('/v1/jobs')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    expect(importList.body.jobs.some((job: { id: string }) => job.id === importResponse.body.id)).toBe(true);

    const importReuse = await request(app)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
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
      .send({ importId: importResponse.body.id })
      .expect(202);

    expect(analyzeQueued.body.kind).toBe('analyze');
    expect(analyzeQueued.body.result).toBeUndefined();

    const analyzeJob = await waitForJobCompletion(app, token, analyzeQueued.body.id);
    expect(analyzeJob.result.outputs.snapshot).toMatch(/^analyses\//);
    expect(typeof analyzeJob.result.exitCode).toBe('number');

    const analyzeReuse = await request(app)
      .post('/v1/analyze')
      .set('Authorization', `Bearer ${token}`)
      .send({ importId: importResponse.body.id })
      .expect(200);
    expect(analyzeReuse.body.reused).toBe(true);
    expect(analyzeReuse.body.id).toBe(analyzeQueued.body.id);

    const reportQueued = await request(app)
      .post('/v1/report')
      .set('Authorization', `Bearer ${token}`)
      .send({ analysisId: analyzeQueued.body.id })
      .expect(202);

    const reportJob = await waitForJobCompletion(app, token, reportQueued.body.id);
    expect(reportJob.result.outputs.complianceHtml).toMatch(/^reports\//);

    const reportReuse = await request(app)
      .post('/v1/report')
      .set('Authorization', `Bearer ${token}`)
      .send({ analysisId: analyzeQueued.body.id })
      .expect(200);
    expect(reportReuse.body.reused).toBe(true);
    expect(reportReuse.body.id).toBe(reportQueued.body.id);

    const packQueued = await request(app)
      .post('/v1/pack')
      .set('Authorization', `Bearer ${token}`)
      .send({ reportId: reportQueued.body.id })
      .expect(202);

    const packJob = await waitForJobCompletion(app, token, packQueued.body.id);
    expect(packJob.result.outputs.archive).toMatch(/^packages\//);
    expect(packJob.result.manifestId).toHaveLength(12);

    const packReuse = await request(app)
      .post('/v1/pack')
      .set('Authorization', `Bearer ${token}`)
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

    const reportAsset = await request(app)
      .get(`/v1/reports/${reportQueued.body.id}/compliance.html`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    expect(reportAsset.text).toContain('<html');
  });
});

