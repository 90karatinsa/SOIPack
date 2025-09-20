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

jest.setTimeout(30000);

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

  it('executes pipeline end-to-end with idempotent stages', async () => {
    const firstImport = await request(app)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
      .attach('reqif', minimalExample('spec.reqif'))
      .attach('junit', minimalExample('results.xml'))
      .attach('lcov', minimalExample('lcov.info'))
      .field('projectName', 'Minimal Project')
      .field('projectVersion', '1.0.0')
      .expect(200);

    expect(firstImport.body.id).toHaveLength(16);
    expect(firstImport.body.reused).toBe(false);
    expect(Array.isArray(firstImport.body.warnings)).toBe(true);

    const secondImport = await request(app)
      .post('/v1/import')
      .set('Authorization', `Bearer ${token}`)
      .attach('reqif', minimalExample('spec.reqif'))
      .attach('junit', minimalExample('results.xml'))
      .attach('lcov', minimalExample('lcov.info'))
      .field('projectName', 'Minimal Project')
      .field('projectVersion', '1.0.0')
      .expect(200);

    expect(secondImport.body.id).toBe(firstImport.body.id);
    expect(secondImport.body.reused).toBe(true);

    const analyzeResponse = await request(app)
      .post('/v1/analyze')
      .set('Authorization', `Bearer ${token}`)
      .send({ importId: firstImport.body.id })
      .expect(200);

    expect(analyzeResponse.body.id).toHaveLength(16);
    expect(analyzeResponse.body.reused).toBe(false);
    expect(typeof analyzeResponse.body.exitCode).toBe('number');

    const analyzeReused = await request(app)
      .post('/v1/analyze')
      .set('Authorization', `Bearer ${token}`)
      .send({ importId: firstImport.body.id })
      .expect(200);

    expect(analyzeReused.body.id).toBe(analyzeResponse.body.id);
    expect(analyzeReused.body.reused).toBe(true);

    const reportResponse = await request(app)
      .post('/v1/report')
      .set('Authorization', `Bearer ${token}`)
      .send({ analysisId: analyzeResponse.body.id })
      .expect(200);

    expect(reportResponse.body.reused).toBe(false);
    expect(reportResponse.body.outputs.complianceHtml).toMatch(/^reports\//);

    const reportReused = await request(app)
      .post('/v1/report')
      .set('Authorization', `Bearer ${token}`)
      .send({ analysisId: analyzeResponse.body.id })
      .expect(200);

    expect(reportReused.body.id).toBe(reportResponse.body.id);
    expect(reportReused.body.reused).toBe(true);

    const packResponse = await request(app)
      .post('/v1/pack')
      .set('Authorization', `Bearer ${token}`)
      .send({ reportId: reportResponse.body.id })
      .expect(200);

    expect(packResponse.body.manifestId).toHaveLength(12);
    expect(packResponse.body.outputs.archive).toMatch(/^packages\//);

    const archivePath = path.resolve(storageDir, packResponse.body.outputs.archive);
    await expect(fsPromises.access(archivePath, fs.constants.F_OK)).resolves.toBeUndefined();

    const manifestPath = path.resolve(storageDir, packResponse.body.outputs.manifest);
    const manifestDir = path.dirname(manifestPath);
    const signaturePath = path.join(manifestDir, 'manifest.sig');
    const manifest = JSON.parse(await fsPromises.readFile(manifestPath, 'utf8')) as Manifest;
    const signature = (await fsPromises.readFile(signaturePath, 'utf8')).trim();
    expect(verifyManifestSignature(manifest, signature, TEST_SIGNING_PUBLIC_KEY)).toBe(true);

    const reportAsset = await request(app)
      .get(`/v1/reports/${reportResponse.body.id}/compliance.html`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    expect(reportAsset.text).toContain('<html');
  });
});

