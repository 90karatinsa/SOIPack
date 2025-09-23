import { createHash, X509Certificate } from 'crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import path from 'path';

import { Manifest } from '@soipack/core';

import {
  ManifestBuildResult,
  buildManifest,
  createSoiDataPack,
  signManifestBundle,
  verifyManifestSignature,
  verifyManifestSignatureDetailed,
} from './index';

const computeSha256 = (filePath: string): string => {
  const hash = createHash('sha256');
  hash.update(readFileSync(filePath));
  return hash.digest('hex');
};

const DEV_CERT_BUNDLE_PATH = path.resolve(__dirname, '../../../test/certs/dev.pem');
const CERTIFICATE_PATTERN = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/;

const loadDevCredentials = (): { bundlePem: string; certificatePem: string; publicKeyPem: string } => {
  const bundlePem = readFileSync(DEV_CERT_BUNDLE_PATH, 'utf8');
  const certificateMatch = bundlePem.match(CERTIFICATE_PATTERN);
  if (!certificateMatch) {
    throw new Error('Dev sertifikası bulunamadı.');
  }
  const certificate = new X509Certificate(certificateMatch[0]);
  const publicKeyPem = certificate.publicKey.export({ format: 'pem', type: 'spki' }).toString();
  return { bundlePem, certificatePem: certificateMatch[0], publicKeyPem };
};

describe('packager', () => {
  const fixturesRoot = path.join(__dirname, '__fixtures__');
  const reportDir = path.join(fixturesRoot, 'report');
  const evidenceDir = path.join(fixturesRoot, 'evidence', 'sample');
  const timestamp = new Date('2024-02-01T10:15:00Z');
  const toolVersion = '0.2.0';

  let manifestResult: ManifestBuildResult;
  let expectedManifest: Manifest;

  beforeAll(async () => {
    manifestResult = await buildManifest({
      reportDir,
      evidenceDirs: [evidenceDir],
      toolVersion,
      now: timestamp,
    });

    expectedManifest = {
      createdAt: timestamp.toISOString(),
      toolVersion,
      files: [
        {
          path: 'evidence/sample/log.csv',
          sha256: computeSha256(path.join(evidenceDir, 'log.csv')),
        },
        {
          path: 'reports/subdir/details.json',
          sha256: computeSha256(path.join(reportDir, 'subdir', 'details.json')),
        },
        {
          path: 'reports/summary.txt',
          sha256: computeSha256(path.join(reportDir, 'summary.txt')),
        },
      ],
    };
  });

  it('produces a deterministic manifest for fixture directories', () => {
    expect(manifestResult.manifest).toEqual(expectedManifest);
  });

  it('signs and verifies manifests with Ed25519 credentials', () => {
    const { bundlePem, certificatePem, publicKeyPem } = loadDevCredentials();

    const signature = signManifestBundle(manifestResult.manifest, { bundlePem }).signature;
    expect(verifyManifestSignature(manifestResult.manifest, signature, certificatePem)).toBe(true);
    expect(verifyManifestSignature(manifestResult.manifest, signature, publicKeyPem)).toBe(true);

    const tamperedManifest: Manifest = {
      ...manifestResult.manifest,
      files: manifestResult.manifest.files.map((file, index) =>
        index === 0 ? { ...file, sha256: `${file.sha256.slice(0, -1)}0` } : file,
      ),
    };

    const detailed = verifyManifestSignatureDetailed(tamperedManifest, signature, { certificatePem });
    expect(detailed.valid).toBe(false);
    expect(detailed.reason).toBe('DIGEST_MISMATCH');
  });

  it('packages reports and evidence into a signed archive', async () => {
    const workDir = mkdtempSync(path.join(tmpdir(), 'soipack-packager-'));
    const bundlePath = path.join(workDir, 'dev.pem');
    const { bundlePem, certificatePem, publicKeyPem } = loadDevCredentials();
    writeFileSync(bundlePath, bundlePem, 'utf8');

    try {
      const result = await createSoiDataPack({
        reportDir,
        evidenceDirs: [evidenceDir],
        toolVersion,
        credentialsPath: bundlePath,
        outputDir: workDir,
        now: timestamp,
      });

      expect(path.basename(result.outputPath)).toBe('soi-pack-20240201_1015.zip');
      expect(existsSync(result.outputPath)).toBe(true);
      expect(result.manifest).toEqual(expectedManifest);
      expect(verifyManifestSignature(result.manifest, result.signature, certificatePem)).toBe(true);
      expect(verifyManifestSignature(result.manifest, result.signature, publicKeyPem)).toBe(true);
    } finally {
      rmSync(workDir, { recursive: true, force: true });
    }
  });
});
