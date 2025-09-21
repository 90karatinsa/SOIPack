import { createHash, generateKeyPairSync } from 'crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import path from 'path';

import { Manifest } from '@soipack/core';

import {
  buildManifest,
  createSoiDataPack,
  signManifest,
  verifyManifestSignature,
  ManifestBuildResult,
} from './index';

const computeSha256 = (filePath: string): string => {
  const hash = createHash('sha256');
  hash.update(readFileSync(filePath));
  return hash.digest('hex');
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

  it('signs and verifies manifests with Ed25519 keys', () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const privateKeyPem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
    const publicKeyPem = publicKey.export({ format: 'pem', type: 'spki' }).toString();

    const signature = signManifest(manifestResult.manifest, privateKeyPem);
    expect(verifyManifestSignature(manifestResult.manifest, signature, publicKeyPem)).toBe(true);

    const tamperedManifest: Manifest = {
      ...manifestResult.manifest,
      files: manifestResult.manifest.files.map((file, index) =>
        index === 0 ? { ...file, sha256: `${file.sha256.slice(0, -1)}0` } : file,
      ),
    };

    expect(verifyManifestSignature(tamperedManifest, signature, publicKeyPem)).toBe(false);
  });

  it('packages reports and evidence into a signed archive', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const privateKeyPem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
    const publicKeyPem = publicKey.export({ format: 'pem', type: 'spki' }).toString();

    const workDir = mkdtempSync(path.join(tmpdir(), 'soipack-packager-'));
    const keyPath = path.join(workDir, 'ed25519.pem');
    writeFileSync(keyPath, privateKeyPem, 'utf8');

    try {
      const result = await createSoiDataPack({
        reportDir,
        evidenceDirs: [evidenceDir],
        toolVersion,
        privateKeyPath: keyPath,
        outputDir: workDir,
        now: timestamp,
      });

      expect(path.basename(result.outputPath)).toBe('soi-pack-20240201_1015.zip');
      expect(existsSync(result.outputPath)).toBe(true);
      expect(result.manifest).toEqual(expectedManifest);
      expect(verifyManifestSignature(result.manifest, result.signature, publicKeyPem)).toBe(true);
    } finally {
      rmSync(workDir, { recursive: true, force: true });
    }
  });
});
