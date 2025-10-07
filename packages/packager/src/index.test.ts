import { createHash, X509Certificate } from 'crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import path from 'path';

import {
  Manifest,
  ManifestFileEntry,
  ManifestMerkleSummary,
  appendEntry,
  createLedger,
  deserializeLedgerProof,
  generateLedgerProof,
  serializeLedgerProof,
  verifyLedgerProof,
} from '@soipack/core';

import {
  ManifestBuildResult,
  buildManifest,
  createSoiDataPack,
  computeManifestDigestHex,
  signManifestBundle,
  verifyManifestSignature,
  verifyManifestSignatureDetailed,
  LedgerAwareManifest,
  ManifestLedgerOptions,
} from './index';

jest.setTimeout(60000);

const computeSha256 = (filePath: string): string => {
  const hash = createHash('sha256');
  hash.update(readFileSync(filePath));
  return hash.digest('hex');
};

const DEV_CERT_BUNDLE_PATH = path.resolve(__dirname, '../../../test/certs/dev.pem');
const CMS_CERT_BUNDLE_PATH = path.resolve(__dirname, '../../../test/certs/cms-test.pem');
const CERTIFICATE_PATTERN = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/;
const DEFAULT_MANIFEST_PROOF_SNAPSHOT_ID = 'manifest-files';

const buildManifestSnapshotId = (digest: string, stage?: string | null): string =>
  stage ? `manifest:${stage}:${digest}` : `manifest:${digest}`;

const buildEvidenceSnapshotId = (stage?: string | null): string =>
  stage ? `${DEFAULT_MANIFEST_PROOF_SNAPSHOT_ID}:${stage}` : DEFAULT_MANIFEST_PROOF_SNAPSHOT_ID;

const computeExpectedMerkleArtifacts = (
  manifest: LedgerAwareManifest,
): { merkle: ManifestMerkleSummary; files: ManifestFileEntry[] } => {
  const digest = computeManifestDigestHex(manifest);
  const stage = manifest.stage ?? null;
  const ledger = appendEntry(createLedger(), {
    snapshotId: buildManifestSnapshotId(digest, stage),
    manifestDigest: digest,
    timestamp: manifest.createdAt,
    evidence: manifest.files.map((file) => ({
      snapshotId: buildEvidenceSnapshotId(stage),
      path: file.path,
      hash: file.sha256,
    })),
  });
  const entry = ledger.entries[ledger.entries.length - 1];

  const merkle: ManifestMerkleSummary = {
    algorithm: 'ledger-merkle-v1',
    root: entry.merkleRoot,
    manifestDigest: digest,
    snapshotId: entry.snapshotId,
  };

  const filesWithProofs = manifest.files.map((file) => {
    const proof = generateLedgerProof(entry, {
      type: 'evidence',
      snapshotId: buildEvidenceSnapshotId(stage),
      path: file.path,
      hash: file.sha256,
    });
    return {
      ...file,
      proof: {
        algorithm: 'ledger-merkle-v1' as const,
        merkleRoot: entry.merkleRoot,
        proof: serializeLedgerProof(proof),
      },
    };
  });

  return { merkle, files: filesWithProofs };
};

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

const loadCmsCredentials = (): { bundlePem: string; certificatePem: string } => {
  const bundlePem = readFileSync(CMS_CERT_BUNDLE_PATH, 'utf8');
  const certificateMatch = bundlePem.match(CERTIFICATE_PATTERN);
  if (!certificateMatch) {
    throw new Error('CMS sertifikası bulunamadı.');
  }
  return { bundlePem, certificatePem: certificateMatch[0] };
};
 
describe('packager', () => {
  const fixturesRoot = path.join(__dirname, '__fixtures__');
  const reportDir = path.join(fixturesRoot, 'report');
  const evidenceDir = path.join(fixturesRoot, 'evidence', 'sample');
  const timestamp = new Date('2024-02-01T10:15:00Z');
  const toolVersion = '0.2.0';
  const ledger: ManifestLedgerOptions = {
    root: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    previousRoot: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
  };

  let manifestResult: ManifestBuildResult;
  let expectedManifest: LedgerAwareManifest;

  beforeAll(async () => {
    manifestResult = await buildManifest({
      reportDir,
      evidenceDirs: [evidenceDir],
      toolVersion,
      now: timestamp,
      ledger,
    });

    const baseManifest: LedgerAwareManifest = {
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
      stage: null,
      ledger: {
        root: ledger.root,
        previousRoot: ledger.previousRoot,
      },
    };

    const { merkle, files } = computeExpectedMerkleArtifacts(baseManifest);

    expectedManifest = {
      ...baseManifest,
      files,
      merkle,
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

    const detailedLedger = verifyManifestSignatureDetailed(manifestResult.manifest, signature, {
      certificatePem,
      expectedLedgerRoot: ledger.root,
      expectedPreviousLedgerRoot: ledger.previousRoot,
      requireLedgerProof: true,
    });
    expect(detailedLedger.valid).toBe(true);
    expect(detailedLedger.ledgerRoot).toBe(ledger.root);
    expect(detailedLedger.previousLedgerRoot).toBe(ledger.previousRoot);
  });

  it('packages reports and evidence into a signed archive', async () => {
    const workDir = mkdtempSync(path.join(tmpdir(), 'soipack-packager-'));
    const bundlePath = path.join(workDir, 'dev.pem');
    const { bundlePem, certificatePem, publicKeyPem } = loadDevCredentials();
    const { bundlePem: cmsBundlePem, certificatePem: cmsCertificate } = loadCmsCredentials();
    writeFileSync(bundlePath, bundlePem, 'utf8');
    const cmsBundlePath = path.join(workDir, 'cms.pem');
    writeFileSync(cmsBundlePath, cmsBundlePem, 'utf8');

    try {
      const result = await createSoiDataPack({
        reportDir,
        evidenceDirs: [evidenceDir],
        toolVersion,
        credentialsPath: bundlePath,
        outputDir: workDir,
        now: timestamp,
        ledger,
        cms: { bundlePath: cmsBundlePath },
      });

      expect(path.basename(result.outputPath)).toBe('soi-pack-20240201_1015.zip');
      expect(existsSync(result.outputPath)).toBe(true);
      expect(verifyManifestSignature(result.manifest, result.signature, certificatePem)).toBe(true);
      expect(verifyManifestSignature(result.manifest, result.signature, publicKeyPem)).toBe(true);

      expect(result.cmsSignature).toEqual(
        expect.objectContaining({
          path: 'manifest.cms',
          algorithm: 'sha256',
          digestAlgorithm: 'SHA-256',
        }),
      );
      const manifestCmsBuffer = Buffer.from(result.cmsSignature?.der ?? '', 'base64');
      expect(result.cmsSignature?.digest).toBe(
        createHash('sha256').update(manifestCmsBuffer).digest('hex'),
      );

      const detailedWithCms = verifyManifestSignatureDetailed(result.manifest, result.signature, {
        certificatePem,
        cms: {
          signatureDer: result.cmsSignature?.der,
          certificatePem: cmsCertificate,
          required: true,
        },
      });
      expect(detailedWithCms.valid).toBe(true);
      expect(detailedWithCms.cms?.verified).toBe(true);
      expect(detailedWithCms.cms?.digestVerified).toBe(true);

      const parsedSbom = JSON.parse(result.sbom.content) as Record<string, unknown>;
      expect(parsedSbom.spdxVersion).toBe('SPDX-2.3');
      expect(Array.isArray(parsedSbom.files)).toBe(true);
      expect((parsedSbom.files as Array<unknown>).length).toBe(expectedManifest.files.length);

      const sbomDigest = createHash('sha256').update(result.sbom.content, 'utf8').digest('hex');
      expect(result.sbom).toEqual({
        path: 'sbom.spdx.json',
        algorithm: 'sha256',
        digest: sbomDigest,
        content: result.sbom.content,
      });
      expect(result.manifest.sbom).toEqual({
        path: 'sbom.spdx.json',
        algorithm: 'sha256',
        digest: sbomDigest,
      });

      const baseManifestWithSbom: LedgerAwareManifest = {
        createdAt: expectedManifest.createdAt,
        toolVersion: expectedManifest.toolVersion,
        files: expectedManifest.files.map((file) => ({ path: file.path, sha256: file.sha256 })),
        stage: expectedManifest.stage,
        ledger: expectedManifest.ledger,
        sbom: result.manifest.sbom,
      };

      const { merkle, files: filesWithProof } = computeExpectedMerkleArtifacts(baseManifestWithSbom);
      const expectedManifestWithSbom: LedgerAwareManifest = {
        ...baseManifestWithSbom,
        files: filesWithProof,
        merkle,
      };

      expect(result.manifest).toEqual(expectedManifestWithSbom);
    } finally {
      rmSync(workDir, { recursive: true, force: true });
    }
  });

  it('exposes verifiable Merkle proofs for each file', () => {
    const merkleRoot = manifestResult.manifest.merkle?.root;
    expect(typeof merkleRoot).toBe('string');

    manifestResult.manifest.files.forEach((file) => {
      expect(file.proof?.algorithm).toBe('ledger-merkle-v1');
      expect(file.proof?.merkleRoot).toBe(merkleRoot);
      expect(typeof file.proof?.proof).toBe('string');
      const proof = deserializeLedgerProof(file.proof!.proof);
      expect(verifyLedgerProof(proof, { expectedMerkleRoot: merkleRoot! })).toBe(merkleRoot);
    });
  });
});
