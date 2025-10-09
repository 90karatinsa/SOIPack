import { createHash } from 'crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import path from 'path';

jest.mock('@soipack/core', () => {
  const actual = jest.requireActual('@soipack/core');
  return {
    ...actual,
    generateLedgerProof: (entry: any, target: any) => ({
      leaf: {
        type: target.type,
        label: `evidence:${target.snapshotId ?? ''}:${target.path ?? ''}`,
        hash: target.hash ?? '',
      },
      path: [],
      merkleRoot: entry.merkleRoot,
    }),
  };
});

jest.mock('./security/signer', () => {
  const { createHash } = require('crypto');
  const { readFileSync } = require('fs');
  const path = require('path');

  const DEV_CERT_BUNDLE_PATH = path.resolve(__dirname, '../../../test/certs/dev.pem');
  const bundlePem = readFileSync(DEV_CERT_BUNDLE_PATH, 'utf8');
  const certificateMatch = bundlePem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/);
  const certificatePem = certificateMatch ? certificateMatch[0] : '-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n';

  const computeManifestDigestHex = (manifest: unknown): string =>
    createHash('sha256').update(JSON.stringify(manifest)).digest('hex');

  const signManifestBundle = (manifest: unknown) => ({
    signature: `stub:${computeManifestDigestHex(manifest)}`,
    manifestDigest: { algorithm: 'SHA-256', hash: computeManifestDigestHex(manifest) },
    certificate: certificatePem,
  });

  const verifyManifestSignature = () => true;

  const verifyManifestSignatureDetailed = (
    _manifest: unknown,
    _signature: string,
    options: { expectedLedgerRoot?: string | null; expectedPreviousLedgerRoot?: string | null } = {},
  ) => ({
    valid: true,
    ledgerRoot: options.expectedLedgerRoot ?? null,
    previousLedgerRoot: options.expectedPreviousLedgerRoot ?? null,
  });

  const signManifestWithSecuritySigner = () => ({ signature: 'stub-signature' });

  const verifyManifestSignatureWithSecuritySigner = () => ({ valid: true });

  const assertValidManifestSignature = () => undefined;

  return {
    computeManifestDigestHex,
    signManifestBundle,
    verifyManifestSignature,
    verifyManifestSignatureDetailed,
    signManifestWithSecuritySigner,
    verifyManifestSignatureWithSecuritySigner,
    assertValidManifestSignature,
  };
});

import {
  buildManifest,
  createSoiDataPack,
  computeManifestDigestHex,
  LedgerAwareManifest,
} from './index';

jest.setTimeout(60000);

const fixturesRoot = path.join(__dirname, '__fixtures__');
const reportDir = path.join(fixturesRoot, 'report');
const evidenceDir = path.join(fixturesRoot, 'evidence', 'sample');
const timestamp = new Date('2024-02-01T10:15:00Z');
const toolVersion = '0.2.0';

const DEFAULT_MANIFEST_PROOF_SNAPSHOT_ID = 'manifest-files';

const buildManifestSnapshotId = (digest: string, stage?: string | null): string =>
  stage ? `manifest:${stage}:${digest}` : `manifest:${digest}`;

const buildEvidenceSnapshotId = (stage?: string | null): string =>
  stage ? `${DEFAULT_MANIFEST_PROOF_SNAPSHOT_ID}:${stage}` : DEFAULT_MANIFEST_PROOF_SNAPSHOT_ID;

const DEV_CERT_BUNDLE_PATH = path.resolve(__dirname, '../../../test/certs/dev.pem');

const loadBundlePem = (): string => readFileSync(DEV_CERT_BUNDLE_PATH, 'utf8');

describe('packager stage routing', () => {
  it('embeds stage metadata and stage-scoped paths in manifests', async () => {
    const stage = 'SOI-3';
    const manifest = (
      await buildManifest({
        reportDir,
        evidenceDirs: [evidenceDir],
        toolVersion,
        now: timestamp,
        stage,
      })
    ).manifest;

    expect(manifest.stage).toBe(stage);
    manifest.files.forEach((file) => {
      if (file.path.startsWith('reports/')) {
        expect(file.path).toMatch(new RegExp(`^reports/${stage}/`));
      } else {
        expect(file.path).toMatch(new RegExp(`^evidence/${stage}/`));
      }
    });

    const digest = manifest.merkle?.manifestDigest ?? computeManifestDigestHex(manifest);
    expect(manifest.merkle?.snapshotId).toBe(buildManifestSnapshotId(digest, stage));
  });

  it('produces distinct Merkle roots for each stage', async () => {
    const first = (
      await buildManifest({
        reportDir,
        evidenceDirs: [evidenceDir],
        toolVersion,
        now: timestamp,
        stage: 'SOI-2',
      })
    ).manifest.merkle?.root;

    const second = (
      await buildManifest({
        reportDir,
        evidenceDirs: [evidenceDir],
        toolVersion,
        now: timestamp,
        stage: 'SOI-4',
      })
    ).manifest.merkle?.root;

    expect(first).not.toBe(second);
  });

  it('packages stage-scoped artifacts and persists stage metadata', async () => {
    const workDir = mkdtempSync(path.join(tmpdir(), 'soipack-packager-stage-'));
    const bundlePath = path.join(workDir, 'dev.pem');
    writeFileSync(bundlePath, loadBundlePem(), 'utf8');

    const stage = 'SOI-1';

    try {
      const result = await createSoiDataPack({
        reportDir,
        evidenceDirs: [evidenceDir],
        toolVersion,
        credentialsPath: bundlePath,
        outputDir: workDir,
        now: timestamp,
        stage,
      });

      expect(result.manifest.stage).toBe(stage);
      const stageSbomDigest = createHash('sha256').update(result.sbom.content, 'utf8').digest('hex');
      expect(result.sbom).toEqual({
        path: 'sbom.spdx.json',
        algorithm: 'sha256',
        digest: stageSbomDigest,
        content: result.sbom.content,
      });
      expect(result.manifest.sbom?.digest).toBe(stageSbomDigest);
      result.manifest.files.forEach((file) => {
        if (file.path.startsWith('reports/')) {
          expect(file.path).toMatch(new RegExp(`^reports/${stage}/`));
        } else {
          expect(file.path).toMatch(new RegExp(`^evidence/${stage}/`));
        }
      });

      const digest = result.manifest.merkle?.manifestDigest ?? computeManifestDigestHex(result.manifest);
      expect(result.manifest.merkle?.snapshotId).toBe(buildManifestSnapshotId(digest, stage));
      expect(result.attestation.path).toBe('attestation.json');
      expect(result.manifest.provenance?.path).toBe('attestation.json');
      expect(result.manifest.provenance?.statementDigest).toBe(result.attestation.statementDigest);
      expect(result.attestation.signature.algorithm).toBe('EdDSA');
    } finally {
      rmSync(workDir, { recursive: true, force: true });
    }
  });
});
