import { createHash, X509Certificate, createPublicKey, verify as verifySignature } from 'crypto';
import { readFileSync } from 'fs';
import path from 'path';

import type { LedgerAwareManifest } from './index';
import { generateAttestation, serializeAttestationDocument } from './attestation';
import type { ManifestSignatureBundle } from './index';

const DEV_CERT_BUNDLE_PATH = path.resolve(__dirname, '../../../test/certs/dev.pem');

const loadDevCredentials = (): { privateKeyPem: string; certificatePem: string; bundlePem: string } => {
  const bundlePem = readFileSync(DEV_CERT_BUNDLE_PATH, 'utf8');
  const certificateMatch = bundlePem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/);
  if (!certificateMatch) {
    throw new Error('Dev sertifikası bulunamadı.');
  }

  return {
    privateKeyPem: bundlePem,
    certificatePem: certificateMatch[0],
    bundlePem,
  };
};

describe('Attestation', () => {
  const manifest: LedgerAwareManifest = {
    createdAt: '2024-02-01T10:15:00.000Z',
    toolVersion: '0.2.0',
    files: [
      {
        path: 'reports/summary.txt',
        sha256: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      },
      {
        path: 'evidence/log.csv',
        sha256: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      },
    ],
    stage: 'SOI-1',
    ledger: {
      root: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
      previousRoot: 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
    },
    merkle: {
      algorithm: 'ledger-merkle-v1',
      root: 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
      manifestDigest: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      snapshotId: 'manifest:SOI-1:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    },
    sbom: {
      path: 'sbom.spdx.json',
      algorithm: 'sha256',
      digest: '1111111111111111111111111111111111111111111111111111111111111111',
    },
  };

  const manifestDigest = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

  it('Attestation Packager attestation generates deterministic provenance statements and Ed25519 JWS signatures', async () => {
    const { bundlePem, certificatePem } = loadDevCredentials();
    const certificate = new X509Certificate(certificatePem);
    const publicKeyPem = certificate.publicKey.export({ format: 'pem', type: 'spki' }).toString();

    const signatureBundle: ManifestSignatureBundle = {
      signature: 'stub-signature',
      certificate: certificatePem,
      manifestDigest: { algorithm: 'SHA-256', hash: manifestDigest },
      ledgerRoot: manifest.ledger?.root ?? null,
      previousLedgerRoot: manifest.ledger?.previousRoot ?? null,
    };

    const result = await generateAttestation({
      manifest,
      manifestDigest,
      sbom: manifest.sbom!,
      files: manifest.files.map((file) => ({ path: file.path, sha256: file.sha256 })),
      packageName: 'soi-pack-test.zip',
      manifestSignature: signatureBundle,
      builderId: 'https://soipack.dev/test-builder',
      invocationId: 'test-run-123',
      signing: {
        privateKeyPem: bundlePem,
        publicKeyPem,
        keyId: 'test-dev-key',
      },
    });

    const serialized = serializeAttestationDocument(result.document);
    expect(serialized).toMatchSnapshot('attestation-document');

    const [encodedHeader, encodedPayload, encodedSignature] = result.signature.jws.split('.');
    expect(encodedHeader).toBe(result.signature.protected);
    expect(encodedPayload).toBe(Buffer.from(result.payload, 'utf8').toString('base64url'));
    expect(encodedSignature).toBe(result.signature.signature);

    const verificationPayload = Buffer.from(`${encodedHeader}.${encodedPayload}`, 'utf8');
    const verified = verifySignature(
      null,
      verificationPayload,
      createPublicKey(result.signature.publicKey),
      Buffer.from(encodedSignature, 'base64url'),
    );
    expect(verified).toBe(true);

    const expectedDigest = createHash('sha256').update(result.payload, 'utf8').digest('hex');
    expect(result.document.statementDigest).toEqual({ algorithm: 'sha256', digest: expectedDigest });
  });
});
