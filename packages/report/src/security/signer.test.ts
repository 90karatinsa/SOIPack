import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { Manifest } from '@soipack/core';

import { signManifestBundle, verifyManifestSignatureDetailed } from './signer';

const DEV_CERT_BUNDLE_PATH = path.resolve(__dirname, '../../../../test/certs/dev.pem');
const CERTIFICATE_PATTERN = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/;

const loadManifest = (): Manifest => ({
  files: [
    { path: 'reports/compliance.html', sha256: 'd1'.repeat(32) },
    { path: 'evidence/log.txt', sha256: 'e2'.repeat(32) },
  ],
  createdAt: '2024-01-01T00:00:00.000Z',
  toolVersion: 'test-tool',
});

describe('security signer', () => {
  const bundlePem = readFileSync(DEV_CERT_BUNDLE_PATH, 'utf8');
  const certificatePem = (() => {
    const match = bundlePem.match(CERTIFICATE_PATTERN);
    if (!match) {
      throw new Error('Test sertifikası yüklenemedi.');
    }
    return match[0];
  })();

  it('produces a valid signature for a manifest', () => {
    const manifest = loadManifest();
    const signature = signManifestBundle(manifest, { bundlePem }).signature;
    const result = verifyManifestSignatureDetailed(manifest, signature);

    expect(result.valid).toBe(true);
    expect(result.digest?.hash).toHaveLength(64);
    expect(result.certificateInfo?.subject).toContain('CN=SOIPack Dev');
  });

  it('detects tampering via digest mismatch', () => {
    const manifest = loadManifest();
    const signature = signManifestBundle(manifest, { bundlePem }).signature;
    const tamperedManifest: Manifest = {
      ...manifest,
      files: [...manifest.files, { path: 'reports/new.html', sha256: 'a'.repeat(64) }],
    };

    const result = verifyManifestSignatureDetailed(tamperedManifest, signature);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('DIGEST_MISMATCH');
  });

  it('reports an error when the certificate is expired', () => {
    const manifest = loadManifest();
    const signature = signManifestBundle(manifest, { bundlePem }).signature;
    const certificate = new X509Certificate(certificatePem);
    const future = new Date(Date.parse(certificate.validTo) + 60_000);

    const result = verifyManifestSignatureDetailed(manifest, signature, { now: future });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('CERT_EXPIRED');
  });
});
