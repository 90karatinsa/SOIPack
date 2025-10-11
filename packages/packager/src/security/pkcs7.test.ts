import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { Manifest } from '@soipack/core';
import {
  signManifestWithSecuritySigner,
  verifyManifestSignatureWithSecuritySigner,
} from './signer';

const DEV_CERT_BUNDLE_PATH = path.resolve(__dirname, '../../../../test/certs/dev.pem');
const CMS_CERT_BUNDLE_PATH = path.resolve(__dirname, '../../../../test/certs/cms-test.pem');
const CERTIFICATE_PATTERN = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/;

const loadPemBundle = (bundlePath: string): string => readFileSync(bundlePath, 'utf8');

const extractCertificate = (pemBundle: string): string => {
  const match = pemBundle.match(CERTIFICATE_PATTERN);
  if (!match) {
    throw new Error('Certificate not found in bundle.');
  }
  return match[0].trim();
};

const buildDigest = (value: string): string => createHash('sha256').update(value).digest('hex');

const baseManifest: Manifest = {
  createdAt: '2024-02-01T10:00:00Z',
  toolVersion: '0.2.0',
  files: [
    { path: 'reports/summary.html', sha256: buildDigest('summary') },
    { path: 'evidence/logs.csv', sha256: buildDigest('logs') },
  ],
};

describe('CMS / PKCS#7 manifest signatures', () => {
  it('produces CMS payloads that verify against the manifest digest', () => {
    const devBundle = loadPemBundle(DEV_CERT_BUNDLE_PATH);
    const cmsBundle = loadPemBundle(CMS_CERT_BUNDLE_PATH);
    const cmsCertificate = extractCertificate(cmsBundle);

    const bundle = signManifestWithSecuritySigner(baseManifest, {
      bundlePem: devBundle,
      cms: { bundlePem: cmsBundle },
    });

    expect(bundle.cmsSignature).toBeDefined();
    expect(bundle.cmsSignature?.der).toEqual(expect.any(String));
    expect(bundle.cmsSignature?.pem).toMatch('BEGIN PKCS7');
    expect(bundle.cmsSignature?.certificates).toContain(cmsCertificate);
    expect(bundle.cmsSignature?.digestAlgorithm).toBe('SHA-256');

    const verification = verifyManifestSignatureWithSecuritySigner(baseManifest, bundle.signature, {
      certificatePem: extractCertificate(devBundle),
      cms: {
        signatureDer: bundle.cmsSignature?.der,
        certificatePem: cmsCertificate,
        required: true,
      },
    });

    expect(verification.valid).toBe(true);
    expect(verification.cms).toEqual(
      expect.objectContaining({
        verified: true,
        digestVerified: true,
        signerSerialNumber: expect.any(String),
        signerSubject: expect.stringContaining('SOIPack CMS Test'),
        signatureAlgorithm: expect.stringMatching(/sha|1\.2\.840\.113549\.1\.1\.11/),
      }),
    );
  });

  it('detects tampered CMS payloads when verification is requested', () => {
    const devBundle = loadPemBundle(DEV_CERT_BUNDLE_PATH);
    const cmsBundle = loadPemBundle(CMS_CERT_BUNDLE_PATH);
    const cmsCertificate = extractCertificate(cmsBundle);

    const bundle = signManifestWithSecuritySigner(baseManifest, {
      bundlePem: devBundle,
      cms: { bundlePem: cmsBundle },
    });

    const cmsDer = bundle.cmsSignature?.der ?? '';
    const tamperedBuffer = Buffer.from(cmsDer, 'base64');
    if (tamperedBuffer.length > 0) {
      tamperedBuffer[tamperedBuffer.length - 1] ^= 0xff;
    }
    const tamperedDer = tamperedBuffer.toString('base64');

    const verification = verifyManifestSignatureWithSecuritySigner(baseManifest, bundle.signature, {
      certificatePem: extractCertificate(devBundle),
      cms: {
        signatureDer: tamperedDer,
        certificatePem: cmsCertificate,
        required: true,
      },
    });

    expect(verification.valid).toBe(false);
    expect(verification.reason).toBe('CMS_SIGNATURE_INVALID');
  });
});
