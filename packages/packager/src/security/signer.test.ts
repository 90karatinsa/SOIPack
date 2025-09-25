import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { Manifest } from '@soipack/core';

import {
  signManifestWithSecuritySigner,
  verifyManifestSignatureWithSecuritySigner,
} from './signer';

const DEV_CERT_BUNDLE_PATH = path.resolve(__dirname, '../../../../test/certs/dev.pem');
const CERTIFICATE_PATTERN = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/;

const loadDevCredentials = (): { bundlePem: string; certificatePem: string } => {
  const bundlePem = readFileSync(DEV_CERT_BUNDLE_PATH, 'utf8');
  const certificateMatch = bundlePem.match(CERTIFICATE_PATTERN);
  if (!certificateMatch) {
    throw new Error('Dev sertifikası bulunamadı.');
  }
  return { bundlePem, certificatePem: certificateMatch[0] };
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

describe('security signer ledger integration', () => {
  it('embeds ledger metadata into the signature payload', () => {
    const { bundlePem, certificatePem } = loadDevCredentials();
    const ledgerRoot = buildDigest('ledger-root');
    const previousLedgerRoot = buildDigest('ledger-prev');

    const bundle = signManifestWithSecuritySigner(baseManifest, {
      bundlePem,
      ledger: { root: ledgerRoot, previousRoot: previousLedgerRoot },
    });

    expect(bundle.ledgerRoot).toBe(ledgerRoot);
    expect(bundle.previousLedgerRoot).toBe(previousLedgerRoot);

    const verification = verifyManifestSignatureWithSecuritySigner(baseManifest, bundle.signature, {
      certificatePem,
      expectedLedgerRoot: ledgerRoot,
      expectedPreviousLedgerRoot: previousLedgerRoot,
    });

    expect(verification.valid).toBe(true);
    expect(verification.ledgerRoot).toBe(ledgerRoot);
    expect(verification.previousLedgerRoot).toBe(previousLedgerRoot);
  });

  it('rejects signatures when ledger roots do not match the expected chain', () => {
    const { bundlePem, certificatePem } = loadDevCredentials();
    const ledgerRoot = buildDigest('ledger-root');

    const bundle = signManifestWithSecuritySigner(baseManifest, {
      bundlePem,
      ledger: { root: ledgerRoot },
    });

    const verification = verifyManifestSignatureWithSecuritySigner(baseManifest, bundle.signature, {
      certificatePem,
      expectedLedgerRoot: buildDigest('other-root'),
    });

    expect(verification.valid).toBe(false);
    expect(verification.reason).toBe('LEDGER_ROOT_MISMATCH');
    expect(verification.ledgerRoot).toBe(ledgerRoot);
  });

  it('rejects signatures when previous ledger root mismatches', () => {
    const { bundlePem, certificatePem } = loadDevCredentials();
    const ledgerRoot = buildDigest('ledger-root');
    const previousLedgerRoot = buildDigest('ledger-prev');

    const bundle = signManifestWithSecuritySigner(baseManifest, {
      bundlePem,
      ledger: { root: ledgerRoot, previousRoot: previousLedgerRoot },
    });

    const verification = verifyManifestSignatureWithSecuritySigner(baseManifest, bundle.signature, {
      certificatePem,
      expectedLedgerRoot: ledgerRoot,
      expectedPreviousLedgerRoot: buildDigest('another-prev'),
    });

    expect(verification.valid).toBe(false);
    expect(verification.reason).toBe('LEDGER_PREVIOUS_MISMATCH');
    expect(verification.previousLedgerRoot).toBe(previousLedgerRoot);
  });

  it('requires ledger metadata when the verifier demands it', () => {
    const { bundlePem, certificatePem } = loadDevCredentials();
    const bundle = signManifestWithSecuritySigner(baseManifest, { bundlePem });

    const verification = verifyManifestSignatureWithSecuritySigner(baseManifest, bundle.signature, {
      certificatePem,
      requireLedgerProof: true,
    });

    expect(verification.valid).toBe(false);
    expect(verification.reason).toBe('LEDGER_ROOT_MISSING');
  });
});
