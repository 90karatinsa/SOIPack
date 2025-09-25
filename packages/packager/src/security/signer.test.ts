import { createHash, sign as signData, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { Manifest } from '@soipack/core';

import {
  signManifestWithSecuritySigner,
  verifyManifestSignatureWithSecuritySigner,
} from './signer';

const DEV_CERT_BUNDLE_PATH = path.resolve(__dirname, '../../../../test/certs/dev.pem');
const CERTIFICATE_PATTERN = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/;
const PRIVATE_KEY_PATTERN = /-----BEGIN (?:RSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA )?PRIVATE KEY-----/;

const loadDevCredentials = (): { bundlePem: string; certificatePem: string; privateKeyPem: string } => {
  const bundlePem = readFileSync(DEV_CERT_BUNDLE_PATH, 'utf8');
  const certificateMatch = bundlePem.match(CERTIFICATE_PATTERN);
  const privateKeyMatch = bundlePem.match(PRIVATE_KEY_PATTERN);
  if (!certificateMatch) {
    throw new Error('Dev sertifikası bulunamadı.');
  }
  if (!privateKeyMatch) {
    throw new Error('Dev özel anahtarı bulunamadı.');
  }
  return { bundlePem, certificatePem: certificateMatch[0], privateKeyPem: privateKeyMatch[0] };
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

type Pkcs11Attribute = { type: number; value?: Buffer };

class MockPkcs11 {
  public readonly slotId = 9;

  private readonly privateKeyHandle = 0x01;

  private readonly certificateHandle = 0x02;

  private readonly attestationHandle = 0x03;

  private readonly certificateDer: Buffer;

  private readonly attestationValue: Buffer;

  private lastTemplate: Pkcs11Attribute[] | undefined;

  private sessionCounter = 100;

  private readonly omitKey: boolean;

  private readonly privateKeyPem?: string;

  public loginPin?: string;

  public lastSignedPayload?: Buffer;

  public signMechanism?: number;

  constructor({
    certificatePem,
    privateKeyPem,
    attestation,
    omitKey = false,
  }: {
    certificatePem: string;
    privateKeyPem?: string;
    attestation?: Buffer;
    omitKey?: boolean;
  }) {
    this.privateKeyPem = privateKeyPem;
    this.certificateDer = new X509Certificate(certificatePem).raw;
    this.attestationValue = attestation ?? Buffer.from('attestation evidence');
    this.omitKey = omitKey;
  }

  load(): void {
    // noop for tests
  }

  C_Initialize(): void {
    // noop
  }

  C_Finalize(): void {
    // noop
  }

  C_GetSlotList(tokenPresent: boolean): number[] {
    return tokenPresent ? [this.slotId] : [];
  }

  C_GetSlotInfo(): {
    slotDescription: Buffer;
    manufacturerID: Buffer;
    hardwareVersion: { major: number; minor: number };
    firmwareVersion: { major: number; minor: number };
  } {
    const slotDescription = Buffer.alloc(64);
    slotDescription.write('YubiHSM Slot', 'utf8');
    const manufacturerID = Buffer.alloc(32);
    manufacturerID.write('Yubico', 'utf8');
    return {
      slotDescription,
      manufacturerID,
      hardwareVersion: { major: 1, minor: 3 },
      firmwareVersion: { major: 4, minor: 2 },
    };
  }

  C_GetTokenInfo(): {
    label: string;
    manufacturerID: string;
    model: string;
    serialNumber: string;
  } {
    return {
      label: 'YubiHSM2-Test',
      manufacturerID: 'Yubico',
      model: 'YHSM2',
      serialNumber: '000123456789',
    };
  }

  C_OpenSession(): number {
    this.sessionCounter += 1;
    return this.sessionCounter;
  }

  C_CloseSession(): void {
    // noop
  }

  C_Login(_session: number, _userType: number, pin: string): void {
    this.loginPin = pin;
  }

  C_Logout(): void {
    // noop
  }

  C_FindObjectsInit(_session: number, template: Pkcs11Attribute[]): void {
    this.lastTemplate = template;
  }

  C_FindObjects(_session: number, _count: number): Array<number> {
    if (!this.lastTemplate) {
      return [];
    }
    const labelEntry = this.lastTemplate.find((attr) => attr.type === 0x00000003);
    const label = labelEntry?.value?.toString('utf8');
    if (label === 'SIGNING-KEY') {
      return this.omitKey ? [] : [this.privateKeyHandle];
    }
    if (label === 'SIGNING-CERT') {
      return [this.certificateHandle];
    }
    if (label === 'ATTEST') {
      return [this.attestationHandle];
    }
    return [];
  }

  C_FindObjectsFinal(): void {
    this.lastTemplate = undefined;
  }

  C_GetAttributeValue(
    _session: number,
    handle: number,
    template: Pkcs11Attribute[],
  ): Array<{ type: number; value: Buffer }> {
    const value =
      handle === this.certificateHandle
        ? this.certificateDer
        : handle === this.attestationHandle
          ? this.attestationValue
          : Buffer.alloc(0);
    return template.map((attribute) => ({ type: attribute.type, value }));
  }

  C_SignInit(_session: number, mechanism: { mechanism: number }, _key: number): void {
    this.signMechanism = mechanism.mechanism;
  }

  C_Sign(_session: number, data: Buffer): Buffer {
    this.lastSignedPayload = Buffer.from(data);
    if (!this.privateKeyPem) {
      throw new Error('Mock private key missing');
    }
    return signData(null, data, this.privateKeyPem);
  }
}

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

describe('security signer pkcs11 integration', () => {
  it('signs manifests via pkcs11 modules and returns hardware evidence', () => {
    const { certificatePem, privateKeyPem } = loadDevCredentials();
    const attestation = Buffer.from('mock-attestation');
    const module = new MockPkcs11({
      certificatePem,
      privateKeyPem,
      attestation,
    });

    const bundle = signManifestWithSecuritySigner(baseManifest, {
      pkcs11: {
        module,
        slotIndex: 0,
        pin: '000001',
        privateKey: { label: 'SIGNING-KEY' },
        certificate: { label: 'SIGNING-CERT' },
        attestation: { label: 'ATTEST', format: 'yubihsm-x509' },
      },
    });

    expect(module.loginPin).toBe('000001');
    expect(module.signMechanism).toBe(0x0000108d);
    expect(module.lastSignedPayload?.toString('utf8')).toContain('.');

    expect(bundle.certificate).toContain('BEGIN CERTIFICATE');

    const verification = verifyManifestSignatureWithSecuritySigner(baseManifest, bundle.signature, {
      certificatePem: bundle.certificate,
    });

    expect(verification.valid).toBe(true);
    expect(bundle.hardware).toEqual(
      expect.objectContaining({
        provider: 'PKCS11',
        slot: expect.objectContaining({
          id: module.slotId,
          description: 'YubiHSM Slot',
          tokenLabel: 'YubiHSM2-Test',
          tokenSerial: '000123456789',
        }),
        attestation: {
          format: 'yubihsm-x509',
          data: attestation.toString('base64'),
        },
      }),
    );
  });

  it('throws a descriptive error when the private key cannot be found', () => {
    const { certificatePem } = loadDevCredentials();
    const module = new MockPkcs11({ certificatePem, omitKey: true });

    expect(() =>
      signManifestWithSecuritySigner(baseManifest, {
        pkcs11: {
          module,
          slotIndex: 0,
          privateKey: { label: 'SIGNING-KEY' },
          certificate: { label: 'SIGNING-CERT' },
        },
      }),
    ).toThrow('PKCS#11 özel anahtarı bulunamadı.');
  });
});
