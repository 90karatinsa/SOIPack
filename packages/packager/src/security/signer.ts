import { createHash, sign as signData, verify as verifySignature, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { Manifest } from '@soipack/core';

type ManifestLedgerMetadata = {
  ledger?: {
    root: string | null;
    previousRoot?: string | null;
  } | null;
};

type LedgerAwareManifest = Manifest & ManifestLedgerMetadata;

export interface ManifestDigest {
  algorithm: 'SHA-256';
  hash: string;
}

export interface LedgerProofMetadata {
  root: string;
  previousRoot?: string | null;
}

export interface ManifestSignatureBundle {
  signature: string;
  certificate: string;
  manifestDigest: ManifestDigest;
  ledgerRoot?: string | null;
  previousLedgerRoot?: string | null;
  hardware?: HardwareSignatureMetadata;
}

export interface SecuritySignerOptions {
  bundlePath?: string;
  bundlePem?: string;
  certificatePath?: string;
  certificatePem?: string;
  privateKeyPath?: string;
  privateKeyPem?: string;
  ledger?: LedgerProofMetadata;
  pkcs11?: Pkcs11SigningOptions;
}

type Pkcs11Attribute = { type: number; value?: Buffer };

interface Pkcs11Like {
  load?(libraryPath: string): void;
  C_Initialize(options?: unknown): void;
  C_Finalize(): void;
  C_GetSlotList(tokenPresent: boolean): Array<number | Buffer>;
  C_GetSlotInfo(slot: number | Buffer): {
    slotDescription: Buffer | string;
    manufacturerID: Buffer | string;
    hardwareVersion?: { major: number; minor: number };
    firmwareVersion?: { major: number; minor: number };
  };
  C_GetTokenInfo(slot: number | Buffer): {
    label?: string;
    manufacturerID?: string;
    model?: string;
    serialNumber?: string;
  };
  C_OpenSession(slot: number | Buffer, flags: number): number;
  C_CloseSession(session: number): void;
  C_Login(session: number, userType: number, pin: string): void;
  C_Logout(session: number): void;
  C_FindObjectsInit(session: number, template: Pkcs11Attribute[]): void;
  C_FindObjects(session: number, count: number): Array<Buffer | number>;
  C_FindObjectsFinal(session: number): void;
  C_GetAttributeValue(
    session: number,
    handle: Buffer | number,
    template: Pkcs11Attribute[],
  ): Array<{ type: number; value?: Buffer }>;
  C_SignInit(
    session: number,
    mechanism: { mechanism: number; parameter?: Buffer | null },
    key: Buffer | number,
  ): void;
  C_Sign(session: number, data: Buffer): Buffer;
}

export interface Pkcs11ObjectSelector {
  label?: string;
  idHex?: string;
}

export interface Pkcs11AttestationOptions extends Pkcs11ObjectSelector {
  format?: string;
}

export interface Pkcs11SigningOptions {
  libraryPath?: string;
  slotId?: number;
  slotIndex?: number;
  pin?: string;
  userType?: number;
  privateKey: Pkcs11ObjectSelector & { label?: string };
  certificate?: Pkcs11ObjectSelector;
  attestation?: Pkcs11AttestationOptions;
  mechanism?: number;
  module?: Pkcs11Like;
}

export interface HardwareSignatureMetadata {
  provider: 'PKCS11';
  slot: {
    id: number;
    index: number;
    description?: string;
    manufacturer?: string;
    hardwareVersion?: string;
    firmwareVersion?: string;
    tokenLabel?: string;
    tokenModel?: string;
    tokenManufacturer?: string;
    tokenSerial?: string;
  };
  attestation?: {
    format: string;
    data: string;
  };
}

const CKF_RW_SESSION = 0x00000002;
const CKF_SERIAL_SESSION = 0x00000004;
const CKU_USER = 1;
const CKO_DATA = 0;
const CKO_CERTIFICATE = 1;
const CKO_PRIVATE_KEY = 3;
const CKA_CLASS = 0x00000000;
const CKA_LABEL = 0x00000003;
const CKA_ID = 0x00000102;
const CKA_VALUE = 0x00000011;
const CKM_EDDSA = 0x0000108d;

export type VerificationFailureReason =
  | 'FORMAT_INVALID'
  | 'UNSUPPORTED_ALGORITHM'
  | 'DIGEST_MISMATCH'
  | 'SIGNATURE_INVALID'
  | 'CERT_EXPIRED'
  | 'CERTIFICATE_MISSING'
  | 'LEDGER_ROOT_MISSING'
  | 'LEDGER_ROOT_MISMATCH'
  | 'LEDGER_PREVIOUS_MISMATCH';

export interface VerificationOptions {
  certificatePem?: string;
  publicKeyPem?: string;
  now?: Date;
  expectedLedgerRoot?: string | null;
  expectedPreviousLedgerRoot?: string | null;
  requireLedgerProof?: boolean;
}

export interface VerificationResult {
  valid: boolean;
  reason?: VerificationFailureReason;
  digest?: ManifestDigest;
  certificateInfo?: {
    subject: string;
    validFrom: string;
    validTo: string;
  };
  ledgerRoot?: string | null;
  previousLedgerRoot?: string | null;
}

const DEFAULT_BUNDLE_PATH = path.resolve(__dirname, '../../../../test/certs/dev.pem');

const CERTIFICATE_PATTERN = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/;
const PRIVATE_KEY_PATTERN = /-----BEGIN (?:RSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA )?PRIVATE KEY-----/;

const base64UrlEncode = (value: Buffer | string): string => {
  const buffer = Buffer.isBuffer(value) ? value : Buffer.from(value, 'utf8');
  return buffer
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
};

const base64UrlDecode = (value: string): Buffer => {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padding = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
  return Buffer.from(normalized + padding, 'base64');
};

const encodePkcs11Uint = (value: number): Buffer => {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32LE(value >>> 0, 0);
  return buffer;
};

const normalizePkcs11String = (value?: string | Buffer | null): string | undefined => {
  if (!value) {
    return undefined;
  }
  if (typeof value === 'string') {
    return value.trim() || undefined;
  }
  return value.toString('utf8').replace(/\0+$/, '').trim() || undefined;
};

const formatVersion = (version?: { major: number; minor: number }): string | undefined => {
  if (!version) {
    return undefined;
  }
  const major = version.major ?? 0;
  const minor = version.minor ?? 0;
  return `${major}.${minor.toString().padStart(2, '0')}`;
};

const readSlotId = (slot: number | Buffer): number => {
  if (typeof slot === 'number') {
    return slot;
  }
  if (slot.length >= 4) {
    return slot.readUInt32LE(0);
  }
  return slot.readUIntLE(0, slot.length);
};

const safeRequire = (moduleName: string): any => {
  try {
    // eslint-disable-next-line global-require, import/no-dynamic-require
    return require(moduleName);
  } catch (error) {
    return undefined;
  }
};

const canonicalizeManifest = (manifest: Manifest & ManifestLedgerMetadata): Manifest => {
  const canonical: LedgerAwareManifest = {
    files: [...manifest.files]
      .map((file) => ({ path: file.path, sha256: file.sha256 }))
      .sort((a, b) => a.path.localeCompare(b.path)),
    createdAt: manifest.createdAt,
    toolVersion: manifest.toolVersion,
  };

  if (manifest.ledger !== undefined) {
    canonical.ledger = manifest.ledger
      ? {
          root: manifest.ledger.root ?? null,
          previousRoot:
            manifest.ledger.previousRoot === undefined
              ? null
              : manifest.ledger.previousRoot,
        }
      : null;
  }

  return canonical;
};

const computeManifestDigest = (manifest: Manifest): ManifestDigest => {
  const canonical = canonicalizeManifest(manifest);
  const serialized = JSON.stringify(canonical);
  const hash = createHash('sha256').update(serialized).digest('hex');
  return { algorithm: 'SHA-256', hash };
};

interface CredentialPair {
  certificatePem: string;
  privateKeyPem: string;
}

const extractCredentialPair = (pemBundle: string): CredentialPair => {
  const certificateMatch = pemBundle.match(CERTIFICATE_PATTERN);
  const privateKeyMatch = pemBundle.match(PRIVATE_KEY_PATTERN);
  if (!certificateMatch || !privateKeyMatch) {
    throw new Error('PEM demeti hem sertifika hem de özel anahtar içermelidir.');
  }

  return {
    certificatePem: certificateMatch[0],
    privateKeyPem: privateKeyMatch[0],
  };
};

const extractCertificatePem = (pemContent: string): string => {
  const certificateMatch = pemContent.match(CERTIFICATE_PATTERN);
  if (!certificateMatch) {
    throw new Error('Sertifika PEM içeriği bulunamadı.');
  }
  return certificateMatch[0];
};

const resolveCredentials = (options: SecuritySignerOptions = {}): CredentialPair => {
  if (options.certificatePem && options.privateKeyPem) {
    return {
      certificatePem: options.certificatePem,
      privateKeyPem: options.privateKeyPem,
    };
  }

  if (options.privateKeyPem && !options.certificatePem) {
    throw new Error('Özel anahtar belirtilirken sertifika PEM içeriği de sağlanmalıdır.');
  }

  if (options.certificatePem && !options.privateKeyPem) {
    throw new Error('Sertifika PEM içeriği özel anahtar olmadan kullanılamaz.');
  }

  if (options.bundlePem) {
    return extractCredentialPair(options.bundlePem);
  }

  if (options.bundlePath) {
    const content = readFileSync(options.bundlePath, 'utf8');
    return extractCredentialPair(content);
  }

  if (options.certificatePath && options.privateKeyPath) {
    return {
      certificatePem: readFileSync(options.certificatePath, 'utf8'),
      privateKeyPem: readFileSync(options.privateKeyPath, 'utf8'),
    };
  }

  if (options.certificatePath && !options.privateKeyPath) {
    const content = readFileSync(options.certificatePath, 'utf8');
    return extractCredentialPair(content);
  }

  if (options.privateKeyPath && !options.certificatePath) {
    throw new Error('Özel anahtar yolunu kullanırken sertifika yolu da belirtilmelidir.');
  }

  const defaultBundle = readFileSync(DEFAULT_BUNDLE_PATH, 'utf8');
  return extractCredentialPair(defaultBundle);
};

const resolveCertificateOnly = (options: SecuritySignerOptions = {}): string | undefined => {
  if (options.certificatePem) {
    return options.certificatePem;
  }

  if (options.bundlePem) {
    return extractCertificatePem(options.bundlePem);
  }

  if (options.bundlePath) {
    return extractCertificatePem(readFileSync(options.bundlePath, 'utf8'));
  }

  if (options.certificatePath) {
    return extractCertificatePem(readFileSync(options.certificatePath, 'utf8'));
  }

  return undefined;
};

const formatCertificateFromDer = (derBase64: string): string => {
  const chunks = derBase64.match(/.{1,64}/g) ?? [];
  return ['-----BEGIN CERTIFICATE-----', ...chunks, '-----END CERTIFICATE-----', ''].join('\n').trim();
};

const buildSigningPreparation = (
  certificatePem: string,
  digest: ManifestDigest,
  ledgerRoot: string | null,
  previousLedgerRoot: string | null,
): { signingInput: string } => {
  const x509 = new X509Certificate(certificatePem);
  const header = {
    alg: 'EdDSA',
    typ: 'SOIManifest',
    x5c: [x509.raw.toString('base64')],
  };
  const payload = {
    digest: digest.hash,
    algorithm: digest.algorithm,
    ledgerRoot,
    previousLedgerRoot,
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));

  return {
    signingInput: `${encodedHeader}.${encodedPayload}`,
  };
};

const buildBundleFromSignature = (
  certificatePem: string,
  digest: ManifestDigest,
  ledgerRoot: string | null,
  previousLedgerRoot: string | null,
  signingInput: string,
  signatureBuffer: Buffer,
): ManifestSignatureBundle => ({
  signature: `${signingInput}.${base64UrlEncode(signatureBuffer)}`,
  certificate: certificatePem.trim(),
  manifestDigest: digest,
  ledgerRoot,
  previousLedgerRoot,
});

const ensurePkcs11Module = (options: Pkcs11SigningOptions): Pkcs11Like => {
  if (options.module) {
    return options.module;
  }

  const pkcs11js = safeRequire('pkcs11js');
  if (!pkcs11js || typeof pkcs11js.PKCS11 !== 'function') {
    throw new Error('PKCS#11 modülü yüklenemedi. "pkcs11js" bağımlılığını ekleyin.');
  }

  const instance: Pkcs11Like = new pkcs11js.PKCS11();
  if (options.libraryPath) {
    instance.load?.(options.libraryPath);
  }
  return instance;
};

const selectPkcs11Slot = (
  pkcs11: Pkcs11Like,
  options: Pkcs11SigningOptions,
): { slotHandle: number | Buffer; slotIndex: number } => {
  const slots = pkcs11.C_GetSlotList(true);
  if (!slots.length) {
    throw new Error('PKCS#11 yuvası bulunamadı.');
  }

  if (typeof options.slotId === 'number') {
    const index = slots.findIndex((slot) => readSlotId(slot) === options.slotId);
    if (index === -1) {
      throw new Error(`Belirtilen PKCS#11 yuvası bulunamadı: ${options.slotId}`);
    }
    return { slotHandle: slots[index], slotIndex: index };
  }

  const targetIndex = options.slotIndex ?? 0;
  if (targetIndex < 0 || targetIndex >= slots.length) {
    throw new Error(`PKCS#11 yuva indeksi geçersiz: ${targetIndex}`);
  }

  return { slotHandle: slots[targetIndex], slotIndex: targetIndex };
};

const findPkcs11ObjectHandle = (
  pkcs11: Pkcs11Like,
  session: number,
  classType: number,
  selector: Pkcs11ObjectSelector,
): Buffer | number | undefined => {
  const template: Pkcs11Attribute[] = [{ type: CKA_CLASS, value: encodePkcs11Uint(classType) }];
  if (selector.label) {
    template.push({ type: CKA_LABEL, value: Buffer.from(selector.label, 'utf8') });
  }
  if (selector.idHex) {
    template.push({ type: CKA_ID, value: Buffer.from(selector.idHex, 'hex') });
  }

  pkcs11.C_FindObjectsInit(session, template);
  try {
    const [handle] = pkcs11.C_FindObjects(session, 1);
    return handle;
  } finally {
    pkcs11.C_FindObjectsFinal(session);
  }
};

const readPkcs11Attribute = (
  pkcs11: Pkcs11Like,
  session: number,
  handle: Buffer | number,
  attributeType = CKA_VALUE,
): Buffer => {
  const [attribute] = pkcs11.C_GetAttributeValue(session, handle, [{ type: attributeType }]);
  if (!attribute || !attribute.value) {
    throw new Error('PKCS#11 nesnesinden değer okunamadı.');
  }
  return attribute.value;
};

const signManifestWithPkcs11 = (
  digest: ManifestDigest,
  ledgerRoot: string | null,
  previousLedgerRoot: string | null,
  options: SecuritySignerOptions,
): ManifestSignatureBundle => {
  const pkcs11Options = options.pkcs11!;
  if (!pkcs11Options.privateKey.label && !pkcs11Options.privateKey.idHex) {
    throw new Error('PKCS#11 imzası için label veya idHex değerli bir özel anahtar seçicisi gereklidir.');
  }

  const pkcs11 = ensurePkcs11Module(pkcs11Options);
  pkcs11.C_Initialize();

  let session: number | undefined;
  let loggedIn = false;

  try {
    const { slotHandle, slotIndex } = selectPkcs11Slot(pkcs11, pkcs11Options);
    const slotInfo = pkcs11.C_GetSlotInfo(slotHandle);
    const tokenInfo = pkcs11.C_GetTokenInfo(slotHandle);

    session = pkcs11.C_OpenSession(slotHandle, CKF_SERIAL_SESSION | CKF_RW_SESSION);

    if (pkcs11Options.pin) {
      pkcs11.C_Login(session, pkcs11Options.userType ?? CKU_USER, pkcs11Options.pin);
      loggedIn = true;
    }

    const privateKeyHandle = findPkcs11ObjectHandle(pkcs11, session, CKO_PRIVATE_KEY, pkcs11Options.privateKey);
    if (!privateKeyHandle) {
      throw new Error('PKCS#11 özel anahtarı bulunamadı.');
    }

    let certificatePem = resolveCertificateOnly(options);
    if (!certificatePem) {
      if (!pkcs11Options.certificate) {
        throw new Error('PKCS#11 sertifikası bulunamadı. Sertifika bilgisi sağlayın.');
      }
      const certificateHandle = findPkcs11ObjectHandle(pkcs11, session, CKO_CERTIFICATE, pkcs11Options.certificate);
      if (!certificateHandle) {
        throw new Error('PKCS#11 sertifika nesnesi bulunamadı.');
      }
      const certificateDer = readPkcs11Attribute(pkcs11, session, certificateHandle);
      certificatePem = formatCertificateFromDer(certificateDer.toString('base64'));
    }

    const trimmedCertificate = certificatePem.trim();
    const { signingInput } = buildSigningPreparation(
      trimmedCertificate,
      digest,
      ledgerRoot,
      previousLedgerRoot,
    );
    pkcs11.C_SignInit(session, { mechanism: pkcs11Options.mechanism ?? CKM_EDDSA }, privateKeyHandle);
    const signatureBuffer = pkcs11.C_Sign(session, Buffer.from(signingInput, 'utf8'));

    const bundle = buildBundleFromSignature(
      trimmedCertificate,
      digest,
      ledgerRoot,
      previousLedgerRoot,
      signingInput,
      signatureBuffer,
    );

    const hardwareMetadata: HardwareSignatureMetadata = {
      provider: 'PKCS11',
      slot: {
        id: readSlotId(slotHandle),
        index: slotIndex,
        description: normalizePkcs11String(slotInfo.slotDescription),
        manufacturer: normalizePkcs11String(slotInfo.manufacturerID),
        hardwareVersion: formatVersion(slotInfo.hardwareVersion),
        firmwareVersion: formatVersion(slotInfo.firmwareVersion),
        tokenLabel: normalizePkcs11String(tokenInfo.label),
        tokenModel: normalizePkcs11String(tokenInfo.model),
        tokenManufacturer: normalizePkcs11String(tokenInfo.manufacturerID),
        tokenSerial: normalizePkcs11String(tokenInfo.serialNumber),
      },
    };

    if (pkcs11Options.attestation && (pkcs11Options.attestation.label || pkcs11Options.attestation.idHex)) {
      const attestationHandle = findPkcs11ObjectHandle(
        pkcs11,
        session,
        CKO_DATA,
        pkcs11Options.attestation,
      );
      if (attestationHandle) {
        const attestationValue = readPkcs11Attribute(pkcs11, session, attestationHandle);
        hardwareMetadata.attestation = {
          format: pkcs11Options.attestation.format ?? 'yubihsm-attestation',
          data: attestationValue.toString('base64'),
        };
      }
    }

    bundle.hardware = hardwareMetadata;
    return bundle;
  } finally {
    if (session !== undefined) {
      try {
        if (loggedIn) {
          pkcs11.C_Logout(session);
        }
      } catch (error) {
        // Ignore logout errors to prioritize primary failure reasons.
      }
      try {
        pkcs11.C_CloseSession(session);
      } catch (error) {
        // Ignore close session errors.
      }
    }
    try {
      pkcs11.C_Finalize();
    } catch (error) {
      // Ignore finalize errors.
    }
  }
};

export const signManifestWithSecuritySigner = (
  manifest: Manifest,
  options: SecuritySignerOptions = {},
): ManifestSignatureBundle => {
  const digest = computeManifestDigest(manifest);
  const manifestLedger = (manifest as ManifestLedgerMetadata).ledger;
  const ledgerSource =
    options.ledger ??
    (manifestLedger && typeof manifestLedger.root === 'string'
      ? {
          root: manifestLedger.root,
          previousRoot: manifestLedger.previousRoot ?? null,
        }
      : undefined);

  const ledgerRoot = ledgerSource?.root ?? null;
  const previousLedgerRoot =
    ledgerSource?.previousRoot ?? manifestLedger?.previousRoot ?? null;

  if (options.pkcs11) {
    return signManifestWithPkcs11(digest, ledgerRoot, previousLedgerRoot, options);
  }

  const credentials = resolveCredentials(options);
  const { signingInput } = buildSigningPreparation(
    credentials.certificatePem,
    digest,
    ledgerRoot,
    previousLedgerRoot,
  );
  const signatureBuffer = signData(
    null,
    Buffer.from(signingInput, 'utf8'),
    credentials.privateKeyPem,
  );

  return buildBundleFromSignature(
    credentials.certificatePem,
    digest,
    ledgerRoot,
    previousLedgerRoot,
    signingInput,
    signatureBuffer,
  );
};

export const verifyManifestSignatureWithSecuritySigner = (
  manifest: Manifest,
  signature: string,
  options: VerificationOptions = {},
): VerificationResult => {
  const segments = signature.split('.');
  if (segments.length !== 3) {
    return { valid: false, reason: 'FORMAT_INVALID' };
  }

  const [encodedHeader, encodedPayload, encodedSignature] = segments;

  let header: { alg?: string; typ?: string; x5c?: string[] };
  try {
    header = JSON.parse(base64UrlDecode(encodedHeader).toString('utf8')) as {
      alg?: string;
      typ?: string;
      x5c?: string[];
    };
  } catch (error) {
    return { valid: false, reason: 'FORMAT_INVALID' };
  }

  if (header.alg !== 'EdDSA') {
    return { valid: false, reason: 'UNSUPPORTED_ALGORITHM' };
  }

  let payload: {
    digest?: string;
    algorithm?: string;
    ledgerRoot?: string | null;
    previousLedgerRoot?: string | null;
  };
  try {
    payload = JSON.parse(base64UrlDecode(encodedPayload).toString('utf8')) as {
      digest?: string;
      algorithm?: string;
      ledgerRoot?: string | null;
      previousLedgerRoot?: string | null;
    };
  } catch (error) {
    return { valid: false, reason: 'FORMAT_INVALID' };
  }

  const digest = computeManifestDigest(manifest);
  const ledgerRoot = typeof payload.ledgerRoot === 'string' ? payload.ledgerRoot : payload.ledgerRoot ?? null;
  const previousLedgerRoot =
    typeof payload.previousLedgerRoot === 'string'
      ? payload.previousLedgerRoot
      : payload.previousLedgerRoot ?? null;
  const ledgerContext = { ledgerRoot, previousLedgerRoot };

  if (payload.algorithm !== digest.algorithm || payload.digest !== digest.hash) {
    return { valid: false, reason: 'DIGEST_MISMATCH', ...ledgerContext };
  }

  if (options.requireLedgerProof && !ledgerRoot) {
    return { valid: false, reason: 'LEDGER_ROOT_MISSING', ...ledgerContext };
  }

  if (typeof options.expectedLedgerRoot !== 'undefined' && ledgerRoot !== options.expectedLedgerRoot) {
    return { valid: false, reason: 'LEDGER_ROOT_MISMATCH', ...ledgerContext };
  }

  if (
    typeof options.expectedPreviousLedgerRoot !== 'undefined' &&
    previousLedgerRoot !== options.expectedPreviousLedgerRoot
  ) {
    return { valid: false, reason: 'LEDGER_PREVIOUS_MISMATCH', ...ledgerContext };
  }

  let certificatePem = options.certificatePem;
  let certificateInfo: VerificationResult['certificateInfo'];
  let verificationKey: Parameters<typeof verifySignature>[2] | undefined = options.publicKeyPem;

  const loadCertificate = (pem: string): X509Certificate | undefined => {
    try {
      return new X509Certificate(pem);
    } catch (error) {
      return undefined;
    }
  };

  let certificate: X509Certificate | undefined;

  if (certificatePem) {
    certificate = loadCertificate(certificatePem);
    if (!certificate) {
      return { valid: false, reason: 'FORMAT_INVALID', ...ledgerContext };
    }
  } else if (!verificationKey && header.x5c?.length) {
    try {
      certificatePem = formatCertificateFromDer(header.x5c[0]);
    } catch (error) {
      return { valid: false, reason: 'FORMAT_INVALID', ...ledgerContext };
    }

    certificate = loadCertificate(certificatePem);
    if (!certificate) {
      return { valid: false, reason: 'FORMAT_INVALID', ...ledgerContext };
    }
  }

  if (certificate) {
    certificateInfo = {
      subject: certificate.subject,
      validFrom: certificate.validFrom,
      validTo: certificate.validTo,
    };

    const now = options.now ?? new Date();
    const notBefore = new Date(certificate.validFrom);
    const notAfter = new Date(certificate.validTo);
    if (now < notBefore || now > notAfter) {
      return {
        valid: false,
        reason: 'CERT_EXPIRED',
        certificateInfo,
        ...ledgerContext,
      };
    }

    verificationKey = certificate.publicKey;
  }

  if (!verificationKey) {
    return { valid: false, reason: 'CERTIFICATE_MISSING', ...ledgerContext };
  }

  let isValid: boolean;
  try {
    isValid = verifySignature(
      null,
      Buffer.from(`${encodedHeader}.${encodedPayload}`, 'utf8'),
      verificationKey,
      base64UrlDecode(encodedSignature),
    );
  } catch (error) {
    return { valid: false, reason: 'FORMAT_INVALID', certificateInfo, ...ledgerContext };
  }

  if (!isValid) {
    return { valid: false, reason: 'SIGNATURE_INVALID', certificateInfo, ...ledgerContext };
  }

  return {
    valid: true,
    digest,
    certificateInfo,
    ...ledgerContext,
  };
};

export const assertValidManifestSignature = (
  manifest: Manifest,
  signature: string,
  options: VerificationOptions = {},
): VerificationResult => {
  const result = verifyManifestSignatureWithSecuritySigner(manifest, signature, options);
  if (!result.valid) {
    const reason = result.reason ?? 'Bilinmeyen hata';
    throw new Error(`Manifest imzası doğrulanamadı: ${reason}`);
  }
  return result;
};

export const computeManifestDigestHex = (manifest: Manifest): string => computeManifestDigest(manifest).hash;
