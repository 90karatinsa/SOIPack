import { createHash, sign as signData, verify as verifySignature, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { Manifest } from '@soipack/core';
import forge from 'node-forge';

import {
  DEFAULT_POST_QUANTUM_ALGORITHM,
  deriveSphincsPlusPublicKey,
  loadDefaultSphincsPlusKeyPair,
  type SphincsPlusAlgorithm,
  signWithSphincsPlus,
  verifyWithSphincsPlus,
} from './pqc';

export type PostQuantumAlgorithm = SphincsPlusAlgorithm;

export interface PostQuantumSigningOptions {
  algorithm?: PostQuantumAlgorithm;
  privateKey?: string;
  privateKeyPath?: string;
  publicKey?: string;
  publicKeyPath?: string;
}

export interface PostQuantumVerificationOptions {
  algorithm?: PostQuantumAlgorithm;
  publicKey?: string;
  required?: boolean;
}

export interface CmsSigningOptions {
  bundlePath?: string;
  bundlePem?: string;
  certificatePath?: string;
  certificatePem?: string;
  privateKeyPath?: string;
  privateKeyPem?: string;
  chainPath?: string;
  chainPem?: string;
  digestAlgorithm?: 'sha256';
}

export interface CmsVerificationOptions {
  signatureDer?: string;
  signaturePem?: string;
  signaturePath?: string;
  required?: boolean;
  certificatePem?: string;
  certificatePath?: string;
}

type ManifestLedgerMetadata = {
  ledger?: {
    root: string | null;
    previousRoot?: string | null;
  } | null;
};

type ManifestStageMetadata = { stage?: string | null };

type LedgerAwareManifest = Manifest & ManifestLedgerMetadata & ManifestStageMetadata;

export interface ManifestDigest {
  algorithm: 'SHA-256';
  hash: string;
}

export interface LedgerProofMetadata {
  root: string;
  previousRoot?: string | null;
}

export interface CmsSignatureBundle {
  der: string;
  pem: string;
  certificates: string[];
  digestAlgorithm: string;
  signerSerialNumber?: string;
  signerIssuer?: string;
  signerSubject?: string;
  signatureAlgorithm?: string;
}

export interface CmsVerificationResult {
  verified: boolean;
  digestVerified: boolean;
  signerSerialNumber?: string;
  signerIssuer?: string;
  signerSubject?: string;
  signatureAlgorithm?: string;
}

export interface ManifestSignatureBundle {
  signature: string;
  certificate: string;
  manifestDigest: ManifestDigest;
  ledgerRoot?: string | null;
  previousLedgerRoot?: string | null;
  hardware?: HardwareSignatureMetadata;
  postQuantumSignature?: {
    algorithm: PostQuantumAlgorithm;
    signature: string;
    publicKey: string;
  };
  cmsSignature?: CmsSignatureBundle;
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
  postQuantum?: PostQuantumSigningOptions | false;
  cms?: CmsSigningOptions | false;
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
  | 'LEDGER_PREVIOUS_MISMATCH'
  | 'CMS_SIGNATURE_REQUIRED'
  | 'CMS_SIGNATURE_MISSING'
  | 'CMS_SIGNATURE_INVALID'
  | 'CMS_DIGEST_MISMATCH'
  | 'CMS_CERTIFICATE_MISMATCH';

export interface VerificationOptions {
  certificatePem?: string;
  publicKeyPem?: string;
  now?: Date;
  expectedLedgerRoot?: string | null;
  expectedPreviousLedgerRoot?: string | null;
  requireLedgerProof?: boolean;
  postQuantum?: PostQuantumVerificationOptions;
  cms?: CmsVerificationOptions;
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
  postQuantum?: {
    algorithm: PostQuantumAlgorithm;
    publicKey: string;
    verified: boolean;
  };
  cms?: CmsVerificationResult;
}

const DEFAULT_BUNDLE_PATH = path.resolve(__dirname, '../../../../test/certs/dev.pem');

const CERTIFICATE_PATTERN = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/;
const ALL_CERTIFICATES_PATTERN = new RegExp(CERTIFICATE_PATTERN.source, 'g');
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

const normalizeBase64String = (value: string): string => value.replace(/\s+/g, '').trim();

type PostQuantumSigningMaterial = {
  algorithm: PostQuantumAlgorithm;
  privateKey: string;
  publicKey: string;
};

type CmsSigningMaterial = {
  certificatePem: string;
  privateKeyPem: string;
  certificateChain: string[];
  digestAlgorithm: 'sha256';
};

const resolvePostQuantumSigningMaterial = (
  options?: PostQuantumSigningOptions | false,
): PostQuantumSigningMaterial | undefined => {
  if (options === false) {
    return undefined;
  }

  const requestedAlgorithm = options?.algorithm ?? DEFAULT_POST_QUANTUM_ALGORITHM;

  let privateKey = options?.privateKey;
  if (!privateKey && options?.privateKeyPath) {
    privateKey = readFileSync(options.privateKeyPath, 'utf8');
  }
  privateKey = privateKey ? normalizeBase64String(privateKey) : undefined;

  let publicKey = options?.publicKey;
  if (!publicKey && options?.publicKeyPath) {
    publicKey = readFileSync(options.publicKeyPath, 'utf8');
  }
  publicKey = publicKey ? normalizeBase64String(publicKey) : undefined;

  if (!privateKey && !publicKey) {
    const defaults = loadDefaultSphincsPlusKeyPair();
    return {
      algorithm: defaults.algorithm,
      privateKey: defaults.privateKey,
      publicKey: defaults.publicKey,
    };
  }

  if (!privateKey) {
    if (publicKey) {
      throw new Error('Post-quantum imza oluşturmak için özel anahtar gereklidir.');
    }
    const defaults = loadDefaultSphincsPlusKeyPair();
    return {
      algorithm: options?.algorithm ?? defaults.algorithm,
      privateKey: defaults.privateKey,
      publicKey: defaults.publicKey,
    };
  }

  if (!publicKey) {
    publicKey = deriveSphincsPlusPublicKey(privateKey, requestedAlgorithm);
  }

  return {
    algorithm: requestedAlgorithm,
    privateKey,
    publicKey,
  };
};

const resolveCmsSigningMaterial = (
  options: SecuritySignerOptions,
): CmsSigningMaterial | undefined => {
  if (options.cms === false) {
    return undefined;
  }

  const cmsOptions = options.cms;
  if (!cmsOptions) {
    return undefined;
  }

  let certificatePem: string | undefined;
  let privateKeyPem: string | undefined;
  let certificateChain: string[] = [];

  const appendChain = (pem?: string): void => {
    if (!pem) {
      return;
    }
    certificateChain.push(...extractCertificateChain(pem));
  };

  if (cmsOptions.bundlePem) {
    const pair = extractCredentialPair(cmsOptions.bundlePem);
    certificatePem = pair.certificatePem;
    privateKeyPem = pair.privateKeyPem;
    certificateChain = [...pair.certificateChain];
  } else if (cmsOptions.bundlePath) {
    const bundlePem = readFileSync(cmsOptions.bundlePath, 'utf8');
    const pair = extractCredentialPair(bundlePem);
    certificatePem = pair.certificatePem;
    privateKeyPem = pair.privateKeyPem;
    certificateChain = [...pair.certificateChain];
  } else {
    if (cmsOptions.certificatePem) {
      certificatePem = cmsOptions.certificatePem;
      appendChain(cmsOptions.certificatePem);
    } else if (cmsOptions.certificatePath) {
      const pem = readFileSync(cmsOptions.certificatePath, 'utf8');
      certificatePem = pem;
      appendChain(pem);
    }

    if (cmsOptions.privateKeyPem) {
      privateKeyPem = cmsOptions.privateKeyPem;
    } else if (cmsOptions.privateKeyPath) {
      privateKeyPem = readFileSync(cmsOptions.privateKeyPath, 'utf8');
    }
  }

  if (!certificatePem || !privateKeyPem) {
    return undefined;
  }

  if (!certificateChain.length) {
    certificateChain.push(certificatePem.trim());
  }

  appendChain(cmsOptions.chainPem);
  if (cmsOptions.chainPath) {
    appendChain(readFileSync(cmsOptions.chainPath, 'utf8'));
  }

  const digestAlgorithm = cmsOptions.digestAlgorithm ?? 'sha256';
  if (digestAlgorithm !== 'sha256') {
    throw new Error('Desteklenmeyen CMS özet algoritması.');
  }

  const seen = new Set<string>();
  const uniqueChain = certificateChain.filter((certificate) => {
    const key = certificate.trim();
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });

  return {
    certificatePem,
    privateKeyPem,
    certificateChain: uniqueChain,
    digestAlgorithm,
  };
};

const createPostQuantumSignature = (
  signingInput: string,
  material?: PostQuantumSigningMaterial,
):
  | {
      algorithm: PostQuantumAlgorithm;
      publicKey: string;
      signature: Buffer;
    }
  | undefined => {
  if (!material) {
    return undefined;
  }

  const signature = signWithSphincsPlus(
    Buffer.from(signingInput, 'utf8'),
    material.privateKey,
    material.algorithm,
  );

  return {
    algorithm: material.algorithm,
    publicKey: material.publicKey,
    signature,
  };
};

const resolveSignatureAlgorithmName = (certificate: forge.pki.Certificate): string | undefined => {
  const oid = certificate.signatureOid ?? certificate.siginfo?.algorithmOid;
  if (!oid) {
    return undefined;
  }
  const friendly = forge.pki.oids[oid];
  return typeof friendly === 'string' ? friendly : oid;
};

const resolveNodeDigestAlgorithm = (oid?: string): 'sha256' | undefined => {
  if (!oid) {
    return undefined;
  }
  switch (oid) {
    case forge.pki.oids.sha256:
    case forge.pki.oids.sha256WithRSAEncryption:
      return 'sha256';
    default:
      return undefined;
  }
};

type ForgeSignedData = forge.pkcs7.PkcsSignedData;

const createCmsSignatureBundle = (
  serializedManifest: string,
  digest: ManifestDigest,
  material?: CmsSigningMaterial,
): CmsSignatureBundle | undefined => {
  if (!material) {
    return undefined;
  }

  const signerCertificate = forge.pki.certificateFromPem(material.certificatePem);
  const privateKey = forge.pki.privateKeyFromPem(material.privateKeyPem);
  const signedData = forge.pkcs7.createSignedData();
  signedData.content = forge.util.createBuffer(serializedManifest, 'utf8');

  for (const certificate of material.certificateChain) {
    signedData.addCertificate(forge.pki.certificateFromPem(certificate));
  }

  signedData.addSigner({
    key: privateKey,
    certificate: signerCertificate,
    digestAlgorithm: forge.pki.oids.sha256,
    authenticatedAttributes: [
      { type: forge.pki.oids.contentType, value: forge.pki.oids.data },
      { type: forge.pki.oids.messageDigest },
    ],
  });

  signedData.sign({ detached: false });

  const derBytes = forge.asn1.toDer(signedData.toAsn1()).getBytes();
  const derBuffer = Buffer.from(derBytes, 'binary');
  const pem = forge.pkcs7.messageToPem(signedData);

  const x509 = new X509Certificate(material.certificatePem);
  const signatureAlgorithm = resolveSignatureAlgorithmName(signerCertificate);

  return {
    der: derBuffer.toString('base64'),
    pem: pem.trim(),
    certificates: material.certificateChain.map((certificate) => certificate.trim()),
    digestAlgorithm: digest.algorithm,
    signerSerialNumber: x509.serialNumber,
    signerIssuer: x509.issuer,
    signerSubject: x509.subject,
    signatureAlgorithm,
  };
};

const extractCmsSignerVerificationInputs = (
  signedMessage: ForgeSignedData,
): {
  digestOid?: string;
  signature?: Buffer;
  signedAttributes?: Buffer;
  attributesPresent: boolean;
} => {
  const capture = (signedMessage as unknown as {
    rawCapture?: {
      signerInfos?: forge.asn1.Asn1[];
      digestAlgorithm?: string;
      signature?: string;
    };
  }).rawCapture;

  const signerInfos = Array.isArray(capture?.signerInfos) ? capture?.signerInfos : [];
  const signerInfo = signerInfos && signerInfos.length > 0 ? signerInfos[0] : undefined;

  let digestOid: string | undefined;
  let signatureBytes: string | undefined;
  let signedAttributes: Buffer | undefined;
  let attributesPresent = false;

  if (signerInfo && Array.isArray(signerInfo.value)) {
    const digestSequence = signerInfo.value[2];
    if (
      digestSequence &&
      Array.isArray(digestSequence.value) &&
      digestSequence.value.length > 0 &&
      typeof digestSequence.value[0]?.value === 'string'
    ) {
      digestOid = forge.asn1.derToOid(digestSequence.value[0].value as string);
    }

    const attributesNode = signerInfo.value.find(
      (node: forge.asn1.Asn1) =>
        node.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC &&
        node.type === 0 &&
        Array.isArray(node.value),
    );

    if (attributesNode) {
      attributesPresent = true;
      const attributeSet = forge.asn1.create(
        forge.asn1.Class.UNIVERSAL,
        forge.asn1.Type.SET,
        true,
        (attributesNode.value as forge.asn1.Asn1[]).map((attribute) => attribute),
      );
      const derBytes = forge.asn1.toDer(attributeSet).getBytes();
      signedAttributes = Buffer.from(derBytes, 'binary');
    }

    const signatureNode = signerInfo.value.find(
      (node: forge.asn1.Asn1) =>
        node.tagClass === forge.asn1.Class.UNIVERSAL &&
        node.type === forge.asn1.Type.OCTETSTRING &&
        typeof node.value === 'string',
    );

    if (signatureNode) {
      signatureBytes = signatureNode.value as string;
    }
  }

  if (!digestOid && capture?.digestAlgorithm) {
    digestOid = forge.asn1.derToOid(capture.digestAlgorithm);
  }

  if (!signatureBytes && typeof capture?.signature === 'string') {
    signatureBytes = capture.signature;
  }

  return {
    digestOid,
    signature: signatureBytes ? Buffer.from(signatureBytes, 'binary') : undefined,
    signedAttributes,
    attributesPresent,
  };
};

const extractCmsContentBuffer = (signedMessage: ForgeSignedData): Buffer | undefined => {
  const rawContent = (signedMessage as unknown as { content?: string | forge.util.ByteBuffer }).content;

  if (typeof rawContent === 'string' && rawContent.length > 0) {
    return Buffer.from(rawContent, 'binary');
  }

  if (rawContent && typeof (rawContent as forge.util.ByteBuffer).bytes === 'function') {
    const byteString = (rawContent as forge.util.ByteBuffer).bytes();
    if (byteString.length > 0) {
      return Buffer.from(byteString, 'binary');
    }
  }

  const captureContent = (signedMessage as unknown as { rawCapture?: { content?: forge.asn1.Asn1 } }).rawCapture?.content;
  if (!captureContent) {
    return undefined;
  }

  if (typeof captureContent.value === 'string') {
    return Buffer.from(captureContent.value, 'binary');
  }

  if (Array.isArray(captureContent.value)) {
    const chunks: string[] = [];
    for (const element of captureContent.value) {
      if (typeof element.value === 'string') {
        chunks.push(element.value as string);
      }
    }
    if (chunks.length > 0) {
      return Buffer.from(chunks.join(''), 'binary');
    }
  }

  return undefined;
};

const verifyCmsSignatureArtifact = (
  serializedManifest: string,
  digest: ManifestDigest,
  options?: CmsVerificationOptions,
): { result?: CmsVerificationResult; failure?: { reason: VerificationFailureReason; cms?: CmsVerificationResult } } => {
  if (!options) {
    return {};
  }

  const required = options.required ?? false;

  let signaturePem = options.signaturePem;
  let signatureDer = options.signatureDer;

  if (options.signaturePath) {
    const content = readFileSync(options.signaturePath, 'utf8');
    if (content.includes('-----BEGIN')) {
      signaturePem = content;
      signatureDer = undefined;
    } else {
      signatureDer = content.trim();
      signaturePem = undefined;
    }
  }

  if (!signaturePem && !signatureDer) {
    if (required) {
      return { failure: { reason: 'CMS_SIGNATURE_MISSING' } };
    }
    return {};
  }

  let signedMessage: ForgeSignedData;

  try {
    if (signaturePem) {
      const parsed = forge.pkcs7.messageFromPem(signaturePem);
      if (!('certificates' in parsed)) {
        return { failure: { reason: 'CMS_SIGNATURE_INVALID' } };
      }
      signedMessage = parsed as ForgeSignedData;
    } else {
      const derBuffer = Buffer.from(signatureDer!, 'base64');
      const asn1 = forge.asn1.fromDer(derBuffer.toString('binary'));
      const parsed = forge.pkcs7.messageFromAsn1(asn1);
      if (!('certificates' in parsed)) {
        return { failure: { reason: 'CMS_SIGNATURE_INVALID' } };
      }
      signedMessage = parsed as ForgeSignedData;
    }
  } catch (error) {
    return { failure: { reason: 'CMS_SIGNATURE_INVALID' } };
  }

  const contentBuffer = extractCmsContentBuffer(signedMessage);

  if (!contentBuffer) {
    const cmsResult: CmsVerificationResult = { verified: false, digestVerified: false };
    return { failure: { reason: 'CMS_SIGNATURE_INVALID', cms: cmsResult } };
  }

  let signerForgeCertificate: forge.pki.Certificate | undefined;
  let signerX509: X509Certificate | undefined;
  if (signedMessage.certificates && signedMessage.certificates.length > 0) {
    try {
      signerForgeCertificate = signedMessage.certificates[0];
      const signerPem = forge.pki.certificateToPem(signerForgeCertificate);
      signerX509 = new X509Certificate(signerPem);
    } catch (error) {
      signerX509 = undefined;
    }
  }

  const signerInputs = extractCmsSignerVerificationInputs(signedMessage);
  const digestAlgorithm = resolveNodeDigestAlgorithm(signerInputs.digestOid);

  if (!signerInputs.signature || !digestAlgorithm || !signerX509) {
    const cmsResult: CmsVerificationResult = { verified: false, digestVerified: false };
    return { failure: { reason: 'CMS_SIGNATURE_INVALID', cms: cmsResult } };
  }

  if (signerInputs.attributesPresent && !signerInputs.signedAttributes) {
    const cmsResult: CmsVerificationResult = { verified: false, digestVerified: false };
    return { failure: { reason: 'CMS_SIGNATURE_INVALID', cms: cmsResult } };
  }

  const signedContent = signerInputs.signedAttributes ?? contentBuffer;
  if (!signedContent) {
    const cmsResult: CmsVerificationResult = { verified: false, digestVerified: false };
    return { failure: { reason: 'CMS_SIGNATURE_INVALID', cms: cmsResult } };
  }

  let verified = false;
  try {
    verified = verifySignature(digestAlgorithm, signedContent, signerX509.publicKey, signerInputs.signature);
  } catch (error) {
    return { failure: { reason: 'CMS_SIGNATURE_INVALID' } };
  }

  const digestVerified = createHash('sha256').update(contentBuffer).digest('hex') === digest.hash;

  const signatureAlgorithm = signerForgeCertificate
    ? resolveSignatureAlgorithmName(signerForgeCertificate)
    : undefined;

  const cmsResult: CmsVerificationResult = {
    verified,
    digestVerified,
    signerSerialNumber: signerX509?.serialNumber,
    signerIssuer: signerX509?.issuer,
    signerSubject: signerX509?.subject,
    signatureAlgorithm,
  };

  if (!verified) {
    return { failure: { reason: 'CMS_SIGNATURE_INVALID', cms: cmsResult } };
  }

  if (!digestVerified || !contentBuffer.equals(Buffer.from(serializedManifest, 'utf8'))) {
    return { failure: { reason: 'CMS_DIGEST_MISMATCH', cms: cmsResult } };
  }

  let expectedCertificatePem = options.certificatePem;
  if (!expectedCertificatePem && options.certificatePath) {
    expectedCertificatePem = readFileSync(options.certificatePath, 'utf8');
  }

  if (expectedCertificatePem) {
    if (!signerX509) {
      return { failure: { reason: 'CMS_CERTIFICATE_MISMATCH', cms: cmsResult } };
    }
    const expectedX509 = new X509Certificate(expectedCertificatePem);
    if (expectedX509.raw.toString('base64') !== signerX509.raw.toString('base64')) {
      return { failure: { reason: 'CMS_CERTIFICATE_MISMATCH', cms: cmsResult } };
    }
  }

  return { result: cmsResult };
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

const canonicalizeManifest = (manifest: Manifest & ManifestLedgerMetadata & ManifestStageMetadata): Manifest => {
  const canonical: LedgerAwareManifest = {
    files: [...manifest.files]
      .map((file) => ({ path: file.path, sha256: file.sha256 }))
      .sort((a, b) => a.path.localeCompare(b.path)),
    createdAt: manifest.createdAt,
    toolVersion: manifest.toolVersion,
  };

  if (manifest.stage !== undefined) {
    canonical.stage = manifest.stage ?? null;
  }

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

const serializeCanonicalManifest = (manifest: Manifest): string => JSON.stringify(manifest);

const computeManifestDigestContext = (
  manifest: Manifest,
): { digest: ManifestDigest; canonical: Manifest; serialized: string } => {
  const canonical = canonicalizeManifest(manifest);
  const serialized = serializeCanonicalManifest(canonical);
  const hash = createHash('sha256').update(serialized).digest('hex');
  return { digest: { algorithm: 'SHA-256', hash }, canonical, serialized };
};

const computeManifestDigest = (manifest: Manifest): ManifestDigest =>
  computeManifestDigestContext(manifest).digest;

interface CredentialPair {
  certificatePem: string;
  privateKeyPem: string;
  certificateChain: string[];
}

const extractCertificateChain = (pemBundle: string): string[] => {
  const certificateMatches = pemBundle.match(ALL_CERTIFICATES_PATTERN) ?? [];
  return certificateMatches.map((certificate) => certificate.trim());
};

const extractCredentialPair = (pemBundle: string): CredentialPair => {
  const certificateMatch = pemBundle.match(CERTIFICATE_PATTERN);
  const privateKeyMatch = pemBundle.match(PRIVATE_KEY_PATTERN);
  if (!certificateMatch || !privateKeyMatch) {
    throw new Error('PEM demeti hem sertifika hem de özel anahtar içermelidir.');
  }

  return {
    certificatePem: certificateMatch[0],
    privateKeyPem: privateKeyMatch[0],
    certificateChain: extractCertificateChain(pemBundle),
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
      certificateChain: [options.certificatePem.trim()],
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
    const certificatePem = readFileSync(options.certificatePath, 'utf8');
    return {
      certificatePem,
      privateKeyPem: readFileSync(options.privateKeyPath, 'utf8'),
      certificateChain: extractCertificateChain(certificatePem),
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
  postQuantum?: { algorithm: PostQuantumAlgorithm; publicKey: string },
): { signingInput: string } => {
  const x509 = new X509Certificate(certificatePem);
  const header: Record<string, unknown> = {
    alg: postQuantum ? 'SOI-HYBRID' : 'EdDSA',
    typ: 'SOIManifest',
    x5c: [x509.raw.toString('base64')],
  };

  if (postQuantum) {
    header.pq = {
      alg: postQuantum.algorithm,
      pub: postQuantum.publicKey,
    };
  }
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
  postQuantumSignature?: {
    algorithm: PostQuantumAlgorithm;
    publicKey: string;
    signature: Buffer;
  },
  cmsSignature?: CmsSignatureBundle,
): ManifestSignatureBundle => {
  const segments = [signingInput, base64UrlEncode(signatureBuffer)];
  let pqSignature: ManifestSignatureBundle['postQuantumSignature'];

  if (postQuantumSignature) {
    const encodedPostQuantum = base64UrlEncode(postQuantumSignature.signature);
    segments.push(encodedPostQuantum);
    pqSignature = {
      algorithm: postQuantumSignature.algorithm,
      publicKey: postQuantumSignature.publicKey,
      signature: encodedPostQuantum,
    };
  }

  return {
    signature: segments.join('.'),
    certificate: certificatePem.trim(),
    manifestDigest: digest,
    ledgerRoot,
    previousLedgerRoot,
    postQuantumSignature: pqSignature,
    cmsSignature,
  };
};

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
  postQuantumMaterial?: PostQuantumSigningMaterial,
  serializedManifest?: string,
  cmsMaterial?: CmsSigningMaterial,
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
      postQuantumMaterial && {
        algorithm: postQuantumMaterial.algorithm,
        publicKey: postQuantumMaterial.publicKey,
      },
    );
    pkcs11.C_SignInit(session, { mechanism: pkcs11Options.mechanism ?? CKM_EDDSA }, privateKeyHandle);
    const signatureBuffer = pkcs11.C_Sign(session, Buffer.from(signingInput, 'utf8'));

    const postQuantumSignature = createPostQuantumSignature(signingInput, postQuantumMaterial);
    const cmsSignature = serializedManifest
      ? createCmsSignatureBundle(serializedManifest, digest, cmsMaterial)
      : undefined;

    const bundle = buildBundleFromSignature(
      trimmedCertificate,
      digest,
      ledgerRoot,
      previousLedgerRoot,
      signingInput,
      signatureBuffer,
      postQuantumSignature,
      cmsSignature,
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
  const { digest, serialized } = computeManifestDigestContext(manifest);
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

  const postQuantumMaterial = resolvePostQuantumSigningMaterial(options.postQuantum);
  const cmsMaterial = resolveCmsSigningMaterial(options);

  if (options.pkcs11) {
    return signManifestWithPkcs11(
      digest,
      ledgerRoot,
      previousLedgerRoot,
      options,
      postQuantumMaterial,
      serialized,
      cmsMaterial,
    );
  }

  const credentials = resolveCredentials(options);
  const { signingInput } = buildSigningPreparation(
    credentials.certificatePem,
    digest,
    ledgerRoot,
    previousLedgerRoot,
    postQuantumMaterial && {
      algorithm: postQuantumMaterial.algorithm,
      publicKey: postQuantumMaterial.publicKey,
    },
  );
  const signatureBuffer = signData(
    null,
    Buffer.from(signingInput, 'utf8'),
    credentials.privateKeyPem,
  );

  const postQuantumSignature = createPostQuantumSignature(signingInput, postQuantumMaterial);
  const cmsSignature = createCmsSignatureBundle(serialized, digest, cmsMaterial);

  return buildBundleFromSignature(
    credentials.certificatePem,
    digest,
    ledgerRoot,
    previousLedgerRoot,
    signingInput,
    signatureBuffer,
    postQuantumSignature,
    cmsSignature,
  );
};

export const verifyManifestSignatureWithSecuritySigner = (
  manifest: Manifest,
  signature: string,
  options: VerificationOptions = {},
): VerificationResult => {
  const segments = signature.split('.');
  if (segments.length !== 3 && segments.length !== 4) {
    return { valid: false, reason: 'FORMAT_INVALID' };
  }

  const [encodedHeader, encodedPayload, encodedSignature, encodedPostQuantumSignature] = segments;

  let header: { alg?: string; typ?: string; x5c?: string[]; pq?: { alg?: string; pub?: string } };
  try {
    header = JSON.parse(base64UrlDecode(encodedHeader).toString('utf8')) as {
      alg?: string;
      typ?: string;
      x5c?: string[];
      pq?: { alg?: string; pub?: string };
    };
  } catch (error) {
    return { valid: false, reason: 'FORMAT_INVALID' };
  }

  if (header.alg !== 'EdDSA' && header.alg !== 'SOI-HYBRID') {
    return { valid: false, reason: 'UNSUPPORTED_ALGORITHM' };
  }

  const isHybrid = header.alg === 'SOI-HYBRID';
  if (isHybrid && !encodedPostQuantumSignature) {
    return { valid: false, reason: 'FORMAT_INVALID' };
  }

  if (!isHybrid && encodedPostQuantumSignature && !options.postQuantum?.required) {
    return { valid: false, reason: 'FORMAT_INVALID' };
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

  const { digest, serialized } = computeManifestDigestContext(manifest);
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

  if (!isHybrid && options.postQuantum?.required) {
    return { valid: false, reason: 'UNSUPPORTED_ALGORITHM', ...ledgerContext };
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

  let postQuantumResult: VerificationResult['postQuantum'];

  if (isHybrid && encodedPostQuantumSignature) {
    const providedPublicKey =
      options.postQuantum?.publicKey ?? (typeof header.pq?.pub === 'string' ? header.pq.pub : undefined);
    const algorithm: PostQuantumAlgorithm =
      options.postQuantum?.algorithm ??
      ((typeof header.pq?.alg === 'string' ? header.pq.alg : DEFAULT_POST_QUANTUM_ALGORITHM) as PostQuantumAlgorithm);

    if (!providedPublicKey) {
      return { valid: false, reason: 'FORMAT_INVALID', certificateInfo, ...ledgerContext };
    }

    const postQuantumSignatureBuffer = base64UrlDecode(encodedPostQuantumSignature);
    const postQuantumValid = verifyWithSphincsPlus(
      Buffer.from(`${encodedHeader}.${encodedPayload}`, 'utf8'),
      postQuantumSignatureBuffer,
      providedPublicKey,
      algorithm,
    );

    postQuantumResult = {
      algorithm,
      publicKey: providedPublicKey,
      verified: postQuantumValid,
    };

    if (!postQuantumValid) {
      return { valid: false, reason: 'SIGNATURE_INVALID', certificateInfo, ...ledgerContext, postQuantum: postQuantumResult };
    }
  }

  const cmsVerification = verifyCmsSignatureArtifact(serialized, digest, options.cms);
  if (cmsVerification.failure) {
    return {
      valid: false,
      reason: cmsVerification.failure.reason,
      certificateInfo,
      ...ledgerContext,
      postQuantum: postQuantumResult,
      cms: cmsVerification.failure.cms,
    };
  }

  return {
    valid: true,
    digest,
    certificateInfo,
    ...ledgerContext,
    postQuantum: postQuantumResult,
    cms: cmsVerification.result,
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
