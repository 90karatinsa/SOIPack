import { createHash, createSign, createVerify, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { Manifest } from '@soipack/core';

export interface ManifestDigest {
  algorithm: 'SHA-256';
  hash: string;
}

export interface ManifestSignatureBundle {
  signature: string;
  certificate: string;
  manifestDigest: ManifestDigest;
}

export interface SecuritySignerOptions {
  bundlePath?: string;
  bundlePem?: string;
  certificatePath?: string;
  certificatePem?: string;
  privateKeyPath?: string;
  privateKeyPem?: string;
}

export type VerificationFailureReason =
  | 'FORMAT_INVALID'
  | 'UNSUPPORTED_ALGORITHM'
  | 'DIGEST_MISMATCH'
  | 'SIGNATURE_INVALID'
  | 'CERT_EXPIRED'
  | 'CERTIFICATE_MISSING';

export interface VerificationOptions {
  certificatePem?: string;
  now?: Date;
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

const canonicalizeManifest = (manifest: Manifest): Manifest => ({
  files: [...manifest.files]
    .map((file) => ({ path: file.path, sha256: file.sha256 }))
    .sort((a, b) => a.path.localeCompare(b.path)),
  createdAt: manifest.createdAt,
  toolVersion: manifest.toolVersion,
});

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

const formatCertificateFromDer = (derBase64: string): string => {
  const chunks = derBase64.match(/.{1,64}/g) ?? [];
  return ['-----BEGIN CERTIFICATE-----', ...chunks, '-----END CERTIFICATE-----', ''].join('\n').trim();
};

const resolveCertificateForVerification = (
  encodedHeader: string,
  options: VerificationOptions,
): { certificatePem?: string; headerCertificateInfo?: { subject: string; validFrom: string; validTo: string } } => {
  const headerJson = base64UrlDecode(encodedHeader).toString('utf8');
  let header: { alg?: string; x5c?: string[] };
  try {
    header = JSON.parse(headerJson) as { alg?: string; x5c?: string[] };
  } catch (error) {
    throw new Error('JWS başlığı çözümlenemedi.');
  }

  let certificatePem = options.certificatePem;
  if (!certificatePem && header.x5c?.length) {
    certificatePem = formatCertificateFromDer(header.x5c[0]);
  }

  if (!certificatePem) {
    return { certificatePem: undefined };
  }

  const x509 = new X509Certificate(certificatePem);
  return {
    certificatePem,
    headerCertificateInfo: {
      subject: x509.subject,
      validFrom: x509.validFrom,
      validTo: x509.validTo,
    },
  };
};

export const signManifestWithSecuritySigner = (
  manifest: Manifest,
  options: SecuritySignerOptions = {},
): ManifestSignatureBundle => {
  const credentials = resolveCredentials(options);
  const digest = computeManifestDigest(manifest);

  const x509 = new X509Certificate(credentials.certificatePem);
  const header = {
    alg: 'RS256',
    typ: 'SOIManifest',
    x5c: [x509.raw.toString('base64')],
  };
  const payload = {
    digest: digest.hash,
    algorithm: digest.algorithm,
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signer = createSign('RSA-SHA256');
  signer.update(signingInput);
  signer.end();
  const signature = signer.sign(credentials.privateKeyPem, 'base64url');

  return {
    signature: `${signingInput}.${signature}`,
    certificate: credentials.certificatePem.trim(),
    manifestDigest: digest,
  };
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

  let header: { alg?: string; typ?: string };
  try {
    header = JSON.parse(base64UrlDecode(encodedHeader).toString('utf8')) as { alg?: string; typ?: string };
  } catch (error) {
    return { valid: false, reason: 'FORMAT_INVALID' };
  }

  if (header.alg !== 'RS256') {
    return { valid: false, reason: 'UNSUPPORTED_ALGORITHM' };
  }

  let payload: { digest?: string; algorithm?: string };
  try {
    payload = JSON.parse(base64UrlDecode(encodedPayload).toString('utf8')) as {
      digest?: string;
      algorithm?: string;
    };
  } catch (error) {
    return { valid: false, reason: 'FORMAT_INVALID' };
  }

  const digest = computeManifestDigest(manifest);
  if (payload.algorithm !== digest.algorithm || payload.digest !== digest.hash) {
    return { valid: false, reason: 'DIGEST_MISMATCH' };
  }

  let certificatePem = options.certificatePem;
  let certificateInfo: VerificationResult['certificateInfo'];
  if (!certificatePem) {
    try {
      const resolved = resolveCertificateForVerification(encodedHeader, options);
      certificatePem = resolved.certificatePem;
      certificateInfo = resolved.headerCertificateInfo;
    } catch (error) {
      return { valid: false, reason: 'FORMAT_INVALID' };
    }
  } else {
    const x509 = new X509Certificate(certificatePem);
    certificateInfo = {
      subject: x509.subject,
      validFrom: x509.validFrom,
      validTo: x509.validTo,
    };
  }

  if (!certificatePem) {
    return { valid: false, reason: 'CERTIFICATE_MISSING' };
  }

  const certificate = new X509Certificate(certificatePem);
  const now = options.now ?? new Date();
  const notBefore = new Date(certificate.validFrom);
  const notAfter = new Date(certificate.validTo);
  if (now < notBefore || now > notAfter) {
    return {
      valid: false,
      reason: 'CERT_EXPIRED',
      certificateInfo,
    };
  }

  const verifier = createVerify('RSA-SHA256');
  verifier.update(`${encodedHeader}.${encodedPayload}`);
  verifier.end();
  const isValid = verifier.verify(certificatePem, base64UrlDecode(encodedSignature));

  if (!isValid) {
    return { valid: false, reason: 'SIGNATURE_INVALID', certificateInfo };
  }

  return {
    valid: true,
    digest,
    certificateInfo,
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
