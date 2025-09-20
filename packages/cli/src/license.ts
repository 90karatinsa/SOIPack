import { promises as fs } from 'fs';
import path from 'path';

import nacl from 'tweetnacl';

export interface LicensePayload {
  licenseId: string;
  issuedTo: string;
  issuedAt: string;
  expiresAt?: string;
  features?: string[];
}

interface LicenseFileContent {
  payload: string;
  signature: string;
}

export class LicenseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LicenseError';
  }
}

const PUBLIC_KEY_BASE64 = 'mXRQccwM4wyv+mmIQZjJWAqDDvD6wYn+c/DpB1w/x20=';
const PUBLIC_KEY = Buffer.from(PUBLIC_KEY_BASE64, 'base64');

export interface VerifyLicenseOptions {
  publicKey?: Uint8Array | string;
}

const resolvePublicKey = (publicKey?: Uint8Array | string): Uint8Array => {
  if (!publicKey) {
    return PUBLIC_KEY;
  }

  if (publicKey instanceof Uint8Array) {
    if (publicKey.length !== 32) {
      throw new LicenseError('Lisans kamu anahtarı 32 bayt uzunluğunda olmalıdır.');
    }
    return Buffer.from(publicKey);
  }

  const normalized = publicKey.replace(/\s+/g, '');
  if (!normalized) {
    throw new LicenseError('Lisans kamu anahtarı boş olamaz.');
  }

  let decoded: Buffer;
  try {
    decoded = Buffer.from(normalized, 'base64');
  } catch (error) {
    throw new LicenseError('Lisans kamu anahtarı base64 formatında olmalıdır.');
  }

  if (decoded.length !== 32) {
    throw new LicenseError('Lisans kamu anahtarı Ed25519 formatında olmalıdır (32 bayt).');
  }

  return decoded;
};

export const DEFAULT_LICENSE_FILE = 'license.key';

export const resolveLicensePath = (inputPath?: string): string =>
  path.resolve(inputPath ?? DEFAULT_LICENSE_FILE);

const readLicenseFile = async (filePath: string): Promise<string> => {
  try {
    return await fs.readFile(filePath, 'utf8');
  } catch (error) {
    const err = error as NodeJS.ErrnoException;
    if (err.code === 'ENOENT') {
      throw new LicenseError(`Lisans dosyası bulunamadı: ${filePath}`);
    }
    throw new LicenseError(`Lisans dosyası okunamadı: ${filePath}`);
  }
};

const parseLicenseContent = (raw: string): LicenseFileContent => {
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch (error) {
    throw new LicenseError('Lisans anahtarı JSON formatında çözülemedi.');
  }

  if (!data || typeof data !== 'object') {
    throw new LicenseError('Lisans anahtarı beklenen alanları içermiyor.');
  }

  const { payload, signature } = data as Partial<LicenseFileContent>;
  if (typeof payload !== 'string' || payload.length === 0) {
    throw new LicenseError('Lisans dosyasında payload alanı bulunamadı.');
  }
  if (typeof signature !== 'string' || signature.length === 0) {
    throw new LicenseError('Lisans dosyasında signature alanı bulunamadı.');
  }

  return { payload, signature };
};

const decodeBase64 = (value: string, description: string): Uint8Array => {
  try {
    return Buffer.from(value, 'base64');
  } catch (error) {
    throw new LicenseError(`${description} base64 olarak çözülemedi.`);
  }
};

const verifySignature = (
  content: LicenseFileContent,
  options?: VerifyLicenseOptions,
): { payload: Uint8Array } => {
  const payloadBuffer = decodeBase64(content.payload, 'Lisans payload\'ı');
  const signatureBuffer = decodeBase64(content.signature, 'Lisans imzası');

  const publicKey = resolvePublicKey(options?.publicKey);
  if (!nacl.sign.detached.verify(payloadBuffer, signatureBuffer, publicKey)) {
    throw new LicenseError('Lisans imzası doğrulanamadı.');
  }

  return { payload: payloadBuffer };
};

const parsePayload = (payloadBytes: Uint8Array): LicensePayload => {
  let payloadJson: unknown;
  try {
    payloadJson = JSON.parse(Buffer.from(payloadBytes).toString('utf8'));
  } catch (error) {
    throw new LicenseError('Lisans içeriği JSON formatında değil.');
  }

  if (!payloadJson || typeof payloadJson !== 'object') {
    throw new LicenseError('Lisans içeriği beklenen alanları içermiyor.');
  }

  const candidate = payloadJson as Partial<LicensePayload>;
  if (typeof candidate.licenseId !== 'string' || candidate.licenseId.length === 0) {
    throw new LicenseError('Lisans kimliği eksik.');
  }
  if (typeof candidate.issuedTo !== 'string' || candidate.issuedTo.length === 0) {
    throw new LicenseError('Lisans sahibi bilgisi eksik.');
  }
  if (typeof candidate.issuedAt !== 'string' || candidate.issuedAt.length === 0) {
    throw new LicenseError('Lisans verilme tarihi eksik.');
  }

  if (candidate.expiresAt) {
    const expiresAt = new Date(candidate.expiresAt);
    if (Number.isNaN(expiresAt.getTime())) {
      throw new LicenseError('Lisans geçerlilik tarihi okunamadı.');
    }
    if (expiresAt.getTime() < Date.now()) {
      throw new LicenseError('Lisans süresi dolmuş.');
    }
  }

  if (candidate.features) {
    const invalidFeature = candidate.features.some((feature) => typeof feature !== 'string');
    if (invalidFeature) {
      throw new LicenseError('Lisans özellik listesi yalnızca metin değerleri içermelidir.');
    }
  }

  return {
    licenseId: candidate.licenseId,
    issuedTo: candidate.issuedTo,
    issuedAt: candidate.issuedAt,
    expiresAt: candidate.expiresAt,
    features: candidate.features,
  };
};

export const verifyLicenseFile = async (
  inputPath: string,
  options?: VerifyLicenseOptions,
): Promise<LicensePayload> => {
  const filePath = resolveLicensePath(inputPath);
  const raw = await readLicenseFile(filePath);
  const content = parseLicenseContent(raw);
  const { payload } = verifySignature(content, options);
  return parsePayload(payload);
};
