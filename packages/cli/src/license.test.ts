import os from 'os';
import path from 'path';
import { promises as fs } from 'fs';

import nacl from 'tweetnacl';

import { LicenseError, verifyLicenseFile } from './license';

const TEST_SEED = Uint8Array.from([
  117, 52, 210, 99, 12, 44, 190, 183,
  99, 146, 83, 11, 231, 45, 199, 131,
  90, 25, 187, 243, 64, 140, 9, 38,
  205, 47, 17, 254, 89, 102, 205, 11,
]);

const KEY_PAIR = nacl.sign.keyPair.fromSeed(TEST_SEED);

interface LicenseFileContent {
  payload: string;
  signature: string;
}

const serializeLicensePayload = (payload: Record<string, unknown>): LicenseFileContent => {
  const payloadBuffer = Buffer.from(JSON.stringify(payload));
  const signature = nacl.sign.detached(payloadBuffer, KEY_PAIR.secretKey);
  return {
    payload: payloadBuffer.toString('base64'),
    signature: Buffer.from(signature).toString('base64'),
  };
};

const writeLicenseFile = async (filePath: string, payload: Record<string, unknown>): Promise<void> => {
  const content = serializeLicensePayload(payload);
  await fs.writeFile(filePath, JSON.stringify(content), 'utf8');
};

describe('license verification', () => {
  let tempDir: string;
  let licensePath: string;

  beforeAll(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'soipack-license-'));
  });

  afterAll(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  beforeEach(() => {
    licensePath = path.join(tempDir, 'license.key');
  });

  it('accepts a valid signed license', async () => {
    const payload = {
      licenseId: 'demo-license',
      issuedTo: 'Test Customer',
      issuedAt: '2024-01-01T00:00:00.000Z',
      expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
      features: ['import', 'analyze'],
    };

    await writeLicenseFile(licensePath, payload);

    const result = await verifyLicenseFile(licensePath);
    expect(result).toMatchObject({
      licenseId: payload.licenseId,
      issuedTo: payload.issuedTo,
      features: payload.features,
    });
  });

  it('rejects licenses with tampered signatures', async () => {
    const payload = {
      licenseId: 'demo-license',
      issuedTo: 'Test Customer',
      issuedAt: '2024-01-01T00:00:00.000Z',
      expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
    };

    const content = serializeLicensePayload(payload);
    const signatureBytes = Buffer.from(content.signature, 'base64');
    signatureBytes[0] ^= 0xff;
    const tampered = {
      payload: content.payload,
      signature: signatureBytes.toString('base64'),
    };

    await fs.writeFile(licensePath, JSON.stringify(tampered), 'utf8');

    await expect(verifyLicenseFile(licensePath)).rejects.toThrow(LicenseError);
  });

  it('rejects expired licenses', async () => {
    const payload = {
      licenseId: 'demo-license',
      issuedTo: 'Test Customer',
      issuedAt: '2024-01-01T00:00:00.000Z',
      expiresAt: new Date(Date.now() - 86_400_000).toISOString(),
    };

    await writeLicenseFile(licensePath, payload);

    await expect(verifyLicenseFile(licensePath)).rejects.toThrow('Lisans süresi dolmuş.');
  });
});
