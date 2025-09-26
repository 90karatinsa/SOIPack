import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { Manifest } from '@soipack/core';

import {
  DEFAULT_POST_QUANTUM_ALGORITHM,
  deriveSphincsPlusPublicKey,
  generateSphincsPlusKeyPair,
  loadDefaultSphincsPlusKeyPair,
  signWithSphincsPlus,
  verifyWithSphincsPlus,
} from './pqc';
import { signManifestWithSecuritySigner } from './signer';

const DEV_CERT_BUNDLE_PATH = path.resolve(__dirname, '../../../../test/certs/dev.pem');
const loadDevBundle = (): string => readFileSync(DEV_CERT_BUNDLE_PATH, 'utf8');

const decodeBase64Url = (value: string): Buffer => {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padding = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
  return Buffer.from(normalized + padding, 'base64');
};

const parseJwsHeader = (signature: string): Record<string, unknown> => {
  const [header] = signature.split('.');
  return JSON.parse(decodeBase64Url(header).toString('utf8')) as Record<string, unknown>;
};

describe('SPHINCS+ primitives', () => {
  it('derives public keys and produces deterministic vectors for the default seed', () => {
    const defaults = loadDefaultSphincsPlusKeyPair();
    const message = Buffer.from('SOIPack PQC deterministic test', 'utf8');

    expect(deriveSphincsPlusPublicKey(defaults.privateKey)).toBe(defaults.publicKey);

    const signature = signWithSphincsPlus(message, defaults.privateKey);
    expect(createHash('sha256').update(signature).digest('hex')).toBe(
      '1659b7546b60e3746415da5c82f4b0cc2cf0c41917964d3d605fadc686b40dff',
    );
    expect(verifyWithSphincsPlus(message, signature, defaults.publicKey)).toBe(true);
    expect(verifyWithSphincsPlus(Buffer.from('tampered'), signature, defaults.publicKey)).toBe(false);
  });

  it('generates working key pairs across supported algorithms', () => {
    const algorithms = [DEFAULT_POST_QUANTUM_ALGORITHM];

    for (const algorithm of algorithms) {
      const pair = generateSphincsPlusKeyPair(algorithm);
      expect(pair.algorithm).toBe(algorithm);
      expect(pair.privateKey).toEqual(expect.any(String));
      expect(pair.publicKey).toEqual(expect.any(String));
      expect(deriveSphincsPlusPublicKey(pair.privateKey, algorithm)).toBe(pair.publicKey);

      const message = Buffer.from(`algorithm-${algorithm}`, 'utf8');
      const signature = signWithSphincsPlus(message, pair.privateKey, algorithm);
      expect(verifyWithSphincsPlus(message, signature, pair.publicKey, algorithm)).toBe(true);
      expect(verifyWithSphincsPlus(message, Buffer.from(signature).reverse(), pair.publicKey, algorithm)).toBe(
        false,
      );
    }
  });
});

describe('signManifestWithSecuritySigner integration', () => {
  const baseManifest: Manifest = {
    createdAt: '2024-02-01T10:00:00Z',
    toolVersion: '0.2.0',
    files: [
      { path: 'reports/summary.html', sha256: createHash('sha256').update('summary').digest('hex') },
      { path: 'evidence/logs.csv', sha256: createHash('sha256').update('logs').digest('hex') },
    ],
  };

  it('embeds provided SPHINCS+ material and produces verifiable post-quantum signatures', () => {
    const bundlePem = loadDevBundle();
    const postQuantumMaterial = loadDefaultSphincsPlusKeyPair();
    const bundle = signManifestWithSecuritySigner(baseManifest, {
      bundlePem,
      postQuantum: {
        algorithm: postQuantumMaterial.algorithm,
        privateKey: postQuantumMaterial.privateKey,
        publicKey: postQuantumMaterial.publicKey,
      },
    });

    expect(bundle.postQuantumSignature).toEqual(
      expect.objectContaining({
        algorithm: postQuantumMaterial.algorithm,
        publicKey: postQuantumMaterial.publicKey,
        signature: expect.any(String),
      }),
    );

    const segments = bundle.signature.split('.');
    expect(segments).toHaveLength(4);

    const signingInput = `${segments[0]}.${segments[1]}`;
    const pqSignature = decodeBase64Url(segments[3]);

    expect(
      verifyWithSphincsPlus(
        Buffer.from(signingInput, 'utf8'),
        pqSignature,
        postQuantumMaterial.publicKey,
        postQuantumMaterial.algorithm,
      ),
    ).toBe(true);

    const header = parseJwsHeader(bundle.signature);
    expect(header.pq).toEqual({
      alg: postQuantumMaterial.algorithm,
      pub: postQuantumMaterial.publicKey,
    });
  });
});
