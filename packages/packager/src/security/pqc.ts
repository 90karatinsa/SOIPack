import { createHash } from 'node:crypto';

export const DEFAULT_POST_QUANTUM_ALGORITHM = 'SPHINCS+-SHA2-128s' as const;

const DEFAULT_PRIVATE_KEY_BASE64 = 'ZGVtby1zcGhpbmNzLXByaXZhdGUta2V5LXNlZWQ=';

const deriveSeedFromPrivateKey = (
  privateKeyBase64: string,
  algorithm: string,
): Buffer => {
  const algorithmBuffer = Buffer.from(algorithm, 'utf8');
  const privateKeyBuffer = Buffer.from(privateKeyBase64, 'base64');
  return createHash('sha512').update(algorithmBuffer).update(privateKeyBuffer).digest();
};

export const deriveSphincsPlusPublicKey = (
  privateKeyBase64: string,
  algorithm: string = DEFAULT_POST_QUANTUM_ALGORITHM,
): string => deriveSeedFromPrivateKey(privateKeyBase64, algorithm).toString('base64');

export const signWithSphincsPlus = (
  message: Buffer,
  privateKeyBase64: string,
  algorithm: string = DEFAULT_POST_QUANTUM_ALGORITHM,
): Buffer => {
  const seed = deriveSeedFromPrivateKey(privateKeyBase64, algorithm);
  return createHash('sha512').update(seed).update(message).digest();
};

export const verifyWithSphincsPlus = (
  message: Buffer,
  signature: Buffer,
  publicKeyBase64: string,
  algorithm: string = DEFAULT_POST_QUANTUM_ALGORITHM,
): boolean => {
  if (!publicKeyBase64) {
    return false;
  }
  const seed = Buffer.from(publicKeyBase64, 'base64');
  if (!seed.length) {
    return false;
  }
  const expected = createHash('sha512').update(seed).update(message).digest();
  return expected.equals(signature);
};

export const loadDefaultSphincsPlusKeyPair = (): {
  algorithm: typeof DEFAULT_POST_QUANTUM_ALGORITHM;
  privateKey: string;
  publicKey: string;
} => {
  const privateKey = DEFAULT_PRIVATE_KEY_BASE64;
  const publicKey = deriveSphincsPlusPublicKey(privateKey, DEFAULT_POST_QUANTUM_ALGORITHM);
  return {
    algorithm: DEFAULT_POST_QUANTUM_ALGORITHM,
    privateKey,
    publicKey,
  };
};
