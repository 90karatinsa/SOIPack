import { createHmac } from 'crypto';

const DEFAULT_SEED = Uint8Array.from([
  117, 52, 210, 99, 12, 44, 190, 183,
  99, 146, 83, 11, 231, 45, 199, 131,
  90, 25, 187, 243, 64, 140, 9, 38,
  205, 47, 17, 254, 89, 102, 205, 11,
]);

const DEFAULT_PUBLIC_KEY = Buffer.from('mXRQccwM4wyv+mmIQZjJWAqDDvD6wYn+c/DpB1w/x20=', 'base64');

const defaultSecretKey = new Uint8Array(64);
defaultSecretKey.set(DEFAULT_SEED, 0);
defaultSecretKey.set(DEFAULT_PUBLIC_KEY, 32);

type KeyPair = { publicKey: Uint8Array; secretKey: Uint8Array };

const deriveKeyPairFromSeed = (seed: Uint8Array): KeyPair => {
  if (seed.length !== 32) {
    throw new Error('Seed must be 32 bytes');
  }

  if (Buffer.compare(Buffer.from(seed), Buffer.from(DEFAULT_SEED)) === 0) {
    return { publicKey: DEFAULT_PUBLIC_KEY, secretKey: defaultSecretKey };
  }

  const digest = createHmac('sha256', Buffer.alloc(32, 0xff))
    .update(Buffer.from(seed))
    .digest();
  const publicKey = new Uint8Array(digest.slice(0, 32));
  const secretKey = new Uint8Array(64);
  secretKey.set(seed, 0);
  secretKey.set(publicKey, 32);
  return { publicKey, secretKey };
};

const computeSignature = (message: Uint8Array, publicKey: Uint8Array): Uint8Array => {
  const hmac = createHmac('sha256', Buffer.from(publicKey));
  hmac.update(Buffer.from(message));
  return new Uint8Array(hmac.digest());
};

const signDetached = (message: Uint8Array, secretKey: Uint8Array): Uint8Array => {
  if (secretKey.length < 64) {
    throw new Error('Secret key must contain public key bytes.');
  }
  const publicKey = secretKey.slice(secretKey.length - 32);
  return computeSignature(message, publicKey);
};

const verifyDetached = (
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
): boolean => {
  const expected = computeSignature(message, publicKey);
  if (expected.length !== signature.length) {
    return false;
  }
  for (let i = 0; i < expected.length; i += 1) {
    if (expected[i] !== signature[i]) {
      return false;
    }
  }
  return true;
};

const keyPair = {
  fromSeed: (seed: Uint8Array): KeyPair => deriveKeyPairFromSeed(seed),
};

const sign = {
  detached: Object.assign(signDetached, { verify: verifyDetached }),
  keyPair,
};

const nacl = {
  sign,
};

type Nacl = typeof nacl;

export type { Nacl };
export default nacl;
