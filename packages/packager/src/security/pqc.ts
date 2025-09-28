import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export const DEFAULT_POST_QUANTUM_ALGORITHM = 'SPHINCS+-SHA2-128s' as const;

const SUPPORTED_ALGORITHMS = [
  'SPHINCS+-SHA2-128s',
  'SPHINCS+-SHA2-128f',
  'SPHINCS+-SHA2-192s',
  'SPHINCS+-SHA2-192f',
  'SPHINCS+-SHA2-256s',
  'SPHINCS+-SHA2-256f',
  'SPHINCS+-SHAKE-128s',
  'SPHINCS+-SHAKE-128f',
  'SPHINCS+-SHAKE-192s',
  'SPHINCS+-SHAKE-192f',
  'SPHINCS+-SHAKE-256s',
  'SPHINCS+-SHAKE-256f',
] as const;

export type SphincsPlusAlgorithm = (typeof SUPPORTED_ALGORITHMS)[number];

type WorkerRequest =
  | { op: 'keygen'; algorithm: SphincsPlusAlgorithm; seed?: string }
  | { op: 'derive'; algorithm: SphincsPlusAlgorithm; privateKey: string }
  | { op: 'sign'; algorithm: SphincsPlusAlgorithm; privateKey: string; message: string }
  | { op: 'verify'; algorithm: SphincsPlusAlgorithm; publicKey: string; message: string; signature: string };

type WorkerResponse =
  | { ok: true; privateKey: string; publicKey: string }
  | { ok: true; publicKey: string }
  | { ok: true; signature: string }
  | { ok: true; verified: boolean }
  | { ok: false; error: string };

type SphincsModule = typeof import('@noble/post-quantum/slh-dsa.js');
type SphincsSignerName =
  | 'slh_dsa_sha2_128s'
  | 'slh_dsa_sha2_128f'
  | 'slh_dsa_sha2_192s'
  | 'slh_dsa_sha2_192f'
  | 'slh_dsa_sha2_256s'
  | 'slh_dsa_sha2_256f'
  | 'slh_dsa_shake_128s'
  | 'slh_dsa_shake_128f'
  | 'slh_dsa_shake_192s'
  | 'slh_dsa_shake_192f'
  | 'slh_dsa_shake_256s'
  | 'slh_dsa_shake_256f';

type SphincsSigner = SphincsModule[SphincsSignerName];

const signerKeyByAlgorithm: Record<SphincsPlusAlgorithm, SphincsSignerName> = {
  'SPHINCS+-SHA2-128s': 'slh_dsa_sha2_128s',
  'SPHINCS+-SHA2-128f': 'slh_dsa_sha2_128f',
  'SPHINCS+-SHA2-192s': 'slh_dsa_sha2_192s',
  'SPHINCS+-SHA2-192f': 'slh_dsa_sha2_192f',
  'SPHINCS+-SHA2-256s': 'slh_dsa_sha2_256s',
  'SPHINCS+-SHA2-256f': 'slh_dsa_sha2_256f',
  'SPHINCS+-SHAKE-128s': 'slh_dsa_shake_128s',
  'SPHINCS+-SHAKE-128f': 'slh_dsa_shake_128f',
  'SPHINCS+-SHAKE-192s': 'slh_dsa_shake_192s',
  'SPHINCS+-SHAKE-192f': 'slh_dsa_shake_192f',
  'SPHINCS+-SHAKE-256s': 'slh_dsa_shake_256s',
  'SPHINCS+-SHAKE-256f': 'slh_dsa_shake_256f',
};

const requirePostQuantum = createRequire(__filename);
let cachedModule: SphincsModule | undefined;
let useWorkerFallback = false;
let workerScriptPath: string | undefined;
const LOCAL_NODE_MODULES = path.resolve(__dirname, '../../node_modules');
const ROOT_NODE_MODULES = path.resolve(__dirname, '../../../../node_modules');

const SPHINCS_MODULE_URL = pathToFileURL(path.resolve(ROOT_NODE_MODULES, '@noble/post-quantum/slh-dsa.js')).href;

const WORKER_SCRIPT = `const moduleUrl = '${SPHINCS_MODULE_URL}';
const {
  slh_dsa_sha2_128f,
  slh_dsa_sha2_128s,
  slh_dsa_sha2_192f,
  slh_dsa_sha2_192s,
  slh_dsa_sha2_256f,
  slh_dsa_sha2_256s,
  slh_dsa_shake_128f,
  slh_dsa_shake_128s,
  slh_dsa_shake_192f,
  slh_dsa_shake_192s,
  slh_dsa_shake_256f,
  slh_dsa_shake_256s,
} = await import(moduleUrl);

const algorithms = {
  'SPHINCS+-SHA2-128s': slh_dsa_sha2_128s,
  'SPHINCS+-SHA2-128f': slh_dsa_sha2_128f,
  'SPHINCS+-SHA2-192s': slh_dsa_sha2_192s,
  'SPHINCS+-SHA2-192f': slh_dsa_sha2_192f,
  'SPHINCS+-SHA2-256s': slh_dsa_sha2_256s,
  'SPHINCS+-SHA2-256f': slh_dsa_sha2_256f,
  'SPHINCS+-SHAKE-128s': slh_dsa_shake_128s,
  'SPHINCS+-SHAKE-128f': slh_dsa_shake_128f,
  'SPHINCS+-SHAKE-192s': slh_dsa_shake_192s,
  'SPHINCS+-SHAKE-192f': slh_dsa_shake_192f,
  'SPHINCS+-SHAKE-256s': slh_dsa_shake_256s,
  'SPHINCS+-SHAKE-256f': slh_dsa_shake_256f,
};

const readInput = async () => {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(typeof chunk === 'string' ? chunk : chunk.toString('utf8'));
  }
  return chunks.join('');
};

const writeResponse = (payload) => {
  process.stdout.write(JSON.stringify(payload));
};

const main = async () => {
  try {
    const raw = await readInput();
    const request = raw ? JSON.parse(raw) : {};
    const signer = algorithms[request.algorithm];
    if (!signer) {
      writeResponse({ ok: false, error: 'Unsupported algorithm' });
      return;
    }
    switch (request.op) {
      case 'keygen': {
        const seed = request.seed ? Buffer.from(request.seed, 'base64') : undefined;
        const { secretKey, publicKey } = signer.keygen(seed);
        writeResponse({
          ok: true,
          privateKey: Buffer.from(secretKey).toString('base64'),
          publicKey: Buffer.from(publicKey).toString('base64'),
        });
        return;
      }
      case 'derive': {
        const secretKey = Buffer.from(request.privateKey, 'base64');
        writeResponse({ ok: true, publicKey: Buffer.from(signer.getPublicKey(secretKey)).toString('base64') });
        return;
      }
      case 'sign': {
        const secretKey = Buffer.from(request.privateKey, 'base64');
        const message = Buffer.from(request.message, 'base64');
        const signature = signer.sign(message, secretKey, { extraEntropy: false });
        writeResponse({ ok: true, signature: Buffer.from(signature).toString('base64') });
        return;
      }
      case 'verify': {
        const signature = Buffer.from(request.signature, 'base64');
        const message = Buffer.from(request.message, 'base64');
        const publicKey = Buffer.from(request.publicKey, 'base64');
        writeResponse({ ok: true, verified: signer.verify(signature, message, publicKey) });
        return;
      }
      default:
        writeResponse({ ok: false, error: 'Unsupported operation' });
    }
  } catch (error) {
    writeResponse({ ok: false, error: error instanceof Error ? error.message : String(error) });
  }
};

await main();
`;

const ensureWorkerScriptPath = (): string => {
  if (!workerScriptPath) {
    const dir = mkdtempSync(path.join(tmpdir(), 'sphincs-worker-'));
    workerScriptPath = path.join(dir, 'worker.mjs');
  }
  writeFileSync(workerScriptPath, WORKER_SCRIPT, 'utf8');
  return workerScriptPath;
};

const invokeWorker = (request: WorkerRequest): WorkerResponse => {
  const script = ensureWorkerScriptPath();
  const nodePathSegments = [LOCAL_NODE_MODULES, ROOT_NODE_MODULES, process.env.NODE_PATH]
    .filter((segment): segment is string => Boolean(segment))
    .join(path.delimiter);
  const result = spawnSync(process.execPath, [script], {
    input: JSON.stringify(request),
    encoding: 'utf8',
    env: { ...process.env, NODE_PATH: nodePathSegments },
  });
  if (result.stderr) {
    throw new Error(result.stderr.trim());
  }
  if (result.error) {
    throw result.error;
  }
  if (typeof result.stdout !== 'string' || result.stdout.length === 0) {
    throw new Error(result.stderr || 'SPHINCS+ worker did not return a result.');
  }
  const response = JSON.parse(result.stdout) as WorkerResponse;
  if (!response.ok) {
    throw new Error(`SPHINCS+ worker error: ${response.error}`);
  }
  return response;
};

const loadSigner = (algorithm: SphincsPlusAlgorithm): SphincsSigner | undefined => {
  if (useWorkerFallback) {
    return undefined;
  }
  if (!cachedModule) {
    try {
      cachedModule = requirePostQuantum('@noble/post-quantum/slh-dsa.js') as SphincsModule;
    } catch (error) {
      useWorkerFallback = true;
      cachedModule = undefined;
      return undefined;
    }
  }
  const key = signerKeyByAlgorithm[algorithm];
  return cachedModule[key];
};

const ensureAlgorithm = (algorithm?: string): SphincsPlusAlgorithm => {
  const requested = algorithm ?? DEFAULT_POST_QUANTUM_ALGORITHM;
  const normalized = requested.toUpperCase();
  const canonical = SUPPORTED_ALGORITHMS.find((entry) => entry.toUpperCase() === normalized);
  if (!canonical) {
    throw new Error(`Desteklenmeyen SPHINCS+ algoritması: ${requested}`);
  }
  return canonical;
};

const BASE64_PATTERN = /^[0-9A-Za-z+/]+={0,2}$/;

const sanitizeBase64 = (value: string): string => value.replace(/\s+/g, '').trim();

const decodeOptionalKey = (value?: string): Uint8Array | undefined => {
  if (!value) {
    return undefined;
  }
  const normalized = sanitizeBase64(value);
  if (!normalized || !BASE64_PATTERN.test(normalized)) {
    return undefined;
  }
  const decoded = Buffer.from(normalized, 'base64');
  return decoded.length > 0 ? new Uint8Array(decoded) : undefined;
};

const decodeRequiredKey = (value: string, label: string): Uint8Array => {
  const decoded = decodeOptionalKey(value);
  if (!decoded) {
    throw new Error(`${label} geçerli bir base64 değeri içermelidir.`);
  }
  return decoded;
};

const performWithWorker = <T>(request: WorkerRequest, transform: (response: WorkerResponse) => T): T => {
  const response = invokeWorker(request);
  return transform(response);
};

export interface SphincsPlusKeyPair {
  algorithm: SphincsPlusAlgorithm;
  privateKey: string;
  publicKey: string;
}

export const generateSphincsPlusKeyPair = (
  algorithm: string = DEFAULT_POST_QUANTUM_ALGORITHM,
  seed?: Uint8Array,
): SphincsPlusKeyPair => {
  const canonical = ensureAlgorithm(algorithm);
  const signer = loadSigner(canonical);
  if (signer) {
    const effectiveSeed = seed ?? (signer.lengths.seed ? new Uint8Array(randomBytes(signer.lengths.seed)) : undefined);
    const { secretKey, publicKey } = signer.keygen(effectiveSeed);
    return {
      algorithm: canonical,
      privateKey: Buffer.from(secretKey).toString('base64'),
      publicKey: Buffer.from(publicKey).toString('base64'),
    };
  }
  const seedBase64 = seed && seed.length > 0 ? Buffer.from(seed).toString('base64') : undefined;
  return performWithWorker({ op: 'keygen', algorithm: canonical, seed: seedBase64 }, (response) => ({
    algorithm: canonical,
    privateKey: (response as { privateKey: string }).privateKey,
    publicKey: (response as { publicKey: string }).publicKey,
  }));
};

export const deriveSphincsPlusPublicKey = (
  privateKeyBase64: string,
  algorithm: string = DEFAULT_POST_QUANTUM_ALGORITHM,
): string => {
  const canonical = ensureAlgorithm(algorithm);
  const signer = loadSigner(canonical);
  if (signer) {
    const privateKey = decodeRequiredKey(privateKeyBase64, `${canonical} özel anahtarı`);
    return Buffer.from(signer.getPublicKey(privateKey)).toString('base64');
  }
  return performWithWorker(
    { op: 'derive', algorithm: canonical, privateKey: sanitizeBase64(privateKeyBase64) },
    (response) => (response as { publicKey: string }).publicKey,
  );
};

export const signWithSphincsPlus = (
  message: Buffer,
  privateKeyBase64: string,
  algorithm: string = DEFAULT_POST_QUANTUM_ALGORITHM,
): Buffer => {
  const canonical = ensureAlgorithm(algorithm);
  const signer = loadSigner(canonical);
  const sanitizedKey = sanitizeBase64(privateKeyBase64);
  if (signer) {
    const privateKey = decodeRequiredKey(sanitizedKey, `${canonical} özel anahtarı`);
    const signature = signer.sign(new Uint8Array(message), privateKey, { extraEntropy: false });
    return Buffer.from(signature);
  }
  return Buffer.from(
    performWithWorker(
      {
        op: 'sign',
        algorithm: canonical,
        privateKey: sanitizedKey,
        message: Buffer.from(message).toString('base64'),
      },
      (response) => (response as { signature: string }).signature,
    ),
    'base64',
  );
};

export const verifyWithSphincsPlus = (
  message: Buffer,
  signature: Buffer,
  publicKeyBase64: string,
  algorithm: string = DEFAULT_POST_QUANTUM_ALGORITHM,
): boolean => {
  const canonical = ensureAlgorithm(algorithm);
  const signer = loadSigner(canonical);
  const publicKey = decodeOptionalKey(publicKeyBase64);
  if (!publicKey) {
    return false;
  }
  if (signer) {
    try {
      return signer.verify(new Uint8Array(signature), new Uint8Array(message), publicKey);
    } catch {
      return false;
    }
  }
  try {
    return performWithWorker(
      {
        op: 'verify',
        algorithm: canonical,
        publicKey: sanitizeBase64(publicKeyBase64),
        message: Buffer.from(message).toString('base64'),
        signature: Buffer.from(signature).toString('base64'),
      },
      (response) => Boolean((response as { verified: boolean }).verified),
    );
  } catch {
    return false;
  }
};

const DEFAULT_PRIVATE_KEY_BASE64 =
  'EVZI4ibtgvESRWYQ/sVXdpjHer0qXeX1uSRzzHHexahiMmHYky3/PWGQHSyZfDwhIFj6jDiWVQ1GokCjzubRMA==';
const DEFAULT_PUBLIC_KEY_BASE64 = 'YjJh2JMt/z1hkB0smXw8ISBY+ow4llUNRqJAo87m0TA=';

export const loadDefaultSphincsPlusKeyPair = (): {
  algorithm: typeof DEFAULT_POST_QUANTUM_ALGORITHM;
  privateKey: string;
  publicKey: string;
} => ({
  algorithm: DEFAULT_POST_QUANTUM_ALGORITHM,
  privateKey: DEFAULT_PRIVATE_KEY_BASE64,
  publicKey: DEFAULT_PUBLIC_KEY_BASE64,
});
