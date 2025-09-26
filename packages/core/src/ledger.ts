import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';

const hashParts = (parts: string[]): string => {
  const hash = createHash('sha256');
  for (const part of parts) {
    hash.update(part, 'utf8');
    hash.update('\u0000', 'utf8');
  }
  return hash.digest('hex');
};

const GENESIS_SEED = 'SOIPack::Ledger::GENESIS';

export const GENESIS_ROOT = hashParts([GENESIS_SEED]);

export interface LedgerEvidenceLink {
  snapshotId: string;
  hash: string;
  path?: string;
}

export interface LedgerEntryInput {
  snapshotId: string;
  manifestDigest: string;
  timestamp: string;
  evidence?: LedgerEvidenceLink[];
}

export interface LedgerSignature {
  algorithm: 'Ed25519';
  publicKey: string;
  signature: string;
  keyId?: string;
}

export interface LedgerEntry extends LedgerEntryInput {
  index: number;
  evidence: LedgerEvidenceLink[];
  merkleRoot: string;
  previousRoot: string;
  ledgerRoot: string;
  signature?: LedgerSignature;
}

export interface Ledger {
  entries: LedgerEntry[];
  root: string;
}

export interface LedgerSignerOptions {
  privateKeyPem: string;
  publicKeyPem?: string;
  keyId?: string;
}

export interface AppendEntryOptions {
  signer?: LedgerSignerOptions;
  expectedPreviousRoot?: string;
}

export class LedgerVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LedgerVerificationError';
  }
}

export class LedgerBranchError extends LedgerVerificationError {
  constructor(message: string) {
    super(message);
    this.name = 'LedgerBranchError';
  }
}

export class LedgerSignatureError extends LedgerVerificationError {
  constructor(message: string) {
    super(message);
    this.name = 'LedgerSignatureError';
  }
}

export class LedgerProofError extends LedgerVerificationError {
  constructor(message: string) {
    super(message);
    this.name = 'LedgerProofError';
  }
}

const canonicalizeEvidence = (evidence: LedgerEvidenceLink[]): LedgerEvidenceLink[] => {
  return [...evidence]
    .map((item) => ({
      snapshotId: item.snapshotId,
      hash: item.hash,
      path: item.path ?? '',
    }))
    .sort((a, b) => {
      if (a.snapshotId !== b.snapshotId) {
        return a.snapshotId.localeCompare(b.snapshotId);
      }
      if (a.path !== b.path) {
        return a.path.localeCompare(b.path);
      }
      return a.hash.localeCompare(b.hash);
    });
};

type LedgerLeafType = 'snapshot' | 'manifest' | 'timestamp' | 'evidence';

interface LedgerLeafDescriptor {
  type: LedgerLeafType;
  label: string;
  hash: string;
  evidence?: LedgerEvidenceLink;
}

export type LedgerProofTarget =
  | { type: 'snapshot' }
  | { type: 'manifest' }
  | { type: 'timestamp' }
  | { type: 'evidence'; snapshotId: string; path?: string; hash: string };

export interface LedgerMerkleProofNode {
  position: 'left' | 'right';
  hash: string;
}

export interface LedgerMerkleProof {
  leaf: { type: LedgerLeafType; label: string; hash: string };
  path: LedgerMerkleProofNode[];
  merkleRoot: string;
}

const computeLeafDescriptors = (
  entry: LedgerEntryInput & { evidence: LedgerEvidenceLink[] },
): LedgerLeafDescriptor[] => {
  const leaves: LedgerLeafDescriptor[] = [
    { type: 'snapshot', label: `snapshot:${entry.snapshotId}`, hash: hashParts(['snapshot', entry.snapshotId]) },
    { type: 'manifest', label: `manifest:${entry.manifestDigest}`, hash: hashParts(['manifest', entry.manifestDigest]) },
    { type: 'timestamp', label: `timestamp:${entry.timestamp}`, hash: hashParts(['timestamp', entry.timestamp]) },
  ];

  entry.evidence.forEach((link) => {
    leaves.push({
      type: 'evidence',
      label: `evidence:${link.snapshotId}:${link.path ?? ''}`,
      hash: hashParts(['evidence', link.snapshotId, link.path ?? '', link.hash]),
      evidence: link,
    });
  });

  return leaves;
};

const computeLeafHashes = (entry: LedgerEntryInput & { evidence: LedgerEvidenceLink[] }): string[] =>
  computeLeafDescriptors(entry).map((leaf) => leaf.hash);

const computeMerkleRoot = (leaves: string[]): string => {
  if (leaves.length === 0) {
    return hashParts(['soipack-ledger-empty']);
  }

  let level = [...leaves];
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = level[i + 1] ?? left;
      next.push(hashParts([left, right]));
    }
    level = next;
  }

  return level[0];
};

const buildMerklePath = (leaves: string[], leafIndex: number): LedgerMerkleProofNode[] => {
  if (leafIndex < 0 || leafIndex >= leaves.length) {
    throw new LedgerProofError('Merkle proof leaf index is out of range.');
  }

  const path: LedgerMerkleProofNode[] = [];
  let index = leafIndex;
  let level = [...leaves];

  while (level.length > 1) {
    const isRightNode = index % 2 === 1;
    const pairIndex = isRightNode ? index - 1 : index + 1;
    const siblingHash = pairIndex < level.length ? level[pairIndex] : level[index];
    path.push({ position: isRightNode ? 'left' : 'right', hash: siblingHash });

    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = level[i + 1] ?? left;
      next.push(hashParts([left, right]));
    }
    index = Math.floor(index / 2);
    level = next;
  }

  return path;
};

const findLeafIndex = (descriptors: LedgerLeafDescriptor[], target: LedgerProofTarget): number => {
  switch (target.type) {
    case 'snapshot':
      return descriptors.findIndex((leaf) => leaf.type === 'snapshot');
    case 'manifest':
      return descriptors.findIndex((leaf) => leaf.type === 'manifest');
    case 'timestamp':
      return descriptors.findIndex((leaf) => leaf.type === 'timestamp');
    case 'evidence':
      return descriptors.findIndex(
        (leaf) =>
          leaf.type === 'evidence' &&
          leaf.evidence?.snapshotId === target.snapshotId &&
          leaf.evidence?.hash === target.hash &&
          (leaf.evidence?.path ?? '') === (target.path ?? ''),
      );
    default:
      return -1;
  }
};

export const createLedger = (): Ledger => ({ entries: [], root: GENESIS_ROOT });

const validateTimestamp = (timestamp: string): void => {
  const value = Date.parse(timestamp);
  if (Number.isNaN(value)) {
    throw new Error('Ledger entry timestamp must be an ISO-8601 string.');
  }
};

const validateDigest = (digest: string): void => {
  if (!/^[a-f0-9]{64}$/i.test(digest)) {
    throw new Error('Ledger entry manifestDigest must be a 64-character hexadecimal SHA-256 digest.');
  }
};

const ensurePreviousRoot = (ledger: Ledger, expected?: string): void => {
  if (expected && expected !== ledger.root) {
    throw new LedgerBranchError('Ledger append attempted on a stale root.');
  }
};

export const appendEntry = (
  ledger: Ledger,
  input: LedgerEntryInput,
  options: AppendEntryOptions = {},
): Ledger => {
  validateTimestamp(input.timestamp);
  validateDigest(input.manifestDigest);
  ensurePreviousRoot(ledger, options.expectedPreviousRoot);

  const evidence = canonicalizeEvidence(input.evidence ?? []);
  const leaves = computeLeafHashes({ ...input, evidence });
  const merkleRoot = computeMerkleRoot(leaves);
  const previousRoot = ledger.root;
  const ledgerRoot = hashParts([previousRoot, merkleRoot]);

  const entry: LedgerEntry = {
    index: ledger.entries.length,
    snapshotId: input.snapshotId,
    manifestDigest: input.manifestDigest,
    timestamp: input.timestamp,
    evidence,
    merkleRoot,
    previousRoot,
    ledgerRoot,
  };

  if (options.signer) {
    const privateKey = createPrivateKey(options.signer.privateKeyPem);
    const publicKey = options.signer.publicKeyPem
      ? options.signer.publicKeyPem
      : createPublicKey(privateKey).export({ format: 'pem', type: 'spki' }).toString();
    const signatureBuffer = sign(null, Buffer.from(entry.ledgerRoot, 'hex'), privateKey);

    entry.signature = {
      algorithm: 'Ed25519',
      publicKey,
      signature: signatureBuffer.toString('base64'),
      keyId: options.signer.keyId,
    };
  }

  return {
    entries: [...ledger.entries, entry],
    root: ledgerRoot,
  };
};

export interface LedgerVerificationResult {
  root: string;
  entries: LedgerEntry[];
}

export const verifyLedger = (ledger: Ledger): LedgerVerificationResult => {
  let expectedRoot = GENESIS_ROOT;

  ledger.entries.forEach((entry, index) => {
    if (entry.index !== index) {
      throw new LedgerBranchError(`Ledger entry ${entry.index} is out of order.`);
    }

    const evidence = canonicalizeEvidence(entry.evidence ?? []);
    const leaves = computeLeafHashes({ ...entry, evidence });
    const merkleRoot = computeMerkleRoot(leaves);

    if (merkleRoot !== entry.merkleRoot) {
      throw new LedgerBranchError(`Ledger entry ${entry.index} merkle root mismatch.`);
    }

    if (entry.previousRoot !== expectedRoot) {
      throw new LedgerBranchError(`Ledger entry ${entry.index} previous root mismatch.`);
    }

    const ledgerRoot = hashParts([expectedRoot, merkleRoot]);

    if (ledgerRoot !== entry.ledgerRoot) {
      throw new LedgerBranchError(`Ledger entry ${entry.index} ledger root mismatch.`);
    }

    if (entry.signature) {
      if (entry.signature.algorithm !== 'Ed25519') {
        throw new LedgerSignatureError(`Ledger entry ${entry.index} uses unsupported signature algorithm.`);
      }

      const signatureValid = verify(
        null,
        Buffer.from(entry.ledgerRoot, 'hex'),
        entry.signature.publicKey,
        Buffer.from(entry.signature.signature, 'base64'),
      );

      if (!signatureValid) {
        throw new LedgerSignatureError(`Ledger entry ${entry.index} signature is invalid.`);
      }
    }

    expectedRoot = ledgerRoot;
  });

  if (ledger.root !== expectedRoot) {
    throw new LedgerBranchError('Ledger root does not match last entry.');
  }

  return {
    root: expectedRoot,
    entries: ledger.entries.map((entry) => ({
      ...entry,
      evidence: canonicalizeEvidence(entry.evidence ?? []),
    })),
  };
};

export const generateLedgerProof = (
  entry: LedgerEntry,
  target: LedgerProofTarget,
): LedgerMerkleProof => {
  const evidence = canonicalizeEvidence(entry.evidence ?? []);
  const descriptors = computeLeafDescriptors({
    snapshotId: entry.snapshotId,
    manifestDigest: entry.manifestDigest,
    timestamp: entry.timestamp,
    evidence,
  });

  const leafIndex = findLeafIndex(descriptors, target);
  if (leafIndex === -1) {
    throw new LedgerProofError('Requested leaf is not present in the ledger entry.');
  }

  const leaf = descriptors[leafIndex];
  const hashes = descriptors.map((descriptor) => descriptor.hash);

  return {
    leaf: { type: leaf.type, label: leaf.label, hash: leaf.hash },
    path: buildMerklePath(hashes, leafIndex),
    merkleRoot: entry.merkleRoot,
  };
};

export const verifyLedgerProof = (
  proof: LedgerMerkleProof,
  options: { expectedMerkleRoot?: string } = {},
): string => {
  if (!proof || typeof proof !== 'object') {
    throw new LedgerProofError('Merkle proof payload is invalid.');
  }

  if (!proof.leaf || typeof proof.leaf.hash !== 'string') {
    throw new LedgerProofError('Merkle proof leaf is missing.');
  }

  if (!Array.isArray(proof.path)) {
    throw new LedgerProofError('Merkle proof path must be an array.');
  }

  let computed = proof.leaf.hash;
  proof.path.forEach((node) => {
    if (!node || (node.position !== 'left' && node.position !== 'right') || typeof node.hash !== 'string') {
      throw new LedgerProofError('Merkle proof path node is invalid.');
    }
    computed =
      node.position === 'left'
        ? hashParts([node.hash, computed])
        : hashParts([computed, node.hash]);
  });

  if (computed !== proof.merkleRoot) {
    throw new LedgerProofError('Merkle proof does not reconstruct the supplied root.');
  }

  if (options.expectedMerkleRoot && proof.merkleRoot !== options.expectedMerkleRoot) {
    throw new LedgerProofError('Merkle root does not match the expected value.');
  }

  return computed;
};

export const serializeLedgerProof = (proof: LedgerMerkleProof): string =>
  JSON.stringify(
    {
      leaf: proof.leaf,
      path: proof.path.map((node) => ({ position: node.position, hash: node.hash })),
      merkleRoot: proof.merkleRoot,
    },
    null,
    2,
  );

export const deserializeLedgerProof = (payload: string): LedgerMerkleProof => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(payload);
  } catch (error) {
    throw new LedgerProofError(`Failed to parse proof JSON: ${(error as Error).message}`);
  }

  if (!parsed || typeof parsed !== 'object') {
    throw new LedgerProofError('Proof payload must be a JSON object.');
  }

  const record = parsed as {
    leaf?: { type?: LedgerLeafType; label?: string; hash?: string };
    path?: Array<{ position?: string; hash?: string }>;
    merkleRoot?: string;
  };

  if (!record.leaf || typeof record.leaf.hash !== 'string' || typeof record.leaf.type !== 'string') {
    throw new LedgerProofError('Proof leaf is missing required fields.');
  }

  if (!Array.isArray(record.path)) {
    throw new LedgerProofError('Proof path must be an array.');
  }

  const path: LedgerMerkleProofNode[] = record.path.map((node) => {
    if (!node || (node.position !== 'left' && node.position !== 'right') || typeof node.hash !== 'string') {
      throw new LedgerProofError('Proof path entry is invalid.');
    }
    return { position: node.position, hash: node.hash };
  });

  if (typeof record.merkleRoot !== 'string' || record.merkleRoot.length === 0) {
    throw new LedgerProofError('Proof merkleRoot is invalid.');
  }

  return {
    leaf: {
      type: record.leaf.type,
      label: record.leaf.label ?? '',
      hash: record.leaf.hash,
    },
    path,
    merkleRoot: record.merkleRoot,
  };
};
