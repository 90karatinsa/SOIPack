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

const computeLeafHashes = (entry: LedgerEntryInput & { evidence: LedgerEvidenceLink[] }): string[] => {
  const leaves: string[] = [
    hashParts(['snapshot', entry.snapshotId]),
    hashParts(['manifest', entry.manifestDigest]),
    hashParts(['timestamp', entry.timestamp]),
  ];

  entry.evidence.forEach((link) => {
    leaves.push(hashParts(['evidence', link.snapshotId, link.path ?? '', link.hash]));
  });

  return leaves;
};

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
