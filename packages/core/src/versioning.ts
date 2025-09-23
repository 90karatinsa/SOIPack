import { createHash } from 'crypto';

export interface SnapshotVersion {
  /**
   * Human friendly identifier similar to a git commit reference
   * built from the creation timestamp and a fingerprint hash.
   */
  id: string;
  /**
   * ISO-8601 timestamp representing when the version was created.
   */
  createdAt: string;
  /**
   * SHA-256 fingerprint that uniquely identifies the version contents.
   */
  fingerprint: string;
  /**
   * Indicates whether the version has been frozen via the freeze workflow.
   */
  isFrozen: boolean;
  /**
   * Optional timestamp representing when the snapshot was frozen.
   */
  frozenAt?: string;
}

const SNAPSHOT_ID_PATTERN = /^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{7,}$/i;

const toIsoTimestamp = (value?: string | Date): string => {
  if (!value) {
    return new Date().toISOString();
  }
  if (value instanceof Date) {
    return value.toISOString();
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    throw new Error(`Invalid timestamp provided: ${value}`);
  }
  return parsed.toISOString();
};

const compactTimestamp = (timestamp: string): string =>
  timestamp.replace(/[-:]/g, '').replace(/\.[0-9]{3}Z$/, 'Z');

const normalizeFingerprint = (fingerprint: string): string => {
  if (!fingerprint || typeof fingerprint !== 'string') {
    throw new Error('Fingerprint must be a non-empty string.');
  }
  const normalized = fingerprint.trim().toLowerCase();
  if (!/^[a-f0-9]{6,}$/i.test(normalized)) {
    throw new Error('Fingerprint must be a hexadecimal digest.');
  }
  return normalized;
};

export const createSnapshotIdentifier = (timestamp: string, fingerprint: string): string => {
  const compact = compactTimestamp(timestamp);
  const normalizedFingerprint = normalizeFingerprint(fingerprint);
  const shortHash = normalizedFingerprint.slice(0, 12);
  const identifier = `${compact}-${shortHash}`;
  if (!SNAPSHOT_ID_PATTERN.test(identifier)) {
    throw new Error(`Computed snapshot identifier is invalid: ${identifier}`);
  }
  return identifier;
};

export const createSnapshotVersion = (
  fingerprint: string,
  options: { createdAt?: string | Date } = {},
): SnapshotVersion => {
  const normalizedFingerprint = normalizeFingerprint(fingerprint);
  const createdAt = toIsoTimestamp(options.createdAt);
  const id = createSnapshotIdentifier(createdAt, normalizedFingerprint);
  return {
    id,
    createdAt,
    fingerprint: normalizedFingerprint,
    isFrozen: false,
  };
};

export const freezeSnapshotVersion = (
  version: SnapshotVersion,
  options: { frozenAt?: string | Date } = {},
): SnapshotVersion => {
  if (version.isFrozen) {
    return version;
  }
  const frozenAt = toIsoTimestamp(options.frozenAt);
  return {
    ...version,
    isFrozen: true,
    frozenAt,
    id: createSnapshotIdentifier(frozenAt, version.fingerprint),
  };
};

export const deriveFingerprint = (values: Iterable<string>): string => {
  const hash = createHash('sha256');
  Array.from(values)
    .sort((a, b) => a.localeCompare(b))
    .forEach((value) => {
      hash.update(value);
      hash.update('\u0000');
    });
  return hash.digest('hex');
};

export const SNAPSHOT_ID_REGEX = SNAPSHOT_ID_PATTERN;
