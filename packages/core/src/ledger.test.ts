import { createHash, generateKeyPairSync } from 'node:crypto';

import {
  appendEntry,
  createLedger,
  GENESIS_ROOT,
  LedgerBranchError,
  LedgerSignatureError,
  LedgerSignerOptions,
  verifyLedger,
} from './ledger';

describe('ledger', () => {
  const buildDigest = (value: string): string => createHash('sha256').update(value).digest('hex');

  const buildSigner = (): LedgerSignerOptions => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    return {
      privateKeyPem: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
      publicKeyPem: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
      keyId: 'lead-auditor',
    };
  };

  it('creates an append-only ledger with verifiable signatures', () => {
    const signer = buildSigner();

    const manifestDigestA = buildDigest('manifest-a');
    const manifestDigestB = buildDigest('manifest-b');

    let ledger = createLedger();
    expect(ledger.root).toBe(GENESIS_ROOT);

    ledger = appendEntry(
      ledger,
      {
        snapshotId: 'SNAP-001',
        manifestDigest: manifestDigestA,
        timestamp: '2024-02-01T12:00:00Z',
        evidence: [
          { snapshotId: 'SNAP-001', path: 'reports/summary.html', hash: buildDigest('summary-v1') },
          { snapshotId: 'SNAP-001', path: 'evidence/logs.csv', hash: buildDigest('logs-v1') },
        ],
      },
      { signer },
    );

    ledger = appendEntry(
      ledger,
      {
        snapshotId: 'SNAP-002',
        manifestDigest: manifestDigestB,
        timestamp: '2024-02-03T09:30:00Z',
        evidence: [
          { snapshotId: 'SNAP-002', path: 'reports/summary.html', hash: buildDigest('summary-v2') },
        ],
      },
      { signer },
    );

    expect(ledger.entries).toHaveLength(2);
    expect(ledger.entries[0].signature?.keyId).toBe('lead-auditor');

    const result = verifyLedger(ledger);
    expect(result.root).toBe(ledger.root);
    expect(result.entries.map((entry) => entry.ledgerRoot)).toEqual(
      ledger.entries.map((entry) => entry.ledgerRoot),
    );
  });

  it('detects branching or tampering with previous roots', () => {
    const signer = buildSigner();

    let ledger = createLedger();
    ledger = appendEntry(
      ledger,
      {
        snapshotId: 'SNAP-001',
        manifestDigest: buildDigest('manifest-a'),
        timestamp: '2024-02-01T12:00:00Z',
      },
      { signer },
    );
    ledger = appendEntry(
      ledger,
      {
        snapshotId: 'SNAP-002',
        manifestDigest: buildDigest('manifest-b'),
        timestamp: '2024-02-02T12:00:00Z',
      },
      { signer },
    );

    const tampered = {
      ...ledger,
      entries: ledger.entries.map((entry, index) => ({
        ...entry,
        previousRoot: index === 1 ? '00'.repeat(32) : entry.previousRoot,
      })),
    };

    expect(() => verifyLedger(tampered)).toThrow(LedgerBranchError);
  });

  it('detects invalid signatures during verification', () => {
    const signer = buildSigner();

    let ledger = createLedger();
    ledger = appendEntry(
      ledger,
      {
        snapshotId: 'SNAP-001',
        manifestDigest: buildDigest('manifest-a'),
        timestamp: '2024-02-01T12:00:00Z',
      },
      { signer },
    );

    const tampered = {
      ...ledger,
      entries: ledger.entries.map((entry) => ({
        ...entry,
        signature: entry.signature
          ? {
              ...entry.signature,
              signature: Buffer.alloc(64, 1).toString('base64'),
            }
          : undefined,
      })),
    };

    expect(() => verifyLedger(tampered)).toThrow(LedgerSignatureError);
  });
});
