import {
  CertificationLevel,
  createRequirement,
  createSnapshotIdentifier,
  createSnapshotVersion,
  deriveFingerprint,
  freezeSnapshotVersion,
  getObjectivesForLevel,
  normalizeTag,
  objectiveCatalog,
  objectiveCatalogById,
  evidenceSchema,
} from './index';

describe('@soipack/core', () => {
  it('creates a requirement with defaults', () => {
    const requirement = createRequirement('REQ-1', 'System shall log in');
    expect(requirement).toEqual({
      id: 'REQ-1',
      title: 'System shall log in',
      description: undefined,
      status: 'draft',
      tags: [],
    });
  });

  it('normalizes tags', () => {
    expect(normalizeTag('  Critical ')).toBe('critical');
  });

  it('validates evidence independence flags', () => {
    const timestamp = '2024-06-19T12:00:00.000Z';
    const snapshotId = createSnapshotIdentifier(timestamp, 'abcdef0123456789');
    const parsed = evidenceSchema.parse({
      source: 'git',
      path: 'artifacts/report.md',
      summary: 'Repository snapshot',
      timestamp,
      snapshotId,
      independent: true,
    });
    expect(parsed.independent).toBe(true);
  });

  describe('DO-178C objective catalog', () => {
    const byLevel = (level: CertificationLevel) => getObjectivesForLevel(level);

    it('loads the canonical DO-178C catalog once', () => {
      expect(objectiveCatalog).not.toHaveLength(0);
      const ids = new Set(objectiveCatalog.map((objective) => objective.id));
      expect(ids.size).toBe(objectiveCatalog.length);
    });

    it('filters objectives per certification level', () => {
      expect(byLevel('A')).toHaveLength(objectiveCatalog.length);
      expect(byLevel('B').length).toBeLessThan(objectiveCatalog.length);
      expect(byLevel('C').length).toBeLessThan(byLevel('B').length);
      expect(byLevel('D').every((objective) => objective.levels.D)).toBe(true);
      expect(byLevel('E')).toHaveLength(0);
    });

    it('provides direct lookup for MC/DC coverage objective', () => {
      const mcdc = objectiveCatalogById.get('A-5-10');
      expect(mcdc).toBeDefined();
      expect(mcdc?.levels).toEqual({ A: true, B: false, C: false, D: false, E: false });
      expect(mcdc?.artifacts).toEqual(['coverage_mcdc', 'analysis']);
    });
  });

  describe('snapshot versioning', () => {
    it('creates deterministic snapshot identifiers from timestamp and hash', () => {
      const id = createSnapshotIdentifier('2024-06-19T12:34:56.000Z', 'abcdef0123456789');
      expect(id).toBe('20240619T123456Z-abcdef012345');
    });

    it('creates and freezes snapshot versions', () => {
      const fingerprint = deriveFingerprint(['alpha', 'beta', 'gamma']);
      const version = createSnapshotVersion(fingerprint, { createdAt: '2024-01-01T00:00:00Z' });
      expect(version).toEqual(
        expect.objectContaining({
          id: expect.stringMatching(/^20240101T000000Z-[a-f0-9]{12}$/),
          fingerprint,
          isFrozen: false,
        }),
      );

      const frozen = freezeSnapshotVersion(version, { frozenAt: '2024-01-02T00:00:00Z' });
      expect(frozen.isFrozen).toBe(true);
      expect(frozen.frozenAt).toBe('2024-01-02T00:00:00.000Z');
      expect(frozen.id.startsWith('20240102T000000Z-')).toBe(true);
      expect(freezeSnapshotVersion(frozen)).toBe(frozen);
    });
  });
});
