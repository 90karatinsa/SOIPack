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
  createDesignRecord,
  designRecordSchema,
  DesignStatus,
  type EvidenceSource,
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

  describe('design records', () => {
    it('creates a design record with normalized tags and trimmed references', () => {
      const record = createDesignRecord('DES-1', 'Authentication design', {
        description: 'Auth module design overview',
        status: 'allocated',
        tags: [' Critical ', 'Auth ', 'critical'],
        requirementRefs: [' REQ-1 ', 'REQ-2'],
        codeRefs: [' src/auth/login.ts ', 'src/common/logger.ts'],
      });

      expect(record).toEqual({
        id: 'DES-1',
        title: 'Authentication design',
        description: 'Auth module design overview',
        status: 'allocated',
        tags: ['critical', 'auth'],
        requirementRefs: ['REQ-1', 'REQ-2'],
        codeRefs: ['src/auth/login.ts', 'src/common/logger.ts'],
      });
    });

    it('rejects blank identifiers', () => {
      expect(() =>
        designRecordSchema.parse({
          id: '',
          title: 'Missing id',
          status: 'draft',
          tags: [],
          requirementRefs: [],
          codeRefs: [],
        }),
      ).toThrow('Design identifier is required.');
    });

    it('rejects blank status values', () => {
      expect(() =>
        designRecordSchema.parse({
          id: 'DES-2',
          title: 'Missing status',
          status: '' as unknown as DesignStatus,
          tags: [],
          requirementRefs: [],
          codeRefs: [],
        }),
      ).toThrow(/Invalid enum value/);
    });

    it('rejects duplicate requirement references', () => {
      expect(() =>
        designRecordSchema.parse({
          id: 'DES-3',
          title: 'Duplicate requirements',
          status: 'draft',
          tags: [],
          requirementRefs: ['REQ-1', 'REQ-1'],
          codeRefs: [],
        }),
      ).toThrow('Requirement reference REQ-1 is duplicated.');
    });
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

  it('accepts jama evidence sources and rejects unknown sources', () => {
    const timestamp = '2024-07-01T08:30:00.000Z';
    const snapshotId = createSnapshotIdentifier(timestamp, '0123456789abcdef');

    const jamaEvidence = evidenceSchema.parse({
      source: 'jama',
      path: 'exports/jama/requirements.csv',
      summary: 'Requirements exported from Jama',
      timestamp,
      snapshotId,
    });

    expect(jamaEvidence.source).toBe('jama');

    expect(() =>
      evidenceSchema.parse({
        source: 'unknownTool' as EvidenceSource,
        path: 'invalid/path',
        summary: 'Invalid evidence',
        timestamp,
        snapshotId,
      }),
    ).toThrow(/Invalid enum value/);
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
