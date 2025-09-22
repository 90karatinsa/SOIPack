import {
  CertificationLevel,
  createRequirement,
  getObjectivesForLevel,
  normalizeTag,
  objectiveCatalog,
  objectiveCatalogById,
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
});
