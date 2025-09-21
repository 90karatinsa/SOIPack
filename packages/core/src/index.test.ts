import { readFileSync } from 'fs';
import { resolve } from 'path';

import {
  CertificationLevel,
  createRequirement,
  normalizeTag,
  objectiveListSchema,
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
    const samplePath = resolve(
      __dirname,
      '../../../data/objectives/do178c_objectives.min.json',
    );
    const raw = readFileSync(samplePath, 'utf-8');
    const parsed = JSON.parse(raw);
    const objectives = objectiveListSchema.parse(parsed);

    const byLevel = (level: CertificationLevel) =>
      objectives.filter((objective) => objective.levels[level]);

    it('validates the DO-178C objective sample data', () => {
      expect(objectives).not.toHaveLength(0);
    });

    it('filters objectives per certification level', () => {
      expect(byLevel('A')).toHaveLength(objectives.length);
      expect(byLevel('B').length).toBeLessThan(objectives.length);
      expect(byLevel('C').length).toBeLessThan(byLevel('B').length);
      expect(byLevel('D').every((objective) => objective.levels.D)).toBe(true);
      expect(byLevel('E')).toHaveLength(0);
    });

    it('marks structural coverage MC/DC as Level A only', () => {
      const mcdc = objectives.find((objective) => objective.id === 'A-5-10');
      expect(mcdc).toBeDefined();
      expect(mcdc?.levels).toEqual({ A: true, B: false, C: false, D: false, E: false });
    });
  });
});
