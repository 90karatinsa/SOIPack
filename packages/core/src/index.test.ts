import { readFileSync } from 'fs';
import { resolve } from 'path';

import { createRequirement, normalizeTag, objectiveListSchema } from './index';

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

  it('validates the DO-178C objective sample data', () => {
    const samplePath = resolve(
      __dirname,
      '../../../data/objectives/do178c_objectives.min.json',
    );
    const raw = readFileSync(samplePath, 'utf-8');
    const objectives = JSON.parse(raw);

    expect(() => objectiveListSchema.parse(objectives)).not.toThrow();
  });
});
