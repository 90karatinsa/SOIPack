import { createRequirement, normalizeTag } from './index';

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
});
