import { registerAdapter, toRequirement } from './index';

describe('@soipack/adapters', () => {
  it('normalizes supported artifacts to lowercase', () => {
    const adapter = registerAdapter({
      name: 'JUnit XML',
      supportedArtifacts: ['JUnit', 'XML'],
    });

    expect(adapter.supportedArtifacts).toEqual(['junit', 'xml']);
  });

  it('throws when no artifact is provided', () => {
    expect(() => registerAdapter({ name: 'Empty', supportedArtifacts: [] })).toThrow(
      'Adapter must support at least one artifact type.',
    );
  });

  it('converts raw record to requirement', () => {
    const requirement = toRequirement({ id: 10, title: ' Login Feature ', description: null });
    expect(requirement).toEqual({
      id: '10',
      title: 'Login Feature',
      description: undefined,
      status: 'draft',
      tags: [],
    });
  });
});
