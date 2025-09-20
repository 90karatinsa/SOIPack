import { AdapterMetadata } from '@soipack/adapters';

import { runCli } from './index';

describe('@soipack/cli', () => {
  const adapters: AdapterMetadata[] = [
    { name: 'Jira CSV', supportedArtifacts: ['CSV'] },
    { name: 'JUnit XML', supportedArtifacts: ['XML'] },
  ];

  it('lists adapters', async () => {
    const output = await runCli('list-adapters', { adapters, requirements: [], testCases: [] });
    expect(output).toContain('Jira CSV: csv');
    expect(output).toContain('JUnit XML: xml');
  });

  it('generates HTML and JSON sections', async () => {
    const output = await runCli('generate-report', {
      adapters,
      requirements: [
        {
          id: 'REQ-1',
          title: 'Provide authentication',
        },
      ],
      testCases: [
        {
          id: 'TC-1',
          name: 'should authenticate',
          requirementId: 'REQ-1',
        },
      ],
    });

    expect(output).toContain('<!DOCTYPE html>');
    expect(output).toContain('"requirements"');
  });
});
