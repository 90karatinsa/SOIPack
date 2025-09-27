import path from 'path';

import { importDoorsClassicCsv } from './doorsClassic';

describe('importDoorsClassicCsv', () => {
  const fixturePath = (...segments: string[]): string =>
    path.resolve(__dirname, 'fixtures', 'doors-classic', ...segments);

  it('parses hierarchy and external links from DOORS Classic exports', async () => {
    const filePath = fixturePath('requirements.sample.csv');
    const result = await importDoorsClassicCsv(filePath);

    expect(result.warnings).toHaveLength(0);
    expect(result.data.requirements).toHaveLength(3);

    const [root, child, leaf] = result.data.requirements;

    expect(root).toEqual({
      id: 'REQ-100',
      title: 'Top Level Requirement',
      description: 'Provides overall guidance.',
      status: 'Approved',
      type: 'System Requirement',
    });

    expect(child).toEqual({
      id: 'REQ-110',
      title: 'Subsystem Requirement',
      description: 'Covers subsystem detail.',
      status: 'In Work',
      type: 'System Requirement',
    });

    expect(leaf).toEqual({
      id: 'REQ-111',
      title: 'Derived Requirement',
      description: 'Ensures subsystem compliance.',
      status: 'Draft',
      type: 'Derived Requirement',
    });

    expect(result.data.traces).toEqual(
      expect.arrayContaining([
        { fromId: 'REQ-110', toId: 'REQ-100', type: 'satisfies' },
        { fromId: 'REQ-111', toId: 'REQ-110', type: 'satisfies' },
        { fromId: 'REQ-110', toId: 'TC-900', type: 'verifies' },
        { fromId: 'REQ-110', toId: 'DES-200', type: 'implements' },
        { fromId: 'REQ-111', toId: 'REQ-200', type: 'satisfies' },
      ]),
    );
  });

  it('warns when parent absolute numbers are missing', async () => {
    const filePath = fixturePath('missing-parent.sample.csv');
    const result = await importDoorsClassicCsv(filePath);

    expect(result.data.requirements).toHaveLength(2);
    expect(result.data.traces).toHaveLength(0);
    expect(result.warnings).toEqual(
      expect.arrayContaining([
        expect.stringContaining('parent absolute number 3'),
      ]),
    );
  });

  it('decodes latin-1 encoded files', async () => {
    const filePath = fixturePath('latin1.sample.csv');
    const result = await importDoorsClassicCsv(filePath);

    expect(result.warnings).toHaveLength(0);
    expect(result.data.requirements).toHaveLength(1);
    expect(result.data.requirements[0]).toEqual({
      id: 'REQ-300',
      title: 'Requisición crítica',
      description: 'Determinación de parámetros álvarez.',
      status: 'En revisión',
      type: 'Sistema',
    });
  });
});
