import path from 'path';

import { fromLDRA, fromPolyspace, fromVectorCAST } from './index';

const fixturePath = (name: string): string =>
  path.resolve(__dirname, '../fixtures', name);

describe('Static analysis adapters', () => {
  it('imports Polyspace findings', async () => {
    const reportPath = fixturePath('polyspace/report.json');
    const { data, warnings } = await fromPolyspace(reportPath);

    expect(warnings).toHaveLength(0);
    expect(data.findings).toHaveLength(2);
    const [first, second] = data.findings ?? [];

    expect(first).toEqual({
      tool: 'polyspace',
      id: 'PS-001',
      file: 'src/foo.c',
      func: 'foo',
      line: 42,
      classification: 'MISRA-C:2012 12.3',
      severity: 'error',
      status: 'unproved',
      message: 'possible overflow',
      objectiveLinks: ['A-5-05', 'A-5-14'],
    });

    expect(second?.severity).toBe('warn');
    expect(second?.status).toBe('justified');
    expect(second?.objectiveLinks).toEqual(['A-5-05', 'A-5-14']);
  });

  it('imports LDRA violations and coverage', async () => {
    const reportPath = fixturePath('ldra/tbvision.json');
    const { data, warnings } = await fromLDRA(reportPath);

    expect(warnings).toHaveLength(0);
    expect(data.findings).toHaveLength(2);
    expect(data.findings?.[0]).toMatchObject({
      tool: 'ldra',
      id: 'L-100',
      classification: 'MISRA 8.7',
      severity: 'error',
      objectiveLinks: ['A-5-05', 'A-5-08', 'A-5-14'],
    });

    expect(data.coverage).toBeDefined();
    expect(data.coverage?.tool).toBe('ldra');
    expect(data.coverage?.files).toHaveLength(1);
    expect(data.coverage?.files[0]).toEqual({
      path: 'src/foo.c',
      stmt: { covered: 50, total: 60 },
      dec: { covered: 30, total: 40 },
      mcdc: { covered: 28, total: 40 },
    });
    expect(data.coverage?.objectiveLinks).toEqual(['A-5-08']);
  });

  it('imports VectorCAST coverage and findings', async () => {
    const reportPath = fixturePath('vectorcast/coverage.json');
    const { data, warnings } = await fromVectorCAST(reportPath);

    expect(warnings).toHaveLength(0);
    expect(data.findings).toHaveLength(2);
    expect(data.findings?.[0]).toMatchObject({
      tool: 'vectorcast',
      id: 'V-001',
      severity: 'info',
      objectiveLinks: ['A-5-06', 'A-5-11'],
    });

    expect(data.coverage).toBeDefined();
    expect(data.coverage?.tool).toBe('vectorcast');
    expect(data.coverage?.files).toHaveLength(2);
    const [first, second] = data.coverage?.files ?? [];
    expect(first).toEqual({
      path: 'src/foo.c',
      stmt: { covered: 60, total: 60 },
      dec: { covered: 30, total: 30 },
      mcdc: { covered: 25, total: 25 },
    });
    expect(second).toEqual({
      path: 'src/bar.c',
      stmt: { covered: 55, total: 60 },
      dec: { covered: 27, total: 30 },
    });
    expect(data.coverage?.objectiveLinks).toEqual(['A-5-08', 'A-5-09', 'A-5-10']);
  });
});
