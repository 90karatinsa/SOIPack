import path from 'path';

import { importParasoft } from './parasoft';

const fixturePath = (name: string): string =>
  path.resolve(__dirname, '__fixtures__', 'parasoft', name);

describe('ParasoftImporter', () => {
  it('imports multi-module Parasoft XML payloads', async () => {
    const reportPath = fixturePath('multi-module.xml');
    const { data, warnings } = await importParasoft(reportPath);

    expect(warnings).toEqual([]);

    expect(data.testResults).toHaveLength(3);
    const results = new Map(data.testResults?.map((result) => [result.testId, result]));
    const first = results.get('TC-1');
    expect(first).toMatchObject({
      status: 'passed',
      duration: 1.2,
      className: 'CoreSuite',
      requirementsRefs: ['REQ-1', 'REQ-2'],
    });
    const failed = results.get('TC-2');
    expect(failed).toMatchObject({ status: 'failed', errorMessage: 'Division by zero' });
    const util = results.get('UTIL-1');
    expect(util).toMatchObject({ status: 'passed', className: 'UtilsSuite', duration: 0.6 });

    expect(data.coverage?.tool).toBe('parasoft');
    expect(data.coverage?.files).toHaveLength(2);
    const coverageByPath = Object.fromEntries(
      (data.coverage?.files ?? []).map((entry) => [entry.path, entry]),
    );
    expect(coverageByPath['src/core.c']).toEqual({
      path: 'src/core.c',
      stmt: { covered: 95, total: 105 },
      dec: { covered: 42, total: 52 },
      mcdc: { covered: 3, total: 3 },
    });
    expect(coverageByPath['src/shared.c']).toEqual({
      path: 'src/shared.c',
      stmt: { covered: 55, total: 60 },
      mcdc: { covered: 12, total: 14 },
    });
    expect(new Set(data.coverage?.objectiveLinks)).toEqual(
      new Set(['A-5-08', 'A-5-09', 'A-5-10']),
    );

    expect(data.findings?.map((finding) => ({ id: finding.id, severity: finding.severity }))).toEqual([
      { id: 'F-1', severity: 'error' },
      { id: 'F-2', severity: 'info' },
      { id: 'F-3', severity: 'warn' },
    ]);

    expect(data.fileHashes).toEqual([
      { artifact: 'cm_record', path: 'src/core.c', hash: 'abcdef1234' },
      { artifact: 'cm_record', path: 'src/shared.c', hash: 'fedcba9876' },
    ]);
  });

  it('filters findings below the requested severity', async () => {
    const reportPath = fixturePath('multi-module.xml');
    const { data } = await importParasoft(reportPath, { minSeverity: 'warn' });

    expect(data.findings?.map((finding) => finding.id)).toEqual(['F-1', 'F-3']);
    expect(new Set(data.findings?.map((finding) => finding.severity))).toEqual(
      new Set(['error', 'warn']),
    );
  });

  it('rounds fractional coverage values to the nearest integer', async () => {
    const reportPath = fixturePath('coverage-rounding.xml');
    const { data, warnings } = await importParasoft(reportPath);

    expect(warnings).toEqual([]);

    expect(data.coverage?.files).toEqual([
      {
        path: 'src/math.c',
        stmt: { covered: 63, total: 100 },
        dec: { covered: 2, total: 5 },
        mcdc: { covered: 2, total: 2 },
      },
    ]);
    expect(new Set(data.coverage?.objectiveLinks)).toEqual(
      new Set(['A-5-08', 'A-5-09', 'A-5-10']),
    );
    expect(data.fileHashes).toEqual([
      { artifact: 'cm_record', path: 'src/math.c', hash: '001122' },
    ]);
  });
});
