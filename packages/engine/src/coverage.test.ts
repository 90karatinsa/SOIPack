import { aggregateCoberturaCoverage, aggregateJsonCoverage } from './coverage';

describe('CoverageAggregator', () => {
  it('aggregates JSON coverage with ignore ranges and warns about missing MC/DC', () => {
    const result = aggregateJsonCoverage(
      {
        files: [
          {
            path: 'src/controllers/auth.ts',
            statements: [
              { line: 1, hit: 1 },
              { line: 2, hit: 0 },
              { line: 3, hit: 1 },
            ],
            branches: [
              { line: 2, covered: 1, total: 2 },
              { line: 3, covered: 2, total: 2 },
            ],
            mcdc: [
              { line: 6, covered: 2, total: 4 },
            ],
          },
          {
            path: 'src/services/audit.ts',
            statements: [
              { line: 10, hit: 1 },
              { line: 11, hit: 0 },
            ],
          },
        ],
      },
      {
        ignore: {
          'src/services/audit.ts': [{ start: 11, end: 12 }],
        },
      },
    );

    expect(result.summary.files).toHaveLength(2);
    const [auth, audit] = result.summary.files;

    expect(auth.statements).toEqual({ covered: 2, total: 3, percentage: 66.7 });
    expect(auth.branches).toEqual({ covered: 3, total: 4, percentage: 75 });
    expect(auth.mcdc).toEqual({ covered: 2, total: 4, percentage: 50 });

    expect(audit.statements).toEqual({ covered: 1, total: 1, percentage: 100 });
    expect(audit.branches).toBeUndefined();
    expect(audit.mcdc).toBeUndefined();

    expect(result.summary.totals.statements).toEqual({ covered: 3, total: 4, percentage: 75 });
    expect(result.summary.totals.mcdc).toEqual({ covered: 2, total: 4, percentage: 50 });

    expect(result.warnings).toContain('MC/DC kapsam verisi eksik: src/services/audit.ts');
    expect(result.warnings).not.toContain('MC/DC kapsam verisi raporda bulunamadı.');
  });

  it('parses Cobertura XML and reports branch and MC/DC warnings', () => {
    const coberturaXml = `<?xml version="1.0" encoding="UTF-8"?>
<coverage line-rate="0.75" branch-rate="0.5" lines-covered="3" lines-valid="4">
  <packages>
    <package name="core">
      <classes>
        <class name="Auth" filename="src/auth.ts">
          <lines>
            <line number="1" hits="1" />
            <line number="2" hits="0" branch="true" condition-coverage="50% (1/2)" />
            <line number="3" hits="1" branch="true" condition-coverage="100% (2/2)" />
            <line number="4" hits="0" />
          </lines>
        </class>
        <class name="Audit" filename="src/audit.ts">
          <lines>
            <line number="10" hits="1" />
            <line number="11" hits="0" />
          </lines>
        </class>
      </classes>
    </package>
  </packages>
</coverage>`;

    const result = aggregateCoberturaCoverage(coberturaXml, {
      ignore: {
        'src/audit.ts': [{ start: 11, end: 20 }],
      },
    });

    expect(result.summary.files).toHaveLength(2);
    const [auth, audit] = result.summary.files;

    expect(auth.statements).toEqual({ covered: 2, total: 4, percentage: 50 });
    expect(auth.branches).toEqual({ covered: 3, total: 4, percentage: 75 });
    expect(auth.mcdc).toBeUndefined();

    expect(audit.statements).toEqual({ covered: 1, total: 1, percentage: 100 });
    expect(audit.branches).toBeUndefined();

    expect(result.summary.totals.statements).toEqual({ covered: 3, total: 5, percentage: 60 });
    expect(result.summary.totals.branches).toEqual({ covered: 3, total: 4, percentage: 75 });
    expect(result.summary.totals.mcdc).toBeUndefined();

    expect(result.warnings).toEqual(
      expect.arrayContaining([
        'Karar kapsamı verisi bulunamadı: src/audit.ts',
        'MC/DC kapsam verisi eksik: src/auth.ts',
        'MC/DC kapsam verisi eksik: src/audit.ts',
        'MC/DC kapsam verisi raporda bulunamadı.',
      ]),
    );
  });
});
