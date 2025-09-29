import { promises as fs } from 'fs';
import os from 'os';
import path from 'path';

import { importCobertura } from './cobertura';

const fixturesDir = path.resolve(__dirname, '../fixtures/cobertura');

describe('importCobertura', () => {
  it('parses Cobertura reports via streaming without losing precision', async () => {
    const fixturePath = path.join(fixturesDir, 'coverage.xml');

    const { data, warnings } = await importCobertura(fixturePath);

    expect(warnings).toEqual([]);
    expect(data).toEqual({
      files: [
        {
          file: 'src/example.ts',
          statements: { covered: 1, total: 2, percentage: 50 },
          branches: { covered: 1, total: 2, percentage: 50 },
          functions: { covered: 1, total: 1, percentage: 100 },
        },
        {
          file: 'src/other.ts',
          statements: { covered: 1, total: 1, percentage: 100 },
          branches: undefined,
          functions: { covered: 1, total: 1, percentage: 100 },
        },
      ],
      totals: {
        statements: { covered: 2, total: 3, percentage: 66.67 },
        branches: { covered: 1, total: 2, percentage: 50 },
        functions: { covered: 2, total: 2, percentage: 100 },
        mcdc: undefined,
      },
      testMap: {
        'AuthSuite#passes': ['src/example.ts'],
        'AuditSuite#records': ['src/other.ts'],
      },
    });
  });

  it('warns when no classes are present in the report', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'cobertura-empty-'));
    const fixturePath = path.join(dir, 'empty.xml');
    await fs.writeFile(
      fixturePath,
      `<?xml version="1.0"?>\n<coverage timestamp="0" version="0"><packages /></coverage>`,
      'utf8',
    );

    const { data, warnings } = await importCobertura(fixturePath);

    expect(data.files).toEqual([]);
    expect(data.totals.statements).toEqual({ covered: 0, total: 0, percentage: 0 });
    expect(warnings).toContain(`No <class> entries found in Cobertura file at ${fixturePath}.`);

    await fs.rm(dir, { recursive: true, force: true });
  });

  it('emits warnings for malformed XML encountered mid-stream', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'cobertura-malformed-'));
    const fixturePath = path.join(dir, 'broken.xml');
    await fs.writeFile(
      fixturePath,
      `<coverage><packages><package><classes><class name="Demo" filename="demo.ts"><lines><line hits="1"></lines></class></classes></package></packages></coverage>`,
      'utf8',
    );

    const { warnings } = await importCobertura(fixturePath);

    expect(warnings.some((warning) => warning.includes('Malformed Cobertura XML'))).toBe(true);

    await fs.rm(dir, { recursive: true, force: true });
  });

  it('streams large Cobertura reports and warns about oversized payloads', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'cobertura-large-'));
    const fixturePath = path.join(dir, 'large.xml');

    const lineBlock = '<line number="1" hits="1" branch="false" />\n';
    const repeatedLines = lineBlock.repeat(120000); // ~6 MiB of XML
    const coverage = `<?xml version="1.0"?>\n<coverage>\n  <packages>\n    <package>\n      <classes>\n        <class name="Big" filename="big.ts">\n          <methods />\n          <lines>\n${repeatedLines}          </lines>\n        </class>\n      </classes>\n    </package>\n  </packages>\n</coverage>`;

    await fs.writeFile(fixturePath, coverage, 'utf8');

    const { data, warnings } = await importCobertura(fixturePath);

    expect(data.files[0]?.statements.total).toBe(120000);
    expect(warnings.some((warning) => warning.includes('exceeded'))).toBe(true);

    await fs.rm(dir, { recursive: true, force: true });
  });
});
