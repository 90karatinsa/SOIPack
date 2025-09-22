import { promises as fs } from 'fs';
import path from 'path';

import { CoverageMetric, CoverageReport, FileCoverageSummary, ParseResult } from './types';
import { parseXml } from './utils/xml';

type UnknownRecord = Record<string, unknown>;

const toArray = <T>(value: T | T[] | undefined): T[] => {
  if (value === undefined) {
    return [];
  }
  return Array.isArray(value) ? value : [value];
};

const asNumber = (value: unknown): number => {
  if (typeof value === 'number') {
    return value;
  }
  const parsed = Number.parseFloat(String(value ?? '0'));
  return Number.isFinite(parsed) ? parsed : 0;
};

const parseConditionCoverage = (value: unknown): { covered: number; total: number } => {
  const text = String(value ?? '').trim();
  const match = text.match(/\((\d+)[^\d]+(\d+)\)/);
  if (match) {
    return { covered: Number.parseInt(match[1], 10), total: Number.parseInt(match[2], 10) };
  }
  const percentMatch = text.match(/(\d+(?:\.\d+)?)%/);
  if (percentMatch) {
    const percent = Number.parseFloat(percentMatch[1]);
    return { covered: percent, total: 100 };
  }
  return { covered: 0, total: 0 };
};

const addMetric = (target: CoverageMetric | undefined, metric: CoverageMetric): CoverageMetric => {
  if (!target) {
    return metric;
  }
  return {
    covered: target.covered + metric.covered,
    total: target.total + metric.total,
    percentage: 0,
  };
};

const finalizeMetric = (metric: CoverageMetric | undefined): CoverageMetric | undefined => {
  if (!metric) {
    return undefined;
  }
  return {
    covered: metric.covered,
    total: metric.total,
    percentage: metric.total > 0 ? Number(((metric.covered / metric.total) * 100).toFixed(2)) : 0,
  };
};

const toTestNames = (value: unknown): string[] => {
  if (!value) {
    return [];
  }
  if (typeof value === 'string') {
    return value
      .split(/[,;\s]+/)
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0);
  }
  if (Array.isArray(value)) {
    return value.flatMap((entry) => toTestNames(entry));
  }
  if (typeof value === 'object') {
    const record = value as UnknownRecord;
    if (typeof record.name === 'string') {
      return [record.name.trim()].filter((entry) => entry.length > 0);
    }
    return Object.values(record).flatMap((entry) => toTestNames(entry));
  }
  return [];
};

const registerTestFile = (
  map: Map<string, Set<string>>,
  testName: string,
  fileName: string,
): void => {
  const normalizedTest = testName.trim();
  const normalizedFile = fileName.trim();
  if (!normalizedTest || !normalizedFile) {
    return;
  }
  const existing = map.get(normalizedTest) ?? new Set<string>();
  existing.add(normalizedFile);
  map.set(normalizedTest, existing);
};

export const importCobertura = async (filePath: string): Promise<ParseResult<CoverageReport>> => {
  const warnings: string[] = [];
  const location = path.resolve(filePath);
  const content = await fs.readFile(location, 'utf8');

  let raw: UnknownRecord;
  try {
    raw = parseXml<UnknownRecord>(content);
  } catch (error) {
    warnings.push(`Failed to parse Cobertura XML at ${location}: ${(error as Error).message}`);
    return {
      data: {
        totals: { statements: { covered: 0, total: 0, percentage: 0 } },
        files: [],
      },
      warnings,
    };
  }

  const coverageRoot = (raw.coverage ?? raw) as UnknownRecord;
  const packages = toArray((coverageRoot.packages as UnknownRecord | undefined)?.package as UnknownRecord | UnknownRecord[] | undefined);

  if (packages.length === 0) {
    warnings.push(`No <class> entries found in Cobertura file at ${location}.`);
  }

  const files: FileCoverageSummary[] = [];
  const testFiles = new Map<string, Set<string>>();

  packages.forEach((pkg) => {
    const classes = toArray((pkg.classes as UnknownRecord | undefined)?.class as UnknownRecord | UnknownRecord[] | undefined);
    classes.forEach((clazz) => {
      const fileName = (clazz.filename as string | undefined) ?? (clazz.name as string | undefined) ?? 'unknown';
      const lines = toArray((clazz.lines as UnknownRecord | undefined)?.line as UnknownRecord | UnknownRecord[] | undefined);
      const methods = toArray((clazz.methods as UnknownRecord | undefined)?.method as UnknownRecord | UnknownRecord[] | undefined);

      let statementCovered = 0;
      let statementTotal = 0;
      let branchCovered = 0;
      let branchTotal = 0;

      lines.forEach((line) => {
        const hits = asNumber(line.hits);
        statementTotal += 1;
        if (hits > 0) {
          statementCovered += 1;
        }
        const testAttributes = [line.tests, line.test, line['covered-by'], line['coveredby'], line['test-name']];
        testAttributes.forEach((attribute) => {
          toTestNames(attribute).forEach((testName) => registerTestFile(testFiles, testName, fileName));
        });
        const branchAttribute = line.branch;
        const hasBranchFlag =
          (typeof branchAttribute === 'string' && branchAttribute.toLowerCase() === 'true') ||
          (typeof branchAttribute === 'boolean' && branchAttribute);
        if (hasBranchFlag || line['condition-coverage']) {
          const { covered, total } = parseConditionCoverage(line['condition-coverage']);
          if (total > 0) {
            branchTotal += total;
            branchCovered += covered;
          } else {
            branchTotal += 1;
            if (hits > 0) {
              branchCovered += 1;
            }
          }
        }
      });

      const functionsTotal = methods.length;
      const functionsCovered = methods.reduce((count, method) => count + (asNumber(method.hits) > 0 ? 1 : 0), 0);

      files.push({
        file: fileName,
        statements: {
          covered: statementCovered,
          total: statementTotal,
          percentage: statementTotal > 0 ? Number(((statementCovered / statementTotal) * 100).toFixed(2)) : 0,
        },
        branches:
          branchTotal > 0
            ? {
                covered: branchCovered,
                total: branchTotal,
                percentage: Number(((branchCovered / branchTotal) * 100).toFixed(2)),
              }
            : undefined,
        functions:
          functionsTotal > 0
            ? {
                covered: functionsCovered,
                total: functionsTotal,
                percentage: Number(((functionsCovered / functionsTotal) * 100).toFixed(2)),
              }
            : undefined,
      });
    });
  });

  const totals = files.reduce<CoverageReport['totals']>((acc, file) => {
    acc.statements = addMetric(acc.statements, { ...file.statements });
    if (file.branches) {
      acc.branches = addMetric(acc.branches, { ...file.branches });
    }
    if (file.functions) {
      acc.functions = addMetric(acc.functions, { ...file.functions });
    }
    return acc;
  }, { statements: { covered: 0, total: 0, percentage: 0 } } as CoverageReport['totals']);

  const finalizedTotals: CoverageReport['totals'] = {
    statements: finalizeMetric(totals.statements)!,
    branches: finalizeMetric(totals.branches),
    functions: finalizeMetric(totals.functions),
  };
  const testMapEntries = Array.from(testFiles.entries()).map(([test, filesForTest]) => [test, Array.from(filesForTest)]);
  const testMap = testMapEntries.length > 0 ? Object.fromEntries(testMapEntries) : undefined;

  return { data: { totals: finalizedTotals, files, testMap }, warnings };
};
