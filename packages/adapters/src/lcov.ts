import { promises as fs } from 'fs';
import path from 'path';

import { CoverageMetric, CoverageReport, FileCoverageSummary, ParseResult } from './types';

interface MetricAccumulator {
  covered: number;
  total: number;
}

interface FileAccumulator {
  file: string;
  statements: MetricAccumulator;
  branches: MetricAccumulator;
  functions: MetricAccumulator;
  mcdc: MetricAccumulator;
}

const createAccumulator = (file: string): FileAccumulator => ({
  file,
  statements: { covered: 0, total: 0 },
  branches: { covered: 0, total: 0 },
  functions: { covered: 0, total: 0 },
  mcdc: { covered: 0, total: 0 },
});

const toCoverageMetric = ({ covered, total }: MetricAccumulator): CoverageMetric => ({
  covered,
  total,
  percentage: total > 0 ? Number(((covered / total) * 100).toFixed(2)) : 0,
});

const mergeMetric = (target: MetricAccumulator, updates: Partial<MetricAccumulator>): void => {
  if (updates.covered !== undefined) {
    target.covered = updates.covered;
  }
  if (updates.total !== undefined) {
    target.total = updates.total;
  }
};

const parseNumber = (value: string, lineNumber: number, label: string, warnings: string[]): number | undefined => {
  const parsed = Number.parseInt(value, 10);
  if (Number.isNaN(parsed)) {
    warnings.push(`Invalid numeric value for ${label} on line ${lineNumber}: ${value}`);
    return undefined;
  }
  return parsed;
};

const finalizeFile = (file: FileAccumulator): FileCoverageSummary => ({
  file: file.file,
  statements: toCoverageMetric(file.statements),
  branches: file.branches.total > 0 ? toCoverageMetric(file.branches) : undefined,
  functions: file.functions.total > 0 ? toCoverageMetric(file.functions) : undefined,
  mcdc: file.mcdc.total > 0 ? toCoverageMetric(file.mcdc) : undefined,
});

const accumulateTotals = (files: FileCoverageSummary[]): CoverageReport['totals'] => {
  const totals: {
    statements: MetricAccumulator;
    branches: MetricAccumulator;
    functions: MetricAccumulator;
    mcdc: MetricAccumulator;
  } = {
    statements: { covered: 0, total: 0 },
    branches: { covered: 0, total: 0 },
    functions: { covered: 0, total: 0 },
    mcdc: { covered: 0, total: 0 },
  };

  files.forEach((file) => {
    totals.statements.covered += file.statements.covered;
    totals.statements.total += file.statements.total;

    if (file.branches) {
      totals.branches.covered += file.branches.covered;
      totals.branches.total += file.branches.total;
    }

    if (file.functions) {
      totals.functions.covered += file.functions.covered;
      totals.functions.total += file.functions.total;
    }

    if (file.mcdc) {
      totals.mcdc.covered += file.mcdc.covered;
      totals.mcdc.total += file.mcdc.total;
    }
  });

  return {
    statements: toCoverageMetric(totals.statements),
    branches: totals.branches.total > 0 ? toCoverageMetric(totals.branches) : undefined,
    functions: totals.functions.total > 0 ? toCoverageMetric(totals.functions) : undefined,
    mcdc: totals.mcdc.total > 0 ? toCoverageMetric(totals.mcdc) : undefined,
  };
};

export const importLcov = async (filePath: string): Promise<ParseResult<CoverageReport>> => {
  const warnings: string[] = [];
  const location = path.resolve(filePath);
  const content = await fs.readFile(location, 'utf8');
  const lines = content.split(/\r?\n/);

  const summaries: FileCoverageSummary[] = [];
  let current: FileAccumulator | undefined;
  let currentTestName: string | undefined;
  const testFiles = new Map<string, Set<string>>();

  const registerTestFile = (testName: string | undefined, file: string | undefined) => {
    const normalizedTestName = testName?.trim();
    const normalizedFile = file?.trim();
    if (!normalizedTestName || !normalizedFile) {
      return;
    }
    const existing = testFiles.get(normalizedTestName) ?? new Set<string>();
    existing.add(normalizedFile);
    testFiles.set(normalizedTestName, existing);
  };

  lines.forEach((line, index) => {
    const lineNumber = index + 1;
    if (line.startsWith('SF:')) {
      if (current) {
        summaries.push(finalizeFile(current));
      }
      const file = line.substring(3).trim();
      current = createAccumulator(file);
      registerTestFile(currentTestName, file);
      return;
    }

    if (line.startsWith('TN:')) {
      currentTestName = line.substring(3).trim();
      return;
    }

    if (!current) {
      return;
    }

    if (line.startsWith('LF:')) {
      const total = parseNumber(line.substring(3).trim(), lineNumber, 'lines found', warnings);
      if (total !== undefined) {
        mergeMetric(current.statements, { total });
      }
      return;
    }

    if (line.startsWith('LH:')) {
      const covered = parseNumber(line.substring(3).trim(), lineNumber, 'lines hit', warnings);
      if (covered !== undefined) {
        mergeMetric(current.statements, { covered });
      }
      return;
    }

    if (line.startsWith('BRF:')) {
      const total = parseNumber(line.substring(4).trim(), lineNumber, 'branches found', warnings);
      if (total !== undefined) {
        mergeMetric(current.branches, { total });
      }
      return;
    }

    if (line.startsWith('BRH:')) {
      const covered = parseNumber(line.substring(4).trim(), lineNumber, 'branches hit', warnings);
      if (covered !== undefined) {
        mergeMetric(current.branches, { covered });
      }
      return;
    }

    if (line.startsWith('FNF:')) {
      const total = parseNumber(line.substring(4).trim(), lineNumber, 'functions found', warnings);
      if (total !== undefined) {
        mergeMetric(current.functions, { total });
      }
      return;
    }

    if (line.startsWith('FNH:')) {
      const covered = parseNumber(line.substring(4).trim(), lineNumber, 'functions hit', warnings);
      if (covered !== undefined) {
        mergeMetric(current.functions, { covered });
      }
      return;
    }

    if (line.trim() === 'end_of_record') {
      summaries.push(finalizeFile(current));
      current = undefined;
      currentTestName = undefined;
    }
  });

  if (current) {
    summaries.push(finalizeFile(current));
  }

  if (summaries.length === 0) {
    warnings.push(`No coverage records found in ${location}.`);
  }

  const totals = accumulateTotals(summaries);
  const testMapEntries = Array.from(testFiles.entries()).map(([testName, files]) => [testName, Array.from(files)]);
  const testMap = testMapEntries.length > 0 ? Object.fromEntries(testMapEntries) : undefined;

  return { data: { totals, files: summaries, testMap }, warnings };
};
