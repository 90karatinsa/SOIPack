import { CoverageMetric, CoverageReport, FileCoverageSummary } from '@soipack/adapters';
import { XMLParser } from 'fast-xml-parser';

type MaybeArray<T> = T | T[];

export interface IgnoreRange {
  start: number;
  end: number;
}

export interface CoverageAggregationOptions {
  /**
   * File specific ignore ranges. Keys are normalized paths using forward slashes.
   */
  ignore?: Record<string, IgnoreRange[]>;
}

export interface JsonStatementEntry {
  line: number;
  hit: number;
}

export interface JsonBranchEntry {
  line: number;
  covered: number;
  total: number;
}

export interface JsonMcdcEntry {
  line: number;
  covered: number;
  total: number;
}

export interface JsonFunctionEntry {
  line: number;
  hit: number;
}

export interface JsonCoverageFile {
  path: string;
  statements: JsonStatementEntry[];
  branches?: JsonBranchEntry[];
  functions?: JsonFunctionEntry[];
  mcdc?: JsonMcdcEntry[];
}

export interface JsonCoveragePayload {
  files: JsonCoverageFile[];
}

export interface CoverageAggregationResult {
  summary: CoverageReport;
  warnings: string[];
}

interface IntermediateTotals {
  statements: { covered: number; total: number };
  branches: { covered: number; total: number };
  functions: { covered: number; total: number };
  mcdc: { covered: number; total: number };
}

const normalizePath = (path: string): string => path.replace(/\\+/g, '/');

const normalizeRanges = (ranges: IgnoreRange[] | undefined): IgnoreRange[] => {
  if (!ranges) {
    return [];
  }

  return ranges
    .map(({ start, end }) => ({
      start: Math.min(start, end),
      end: Math.max(start, end),
    }))
    .sort((a, b) => a.start - b.start);
};

const shouldIgnoreLine = (line: number, ranges: IgnoreRange[]): boolean =>
  ranges.some((range) => line >= range.start && line <= range.end);

const toMetric = ({ covered, total }: { covered: number; total: number }): CoverageMetric => ({
  covered,
  total,
  percentage: total === 0 ? 0 : Number(((covered / total) * 100).toFixed(1)),
});

const mergeTotals = (files: FileCoverageSummary[]): CoverageReport['totals'] => {
  const totals: IntermediateTotals = {
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

  const result: CoverageReport['totals'] = {
    statements: toMetric(totals.statements),
  };

  if (totals.branches.total > 0) {
    result.branches = toMetric(totals.branches);
  }

  if (totals.functions.total > 0) {
    result.functions = toMetric(totals.functions);
  }

  if (totals.mcdc.total > 0) {
    result.mcdc = toMetric(totals.mcdc);
  }

  return result;
};

const buildFileSummary = (
  path: string,
  statements: { covered: number; total: number },
  branches?: { covered: number; total: number },
  functions?: { covered: number; total: number },
  mcdc?: { covered: number; total: number },
): FileCoverageSummary => {
  const summary: FileCoverageSummary = {
    file: path,
    statements: toMetric(statements),
  };

  if (branches) {
    summary.branches = toMetric(branches);
  }

  if (functions) {
    summary.functions = toMetric(functions);
  }

  if (mcdc) {
    summary.mcdc = toMetric(mcdc);
  }

  return summary;
};

const computeJsonFileCoverage = (
  file: JsonCoverageFile,
  ignoreRanges: IgnoreRange[],
  warnings: Set<string>,
): FileCoverageSummary => {
  const statements = file.statements.filter((entry) => !shouldIgnoreLine(entry.line, ignoreRanges));
  const statementCovered = statements.filter((entry) => entry.hit > 0).length;

  const branches = (file.branches ?? []).filter((entry) => !shouldIgnoreLine(entry.line, ignoreRanges));
  const branchTotals = branches.reduce(
    (acc, entry) => {
      acc.covered += entry.covered;
      acc.total += entry.total;
      return acc;
    },
    { covered: 0, total: 0 },
  );

  const functions = (file.functions ?? []).filter((entry) => !shouldIgnoreLine(entry.line, ignoreRanges));
  const functionCovered = functions.filter((entry) => entry.hit > 0).length;

  const mcdcEntries = (file.mcdc ?? []).filter((entry) => !shouldIgnoreLine(entry.line, ignoreRanges));
  const mcdcTotals = mcdcEntries.reduce(
    (acc, entry) => {
      acc.covered += entry.covered;
      acc.total += entry.total;
      return acc;
    },
    { covered: 0, total: 0 },
  );

  if ((file.mcdc?.length ?? 0) === 0) {
    warnings.add(`MC/DC kapsam verisi eksik: ${file.path}`);
  }

  if ((file.functions?.length ?? 0) === 0 || functions.length === 0) {
    warnings.add(`Fonksiyon kapsam verisi eksik: ${file.path}`);
  }

  const branchSummary = branchTotals.total > 0 ? branchTotals : undefined;
  const functionSummary = functions.length > 0 ? { covered: functionCovered, total: functions.length } : undefined;
  const mcdcSummary = mcdcTotals.total > 0 ? mcdcTotals : undefined;

  return buildFileSummary(
    file.path,
    { covered: statementCovered, total: statements.length },
    branchSummary,
    functionSummary,
    mcdcSummary,
  );
};

export const aggregateJsonCoverage = (
  payload: JsonCoveragePayload,
  options: CoverageAggregationOptions = {},
): CoverageAggregationResult => {
  const warnings = new Set<string>();
  const files = payload.files.map((file) => {
    const normalizedPath = normalizePath(file.path);
    const ignore = normalizeRanges(options.ignore?.[normalizedPath] ?? options.ignore?.[file.path]);
    return computeJsonFileCoverage({ ...file, path: normalizedPath }, ignore, warnings);
  });

  const summary: CoverageReport = {
    files,
    totals: mergeTotals(files),
  };

  if (!summary.totals.functions) {
    warnings.add('Fonksiyon kapsam verisi raporda bulunamadı.');
  }

  if (!summary.totals.mcdc) {
    warnings.add('MC/DC kapsam verisi raporda bulunamadı.');
  }

  return { summary, warnings: Array.from(warnings) };
};

const parseConditionCoverage = (value: string | undefined): { covered: number; total: number } | undefined => {
  if (!value) {
    return undefined;
  }

  const match = value.match(/\((\d+)\/(\d+)\)/);
  if (!match) {
    return undefined;
  }

  const covered = Number(match[1]);
  const total = Number(match[2]);
  if (Number.isNaN(covered) || Number.isNaN(total) || total === 0) {
    return undefined;
  }

  return { covered, total };
};

export const aggregateCoberturaCoverage = (
  xml: string,
  options: CoverageAggregationOptions = {},
): CoverageAggregationResult => {
  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: '',
    allowBooleanAttributes: true,
  });

  const document = parser.parse(xml);
  const toArray = <T>(value: MaybeArray<T> | undefined): T[] => {
    if (value === undefined) {
      return [];
    }
    return Array.isArray(value) ? value : [value];
  };

  const files: FileCoverageSummary[] = [];
  const warnings = new Set<string>();

  toArray(document.coverage?.packages?.package).forEach((pkg) => {
    toArray(pkg.classes?.class).forEach((cls) => {
      const filename = normalizePath(cls.filename);
      const ignoreRanges = normalizeRanges(options.ignore?.[filename] ?? options.ignore?.[cls.filename]);

      const lines = toArray(cls.lines?.line).map((line) => ({
        number: Number(line.number),
        hits: Number(line.hits ?? 0),
        branch: line.branch === true || line.branch === 'true',
        condition: typeof line['condition-coverage'] === 'string' ? line['condition-coverage'] : undefined,
      }));

      const filtered = lines.filter((line) => !shouldIgnoreLine(line.number, ignoreRanges));
      const statementTotal = filtered.length;
      const statementCovered = filtered.filter((line) => line.hits > 0).length;

      const methods = toArray(cls.methods?.method).map((method) => ({
        lines: toArray(method.lines?.line).map((line) => ({
          number: Number(line.number),
          hits: Number(line.hits ?? 0),
        })),
      }));

      const functionTotals = methods.reduce(
        (acc, method) => {
          const methodLines = method.lines.filter((line) => !shouldIgnoreLine(line.number, ignoreRanges));
          if (methodLines.length === 0) {
            return acc;
          }
          acc.total += 1;
          if (methodLines.some((line) => line.hits > 0)) {
            acc.covered += 1;
          }
          return acc;
        },
        { covered: 0, total: 0 },
      );

      const branchTotals = filtered
        .map((line) => (line.branch ? parseConditionCoverage(line.condition) : undefined))
        .filter((value): value is { covered: number; total: number } => value !== undefined)
        .reduce(
          (acc, entry) => {
            acc.covered += entry.covered;
            acc.total += entry.total;
            return acc;
          },
          { covered: 0, total: 0 },
        );

      if (branchTotals.total === 0) {
        warnings.add(`Karar kapsamı verisi bulunamadı: ${filename}`);
      }

      if (functionTotals.total === 0) {
        warnings.add(`Fonksiyon kapsam verisi eksik: ${filename}`);
      }

      warnings.add(`MC/DC kapsam verisi eksik: ${filename}`);

      files.push(
        buildFileSummary(
          filename,
          { covered: statementCovered, total: statementTotal },
          branchTotals.total > 0 ? branchTotals : undefined,
          functionTotals.total > 0 ? functionTotals : undefined,
          undefined,
        ),
      );
    });
  });

  const summary: CoverageReport = {
    files,
    totals: mergeTotals(files),
  };

  if (!summary.totals.functions) {
    warnings.add('Fonksiyon kapsam verisi raporda bulunamadı.');
  }

  if (!summary.totals.mcdc) {
    warnings.add('MC/DC kapsam verisi raporda bulunamadı.');
  }

  return { summary, warnings: Array.from(warnings) };
};
