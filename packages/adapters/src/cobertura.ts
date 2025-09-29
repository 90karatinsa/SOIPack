import { createReadStream } from 'fs';
import path from 'path';

import { SaxesParser, SaxesTagPlain } from 'saxes';

import { CoverageMetric, CoverageReport, FileCoverageSummary, ParseResult } from './types';

type UnknownRecord = Record<string, unknown>;

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

const REPORT_SIZE_WARNING_BYTES = 5 * 1024 * 1024; // 5 MiB
const TEST_TAGS = new Set(['tests', 'test', 'covered-by', 'coveredby', 'test-name']);

export const importCobertura = async (filePath: string): Promise<ParseResult<CoverageReport>> => {
  const warnings: string[] = [];
  const location = path.resolve(filePath);
  const files: FileCoverageSummary[] = [];
  const testFiles = new Map<string, Set<string>>();

  interface ClassAccumulator {
    file: string;
    statementsCovered: number;
    statementsTotal: number;
    branchCovered: number;
    branchTotal: number;
    functionsCovered: number;
    functionsTotal: number;
  }

  interface LineContext {
    file: string;
    tests: Set<string>;
    tagStack: string[];
  }

  let currentClass: ClassAccumulator | undefined;
  let currentLine: LineContext | undefined;
  let sawClass = false;
  let totalBytes = 0;
  let sizeWarningIssued = false;
  const elementStack: string[] = [];

  const finalizeCurrentClass = () => {
    if (!currentClass) {
      return;
    }
    const {
      file,
      statementsCovered,
      statementsTotal,
      branchCovered,
      branchTotal,
      functionsCovered,
      functionsTotal,
    } = currentClass;

    files.push({
      file,
      statements: {
        covered: statementsCovered,
        total: statementsTotal,
        percentage: statementsTotal > 0 ? Number(((statementsCovered / statementsTotal) * 100).toFixed(2)) : 0,
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

    currentClass = undefined;
  };

  const registerLineTests = (line: LineContext | undefined) => {
    if (!line) {
      return;
    }
    line.tests.forEach((testName) => registerTestFile(testFiles, testName, line.file));
  };

  const parser = new SaxesParser({ xmlns: false });
  parser.on('error', (error: unknown) => {
    warnings.push(`Malformed Cobertura XML at ${location}: ${(error as Error).message}`);
  });

  parser.on('opentag', (tag: SaxesTagPlain) => {
    const name = tag.name.toLowerCase();
    elementStack.push(name);

    if (name === 'class') {
      sawClass = true;
      const attributes = tag.attributes;
      const fileName =
        (typeof attributes.filename === 'string' && attributes.filename) ||
        (typeof attributes.name === 'string' && attributes.name) ||
        'unknown';
      currentClass = {
        file: fileName,
        statementsCovered: 0,
        statementsTotal: 0,
        branchCovered: 0,
        branchTotal: 0,
        functionsCovered: 0,
        functionsTotal: 0,
      };
      return;
    }

    if (!currentClass) {
      return;
    }

    if (name === 'method') {
      const hits = asNumber((tag.attributes as Record<string, unknown>).hits);
      currentClass.functionsTotal += 1;
      if (hits > 0) {
        currentClass.functionsCovered += 1;
      }
      return;
    }

    if (name === 'line') {
      const parent = elementStack[elementStack.length - 2];
      const insideMethod = elementStack.slice(0, -1).includes('method');
      if (insideMethod || parent !== 'lines') {
        currentLine = undefined;
        return;
      }

      const attributes = tag.attributes as Record<string, unknown>;
      const hits = asNumber(attributes.hits);
      currentClass.statementsTotal += 1;
      if (hits > 0) {
        currentClass.statementsCovered += 1;
      }

      const lineTests = new Set<string>();
      const testAttributes = [
        attributes.tests,
        attributes.test,
        attributes['covered-by'],
        attributes.coveredby,
        attributes['test-name'],
      ];
      testAttributes.forEach((attribute) => {
        toTestNames(attribute).forEach((testName) => lineTests.add(testName));
      });

      const branchAttribute = attributes.branch;
      const hasBranchFlag =
        (typeof branchAttribute === 'string' && branchAttribute.toLowerCase() === 'true') ||
        (typeof branchAttribute === 'boolean' && branchAttribute);
      const conditionCoverage = attributes['condition-coverage'];
      if (hasBranchFlag || conditionCoverage !== undefined) {
        const { covered, total } = parseConditionCoverage(conditionCoverage);
        if (total > 0) {
          currentClass.branchTotal += total;
          currentClass.branchCovered += covered;
        } else {
          currentClass.branchTotal += 1;
          if (hits > 0) {
            currentClass.branchCovered += 1;
          }
        }
      }

      currentLine = { file: currentClass.file, tests: lineTests, tagStack: [] };
      return;
    }

    if (currentLine) {
      currentLine.tagStack.push(name);
      if (TEST_TAGS.has(name)) {
        const attributes = tag.attributes as Record<string, unknown>;
        const attributeCandidates = [attributes.name, attributes.value, attributes['test-name']];
        attributeCandidates.forEach((candidate) => {
          toTestNames(candidate).forEach((testName) => currentLine!.tests.add(testName));
        });
      }
    }
  });

  parser.on('text', (text: string) => {
    const lineContext = currentLine;
    if (!lineContext || text.trim().length === 0) {
      return;
    }
    const currentTag = lineContext.tagStack[lineContext.tagStack.length - 1];
    if (currentTag && TEST_TAGS.has(currentTag)) {
      toTestNames(text).forEach((testName) => lineContext.tests.add(testName));
    }
  });

  parser.on('closetag', (tag: unknown) => {
    const rawTag = tag as { name?: string };
    const name = typeof rawTag === 'object' && rawTag?.name ? String(rawTag.name).toLowerCase() : String(tag).toLowerCase();
    const last = elementStack.pop();
    if (last !== name) {
      // Maintain stack integrity even when malformed closing tags appear.
      const mismatchIndex = elementStack.lastIndexOf(name);
      if (mismatchIndex >= 0) {
        elementStack.splice(mismatchIndex, 1);
      }
    }

    if (name === 'line') {
      if (currentClass) {
        registerLineTests(currentLine);
      }
      currentLine = undefined;
      return;
    }

    if (!currentClass) {
      return;
    }

    if (name === 'class') {
      finalizeCurrentClass();
      return;
    }

    if (currentLine) {
      currentLine.tagStack.pop();
    }
  });

  try {
    await new Promise<void>((resolve, reject) => {
      const stream = createReadStream(location, { encoding: 'utf8' });
      stream.setEncoding('utf8');

      stream.on('error', (error) => {
        reject(error);
      });

      stream.on('data', (chunk) => {
        const textChunk = typeof chunk === 'string' ? chunk : chunk.toString('utf8');
        totalBytes += Buffer.byteLength(textChunk, 'utf8');
        if (!sizeWarningIssued && totalBytes > REPORT_SIZE_WARNING_BYTES) {
          warnings.push(
            `Cobertura report at ${location} exceeded ${REPORT_SIZE_WARNING_BYTES} bytes; continuing with streaming parser.`,
          );
          sizeWarningIssued = true;
        }
        parser.write(textChunk);
      });

      stream.on('end', () => {
        parser.close();
      });

      parser.on('end', () => {
        resolve();
      });
    });
  } catch (error) {
    warnings.push(`Failed to read Cobertura XML at ${location}: ${(error as Error).message}`);
    return {
      data: {
        totals: { statements: { covered: 0, total: 0, percentage: 0 } },
        files: [],
      },
      warnings,
    };
  }

  finalizeCurrentClass();

  if (!sawClass) {
    warnings.push(`No <class> entries found in Cobertura file at ${location}.`);
  }

  const totals = files.reduce<CoverageReport['totals']>((acc, file) => {
    acc.statements = addMetric(acc.statements, { ...file.statements });
    if (file.branches) {
      acc.branches = addMetric(acc.branches, { ...file.branches });
    }
    if (file.functions) {
      acc.functions = addMetric(acc.functions, { ...file.functions });
    }
    if (file.mcdc) {
      acc.mcdc = addMetric(acc.mcdc, { ...file.mcdc });
    }
    return acc;
  }, {
    statements: { covered: 0, total: 0, percentage: 0 },
  } as CoverageReport['totals']);

  const finalizedTotals: CoverageReport['totals'] = {
    statements: finalizeMetric(totals.statements)!,
    branches: finalizeMetric(totals.branches),
    functions: finalizeMetric(totals.functions),
    mcdc: finalizeMetric(totals.mcdc),
  };
  const testMapEntries = Array.from(testFiles.entries()).map(([test, filesForTest]) => [test, Array.from(filesForTest)]);
  const testMap = testMapEntries.length > 0 ? Object.fromEntries(testMapEntries) : undefined;

  return { data: { totals: finalizedTotals, files, testMap }, warnings };
};
