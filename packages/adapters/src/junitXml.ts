import { promises as fs } from 'fs';
import path from 'path';

import { ParseResult, TestResult, TestStatus } from './types';
import { parseXml } from './utils/xml';

type UnknownRecord = Record<string, unknown>;

const toArray = <T>(value: T | T[] | undefined): T[] => {
  if (value === undefined) {
    return [];
  }
  return Array.isArray(value) ? value : [value];
};

const flatten = (value: unknown): string => {
  if (value === null || value === undefined) {
    return '';
  }
  if (typeof value === 'string') {
    return value;
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => flatten(item)).join('\n');
  }
  if (typeof value === 'object') {
    return Object.values(value as UnknownRecord)
      .map((entry) => flatten(entry))
      .join('\n');
  }
  return '';
};

const composeMessage = (entry: UnknownRecord): string => {
  const { message: attributeMessageRaw, ...rest } = entry;
  const attributeMessage = typeof attributeMessageRaw === 'string' ? attributeMessageRaw : undefined;
  const textContent = flatten(rest).trim();
  const parts = [attributeMessage, textContent.length > 0 ? textContent : undefined]
    .filter((value): value is string => Boolean(value))
    .map((value) => value.trim());
  const uniqueParts = parts.filter((part, index) => parts.indexOf(part) === index);
  return uniqueParts.join('\n');
};

const detectStatus = (testcase: UnknownRecord): { status: TestStatus; message?: string } => {
  if (testcase.skipped !== undefined) {
    return { status: 'skipped' };
  }
  const failure = (testcase.failure as UnknownRecord | UnknownRecord[] | undefined) ?? undefined;
  const error = (testcase.error as UnknownRecord | UnknownRecord[] | undefined) ?? undefined;
  if (failure !== undefined) {
    const failures = toArray(failure);
    const message = failures
      .map((entry) => composeMessage(entry as UnknownRecord))
      .filter((value) => value.trim().length > 0)
      .join('\n');
    return { status: 'failed', message: message || undefined };
  }
  if (error !== undefined) {
    const errors = toArray(error);
    const message = errors
      .map((entry) => composeMessage(entry as UnknownRecord))
      .filter((value) => value.trim().length > 0)
      .join('\n');
    return { status: 'failed', message: message || undefined };
  }
  return { status: 'passed' };
};

const extractRequirements = (testcase: UnknownRecord): string[] | undefined => {
  const properties = (testcase.properties as UnknownRecord | undefined)?.property;
  const entries = toArray(properties as UnknownRecord | UnknownRecord[] | undefined);
  const requirementTokens: string[] = [];

  entries.forEach((property) => {
    const name = (property?.name as string | undefined)?.toLowerCase();
    if (name && ['requirements', 'requirement', 'requirementids'].includes(name)) {
      const value = flatten(property?.value ?? property?.['#text']);
      requirementTokens.push(...value.split(/[,;\s]+/));
    }
  });

  const cleaned = requirementTokens
    .map((token) => token.trim())
    .filter((token) => token.length > 0);

  return cleaned.length > 0 ? cleaned : undefined;
};

export const importJUnitXml = async (filePath: string): Promise<ParseResult<TestResult[]>> => {
  const warnings: string[] = [];
  const location = path.resolve(filePath);
  const content = await fs.readFile(location, 'utf8');

  let raw: UnknownRecord;
  try {
    raw = parseXml<UnknownRecord>(content);
  } catch (error) {
    warnings.push(`Failed to parse JUnit XML at ${location}: ${(error as Error).message}`);
    return { data: [], warnings };
  }

  const suites = toArray<UnknownRecord>(
    (raw.testsuites as UnknownRecord | UnknownRecord[] | undefined) ?? (raw.testsuite as UnknownRecord | UnknownRecord[] | undefined),
  );
  if (suites.length === 0) {
    warnings.push(`No <testsuite> elements found in ${location}.`);
    return { data: [], warnings };
  }

  const results: TestResult[] = [];

  suites.forEach((suite) => {
    const testcases = toArray<UnknownRecord>((suite.testcase as UnknownRecord | UnknownRecord[] | undefined) ?? []);
    if (testcases.length === 0) {
      warnings.push(`Test suite ${suite.name ?? 'unknown'} does not contain any <testcase> elements.`);
    }
    testcases.forEach((testcase, index) => {
      const name = (testcase.name as string | undefined) ?? `case-${index + 1}`;
      const className = (testcase.classname as string | undefined) ?? (suite.name as string | undefined) ?? 'unknown';
      const testId = (testcase.id as string | undefined) ?? `${className}#${name}`;
      const duration = Number.parseFloat(String(testcase.time ?? '0'));
      if (Number.isNaN(duration)) {
        warnings.push(`Testcase ${testId} has an invalid duration value.`);
      }
      const { status, message } = detectStatus(testcase as UnknownRecord);
      const requirementRefs = extractRequirements(testcase as UnknownRecord);
      results.push({
        testId,
        className,
        name,
        status,
        duration: Number.isFinite(duration) ? duration : 0,
        errorMessage: message,
        requirementsRefs: requirementRefs,
      });
    });
  });

  return { data: results, warnings };
};
