import { createReadStream } from 'fs';
import path from 'path';

import { SaxesParser, SaxesTagPlain } from 'saxes';

import { ParseResult, TestResult, TestStatus } from '../types';

interface SuiteContext {
  name?: string;
}

interface ActiveSection {
  type: 'failure' | 'error' | 'skipped';
  messageAttr?: string;
  text: string[];
}

interface ActiveProperty {
  name?: string;
  valueAttr?: string;
  buffer: string[];
}

interface TestcaseState {
  testId: string;
  className: string;
  name: string;
  duration: number;
  status: TestStatus;
  messageParts: string[];
  requirementIds: Set<string>;
  activeSection?: ActiveSection;
  activeProperty?: ActiveProperty;
}

const normalize = (value: unknown): string | undefined => {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value === 'string') {
    return value;
  }
  return String(value);
};

const tokenizeRequirements = (input: string): string[] =>
  input
    .split(/[,;\s]+/u)
    .map((token) => token.trim())
    .filter((token) => token.length > 0);

const resolveTagName = (tag: unknown): string => {
  if (typeof tag === 'string') {
    return tag;
  }
  if (tag && typeof (tag as SaxesTagPlain).name === 'string') {
    return (tag as SaxesTagPlain).name;
  }
  return '';
};

const finalizeSection = (section: ActiveSection): string | undefined => {
  const parts = [] as string[];
  if (section.messageAttr) {
    parts.push(section.messageAttr.trim());
  }
  const text = section.text.join('').trim();
  if (text.length > 0) {
    parts.push(text);
  }
  const unique = parts.filter((item, index, array) => array.indexOf(item) === index);
  return unique.length > 0 ? unique.join('\n') : undefined;
};

export const parseJUnitStream = async (filePath: string): Promise<ParseResult<TestResult[]>> =>
  new Promise((resolve, reject) => {
    const location = path.resolve(filePath);
    const warnings: string[] = [];
    const results: TestResult[] = [];
    const stream = createReadStream(location, { encoding: 'utf8' });
    const parser = new SaxesParser({ xmlns: false });
    const suites: SuiteContext[] = [];
    let currentTest: TestcaseState | undefined;
    let caseCounter = 0;
    let encounteredTestcase = false;
    let settled = false;

    const finalizeCurrentTest = () => {
      if (!currentTest) {
        return;
      }
      if (currentTest.activeSection) {
        const message = finalizeSection(currentTest.activeSection);
        if (message) {
          currentTest.messageParts.push(message);
        }
      }
      if (currentTest.activeProperty) {
        const { name, valueAttr, buffer } = currentTest.activeProperty;
        if (name && ['requirements', 'requirement', 'requirementids'].includes(name)) {
          tokenizeRequirements((valueAttr ?? buffer.join('')).trim()).forEach((token) =>
            currentTest?.requirementIds.add(token),
          );
        }
      }

      const uniqueMessages = currentTest.messageParts.filter(
        (message, index, array) => array.indexOf(message) === index,
      );
      const requirements = Array.from(currentTest.requirementIds);

      results.push({
        testId: currentTest.testId,
        className: currentTest.className,
        name: currentTest.name,
        status: currentTest.status,
        duration: currentTest.duration,
        errorMessage: uniqueMessages.length > 0 ? uniqueMessages.join('\n') : undefined,
        requirementsRefs: requirements.length > 0 ? requirements : undefined,
      });

      currentTest = undefined;
    };

    parser.on('error', (error) => {
      if (settled) {
        return;
      }
      settled = true;
      parser.close();
      stream.destroy(error as Error);
      reject(new Error(`Invalid JUnit XML at ${location}: ${(error as Error).message}`));
    });

    parser.on('opentag', (tag: SaxesTagPlain) => {
      const name = tag.name.toLowerCase();
      const attrs = tag.attributes as Record<string, unknown>;
      if (name === 'testsuite') {
        suites.push({ name: normalize(attrs.name) ?? normalize(attrs.id) });
        return;
      }

      if (name === 'testcase') {
        encounteredTestcase = true;
        caseCounter += 1;
        const suite = suites[suites.length - 1];
        const testName = normalize(attrs.name) ?? `case-${caseCounter}`;
        const className = normalize(attrs.classname) ?? suite?.name ?? 'unknown';
        const testId = normalize(attrs.id) ?? `${className}#${testName}`;
        const durationRaw = normalize(attrs.time);
        const duration = durationRaw !== undefined ? Number.parseFloat(durationRaw) : 0;
        if (!Number.isFinite(duration)) {
          warnings.push(`Testcase ${testId} has an invalid duration value.`);
        }

        currentTest = {
          testId,
          className,
          name: testName,
          duration: Number.isFinite(duration) ? duration : 0,
          status: 'passed',
          messageParts: [],
          requirementIds: new Set<string>(),
        };
        return;
      }

      if (!currentTest) {
        return;
      }

      if (name === 'failure' || name === 'error') {
        currentTest.status = 'failed';
        currentTest.activeSection = {
          type: name,
          messageAttr: normalize(attrs.message),
          text: [],
        };
        return;
      }

      if (name === 'skipped') {
        currentTest.status = 'skipped';
        currentTest.activeSection = {
          type: 'skipped',
          messageAttr: normalize(attrs.message),
          text: [],
        };
        return;
      }

      if (name === 'property') {
        currentTest.activeProperty = {
          name: normalize(attrs.name)?.toLowerCase(),
          valueAttr: normalize(attrs.value),
          buffer: [],
        };
      }
    });

    parser.on('text', (text) => {
      if (!currentTest) {
        return;
      }
      if (currentTest.activeSection) {
        currentTest.activeSection.text.push(text);
        return;
      }
      if (currentTest.activeProperty) {
        currentTest.activeProperty.buffer.push(text);
      }
    });

    parser.on('closetag', (tag) => {
      const rawName = resolveTagName(tag);
      if (!rawName) {
        return;
      }
      const name = rawName.toLowerCase();
      if (name === 'testsuite') {
        suites.pop();
        return;
      }

      if (!currentTest) {
        return;
      }

      if (name === 'failure' || name === 'error' || name === 'skipped') {
        if (currentTest.activeSection) {
          const message = finalizeSection(currentTest.activeSection);
          if (message) {
            currentTest.messageParts.push(message);
          }
          currentTest.activeSection = undefined;
        }
        return;
      }

      if (name === 'property') {
        const property = currentTest.activeProperty;
        if (property) {
          const value = property.valueAttr ?? property.buffer.join('');
          if (property.name && ['requirements', 'requirement', 'requirementids'].includes(property.name)) {
            tokenizeRequirements(value).forEach((token) => currentTest?.requirementIds.add(token));
          }
        }
        currentTest.activeProperty = undefined;
        return;
      }

      if (name === 'testcase') {
        finalizeCurrentTest();
      }
    });

    parser.on('end', () => {
      if (settled) {
        return;
      }
      if (currentTest) {
        finalizeCurrentTest();
      }
      if (!encounteredTestcase) {
        warnings.push(`No <testcase> elements found in ${location}.`);
      }
      settled = true;
      resolve({ data: results, warnings });
    });

    stream.on('error', (error) => {
      if (settled) {
        return;
      }
      settled = true;
      reject(new Error(`Unable to read ${location}: ${(error as Error).message}`));
    });
    stream.on('data', (chunk) => {
      try {
        parser.write(typeof chunk === 'string' ? chunk : chunk.toString());
      } catch (error) {
        if (settled) {
          return;
        }
        settled = true;
        parser.close();
        stream.destroy(error as Error);
        reject(new Error(`Invalid JUnit XML at ${location}: ${(error as Error).message}`));
      }
    });
    stream.on('end', () => {
      parser.close();
    });
  });
