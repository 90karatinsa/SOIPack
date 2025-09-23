import type { TestResult } from '@soipack/adapters';
import type { Requirement } from '@soipack/core';

import type { RequirementTrace } from './index';

export type TraceSuggestionType = 'test' | 'code';
export type TraceSuggestionConfidence = 'low' | 'medium' | 'high';

export interface TraceSuggestion {
  requirementId: string;
  type: TraceSuggestionType;
  targetId: string;
  targetName?: string;
  confidence: TraceSuggestionConfidence;
  reason: string;
  viaTestId?: string;
}

const stopWords = new Set([
  'the',
  'and',
  'shall',
  'will',
  'must',
  'should',
  'system',
  'test',
  'tests',
  'case',
  'cases',
  'function',
  'software',
  'data',
  'code',
  'input',
  'output',
  'user',
  'with',
  'from',
  'when',
  'that',
  'this',
]);

const normalizeIdentifier = (value: string | undefined): string => {
  if (!value) {
    return '';
  }
  return value.replace(/[^a-z0-9]/gi, '').toLowerCase();
};

const tokenize = (value: string | undefined): string[] => {
  if (!value) {
    return [];
  }
  return value
    .toLowerCase()
    .split(/[^a-z0-9]+/u)
    .map((token) => token.trim())
    .filter((token) => token.length >= 4 && !stopWords.has(token));
};

const intersectKeywords = (a: Set<string>, b: Set<string>): string[] => {
  const matches: string[] = [];
  a.forEach((token) => {
    if (b.has(token)) {
      matches.push(token);
    }
  });
  return matches;
};

const degradeConfidence = (confidence: TraceSuggestionConfidence): TraceSuggestionConfidence => {
  if (confidence === 'high') {
    return 'medium';
  }
  if (confidence === 'medium') {
    return 'low';
  }
  return 'low';
};

interface TestSuggestion {
  confidence: TraceSuggestionConfidence;
  reason: string;
}

const evaluateTestCandidate = (
  requirement: Requirement,
  test: TestResult,
  requirementKeywords: Set<string>,
): TestSuggestion | null => {
  const requirementIdKey = normalizeIdentifier(requirement.id);
  const testIdKey = normalizeIdentifier(test.testId);
  const testNameKey = normalizeIdentifier(test.name);
  const testClassKey = normalizeIdentifier(test.className);

  if (
    requirementIdKey &&
    (testIdKey.includes(requirementIdKey) ||
      (testNameKey && testNameKey.includes(requirementIdKey)) ||
      (testClassKey && testClassKey.includes(requirementIdKey)))
  ) {
    return {
      confidence: 'high',
      reason: `Test ${test.testId} gereksinim kimliğini içeriyor (${requirement.id}).`,
    };
  }

  const testKeywords = new Set<string>([
    ...tokenize(test.name),
    ...tokenize(test.className),
  ]);
  const matches = intersectKeywords(requirementKeywords, testKeywords);
  if (matches.length >= 2) {
    const display = matches.slice(0, 3).join(', ');
    return {
      confidence: 'medium',
      reason: `Gereksinim ve test açıklamaları ortak anahtar kelimeler içeriyor (${display}).`,
    };
  }
  if (matches.length === 1) {
    return {
      confidence: 'low',
      reason: `Test ${test.testId} adı gereksinim anahtar kelimesiyle eşleşiyor (${matches[0]}).`,
    };
  }

  return null;
};

const addSuggestion = (
  suggestions: TraceSuggestion[],
  seen: Set<string>,
  suggestion: TraceSuggestion,
): void => {
  const key = `${suggestion.requirementId}|${suggestion.type}|${suggestion.targetId}`;
  if (seen.has(key)) {
    return;
  }
  seen.add(key);
  suggestions.push(suggestion);
};

export const generateTraceSuggestions = (
  traces: RequirementTrace[],
  tests: TestResult[],
  testToCodeMap: Record<string, string[]>,
): TraceSuggestion[] => {
  if (traces.length === 0 || tests.length === 0) {
    return [];
  }

  const suggestions: TraceSuggestion[] = [];
  const seen = new Set<string>();

  traces.forEach((trace) => {
    const existingTestIds = new Set(trace.tests.map((test) => test.testId));
    const existingCodePaths = new Set(trace.code.map((code) => code.path));
    const requirementKeywords = new Set<string>([
      ...tokenize(trace.requirement.title),
      ...tokenize(trace.requirement.description),
    ]);

    const suggestedTests = new Map<string, TraceSuggestionConfidence>();

    tests.forEach((test) => {
      if (existingTestIds.has(test.testId)) {
        return;
      }
      const evaluation = evaluateTestCandidate(trace.requirement, test, requirementKeywords);
      if (!evaluation) {
        return;
      }
      suggestedTests.set(test.testId, evaluation.confidence);
      addSuggestion(suggestions, seen, {
        requirementId: trace.requirement.id,
        type: 'test',
        targetId: test.testId,
        targetName: test.name ?? test.testId,
        confidence: evaluation.confidence,
        reason: evaluation.reason,
      });
    });

    const relatedTests = new Set<string>([...existingTestIds, ...suggestedTests.keys()]);
    relatedTests.forEach((testId) => {
      const coveredPaths = testToCodeMap[testId] ?? [];
      if (coveredPaths.length === 0) {
        return;
      }
      const baseConfidence = existingTestIds.has(testId)
        ? 'high'
        : degradeConfidence(suggestedTests.get(testId) ?? 'low');
      coveredPaths.forEach((codePath) => {
        if (existingCodePaths.has(codePath)) {
          return;
        }
        const isExisting = existingTestIds.has(testId);
        addSuggestion(suggestions, seen, {
          requirementId: trace.requirement.id,
          type: 'code',
          targetId: codePath,
          targetName: codePath,
          confidence: baseConfidence,
          reason: isExisting
            ? `${codePath} dosyası halihazırda izlenen ${testId} testi tarafından kapsanıyor.`
            : `${codePath} dosyası önerilen ${testId} testi tarafından kapsanıyor.`,
          viaTestId: testId,
        });
      });
    });
  });

  return suggestions.sort((a, b) => {
    if (a.requirementId !== b.requirementId) {
      return a.requirementId.localeCompare(b.requirementId);
    }
    if (a.type !== b.type) {
      return a.type.localeCompare(b.type);
    }
    return a.targetId.localeCompare(b.targetId);
  });
};
