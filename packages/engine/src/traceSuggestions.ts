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
    .split(/[^\p{L}0-9]+/u)
    .map((token) => token.trim())
    .filter((token) => token.length >= 3 && !stopWords.has(token));
};

const buildNormalizedText = (...values: Array<string | undefined>): string =>
  values
    .filter((value): value is string => typeof value === 'string' && value.trim().length > 0)
    .map((value) => value.toLowerCase().replace(/\s+/g, ' ').trim())
    .join(' ');

const computeTermFrequency = (tokens: string[]): Map<string, number> => {
  const frequencies = new Map<string, number>();
  tokens.forEach((token) => {
    frequencies.set(token, (frequencies.get(token) ?? 0) + 1);
  });
  return frequencies;
};

const computeInverseDocumentFrequency = (documents: Map<string, string[]>): Map<string, number> => {
  const totals = documents.size;
  const documentFrequency = new Map<string, number>();
  documents.forEach((tokens) => {
    const seen = new Set(tokens);
    seen.forEach((token) => {
      documentFrequency.set(token, (documentFrequency.get(token) ?? 0) + 1);
    });
  });

  const idf = new Map<string, number>();
  documentFrequency.forEach((count, token) => {
    const weight = Math.log((totals + 1) / (count + 1)) + 1;
    idf.set(token, weight);
  });
  return idf;
};

const buildTfIdfVector = (
  termFrequency: Map<string, number>,
  idf: Map<string, number>,
): Map<string, number> => {
  if (termFrequency.size === 0) {
    return new Map();
  }

  const totalTerms = Array.from(termFrequency.values()).reduce((acc, value) => acc + value, 0);
  const vector = new Map<string, number>();
  let total = 0;
  termFrequency.forEach((count, token) => {
    const tf = totalTerms > 0 ? count / totalTerms : 0;
    const weight = tf * (idf.get(token) ?? 0);
    vector.set(token, weight);
    total += weight * weight;
  });

  const magnitude = Math.sqrt(total);
  if (magnitude === 0) {
    return vector;
  }

  const normalized = new Map<string, number>();
  vector.forEach((weight, token) => {
    normalized.set(token, weight / magnitude);
  });
  return normalized;
};

const cosineSimilarity = (a: Map<string, number>, b: Map<string, number>): number => {
  if (a.size === 0 || b.size === 0) {
    return 0;
  }

  const [shorter, longer] = a.size <= b.size ? [a, b] : [b, a];
  let dot = 0;
  shorter.forEach((weight, token) => {
    const other = longer.get(token);
    if (other) {
      dot += weight * other;
    }
  });
  return Number.isFinite(dot) ? dot : 0;
};

const levenshteinDistance = (a: string, b: string): number => {
  if (a === b) {
    return 0;
  }
  if (a.length === 0) {
    return b.length;
  }
  if (b.length === 0) {
    return a.length;
  }

  const rows = Array.from({ length: a.length + 1 }, () => new Array<number>(b.length + 1));
  for (let i = 0; i <= a.length; i += 1) {
    rows[i][0] = i;
  }
  for (let j = 0; j <= b.length; j += 1) {
    rows[0][j] = j;
  }

  for (let i = 1; i <= a.length; i += 1) {
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      rows[i][j] = Math.min(
        rows[i - 1][j] + 1,
        rows[i][j - 1] + 1,
        rows[i - 1][j - 1] + cost,
      );
    }
  }

  return rows[a.length][b.length];
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

interface RequirementEmbedding {
  tokens: string[];
  keywords: Set<string>;
  termFrequency: Map<string, number>;
  vector: Map<string, number>;
  normalizedText: string;
}

interface TestEmbedding {
  tokens: string[];
  keywords: Set<string>;
  termFrequency: Map<string, number>;
  vector: Map<string, number>;
  normalizedText: string;
}

const evaluateTestCandidate = (
  requirement: Requirement,
  test: TestResult,
  requirementEmbedding: RequirementEmbedding,
  testEmbedding: TestEmbedding,
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

  const cosine = cosineSimilarity(requirementEmbedding.vector, testEmbedding.vector);
  const commonKeywords = intersectKeywords(requirementEmbedding.keywords, testEmbedding.keywords);
  if (cosine >= 0.6) {
    const reasonKeywords = commonKeywords.slice(0, 3).join(', ');
    const suffix = reasonKeywords ? `; ortak terimler (${reasonKeywords})` : '';
    return {
      confidence: 'high',
      reason: `Gereksinim ve test TF-IDF benzerliği ${(cosine * 100).toFixed(0)}%${suffix}.`,
    };
  }
  if (cosine >= 0.4) {
    const reasonKeywords = commonKeywords.slice(0, 3).join(', ');
    const suffix = reasonKeywords ? `; ortak terimler (${reasonKeywords})` : '';
    return {
      confidence: 'medium',
      reason: `TF-IDF benzerliği ${(cosine * 100).toFixed(0)}% olarak hesaplandı${suffix}.`,
    };
  }
  if (cosine >= 0.2) {
    const reasonKeywords = commonKeywords.slice(0, 2).join(', ');
    const suffix = reasonKeywords ? `; anahtar kelimeler (${reasonKeywords})` : '';
    return {
      confidence: 'low',
      reason: `TF-IDF benzerliği ${(cosine * 100).toFixed(0)}% seviyesinde${suffix}.`,
    };
  }

  if (commonKeywords.length > 0) {
    const display = commonKeywords.slice(0, 3).join(', ');
    return {
      confidence: 'medium',
      reason: `TF-IDF benzerliği ${(cosine * 100).toFixed(0)}% ve ortak anahtar kelimeler (${display}).`,
    };
  }

  const requirementText = requirementEmbedding.normalizedText;
  const testText = testEmbedding.normalizedText;
  if (!requirementText || !testText) {
    return null;
  }

  const distance = levenshteinDistance(requirementText, testText);
  const maxLength = Math.max(requirementText.length, testText.length, 1);
  const similarity = 1 - distance / maxLength;

  if (similarity >= 0.5) {
    return {
      confidence: 'medium',
      reason: `Levenshtein benzerliği ${(similarity * 100).toFixed(0)}% (mesafe ${distance}).`,
    };
  }
  if (similarity >= 0.3) {
    return {
      confidence: 'low',
      reason: `Levenshtein benzerliği ${(similarity * 100).toFixed(0)}% (mesafe ${distance}).`,
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

  const requirementDocuments = new Map<string, RequirementEmbedding>();
  const testDocuments = new Map<string, TestEmbedding>();
  const corpus = new Map<string, string[]>();

  traces.forEach((trace) => {
    const tokens = [
      ...tokenize(trace.requirement.title),
      ...tokenize(trace.requirement.description),
    ];
    const termFrequency = computeTermFrequency(tokens);
    const normalizedText = buildNormalizedText(trace.requirement.title, trace.requirement.description);
    requirementDocuments.set(trace.requirement.id, {
      tokens,
      keywords: new Set(tokens),
      termFrequency,
      vector: new Map(),
      normalizedText,
    });
    corpus.set(`req:${trace.requirement.id}`, tokens);
  });

  tests.forEach((test) => {
    const tokens = [
      ...tokenize(test.name),
      ...tokenize(test.className),
      ...tokenize(test.testId),
    ];
    const termFrequency = computeTermFrequency(tokens);
    const normalizedText = buildNormalizedText(test.name, test.className, test.testId);
    testDocuments.set(test.testId, {
      tokens,
      keywords: new Set(tokens),
      termFrequency,
      vector: new Map(),
      normalizedText,
    });
    corpus.set(`test:${test.testId}`, tokens);
  });

  const idf = computeInverseDocumentFrequency(corpus);
  requirementDocuments.forEach((embedding, id) => {
    requirementDocuments.set(id, {
      ...embedding,
      vector: buildTfIdfVector(embedding.termFrequency, idf),
    });
  });
  testDocuments.forEach((embedding, id) => {
    testDocuments.set(id, {
      ...embedding,
      vector: buildTfIdfVector(embedding.termFrequency, idf),
    });
  });

  const suggestions: TraceSuggestion[] = [];
  const seen = new Set<string>();

  traces.forEach((trace) => {
    const existingTestIds = new Set(trace.tests.map((test) => test.testId));
    const existingCodePaths = new Set(trace.code.map((code) => code.path));
    const requirementEmbedding = requirementDocuments.get(trace.requirement.id);
    if (!requirementEmbedding) {
      return;
    }

    const suggestedTests = new Map<string, TraceSuggestionConfidence>();

    tests.forEach((test) => {
      if (existingTestIds.has(test.testId)) {
        return;
      }
      const testEmbedding = testDocuments.get(test.testId);
      if (!testEmbedding) {
        return;
      }
      const evaluation = evaluateTestCandidate(trace.requirement, test, requirementEmbedding, testEmbedding);
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
