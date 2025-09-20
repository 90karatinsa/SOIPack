import { Requirement, TestCase } from '@soipack/core';

export interface TraceLink {
  source: Requirement;
  target: TestCase;
  confidence: number;
}

export interface TraceMatrix {
  requirementId: string;
  testCaseIds: string[];
}

export const createTraceLink = (
  source: Requirement,
  target: TestCase,
  confidence: number,
): TraceLink => {
  if (confidence < 0 || confidence > 1) {
    throw new Error('Confidence must be within 0 and 1.');
  }

  return {
    source,
    target,
    confidence: Number(confidence.toFixed(2)),
  };
};

export const buildTraceMatrix = (links: TraceLink[]): TraceMatrix[] => {
  const grouped = new Map<string, string[]>();

  links.forEach((link) => {
    const existing = grouped.get(link.source.id) ?? [];
    grouped.set(link.source.id, Array.from(new Set([...existing, link.target.id])));
  });

  return Array.from(grouped.entries()).map(([requirementId, testCaseIds]) => ({
    requirementId,
    testCaseIds,
  }));
};
