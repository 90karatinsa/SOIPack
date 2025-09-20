export interface ParseResult<T> {
  data: T;
  warnings: string[];
}

export interface JiraRequirement {
  id: string;
  summary: string;
  status: string;
  priority?: string;
  links: string[];
}

export interface ReqIFRequirement {
  id: string;
  text: string;
}

export type TestStatus = 'passed' | 'failed' | 'skipped';

export interface TestResult {
  testId: string;
  className: string;
  name: string;
  status: TestStatus;
  duration: number;
  errorMessage?: string;
  requirementsRefs?: string[];
}

export interface CoverageMetric {
  covered: number;
  total: number;
  percentage: number;
}

export interface FileCoverageSummary {
  file: string;
  statements: CoverageMetric;
  branches?: CoverageMetric;
  functions?: CoverageMetric;
}

export interface CoverageSummary {
  totals: {
    statements: CoverageMetric;
    branches?: CoverageMetric;
    functions?: CoverageMetric;
  };
  files: FileCoverageSummary[];
}

export interface BuildInfo {
  hash: string;
  author: string;
  date: string;
  message: string;
}
