export interface ParseResult<T> {
  data: T;
  warnings: string[];
}

export interface JiraRequirement {
  id: string;
  summary: string;
  status: string;
  priority?: string;
  description?: string;
  components?: string[];
  labels?: string[];
  epicLink?: string;
  links: string[];
  attachments?: string[];
  parentId?: string;
  children?: string[];
  customFields?: Record<string, string | string[] | undefined>;
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
  testMap?: Record<string, string[]>;
}

export interface BuildInfo {
  hash: string;
  author: string;
  date: string;
  message: string;
}
