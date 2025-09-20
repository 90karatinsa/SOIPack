export type CoverageStatus = 'covered' | 'partial' | 'missing';

export type PipelineLogSeverity = 'info' | 'success' | 'warning' | 'error';

export interface PipelineLogEntry {
  id: string;
  timestamp: string;
  severity: PipelineLogSeverity;
  message: string;
}

export type JobKind = 'import' | 'analyze' | 'report' | 'pack';

export type JobStatus = 'queued' | 'running' | 'completed' | 'failed';

export interface ApiJobError {
  statusCode: number;
  code: string;
  message: string;
  details?: unknown;
}

export interface ApiJob<T = unknown> {
  id: string;
  kind: JobKind;
  hash: string;
  status: JobStatus;
  createdAt: string;
  updatedAt: string;
  result?: T;
  error?: ApiJobError;
  reused?: boolean;
}

export interface ImportJobResult {
  warnings: string[];
  outputs: {
    directory: string;
    workspace: string;
  };
}

export interface AnalyzeJobResult {
  exitCode: number;
  outputs: {
    directory: string;
    snapshot: string;
    traces: string;
    analysis: string;
  };
}

export interface ReportJobResult {
  outputs: {
    directory: string;
    complianceHtml: string;
    complianceJson: string;
    traceHtml: string;
    gapsHtml: string;
    analysis: string;
    snapshot: string;
    traces: string;
  };
}

export interface PackJobResult {
  manifestId: string;
  outputs: {
    directory: string;
    manifest: string;
    archive: string;
  };
}

export interface ComplianceRequirementCoverage {
  requirementId: string;
  title?: string;
  status: CoverageStatus;
  coverage?: {
    statements?: CoverageMetric;
    branches?: CoverageMetric;
    functions?: CoverageMetric;
  };
  codePaths?: string[];
}

export interface CoverageMetric {
  covered: number;
  total: number;
  percentage: number;
}

export interface ComplianceStatisticsPayload {
  objectives: {
    total: number;
    covered: number;
    partial: number;
    missing: number;
  };
  requirements: {
    total: number;
  };
  tests: {
    total: number;
    passed: number;
    failed: number;
    skipped: number;
  };
  codePaths: {
    total: number;
  };
}

export interface ComplianceMatrixPayload {
  manifestId?: string;
  generatedAt: string;
  version: string;
  stats: ComplianceStatisticsPayload;
  objectives: unknown[];
  requirementCoverage: ComplianceRequirementCoverage[];
}

export type TestRunStatus = 'pending' | 'passed' | 'failed' | 'skipped';

export interface RequirementTraceTest {
  testId: string;
  name: string;
  status: TestRunStatus;
}

export interface CodePathEntry {
  path: string;
  coverage?: {
    statements?: CoverageMetric;
    branches?: CoverageMetric;
    functions?: CoverageMetric;
  };
}

export interface RequirementTracePayload {
  requirement: {
    id: string;
    title: string;
    description?: string;
    status?: string;
    tags?: string[];
  };
  tests: RequirementTraceTest[];
  code: CodePathEntry[];
}

export interface RequirementViewModel {
  id: string;
  title: string;
  description?: string;
  requirementStatus?: string;
  tags: string[];
  coverageStatus: CoverageStatus;
  coveragePercent?: number;
  coverageLabel?: string;
  code: Array<{
    path: string;
    coveragePercent?: number;
    coverageLabel?: string;
  }>;
  tests: Array<{
    id: string;
    name: string;
    status: CoverageStatus;
    result: TestRunStatus;
  }>;
}

export interface ReportDataset {
  reportId: string;
  generatedAt: string;
  version: string;
  requirements: RequirementViewModel[];
  summary: {
    total: number;
    covered: number;
    partial: number;
    missing: number;
  };
}

export interface ReportAssetMap {
  reportId: string;
  assets: {
    complianceHtml: string;
    complianceJson: string;
    traceHtml: string;
    gapsHtml: string;
    analysis: string;
    snapshot: string;
    traces: string;
  };
}
