import type { ObjectiveArtifactType, TraceLinkType } from '@soipack/core';

export interface ParseResult<T> {
  data: T;
  warnings: string[];
}

export interface JiraRequirement {
  id: string;
  summary: string;
  status: string;
  issueType?: string;
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
  title: string;
  shortName?: string;
  descriptionHtml?: string;
  text?: string;
  parentId?: string;
  childrenIds: string[];
  tracesTo: string[];
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

export interface RemoteRequirementRecord {
  id: string;
  title: string;
  description?: string;
  status?: string;
  type?: string;
  url?: string;
}

export interface RemoteTraceLink {
  fromId: string;
  toId: string;
  type: TraceLinkType;
}

export interface RemoteTestRecord {
  id: string;
  name: string;
  className?: string;
  status: string;
  durationMs?: number;
  errorMessage?: string;
  requirementIds?: string[];
  startedAt?: string;
  finishedAt?: string;
}

export interface RemoteDesignRecord {
  id: string;
  title: string;
  description?: string;
  status?: string;
  type?: string;
  url?: string;
  requirementIds?: string[];
  codeRefs?: string[];
}

export interface RemoteBuildRecord {
  id: string;
  name?: string;
  url?: string;
  status?: string;
  branch?: string;
  revision?: string;
  startedAt?: string;
  completedAt?: string;
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
  mcdc?: CoverageMetric;
}

export interface CoverageReport {
  totals: {
    statements: CoverageMetric;
    branches?: CoverageMetric;
    functions?: CoverageMetric;
    mcdc?: CoverageMetric;
  };
  files: FileCoverageSummary[];
  testMap?: Record<string, string[]>;
}

export interface BuildInfo {
  hash: string;
  author: string;
  date: string;
  message: string;
  branches: string[];
  tags: string[];
  dirty: boolean;
  remoteOrigins: string[];
}

export type EvidenceKind =
  | 'plan'
  | 'standard'
  | 'review'
  | 'analysis'
  | 'test'
  | 'coverage_stmt'
  | 'coverage_dec'
  | 'coverage_mcdc'
  | 'trace'
  | 'cm_record'
  | 'qa_record'
  | 'problem_report'
  | 'conformity';

export interface Finding {
  tool: 'polyspace' | 'ldra' | 'vectorcast' | 'parasoft';
  id: string;
  file?: string;
  func?: string;
  line?: number;
  severity?: 'info' | 'warn' | 'error';
  classification?: string;
  message: string;
  status?: 'open' | 'justified' | 'closed' | 'proved' | 'unproved';
  objectiveLinks?: string[];
}

export interface CoverageSummary {
  tool: 'vectorcast' | 'ldra' | 'simulink' | 'parasoft';
  files: Array<{
    path: string;
    stmt: { covered: number; total: number };
    dec?: { covered: number; total: number };
    mcdc?: { covered: number; total: number };
  }>;
  objectiveLinks?: string[];
}

export interface ImportedBundle {
  findings?: Finding[];
  coverage?: CoverageSummary;
  testResults?: TestResult[];
  fileHashes?: ImportedFileHash[];
}

export interface ImportedFileHash {
  artifact: ObjectiveArtifactType;
  path: string;
  hash: string;
}
