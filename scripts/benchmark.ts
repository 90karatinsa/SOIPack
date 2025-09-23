import { promises as fsPromises } from 'fs';
import Module from 'module';
import os from 'os';
import path from 'path';
import { performance } from 'perf_hooks';

import {
  CoverageMetric,
  CoverageReport,
  CoverageSummary as StructuralCoverageSummary,
  FileCoverageSummary,
  TestResult,
} from '@soipack/adapters';
import { Requirement } from '@soipack/core';

import type { ImportBundle } from '../packages/engine/src';

type TraceEngineCtor = typeof import('../packages/engine/src').TraceEngine;
type JobQueueCtor = typeof import('../packages/server/src/queue').JobQueue;

const stubModuleRoot = path.resolve(__dirname, 'stubs', 'node_modules');
const moduleGlobals = Module as unknown as { globalPaths: string[] };
if (!moduleGlobals.globalPaths.includes(stubModuleRoot)) {
  moduleGlobals.globalPaths.push(stubModuleRoot);
}
process.env.NODE_PATH = [stubModuleRoot, process.env.NODE_PATH ?? '']
  .filter((segment) => segment && segment.length > 0)
  .join(path.delimiter);
(Module as unknown as { _initPaths: () => void })._initPaths();

let TraceEngine: TraceEngineCtor | undefined;
let JobQueue: JobQueueCtor | undefined;

const ensureDependenciesLoaded = async (): Promise<void> => {
  if (!TraceEngine) {
    const engineModule = await import('../packages/engine/src');
    TraceEngine = engineModule.TraceEngine;
  }
  if (!JobQueue) {
    const serverModule = await import('../packages/server/src/queue');
    JobQueue = serverModule.JobQueue;
  }
};

type Scenario = {
  name: string;
  requirementCount: number;
  testCount: number;
};

type EngineBenchmarkResult = {
  statusCounts: Record<'covered' | 'partial' | 'missing', number>;
  totalStatements: number;
  totalCoveredStatements: number;
};

type ServerBenchmarkResult = {
  completedJobs: number;
};

type BenchmarkMetrics<T> = {
  durationMs: number;
  peakMemoryBytes: number;
  result: T;
};

const formatBytes = (bytes: number): string => {
  if (bytes === 0) {
    return '0 B';
  }
  const units = ['B', 'KB', 'MB', 'GB'];
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / 1024 ** exponent;
  return `${value.toFixed(value >= 10 || exponent === 0 ? 0 : 2)} ${units[exponent]}`;
};

const formatDuration = (ms: number): string => `${(ms / 1000).toFixed(2)} s`;

const createCoverageMetric = (covered: number, total: number): CoverageMetric => ({
  covered,
  total,
  percentage: Number(((covered / total) * 100).toFixed(2)),
});

const buildScenarioBundle = (scenario: Scenario): ImportBundle => {
  const requirements: Requirement[] = Array.from({ length: scenario.requirementCount }, (_, index) => ({
    id: `REQ-${index + 1}`,
    title: `Benchmark requirement ${index + 1}`,
    status: 'approved',
    tags: [],
  }));

  const tests: TestResult[] = Array.from({ length: scenario.testCount }, (_, index) => ({
    testId: `TEST-${index + 1}`,
    className: `Suite${Math.floor(index / 50)}`,
    name: `Benchmark test ${index + 1}`,
    status: index % 23 === 0 ? 'failed' : 'passed',
    duration: 25,
    requirementsRefs: [`REQ-${(index % scenario.requirementCount) + 1}`],
  }));

  const coverageFileCount = Math.min(2000, Math.max(1, Math.floor(scenario.testCount / 10)));
  const coverageFiles: FileCoverageSummary[] = Array.from({ length: coverageFileCount }, (_, index) => {
    const statementsTotal = 120;
    const statementsCovered = 96;
    const branchesTotal = 80;
    const branchesCovered = 60;
    const functionsTotal = 40;
    const functionsCovered = 28;
    const mcdcTotal = 30;
    const mcdcCovered = 22;

    return {
      file: `src/module_${index}.ts`,
      statements: createCoverageMetric(statementsCovered, statementsTotal),
      branches: createCoverageMetric(branchesCovered, branchesTotal),
      functions: createCoverageMetric(functionsCovered, functionsTotal),
      mcdc: createCoverageMetric(mcdcCovered, mcdcTotal),
    };
  });

  const aggregateCoverage = coverageFiles.reduce(
    (totals, file) => {
      totals.statements.covered += file.statements.covered;
      totals.statements.total += file.statements.total;
      if (file.branches) {
        totals.branches.covered += file.branches.covered;
        totals.branches.total += file.branches.total;
      }
      if (file.functions) {
        totals.functions.covered += file.functions.covered;
        totals.functions.total += file.functions.total;
      }
      if (file.mcdc) {
        totals.mcdc.covered += file.mcdc.covered;
        totals.mcdc.total += file.mcdc.total;
      }
      return totals;
    },
    {
      statements: { covered: 0, total: 0 },
      branches: { covered: 0, total: 0 },
      functions: { covered: 0, total: 0 },
      mcdc: { covered: 0, total: 0 },
    },
  );

  const coverageReport: CoverageReport = {
    totals: {
      statements: createCoverageMetric(
        aggregateCoverage.statements.covered,
        aggregateCoverage.statements.total,
      ),
      branches: createCoverageMetric(aggregateCoverage.branches.covered, aggregateCoverage.branches.total),
      functions: createCoverageMetric(
        aggregateCoverage.functions.covered,
        aggregateCoverage.functions.total,
      ),
      mcdc: createCoverageMetric(aggregateCoverage.mcdc.covered, aggregateCoverage.mcdc.total),
    },
    files: coverageFiles,
  };

  const structuralCoverage: StructuralCoverageSummary = {
    tool: 'vectorcast',
    files: coverageFiles.map((file) => ({
      path: file.file,
      stmt: { covered: file.statements.covered, total: file.statements.total },
      dec: file.branches
        ? { covered: file.branches.covered, total: file.branches.total }
        : undefined,
      mcdc: file.mcdc ? { covered: file.mcdc.covered, total: file.mcdc.total } : undefined,
    })),
    objectiveLinks: ['BENCH-OBJ-1', 'BENCH-OBJ-2'],
  };

  const testToCodeMap: Record<string, string[]> = {};
  const coveragePaths = coverageFiles.map((file) => file.file);
  for (const test of tests) {
    const index = Number.parseInt(test.testId.split('-')[1] ?? '1', 10) - 1;
    const coveragePath = coveragePaths[index % coveragePaths.length];
    testToCodeMap[test.testId] = [coveragePath];
  }

  const bundle: ImportBundle = {
    requirements,
    objectives: [],
    testResults: tests,
    coverage: coverageReport,
    structuralCoverage,
    evidenceIndex: {},
    traceLinks: [],
    testToCodeMap,
  };

  return bundle;
};

const trackMetrics = async <T>(fn: () => Promise<T> | T): Promise<BenchmarkMetrics<T>> => {
  const baseline = process.memoryUsage().rss;
  let peak = baseline;
  const interval = setInterval(() => {
    const { rss } = process.memoryUsage();
    if (rss > peak) {
      peak = rss;
    }
  }, 50);

  try {
    const start = performance.now();
    const result = await fn();
    const durationMs = performance.now() - start;
    const finalRss = process.memoryUsage().rss;
    peak = Math.max(peak, finalRss);
    return { durationMs, peakMemoryBytes: peak, result };
  } finally {
    clearInterval(interval);
  }
};

const runEngineBenchmark = (scenario: Scenario): EngineBenchmarkResult => {
  const bundle = buildScenarioBundle(scenario);
  const EngineCtor = TraceEngine!;
  const engine = new EngineCtor(bundle);
  const statusCounts: EngineBenchmarkResult['statusCounts'] = {
    covered: 0,
    partial: 0,
    missing: 0,
  };
  let totalStatements = 0;
  let totalCoveredStatements = 0;

  for (const item of engine.streamRequirementCoverage()) {
    statusCounts[item.status] += 1;
    const statements = item.coverage?.statements;
    if (statements) {
      totalStatements += statements.total;
      totalCoveredStatements += statements.covered;
    }
  }

  return { statusCounts, totalStatements, totalCoveredStatements };
};

const runServerBenchmark = async (scenario: Scenario): Promise<ServerBenchmarkResult> => {
  const baseDir = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'soipack-benchmark-queue-'));
  try {
    const QueueCtor = JobQueue!;
    const queue = new QueueCtor(4, {
      directory: baseDir,
      createRunner: () => async () => undefined,
      persistJobs: false,
    });

    const tenantId = 'benchmark-tenant';
    const now = Date.now();
    for (let index = 0; index < scenario.requirementCount; index += 1) {
      queue.adoptCompleted({
        tenantId,
        id: `req-job-${index.toString().padStart(6, '0')}`,
        kind: 'analyze',
        hash: `req-hash-${index}`,
        createdAt: new Date(now - index).toISOString(),
        result: { requirement: index },
      });
    }

    for (let index = 0; index < scenario.testCount; index += 1) {
      queue.adoptCompleted({
        tenantId,
        id: `test-job-${index.toString().padStart(6, '0')}`,
        kind: 'report',
        hash: `test-hash-${index}`,
        createdAt: new Date(now - scenario.requirementCount - index).toISOString(),
        result: { test: index },
      });
    }

    let completedJobs = 0;
    for (const summary of queue.stream(tenantId)) {
      if (summary.status === 'completed') {
        completedJobs += 1;
      }
    }

    return { completedJobs };
  } finally {
    await fsPromises.rm(baseDir, { recursive: true, force: true });
  }
};

const runScenario = async (
  scenario: Scenario,
): Promise<{
  scenario: Scenario;
  engine: BenchmarkMetrics<EngineBenchmarkResult>;
  server: BenchmarkMetrics<ServerBenchmarkResult>;
}> => {
  const engine = await trackMetrics(() => runEngineBenchmark(scenario));
  const server = await trackMetrics(() => runServerBenchmark(scenario));
  return { scenario, engine, server };
};

const scenarios: Scenario[] = [
  { name: 'baseline', requirementCount: 5000, testCount: 10000 },
  { name: 'target', requirementCount: 50000, testCount: 100000 },
];

(async () => {
  await ensureDependenciesLoaded();

  const results: Array<{
    scenario: Scenario;
    engine: BenchmarkMetrics<EngineBenchmarkResult>;
    server: BenchmarkMetrics<ServerBenchmarkResult>;
  }> = [];

  for (const scenario of scenarios) {
    const result = await runScenario(scenario);
    results.push(result);
    const engineMemory = formatBytes(result.engine.peakMemoryBytes);
    const serverMemory = formatBytes(result.server.peakMemoryBytes);
    const engineDuration = formatDuration(result.engine.durationMs);
    const serverDuration = formatDuration(result.server.durationMs);
    // eslint-disable-next-line no-console
    console.log(`\nScenario: ${scenario.name}`);
    // eslint-disable-next-line no-console
    console.log(
      `  Engine -> duration: ${engineDuration}, peak memory: ${engineMemory}, coverage entries: ${scenario.requirementCount}`,
    );
    // eslint-disable-next-line no-console
    console.log(
      `  Server -> duration: ${serverDuration}, peak memory: ${serverMemory}, completed jobs: ${result.server.result.completedJobs}`,
    );
  }

  const target = results.find((item) => item.scenario.name === 'target');
  if (!target) {
    throw new Error('Target scenario results missing');
  }

  const totalDuration = target.engine.durationMs + target.server.durationMs;
  const peakMemory = Math.max(target.engine.peakMemoryBytes, target.server.peakMemoryBytes);

  if (peakMemory > 1024 ** 3) {
    throw new Error(`Peak memory ${formatBytes(peakMemory)} exceeded 1 GB limit for target scenario`);
  }

  if (totalDuration > 60000) {
    throw new Error(
      `Total duration ${formatDuration(totalDuration)} exceeded 60 second limit for target scenario`,
    );
  }

  const coverageRate =
    target.engine.result.totalStatements === 0
      ? 0
      : (target.engine.result.totalCoveredStatements / target.engine.result.totalStatements) * 100;

  // eslint-disable-next-line no-console
  console.log('\nSummary');
  // eslint-disable-next-line no-console
  console.log(
    `  Target scenario coverage rate: ${coverageRate.toFixed(2)}% across ${target.scenario.requirementCount} requirements`,
  );
  // eslint-disable-next-line no-console
  console.log(
    `  Combined duration: ${formatDuration(totalDuration)}, peak memory: ${formatBytes(peakMemory)}`,
  );
})().catch((error) => {
  // eslint-disable-next-line no-console
  console.error(error);
  process.exitCode = 1;
});
