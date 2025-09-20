import { CoverageSummary, TestResult } from '@soipack/adapters';
import {
  Evidence,
  Objective,
  ObjectiveArtifactType,
  Requirement,
  TraceLink,
  createRequirement,
} from '@soipack/core';

import { ImportBundle, ObjectiveMapper, TraceEngine, generateComplianceSnapshot } from './index';

const evidence = (
  type: ObjectiveArtifactType,
  path: string,
  source: Evidence['source'],
): Evidence => ({
  source,
  path,
  summary: `${type} evidence`,
  timestamp: '2024-01-10T10:00:00Z',
});

const requirementFixture = (): Requirement[] => [
  createRequirement('REQ-1', 'Authenticate user', { status: 'implemented' }),
  createRequirement('REQ-2', 'Lock account after failures', { status: 'approved' }),
  createRequirement('REQ-3', 'Audit login attempts', { status: 'draft' }),
];

const coverageFixture = (): CoverageSummary => ({
  totals: {
    statements: { covered: 80, total: 100, percentage: 80 },
    branches: { covered: 30, total: 50, percentage: 60 },
    functions: { covered: 12, total: 20, percentage: 60 },
  },
  files: [
    {
      file: 'src/auth/login.ts',
      statements: { covered: 30, total: 40, percentage: 75 },
      branches: { covered: 10, total: 16, percentage: 62.5 },
      functions: { covered: 5, total: 6, percentage: 83.33 },
    },
    {
      file: 'src/common/logger.ts',
      statements: { covered: 20, total: 20, percentage: 100 },
      functions: { covered: 3, total: 3, percentage: 100 },
    },
  ],
});

const testResultsFixture = (): TestResult[] => [
  {
    testId: 'TC-1',
    className: 'AuthSuite',
    name: 'should authenticate valid users',
    status: 'passed',
    duration: 12,
    requirementsRefs: ['REQ-1'],
  },
  {
    testId: 'TC-2',
    className: 'AuthSuite',
    name: 'should reject locked users',
    status: 'failed',
    duration: 15,
    requirementsRefs: ['REQ-1', 'REQ-2'],
  },
  {
    testId: 'TC-3',
    className: 'AuditSuite',
    name: 'should record failed login attempts',
    status: 'passed',
    duration: 8,
    requirementsRefs: ['REQ-2'],
  },
  {
    testId: 'TC-4',
    className: 'AuditSuite',
    name: 'should send audit notifications',
    status: 'skipped',
    duration: 5,
  },
];

const level = { A: true, B: false, C: false, D: false, E: false } as const;

const objectivesFixture = (): Objective[] => [
  {
    id: 'A-Plans-Obj1',
    area: 'Plans',
    description: 'Ensure PSAC baseline is established.',
    artifacts: ['psac'],
    level,
  },
  {
    id: 'A-Plans-Obj2',
    area: 'Plans',
    description: 'Ensure SDP and PSAC consistency.',
    artifacts: ['psac', 'sdp'],
    level,
  },
  {
    id: 'A-Verification-Obj1',
    area: 'Verification',
    description: 'Verify implementation with tests and coverage.',
    artifacts: ['testResults', 'coverage'],
    level,
  },
  {
    id: 'A-Verification-Obj2',
    area: 'Verification',
    description: 'Trace tests back to requirements.',
    artifacts: ['testResults', 'traceability'],
    level,
  },
  {
    id: 'A-Standards-Obj1',
    area: 'Standards',
    description: 'Maintain configuration index with plans.',
    artifacts: ['configurationIndex', 'sdp'],
    level,
  },
  {
    id: 'A-Reviews-Obj1',
    area: 'Reviews',
    description: 'Perform peer reviews for life cycle data.',
    artifacts: ['analysisReport'],
    level,
  },
  {
    id: 'A-Reviews-Obj2',
    area: 'Reviews',
    description: 'Audit configuration baselines.',
    artifacts: ['git'],
    level,
  },
];

const evidenceIndexFixture = () => ({
  psac: [evidence('psac', 'plans/psac.md', 'git')],
  sdp: [evidence('sdp', 'plans/sdp.md', 'git')],
  testResults: [evidence('testResults', 'reports/junit.xml', 'junit')],
  coverage: [evidence('coverage', 'reports/lcov.info', 'lcov')],
});

const traceLinksFixture = (): TraceLink[] => [{ from: 'REQ-3', to: 'TC-4', type: 'verifies' }];

const bundleFixture = (): ImportBundle => ({
  requirements: requirementFixture(),
  objectives: objectivesFixture(),
  testResults: testResultsFixture(),
  coverage: coverageFixture(),
  evidenceIndex: evidenceIndexFixture(),
  traceLinks: traceLinksFixture(),
  testToCodeMap: {
    'TC-1': ['src/auth/login.ts'],
    'TC-2': ['src/common/logger.ts'],
    'TC-3': ['src/auth/login.ts'],
    'TC-4': ['src/common/logger.ts'],
  },
  generatedAt: '2024-02-01T10:00:00Z',
});

describe('TraceEngine', () => {
  const bundle = bundleFixture();
  const engine = new TraceEngine(bundle);

  it('links requirements to their related tests and code paths', () => {
    const trace = engine.getRequirementTrace('REQ-1');
    expect(trace.tests.map((test) => test.testId)).toEqual(
      expect.arrayContaining(['TC-1', 'TC-2']),
    );
    const codePaths = trace.code.map((item) => item.path);
    expect(codePaths).toEqual(
      expect.arrayContaining(['src/auth/login.ts', 'src/common/logger.ts']),
    );

    const loginCoverage = trace.code.find((item) => item.path === 'src/auth/login.ts');
    expect(loginCoverage?.coverage?.statements.covered).toBe(30);

    const graph = engine.getGraph();
    const codeNode = graph.nodes.find(
      (node) => node.type === 'code' && node.id === 'src/auth/login.ts',
    );
    expect(codeNode?.type).toBe('code');
    if (codeNode?.type === 'code') {
      expect(codeNode.data.coverage?.statements?.percentage).toBeCloseTo(75, 2);
    }
  });

  it('incorporates trace links when tests lack explicit requirement references', () => {
    const trace = engine.getRequirementTrace('REQ-3');
    expect(trace.tests.map((test) => test.testId)).toContain('TC-4');
  });

  it('summarizes coverage status per requirement', () => {
    const coverage = engine.getRequirementCoverage();
    const req1 = coverage.find((item) => item.requirement.id === 'REQ-1');
    const req3 = coverage.find((item) => item.requirement.id === 'REQ-3');

    expect(req1?.status).toBe('partial');
    expect(req1?.coverage?.statements?.percentage).toBeCloseTo(83.33, 2);
    expect(req3?.status).toBe('covered');
    expect(req3?.coverage?.statements?.percentage).toBe(100);
  });

  it('links requirements directly to code paths defined via trace links', () => {
    const manualRequirement = createRequirement('REQ-Manual', 'Manual coverage mapping', {
      status: 'draft',
    });

    const manualBundle: ImportBundle = {
      ...bundle,
      requirements: [...bundle.requirements, manualRequirement],
      traceLinks: [
        ...(bundle.traceLinks ?? []),
        { from: 'REQ-Manual', to: 'src/auth/login.ts', type: 'implements' },
      ],
    };

    const manualEngine = new TraceEngine(manualBundle);
    const trace = manualEngine.getRequirementTrace('REQ-Manual');

    expect(trace.tests).toHaveLength(0);
    expect(trace.code.map((item) => item.path)).toContain('src/auth/login.ts');

    const coverage = manualEngine
      .getRequirementCoverage()
      .find((item) => item.requirement.id === 'REQ-Manual');
    expect(coverage?.status).toBe('partial');
  });
});

describe('ObjectiveMapper', () => {
  const bundle = bundleFixture();
  const mapper = new ObjectiveMapper(bundle.objectives, bundle.evidenceIndex);
  const coverage = mapper.mapObjectives();

  it('returns coverage summaries for each objective', () => {
    const statuses = new Map(coverage.map((item) => [item.objectiveId, item.status]));
    expect(statuses.get('A-Plans-Obj1')).toBe('covered');
    expect(statuses.get('A-Plans-Obj2')).toBe('covered');
    expect(statuses.get('A-Verification-Obj1')).toBe('covered');
    expect(statuses.get('A-Verification-Obj2')).toBe('partial');
    expect(statuses.get('A-Standards-Obj1')).toBe('partial');
    expect(statuses.get('A-Reviews-Obj1')).toBe('missing');
    expect(statuses.get('A-Reviews-Obj2')).toBe('missing');
  });

  it('collects evidence references for satisfied artifacts', () => {
    const plansObjective = coverage.find((item) => item.objectiveId === 'A-Plans-Obj2');
    expect(plansObjective?.evidenceRefs).toEqual(
      expect.arrayContaining(['psac:plans/psac.md', 'sdp:plans/sdp.md']),
    );
  });
});

describe('Compliance snapshot generation', () => {
  const bundle = bundleFixture();
  const snapshot = generateComplianceSnapshot(bundle);

  it('summarizes objective coverage and statistics', () => {
    expect(snapshot.objectives).toHaveLength(7);
    expect(snapshot.stats.objectives).toEqual({
      total: 7,
      covered: 3,
      partial: 2,
      missing: 2,
    });

    expect(snapshot.stats.tests).toEqual({ total: 4, passed: 2, failed: 1, skipped: 1 });
    expect(snapshot.stats.requirements).toEqual({ total: 3 });
    expect(snapshot.stats.codePaths).toEqual({ total: 2 });
  });

  it('derives gap analysis grouped by artifact category', () => {
    expect(snapshot.gaps.tests).toEqual([
      { objectiveId: 'A-Verification-Obj2', missingArtifacts: ['traceability'] },
    ]);

    expect(snapshot.gaps.standards).toEqual(
      expect.arrayContaining([
        { objectiveId: 'A-Standards-Obj1', missingArtifacts: ['configurationIndex'] },
        { objectiveId: 'A-Reviews-Obj1', missingArtifacts: ['analysisReport'] },
        { objectiveId: 'A-Reviews-Obj2', missingArtifacts: ['git'] },
      ]),
    );

    expect(snapshot.gaps.coverage).toHaveLength(0);
    expect(snapshot.gaps.plans).toHaveLength(0);
  });

  it('exposes trace graph nodes for requirements, tests, and code paths', () => {
    const types = snapshot.traceGraph.nodes.reduce<Record<string, number>>((acc, node) => {
      acc[node.type] = (acc[node.type] ?? 0) + 1;
      return acc;
    }, {});

    expect(types.requirement).toBe(3);
    expect(types.test).toBe(4);
    expect(types.code).toBe(2);
  });

  it('includes requirement coverage breakdowns', () => {
    expect(snapshot.requirementCoverage).toHaveLength(3);
    const coverageByRequirement = new Map(
      snapshot.requirementCoverage.map((item) => [item.requirement.id, item]),
    );

    expect(coverageByRequirement.get('REQ-1')?.status).toBe('partial');
    expect(coverageByRequirement.get('REQ-3')?.status).toBe('covered');
    expect(coverageByRequirement.get('REQ-3')?.coverage?.statements?.percentage).toBe(100);
  });
});
