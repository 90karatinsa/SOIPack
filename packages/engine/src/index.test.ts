import { CoverageReport, TestResult, CoverageSummary as StructuralCoverageSummary } from '@soipack/adapters';
import {
  Evidence,
  Objective,
  ObjectiveArtifactType,
  Requirement,
  TraceLink,
  createRequirement,
} from '@soipack/core';

import {
  EvidenceIndex,
  ImportBundle,
  ObjectiveMapper,
  TraceEngine,
  generateComplianceSnapshot,
} from './index';

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

const coverageFixture = (): CoverageReport => ({
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

const structuralCoverageFixture = (): StructuralCoverageSummary => ({
  tool: 'vectorcast',
  files: [
    {
      path: 'src/auth/login.ts',
      stmt: { covered: 60, total: 60 },
      dec: { covered: 40, total: 50 },
      mcdc: { covered: 30, total: 40 },
    },
    {
      path: 'src/common/logger.ts',
      stmt: { covered: 30, total: 30 },
      dec: { covered: 20, total: 20 },
    },
  ],
  objectiveLinks: ['A-5-08', 'A-5-09', 'A-5-10'],
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

const objectivesFixture = (): Objective[] => [
  {
    id: 'A-3-01',
    table: 'A-3',
    name: 'Plan Seti Tanımlı',
    desc: 'Tüm yazılım planlarının kapsam ve sorumlulukları tanımlanmış.',
    artifacts: ['plan'],
    levels: { A: true, B: true, C: true, D: true, E: false },
    independence: 'recommended',
  },
  {
    id: 'A-3-04',
    table: 'A-3',
    name: 'Doğrulama Stratejisi',
    desc: 'Gözden geçirme, analiz ve test stratejisi ve kriterleri tanımlı.',
    artifacts: ['plan', 'review'],
    levels: { A: true, B: true, C: true, D: true, E: false },
    independence: 'required',
  },
  {
    id: 'A-4-01',
    table: 'A-4',
    name: 'Üst Düzey Gereksinimler',
    desc: 'HLR doğru, tutarlı, izlenebilir ve test edilebilir.',
    artifacts: ['analysis', 'trace', 'review'],
    levels: { A: true, B: true, C: true, D: true, E: false },
    independence: 'required',
  },
  {
    id: 'A-5-06',
    table: 'A-5',
    name: 'Test Stratejisi Uygulandı',
    desc: 'Gereksinim-tabanlı testler koşuldu; sonuçlar kaydedildi.',
    artifacts: ['test', 'trace', 'analysis'],
    levels: { A: true, B: true, C: true, D: true, E: false },
    independence: 'required',
  },
  {
    id: 'A-5-08',
    table: 'A-5',
    name: 'Yapısal Kapsam—Statement',
    desc: 'Kod satır kapsamı ölçüldü ve açıklandı.',
    artifacts: ['coverage_stmt', 'analysis'],
    levels: { A: true, B: true, C: true, D: false, E: false },
    independence: 'required',
  },
  {
    id: 'A-5-09',
    table: 'A-5',
    name: 'Yapısal Kapsam—Decision/Branch',
    desc: 'Karar/branch kapsamı ölçüldü ve açıklandı.',
    artifacts: ['coverage_dec', 'analysis'],
    levels: { A: true, B: true, C: false, D: false, E: false },
    independence: 'required',
  },
  {
    id: 'A-5-10',
    table: 'A-5',
    name: 'Yapısal Kapsam—MC/DC',
    desc: 'Koşul/Karşılıklı Bağımsız Karar kapsamı sağlandı.',
    artifacts: ['coverage_mcdc', 'analysis'],
    levels: { A: true, B: false, C: false, D: false, E: false },
    independence: 'required',
  },
  {
    id: 'A-6-02',
    table: 'A-6',
    name: 'Değişiklik Kontrolü',
    desc: 'Değişiklikler onaylı, izlenebilir ve kayıtlı.',
    artifacts: ['cm_record', 'problem_report'],
    levels: { A: true, B: true, C: true, D: true, E: false },
    independence: 'required',
  },
];

const evidenceIndexFixture = () => ({
  plan: [evidence('plan', 'plans/plan.md', 'git')],
  analysis: [evidence('analysis', 'analysis/resources.md', 'git')],
  test: [evidence('test', 'reports/junit.xml', 'junit')],
  trace: [evidence('trace', 'traces/requirements.csv', 'git')],
  coverage_stmt: [evidence('coverage_stmt', 'reports/lcov.info', 'lcov')],
  coverage_dec: [evidence('coverage_dec', 'reports/vectorcast.json', 'vectorcast')],
  coverage_mcdc: [evidence('coverage_mcdc', 'reports/vectorcast.json', 'vectorcast')],
});

const traceLinksFixture = (): TraceLink[] => [{ from: 'REQ-3', to: 'TC-4', type: 'verifies' }];

const bundleFixture = (): ImportBundle => ({
  requirements: requirementFixture(),
  objectives: objectivesFixture(),
  testResults: testResultsFixture(),
  coverage: coverageFixture(),
  structuralCoverage: structuralCoverageFixture(),
  evidenceIndex: evidenceIndexFixture(),
  traceLinks: traceLinksFixture(),
  testToCodeMap: {
    'TC-1': ['src/auth/login.ts'],
    'TC-2': ['src/common/logger.ts'],
    'TC-3': ['src/auth/login.ts'],
    'TC-4': ['src/common/logger.ts'],
  },
  generatedAt: '2024-02-01T10:00:00Z',
  targetLevel: 'A',
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
  const mapper = new ObjectiveMapper(bundle.objectives, bundle.evidenceIndex, {
    structuralCoverage: bundle.structuralCoverage,
  });
  const coverage = mapper.mapObjectives();

  it('returns coverage summaries for each objective', () => {
    const statuses = new Map(coverage.map((item) => [item.objectiveId, item.status]));
    expect(statuses.get('A-3-01')).toBe('covered');
    expect(statuses.get('A-3-04')).toBe('partial');
    expect(statuses.get('A-4-01')).toBe('partial');
    expect(statuses.get('A-5-06')).toBe('covered');
    expect(statuses.get('A-5-08')).toBe('covered');
    expect(statuses.get('A-5-09')).toBe('partial');
    expect(statuses.get('A-5-10')).toBe('partial');
    expect(statuses.get('A-6-02')).toBe('missing');
  });

  it('collects evidence references for satisfied artifacts', () => {
    const testObjective = coverage.find((item) => item.objectiveId === 'A-5-06');
    expect(testObjective?.evidenceRefs).toEqual(
      expect.arrayContaining([
        'test:reports/junit.xml',
        'trace:traces/requirements.csv',
        'analysis:analysis/resources.md',
      ]),
    );
  });

  it('marks MC/DC objective missing when structural coverage evidence is absent', () => {
    const evidence = evidenceIndexFixture();
    delete (evidence as Partial<EvidenceIndex>).coverage_mcdc;

    const mapper = new ObjectiveMapper(bundle.objectives, evidence, {
      structuralCoverage: structuralCoverageFixture(),
    });
    const coverage = mapper.mapObjectives();
    const mcDc = coverage.find((item) => item.objectiveId === 'A-5-10');
    expect(mcDc?.status).toBe('missing');
  });

  it('treats MC/DC objective as missing when no metric data is available', () => {
    const coverageSummary = structuralCoverageFixture();
    const stripped: StructuralCoverageSummary = {
      tool: coverageSummary.tool,
      files: coverageSummary.files.map((file) => ({ path: file.path, stmt: file.stmt, dec: file.dec })),
    };
    const mapper = new ObjectiveMapper(bundle.objectives, evidenceIndexFixture(), {
      structuralCoverage: stripped,
    });
    const coverage = mapper.mapObjectives();
    const mcDc = coverage.find((item) => item.objectiveId === 'A-5-10');
    expect(mcDc?.status).toBe('missing');
  });
});

describe('Compliance snapshot generation', () => {
  const bundle = bundleFixture();
  const snapshot = generateComplianceSnapshot(bundle);

  it('summarizes objective coverage and statistics', () => {
    expect(snapshot.objectives).toHaveLength(8);
    expect(snapshot.stats.objectives).toEqual({
      total: 8,
      covered: 3,
      partial: 4,
      missing: 1,
    });

    expect(snapshot.stats.tests).toEqual({ total: 4, passed: 2, failed: 1, skipped: 1 });
    expect(snapshot.stats.requirements).toEqual({ total: 3 });
    expect(snapshot.stats.codePaths).toEqual({ total: 2 });
  });

  it('derives gap analysis grouped by artifact category', () => {
    expect(snapshot.gaps.reviews).toEqual(
      expect.arrayContaining([
        { objectiveId: 'A-3-04', missingArtifacts: ['review'] },
        { objectiveId: 'A-4-01', missingArtifacts: ['review'] },
      ]),
    );

    expect(snapshot.gaps.coverage).toEqual(
      expect.arrayContaining([
        { objectiveId: 'A-5-09', missingArtifacts: ['coverage_dec'] },
        { objectiveId: 'A-5-10', missingArtifacts: ['coverage_mcdc'] },
      ]),
    );

    expect(snapshot.gaps.configuration).toEqual([
      { objectiveId: 'A-6-02', missingArtifacts: ['cm_record'] },
    ]);

    expect(snapshot.gaps.issues).toEqual([
      { objectiveId: 'A-6-02', missingArtifacts: ['problem_report'] },
    ]);

    expect(snapshot.gaps.plans).toHaveLength(0);
    expect(snapshot.gaps.standards).toHaveLength(0);
    expect(snapshot.gaps.analysis).toHaveLength(0);
    expect(snapshot.gaps.tests).toHaveLength(0);
    expect(snapshot.gaps.trace).toHaveLength(0);
    expect(snapshot.gaps.quality).toHaveLength(0);
    expect(snapshot.gaps.conformity).toHaveLength(0);
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
