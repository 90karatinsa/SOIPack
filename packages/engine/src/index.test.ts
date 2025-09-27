import { createHash } from 'crypto';

import { CoverageReport, TestResult, CoverageSummary as StructuralCoverageSummary } from '@soipack/adapters';
import {
  Evidence,
  Objective,
  ObjectiveArtifactType,
  Requirement,
  TraceLink,
  createRequirement,
  createDesignRecord,
  createSnapshotIdentifier,
  freezeSnapshotVersion,
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
  options: { independent?: boolean } = {},
): Evidence => ({
  source,
  path,
  summary: `${type} evidence`,
  timestamp: '2024-01-10T10:00:00Z',
  snapshotId: createSnapshotIdentifier(
    '2024-01-10T10:00:00Z',
    createHash('sha256').update(`${type}:${path}`).digest('hex'),
  ),
  ...(options.independent ? { independent: true } : {}),
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
    mcdc: { covered: 18, total: 24, percentage: 75 },
  },
  files: [
    {
      file: 'src/auth/login.ts',
      statements: { covered: 30, total: 40, percentage: 75 },
      branches: { covered: 10, total: 16, percentage: 62.5 },
      functions: { covered: 5, total: 6, percentage: 83.33 },
      mcdc: { covered: 12, total: 16, percentage: 75 },
    },
    {
      file: 'src/common/logger.ts',
      statements: { covered: 20, total: 20, percentage: 100 },
      functions: { covered: 3, total: 3, percentage: 100 },
      mcdc: { covered: 6, total: 8, percentage: 75 },
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

const designFixture = () => [
  createDesignRecord('DES-1', 'Authentication component design', {
    status: 'implemented',
    requirementRefs: ['REQ-1'],
    codeRefs: ['src/auth/login.ts'],
  }),
  createDesignRecord('DES-2', 'Audit logging design', {
    status: 'allocated',
    requirementRefs: ['REQ-2', 'REQ-3'],
    codeRefs: ['src/common/logger.ts'],
  }),
];

const objectivesFixture = (): Objective[] => [
  {
    id: 'A-3-01',
    table: 'A-3',
    stage: 'SOI-1',
    name: 'Plan Seti Tanımlı',
    desc: 'Tüm yazılım planlarının kapsam ve sorumlulukları tanımlanmış.',
    artifacts: ['plan'],
    levels: { A: true, B: true, C: true, D: true, E: false },
    independence: 'recommended',
  },
  {
    id: 'A-3-04',
    table: 'A-3',
    stage: 'SOI-1',
    name: 'Doğrulama Stratejisi',
    desc: 'Gözden geçirme, analiz ve test stratejisi ve kriterleri tanımlı.',
    artifacts: ['plan', 'review'],
    levels: { A: true, B: true, C: true, D: true, E: false },
    independence: 'required',
  },
  {
    id: 'A-4-01',
    table: 'A-4',
    stage: 'SOI-2',
    name: 'Üst Düzey Gereksinimler',
    desc: 'HLR doğru, tutarlı, izlenebilir ve test edilebilir.',
    artifacts: ['analysis', 'trace', 'review'],
    levels: { A: true, B: true, C: true, D: true, E: false },
    independence: 'required',
  },
  {
    id: 'A-5-06',
    table: 'A-5',
    stage: 'SOI-3',
    name: 'Test Stratejisi Uygulandı',
    desc: 'Gereksinim-tabanlı testler koşuldu; sonuçlar kaydedildi.',
    artifacts: ['test', 'trace', 'analysis'],
    levels: { A: true, B: true, C: true, D: true, E: false },
    independence: 'required',
  },
  {
    id: 'A-5-08',
    table: 'A-5',
    stage: 'SOI-3',
    name: 'Yapısal Kapsam—Statement',
    desc: 'Kod satır kapsamı ölçüldü ve açıklandı.',
    artifacts: ['coverage_stmt', 'analysis'],
    levels: { A: true, B: true, C: true, D: false, E: false },
    independence: 'required',
  },
  {
    id: 'A-5-09',
    table: 'A-5',
    stage: 'SOI-3',
    name: 'Yapısal Kapsam—Decision/Branch',
    desc: 'Karar/branch kapsamı ölçüldü ve açıklandı.',
    artifacts: ['coverage_dec', 'analysis'],
    levels: { A: true, B: true, C: false, D: false, E: false },
    independence: 'required',
  },
  {
    id: 'A-5-10',
    table: 'A-5',
    stage: 'SOI-3',
    name: 'Yapısal Kapsam—MC/DC',
    desc: 'Koşul/Karşılıklı Bağımsız Karar kapsamı sağlandı.',
    artifacts: ['coverage_mcdc', 'analysis'],
    levels: { A: true, B: false, C: false, D: false, E: false },
    independence: 'required',
  },
  {
    id: 'A-6-02',
    table: 'A-6',
    stage: 'SOI-3',
    name: 'Değişiklik Kontrolü',
    desc: 'Değişiklikler onaylı, izlenebilir ve kayıtlı.',
    artifacts: ['cm_record', 'problem_report'],
    levels: { A: true, B: true, C: true, D: true, E: false },
    independence: 'required',
  },
];

const evidenceIndexFixture = () => {
  const independent = { independent: true } as const;
  return {
    plan: [evidence('plan', 'plans/plan.md', 'git', independent)],
    analysis: [evidence('analysis', 'analysis/resources.md', 'git', independent)],
    test: [evidence('test', 'reports/junit.xml', 'junit', independent)],
    trace: [evidence('trace', 'traces/requirements.csv', 'git', independent)],
    coverage_stmt: [evidence('coverage_stmt', 'reports/lcov.info', 'lcov', independent)],
    coverage_dec: [evidence('coverage_dec', 'reports/vectorcast.json', 'vectorcast', independent)],
    coverage_mcdc: [evidence('coverage_mcdc', 'reports/vectorcast.json', 'vectorcast', independent)],
  };
};

const traceLinksFixture = (): TraceLink[] => [{ from: 'REQ-3', to: 'TC-4', type: 'verifies' }];

const bundleFixture = (): ImportBundle => ({
  requirements: requirementFixture(),
  designs: designFixture(),
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
    expect(trace.designs.map((design) => design.id)).toEqual(
      expect.arrayContaining(['DES-1']),
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

  it('includes design records in the trace graph', () => {
    const graph = engine.getGraph();
    const designNodes = graph.nodes.filter((node) => node.type === 'design');
    expect(designNodes.map((node) => node.id)).toEqual(
      expect.arrayContaining(['DES-1', 'DES-2']),
    );
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
    expect(req1?.coverage?.mcdc?.percentage).toBe(75);
    expect(req3?.status).toBe('covered');
    expect(req3?.coverage?.statements?.percentage).toBe(100);
    expect(req3?.coverage?.mcdc?.percentage).toBe(75);
  });

  it('treats coverage as missing when no design records are linked', () => {
    const requirement = createRequirement('REQ-NO-DESIGN', 'Legacy mapping', { status: 'implemented' });
    const coverage: CoverageReport = {
      totals: { statements: { covered: 10, total: 10, percentage: 100 } },
      files: [
        {
          file: 'src/control/module.c',
          statements: { covered: 10, total: 10, percentage: 100 },
        },
      ],
    };

    const bundle: ImportBundle = {
      requirements: [requirement],
      designs: [],
      objectives: [],
      testResults: [],
      coverage,
      structuralCoverage: undefined,
      evidenceIndex: {},
      traceLinks: [{ from: 'REQ-NO-DESIGN', to: 'src/control/module.c', type: 'implements' }],
      testToCodeMap: {},
      generatedAt: '2024-02-01T00:00:00Z',
    };

    const engineWithoutDesigns = new TraceEngine(bundle);
    const coverageStatus = engineWithoutDesigns
      .getRequirementCoverage()
      .find((item) => item.requirement.id === 'REQ-NO-DESIGN');

    expect(coverageStatus?.status).toBe('missing');
    const trace = engineWithoutDesigns.getRequirementTrace('REQ-NO-DESIGN');
    expect(trace.designs).toHaveLength(0);
    expect(trace.code.map((item) => item.path)).toContain('src/control/module.c');
  });

  it('streams requirement coverage lazily to support large datasets', () => {
    const iterator = engine.streamRequirementCoverage();
    const first = iterator.next();
    expect(first.done).toBe(false);
    const remaining = Array.from(iterator);
    expect(remaining.length).toBe(bundle.requirements.length - 1);

    const reconstructed = first.value ? [first.value, ...remaining] : remaining;
    expect(reconstructed).toEqual(engine.getRequirementCoverage());
  });

  it('links requirements directly to code paths defined via trace links', () => {
    const manualRequirement = createRequirement('REQ-Manual', 'Manual coverage mapping', {
      status: 'draft',
    });

    const manualDesign = createDesignRecord('DES-Manual', 'Manual trace design', {
      status: 'allocated',
      requirementRefs: ['REQ-Manual'],
      codeRefs: ['src/auth/login.ts'],
    });

    const manualBundle: ImportBundle = {
      ...bundle,
      requirements: [...bundle.requirements, manualRequirement],
      designs: [...(bundle.designs ?? []), manualDesign],
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

  it('downgrades objectives that lack independent evidence for required artifacts', () => {
    const evidence = evidenceIndexFixture();
    if (evidence.test) {
      evidence.test = evidence.test.map(({ independent: _ignored, ...rest }) => ({
        ...rest,
      })) as Evidence[];
    }

    const mapper = new ObjectiveMapper(bundle.objectives, evidence, {
      structuralCoverage: bundle.structuralCoverage,
    });
    const coverage = mapper.mapObjectives();
    const verification = coverage.find((item) => item.objectiveId === 'A-5-06');
    expect(verification?.status).toBe('missing');
    expect(verification?.missingArtifacts).toEqual(expect.arrayContaining(['test']));
  });
});

describe('Compliance snapshot generation', () => {
  const bundle = bundleFixture();
  const snapshot = generateComplianceSnapshot(bundle);

  it('produces a snapshot version with deterministic fingerprint', () => {
    expect(snapshot.version.id).toMatch(/^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}$/);
    const repeated = generateComplianceSnapshot(bundleFixture());
    expect(repeated.version.fingerprint).toBe(snapshot.version.fingerprint);
    expect(repeated.version.id).not.toBeUndefined();
  });

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
    expect(snapshot.stats.designs).toEqual({ total: 2 });
  });

  it('omits risk blocks by default for backward compatibility', () => {
    expect(snapshot.risk).toBeUndefined();
  });

  it('attaches computed risk insights when requested', () => {
    const withRisk = generateComplianceSnapshot(bundle, {
      includeRisk: true,
      risk: {
        coverageHistory: [
          { timestamp: '2024-01-01T00:00:00Z', coverage: 82 },
          { timestamp: '2024-01-08T00:00:00Z', coverage: 80 },
          { timestamp: '2024-01-15T00:00:00Z', coverage: 78 },
        ],
      },
    });

    expect(withRisk.risk?.profile.score).toBeGreaterThanOrEqual(0);
    expect(withRisk.risk?.profile.breakdown.length).toBeGreaterThan(0);
    expect(withRisk.risk?.coverageDrift?.classification).toBeDefined();
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

  it('appends design gaps when requirements lack design coverage', () => {
    const withoutDesigns = generateComplianceSnapshot({
      ...bundleFixture(),
      designs: [],
    });

    expect(withoutDesigns.gaps.trace).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          objectiveId: 'REQ-1',
          missingArtifacts: expect.arrayContaining(['design']),
        }),
      ]),
    );
  });

  it('exposes trace graph nodes for requirements, tests, and code paths', () => {
    const types = snapshot.traceGraph.nodes.reduce<Record<string, number>>((acc, node) => {
      acc[node.type] = (acc[node.type] ?? 0) + 1;
      return acc;
    }, {});

    expect(types.requirement).toBe(3);
    expect(types.test).toBe(4);
    expect(types.code).toBe(2);
    expect(types.design).toBe(2);
  });

  it('includes requirement coverage breakdowns', () => {
    expect(snapshot.requirementCoverage).toHaveLength(3);
    const coverageByRequirement = new Map(
      snapshot.requirementCoverage.map((item) => [item.requirement.id, item]),
    );

    expect(coverageByRequirement.get('REQ-1')?.status).toBe('partial');
    expect(coverageByRequirement.get('REQ-3')?.status).toBe('covered');
    expect(coverageByRequirement.get('REQ-3')?.coverage?.statements?.percentage).toBe(100);
    expect(coverageByRequirement.get('REQ-1')?.coverage?.mcdc?.percentage).toBe(75);
    expect(coverageByRequirement.get('REQ-1')?.designs.map((design) => design.id)).toEqual(
      expect.arrayContaining(['DES-1']),
    );
  });

  it('does not emit quality findings when bundle is consistent', () => {
    expect(snapshot.qualityFindings).toHaveLength(0);
  });

  it('reuses frozen snapshot metadata when provided in the bundle', () => {
    const frozenVersion = freezeSnapshotVersion(snapshot.version, {
      frozenAt: '2024-04-01T00:00:00Z',
    });
    const frozenSnapshot = generateComplianceSnapshot({ ...bundle, snapshot: frozenVersion });
    expect(frozenSnapshot.version.isFrozen).toBe(true);
    expect(frozenSnapshot.version.fingerprint).toBe(snapshot.version.fingerprint);
    expect(frozenSnapshot.version.id.startsWith('20240401T000000Z-')).toBe(true);
  });
});

describe('compliance delta tracking', () => {
  it('computes compliance delta summaries across snapshot history', () => {
    const baselineBundle = bundleFixture();
    const baseline = generateComplianceSnapshot(baselineBundle);

    const improvedEvidence: EvidenceIndex = {
      ...evidenceIndexFixture(),
      cm_record: [
        evidence('cm_record', 'cm/records.md', 'git', { independent: true }),
      ],
      problem_report: [
        evidence('problem_report', 'cm/problems.md', 'git', { independent: true }),
      ],
    };
    const improvedBundle: ImportBundle = {
      ...bundleFixture(),
      generatedAt: '2024-02-15T10:00:00Z',
      evidenceIndex: improvedEvidence,
    };
    const improvedSnapshot = generateComplianceSnapshot(improvedBundle);

    const regressedEvidence: EvidenceIndex = {
      ...(improvedBundle.evidenceIndex as EvidenceIndex),
      coverage_stmt: [],
    };
    const regressedBundle: ImportBundle = {
      ...improvedBundle,
      generatedAt: '2024-03-01T10:00:00Z',
      evidenceIndex: regressedEvidence,
    };

    const finalSnapshot = generateComplianceSnapshot(regressedBundle, {
      includeRisk: true,
      risk: {
        snapshotHistory: [
          {
            version: baseline.version,
            generatedAt: baseline.generatedAt,
            objectives: baseline.objectives,
          },
          {
            version: improvedSnapshot.version,
            generatedAt: improvedSnapshot.generatedAt,
            objectives: improvedSnapshot.objectives,
          },
        ],
      },
    });

    expect(finalSnapshot.risk?.complianceDelta?.steps).toHaveLength(2);
    expect(finalSnapshot.risk?.complianceDelta?.totals.improvements).toBeGreaterThan(0);

    const improvementStep = finalSnapshot.risk?.complianceDelta?.steps[0];
    expect(improvementStep?.improvements.map((entry) => entry.objectiveId)).toContain('A-6-02');

    const latest = finalSnapshot.risk?.complianceDelta?.latest;
    expect(latest?.regressions.map((entry) => entry.objectiveId)).toContain('A-5-08');
    expect(finalSnapshot.risk?.complianceDelta?.totals.regressions).toBe(1);
  });
});

describe('Quality checks', () => {
  it('identifies verified requirements without supporting tests or coverage', () => {
    const requirement = createRequirement('REQ-Q', 'Quality rule', { status: 'verified' });
    const bundle: ImportBundle = {
      requirements: [requirement],
      objectives: [],
      testResults: [],
      coverage: undefined,
      structuralCoverage: undefined,
      evidenceIndex: {},
      traceLinks: [],
      testToCodeMap: {},
      generatedAt: '2024-03-01T08:00:00Z',
    };

    const snapshot = generateComplianceSnapshot(bundle);

    expect(snapshot.qualityFindings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'REQ-Q-verified-no-tests', severity: 'error', category: 'trace' }),
        expect.objectContaining({ id: 'REQ-Q-coverage-missing', severity: 'error', category: 'coverage' }),
      ]),
    );
  });

  it('reports failing verification tests and partial coverage', () => {
    const requirement = createRequirement('REQ-F', 'Failing verification', { status: 'verified' });
    const test: TestResult = {
      testId: 'TC-F-1',
      className: 'VerificationSuite',
      name: 'should satisfy requirement',
      status: 'failed',
      duration: 5,
      requirementsRefs: ['REQ-F'],
    };
    const coverage: CoverageReport = {
      totals: {
        statements: { covered: 1, total: 2, percentage: 50 },
        mcdc: { covered: 0, total: 2, percentage: 0 },
      },
      files: [
        {
          file: 'src/control/module.c',
          statements: { covered: 1, total: 2, percentage: 50 },
          mcdc: { covered: 0, total: 2, percentage: 0 },
        },
      ],
    };

    const bundle: ImportBundle = {
      requirements: [requirement],
      designs: [
        createDesignRecord('DES-F', 'Control logic design', {
          status: 'implemented',
          requirementRefs: ['REQ-F'],
          codeRefs: ['src/control/module.c'],
        }),
      ],
      objectives: [],
      testResults: [test],
      coverage,
      structuralCoverage: undefined,
      evidenceIndex: {},
      traceLinks: [],
      testToCodeMap: { 'TC-F-1': ['src/control/module.c'] },
      generatedAt: '2024-03-02T09:00:00Z',
    };

    const snapshot = generateComplianceSnapshot(bundle);

    expect(snapshot.qualityFindings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'REQ-F-verified-failing-tests', severity: 'error', category: 'tests' }),
        expect.objectContaining({ id: 'REQ-F-coverage-partial', severity: 'warn', category: 'coverage' }),
      ]),
    );
  });

  it('flags ambiguous DO-178C wording for requirements', () => {
    const requirement = createRequirement('REQ-CLAR', 'Authentication requirement TBD', {
      status: 'draft',
      description: 'The login process shall be tested as appropriate and TBD until criteria are defined.',
    });
    const bundle: ImportBundle = {
      requirements: [requirement],
      objectives: [],
      testResults: [],
      coverage: undefined,
      structuralCoverage: undefined,
      evidenceIndex: {},
      traceLinks: [],
      testToCodeMap: {},
      generatedAt: '2024-03-05T12:00:00Z',
    };

    const snapshot = generateComplianceSnapshot(bundle);

    expect(snapshot.qualityFindings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'REQ-CLAR-clarity-placeholder-tbd', severity: 'warn', category: 'analysis' }),
        expect.objectContaining({ id: 'REQ-CLAR-clarity-as-appropriate', severity: 'warn', category: 'analysis' }),
        expect.objectContaining({ id: 'REQ-CLAR-clarity-passive-voice', severity: 'warn', category: 'analysis' }),
      ]),
    );
  });

  it('raises clarity conflicts when verified requirements retain placeholders or mismatched status tags', () => {
    const requirement = createRequirement('REQ-STAT', 'Finalized safety constraint', {
      status: 'verified',
      description: 'Verification evidence TBD pending DER approval.',
      tags: ['draft', 'safety-critical'],
    });
    const bundle: ImportBundle = {
      requirements: [requirement],
      objectives: [],
      testResults: [],
      coverage: undefined,
      structuralCoverage: undefined,
      evidenceIndex: {},
      traceLinks: [],
      testToCodeMap: {},
      generatedAt: '2024-03-06T12:00:00Z',
    };

    const snapshot = generateComplianceSnapshot(bundle);

    expect(snapshot.qualityFindings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'REQ-STAT-clarity-status-placeholder', severity: 'error', category: 'analysis' }),
        expect.objectContaining({ id: 'REQ-STAT-clarity-status-tag-conflict', severity: 'warn', category: 'analysis' }),
      ]),
    );
  });

  it('flags unresolved static analysis findings as quality alerts', () => {
    const requirement = createRequirement('REQ-SA', 'Static analysis watch', { status: 'draft' });
    const bundle: ImportBundle = {
      requirements: [requirement],
      objectives: [],
      testResults: [],
      coverage: undefined,
      structuralCoverage: undefined,
      evidenceIndex: {},
      traceLinks: [],
      testToCodeMap: {},
      generatedAt: '2024-03-02T09:00:00Z',
      findings: [
        {
          tool: 'polyspace',
          id: 'PS-900',
          severity: 'error',
          status: 'unproved',
          message: 'potential overflow in guidance logic',
        },
        {
          tool: 'ldra',
          id: 'L-210',
          severity: 'warn',
          status: 'closed',
          message: 'style deviation resolved',
        },
      ],
    };

    const snapshot = generateComplianceSnapshot(bundle);

    expect(snapshot.qualityFindings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: 'analysis-polyspace-PS-900',
          category: 'analysis',
          severity: 'error',
        }),
      ]),
    );
    expect(snapshot.qualityFindings.find((finding) => finding.id === 'analysis-ldra-L-210')).toBeUndefined();
  });
});

describe('TraceSuggestions', () => {
  it('suggests trace links from test identifiers and coverage maps', () => {
    const requirement = createRequirement('REQ-LOG-1', 'Logging requirement', { status: 'draft' });
    const bundle: ImportBundle = {
      requirements: [requirement],
      objectives: [],
      testResults: [
        {
          testId: 'TC-REQ-LOG-1',
          className: 'LoggingSuite',
          name: 'REQ-LOG-1 ensures logging',
          status: 'passed',
          duration: 5,
        },
      ],
      coverage: undefined,
      structuralCoverage: undefined,
      evidenceIndex: {},
      traceLinks: [],
      testToCodeMap: { 'TC-REQ-LOG-1': ['src/logging/logger.c'] },
      generatedAt: '2024-03-02T09:00:00Z',
    };

    const snapshot = generateComplianceSnapshot(bundle);

    expect(snapshot.traceSuggestions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          requirementId: 'REQ-LOG-1',
          type: 'test',
          targetId: 'TC-REQ-LOG-1',
          confidence: 'high',
        }),
        expect.objectContaining({
          requirementId: 'REQ-LOG-1',
          type: 'code',
          targetId: 'src/logging/logger.c',
          viaTestId: 'TC-REQ-LOG-1',
        }),
      ]),
    );
  });

  it('scores paraphrased requirement titles using TF-IDF similarity and provides rationale', () => {
    const requirement = createRequirement('REQ-AUDIT-ROT', 'Audit kayıtları döngüsel tutulmalı', {
      status: 'verified',
      description: 'Sistem logları kapasite dolmadan önce otomatik döndürülür.',
    });
    const bundle: ImportBundle = {
      requirements: [requirement],
      objectives: [],
      testResults: [
        {
          testId: 'TC-AUDIT-ROTATE',
          className: 'AuditSuite',
          name: 'Audit log rotation persists events',
          status: 'passed',
          duration: 4,
        },
        {
          testId: 'TC-NOISE',
          className: 'MiscSuite',
          name: 'Handles unrelated telemetry',
          status: 'passed',
          duration: 3,
        },
      ],
      coverage: undefined,
      structuralCoverage: undefined,
      evidenceIndex: {},
      traceLinks: [],
      testToCodeMap: { 'TC-AUDIT-ROTATE': ['src/security/audit_log.c'] },
      generatedAt: '2024-03-03T10:00:00Z',
    };

    const snapshot = generateComplianceSnapshot(bundle);

    const rotationSuggestion = snapshot.traceSuggestions.find(
      (suggestion) => suggestion.targetId === 'TC-AUDIT-ROTATE',
    );
    expect(rotationSuggestion).toBeDefined();
    expect(rotationSuggestion?.confidence === 'high' || rotationSuggestion?.confidence === 'medium').toBe(true);
    expect(rotationSuggestion?.reason).toContain('TF-IDF');

    const unrelatedSuggestion = snapshot.traceSuggestions.find(
      (suggestion) => suggestion.targetId === 'TC-NOISE',
    );
    expect(unrelatedSuggestion).toBeUndefined();
  });
});

