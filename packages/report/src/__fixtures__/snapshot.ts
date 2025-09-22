import { CoverageReport, CoverageSummary, TestResult } from '@soipack/adapters';
import {
  Evidence,
  EvidenceSource,
  Objective,
  ObjectiveArtifactType,
  createRequirement,
} from '@soipack/core';
import {
  ComplianceSnapshot,
  ImportBundle,
  RequirementTrace,
  TraceEngine,
  generateComplianceSnapshot,
} from '@soipack/engine';

export interface ReportFixture {
  snapshot: ComplianceSnapshot;
  traces: RequirementTrace[];
  objectives: Objective[];
  manifestId: string;
}

const allLevels = { A: true, B: true, C: true, D: true, E: false } as const;
const noDLevels = { A: true, B: true, C: true, D: false, E: false } as const;

const evidenceSourceMap: Partial<Record<ObjectiveArtifactType, EvidenceSource>> = {
  plan: 'git',
  analysis: 'other',
  test: 'junit',
  trace: 'git',
  coverage_stmt: 'lcov',
  cm_record: 'git',
  problem_report: 'other',
};

const buildEvidence = (
  artifact: ObjectiveArtifactType,
  path: string,
  summary: string,
): Evidence => ({
  source: evidenceSourceMap[artifact] ?? 'other',
  path,
  summary,
  timestamp: '2024-01-10T09:30:00Z',
});

const coverageFixture = (): CoverageReport => ({
  totals: {
    statements: { covered: 55, total: 80, percentage: 68.75 },
    branches: { covered: 22, total: 40, percentage: 55 },
    functions: { covered: 18, total: 24, percentage: 75 },
    mcdc: { covered: 20, total: 32, percentage: 62.5 },
  },
  files: [
    {
      file: 'src/auth/login.ts',
      statements: { covered: 28, total: 32, percentage: 87.5 },
      branches: { covered: 12, total: 16, percentage: 75 },
      functions: { covered: 8, total: 10, percentage: 80 },
      mcdc: { covered: 12, total: 16, percentage: 75 },
    },
    {
      file: 'src/security/audit.ts',
      statements: { covered: 16, total: 32, percentage: 50 },
      branches: { covered: 6, total: 12, percentage: 50 },
      functions: { covered: 4, total: 8, percentage: 50 },
      mcdc: { covered: 8, total: 16, percentage: 50 },
    },
  ],
});

const structuralCoverageFixture = (): CoverageSummary => ({
  tool: 'vectorcast',
  files: [
    {
      path: 'src/auth/login.ts',
      stmt: { covered: 55, total: 80 },
      dec: { covered: 22, total: 40 },
      mcdc: { covered: 20, total: 32 },
    },
  ],
  objectiveLinks: ['A-5-08'],
});

const testResultsFixture = (): TestResult[] => [
  {
    testId: 'TC-LOGIN-1',
    className: 'AuthenticationFlow',
    name: 'geçerli kullanıcı giriş yapabilmeli',
    status: 'passed',
    duration: 12,
    requirementsRefs: ['REQ-AUTH-1'],
  },
  {
    testId: 'TC-LOGIN-2',
    className: 'AuthenticationFlow',
    name: 'başarısız girişler kilitlenmeli',
    status: 'failed',
    duration: 14,
    requirementsRefs: ['REQ-AUTH-1', 'REQ-AUTH-2'],
  },
  {
    testId: 'TC-AUDIT-1',
    className: 'AuditFlow',
    name: 'denetim kayıtları oluşturulmalı',
    status: 'passed',
    duration: 9,
    requirementsRefs: ['REQ-AUTH-2'],
  },
  {
    testId: 'TC-AUDIT-2',
    className: 'AuditFlow',
    name: 'uyarı bildirimleri gönderilmeli',
    status: 'skipped',
    duration: 7,
    requirementsRefs: ['REQ-AUTH-3'],
  },
];

const objectivesFixture = (): Objective[] => [
  {
    id: 'A-3-04',
    table: 'A-3',
    name: 'Doğrulama Stratejisi',
    desc: 'Gözden geçirme, analiz ve test stratejisi ve kriterleri tanımlı.',
    artifacts: ['plan', 'review'],
    levels: allLevels,
    independence: 'required',
  },
  {
    id: 'A-4-01',
    table: 'A-4',
    name: 'Üst Düzey Gereksinimler',
    desc: 'HLR doğru, tutarlı, izlenebilir ve test edilebilir.',
    artifacts: ['analysis', 'trace', 'review'],
    levels: allLevels,
    independence: 'required',
  },
  {
    id: 'A-5-06',
    table: 'A-5',
    name: 'Test Stratejisi Uygulandı',
    desc: 'Gereksinim-tabanlı testler koşuldu; sonuçlar kaydedildi.',
    artifacts: ['test', 'trace', 'analysis'],
    levels: allLevels,
    independence: 'required',
  },
  {
    id: 'A-5-08',
    table: 'A-5',
    name: 'Yapısal Kapsam—Statement',
    desc: 'Kod satır kapsamı ölçüldü ve açıklandı.',
    artifacts: ['coverage_stmt', 'analysis'],
    levels: noDLevels,
    independence: 'required',
  },
  {
    id: 'A-6-02',
    table: 'A-6',
    name: 'Değişiklik Kontrolü',
    desc: 'Değişiklikler onaylı, izlenebilir ve kayıtlı.',
    artifacts: ['cm_record', 'problem_report'],
    levels: allLevels,
    independence: 'required',
  },
];

const requirementFixture = () => [
  createRequirement('REQ-AUTH-1', 'Çok faktörlü giriş sağlamalı', {
    status: 'approved',
    tags: ['security', 'auth'],
  }),
  createRequirement('REQ-AUTH-2', 'Başarısız girişler kaydedilmeli', {
    status: 'verified',
    tags: ['audit'],
  }),
  createRequirement('REQ-AUTH-3', 'Giriş ihlallerinde uyarı gönderilmeli', {
    status: 'draft',
    tags: ['alerting'],
  }),
];

const evidenceFixture = (): ImportBundle['evidenceIndex'] => ({
  plan: [buildEvidence('plan', 'docs/verification-plan.md', 'Plan doğrulama stratejisi')],
  analysis: [buildEvidence('analysis', 'reports/safety-analysis.pdf', 'Güvenlik analizi özeti')],
  test: [buildEvidence('test', 'reports/junit.xml', 'JUnit sonuçları')],
  trace: [buildEvidence('trace', 'artifacts/trace-map.csv', 'İzlenebilirlik matrisi')],
  coverage_stmt: [
    buildEvidence('coverage_stmt', 'reports/coverage-summary.json', 'Satır kapsamı özeti'),
  ],
  coverage_mcdc: [
    buildEvidence('coverage_mcdc', 'reports/vectorcast.json', 'MC/DC kapsam raporu'),
  ],
});

export const createReportFixture = (): ReportFixture => {
  const requirements = requirementFixture();
  const objectives = objectivesFixture();
  const testResults = testResultsFixture();
  const coverage = coverageFixture();
  const structuralCoverage = structuralCoverageFixture();
  const evidenceIndex = evidenceFixture();
  const bundle: ImportBundle = {
    requirements,
    objectives,
    testResults,
    coverage,
    structuralCoverage,
    evidenceIndex,
    testToCodeMap: {
      'TC-LOGIN-1': ['src/auth/login.ts'],
      'TC-LOGIN-2': ['src/auth/login.ts', 'src/security/audit.ts'],
      'TC-AUDIT-1': ['src/security/audit.ts'],
    },
    generatedAt: '2024-02-01T12:00:00Z',
  };

  const snapshot = generateComplianceSnapshot(bundle);
  const engine = new TraceEngine(bundle);
  const traces = requirements.map((requirement) => engine.getRequirementTrace(requirement.id));

  return {
    snapshot,
    traces,
    objectives,
    manifestId: 'MAN-TR-2024-0001',
  };
};
