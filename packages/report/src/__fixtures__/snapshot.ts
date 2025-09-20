import { CoverageSummary, TestResult } from '@soipack/adapters';
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

const level = { A: true, B: false, C: false, D: false, E: false } as const;

const evidenceSourceMap: Partial<Record<ObjectiveArtifactType, EvidenceSource>> = {
  testResults: 'junit',
  coverage: 'lcov',
  git: 'git',
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

const coverageFixture = (): CoverageSummary => ({
  totals: {
    statements: { covered: 55, total: 80, percentage: 68.75 },
    branches: { covered: 22, total: 40, percentage: 55 },
    functions: { covered: 18, total: 24, percentage: 75 },
  },
  files: [
    {
      file: 'src/auth/login.ts',
      statements: { covered: 28, total: 32, percentage: 87.5 },
      branches: { covered: 12, total: 16, percentage: 75 },
      functions: { covered: 8, total: 10, percentage: 80 },
    },
    {
      file: 'src/security/audit.ts',
      statements: { covered: 16, total: 32, percentage: 50 },
      branches: { covered: 6, total: 12, percentage: 50 },
      functions: { covered: 4, total: 8, percentage: 50 },
    },
  ],
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
    id: 'OBJ-PLAN-1',
    area: 'Plans',
    description: 'PSAC ve SDP tutarlılığı doğrulanmalı.',
    artifacts: ['psac', 'sdp'],
    level,
  },
  {
    id: 'OBJ-VER-1',
    area: 'Verification',
    description: 'Test sonuçları ve izlenebilirlik kanıtlanmalı.',
    artifacts: ['testResults', 'traceability'],
    level,
  },
  {
    id: 'OBJ-VER-2',
    area: 'Verification',
    description: 'Kod kapsamı düzenli olarak izlenmeli.',
    artifacts: ['coverage'],
    level,
  },
  {
    id: 'OBJ-STND-1',
    area: 'Standards',
    description: 'Konfigürasyon indeksinin güncelliği izlenmeli.',
    artifacts: ['configurationIndex', 'git'],
    level,
  },
];

const requirementFixture = () => [
  createRequirement('REQ-AUTH-1', 'Çok faktörlü giriş sağlamalı', {
    status: 'approved',
    tags: ['security', 'auth'],
  }),
  createRequirement('REQ-AUTH-2', 'Başarısız girişler kaydedilmeli', {
    status: 'implemented',
    tags: ['audit'],
  }),
  createRequirement('REQ-AUTH-3', 'Giriş ihlallerinde uyarı gönderilmeli', {
    status: 'draft',
    tags: ['alerting'],
  }),
];

const evidenceFixture = (): ImportBundle['evidenceIndex'] => ({
  psac: [buildEvidence('psac', 'docs/psac-v1.pdf', 'PSAC onayı')],
  sdp: [],
  testResults: [buildEvidence('testResults', 'reports/junit.xml', 'JUnit sonuçları')],
  traceability: [],
  coverage: [buildEvidence('coverage', 'reports/coverage-summary.json', 'İstanbul kapsama özeti')],
  configurationIndex: [],
  git: [buildEvidence('git', 'git://repo#main', 'Git commit referansı')],
});

export const createReportFixture = (): ReportFixture => {
  const requirements = requirementFixture();
  const objectives = objectivesFixture();
  const testResults = testResultsFixture();
  const coverage = coverageFixture();
  const evidenceIndex = evidenceFixture();
  const bundle: ImportBundle = {
    requirements,
    objectives,
    testResults,
    coverage,
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
