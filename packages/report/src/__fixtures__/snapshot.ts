import { createHash } from 'crypto';

import { CoverageReport, CoverageSummary, TestResult } from '@soipack/adapters';
import {
  Evidence,
  EvidenceSource,
  Objective,
  ObjectiveArtifactType,
  createRequirement,
  createSnapshotIdentifier,
  createSnapshotVersion,
} from '@soipack/core';
import {
  ComplianceSnapshot,
  type ComplianceDeltaSnapshot,
  ImportBundle,
  RequirementTrace,
  TraceEngine,
  generateComplianceSnapshot,
} from '@soipack/engine';
import type { AuditFlagSignal, CoverageSnapshot } from '@soipack/engine';

import type { SignoffTimelineEntry } from '../index';

export interface ReportFixture {
  snapshot: ComplianceSnapshot;
  traces: RequirementTrace[];
  objectives: Objective[];
  manifestId: string;
  signoffs: SignoffTimelineEntry[];
  programName: string;
  certificationLevel: string;
  projectVersion: string;
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
): Evidence => {
  const timestamp = '2024-01-10T09:30:00Z';
  const fingerprint = createHash('sha256')
    .update(`${artifact}:${path}:${summary}`)
    .digest('hex');
  return {
    source: evidenceSourceMap[artifact] ?? 'other',
    path,
    summary,
    timestamp,
    snapshotId: createSnapshotIdentifier(timestamp, fingerprint),
  };
};

export const coverageSummaryFixture = (): CoverageReport => ({
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

const coverageHistoryFixture = (): CoverageSnapshot[] => [
  { timestamp: '2023-12-20T12:00:00Z', coverage: 60 },
  { timestamp: '2024-01-05T12:00:00Z', coverage: 63 },
  { timestamp: '2024-01-15T12:00:00Z', coverage: 65 },
  { timestamp: '2024-02-01T12:00:00Z', coverage: 68 },
];

const auditFlagsFixture = (): AuditFlagSignal[] => [
  { severity: 'high', acknowledged: false, ageDays: 14 },
  { severity: 'medium', acknowledged: true, ageDays: 6 },
];

const objectivesFixture = (): Objective[] => [
  {
    id: 'A-3-04',
    table: 'A-3',
    stage: 'SOI-1',
    name: 'Doğrulama Stratejisi',
    desc: 'Gözden geçirme, analiz ve test stratejisi ve kriterleri tanımlı.',
    artifacts: ['plan', 'review'],
    levels: allLevels,
    independence: 'required',
  },
  {
    id: 'A-4-01',
    table: 'A-4',
    stage: 'SOI-2',
    name: 'Üst Düzey Gereksinimler',
    desc: 'HLR doğru, tutarlı, izlenebilir ve test edilebilir.',
    artifacts: ['analysis', 'trace', 'review'],
    levels: allLevels,
    independence: 'required',
  },
  {
    id: 'A-5-06',
    table: 'A-5',
    stage: 'SOI-3',
    name: 'Test Stratejisi Uygulandı',
    desc: 'Gereksinim-tabanlı testler koşuldu; sonuçlar kaydedildi.',
    artifacts: ['test', 'trace', 'analysis'],
    levels: allLevels,
    independence: 'required',
  },
  {
    id: 'A-5-08',
    table: 'A-5',
    stage: 'SOI-3',
    name: 'Yapısal Kapsam—Statement',
    desc: 'Kod satır kapsamı ölçüldü ve açıklandı.',
    artifacts: ['coverage_stmt', 'analysis'],
    levels: noDLevels,
    independence: 'required',
  },
  {
    id: 'A-6-02',
    table: 'A-6',
    stage: 'SOI-3',
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

export const signoffTimelineFixture = (): SignoffTimelineEntry[] => [
  {
    id: 'signoff-001',
    documentId: 'DOC-SEC-PLAN',
    revisionId: 'rev-main-001',
    revisionHash: 'a9f4c2d1e3b56789',
    requestedBy: 'auditor-istanbul',
    requestedFor: 'lead-reviewer',
    requestedAt: '2024-01-15T09:45:00Z',
    status: 'approved',
    approvedAt: '2024-01-16T13:20:00Z',
    signerId: 'lead-reviewer',
    signerPublicKey: 'MCowBQYDK2VwAyEA7L9sExampleKeyFragment123456==',
    signature: 'SIG-APPROVED-001-BASE64',
    workspaceId: 'workspace-flight',
  },
  {
    id: 'signoff-002',
    documentId: 'DOC-SEC-REPORT',
    revisionId: 'rev-main-002',
    revisionHash: 'b1e2c3d4f5a67890',
    requestedBy: 'auditor-istanbul',
    requestedFor: 'compliance-owner',
    requestedAt: '2024-01-20T10:15:00Z',
    status: 'pending',
    signerPublicKey: null,
    signature: null,
    workspaceId: 'workspace-flight',
  },
];

export const createReportFixture = (): ReportFixture => {
  const programName = 'Flight Control Modernizasyonu';
  const certificationLevel = 'DO-178C Seviye A';
  const projectVersion = 'v2.3.1';
  const requirements = requirementFixture();
  const objectives = objectivesFixture();
  const baseTestResults = testResultsFixture();
  const currentTestResults: TestResult[] = [
    ...baseTestResults.map((test) => ({ ...test })),
    {
      testId: 'TC-AUDIT-NEW',
      className: 'AuditFlow',
      name: 'ek audit bildirimleri kaydedilmeli',
      status: 'failed',
      duration: 6,
      requirementsRefs: ['REQ-AUTH-3'],
    },
  ];
  const coverage = coverageSummaryFixture();
  const structuralCoverage = structuralCoverageFixture();
  const evidenceIndex = evidenceFixture();
  const findings = [
    {
      tool: 'polyspace' as const,
      id: 'FND-SEC-001',
      severity: 'error' as const,
      message: 'Null pointer analizi başarısız oldu.',
      status: 'open' as const,
    },
    {
      tool: 'vectorcast' as const,
      id: 'FND-SEC-002',
      severity: 'warn' as const,
      message: 'Zamanlama toleransı azalıyor.',
      status: 'open' as const,
    },
  ];
  const testToCodeMap: ImportBundle['testToCodeMap'] = {
    'TC-LOGIN-1': ['src/auth/login.ts'],
    'TC-LOGIN-2': ['src/auth/login.ts', 'src/security/audit.ts'],
    'TC-AUDIT-1': ['src/security/audit.ts'],
    'TC-AUDIT-2': ['src/security/audit.ts'],
    'TC-AUDIT-NEW': ['src/security/new-audit.ts'],
  };
  const bundle: ImportBundle = {
    requirements,
    objectives,
    testResults: currentTestResults,
    coverage,
    structuralCoverage,
    evidenceIndex,
    findings,
    testToCodeMap,
    generatedAt: '2024-02-01T12:00:00Z',
  };

  const baselineBundle: ImportBundle = {
    ...bundle,
    testResults: baseTestResults.map((test) => ({ ...test, status: 'passed' as const })),
    testToCodeMap: {
      'TC-LOGIN-1': ['src/auth/login.ts', 'src/auth/legacy.ts'],
      'TC-LOGIN-2': ['src/auth/login.ts', 'src/security/audit.ts'],
      'TC-AUDIT-1': ['src/security/audit.ts'],
      'TC-AUDIT-2': ['src/security/audit.ts'],
    },
  };

  const baselineEngine = new TraceEngine(baselineBundle);
  const baselineGraph = baselineEngine.getGraph();
  const baselineSnapshot = generateComplianceSnapshot(baselineBundle);

  const downgradeStatus = (status: ComplianceSnapshot['objectives'][number]['status']):
    ComplianceSnapshot['objectives'][number]['status'] => {
      if (status === 'covered') {
        return 'partial';
      }
      if (status === 'partial') {
        return 'missing';
      }
      return 'missing';
    };

  const upgradeStatus = (status: ComplianceSnapshot['objectives'][number]['status']):
    ComplianceSnapshot['objectives'][number]['status'] => {
      if (status === 'missing') {
        return 'partial';
      }
      if (status === 'partial') {
        return 'covered';
      }
      return 'covered';
    };

  const buildHistoryEntry = (seed: string, createdAt: string, mapper: (status: ComplianceSnapshot['objectives'][number]['status']) => ComplianceSnapshot['objectives'][number]['status']): ComplianceDeltaSnapshot => {
    const fingerprint = createHash('sha256').update(seed).digest('hex');
    const version = createSnapshotVersion(fingerprint, { createdAt });
    return {
      version,
      generatedAt: createdAt,
      objectives: baselineSnapshot.objectives.map((objective) => ({
        ...objective,
        status: mapper(objective.status),
      })),
    };
  };

  const snapshotHistory: ComplianceDeltaSnapshot[] = [
    buildHistoryEntry('history:downgrade', '2024-01-10T00:00:00Z', downgradeStatus),
    buildHistoryEntry('history:upgrade', '2024-01-20T00:00:00Z', upgradeStatus),
  ];

  const snapshot = generateComplianceSnapshot(
    { ...bundle, snapshot: baselineSnapshot.version },
    {
      includeRisk: true,
      risk: {
        audit: auditFlagsFixture(),
        coverageHistory: coverageHistoryFixture(),
        snapshotHistory,
      },
      changeImpactBaseline: baselineGraph,
    },
  );
  const objectiveConfidence: Record<string, number> = {
    'A-3-04': 0.92,
    'A-4-01': 0.68,
    'A-5-06': 0.41,
    'A-5-08': 0.27,
  };
  (snapshot.objectives as Array<
    (typeof snapshot.objectives)[number] & { confidence?: number }
  >).forEach((objective) => {
    const value = objectiveConfidence[objective.objectiveId];
    if (value !== undefined) {
      objective.confidence = value;
    }
  });
  const engine = new TraceEngine(bundle);
  const traces = requirements.map((requirement) => engine.getRequirementTrace(requirement.id));
  const signoffs = signoffTimelineFixture();

  snapshot.gaps.staleEvidence = [
    {
      objectiveId: 'A-1-01',
      artifactType: 'plan',
      latestEvidenceTimestamp: '2023-12-28T10:00:00Z',
      reasons: ['exceedsMaxAge'],
      ageDays: 95,
      maxAgeDays: 60,
    },
    {
      objectiveId: 'A-2-05',
      artifactType: 'analysis',
      latestEvidenceTimestamp: '2023-11-15T09:00:00Z',
      reasons: ['beforeSnapshot'],
      ageDays: 140,
      maxAgeDays: 120,
    },
    {
      objectiveId: 'A-3-04',
      artifactType: 'test',
      latestEvidenceTimestamp: '2023-07-03T09:00:00Z',
      reasons: ['exceedsMaxAge'],
      ageDays: 210,
      maxAgeDays: 150,
    },
    {
      objectiveId: 'A-3-04',
      artifactType: 'trace',
      latestEvidenceTimestamp: '2023-12-05T09:00:00Z',
      reasons: ['beforeSnapshot'],
    },
    {
      objectiveId: 'A-5-06',
      artifactType: 'test',
      latestEvidenceTimestamp: '2023-09-18T09:00:00Z',
      reasons: ['exceedsMaxAge'],
      ageDays: 285,
      maxAgeDays: 150,
    },
  ];

  return {
    snapshot,
    traces,
    objectives,
    manifestId: 'MAN-TR-2024-0001',
    signoffs,
    programName,
    certificationLevel,
    projectVersion,
  };
};
