import { createHash } from 'crypto';

import {
  Evidence,
  Objective,
  ObjectiveArtifactType,
  createSnapshotIdentifier,
} from '@soipack/core';

import { buildComplianceMatrix } from './complianceMatrix';
import type { EvidenceIndex } from './index';

const evidence = (
  type: ObjectiveArtifactType,
  path: string,
  source: Evidence['source'],
): Evidence => ({
  source,
  path,
  summary: `${type} evidence`,
  timestamp: '2024-01-10T10:00:00Z',
  snapshotId: createSnapshotIdentifier(
    '2024-01-10T10:00:00Z',
    createHash('sha256').update(`${type}:${path}`).digest('hex'),
  ),
});

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

describe('complianceMatrix', () => {
  const objectives = objectivesFixture();

  const levelAEvidence: EvidenceIndex = {
    plan: [evidence('plan', 'plans/psac.md', 'git')],
    review: [evidence('review', 'reviews/plan-review.md', 'git')],
    analysis: [evidence('analysis', 'analysis/safety.md', 'git')],
    test: [evidence('test', 'reports/junit.xml', 'junit')],
    trace: [evidence('trace', 'traces/hlr.csv', 'git')],
    coverage_stmt: [evidence('coverage_stmt', 'coverage/lcov.info', 'lcov')],
    coverage_mcdc: [evidence('coverage_mcdc', 'coverage/mcdc.json', 'vectorcast')],
    cm_record: [evidence('cm_record', 'cm/register.csv', 'git')],
  };

  it('summarizes satisfied and partial objectives for level A', () => {
    const matrix = buildComplianceMatrix({
      level: 'A',
      evidenceIndex: levelAEvidence,
      objectives,
    });

    expect(matrix.summary).toEqual({ satisfied: 6, partial: 2, missing: 0, notApplicable: 0 });
    const decisionCoverage = matrix.tables
      .find((table) => table.table === 'A-5')
      ?.objectives.find((entry) => entry.objective.id === 'A-5-09');
    expect(decisionCoverage?.status).toBe('partial');
    expect(decisionCoverage?.missingArtifacts).toEqual(['coverage_dec']);
  });

  it('marks MC/DC objectives as not applicable for level B', () => {
    const matrix = buildComplianceMatrix({
      level: 'B',
      evidenceIndex: levelAEvidence,
      objectives,
    });

    const mcDc = matrix.tables
      .find((table) => table.table === 'A-5')
      ?.objectives.find((entry) => entry.objective.id === 'A-5-10');

    expect(mcDc?.status).toBe('not-applicable');
    expect(mcDc?.missingArtifacts).toEqual([]);
    expect(matrix.summary.notApplicable).toBe(1);
  });

  it('flags missing structural coverage evidence for level C bundles', () => {
    const leanEvidence: EvidenceIndex = {
      plan: [evidence('plan', 'plans/psac.md', 'git')],
      test: [evidence('test', 'reports/junit.xml', 'junit')],
    };

    const matrix = buildComplianceMatrix({ level: 'C', evidenceIndex: leanEvidence, objectives });

    const tableA5 = matrix.tables.find((table) => table.table === 'A-5');
    const statementCoverage = tableA5?.objectives.find((entry) => entry.objective.id === 'A-5-08');
    const decisionCoverage = tableA5?.objectives.find((entry) => entry.objective.id === 'A-5-09');

    expect(statementCoverage?.status).toBe('missing');
    expect(statementCoverage?.missingArtifacts).toEqual(['coverage_stmt', 'analysis']);
    expect(decisionCoverage?.status).toBe('not-applicable');
    expect(decisionCoverage?.missingArtifacts).toEqual([]);
  });

  it('filters objectives by SOI stage when requested', () => {
    const matrix = buildComplianceMatrix({
      level: 'A',
      evidenceIndex: levelAEvidence,
      objectives,
      stage: 'SOI-1',
    });

    expect(matrix.stage).toBe('SOI-1');
    expect(matrix.tables).toHaveLength(1);
    expect(matrix.tables[0]?.table).toBe('A-3');
    expect(matrix.summary).toEqual({ satisfied: 2, partial: 0, missing: 0, notApplicable: 0 });
  });

  it('returns an empty matrix for stages without objectives', () => {
    const matrix = buildComplianceMatrix({
      level: 'A',
      evidenceIndex: levelAEvidence,
      objectives,
      stage: 'SOI-4',
    });

    expect(matrix.stage).toBe('SOI-4');
    expect(matrix.tables).toHaveLength(0);
    expect(matrix.summary).toEqual({ satisfied: 0, partial: 0, missing: 0, notApplicable: 0 });
    expect(matrix.warnings).toHaveLength(0);
  });
});
