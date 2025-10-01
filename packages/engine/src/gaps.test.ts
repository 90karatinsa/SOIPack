import type { Evidence, Objective } from '@soipack/core';

import traceFixture from '../test/fixtures/traceability.json';

import {
  TraceabilityGapAnalyzer,
  type TraceabilityModel,
  detectStaleEvidence,
} from './gaps';
import { buildGapAnalysis, type EvidenceIndex, type ObjectiveCoverage } from './index';

describe('TraceabilityGapAnalyzer', () => {
  it('flags missing links and conflicting evidence chains', () => {
    const analyzer = new TraceabilityGapAnalyzer(traceFixture as TraceabilityModel);
    const report = analyzer.analyze();

    expect(report.requirementGaps).toHaveLength(3);
    expect(report.summary.highPriorityRequirements).toEqual(['REQ-2', 'REQ-3', 'REQ-4']);

    const gapIds = report.requirementGaps.map((gap) => gap.requirementId);
    expect(gapIds).toEqual(expect.arrayContaining(['REQ-2', 'REQ-3', 'REQ-4']));

    const requirementTwo = report.requirementGaps.find((gap) => gap.requirementId === 'REQ-2');
    expect(requirementTwo).toBeDefined();
    expect(requirementTwo?.missingDesign).toBe(false);
    expect(requirementTwo?.missingCode).toBe(true);
    expect(requirementTwo?.missingTests).toBe(true);
    expect(requirementTwo?.severity).toBe('high');

    const requirementFour = report.requirementGaps.find((gap) => gap.requirementId === 'REQ-4');
    expect(requirementFour?.missingDesign).toBe(false);
    expect(requirementFour?.missingCode).toBe(false);
    expect(requirementFour?.missingTests).toBe(true);
    expect(requirementFour?.tests).toHaveLength(0);

    expect(report.orphans).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: 'design', id: 'DES-3' }),
        expect.objectContaining({ type: 'code', id: 'CODE-2' }),
        expect.objectContaining({ type: 'test', id: 'TEST-ghost' }),
      ]),
    );

    expect(report.conflicts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ sourceId: 'CODE-4', targetId: 'TEST-4' }),
        expect.objectContaining({ sourceId: 'TEST-2', targetId: 'CODE-2' }),
        expect.objectContaining({ sourceId: 'TEST-4', targetId: 'CODE-X' }),
      ]),
    );
  });
});

const createObjective = (id: string, artifacts: Objective['artifacts'] = ['plan']): Objective => ({
  id,
  table: 'A-3',
  stage: 'SOI-1',
  name: `${id} objective`,
  desc: `${id} objective description`,
  artifacts,
  levels: { A: true, B: true, C: true, D: true, E: true },
  independence: 'none',
});

const createEvidence = (path: string, timestamp: string): Evidence => ({
  source: 'git',
  path,
  summary: `Evidence for ${path}`,
  timestamp,
  snapshotId: '20240101T000000Z-deadbeef',
});

describe('detectStaleEvidence', () => {
  it('flags evidence captured before the snapshot baseline', () => {
    const objectives = [createObjective('A-OBJ-1')];
    const evidenceIndex: EvidenceIndex = {
      plan: [createEvidence('plans/plan.md', '2024-03-01T00:00:00Z')],
    };

    const findings = detectStaleEvidence(objectives, evidenceIndex, {
      snapshotTimestamp: '2024-04-01T00:00:00Z',
      analysisTimestamp: '2024-04-15T00:00:00Z',
      maxAgeDays: null,
    });

    expect(findings).toEqual([
      expect.objectContaining({
        objectiveId: 'A-OBJ-1',
        artifactType: 'plan',
        reasons: ['beforeSnapshot'],
      }),
    ]);
  });

  it('reports evidence that exceeds the allowed age threshold', () => {
    const objectives = [createObjective('A-OBJ-2')];
    const evidenceIndex: EvidenceIndex = {
      plan: [createEvidence('plans/plan.md', '2024-03-01T00:00:00Z')],
    };

    const findings = detectStaleEvidence(objectives, evidenceIndex, {
      analysisTimestamp: '2024-04-20T00:00:00Z',
      maxAgeDays: 30,
    });

    expect(findings).toHaveLength(1);
    expect(findings[0].objectiveId).toBe('A-OBJ-2');
    expect(findings[0].reasons).toContain('exceedsMaxAge');
    expect(findings[0].ageDays).toBeGreaterThan(30);
  });

  it('respects objective-level overrides when computing staleness', () => {
    const objectives = [createObjective('A-RELAXED'), createObjective('A-STRICT')];
    const evidenceIndex: EvidenceIndex = {
      plan: [createEvidence('plans/plan.md', '2024-01-15T00:00:00Z')],
    };

    const findings = detectStaleEvidence(objectives, evidenceIndex, {
      analysisTimestamp: '2024-04-01T00:00:00Z',
      maxAgeDays: 60,
      overrides: { objectives: { 'A-RELAXED': 120 } },
    });

    expect(findings.find((item) => item.objectiveId === 'A-STRICT')).toBeDefined();
    expect(findings.find((item) => item.objectiveId === 'A-RELAXED')).toBeUndefined();
  });

  it('ignores stale warnings when fresher evidence is present', () => {
    const objectives = [createObjective('A-MIXED')];
    const evidenceIndex: EvidenceIndex = {
      plan: [
        createEvidence('plans/plan-old.md', '2024-02-01T00:00:00Z'),
        createEvidence('plans/plan-new.md', '2024-03-28T00:00:00Z'),
      ],
    };

    const findings = detectStaleEvidence(objectives, evidenceIndex, {
      analysisTimestamp: '2024-04-15T00:00:00Z',
      maxAgeDays: 45,
    });

    expect(findings).toHaveLength(0);
  });
});

describe('buildGapAnalysis stale evidence integration', () => {
  it('attaches stale evidence findings to the gap summary', () => {
    const objectives = [createObjective('A-INTEGRATION')];
    const coverage: ObjectiveCoverage[] = [
      {
        objectiveId: 'A-INTEGRATION',
        status: 'covered',
        evidenceRefs: [],
        satisfiedArtifacts: ['plan'],
        missingArtifacts: [],
      },
    ];
    const evidenceIndex: EvidenceIndex = {
      plan: [createEvidence('plans/plan.md', '2024-01-01T00:00:00Z')],
    };

    const gaps = buildGapAnalysis(coverage, {
      objectives,
      evidenceIndex,
      staleEvidence: {
        analysisTimestamp: '2024-04-01T00:00:00Z',
        maxAgeDays: 30,
      },
    });

    expect(gaps.staleEvidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          objectiveId: 'A-INTEGRATION',
          artifactType: 'plan',
          reasons: expect.arrayContaining(['exceedsMaxAge']),
        }),
      ]),
    );
  });
});
