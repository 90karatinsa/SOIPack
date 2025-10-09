import type { StaleEvidenceFinding } from '@soipack/engine';

import {
  buildStaleEvidenceHeatmap,
  defaultAgeBands,
  type StaleEvidenceHeatmapBandDefinition,
} from './staleHeatmap';

describe('buildStaleEvidenceHeatmap', () => {
  const stageLookup = new Map([
    ['A-1-01', 'SOI-1'],
    ['A-2-05', 'SOI-2'],
    ['A-3-04', 'SOI-3'],
    ['A-4-01', 'SOI-4'],
  ] as const);

  const findings: StaleEvidenceFinding[] = [
    {
      objectiveId: 'A-1-01',
      artifactType: 'plan',
      latestEvidenceTimestamp: '2024-02-01T10:00:00Z',
      reasons: ['beforeSnapshot'],
      ageDays: 12,
    },
    {
      objectiveId: 'A-2-05',
      artifactType: 'analysis',
      latestEvidenceTimestamp: '2024-01-12T10:00:00Z',
      reasons: ['exceedsMaxAge'],
      ageDays: 120,
      maxAgeDays: 90,
    },
    {
      objectiveId: 'A-2-05',
      artifactType: 'test',
      latestEvidenceTimestamp: '2024-01-15T10:00:00Z',
      reasons: ['beforeSnapshot'],
      ageDays: undefined,
    },
    {
      objectiveId: 'A-4-01',
      artifactType: 'trace',
      latestEvidenceTimestamp: '2023-08-20T10:00:00Z',
      reasons: ['exceedsMaxAge'],
      ageDays: 410,
    },
  ];

  it('buckets findings by stage and age band with sorted labels', () => {
    const heatmap = buildStaleEvidenceHeatmap(findings, {
      stageLookup,
      stageLabels: {
        'SOI-1': 'SOI-1 Planlama',
        'SOI-2': 'SOI-2 Geliştirme',
        'SOI-3': 'SOI-3 Doğrulama',
        'SOI-4': 'SOI-4 Sertifikasyon',
      },
    });

    expect(heatmap).toBeDefined();
    expect(heatmap?.totalFindings).toBe(findings.length);
    expect(heatmap?.bands.map((band) => band.id)).toEqual([
      ...defaultAgeBands.map((band) => band.id),
      'unknown',
    ]);
    expect(heatmap?.stages.map((stage) => stage.id)).toEqual(['SOI-1', 'SOI-2', 'SOI-4']);
    expect(heatmap?.stages[0]?.label).toBe('SOI-1 Planlama');
    expect(heatmap?.stages[1]?.label).toBe('SOI-2 Geliştirme');
    expect(heatmap?.bandTotals['31-90']).toBe(0);
    expect(heatmap?.bandTotals['91-180']).toBe(1);
    expect(heatmap?.bandTotals['366+']).toBe(1);
    expect(heatmap?.bandTotals.unknown).toBe(1);
    expect(heatmap?.stageTotals['SOI-2']).toBe(2);
    expect(heatmap?.maxBucketCount).toBeGreaterThan(0);

    const soi2 = heatmap?.stages.find((stage) => stage.id === 'SOI-2');
    expect(soi2?.buckets.find((bucket) => bucket.bandId === '91-180')?.count).toBe(1);
    expect(soi2?.buckets.find((bucket) => bucket.bandId === 'unknown')?.count).toBe(1);
    expect(soi2?.buckets.find((bucket) => bucket.bandId === 'unknown')?.objectiveIds).toEqual([
      'A-2-05',
    ]);
  });

  it('returns undefined when there are no stale findings', () => {
    const heatmap = buildStaleEvidenceHeatmap([], { stageLookup });
    expect(heatmap).toBeUndefined();
  });

  it('supports custom age bands and stage labels', () => {
    const customBands: StaleEvidenceHeatmapBandDefinition[] = [
      { id: '0-14', label: '0-14 gün', minDays: 0, maxDays: 14 },
      { id: '15-60', label: '15-60 gün', minDays: 15, maxDays: 60 },
      { id: '61+', label: '61+ gün', minDays: 61 },
    ];

    const heatmap = buildStaleEvidenceHeatmap(findings.slice(0, 2), {
      stageLookup,
      stageLabels: { 'SOI-1': 'SOI-1', 'SOI-2': 'SOI-2' },
      ageBands: customBands,
      unknownBandLabel: 'Yaş tespit edilemedi',
      unknownStageLabel: 'Bilinmeyen',
    });

    expect(heatmap?.bands.map((band) => band.id)).toEqual(['0-14', '15-60', '61+']);
    expect(heatmap?.bandTotals['0-14']).toBe(1);
    expect(heatmap?.bandTotals['61+']).toBe(1);
    expect(heatmap?.stages.map((stage) => stage.label)).toEqual(['SOI-1', 'SOI-2']);
    expect(heatmap?.bands[0]).not.toBe(customBands[0]);
    expect(customBands).toEqual([
      { id: '0-14', label: '0-14 gün', minDays: 0, maxDays: 14 },
      { id: '15-60', label: '15-60 gün', minDays: 15, maxDays: 60 },
      { id: '61+', label: '61+ gün', minDays: 61 },
    ]);
  });
});
