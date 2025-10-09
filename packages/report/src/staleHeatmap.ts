import { soiStages, type SoiStage } from '@soipack/core';
import type { StaleEvidenceFinding } from '@soipack/engine';

export interface StaleEvidenceHeatmapBandDefinition {
  id: string;
  label: string;
  minDays?: number;
  maxDays?: number;
}

export interface StaleEvidenceHeatmapBucketView {
  bandId: string;
  label: string;
  count: number;
  objectiveIds: string[];
}

export interface StaleEvidenceHeatmapStageView {
  id: string;
  label: string;
  stage?: SoiStage;
  totals: number;
  buckets: StaleEvidenceHeatmapBucketView[];
}

export interface StaleEvidenceHeatmapView {
  totalFindings: number;
  updatedAt?: string;
  maxBucketCount: number;
  bands: StaleEvidenceHeatmapBandDefinition[];
  stages: StaleEvidenceHeatmapStageView[];
  stageTotals: Record<string, number>;
  bandTotals: Record<string, number>;
}

export interface BuildStaleEvidenceHeatmapOptions {
  stageLookup?: Map<string, SoiStage | undefined>;
  stageLabels?: Partial<Record<SoiStage, string>>;
  unknownStageLabel?: string;
  unknownBandLabel?: string;
  ageBands?: StaleEvidenceHeatmapBandDefinition[];
}

const DEFAULT_UNKNOWN_STAGE_LABEL = 'Bilinmeyen Aşama';
const DEFAULT_UNKNOWN_BAND_LABEL = 'Yaş bilinmiyor';

export const defaultAgeBands: StaleEvidenceHeatmapBandDefinition[] = [
  { id: '0-30', label: '0-30 gün', minDays: 0, maxDays: 30 },
  { id: '31-90', label: '31-90 gün', minDays: 31, maxDays: 90 },
  { id: '91-180', label: '91-180 gün', minDays: 91, maxDays: 180 },
  { id: '181-365', label: '181-365 gün', minDays: 181, maxDays: 365 },
  { id: '366+', label: '366+ gün', minDays: 366 },
];

const normalizeBands = (
  bands?: StaleEvidenceHeatmapBandDefinition[],
): StaleEvidenceHeatmapBandDefinition[] => {
  const list = (bands ?? defaultAgeBands).map((band) => ({ ...band }));
  list.sort((left, right) => {
    const leftMin = left.minDays ?? Number.NEGATIVE_INFINITY;
    const rightMin = right.minDays ?? Number.NEGATIVE_INFINITY;
    if (leftMin === rightMin) {
      const leftMax = left.maxDays ?? Number.POSITIVE_INFINITY;
      const rightMax = right.maxDays ?? Number.POSITIVE_INFINITY;
      if (leftMax === rightMax) {
        return left.label.localeCompare(right.label, 'tr');
      }
      return leftMax - rightMax;
    }
    return leftMin - rightMin;
  });
  return list;
};

const resolveBand = (
  ageDays: number | undefined,
  bands: StaleEvidenceHeatmapBandDefinition[],
  unknownBand: StaleEvidenceHeatmapBandDefinition,
): StaleEvidenceHeatmapBandDefinition => {
  if (ageDays === undefined || !Number.isFinite(ageDays)) {
    return unknownBand;
  }
  for (const band of bands) {
    const min = band.minDays ?? Number.NEGATIVE_INFINITY;
    const max = band.maxDays ?? Number.POSITIVE_INFINITY;
    if (ageDays >= min && ageDays <= max) {
      return band;
    }
  }
  return bands[bands.length - 1] ?? unknownBand;
};

const resolveStageLabel = (
  stage: SoiStage | undefined,
  stageLabels?: Partial<Record<SoiStage, string>>,
): string | undefined => (stage ? stageLabels?.[stage] : undefined);

export const buildStaleEvidenceHeatmap = (
  findings: StaleEvidenceFinding[],
  options: BuildStaleEvidenceHeatmapOptions = {},
): StaleEvidenceHeatmapView | undefined => {
  if (!findings.length) {
    return undefined;
  }

  const stageLookup = options.stageLookup ?? new Map<string, SoiStage | undefined>();
  const normalizedBands = normalizeBands(options.ageBands);
  const unknownBand: StaleEvidenceHeatmapBandDefinition = {
    id: 'unknown',
    label: options.unknownBandLabel ?? DEFAULT_UNKNOWN_BAND_LABEL,
  };

  let includeUnknownBand = false;
  const bandTotals: Record<string, number> = Object.fromEntries(
    normalizedBands.map((band) => [band.id, 0]),
  );
  const stageTotals: Record<string, number> = {};
  const stageBuckets = new Map<
    string,
    {
      stage?: SoiStage;
      label: string;
      buckets: Map<string, { count: number; objectiveIds: Set<string>; label: string }>;
    }
  >();

  let maxBucketCount = 0;
  let latestTimestamp = Number.NEGATIVE_INFINITY;

  const ensureStageEntry = (stageId: string, stage?: SoiStage): void => {
    if (stageBuckets.has(stageId)) {
      return;
    }
    const label =
      resolveStageLabel(stage, options.stageLabels) ?? stage ?? options.unknownStageLabel ?? DEFAULT_UNKNOWN_STAGE_LABEL;
    const bucketMap = new Map<string, { count: number; objectiveIds: Set<string>; label: string }>();
    normalizedBands.forEach((band) => {
      bucketMap.set(band.id, { count: 0, objectiveIds: new Set(), label: band.label });
    });
    stageBuckets.set(stageId, { stage, label, buckets: bucketMap });
  };

  findings.forEach((finding) => {
    const stage = stageLookup.get(finding.objectiveId);
    const stageId = stage ?? 'unknown';
    ensureStageEntry(stageId, stage);

    const parsed = Date.parse(finding.latestEvidenceTimestamp);
    if (Number.isFinite(parsed) && parsed > latestTimestamp) {
      latestTimestamp = parsed;
    }

    const band = resolveBand(finding.ageDays, normalizedBands, unknownBand);
    if (band.id === unknownBand.id) {
      includeUnknownBand = true;
    }

    const stageEntry = stageBuckets.get(stageId)!;
    if (!stageEntry.buckets.has(band.id)) {
      stageEntry.buckets.set(band.id, {
        count: 0,
        objectiveIds: new Set<string>(),
        label: band.label,
      });
    }
    const bucket = stageEntry.buckets.get(band.id)!;
    bucket.count += 1;
    bucket.objectiveIds.add(finding.objectiveId);
    stageTotals[stageId] = (stageTotals[stageId] ?? 0) + 1;
    bandTotals[band.id] = (bandTotals[band.id] ?? 0) + 1;
    if (bucket.count > maxBucketCount) {
      maxBucketCount = bucket.count;
    }
  });

  if (includeUnknownBand) {
    bandTotals[unknownBand.id] = bandTotals[unknownBand.id] ?? 0;
    normalizedBands.push(unknownBand);
    stageBuckets.forEach((entry) => {
      if (!entry.buckets.has(unknownBand.id)) {
        entry.buckets.set(unknownBand.id, {
          count: 0,
          objectiveIds: new Set<string>(),
          label: unknownBand.label,
        });
      }
    });
  }

  const orderedStages = Array.from(stageBuckets.entries())
    .filter(([, entry]) => {
      const stageId = entry.stage ?? 'unknown';
      return (stageTotals[stageId] ?? 0) > 0;
    })
    .sort((left, right) => {
      const [leftId, leftEntry] = left;
      const [rightId, rightEntry] = right;
      const leftStage = leftEntry.stage;
      const rightStage = rightEntry.stage;
      const leftIndex = leftStage ? soiStages.indexOf(leftStage) : Infinity;
      const rightIndex = rightStage ? soiStages.indexOf(rightStage) : Infinity;
      if (leftIndex !== rightIndex) {
        return leftIndex - rightIndex;
      }
      if (leftStage && rightStage) {
        return leftStage.localeCompare(rightStage, 'tr');
      }
      return leftEntry.label.localeCompare(rightEntry.label, 'tr');
    })
    .map(([stageId, entry]) => {
      const buckets = normalizedBands.map((band) => {
        const bucket = entry.buckets.get(band.id);
        return {
          bandId: band.id,
          label: bucket?.label ?? band.label,
          count: bucket?.count ?? 0,
          objectiveIds: bucket ? Array.from(bucket.objectiveIds).sort((a, b) => a.localeCompare(b, 'tr')) : [],
        } satisfies StaleEvidenceHeatmapBucketView;
      });
      return {
        id: stageId,
        label: entry.label,
        stage: entry.stage,
        totals: stageTotals[stageId] ?? 0,
        buckets,
      } satisfies StaleEvidenceHeatmapStageView;
    });

  const totalFindings = findings.length;
  const updatedAt = Number.isFinite(latestTimestamp) ? new Date(latestTimestamp).toISOString() : undefined;

  return {
    totalFindings,
    updatedAt,
    maxBucketCount,
    bands: normalizedBands.map((band) => ({ ...band })),
    stages: orderedStages,
    stageTotals,
    bandTotals,
  } satisfies StaleEvidenceHeatmapView;
};
