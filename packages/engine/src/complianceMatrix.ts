import {
  CertificationLevel,
  Evidence,
  Objective,
  ObjectiveArtifactType,
  ObjectiveTable,
  SoiStage,
  objectiveCatalog,
  objectiveTables,
} from '@soipack/core';

import type { EvidenceIndex } from './index';

export type ObjectiveComplianceStatus =
  | 'satisfied'
  | 'partial'
  | 'missing'
  | 'not-applicable';

export interface ObjectiveEvidenceBundle {
  type: ObjectiveArtifactType;
  items: Evidence[];
}

export interface ComplianceObjectiveResult {
  objective: Objective;
  status: ObjectiveComplianceStatus;
  evidence: ObjectiveEvidenceBundle[];
  evidenceList: Evidence[];
  missingArtifacts: ObjectiveArtifactType[];
  warnings: string[];
  confidenceScore: number;
}

export interface ComplianceMatrixTable {
  table: ObjectiveTable;
  objectives: ComplianceObjectiveResult[];
}

export interface ComplianceMatrixSummary {
  satisfied: number;
  partial: number;
  missing: number;
  notApplicable: number;
}

export interface BuildComplianceMatrixOptions {
  level: CertificationLevel;
  evidenceIndex: EvidenceIndex;
  objectives?: Objective[];
  stage?: SoiStage;
}

export interface ComplianceMatrix {
  level: CertificationLevel;
  stage?: SoiStage;
  tables: ComplianceMatrixTable[];
  summary: ComplianceMatrixSummary;
  warnings: string[];
}

const sortCatalog = (objectives: Objective[]): Objective[] =>
  [...objectives].sort((left, right) => left.id.localeCompare(right.id));

const sortComplianceEntries = (
  entries: ComplianceObjectiveResult[],
): ComplianceObjectiveResult[] =>
  [...entries].sort((left, right) =>
    left.objective.id.localeCompare(right.objective.id),
  );

const summarizeStatus = (
  summary: ComplianceMatrixSummary,
  status: ObjectiveComplianceStatus,
): void => {
  switch (status) {
    case 'satisfied':
      summary.satisfied += 1;
      break;
    case 'partial':
      summary.partial += 1;
      break;
    case 'missing':
      summary.missing += 1;
      break;
    case 'not-applicable':
      summary.notApplicable += 1;
      break;
    default:
      break;
  }
};

const clamp = (value: number, min: number, max: number): number =>
  Math.min(Math.max(value, min), max);

const roundToTwo = (value: number): number => Math.round(value * 100) / 100;

const computeCompletenessScore = (
  bundles: ObjectiveEvidenceBundle[],
  totalArtifacts: number,
): number => {
  if (totalArtifacts === 0) {
    return 1;
  }

  const satisfiedArtifacts = bundles.filter((bundle) => bundle.items.length > 0).length;
  return satisfiedArtifacts / totalArtifacts;
};

const computeIndependenceScore = (
  objective: Objective,
  bundles: ObjectiveEvidenceBundle[],
): number => {
  if (objective.independence === 'none') {
    return 1;
  }

  const hasIndependentEvidence = bundles.some((bundle) =>
    bundle.items.some((item) => item.independent !== false),
  );

  if (hasIndependentEvidence) {
    return 1;
  }

  return objective.independence === 'required' ? 0.4 : 0.7;
};

const computeStalenessScore = (
  bundles: ObjectiveEvidenceBundle[],
  now: number = Date.now(),
): number => {
  const timestamps: number[] = [];
  bundles.forEach((bundle) => {
    bundle.items.forEach((item) => {
      const parsed = Date.parse(item.timestamp);
      if (Number.isFinite(parsed)) {
        timestamps.push(parsed);
      }
    });
  });

  if (timestamps.length === 0) {
    return 0;
  }

  const latestEvidence = Math.max(...timestamps);
  if (!Number.isFinite(latestEvidence)) {
    return 0.5;
  }

  const ageMs = now - latestEvidence;
  if (!Number.isFinite(ageMs)) {
    return 0.5;
  }

  const ageDays = ageMs / (1000 * 60 * 60 * 24);
  if (ageDays <= 0) {
    return 1;
  }
  if (ageDays <= 30) {
    return 1;
  }
  if (ageDays <= 90) {
    return 0.85;
  }
  if (ageDays <= 180) {
    return 0.7;
  }
  if (ageDays <= 365) {
    return 0.5;
  }
  return 0.2;
};

const computeConfidenceScore = (
  objective: Objective,
  status: ObjectiveComplianceStatus,
  bundles: ObjectiveEvidenceBundle[],
): number => {
  if (status === 'not-applicable') {
    return 1;
  }

  const completenessScore = computeCompletenessScore(bundles, objective.artifacts.length);
  if (completenessScore === 0) {
    return 0;
  }

  const independenceScore = computeIndependenceScore(objective, bundles);
  const stalenessScore = computeStalenessScore(bundles);
  const combined = completenessScore * independenceScore * stalenessScore;
  return roundToTwo(clamp(combined, 0, 1));
};

export const buildComplianceMatrix = ({
  level,
  evidenceIndex,
  objectives,
  stage,
}: BuildComplianceMatrixOptions): ComplianceMatrix => {
  const catalog = sortCatalog(objectives ?? objectiveCatalog);
  const filteredCatalog = stage ? catalog.filter((objective) => objective.stage === stage) : catalog;
  const tables = new Map<ObjectiveTable, ComplianceObjectiveResult[]>();
  const summary: ComplianceMatrixSummary = {
    satisfied: 0,
    partial: 0,
    missing: 0,
    notApplicable: 0,
  };
  const globalWarnings = new Set<string>();

  filteredCatalog.forEach((objective) => {
    const bundles: ObjectiveEvidenceBundle[] = objective.artifacts.map((artifact) => ({
      type: artifact,
      items: [...(evidenceIndex[artifact] ?? [])],
    }));
    const missingArtifacts = bundles
      .filter((bundle) => bundle.items.length === 0)
      .map((bundle) => bundle.type);

    const evidenceList = bundles.flatMap((bundle) => bundle.items);
    const entryWarnings: string[] = [];
    const applicable = objective.levels[level];
    let status: ObjectiveComplianceStatus;

    if (!applicable) {
      status = 'not-applicable';
    } else if (missingArtifacts.length === objective.artifacts.length) {
      status = 'missing';
      entryWarnings.push(
        `Objective ${objective.id} has no supporting evidence for required artifacts (${objective.artifacts.join(', ')}).`,
      );
    } else if (missingArtifacts.length > 0) {
      status = 'partial';
      entryWarnings.push(
        `Objective ${objective.id} is missing evidence for: ${missingArtifacts.join(', ')}.`,
      );
    } else {
      status = 'satisfied';
    }

    const finalMissingArtifacts = status === 'not-applicable' ? [] : missingArtifacts;

    summarizeStatus(summary, status);

    entryWarnings.forEach((warning) => globalWarnings.add(warning));

    const tableEntries = tables.get(objective.table) ?? [];
    tableEntries.push({
      objective,
      status,
      evidence: bundles,
      evidenceList,
      missingArtifacts: finalMissingArtifacts,
      warnings: entryWarnings,
      confidenceScore: computeConfidenceScore(objective, status, bundles),
    });
    tables.set(objective.table, tableEntries);
  });

  const orderedTables: ComplianceMatrixTable[] = objectiveTables
    .map((table) => ({
      table,
      objectives: sortComplianceEntries(tables.get(table) ?? []),
    }))
    .filter((entry) => entry.objectives.length > 0);

  return {
    level,
    stage,
    tables: orderedTables,
    summary,
    warnings: Array.from(globalWarnings),
  };
};
