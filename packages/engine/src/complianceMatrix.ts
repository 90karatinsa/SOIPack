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
