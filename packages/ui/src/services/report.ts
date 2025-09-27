import {
  type ComplianceMatrixPayload,
  type ComplianceObjectiveView,
  type CoverageMetric,
  type RequirementTracePayload,
  type RequirementViewModel,
  type ReportDataset,
  type StageObjectiveView,
  type TestRunStatus,
} from '../types/pipeline';

const selectCoverageMetric = (
  coverage?: {
    statements?: CoverageMetric;
    branches?: CoverageMetric;
    functions?: CoverageMetric;
  },
): CoverageMetric | undefined => {
  if (!coverage) {
    return undefined;
  }
  if (coverage.statements && coverage.statements.total > 0) {
    return coverage.statements;
  }
  if (coverage.functions && coverage.functions.total > 0) {
    return coverage.functions;
  }
  if (coverage.branches && coverage.branches.total > 0) {
    return coverage.branches;
  }
  return undefined;
};

const normalizeTestStatus = (status: TestRunStatus) => {
  switch (status) {
    case 'passed':
      return 'covered' as const;
    case 'failed':
      return 'missing' as const;
    case 'skipped':
    case 'pending':
    default:
      return 'partial' as const;
  }
};

const formatCoverageLabel = (metric?: CoverageMetric): string | undefined => {
  if (!metric) {
    return undefined;
  }
  return `${metric.covered}/${metric.total}`;
};

const buildRequirementView = (
  coverageEntry: ComplianceMatrixPayload['requirementCoverage'][number],
  trace?: RequirementTracePayload,
): RequirementViewModel => {
  const metric = selectCoverageMetric(coverageEntry.coverage);
  const codeMap = new Map<string, { coveragePercent?: number; coverageLabel?: string }>();

  (coverageEntry.codePaths ?? []).forEach((path) => {
    if (!codeMap.has(path)) {
      codeMap.set(path, {});
    }
  });

  trace?.code.forEach((code) => {
    const existing = codeMap.get(code.path) ?? {};
    const codeMetric = selectCoverageMetric(code.coverage);
    if (codeMetric) {
      existing.coveragePercent = codeMetric.percentage;
      existing.coverageLabel = formatCoverageLabel(codeMetric);
    }
    codeMap.set(code.path, existing);
  });

  return {
    id: coverageEntry.requirementId,
    title: trace?.requirement.title ?? coverageEntry.title ?? coverageEntry.requirementId,
    description: trace?.requirement.description,
    requirementStatus: trace?.requirement.status,
    tags: trace?.requirement.tags ?? [],
    coverageStatus: coverageEntry.status,
    coveragePercent: metric?.percentage,
    coverageLabel: formatCoverageLabel(metric),
    code: Array.from(codeMap.entries()).map(([path, info]) => ({
      path,
      coveragePercent: info.coveragePercent,
      coverageLabel: info.coverageLabel,
    })),
    tests: (trace?.tests ?? []).map((test) => ({
      id: test.testId,
      name: test.name,
      status: normalizeTestStatus(test.status),
      result: test.status,
    })),
  };
};

const buildTraceOnlyRequirement = (trace: RequirementTracePayload): RequirementViewModel => {
  const code = trace.code.map((entry) => {
    const metric = selectCoverageMetric(entry.coverage);
    return {
      path: entry.path,
      coveragePercent: metric?.percentage,
      coverageLabel: formatCoverageLabel(metric),
    };
  });

  return {
    id: trace.requirement.id,
    title: trace.requirement.title,
    description: trace.requirement.description,
    requirementStatus: trace.requirement.status,
    tags: trace.requirement.tags ?? [],
    coverageStatus: 'missing',
    coveragePercent: undefined,
    coverageLabel: undefined,
    code,
    tests: trace.tests.map((test) => ({
      id: test.testId,
      name: test.name,
      status: normalizeTestStatus(test.status),
      result: test.status,
    })),
  };
};

export const createReportDataset = (
  reportId: string,
  compliance: ComplianceMatrixPayload,
  traces: RequirementTracePayload[],
): ReportDataset => {
  const traceMap = new Map<string, RequirementTracePayload>();
  traces.forEach((trace) => {
    traceMap.set(trace.requirement.id, trace);
  });

  const requirements = compliance.requirementCoverage.map((entry) => {
    const trace = traceMap.get(entry.requirementId);
    traceMap.delete(entry.requirementId);
    return buildRequirementView(entry, trace);
  });

  traceMap.forEach((trace) => {
    requirements.push(buildTraceOnlyRequirement(trace));
  });

  requirements.sort((a, b) => a.id.localeCompare(b.id));

  const summary = requirements.reduce(
    (acc, item) => {
      acc.total += 1;
      acc[item.coverageStatus] += 1;
      return acc;
    },
    { total: 0, covered: 0, partial: 0, missing: 0 },
  );

  const objectiveLookup = new Map(
    (compliance.objectives ?? []).map((objective) => [objective.id, objective]),
  );

  let objectivesByStage: StageObjectiveView[] = (compliance.stages ?? []).map((stage) => {
    const objectives: ComplianceObjectiveView[] = stage.objectiveIds
      .map((id) => objectiveLookup.get(id))
      .filter((value): value is NonNullable<typeof value> => Boolean(value))
      .map((objective) => ({
        id: objective.id,
        name: objective.name,
        table: objective.table,
        description: objective.desc,
        status: objective.status,
        satisfiedArtifacts: objective.satisfiedArtifacts,
        missingArtifacts: objective.missingArtifacts,
        evidenceRefs: objective.evidenceRefs,
      }));
    return {
      id: stage.id,
      label: stage.label,
      summary: stage.summary,
      objectives,
    };
  });

  if (objectivesByStage.length === 0 && objectiveLookup.size > 0) {
    const fallbackObjectives: ComplianceObjectiveView[] = Array.from(objectiveLookup.values()).map(
      (objective) => ({
        id: objective.id,
        name: objective.name,
        table: objective.table,
        description: objective.desc,
        status: objective.status,
        satisfiedArtifacts: objective.satisfiedArtifacts,
        missingArtifacts: objective.missingArtifacts,
        evidenceRefs: objective.evidenceRefs,
      }),
    );
    objectivesByStage = [
      {
        id: 'all',
        label: 'Tüm Stajlar',
        summary: fallbackObjectives.reduce(
          (acc, objective) => {
            acc.total += 1;
            acc[objective.status] += 1;
            return acc;
          },
          { total: 0, covered: 0, partial: 0, missing: 0 },
        ),
        objectives: fallbackObjectives,
      },
    ];
  }

  return {
    reportId,
    generatedAt: compliance.generatedAt,
    version: compliance.version,
    requirements,
    summary,
    objectivesByStage,
  };
};
