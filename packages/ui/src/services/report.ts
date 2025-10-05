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

const createEmptySuggestionGroup = (): RequirementViewModel['suggestions'] => ({
  code: [],
  tests: [],
});

const buildSuggestionMap = (
  suggestions: ComplianceMatrixPayload['traceSuggestions'],
): Map<string, RequirementViewModel['suggestions']> => {
  const lookup = new Map<string, RequirementViewModel['suggestions']>();

  (suggestions ?? []).forEach((suggestion) => {
    if (!lookup.has(suggestion.requirementId)) {
      lookup.set(suggestion.requirementId, createEmptySuggestionGroup());
    }
    const group = lookup.get(suggestion.requirementId)!;
    const entry = {
      type: suggestion.type,
      targetId: suggestion.targetId,
      target: suggestion.targetName ?? suggestion.targetId,
      confidence: suggestion.confidence,
      reason: suggestion.reason,
    };
    if (suggestion.type === 'code') {
      group.code.push(entry);
    } else {
      group.tests.push(entry);
    }
  });

  lookup.forEach((group) => {
    group.code.sort((a, b) => a.targetId.localeCompare(b.targetId));
    group.tests.sort((a, b) => a.targetId.localeCompare(b.targetId));
  });

  return lookup;
};

const cloneSuggestionGroup = (
  group?: RequirementViewModel['suggestions'],
): RequirementViewModel['suggestions'] => ({
  code: (group?.code ?? []).map((entry) => ({ ...entry })),
  tests: (group?.tests ?? []).map((entry) => ({ ...entry })),
});

const collectRequirementDesigns = (
  designIds: string[] | undefined,
  traceDesigns: RequirementTracePayload['designs'],
): RequirementViewModel['designs'] => {
  const designs = new Map<string, RequirementViewModel['designs'][number]>();

  (traceDesigns ?? []).forEach((design) => {
    designs.set(design.id, {
      id: design.id,
      title: design.title,
      status: design.status,
    });
  });

  (designIds ?? []).forEach((designId) => {
    if (!designs.has(designId)) {
      designs.set(designId, {
        id: designId,
        title: designId,
      });
    }
  });

  return Array.from(designs.values()).sort((a, b) => a.id.localeCompare(b.id));
};

const buildRequirementView = (
  coverageEntry: ComplianceMatrixPayload['requirementCoverage'][number],
  trace?: RequirementTracePayload,
  suggestions?: RequirementViewModel['suggestions'],
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
    designs: collectRequirementDesigns(coverageEntry.designs, trace?.designs),
    suggestions: cloneSuggestionGroup(suggestions),
  };
};

const buildTraceOnlyRequirement = (
  trace: RequirementTracePayload,
  suggestions?: RequirementViewModel['suggestions'],
): RequirementViewModel => {
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
    designs: collectRequirementDesigns(undefined, trace.designs),
    suggestions: cloneSuggestionGroup(suggestions),
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

  const suggestionMap = buildSuggestionMap(compliance.traceSuggestions);

  const requirements = compliance.requirementCoverage.map((entry) => {
    const trace = traceMap.get(entry.requirementId);
    traceMap.delete(entry.requirementId);
    return buildRequirementView(entry, trace, suggestionMap.get(entry.requirementId));
  });

  traceMap.forEach((trace) => {
    requirements.push(buildTraceOnlyRequirement(trace, suggestionMap.get(trace.requirement.id)));
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
