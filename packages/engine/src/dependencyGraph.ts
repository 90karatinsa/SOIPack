import { Objective, ObjectiveArtifactType, objectiveCatalogById } from '@soipack/core';

const stageOrder: Record<Objective['stage'], number> = {
  'SOI-1': 0,
  'SOI-2': 1,
  'SOI-3': 2,
  'SOI-4': 3,
};

const tableOrder: Record<Objective['table'], number> = {
  'A-3': 0,
  'A-4': 1,
  'A-5': 2,
  'A-6': 3,
  'A-7': 4,
};

const independenceOrder: Record<Objective['independence'], number> = {
  required: 0,
  recommended: 1,
  none: 2,
};

const artifactDependencies: Partial<Record<ObjectiveArtifactType, ObjectiveArtifactType[]>> = {
  review: ['plan'],
  analysis: ['plan', 'standard'],
  trace: ['plan', 'analysis'],
  test: ['plan', 'analysis', 'review'],
  coverage_stmt: ['test'],
  coverage_dec: ['test', 'analysis'],
  coverage_mcdc: ['coverage_dec'],
  qa_record: ['plan', 'standard', 'analysis'],
  cm_record: ['plan', 'standard'],
  problem_report: ['test'],
  conformity: ['plan', 'standard', 'analysis', 'test', 'qa_record', 'cm_record'],
};

const baseArtifactPreferences: Partial<Record<ObjectiveArtifactType, Objective['table'][]>> = {
  test: ['A-5', 'A-4', 'A-3'],
  coverage_stmt: ['A-5'],
  coverage_dec: ['A-5'],
  coverage_mcdc: ['A-5'],
  qa_record: ['A-6', 'A-3'],
  cm_record: ['A-7', 'A-3'],
  problem_report: ['A-5', 'A-4'],
  conformity: ['A-6', 'A-7', 'A-5'],
};

const getArtifactPreference = (
  artifact: ObjectiveArtifactType,
  target: Objective,
): Objective['table'][] | undefined => {
  if (artifact === 'analysis') {
    if (target.table === 'A-4') {
      return ['A-3', 'A-4'];
    }
    if (target.table === 'A-5') {
      return ['A-4', 'A-3'];
    }
    if (target.table === 'A-6' || target.table === 'A-7') {
      return ['A-5', 'A-4', 'A-3'];
    }
  }
  if (artifact === 'trace') {
    if (target.table === 'A-4') {
      return ['A-3', 'A-4'];
    }
    if (target.table === 'A-5') {
      return ['A-4', 'A-3'];
    }
  }
  return baseArtifactPreferences[artifact];
};

export interface ObjectiveDependencyNode {
  objective: Objective;
  prerequisites: string[];
  dependents: string[];
  rationale: Record<string, string[]>;
}

export interface ObjectiveDependencyGraphEdge {
  from: string;
  to: string;
  reasons: string[];
}

export interface ObjectiveDependencyGraph {
  nodes: Map<string, ObjectiveDependencyNode>;
  edges: ObjectiveDependencyGraphEdge[];
}

export interface BuildObjectiveDependencyGraphOptions {
  manualDependencies?: Array<{ from: string; to: string; reason?: string }>;
}

type CandidateIndex = Map<ObjectiveArtifactType, Objective[]>;

const buildCandidateIndex = (objectives: Objective[]): CandidateIndex => {
  const index: CandidateIndex = new Map();
  objectives.forEach((objective) => {
    objective.artifacts.forEach((artifact) => {
      const existing = index.get(artifact) ?? [];
      existing.push(objective);
      index.set(artifact, existing);
    });
  });

  for (const [artifact, candidates] of index.entries()) {
    candidates.sort((a, b) => {
      const tableDelta = tableOrder[a.table] - tableOrder[b.table];
      if (tableDelta !== 0) {
        return tableDelta;
      }
      const stageDelta = stageOrder[a.stage] - stageOrder[b.stage];
      if (stageDelta !== 0) {
        return stageDelta;
      }
      const independenceDelta = independenceOrder[a.independence] - independenceOrder[b.independence];
      if (independenceDelta !== 0) {
        return independenceDelta;
      }
      return a.id.localeCompare(b.id);
    });
  }

  return index;
};

const findPrerequisiteCandidate = (
  artifact: ObjectiveArtifactType,
  target: Objective,
  index: CandidateIndex,
): Objective | undefined => {
  const candidates = index.get(artifact);
  if (!candidates) {
    return undefined;
  }

  const filtered = candidates.filter((candidate) => candidate.id !== target.id);
  if (filtered.length === 0) {
    return undefined;
  }

  const preferred = filtered.sort((a, b) => {
    const preference = getArtifactPreference(artifact, target);
    if (preference) {
      const aPref = preference.indexOf(a.table);
      const bPref = preference.indexOf(b.table);
      if (aPref === -1 && bPref !== -1) {
        return 1;
      }
      if (aPref !== -1 && bPref === -1) {
        return -1;
      }
      if (aPref !== -1 && bPref !== -1 && aPref !== bPref) {
        return aPref - bPref;
      }
    }
    const targetTableRank = tableOrder[target.table];
    const computeTablePenalty = (candidate: Objective): number => {
      const diff = targetTableRank - tableOrder[candidate.table];
      if (diff > 0) {
        return diff;
      }
      if (diff === 0) {
        return targetTableRank + 1;
      }
      return targetTableRank + 1 + Math.abs(diff);
    };
    const aTablePenalty = computeTablePenalty(a);
    const bTablePenalty = computeTablePenalty(b);
    if (aTablePenalty !== bTablePenalty) {
      return aTablePenalty - bTablePenalty;
    }
    const tableDelta = tableOrder[a.table] - tableOrder[b.table];
    if (tableDelta !== 0) {
      return tableDelta;
    }
    const targetStageRank = stageOrder[target.stage];
    const aStageRank = stageOrder[a.stage];
    const bStageRank = stageOrder[b.stage];

    const aStagePenalty = aStageRank <= targetStageRank ? targetStageRank - aStageRank : 10 + (aStageRank - targetStageRank);
    const bStagePenalty = bStageRank <= targetStageRank ? targetStageRank - bStageRank : 10 + (bStageRank - targetStageRank);
    if (aStagePenalty !== bStagePenalty) {
      return aStagePenalty - bStagePenalty;
    }

    const independenceDelta = independenceOrder[a.independence] - independenceOrder[b.independence];
    if (independenceDelta !== 0) {
      return independenceDelta;
    }
    return a.id.localeCompare(b.id);
  });

  return preferred[0];
};

interface EdgeReasonsIndex {
  add: (from: string, to: string, reason: string) => void;
  entries: () => Array<{ from: string; to: string; reasons: string[] }>;
}

const createEdgeReasonIndex = (): EdgeReasonsIndex => {
  const store = new Map<string, Map<string, Set<string>>>();

  return {
    add: (from, to, reason) => {
      if (!store.has(from)) {
        store.set(from, new Map());
      }
      const targets = store.get(from)!;
      if (!targets.has(to)) {
        targets.set(to, new Set());
      }
      if (reason) {
        targets.get(to)!.add(reason);
      }
    },
    entries: () => {
      const result: Array<{ from: string; to: string; reasons: string[] }> = [];
      for (const [from, targets] of store.entries()) {
        for (const [to, reasons] of targets.entries()) {
          result.push({ from, to, reasons: Array.from(reasons).sort() });
        }
      }
      result.sort((a, b) => {
        if (a.from !== b.from) {
          return a.from.localeCompare(b.from);
        }
        if (a.to !== b.to) {
          return a.to.localeCompare(b.to);
        }
        return a.reasons.join(',').localeCompare(b.reasons.join(','));
      });
      return result;
    },
  };
};

export const buildObjectiveDependencyGraph = (
  objectives: Objective[],
  options: BuildObjectiveDependencyGraphOptions = {},
): ObjectiveDependencyGraph => {
  const { manualDependencies = [] } = options;
  const nodes = new Map<string, ObjectiveDependencyNode>();
  objectives.forEach((objective) => {
    nodes.set(objective.id, {
      objective,
      prerequisites: [],
      dependents: [],
      rationale: {},
    });
  });

  const candidateIndex = buildCandidateIndex(objectives);
  const edgeIndex = createEdgeReasonIndex();

  objectives.forEach((objective) => {
    objective.artifacts.forEach((artifact) => {
      const dependencies = artifactDependencies[artifact];
      if (!dependencies) {
        return;
      }
      dependencies.forEach((dependency) => {
        if (
          (dependency === 'plan' || dependency === 'standard') &&
          objective.artifacts.includes(dependency)
        ) {
          return;
        }
        const candidate = findPrerequisiteCandidate(dependency, objective, candidateIndex);
        if (!candidate || !nodes.has(candidate.id)) {
          return;
        }
        edgeIndex.add(candidate.id, objective.id, `artifact:${artifact}->${dependency}`);
      });
    });
  });

  manualDependencies.forEach(({ from, to, reason }) => {
    if (!nodes.has(from) || !nodes.has(to)) {
      return;
    }
    edgeIndex.add(from, to, `manual:${reason ?? 'unspecified'}`);
  });

  const edges: ObjectiveDependencyGraphEdge[] = [];

  for (const { from, to, reasons } of edgeIndex.entries()) {
    const source = nodes.get(from);
    const target = nodes.get(to);
    if (!source || !target) {
      continue;
    }

    target.prerequisites.push(from);
    target.rationale[from] = reasons;
    source.dependents.push(to);
    edges.push({ from, to, reasons });
  }

  nodes.forEach((node) => {
    node.prerequisites.sort();
    node.dependents.sort();
  });

  edges.sort((a, b) => {
    if (a.from !== b.from) {
      return a.from.localeCompare(b.from);
    }
    if (a.to !== b.to) {
      return a.to.localeCompare(b.to);
    }
    return a.reasons.join(',').localeCompare(b.reasons.join(','));
  });

  return { nodes, edges };
};

export interface TopologicalSortResult {
  order: ObjectiveDependencyNode[];
  hasCycle: boolean;
  unsorted: ObjectiveDependencyNode[];
}

const sortTieBreaker = (a: ObjectiveDependencyNode, b: ObjectiveDependencyNode): number => {
  const tableDelta = tableOrder[a.objective.table] - tableOrder[b.objective.table];
  if (tableDelta !== 0) {
    return tableDelta;
  }
  const stageDelta = stageOrder[a.objective.stage] - stageOrder[b.objective.stage];
  if (stageDelta !== 0) {
    return stageDelta;
  }
  return a.objective.id.localeCompare(b.objective.id);
};

export const topologicallySortObjectives = (graph: ObjectiveDependencyGraph): TopologicalSortResult => {
  const indegree = new Map<string, number>();
  graph.nodes.forEach((node, id) => {
    indegree.set(id, node.prerequisites.length);
  });

  const ready: string[] = [];
  indegree.forEach((count, id) => {
    if (count === 0) {
      ready.push(id);
    }
  });

  const order: ObjectiveDependencyNode[] = [];
  const processed = new Set<string>();

  while (ready.length > 0) {
    ready.sort((idA, idB) => {
      const nodeA = graph.nodes.get(idA)!;
      const nodeB = graph.nodes.get(idB)!;
      return sortTieBreaker(nodeA, nodeB);
    });
    const currentId = ready.shift()!;
    const currentNode = graph.nodes.get(currentId);
    if (!currentNode) {
      continue;
    }
    order.push(currentNode);
    processed.add(currentId);

    currentNode.dependents.forEach((dependentId) => {
      const dependentCount = indegree.get(dependentId);
      if (dependentCount === undefined) {
        return;
      }
      const nextCount = dependentCount - 1;
      indegree.set(dependentId, nextCount);
      if (nextCount === 0) {
        ready.push(dependentId);
      }
    });
  }

  const hasCycle = order.length !== graph.nodes.size;
  const unsorted: ObjectiveDependencyNode[] = [];

  if (hasCycle) {
    graph.nodes.forEach((node, id) => {
      if (!processed.has(id)) {
        unsorted.push(node);
      }
    });
    unsorted.sort(sortTieBreaker);
  }

  return { order, hasCycle, unsorted };
};

const normaliseCycle = (cycle: string[]): string[] => {
  if (cycle.length === 0) {
    return cycle;
  }
  const unique = cycle.slice(0, -1);
  let minIndex = 0;
  unique.forEach((id, index) => {
    if (id.localeCompare(unique[minIndex]) < 0) {
      minIndex = index;
    }
  });
  const rotated = unique.slice(minIndex).concat(unique.slice(0, minIndex));
  rotated.push(rotated[0]);
  return rotated;
};

export const detectObjectiveCycles = (graph: ObjectiveDependencyGraph): string[][] => {
  const visited = new Set<string>();
  const stack = new Set<string>();
  const path: string[] = [];
  const cycles: string[][] = [];
  const seen = new Set<string>();

  const recordCycle = (cyclePath: string[], startId: string) => {
    const startIndex = cyclePath.indexOf(startId);
    if (startIndex === -1) {
      return;
    }
    const cycle = cyclePath.slice(startIndex);
    if (cycle[cycle.length - 1] !== startId) {
      cycle.push(startId);
    }
    const normalised = normaliseCycle(cycle);
    const key = normalised.join('>');
    if (!seen.has(key)) {
      seen.add(key);
      cycles.push(normalised);
    }
  };

  const dfs = (nodeId: string) => {
    if (stack.has(nodeId)) {
      recordCycle([...path, nodeId], nodeId);
      return;
    }
    if (visited.has(nodeId)) {
      return;
    }
    visited.add(nodeId);
    stack.add(nodeId);
    path.push(nodeId);

    const node = graph.nodes.get(nodeId);
    if (node) {
      node.dependents.forEach((dependentId) => {
        if (!stack.has(dependentId)) {
          dfs(dependentId);
        } else {
          recordCycle([...path, dependentId], dependentId);
        }
      });
    }

    stack.delete(nodeId);
    path.pop();
  };

  graph.nodes.forEach((_node, id) => {
    if (!visited.has(id)) {
      dfs(id);
    }
  });

  cycles.sort((a, b) => a.join('>').localeCompare(b.join('>')));
  return cycles;
};

export const getObjectiveById = (id: string): Objective | undefined => objectiveCatalogById.get(id);
