import type { TraceGraph, TraceGraphNode, TraceNodeType } from './index';

type ChangeImpactState = 'added' | 'removed' | 'modified' | 'impacted';

type ChangeWeights = {
  added: number;
  removed: number;
  linkChanged: number;
  statusChange: number;
  coverageWeight: number;
  rippleDecay: number;
  rippleDepth: number;
};

const DEFAULT_WEIGHTS: ChangeWeights = {
  added: 4,
  removed: 5,
  linkChanged: 1.5,
  statusChange: 3,
  coverageWeight: 10,
  rippleDecay: 0.6,
  rippleDepth: 3,
};

interface NodeSnapshot {
  key: string;
  id: string;
  type: TraceNodeType;
  links: Set<string>;
  data: TraceGraphNode['data'];
}

const isTestSnapshot = (
  node: NodeSnapshot,
): node is NodeSnapshot & { type: 'test'; data: Extract<TraceGraphNode, { type: 'test' }>['data'] } => node.type === 'test';

interface ChangeImpactAccumulator {
  key: string;
  id: string;
  type: TraceNodeType;
  state: ChangeImpactState;
  base: number;
  coverage: number;
  ripple: number;
  reasons: string[];
}

export interface ChangeImpactScore {
  key: string;
  id: string;
  type: TraceNodeType;
  severity: number;
  state: ChangeImpactState;
  reasons: string[];
  base: number;
  coverage: number;
  ripple: number;
}

interface AnalyzeOptions {
  weights?: Partial<ChangeWeights>;
}

const toSnapshotMap = (graph: TraceGraph): Map<string, NodeSnapshot> => {
  const map = new Map<string, NodeSnapshot>();
  graph.nodes.forEach((node) => {
    map.set(node.key, {
      key: node.key,
      id: node.id,
      type: node.type,
      data: node.data,
      links: new Set(node.links ?? []),
    });
  });
  return map;
};

const combineAdjacency = (
  baseline: Map<string, NodeSnapshot>,
  current: Map<string, NodeSnapshot>,
): Map<string, Set<string>> => {
  const adjacency = new Map<string, Set<string>>();
  const ingest = (map: Map<string, NodeSnapshot>) => {
    map.forEach((node) => {
      const target = adjacency.get(node.key) ?? new Set<string>();
      node.links.forEach((link) => target.add(link));
      adjacency.set(node.key, target);
      node.links.forEach((link) => {
        const reverse = adjacency.get(link) ?? new Set<string>();
        reverse.add(node.key);
        adjacency.set(link, reverse);
      });
    });
  };

  ingest(baseline);
  ingest(current);
  return adjacency;
};

const requirementCoverageRatio = (
  node: NodeSnapshot | undefined,
  map: Map<string, NodeSnapshot>,
): number => {
  if (!node || node.type !== 'requirement') {
    return 0;
  }
  const tests = Array.from(node.links)
    .map((key) => map.get(key))
    .filter((candidate): candidate is NodeSnapshot => candidate !== undefined)
    .filter(isTestSnapshot);
  if (tests.length === 0) {
    return 0;
  }
  const passed = tests.filter((test) => test.data.status === 'passed').length;
  return passed / tests.length;
};

const statusWeight = (status: string | undefined): number => {
  if (!status) {
    return 0;
  }
  if (status === 'failed') {
    return 2;
  }
  if (status === 'skipped') {
    return 1;
  }
  return 0;
};

const ensureAccumulator = (
  map: Map<string, ChangeImpactAccumulator>,
  key: string,
  node: NodeSnapshot | undefined,
  fallback: NodeSnapshot | undefined,
): ChangeImpactAccumulator => {
  const existing = map.get(key);
  if (existing) {
    return existing;
  }
  const source = node ?? fallback;
  if (!source) {
    throw new Error(`Trace graph anahtarı bulunamadı: ${key}`);
  }
  const accumulator: ChangeImpactAccumulator = {
    key,
    id: source.id,
    type: source.type,
    state: 'impacted',
    base: 0,
    coverage: 0,
    ripple: 0,
    reasons: [],
  };
  map.set(key, accumulator);
  return accumulator;
};

const unionKeys = (
  baseline: Map<string, NodeSnapshot>,
  current: Map<string, NodeSnapshot>,
): Set<string> => {
  const keys = new Set<string>();
  baseline.forEach((_, key) => keys.add(key));
  current.forEach((_, key) => keys.add(key));
  return keys;
};

const buildReason = (message: string, accumulator: ChangeImpactAccumulator): void => {
  accumulator.reasons.push(message);
};

const markState = (accumulator: ChangeImpactAccumulator, state: ChangeImpactState): void => {
  if (accumulator.state === 'impacted') {
    accumulator.state = state;
    return;
  }
  if (state === 'added' || state === 'removed') {
    accumulator.state = state;
    return;
  }
  if (state === 'modified' && accumulator.state !== 'added' && accumulator.state !== 'removed') {
    accumulator.state = 'modified';
  }
};

const analyzeDirectChanges = (
  baseline: Map<string, NodeSnapshot>,
  current: Map<string, NodeSnapshot>,
  weights: ChangeWeights,
): Map<string, ChangeImpactAccumulator> => {
  const scores = new Map<string, ChangeImpactAccumulator>();
  const keys = unionKeys(baseline, current);

  keys.forEach((key) => {
    const baselineNode = baseline.get(key);
    const currentNode = current.get(key);
    const accumulator = ensureAccumulator(scores, key, currentNode, baselineNode);

    if (!baselineNode && currentNode) {
      accumulator.base += weights.added;
      markState(accumulator, 'added');
      buildReason(`${currentNode.id} düğümü yeni eklendi.`, accumulator);
      return;
    }

    if (baselineNode && !currentNode) {
      accumulator.base += weights.removed;
      markState(accumulator, 'removed');
      buildReason(`${baselineNode.id} düğümü çalışma alanından kaldırıldı.`, accumulator);
      return;
    }

    if (!baselineNode || !currentNode) {
      return;
    }

    const removedLinks = Array.from(baselineNode.links).filter((link) => !currentNode.links.has(link));
    const addedLinks = Array.from(currentNode.links).filter((link) => !baselineNode.links.has(link));
    const linkDelta = removedLinks.length + addedLinks.length;
    if (linkDelta > 0) {
      accumulator.base += linkDelta * weights.linkChanged;
      markState(accumulator, 'modified');
      if (addedLinks.length > 0) {
        buildReason(`${currentNode.id} düğümüne ${addedLinks.length} bağlantı eklendi.`, accumulator);
      }
      if (removedLinks.length > 0) {
        buildReason(`${currentNode.id} düğümünden ${removedLinks.length} bağlantı kaldırıldı.`, accumulator);
      }
    }

    if (currentNode.type === 'test') {
      const before = statusWeight((baselineNode.data as { status?: string }).status);
      const after = statusWeight((currentNode.data as { status?: string }).status);
      if (after > before) {
        const delta = after - before;
        accumulator.base += delta * weights.statusChange;
        markState(accumulator, 'modified');
        buildReason(
          `${currentNode.id} testi ${String((currentNode.data as { status?: string }).status)} durumuna düştü ` +
            `(önceki: ${String((baselineNode.data as { status?: string }).status ?? 'bilinmiyor')}).`,
          accumulator,
        );
      }
    }

    if (currentNode.type === 'requirement') {
      const before = requirementCoverageRatio(baselineNode, baseline);
      const after = requirementCoverageRatio(currentNode, current);
      const drop = before - after;
      if (drop > 0) {
        const coveragePenalty = drop * weights.coverageWeight;
        accumulator.coverage += coveragePenalty;
        markState(accumulator, 'modified');
        buildReason(
          `${currentNode.id} gereksinimi için test kapsamı %${Math.round(before * 100)}'den %${Math.round(
            after * 100,
          )}'e düştü.`,
          accumulator,
        );
      }
    }
  });

  return scores;
};

const applyRipple = (
  scores: Map<string, ChangeImpactAccumulator>,
  adjacency: Map<string, Set<string>>,
  weights: ChangeWeights,
): void => {
  scores.forEach((score, key) => {
    const originImpact = score.base + score.coverage;
    if (originImpact <= 0) {
      return;
    }
    const visited = new Set<string>([key]);
    const queue: Array<{ key: string; depth: number }> = [];
    (adjacency.get(key) ?? []).forEach((neighbor) => {
      queue.push({ key: neighbor, depth: 1 });
    });

    while (queue.length > 0) {
      const current = queue.shift()!;
      if (current.depth > weights.rippleDepth) {
        continue;
      }
      if (visited.has(current.key)) {
        continue;
      }
      visited.add(current.key);
      const decay = weights.rippleDecay ** current.depth;
      const addition = originImpact * decay;
      const neighborScore = scores.get(current.key);
      if (neighborScore) {
        neighborScore.ripple += addition;
        if (neighborScore.state === 'impacted' && addition > 0) {
          neighborScore.reasons.push(
            `${neighborScore.id} düğümü, ${score.id} değişikliğinden ${current.depth}. seviyede etkilendi.`,
          );
        }
      }

      const nextDepth = current.depth + 1;
      if (nextDepth > weights.rippleDepth) {
        continue;
      }
      (adjacency.get(current.key) ?? []).forEach((neighbor) => {
        if (!visited.has(neighbor)) {
          queue.push({ key: neighbor, depth: nextDepth });
        }
      });
    }
  });
};

export const analyzeChangeImpact = (
  baseline: TraceGraph,
  current: TraceGraph,
  options: AnalyzeOptions = {},
): ChangeImpactScore[] => {
  const weights: ChangeWeights = { ...DEFAULT_WEIGHTS, ...options.weights };
  const baselineMap = toSnapshotMap(baseline);
  const currentMap = toSnapshotMap(current);
  const adjacency = combineAdjacency(baselineMap, currentMap);

  const scores = analyzeDirectChanges(baselineMap, currentMap, weights);
  applyRipple(scores, adjacency, weights);

  const result: ChangeImpactScore[] = [];
  scores.forEach((value) => {
    const severity = value.base + value.coverage + value.ripple;
    if (severity <= 0) {
      return;
    }
    result.push({
      key: value.key,
      id: value.id,
      type: value.type,
      severity,
      state: value.state,
      reasons: value.reasons,
      base: value.base,
      coverage: value.coverage,
      ripple: value.ripple,
    });
  });

  result.sort((a, b) => {
    if (b.severity !== a.severity) {
      return b.severity - a.severity;
    }
    if (a.type !== b.type) {
      return a.type.localeCompare(b.type);
    }
    return a.id.localeCompare(b.id);
  });

  return result;
};
