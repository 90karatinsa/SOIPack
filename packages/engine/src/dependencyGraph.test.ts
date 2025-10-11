import {
  buildObjectiveDependencyGraph,
  detectObjectiveCycles,
  getObjectiveById,
  topologicallySortObjectives,
} from './dependencyGraph';

const pick = (id: string) => {
  const objective = getObjectiveById(id);
  if (!objective) {
    throw new Error(`Objective ${id} not found in catalog`);
  }
  return objective;
};

describe('objective dependency graph', () => {
  const subset = [
    pick('A-3-01'),
    pick('A-3-02'),
    pick('A-3-03'),
    pick('A-4-01'),
    pick('A-4-02'),
    pick('A-5-08'),
    pick('A-5-09'),
    pick('A-5-10'),
    pick('A-5-11'),
  ];

  it('infers prerequisites across tables and artifact chains', () => {
    const graph = buildObjectiveDependencyGraph(subset);

    const hlrNode = graph.nodes.get('A-4-01');
    expect(hlrNode?.prerequisites).toEqual(
      expect.arrayContaining(['A-3-01', 'A-3-02', 'A-3-03']),
    );
    expect(hlrNode?.rationale['A-3-01']).toContain('artifact:review->plan');
    expect(hlrNode?.rationale['A-3-02']).toContain('artifact:analysis->standard');

    const decisionCoverage = graph.nodes.get('A-5-09');
    expect(decisionCoverage?.prerequisites).toEqual(
      expect.arrayContaining(['A-5-11', 'A-4-01', 'A-3-01', 'A-3-02']),
    );
    expect(decisionCoverage?.rationale['A-5-11']).toContain('artifact:coverage_dec->test');
    expect(decisionCoverage?.rationale['A-4-01']).toContain('artifact:coverage_dec->analysis');

    const mcdcCoverage = graph.nodes.get('A-5-10');
    expect(mcdcCoverage?.prerequisites).toEqual(
      expect.arrayContaining(['A-5-09', 'A-3-01', 'A-3-02']),
    );
    expect(mcdcCoverage?.rationale['A-5-09']).toContain('artifact:coverage_mcdc->coverage_dec');

    const topo = topologicallySortObjectives(graph);
    expect(topo.hasCycle).toBe(false);
    const orderedIds = topo.order.map((node) => node.objective.id);
    expect(orderedIds.indexOf('A-3-01')).toBeLessThan(orderedIds.indexOf('A-4-01'));
    expect(orderedIds.indexOf('A-4-01')).toBeLessThan(orderedIds.indexOf('A-5-09'));
    expect(orderedIds.indexOf('A-5-09')).toBeLessThan(orderedIds.indexOf('A-5-10'));
    expect(detectObjectiveCycles(graph)).toHaveLength(0);
  });

  it('detects cycles when manual dependencies introduce loops', () => {
    const graph = buildObjectiveDependencyGraph(subset, {
      manualDependencies: [
        { from: 'A-4-01', to: 'A-5-10', reason: 'force ordering' },
        { from: 'A-5-10', to: 'A-4-01', reason: 'feedback loop' },
      ],
    });

    const cycles = detectObjectiveCycles(graph);
    expect(
      cycles.some((cycle) => cycle.includes('A-4-01') && cycle.includes('A-5-10')),
    ).toBe(true);

    const topo = topologicallySortObjectives(graph);
    expect(topo.hasCycle).toBe(true);
    const unsortedIds = topo.unsorted.map((node) => node.objective.id);
    expect(unsortedIds).toEqual(expect.arrayContaining(['A-4-01', 'A-5-10']));

    const hlrNode = graph.nodes.get('A-4-01');
    expect(hlrNode?.prerequisites).toContain('A-5-10');
    expect(hlrNode?.rationale['A-5-10']).toContain('manual:feedback loop');
  });
});
