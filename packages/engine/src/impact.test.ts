import { analyzeChangeImpact, type ChangeImpactScore } from './impact';
import type { TraceGraph } from './index';

const requirementNode = (id: string, links: string[]): TraceGraph['nodes'][number] => ({
  key: `requirement:${id}`,
  id,
  type: 'requirement',
  data: { id, title: `${id} title`, status: 'draft', tags: [] },
  links,
});

const testNode = (
  id: string,
  status: 'passed' | 'failed' | 'skipped',
  links: string[],
): TraceGraph['nodes'][number] => ({
  key: `test:${id}`,
  id,
  type: 'test',
  data: { testId: id, className: 'Suite', name: id, status, duration: 1 },
  links,
});

const codeNode = (path: string, links: string[]): TraceGraph['nodes'][number] => ({
  key: `code:${path}`,
  id: path,
  type: 'code',
  data: { path },
  links,
});

describe('change impact analyzer', () => {
  const baseline: TraceGraph = {
    nodes: [
      requirementNode('REQ-1', ['test:TEST-1', 'code:src/control.c']),
      requirementNode('REQ-2', ['test:TEST-2', 'code:src/logger.c']),
      testNode('TEST-1', 'passed', ['requirement:REQ-1', 'code:src/control.c']),
      testNode('TEST-2', 'passed', ['requirement:REQ-2', 'code:src/logger.c']),
      codeNode('src/control.c', ['requirement:REQ-1', 'test:TEST-1']),
      codeNode('src/logger.c', ['requirement:REQ-2', 'test:TEST-2']),
    ],
  };

  const current: TraceGraph = {
    nodes: [
      requirementNode('REQ-1', ['test:TEST-1', 'code:src/control.c']),
      requirementNode('REQ-2', ['test:TEST-2']),
      requirementNode('REQ-3', ['test:TEST-3', 'code:src/new.c']),
      testNode('TEST-1', 'failed', ['requirement:REQ-1', 'code:src/control.c']),
      testNode('TEST-2', 'passed', ['requirement:REQ-2']),
      testNode('TEST-3', 'failed', ['requirement:REQ-3', 'code:src/new.c']),
      codeNode('src/control.c', ['requirement:REQ-1', 'test:TEST-1']),
      codeNode('src/new.c', ['requirement:REQ-3', 'test:TEST-3']),
    ],
  };

  it('ranks impacted nodes by severity with coverage and ripple effects', () => {
    const scores = analyzeChangeImpact(baseline, current);
    const pick = (id: string): ChangeImpactScore | undefined =>
      scores.find((entry) => entry.id === id || entry.key === id);

    expect(scores).not.toHaveLength(0);
    expect(scores[0]?.id).toBe('REQ-1');
    expect(scores[0]?.severity).toBeGreaterThan(13);
    expect(scores[0]?.reasons.join(' ')).toContain('kapsamı');

    const failingTest = pick('TEST-1');
    expect(failingTest?.state).toBe('modified');
    expect(failingTest?.base).toBeGreaterThan(5);
    expect(failingTest?.ripple).toBeGreaterThan(0);

    const controlCode = pick('src/control.c');
    expect(controlCode?.state).toBe('impacted');
    expect(controlCode?.ripple).toBeGreaterThan(5);

    const removedCode = pick('code:src/logger.c');
    expect(removedCode?.state).toBe('removed');
    expect(removedCode?.severity).toBeGreaterThanOrEqual(5);

    const newRequirement = pick('REQ-3');
    expect(newRequirement?.state).toBe('added');
    expect(newRequirement?.severity).toBeGreaterThan(4);

    const newTest = pick('TEST-3');
    expect(newTest?.state).toBe('added');
    expect(newTest?.severity).toBeGreaterThan(4);
  });
});
