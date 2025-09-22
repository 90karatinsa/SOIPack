import traceFixture from '../test/fixtures/traceability.json';

import { TraceabilityGapAnalyzer, TraceabilityModel } from './gaps';

describe('TraceabilityGapAnalyzer', () => {
  it('flags missing links and conflicting evidence chains', () => {
    const analyzer = new TraceabilityGapAnalyzer(traceFixture as TraceabilityModel);
    const report = analyzer.analyze();

    expect(report.requirementGaps).toHaveLength(3);
    expect(report.summary.highPriorityRequirements).toEqual(['REQ-2', 'REQ-3', 'REQ-4']);

    const gapIds = report.requirementGaps.map((gap) => gap.requirementId);
    expect(gapIds).toEqual(expect.arrayContaining(['REQ-2', 'REQ-3', 'REQ-4']));

    const requirementTwo = report.requirementGaps.find((gap) => gap.requirementId === 'REQ-2');
    expect(requirementTwo).toBeDefined();
    expect(requirementTwo?.missingDesign).toBe(false);
    expect(requirementTwo?.missingCode).toBe(true);
    expect(requirementTwo?.missingTests).toBe(true);
    expect(requirementTwo?.severity).toBe('high');

    const requirementFour = report.requirementGaps.find((gap) => gap.requirementId === 'REQ-4');
    expect(requirementFour?.missingDesign).toBe(false);
    expect(requirementFour?.missingCode).toBe(false);
    expect(requirementFour?.missingTests).toBe(true);
    expect(requirementFour?.tests).toHaveLength(0);

    expect(report.orphans).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: 'design', id: 'DES-3' }),
        expect.objectContaining({ type: 'code', id: 'CODE-2' }),
        expect.objectContaining({ type: 'test', id: 'TEST-ghost' }),
      ]),
    );

    expect(report.conflicts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ sourceId: 'CODE-4', targetId: 'TEST-4' }),
        expect.objectContaining({ sourceId: 'TEST-2', targetId: 'CODE-2' }),
        expect.objectContaining({ sourceId: 'TEST-4', targetId: 'CODE-X' }),
      ]),
    );
  });
});
