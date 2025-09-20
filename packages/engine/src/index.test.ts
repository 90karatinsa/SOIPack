import { createRequirement, TestCase } from '@soipack/core';

import { buildTraceMatrix, createTraceLink } from './index';

describe('@soipack/engine', () => {
  const requirement = createRequirement('REQ-10', 'Authenticate user');
  const test: TestCase = {
    id: 'TC-1',
    name: 'should authenticate with valid credentials',
    requirementId: requirement.id,
    status: 'pending',
  };

  it('creates trace link with precision', () => {
    const link = createTraceLink(requirement, test, 0.876);
    expect(link.confidence).toBe(0.88);
  });

  it('builds trace matrix grouped by requirement', () => {
    const matrix = buildTraceMatrix([
      createTraceLink(requirement, test, 0.9),
      createTraceLink(requirement, { ...test, id: 'TC-2' }, 0.75),
    ]);

    expect(matrix).toEqual([
      {
        requirementId: 'REQ-10',
        testCaseIds: ['TC-1', 'TC-2'],
      },
    ]);
  });
});
