import path from 'path';

import { importQaLogs } from './qaLogs';

describe('importQaLogs', () => {
  it('parses QA sign-off entries', async () => {
    const fixture = path.join(__dirname, '__fixtures__', 'qa-logs', 'sample.csv');
    const result = await importQaLogs(fixture);

    expect(result.warnings).toEqual([]);
    expect(result.data).toHaveLength(3);
    expect(result.data[0]).toEqual(
      expect.objectContaining({
        objectiveId: 'A-7-01',
        artifact: 'Software Quality Audit',
        reviewer: 'QA Lead',
        status: 'approved',
        completedAt: '2024-02-10',
        notes: 'Checklist complete',
      }),
    );
    expect(result.data[2]).toEqual(
      expect.objectContaining({
        objectiveId: 'A-7-03',
        reviewer: 'QA Auditor',
        status: 'approved',
        completedAt: '2024-02-12',
        notes: 'Follow-up required',
      }),
    );
  });

  it('warns and returns empty data when objective header missing', async () => {
    const fixture = path.join(__dirname, '__fixtures__', 'qa-logs', 'missing-objective.csv');
    const result = await importQaLogs(fixture);

    expect(result.data).toEqual([]);
    expect(result.warnings).toEqual(
      expect.arrayContaining([
        'CSV file is missing an Objective column.',
        'Row 2 is missing an objective id and was skipped.',
      ]),
    );
  });
});
