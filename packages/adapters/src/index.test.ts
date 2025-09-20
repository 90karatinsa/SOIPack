import path from 'path';

import {
  importCobertura,
  importGitMetadata,
  importJiraCsv,
  importJUnitXml,
  importLcov,
  importReqIF,
  registerAdapter,
  toRequirement,
} from './index';

describe('@soipack/adapters', () => {
  it('normalizes supported artifacts to lowercase', () => {
    const adapter = registerAdapter({
      name: 'JUnit XML',
      supportedArtifacts: ['JUnit', 'XML'],
    });

    expect(adapter.supportedArtifacts).toEqual(['junit', 'xml']);
  });

  it('throws when no artifact is provided', () => {
    expect(() => registerAdapter({ name: 'Empty', supportedArtifacts: [] })).toThrow(
      'Adapter must support at least one artifact type.',
    );
  });

  it('converts raw record to requirement', () => {
    const requirement = toRequirement({ id: 10, title: ' Login Feature ', description: null });
    expect(requirement).toEqual({
      id: '10',
      title: 'Login Feature',
      description: undefined,
      status: 'draft',
      tags: [],
    });
  });

  it('imports requirements from Jira CSV', async () => {
    const { data, warnings } = await importJiraCsv(
      path.resolve(__dirname, '../fixtures/jira/issues.sample.csv'),
    );

    expect(warnings).toHaveLength(0);
    expect(data).toHaveLength(3);
    expect(data[0]).toEqual({
      id: 'PROJ-1',
      summary: 'Implement login',
      status: 'In Progress',
      priority: 'High',
      links: ['PROJ-2', 'PROJ-3'],
    });
  });

  it('imports requirements from ReqIF', async () => {
    const { data, warnings } = await importReqIF(path.resolve(__dirname, '../fixtures/reqif/sample.reqif'));

    expect(warnings).toHaveLength(0);
    expect(data).toHaveLength(2);
    expect(data[0]).toEqual({ id: 'REQ-1', text: 'System shall allow login.' });
    expect(data[1]).toEqual({ id: 'REQ-2', text: 'System shall log errors.' });
  });

  it('imports JUnit XML test results', async () => {
    const { data, warnings } = await importJUnitXml(
      path.resolve(__dirname, '../fixtures/junit/results.sample.xml'),
    );

    expect(warnings).toHaveLength(0);
    expect(data).toHaveLength(3);
    expect(data.map((test) => test.status)).toEqual(['passed', 'failed', 'skipped']);
    expect(data[0]).toMatchObject({
      testId: 'example.Class#passes',
      className: 'example.Class',
      name: 'passes',
      requirementsRefs: ['REQ-1', 'REQ-2'],
    });
    expect(data[1]).toMatchObject({ errorMessage: 'Assertion failed\nExpected true but was false' });
  });

  it('imports LCOV coverage summaries', async () => {
    const { data, warnings } = await importLcov(path.resolve(__dirname, '../fixtures/lcov/lcov.info'));

    expect(warnings).toHaveLength(0);
    expect(data.files).toHaveLength(2);
    expect(data.totals.statements).toMatchObject({ covered: 2, total: 3, percentage: 66.67 });
    expect(data.totals.branches).toMatchObject({ covered: 1, total: 2, percentage: 50 });
    expect(data.totals.functions).toMatchObject({ covered: 1, total: 1, percentage: 100 });
    expect(data.testMap).toEqual({
      'AuthSuite#passes': ['/workspace/app/src/file1.ts'],
      'AuditSuite#records': ['/workspace/app/src/file2.ts'],
    });
  });

  it('imports Cobertura coverage summaries', async () => {
    const { data, warnings } = await importCobertura(
      path.resolve(__dirname, '../fixtures/cobertura/coverage.xml'),
    );

    expect(warnings).toHaveLength(0);
    expect(data.files).toHaveLength(2);
    expect(data.totals.statements).toMatchObject({ covered: 2, total: 3, percentage: 66.67 });
    expect(data.totals.branches).toMatchObject({ covered: 1, total: 2, percentage: 50 });
    expect(data.totals.functions).toMatchObject({ covered: 2, total: 2, percentage: 100 });
    expect(data.testMap).toEqual({
      'AuthSuite#passes': ['src/example.ts'],
      'AuditSuite#records': ['src/other.ts'],
    });
  });

  it('collects git metadata', async () => {
    const { data, warnings } = await importGitMetadata(path.resolve(__dirname, '../../..'));

    expect(warnings).toHaveLength(0);
    expect(data).not.toBeNull();
    expect(data).toEqual(
      expect.objectContaining({
        hash: expect.any(String),
        author: expect.any(String),
        date: expect.any(String),
      }),
    );
  });
});
