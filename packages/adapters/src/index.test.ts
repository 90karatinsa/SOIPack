import { execFile } from 'child_process';
import { promises as fs } from 'fs';
import os from 'os';
import path from 'path';
import { promisify } from 'util';

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

const execFileAsync = promisify(execFile);

const createGitRepository = async (): Promise<string> => {
  const repoRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'soipack-git-'));

  await execFileAsync('git', ['init'], { cwd: repoRoot });
  await execFileAsync('git', ['checkout', '-b', 'main'], { cwd: repoRoot });
  await execFileAsync('git', ['config', 'user.name', 'Test User'], { cwd: repoRoot });
  await execFileAsync('git', ['config', 'user.email', 'test@example.com'], { cwd: repoRoot });

  await fs.writeFile(path.join(repoRoot, 'README.md'), '# Test Repository\n', 'utf8');
  await execFileAsync('git', ['add', 'README.md'], { cwd: repoRoot });
  await execFileAsync('git', ['commit', '-m', 'Initial commit'], { cwd: repoRoot });

  return repoRoot;
};

describe('@soipack/adapters', () => {
  const tempRepos: string[] = [];

  afterAll(async () => {
    await Promise.all(tempRepos.map((dir) => fs.rm(dir, { recursive: true, force: true })));
  });

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
    const filePath = path.resolve(__dirname, '../fixtures/jira/issues.sample.csv');
    const { data, warnings } = await importJiraCsv(filePath);

    expect(warnings).toHaveLength(0);
    expect(data).toHaveLength(3);

    const [epic, story, subTask] = data;

    expect(epic).toEqual({
      id: 'PROJ-1',
      summary: 'Implement login',
      status: 'In Progress',
      priority: 'High',
      description: 'Authentication epic covering login',
      components: ['Authentication'],
      labels: ['backend', 'critical'],
      links: ['PROJ-2', 'PROJ-3'],
      attachments: ['LoginSpec.docx', 'Sequence.png'],
    });

    expect(story).toEqual({
      id: 'PROJ-2',
      summary: 'Write API tests',
      status: 'Done',
      priority: 'Medium',
      description: 'API coverage for login flows',
      components: ['API'],
      labels: ['backend', 'testing'],
      epicLink: 'PROJ-1',
      links: ['PROJ-1'],
      children: ['PROJ-3'],
    });

    expect(subTask).toEqual({
      id: 'PROJ-3',
      summary: 'Design UI',
      status: 'To Do',
      priority: 'Low',
      description: 'Design the login user interface',
      labels: ['ui'],
      epicLink: 'PROJ-1',
      links: ['PROJ-1'],
      attachments: ['Wireframe.png'],
      parentId: 'PROJ-2',
    });
  });

  it('maps custom fields from Jira CSV when configured', async () => {
    const filePath = path.resolve(__dirname, '../fixtures/jira/issues.sample.csv');
    const { data, warnings } = await importJiraCsv(filePath, {
      customFieldMappings: {
        storyPoints: 'Story Points',
        qaOwner: ['QA Owner'],
      },
    });

    expect(warnings).toHaveLength(0);
    expect(data[0].customFields).toEqual({ storyPoints: '8', qaOwner: 'qa@example.com' });
    expect(data[1].customFields).toEqual({ storyPoints: '5', qaOwner: 'qa.lead@example.com' });
    expect(data[2].customFields).toEqual({ storyPoints: '3', qaOwner: 'designer@example.com' });
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

  it('collects rich git metadata for clean repositories', async () => {
    const repoRoot = await createGitRepository();
    tempRepos.push(repoRoot);

    await execFileAsync('git', ['remote', 'add', 'origin', 'https://example.com/repo.git'], {
      cwd: repoRoot,
    });

    const { data, warnings } = await importGitMetadata(repoRoot);

    expect(warnings).toHaveLength(0);
    expect(data).not.toBeNull();
    expect(data).toEqual(
      expect.objectContaining({
        hash: expect.any(String),
        author: 'Test User',
        branches: ['main'],
        tags: [],
        dirty: false,
        remoteOrigins: ['https://example.com/repo.git'],
      }),
    );
  });

  it('captures tags that point to the current commit', async () => {
    const repoRoot = await createGitRepository();
    tempRepos.push(repoRoot);

    await execFileAsync('git', ['tag', 'v1.0.0'], { cwd: repoRoot });

    const { data } = await importGitMetadata(repoRoot);

    expect(data).not.toBeNull();
    expect(data?.tags).toEqual(['v1.0.0']);
  });

  it('marks dirty working trees and reports warnings', async () => {
    const repoRoot = await createGitRepository();
    tempRepos.push(repoRoot);

    await execFileAsync('git', ['remote', 'add', 'origin', 'https://example.com/repo.git'], {
      cwd: repoRoot,
    });

    await fs.appendFile(path.join(repoRoot, 'README.md'), 'Modified\n', 'utf8');

    const { data, warnings } = await importGitMetadata(repoRoot);

    expect(data).not.toBeNull();
    expect(data?.dirty).toBe(true);
    expect(warnings).toContain('Repository has uncommitted changes.');
  });
});
