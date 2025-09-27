import { execFile } from 'child_process';
import { createWriteStream, promises as fs } from 'fs';
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
  importDoorsClassicCsv,
  parseJUnitStream,
  parseLcovStream,
  parseReqifStream,
  registerAdapter,
  toRequirement,
  fetchDoorsNextArtifacts,
  doorsNextAdapterMetadata,
  aggregateImportBundle,
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
  const tempDirs: string[] = [];

  afterAll(async () => {
    const targets = [...tempRepos, ...tempDirs];
    await Promise.all(targets.map((dir) => fs.rm(dir, { recursive: true, force: true })));
  });

  const createTempFilePath = async (prefix: string): Promise<string> => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
    tempDirs.push(dir);
    return path.join(dir, 'input');
  };

  const createLargeJUnitFile = async (testcaseCount: number): Promise<string> => {
    const filePath = await createTempFilePath('soipack-junit-');
    const stream = createWriteStream(filePath, { encoding: 'utf8' });
    await new Promise<void>((resolve, reject) => {
      stream.on('error', reject);
      stream.write('<testsuite name="LargeSuite">\n');
      for (let index = 0; index < testcaseCount; index += 1) {
        const requirementId = String(index).padStart(5, '0');
        const payload =
          `<testcase classname="LargeSuite" name="case-${index}" time="0.1">` +
          `<failure message="Assertion failed">Detailed failure message ${'X'.repeat(256)}</failure>` +
          `<properties><property name="requirements">REQ-${requirementId}</property></properties>` +
          '</testcase>\n';
        stream.write(payload);
      }
      stream.write('</testsuite>');
      stream.end(() => resolve());
    });
    return filePath;
  };

  const createLargeLcovFile = async (recordCount: number): Promise<string> => {
    const filePath = await createTempFilePath('soipack-lcov-');
    const stream = createWriteStream(filePath, { encoding: 'utf8' });
    await new Promise<void>((resolve, reject) => {
      stream.on('error', reject);
      for (let index = 0; index < recordCount; index += 1) {
        stream.write(`TN:Suite${Math.floor(index / 10)}\n`);
        stream.write(`SF:/workspace/app/src/file${index}.ts\n`);
        stream.write('LF:200\n');
        stream.write('LH:150\n');
        stream.write('BRF:40\n');
        stream.write('BRH:20\n');
        stream.write('FNF:10\n');
        stream.write('FNH:7\n');
        stream.write('DA:1,1\n'.repeat(25));
        stream.write('end_of_record\n');
      }
      stream.end(() => resolve());
    });
    return filePath;
  };

  const createLargeReqifFile = async (objectCount: number): Promise<string> => {
    const filePath = await createTempFilePath('soipack-reqif-');
    const stream = createWriteStream(filePath, { encoding: 'utf8' });
    await new Promise<void>((resolve, reject) => {
      stream.on('error', reject);
      stream.write('<REQ-IF><CORE-CONTENT><SPEC-OBJECTS>');
      for (let index = 0; index < objectCount; index += 1) {
        const payload = 'Requirement text ' + index + ' ' + 'detail '.repeat(60);
        stream.write(
          `<SPEC-OBJECT IDENTIFIER="REQ-${String(index).padStart(5, '0')}">` +
            '<VALUES><ATTRIBUTE-VALUE-STRING><THE-VALUE>' +
            payload +
            '</THE-VALUE></ATTRIBUTE-VALUE-STRING></VALUES></SPEC-OBJECT>',
        );
      }
      stream.write('</SPEC-OBJECTS></CORE-CONTENT></REQ-IF>');
      stream.end(() => resolve());
    });
    return filePath;
  };

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

  it('exposes DOORS Classic CSV importer through the facade', () => {
    expect(typeof importDoorsClassicCsv).toBe('function');
  });

  it('aggregates remote bundles while deduplicating requirement identifiers', async () => {
    const factory = aggregateImportBundle([
      async () => ({
        data: {
          requirements: [
            { id: 'REQ-1', title: 'First requirement' },
            { id: 'REQ-2', title: 'Second requirement' },
          ],
          traces: [{ fromId: 'REQ-1', toId: 'TC-1', type: 'verifies' }],
        },
        warnings: ['alpha'],
      }),
      async () => ({
        data: {
          requirements: [
            { id: 'req-1', title: 'Duplicate first' },
            { id: 'REQ-3', title: 'Third requirement' },
          ],
          traces: [{ fromId: 'REQ-3', toId: 'REQ-1', type: 'satisfies' }],
        },
        warnings: ['beta'],
      }),
    ]);

    expect(typeof factory).toBe('function');

    const result = await factory();
    expect(result.warnings).toEqual(['alpha', 'beta']);
    expect(result.data.requirements).toHaveLength(3);
    expect(result.data.requirements).toEqual(
      expect.arrayContaining([
        { id: 'REQ-1', title: 'First requirement' },
        { id: 'REQ-2', title: 'Second requirement' },
        { id: 'REQ-3', title: 'Third requirement' },
      ]),
    );
    expect(result.data.traces).toEqual(
      expect.arrayContaining([
        { fromId: 'REQ-1', toId: 'TC-1', type: 'verifies' },
        { fromId: 'REQ-3', toId: 'REQ-1', type: 'satisfies' },
      ]),
    );
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
      issueType: 'Epic',
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
      issueType: 'Story',
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
      issueType: 'Sub-task',
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
    expect(data[0]).toMatchObject({ id: 'REQ-1', text: 'System shall allow login.' });
    expect(data[1]).toMatchObject({ id: 'REQ-2', text: 'System shall log errors.' });
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
  describe('streaming converters', () => {
    it('processes large JUnit XML files efficiently', async () => {
      const filePath = await createLargeJUnitFile(28000);
      const stats = await fs.stat(filePath);
      expect(stats.size).toBeGreaterThan(5 * 1024 * 1024);
      const { data, warnings } = await parseJUnitStream(filePath);
      expect(data).toHaveLength(28000);
      expect(warnings).toHaveLength(0);
    });

    it('rejects malformed JUnit XML with descriptive errors', async () => {
      const filePath = await createTempFilePath('soipack-bad-junit-');
      await fs.writeFile(filePath, '<testsuite><testcase></testsuite>', 'utf8');
      await expect(parseJUnitStream(filePath)).rejects.toThrow(/Invalid JUnit XML/);
    });

    it('processes large LCOV reports without exhausting memory', async () => {
      const filePath = await createLargeLcovFile(26000);
      const stats = await fs.stat(filePath);
      expect(stats.size).toBeGreaterThan(5 * 1024 * 1024);
      const { data, warnings } = await parseLcovStream(filePath);
      expect(data.files).toHaveLength(26000);
      expect(data.totals.statements.total).toBe(26000 * 200);
      expect(warnings).toHaveLength(0);
    });

    it('rejects malformed LCOV reports with actionable errors', async () => {
      const filePath = await createTempFilePath('soipack-bad-lcov-');
      await fs.writeFile(filePath, 'TN:Broken\nend_of_record\n', 'utf8');
      await expect(parseLcovStream(filePath)).rejects.toThrow(/LCOV/);
    });

    it('processes large ReqIF packages without OOM', async () => {
      const filePath = await createLargeReqifFile(15000);
      const stats = await fs.stat(filePath);
      expect(stats.size).toBeGreaterThan(5 * 1024 * 1024);
      const { data, warnings } = await parseReqifStream(filePath);
      expect(data).toHaveLength(15000);
      expect(warnings.filter((warning) => warning.includes('THE-VALUE'))).toHaveLength(0);
    });

    it('rejects malformed ReqIF documents with descriptive errors', async () => {
      const filePath = await createTempFilePath('soipack-bad-reqif-');
      await fs.writeFile(filePath, '<REQ-IF><SPEC-OBJECTS><SPEC-OBJECT>', 'utf8');
      await expect(parseReqifStream(filePath)).rejects.toThrow(/Invalid ReqIF XML/);
    });
  });

  it('exposes the DOORS Next adapter through the barrel module', () => {
    expect(typeof fetchDoorsNextArtifacts).toBe('function');
    expect(doorsNextAdapterMetadata).toEqual({
      name: 'IBM DOORS Next Generation',
      supportedArtifacts: ['requirements', 'tests', 'designs'],
      description: 'Fetches DOORS Next /rm requirements, test cases, and design records via OSLC.',
    });
  });

});
