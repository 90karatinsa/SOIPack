import { createHash } from 'crypto';
import { EventEmitter } from 'events';
import { promises as fs } from 'fs';
import http from 'http';
import os from 'os';
import path from 'path';
import { PassThrough } from 'stream';

import { Manifest } from '@soipack/core';
import { ImportBundle, TraceEngine } from '@soipack/engine';
import { signManifest, verifyManifestSignature } from '@soipack/packager';

import type { LicensePayload } from './license';
import type { Logger } from './logging';

import {
  downloadPackageArtifacts,
  exitCodes,
  runAnalyze,
  runObjectivesList,
  runImport,
  runPack,
  runIngestPipeline,
  runIngestAndPackage,
  runReport,
  runVerify,
  __internal,
} from './index';

const TEST_SIGNING_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEICiI0Jsw2AjCiWk2uBb89bIQkOH18XHytA2TtblwFzgQ
-----END PRIVATE KEY-----
`;

const TEST_SIGNING_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAOCPbC2Pxenbum50JoDbus/HoZnN2okit05G+z44CvK8=
-----END PUBLIC KEY-----
`;

describe('@soipack/cli pipeline', () => {
  const fixturesDir = path.resolve(__dirname, '../../../examples/minimal');
  const objectivesPath = path.resolve(
    __dirname,
    '../../../data/objectives/do178c_objectives.min.json',
  );
  let tempRoot: string;

  beforeAll(async () => {
    tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'soipack-cli-'));
  });

  afterAll(async () => {
    await fs.rm(tempRoot, { recursive: true, force: true });
  });

  it('runs the minimal demo end-to-end', async () => {
    const workDir = path.join(tempRoot, 'work');
    const analysisDir = path.join(tempRoot, 'analysis');
    const distDir = path.join(tempRoot, 'dist');
    const reportsDir = path.join(distDir, 'reports');
    const releaseDir = path.join(tempRoot, 'release');

    const importResult = await runImport({
      output: workDir,
      jira: path.join(fixturesDir, 'issues.csv'),
      reqif: path.join(fixturesDir, 'spec.reqif'),
      junit: path.join(fixturesDir, 'results.xml'),
      lcov: path.join(fixturesDir, 'lcov.info'),
      cobertura: path.join(fixturesDir, 'coverage.xml'),
      git: path.resolve(fixturesDir, '../..'),
      level: 'C',
      objectives: objectivesPath,
      projectName: 'Demo Avionics',
      projectVersion: '1.0.0',
    });

    const workspaceStats = await fs.stat(path.join(workDir, 'workspace.json'));
    expect(workspaceStats.isFile()).toBe(true);
    expect(importResult.workspace.requirements.length).toBeGreaterThan(0);

    const analysisResult = await runAnalyze({
      input: workDir,
      output: analysisDir,
      level: 'C',
      objectives: objectivesPath,
      projectName: 'Demo Avionics',
      projectVersion: '1.0.0',
    });

    expect([exitCodes.success, exitCodes.missingEvidence]).toContain(analysisResult.exitCode);

    const reportResult = await runReport({
      input: analysisDir,
      output: reportsDir,
    });

    const complianceHtmlStats = await fs.stat(reportResult.complianceHtml);
    expect(complianceHtmlStats.isFile()).toBe(true);

    expect(Object.keys(reportResult.plans)).toEqual(
      expect.arrayContaining(['psac', 'sdp', 'svp', 'scmp', 'sqap']),
    );
    const psacPlan = reportResult.plans.psac;
    const psacDocxStats = await fs.stat(psacPlan.docx);
    expect(psacDocxStats.isFile()).toBe(true);
    if (psacPlan.pdf) {
      const psacPdfStats = await fs.stat(psacPlan.pdf);
      expect(psacPdfStats.isFile()).toBe(true);
    } else {
      expect(reportResult.warnings.some((warning) => warning.includes('PDF generation'))).toBe(true);
    }

    const analysisWithPlans = JSON.parse(
      await fs.readFile(path.join(reportsDir, 'analysis.json'), 'utf8'),
    ) as { warnings: string[] };
    reportResult.warnings.forEach((warning) => {
      expect(analysisWithPlans.warnings).toContain(warning);
    });

    const packResult = await runPack({
      input: distDir,
      output: releaseDir,
      packageName: 'demo.zip',
      signingKey: TEST_SIGNING_PRIVATE_KEY,
    });

    const archiveStats = await fs.stat(packResult.archivePath);
    expect(archiveStats.isFile()).toBe(true);
    expect(packResult.manifestId).toHaveLength(12);

    const manifestStats = await fs.stat(packResult.manifestPath);
    expect(manifestStats.isFile()).toBe(true);

    const manifest = JSON.parse(await fs.readFile(packResult.manifestPath, 'utf8')) as Manifest;
    const signature = (await fs.readFile(path.join(releaseDir, 'manifest.sig'), 'utf8')).trim();
    expect(verifyManifestSignature(manifest, signature, TEST_SIGNING_PUBLIC_KEY)).toBe(true);
  });

  it('generates compliance and coverage summaries with runIngestPipeline', async () => {
    const ingestOutput = path.join(tempRoot, 'ingest-dist');
    const workingDir = path.join(tempRoot, 'ingest-work');

    const result = await runIngestPipeline({
      inputDir: fixturesDir,
      outputDir: ingestOutput,
      workingDir,
      objectives: objectivesPath,
      level: 'C',
      projectName: 'Demo Avionics',
      projectVersion: '1.0.0',
    });

    expect(result.reportsDir).toBe(path.join(ingestOutput, 'reports'));
    expect(result.complianceSummary.total).toBeGreaterThan(0);
    expect(result.complianceSummary.covered).toBeGreaterThan(0);
    expect(result.coverageSummary).toEqual(expect.objectContaining({ statements: expect.any(Number) }));
    const complianceStats = await fs.stat(result.compliancePath);
    expect(complianceStats.isFile()).toBe(true);
  });

  it('packages demo data into a signed archive with consistent manifest hashes', async () => {
    const packageOutput = path.join(tempRoot, 'ingest-package');

    const result = await runIngestAndPackage({
      inputDir: fixturesDir,
      outputDir: packageOutput,
      objectives: objectivesPath,
      level: 'C',
      projectName: 'Demo Avionics',
      projectVersion: '1.0.0',
      signingKey: TEST_SIGNING_PRIVATE_KEY,
      packageName: 'soi-pack.zip',
    });

    const archiveStats = await fs.stat(result.archivePath);
    expect(archiveStats.isFile()).toBe(true);
    expect(result.archivePath).toBe(path.join(packageOutput, 'soi-pack.zip'));

    const manifest = JSON.parse(await fs.readFile(result.manifestPath, 'utf8')) as Manifest;
    expect(manifest.files.length).toBeGreaterThan(0);

    const firstEntry = manifest.files[0];
    const assetPath = path.join(packageOutput, firstEntry.path);
    const assetContent = await fs.readFile(assetPath);
    const computedHash = createHash('sha256').update(assetContent).digest('hex');
    expect(computedHash).toBe(firstEntry.sha256);

    const signature = (await fs.readFile(path.join(packageOutput, 'manifest.sig'), 'utf8')).trim();
    expect(verifyManifestSignature(manifest, signature, TEST_SIGNING_PUBLIC_KEY)).toBe(true);
  });

  it('fails manifest verification when packaged data is tampered', async () => {
    const tamperOutput = path.join(tempRoot, 'ingest-package-tamper');

    const result = await runIngestAndPackage({
      inputDir: fixturesDir,
      outputDir: tamperOutput,
      objectives: objectivesPath,
      level: 'C',
      projectName: 'Demo Avionics',
      projectVersion: '1.0.0',
      signingKey: TEST_SIGNING_PRIVATE_KEY,
      packageName: 'soi-pack.zip',
    });

    const manifest = JSON.parse(await fs.readFile(result.manifestPath, 'utf8')) as Manifest;
    expect(manifest.files.length).toBeGreaterThan(0);
    manifest.files[0].sha256 = '0'.repeat(64);
    await fs.writeFile(result.manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');

    const signature = (await fs.readFile(path.join(tamperOutput, 'manifest.sig'), 'utf8')).trim();
    expect(verifyManifestSignature(manifest, signature, TEST_SIGNING_PUBLIC_KEY)).toBe(false);
  });

  it('derives test-to-code mapping from coverage adapters', async () => {
    const mappingRoot = await fs.mkdtemp(path.join(tempRoot, 'mapping-'));
    const workDir = path.join(mappingRoot, 'workspace');
    const junitPath = path.join(mappingRoot, 'results.xml');
    const lcovPath = path.join(mappingRoot, 'lcov.info');

    await fs.writeFile(
      junitPath,
      `<?xml version="1.0"?><testsuite name="Sample"><testcase classname="AuthTests" name="validates login" time="1.2" /></testsuite>`,
      'utf8',
    );

    await fs.writeFile(
      lcovPath,
      [
        'TN:AuthTests#validates login',
        'SF:src/auth/login.ts',
        'DA:1,1',
        'LF:1',
        'LH:1',
        'end_of_record',
      ].join('\n'),
      'utf8',
    );

    const result = await runImport({
      output: workDir,
      junit: junitPath,
      lcov: lcovPath,
    });

    expect(result.workspace.testToCodeMap).toHaveProperty('AuthTests#validates login');
    expect(result.workspace.testToCodeMap['AuthTests#validates login']).toEqual([
      'src/auth/login.ts',
    ]);
  });

  it('ingests manual trace links and merges them with generated data without duplicates', async () => {
    const fixtureDir = path.join(__dirname, '__fixtures__', 'manual-links');
    const workDir = path.join(tempRoot, 'manual-links-workspace');

    const result = await runImport({
      output: workDir,
      jira: path.join(fixtureDir, 'issues.csv'),
      junit: path.join(fixtureDir, 'results.xml'),
      lcov: path.join(fixtureDir, 'lcov.info'),
      traceLinksCsv: path.join(fixtureDir, 'trace-links.csv'),
      traceLinksJson: path.join(fixtureDir, 'trace-links.json'),
    });

    expect(result.warnings).toContain(
      'Birden fazla kaynaktan gelen yinelenen izlenebilirlik bağlantıları bulundu ve yok sayıldı.',
    );

    expect(result.workspace.traceLinks).toHaveLength(3);
    expect(result.workspace.traceLinks).toEqual(
      expect.arrayContaining([
        { from: 'REQ-1', to: 'AuthTests#validates login', type: 'verifies' },
        { from: 'REQ-2', to: 'AuthTests#handles lockout', type: 'verifies' },
        { from: 'REQ-3', to: 'src/auth/login.ts', type: 'implements' },
      ]),
    );

    const bundle: ImportBundle = {
      requirements: result.workspace.requirements,
      objectives: [],
      testResults: result.workspace.testResults,
      coverage: result.workspace.coverage,
      evidenceIndex: result.workspace.evidenceIndex,
      traceLinks: result.workspace.traceLinks,
      testToCodeMap: result.workspace.testToCodeMap,
      generatedAt: result.workspace.metadata.generatedAt,
    };

    const engine = new TraceEngine(bundle);
    const manualTrace = engine.getRequirementTrace('REQ-3');
    expect(manualTrace.tests).toHaveLength(0);
    expect(manualTrace.code.map((entry) => entry.path)).toContain('src/auth/login.ts');

    const derivedTrace = engine.getRequirementTrace('REQ-2');
    expect(derivedTrace.tests.map((test) => test.testId)).toContain('AuthTests#handles lockout');
  });
});

describe('runObjectivesList', () => {
  const objectivesPath = path.resolve(
    __dirname,
    '../../../data/objectives/do178c_objectives.min.json',
  );

  it('loads objectives from the given path', async () => {
    const result = await runObjectivesList({ objectives: objectivesPath });
    expect(result.sourcePath).toBe(objectivesPath);
    expect(result.objectives.length).toBeGreaterThan(0);
  });

  it('filters objectives by certification level', async () => {
    const all = await runObjectivesList({ objectives: objectivesPath, level: 'A' });
    const levelC = await runObjectivesList({ objectives: objectivesPath, level: 'C' });

    expect(all.objectives.every((objective) => objective.levels.A)).toBe(true);
    expect(levelC.objectives.every((objective) => objective.levels.C)).toBe(true);
    expect(levelC.objectives.length).toBeLessThan(all.objectives.length);
  });
});

describe('runPack package name validation', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'soipack-pack-name-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  const createPackInputs = async () => {
    const distDir = path.join(tempDir, 'dist');
    const reportsDir = path.join(distDir, 'reports');
    const releaseDir = path.join(tempDir, 'release');
    await fs.mkdir(reportsDir, { recursive: true });
    await fs.writeFile(path.join(reportsDir, 'report.txt'), 'demo report', 'utf8');
    return { distDir, releaseDir };
  };

  it('accepts release.zip as a package name', async () => {
    const { distDir, releaseDir } = await createPackInputs();

    const result = await runPack({
      input: distDir,
      output: releaseDir,
      packageName: 'release.zip',
      signingKey: TEST_SIGNING_PRIVATE_KEY,
    });

    expect(path.basename(result.archivePath)).toBe('release.zip');
  });

  it.each([
    '../hack.zip',
    path.join(path.sep, 'tmp', 'hack.zip'),
  ])('rejects unsafe package name %s', async (packageName) => {
    const { distDir, releaseDir } = await createPackInputs();

    await expect(
      runPack({
        input: distDir,
        output: releaseDir,
        packageName,
        signingKey: TEST_SIGNING_PRIVATE_KEY,
      }),
    ).rejects.toThrow(/packageName/);
  });
});

describe('runVerify', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'soipack-verify-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  const createManifest = (): Manifest => ({
    files: [
      {
        path: 'reports/compliance_matrix.html',
        sha256: 'abc123def4567890abc123def4567890abc123def4567890abc123def4567890',
      },
      {
        path: 'reports/gaps.html',
        sha256: 'def123abc4567890def123abc4567890def123abc4567890def123abc4567890',
      },
    ],
    createdAt: '2024-01-01T00:00:00.000Z',
    toolVersion: '1.0.0-test',
  });

  const writeVerificationFiles = async (
    manifest: Manifest,
    overrides: {
      manifestJson?: string;
      signature?: string;
    } = {},
  ): Promise<{ manifestPath: string; signaturePath: string; publicKeyPath: string }> => {
    const manifestPath = path.join(tempDir, 'manifest.json');
    const signaturePath = path.join(tempDir, 'manifest.sig');
    const publicKeyPath = path.join(tempDir, 'public.pem');

    const manifestJson = overrides.manifestJson ?? `${JSON.stringify(manifest, null, 2)}\n`;
    await fs.writeFile(manifestPath, manifestJson, 'utf8');

    const signatureValue = overrides.signature ?? signManifest(manifest, TEST_SIGNING_PRIVATE_KEY);
    await fs.writeFile(signaturePath, `${signatureValue}\n`, 'utf8');

    await fs.writeFile(publicKeyPath, TEST_SIGNING_PUBLIC_KEY, 'utf8');

    return { manifestPath, signaturePath, publicKeyPath };
  };

  it('returns success for a valid manifest signature', async () => {
    const manifest = createManifest();
    const { manifestPath, signaturePath, publicKeyPath } = await writeVerificationFiles(manifest);

    const result = await runVerify({ manifestPath, signaturePath, publicKeyPath });

    expect(result.isValid).toBe(true);
    expect(result.manifestId).toHaveLength(12);
  });

  it('flags tampered manifests as invalid', async () => {
    const manifest = createManifest();
    const originalSignature = signManifest(manifest, TEST_SIGNING_PRIVATE_KEY);
    const tamperedManifest = {
      ...manifest,
      files: [
        ...manifest.files,
        {
          path: 'evidence/new.txt',
          sha256: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        },
      ],
    } satisfies Manifest;

    const { manifestPath, signaturePath, publicKeyPath } = await writeVerificationFiles(
      tamperedManifest,
      {
        signature: originalSignature,
      },
    );

    const result = await runVerify({ manifestPath, signaturePath, publicKeyPath });

    expect(result.isValid).toBe(false);
    expect(result.manifestId).toHaveLength(12);
  });

  it('throws on malformed manifest inputs', async () => {
    const manifest = createManifest();
    const malformedJson = '{"files": ["broken"]';
    const { manifestPath, signaturePath, publicKeyPath } = await writeVerificationFiles(manifest, {
      manifestJson: malformedJson,
    });

    await expect(runVerify({ manifestPath, signaturePath, publicKeyPath })).rejects.toThrow(
      /Manifest JSON formatı çözümlenemedi/,
    );
  });
});

describe('downloadPackageArtifacts', () => {
  class MockClientRequest extends EventEmitter {
    timeoutHandler?: () => void;
    timeoutMs?: number;

    setTimeout(ms: number, handler: () => void): this {
      this.timeoutMs = ms;
      this.timeoutHandler = handler;
      return this;
    }

    triggerTimeout(): void {
      this.timeoutHandler?.();
    }

    destroy(error?: Error): this {
      if (error) {
        this.emit('error', error);
      }
      return this;
    }
  }

  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'soipack-download-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  const createHttpGetMock = () => jest.fn() as jest.MockedFunction<typeof http.get>;

  it('rejects HTTP downloads when insecure flag is not set', async () => {
    const getMock = createHttpGetMock();

    await expect(
      downloadPackageArtifacts({
        baseUrl: 'http://example.com',
        token: 'demo-token',
        packageId: 'pkg-123',
        outputDir: tempDir,
        httpGet: getMock,
      }),
    ).rejects.toThrow('HTTP istekleri varsayılan olarak engellenir');

    expect(getMock).not.toHaveBeenCalled();
  });

  it('allows HTTP downloads when --allow-insecure-http is set', async () => {
    const requests: MockClientRequest[] = [];
    let callCount = 0;
    const getMock = createHttpGetMock();

    getMock.mockImplementation(((url: unknown, _options: unknown, callback: (res: http.IncomingMessage) => void) => {
        const request = new MockClientRequest();
        requests.push(request);

        const responseStream = new PassThrough();
        const response = Object.assign(responseStream, {
          statusCode: 200,
          headers: {} as http.IncomingHttpHeaders,
        }) as unknown as http.IncomingMessage;

        process.nextTick(() => {
          callback(response);
          responseStream.write(callCount === 0 ? 'archive-content' : 'manifest-content');
          responseStream.end();
        });

        callCount += 1;

        return request as unknown as http.ClientRequest;
      }) as unknown as typeof http.get);

    const result = await downloadPackageArtifacts({
      baseUrl: 'http://example.com',
      token: 'demo-token',
      packageId: 'pkg-123',
      outputDir: tempDir,
      allowInsecureHttp: true,
      httpGet: getMock,
    });

    expect(callCount).toBe(2);
    expect(requests).toHaveLength(2);
    requests.forEach((request) => expect(typeof request.timeoutHandler).toBe('function'));

    const archiveStats = await fs.stat(result.archivePath);
    const manifestStats = await fs.stat(result.manifestPath);
    expect(archiveStats.isFile()).toBe(true);
    expect(manifestStats.isFile()).toBe(true);
    expect(archiveStats.size).toBeGreaterThan(0);
    expect(manifestStats.size).toBeGreaterThan(0);
  });

  it('aborts requests that exceed the timeout', async () => {
    const requests: MockClientRequest[] = [];
    const getMock = createHttpGetMock();

    getMock.mockImplementation(((...args: Parameters<typeof http.get>) => {
        void args;
        const request = new MockClientRequest();
        requests.push(request);
        return request as unknown as http.ClientRequest;
      }) as unknown as typeof http.get);

    const downloadPromise = downloadPackageArtifacts({
      baseUrl: 'http://example.com',
      token: 'demo-token',
      packageId: 'pkg-123',
      outputDir: tempDir,
      allowInsecureHttp: true,
      httpGet: getMock,
    });

    await new Promise((resolve) => setTimeout(resolve, 20));

    expect(getMock).toHaveBeenCalledTimes(1);
    const request = requests[0];
    expect(request).toBeDefined();
    expect(request!.timeoutHandler).toBeDefined();

    request!.triggerTimeout();

    await expect(downloadPromise).rejects.toThrow('tamamlanmadı');
  });
});

describe('logLicenseValidated redaction', () => {
  it('hashes license identifiers before logging', () => {
    const debug = jest.fn();
    const stubLogger = {
      debug,
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
      fatal: jest.fn(),
      trace: jest.fn(),
      level: 'info',
      child: jest.fn(),
    };
    const logger = stubLogger as unknown as Logger;
    (stubLogger.child as jest.Mock).mockReturnValue(logger);
    const license: LicensePayload = {
      licenseId: 'test-license-id',
      issuedTo: 'Test Issued To',
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
      features: ['feature-a'],
    };

    __internal.logLicenseValidated(logger, license, { command: 'test' });

    expect(debug.mock.calls.length).toBe(1);
    const [payload] = debug.mock.calls[0];
    expect(payload.licenseIdFingerprint).toMatch(/^sha256:/);
    expect(payload.issuedToFingerprint).toMatch(/^sha256:/);
    expect(payload.licenseIdFingerprint).not.toContain('test-license-id');
    expect(payload.issuedToFingerprint).not.toContain('Test Issued To');
    expect(payload).not.toHaveProperty('licenseId');
    expect(payload).not.toHaveProperty('issuedTo');
  });
});
