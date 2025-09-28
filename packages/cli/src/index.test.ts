import { createHash, X509Certificate } from 'crypto';
import { EventEmitter } from 'events';
import { promises as fs, readFileSync, createWriteStream } from 'fs';
import http from 'http';
import os from 'os';
import path from 'path';
import { PassThrough } from 'stream';

jest.setTimeout(180000);

import * as adapters from '@soipack/adapters';
import type { CoverageReport, CoverageSummary as StructuralCoverageSummary } from '@soipack/adapters';
import { Manifest, SnapshotVersion } from '@soipack/core';
import { ImportBundle, TraceEngine } from '@soipack/engine';
import { signManifestBundle, verifyManifestSignature, verifyManifestSignatureDetailed } from '@soipack/packager';
import type { PlanTemplateId } from '@soipack/report';
import { createReportFixture } from '@soipack/report/__fixtures__/snapshot';
import { ZipFile } from 'yazl';

type ManifestWithSbom = Manifest & {
  sbom?: { path: string; algorithm: string; digest: string } | null;
};

import type { LicensePayload } from './license';
import { setCliLocale } from './localization';
import type { Logger } from './logging';

jest.mock(
  'yauzl',
  () => ({
    open: jest.fn(),
    fromBuffer: jest.fn(),
    ZipFile: function MockZipFile() {},
  }),
  { virtual: true },
);

jest.mock(
  'saxes',
  () => {
    class MockSaxesParser {
      // eslint-disable-next-line @typescript-eslint/no-empty-function
      on() {}
      write() {
        return this;
      }
      // eslint-disable-next-line @typescript-eslint/no-empty-function
      close() {}
    }
    return { SaxesParser: MockSaxesParser, SaxesTagPlain: class {} };
  },
  { virtual: true },
);

jest.mock(
  'fast-xml-parser',
  () => ({
    XMLParser: class {
      parse() {
        return {};
      }
    },
  }),
  { virtual: true },
);

import {
  downloadPackageArtifacts,
  exitCodes,
  runAnalyze,
  runObjectivesList,
  runGeneratePlans,
  runFreeze,
  runImport,
  runPack,
  runIngestPipeline,
  runIngestAndPackage,
  runReport,
  runVerify,
  runRiskSimulate,
  __internal,
} from './index';

const DEV_CERT_BUNDLE_PATH = path.resolve(__dirname, '../../../test/certs/dev.pem');
const TEST_SIGNING_BUNDLE = readFileSync(DEV_CERT_BUNDLE_PATH, 'utf8');
const CMS_CERT_BUNDLE_PATH = path.resolve(__dirname, '../../../test/certs/cms-test.pem');
const TEST_CMS_BUNDLE = readFileSync(CMS_CERT_BUNDLE_PATH, 'utf8');
const CERTIFICATE_PATTERN = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/;
const TEST_SIGNING_CERTIFICATE = (() => {
  const match = TEST_SIGNING_BUNDLE.match(CERTIFICATE_PATTERN);
  if (!match) {
    throw new Error('Test certificate bundle is invalid.');
  }
  return match[0];
})();
const TEST_CMS_CERTIFICATE = (() => {
  const match = TEST_CMS_BUNDLE.match(CERTIFICATE_PATTERN);
  if (!match) {
    throw new Error('Test CMS certificate bundle is invalid.');
  }
  return match[0];
})();
const TEST_SIGNING_PUBLIC_KEY = new X509Certificate(TEST_SIGNING_CERTIFICATE)
  .publicKey.export({ format: 'pem', type: 'spki' })
  .toString();

afterEach(() => {
  jest.restoreAllMocks();
});

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

    const statementEvidence = importResult.workspace.evidenceIndex.coverage_stmt ?? [];
    expect(statementEvidence.map((entry) => entry.source)).toEqual(
      expect.arrayContaining(['lcov', 'cobertura']),
    );
    const decisionEvidence = importResult.workspace.evidenceIndex.coverage_dec ?? [];
    expect(decisionEvidence).toHaveLength(0);
    const mcdcEvidence = importResult.workspace.evidenceIndex.coverage_mcdc ?? [];
    expect(mcdcEvidence).toHaveLength(0);

    const workspaceStats = await fs.stat(path.join(workDir, 'workspace.json'));
    expect(workspaceStats.isFile()).toBe(true);
    expect(importResult.workspace.requirements.length).toBeGreaterThan(0);
    expect(importResult.workspace.metadata.version.id).toMatch(/^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}$/);
    expect(importResult.workspace.metadata.version.isFrozen).toBe(false);

    const analysisResult = await runAnalyze({
      input: workDir,
      output: analysisDir,
      level: 'C',
      objectives: objectivesPath,
      projectName: 'Demo Avionics',
      projectVersion: '1.0.0',
    });

    expect([exitCodes.success, exitCodes.missingEvidence]).toContain(analysisResult.exitCode);

    const snapshotData = JSON.parse(
      await fs.readFile(analysisResult.snapshotPath, 'utf8'),
    ) as { version: SnapshotVersion };
    expect(snapshotData.version.fingerprint).toHaveLength(64);
    expect(snapshotData.version.id).toMatch(/^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}$/);

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
    ) as { warnings: string[]; metadata: { version: SnapshotVersion } };
    reportResult.warnings.forEach((warning) => {
      expect(analysisWithPlans.warnings).toContain(warning);
    });
    expect(analysisWithPlans.metadata.version.id).toBe(snapshotData.version.id);

    const ledgerPath = path.join(tempRoot, 'ledger-e2e.json');
    const packResult = await runPack({
      input: distDir,
      output: releaseDir,
      packageName: 'demo.zip',
      signingKey: TEST_SIGNING_BUNDLE,
      ledger: { path: ledgerPath },
      cms: { bundlePem: TEST_CMS_BUNDLE },
    });

    const archiveStats = await fs.stat(packResult.archivePath);
    expect(archiveStats.isFile()).toBe(true);
    expect(packResult.manifestId).toHaveLength(12);
    expect(packResult.manifestDigest).toHaveLength(64);
    expect(packResult.ledgerPath).toBe(ledgerPath);
    expect(packResult.ledgerEntry).toBeDefined();

    const manifestStats = await fs.stat(packResult.manifestPath);
    expect(manifestStats.isFile()).toBe(true);

    expect(packResult.sbomPath).toBe(path.join(releaseDir, 'sbom.spdx.json'));
    const sbomContent = await fs.readFile(packResult.sbomPath, 'utf8');
    const sbomDigest = createHash('sha256').update(sbomContent).digest('hex');
    expect(packResult.sbomSha256).toBe(sbomDigest);
    const sbomDocument = JSON.parse(sbomContent) as { spdxVersion: string; files: unknown[] };
    expect(sbomDocument.spdxVersion).toBe('SPDX-2.3');
    expect(Array.isArray(sbomDocument.files)).toBe(true);

    const manifest = JSON.parse(await fs.readFile(packResult.manifestPath, 'utf8')) as ManifestWithSbom & {
      ledger?: { root: string | null; previousRoot: string | null } | null;
    };
    const signature = (await fs.readFile(path.join(releaseDir, 'manifest.sig'), 'utf8')).trim();
    const cmsPath = path.join(releaseDir, 'manifest.cms');
    const cmsContent = await fs.readFile(cmsPath, 'utf8');
    expect(cmsContent.trim()).toContain('BEGIN PKCS7');
    expect(packResult.cmsSignaturePath).toBe(cmsPath);
    const cmsHash = createHash('sha256').update(cmsContent).digest('hex');
    expect(packResult.cmsSignatureSha256).toBe(cmsHash);
    expect(verifyManifestSignature(manifest, signature, TEST_SIGNING_PUBLIC_KEY)).toBe(true);
    expect(manifest.ledger).toEqual({
      root: packResult.ledgerEntry?.ledgerRoot ?? null,
      previousRoot: packResult.ledgerEntry?.previousRoot ?? null,
    });
    expect(manifest.sbom).toEqual({
      path: 'sbom.spdx.json',
      algorithm: 'sha256',
      digest: packResult.sbomSha256,
    });

    const detailedVerification = verifyManifestSignatureDetailed(manifest, signature, {
      publicKeyPem: TEST_SIGNING_PUBLIC_KEY,
      expectedLedgerRoot: packResult.ledgerEntry?.ledgerRoot,
      expectedPreviousLedgerRoot: packResult.ledgerEntry?.previousRoot,
      requireLedgerProof: true,
      cms: {
        signaturePem: cmsContent.trim(),
        certificatePem: TEST_CMS_CERTIFICATE,
        required: true,
      },
    });
    expect(detailedVerification.valid).toBe(true);
    expect(detailedVerification.cms).toEqual(
      expect.objectContaining({ verified: true, digestVerified: true }),
    );

    const ledgerData = JSON.parse(await fs.readFile(ledgerPath, 'utf8')) as {
      root: string;
      entries: Array<{ ledgerRoot: string; manifestDigest: string; snapshotId: string }>;
    };
    expect(ledgerData.root).toBe(packResult.ledgerEntry?.ledgerRoot);
    expect(ledgerData.entries).toHaveLength(1);
    expect(ledgerData.entries[0].manifestDigest).toBe(packResult.manifestDigest);
    expect(ledgerData.entries[0].snapshotId).toBe(snapshotData.version.id);
    expect(packResult.ledger?.root).toBe(ledgerData.root);
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
    expect(result.complianceSummary.covered).toBeGreaterThanOrEqual(0);
    expect(
      result.complianceSummary.covered +
        result.complianceSummary.partial +
        result.complianceSummary.missing,
    ).toBe(result.complianceSummary.total);
    expect(result.coverageSummary).toEqual(expect.objectContaining({ statements: expect.any(Number) }));
    const complianceStats = await fs.stat(result.compliancePath);
    expect(complianceStats.isFile()).toBe(true);
  });

  it('packages demo data into a signed archive with consistent manifest hashes', async () => {
    const packageOutput = path.join(tempRoot, 'ingest-package');

    const ledgerPath = path.join(packageOutput, 'ledger.json');
    const result = await runIngestAndPackage({
      inputDir: fixturesDir,
      outputDir: packageOutput,
      objectives: objectivesPath,
      level: 'C',
      projectName: 'Demo Avionics',
      projectVersion: '1.0.0',
      signingKey: TEST_SIGNING_BUNDLE,
      packageName: 'soi-pack.zip',
      ledger: { path: ledgerPath },
      cms: { bundlePem: TEST_CMS_BUNDLE },
    });

    const archiveStats = await fs.stat(result.archivePath);
    expect(archiveStats.isFile()).toBe(true);
    expect(result.archivePath).toBe(path.join(packageOutput, 'soi-pack.zip'));

    expect(result.ledgerEntry).toBeDefined();
    expect(result.manifestDigest).toHaveLength(64);
    const storedLedger = JSON.parse(await fs.readFile(ledgerPath, 'utf8')) as {
      root: string;
      entries: Array<{ manifestDigest: string; snapshotId: string }>;
    };
    expect(storedLedger.root).toBe(result.ledgerEntry?.ledgerRoot);
    expect(storedLedger.entries[0]?.manifestDigest).toBe(result.manifestDigest);
    expect(storedLedger.entries[0]?.snapshotId).toBe(result.ledgerEntry?.snapshotId);

    const manifest = JSON.parse(await fs.readFile(result.manifestPath, 'utf8')) as ManifestWithSbom;
    expect(manifest.files.length).toBeGreaterThan(0);

    const firstEntry = manifest.files[0];
    const assetPath = path.join(packageOutput, firstEntry.path);
    const assetContent = await fs.readFile(assetPath);
    const computedHash = createHash('sha256').update(assetContent).digest('hex');
    expect(computedHash).toBe(firstEntry.sha256);

    expect(result.sbomPath).toBe(path.join(packageOutput, 'sbom.spdx.json'));
    const sbomContent = await fs.readFile(result.sbomPath, 'utf8');
    const sbomDigest = createHash('sha256').update(sbomContent).digest('hex');
    expect(result.sbomSha256).toBe(sbomDigest);
    const sbomDocument = JSON.parse(sbomContent) as { spdxVersion: string };
    expect(sbomDocument.spdxVersion).toBe('SPDX-2.3');
    expect(manifest.sbom).toEqual({
      path: 'sbom.spdx.json',
      algorithm: 'sha256',
      digest: result.sbomSha256,
    });

    const signature = (await fs.readFile(path.join(packageOutput, 'manifest.sig'), 'utf8')).trim();
    expect(verifyManifestSignature(manifest, signature, TEST_SIGNING_PUBLIC_KEY)).toBe(true);
    const cmsPath = path.join(packageOutput, 'manifest.cms');
    const cmsContent = await fs.readFile(cmsPath, 'utf8');
    expect(result.cmsSignaturePath).toBe(cmsPath);
    const cmsHash = createHash('sha256').update(cmsContent).digest('hex');
    expect(result.cmsSignatureSha256).toBe(cmsHash);
    const detailed = verifyManifestSignatureDetailed(manifest, signature, {
      publicKeyPem: TEST_SIGNING_PUBLIC_KEY,
      cms: { signaturePem: cmsContent.trim(), certificatePem: TEST_CMS_CERTIFICATE, required: true },
    });
    expect(detailed.valid).toBe(true);
  });


  it('generates plan documents from configuration JSON', async () => {
    const configDir = path.join(tempRoot, 'plan-generator');
    await fs.mkdir(configDir, { recursive: true });

    const fixture = createReportFixture();
    const snapshotPath = path.join(configDir, 'snapshot.json');
    await fs.writeFile(snapshotPath, JSON.stringify(fixture.snapshot, null, 2));
    const objectivesPathLocal = path.join(configDir, 'objectives.json');
    await fs.writeFile(objectivesPathLocal, JSON.stringify(fixture.objectives, null, 2));

    const outputDirRelative = '../plan-output';
    const configPath = path.join(configDir, 'plans.json');
    const planConfig = {
      snapshot: './snapshot.json',
      objectives: './objectives.json',
      outputDir: outputDirRelative,
      manifestId: fixture.manifestId,
      level: 'C',
      generatedAt: fixture.snapshot.generatedAt,
      project: { name: 'Demo Avionics', version: '1.0.0' },
      plans: [
        { id: 'psac' },
        { id: 'sdp', overrides: { sections: { introduction: '<p>CLI intro override.</p>' } } },
        { id: 'svp' },
        { id: 'scmp' },
        { id: 'sqap' },
      ],
    };
    await fs.writeFile(configPath, JSON.stringify(planConfig, null, 2));

    const result = await runGeneratePlans({ config: configPath });
    const expectedOutputDir = path.resolve(configDir, outputDirRelative);
    expect(result.outputDir).toBe(expectedOutputDir);
    expect(result.plans).toHaveLength(5);

    for (const plan of result.plans) {
      const docxBuffer = await fs.readFile(plan.docxPath);
      const pdfBuffer = await fs.readFile(plan.pdfPath);
      expect(docxBuffer.subarray(0, 2).toString('ascii')).toBe('PK');
      expect(pdfBuffer.subarray(0, 4).toString('ascii')).toBe('%PDF');
      expect(createHash('sha256').update(docxBuffer).digest('hex')).toBe(plan.docxSha256);
      expect(createHash('sha256').update(pdfBuffer).digest('hex')).toBe(plan.pdfSha256);
    }

    const manifest = JSON.parse(await fs.readFile(result.manifestPath, 'utf8')) as {
      plans: Array<{
        id: string;
        outputs: Array<{ format: string; path: string; sha256: string }>;
      }>;
    };
    expect(manifest.plans).toHaveLength(5);
    manifest.plans.forEach((entry) => {
      expect(entry.outputs).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ format: 'pdf' }),
          expect.objectContaining({ format: 'docx' }),
        ]),
      );

      const planResult = result.plans.find((plan) => plan.id === entry.id as PlanTemplateId);
      expect(planResult).toBeDefined();
      entry.outputs.forEach((output) => {
        const absolutePath = path.resolve(expectedOutputDir, output.path);
        if (output.format === 'pdf') {
          expect(output.sha256).toBe(planResult!.pdfSha256);
          expect(absolutePath).toBe(planResult!.pdfPath);
        }
        if (output.format === 'docx') {
          expect(output.sha256).toBe(planResult!.docxSha256);
          expect(absolutePath).toBe(planResult!.docxPath);
        }
      });
    });
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
      signingKey: TEST_SIGNING_BUNDLE,
      packageName: 'soi-pack.zip',
    });

    const manifest = JSON.parse(await fs.readFile(result.manifestPath, 'utf8')) as ManifestWithSbom;
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
      snapshot: result.workspace.metadata.version,
    };

    const engine = new TraceEngine(bundle);
    const manualTrace = engine.getRequirementTrace('REQ-3');
    expect(manualTrace.tests).toHaveLength(0);
    expect(manualTrace.code.map((entry) => entry.path)).toContain('src/auth/login.ts');

    const derivedTrace = engine.getRequirementTrace('REQ-2');
    expect(derivedTrace.tests.map((test) => test.testId)).toContain('AuthTests#handles lockout');
  });

  it('attaches manual DO-178C artefacts from the import map', async () => {
    const fixtureDir = path.join(__dirname, '__fixtures__', 'manual-artifacts');
    const workDir = path.join(tempRoot, 'manual-artifacts-workspace');

    const result = await runImport({
      output: workDir,
      manualArtifacts: {
        plan: [path.join(fixtureDir, 'system-plan.md')],
        standard: [path.join(fixtureDir, 'software-standard.txt')],
        qa_record: [path.join(fixtureDir, 'qa-summary.csv')],
      },
    });

    const planEvidence = result.workspace.evidenceIndex.plan ?? [];
    expect(planEvidence.map((entry) => path.basename(entry.path))).toContain('system-plan.md');
    expect(planEvidence[0]?.hash).toMatch(/^[a-f0-9]{64}$/);

    const standardEvidence = result.workspace.evidenceIndex.standard ?? [];
    expect(standardEvidence.map((entry) => path.basename(entry.path))).toContain(
      'software-standard.txt',
    );

    const qaEvidence = result.workspace.evidenceIndex.qa_record ?? [];
    expect(qaEvidence.map((entry) => path.basename(entry.path))).toContain('qa-summary.csv');

    expect(result.workspace.metadata.inputs.manualArtifacts?.plan?.[0]).toMatch(/system-plan\.md$/);
    expect(result.workspace.metadata.inputs.manualArtifacts?.qa_record?.[0]).toMatch(
      /qa-summary\.csv$/,
    );
  });

  it('imports QA logs into qa_record evidence and covers A-7 objectives', async () => {
    const fixtureDir = path.join(__dirname, '__fixtures__', 'qa-logs');
    const workspaceDir = path.join(tempRoot, 'qa-logs-workspace');
    const analysisDir = path.join(tempRoot, 'qa-logs-analysis');

    const importResult = await runImport({
      output: workspaceDir,
      qaLogs: [path.join(fixtureDir, 'qa-log.csv')],
      objectives: path.join(fixtureDir, 'objectives.json'),
    });

    const qaEvidence = importResult.workspace.evidenceIndex.qa_record ?? [];
    expect(qaEvidence).toHaveLength(2);
    expect(qaEvidence.every((entry) => entry.hash && entry.hash.length === 64)).toBe(true);

    const analysisResult = await runAnalyze({
      input: workspaceDir,
      output: analysisDir,
      objectives: path.join(fixtureDir, 'objectives.json'),
    });

    expect(analysisResult.exitCode).toBe(exitCodes.success);

    const snapshot = JSON.parse(
      await fs.readFile(path.join(analysisDir, 'snapshot.json'), 'utf8'),
    ) as {
      objectives: Array<{ objectiveId: string; status: string }>;
    };

    snapshot.objectives
      .filter((entry) => entry.objectiveId.startsWith('A-7-0'))
      .forEach((objective) => {
        expect(objective.status).toBe('covered');
      });
  });

  it('imports Jira problem reports and clears problem_report objectives', async () => {
    const fixtureDir = path.join(__dirname, '__fixtures__', 'jira-problems');
    const workspaceDir = path.join(tempRoot, 'jira-problems-workspace');
    const analysisDir = path.join(tempRoot, 'jira-problems-analysis');

    const importResult = await runImport({
      output: workspaceDir,
      jiraDefects: [path.join(fixtureDir, 'defects.csv')],
      objectives: path.join(fixtureDir, 'objectives.json'),
    });

    const problemEvidence = importResult.workspace.evidenceIndex.problem_report ?? [];
    expect(problemEvidence).toHaveLength(1);
    expect(problemEvidence[0]?.summary).toContain('Jira problem raporu');
    expect(problemEvidence[0]?.hash).toMatch(/^[a-f0-9]{64}$/);

    const jiraMetadata = importResult.workspace.metadata.sources?.jira;
    expect(jiraMetadata?.problemReports).toBe(2);
    expect(jiraMetadata?.openProblems).toBe(1);
    expect(jiraMetadata?.reports).toEqual([
      expect.objectContaining({ file: expect.stringMatching(/defects\.csv$/), total: 2, open: 1 }),
    ]);

    const analysisResult = await runAnalyze({
      input: workspaceDir,
      output: analysisDir,
      objectives: path.join(fixtureDir, 'objectives.json'),
    });

    expect(analysisResult.exitCode).toBe(exitCodes.success);

    const snapshot = JSON.parse(
      await fs.readFile(path.join(analysisDir, 'snapshot.json'), 'utf8'),
    ) as {
      objectives: Array<{ objectiveId: string; status: string }>;
    };

    const changeControl = snapshot.objectives.find((entry) => entry.objectiveId === 'A-6-02');
    expect(changeControl?.status).toBe('covered');
  });

  it('propagates static analysis findings into compliance quality warnings', async () => {
    const fixtureDir = path.join(__dirname, '__fixtures__', 'quality');
    const workspaceDir = path.join(tempRoot, 'quality-workspace');
    const analysisDir = path.join(tempRoot, 'quality-analysis');
    const reportDir = path.join(tempRoot, 'quality-report');

    await runImport({
      output: workspaceDir,
      polyspace: path.join(fixtureDir, 'polyspace.json'),
      ldra: path.join(fixtureDir, 'ldra.json'),
    });

    const analysisResult = await runAnalyze({
      input: workspaceDir,
      output: analysisDir,
      objectives: objectivesPath,
    });

    expect([exitCodes.success, exitCodes.missingEvidence]).toContain(analysisResult.exitCode);

    await runReport({
      input: analysisDir,
      output: reportDir,
    });

    const compliance = JSON.parse(
      await fs.readFile(path.join(reportDir, 'compliance.json'), 'utf8'),
    ) as {
      qualityFindings: Array<{ category: string; message: string }>;
    };

    const analysisFindings = compliance.qualityFindings.filter(
      (finding) => finding.category === 'analysis',
    );
    expect(analysisFindings.length).toBeGreaterThan(0);
    expect(analysisFindings.map((finding) => finding.message)).toEqual(
      expect.arrayContaining([expect.stringContaining('Polyspace bulgusu')]),
    );
  });

  it('surfaces trace suggestions in analysis results and trace reports', async () => {
    const fixtureDir = path.join(__dirname, '__fixtures__', 'trace-suggestions');
    const inputDir = path.join(tempRoot, 'trace-suggestions-input');
    const analysisDir = path.join(tempRoot, 'trace-suggestions-analysis');
    const reportDir = path.join(tempRoot, 'trace-suggestions-report');

    await fs.mkdir(inputDir, { recursive: true });
    await fs.copyFile(path.join(fixtureDir, 'workspace.json'), path.join(inputDir, 'workspace.json'));

    const analysisResult = await runAnalyze({
      input: inputDir,
      output: analysisDir,
      level: 'C',
      objectives: objectivesPath,
    });

    expect([exitCodes.success, exitCodes.missingEvidence]).toContain(analysisResult.exitCode);

    const analysisData = JSON.parse(
      await fs.readFile(path.join(analysisDir, 'analysis.json'), 'utf8'),
    ) as {
      traceSuggestions: Array<{ requirementId: string; targetId: string }>;
    };

    expect(analysisData.traceSuggestions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ requirementId: 'REQ-TRACE-1', targetId: 'TC-REQ-TRACE-1' }),
        expect.objectContaining({ requirementId: 'REQ-TRACE-1', targetId: 'src/logger.c' }),
      ]),
    );

    await runReport({
      input: analysisDir,
      output: reportDir,
    });

    const traceHtml = await fs.readFile(path.join(reportDir, 'trace.html'), 'utf8');
    const traceCsv = await fs.readFile(path.join(reportDir, 'trace.csv'), 'utf8');
    expect(traceHtml).toContain('Önerilen İz Bağlantıları');
    expect(traceHtml).toContain('TC-REQ-TRACE-1');
    expect(traceHtml).toContain('src/logger.c');
    expect(traceCsv.split('\n')[0]).toContain('Requirement ID');
    expect(traceCsv).toContain('REQ-TRACE-1');
  });

  it('marks configured evidence entries as independently reviewed', async () => {
    const fixtureDir = path.join(__dirname, '__fixtures__', 'manual-links');
    const workDir = path.join(tempRoot, 'independent-evidence-workspace');

    const result = await runImport({
      output: workDir,
      junit: path.join(fixtureDir, 'results.xml'),
      traceLinksCsv: path.join(fixtureDir, 'trace-links.csv'),
      independentSources: ['junit'],
      independentArtifacts: [`trace=${path.join(fixtureDir, 'trace-links.csv')}`],
    });

    const testEvidence = result.workspace.evidenceIndex.test?.[0];
    expect(testEvidence).toEqual(
      expect.objectContaining({
        independent: true,
        hash: expect.stringMatching(/^[a-f0-9]{64}$/),
      }),
    );

    const traceEvidence = result.workspace.evidenceIndex.trace?.find((item) =>
      item.path.endsWith('trace-links.csv'),
    );
    expect(traceEvidence).toEqual(
      expect.objectContaining({
        independent: true,
        hash: expect.stringMatching(/^[a-f0-9]{64}$/),
      }),
    );
  });

  it('highlights independence gaps in analysis output for the fixture workspace', async () => {
    const fixtureDir = path.join(__dirname, '__fixtures__', 'independence');
    const inputDir = path.join(tempRoot, 'independence-analysis-input');
    await fs.mkdir(inputDir, { recursive: true });
    await fs.copyFile(
      path.join(fixtureDir, 'workspace.json'),
      path.join(inputDir, 'workspace.json'),
    );

    const outputDir = path.join(tempRoot, 'independence-analysis-output');

    const result = await runAnalyze({
      input: inputDir,
      output: outputDir,
      level: 'A',
      objectives: path.join(fixtureDir, 'objectives.json'),
    });

    expect([exitCodes.success, exitCodes.missingEvidence]).toContain(result.exitCode);

    const snapshot = JSON.parse(
      await fs.readFile(path.join(outputDir, 'snapshot.json'), 'utf8'),
    ) as {
      objectives: Array<{ objectiveId: string; status: string; missingArtifacts: string[] }>;
      gaps: { analysis: Array<{ objectiveId: string; missingArtifacts: string[] }> };
    };
    const objective = snapshot.objectives.find((item) => item.objectiveId === 'A-3-99');
    expect(objective?.status).toBe('missing');
    expect(objective?.missingArtifacts).toEqual(expect.arrayContaining(['analysis']));

    const analysisGap = snapshot.gaps.analysis.find((item) => item.objectiveId === 'A-3-99');
    expect(analysisGap?.missingArtifacts).toContain('analysis');

    const analysisJson = JSON.parse(
      await fs.readFile(path.join(outputDir, 'analysis.json'), 'utf8'),
    ) as {
      gaps: { analysis: Array<{ objectiveId: string; missingArtifacts: string[] }> };
    };
    const recordedGap = analysisJson.gaps.analysis.find((item) => item.objectiveId === 'A-3-99');
    expect(recordedGap?.missingArtifacts).toContain('analysis');
  });

  describe('certification gating', () => {
    const fixtureDir = path.join(__dirname, '__fixtures__', 'certification-gating');

    it('fails Level A analysis when MC/DC evidence is missing', async () => {
      const inputDir = path.join(tempRoot, 'cert-gating-level-a-input');
      const outputDir = path.join(tempRoot, 'cert-gating-level-a-output');

      await fs.mkdir(inputDir, { recursive: true });
      await fs.copyFile(path.join(fixtureDir, 'workspace.json'), path.join(inputDir, 'workspace.json'));

      const result = await runAnalyze({
        input: inputDir,
        output: outputDir,
        level: 'A',
        objectives: objectivesPath,
      });

      expect(result.exitCode).toBe(exitCodes.missingEvidence);

      const analysisData = JSON.parse(
        await fs.readFile(path.join(outputDir, 'analysis.json'), 'utf8'),
      ) as { warnings: string[] };

      expect(analysisData.warnings).toEqual(
        expect.arrayContaining([expect.stringContaining('MC/DC coverage evidence')]),
      );
    });

    it('downgrades missing statement coverage to a warning for Level C', async () => {
      const inputDir = path.join(tempRoot, 'cert-gating-level-c-input');
      const outputDir = path.join(tempRoot, 'cert-gating-level-c-output');

      await fs.mkdir(inputDir, { recursive: true });
      await fs.copyFile(path.join(fixtureDir, 'workspace.json'), path.join(inputDir, 'workspace.json'));

      const result = await runAnalyze({
        input: inputDir,
        output: outputDir,
        level: 'C',
        objectives: objectivesPath,
      });

      expect(result.exitCode).toBe(exitCodes.success);

      const analysisData = JSON.parse(
        await fs.readFile(path.join(outputDir, 'analysis.json'), 'utf8'),
      ) as { warnings: string[] };

      expect(analysisData.warnings).toEqual(
        expect.arrayContaining([expect.stringContaining('Level C warning')]),
      );
      expect(analysisData.warnings).toEqual(
        expect.arrayContaining([expect.stringContaining('Statement coverage evidence')]),
      );
    });
  });
});

describe('design CSV importer', () => {
  it('imports design records from CSV with normalization', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'soipack-design-import-'));
    try {
      const designCsvPath = path.join(tempDir, 'designs.csv');
      await fs.writeFile(
        designCsvPath,
        [
          'Design ID,Title,Status,Requirement IDs,Code Paths,Tags',
          'DES-1,Flight Control,Implemented,"REQ-1; REQ-2","src/control/module.c","Core;Control"',
          'DES-2,Invalid Status,Planned,REQ-3,"src/common/logger.ts","Audit"',
          'DES-3,Duplicate Refs,Allocated,"REQ-3; REQ-3","src/common/logger.ts","Audit"',
        ].join('\n'),
        'utf8',
      );

      const workDir = path.join(tempDir, 'work');
      const result = await runImport({ output: workDir, designCsv: designCsvPath });

      expect(result.workspace.designs).toEqual([
        {
          id: 'DES-1',
          title: 'Flight Control',
          description: undefined,
          status: 'implemented',
          tags: ['core', 'control'],
          requirementRefs: ['REQ-1', 'REQ-2'],
          codeRefs: ['src/control/module.c'],
        },
      ]);

      expect(result.warnings).toEqual(
        expect.arrayContaining([
          expect.stringContaining("Design CSV designs.csv row 3 has unsupported status 'Planned'"),
          expect.stringContaining('Design CSV designs.csv row 4 invalid: Requirement reference REQ-3 is duplicated.'),
        ]),
      );

      const workspaceOnDisk = JSON.parse(
        await fs.readFile(result.workspacePath, 'utf8'),
      ) as { designs: unknown };
      expect(Array.isArray(workspaceOnDisk.designs)).toBe(true);
      expect((workspaceOnDisk.designs as unknown[])).toHaveLength(1);
    } finally {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  });

  it('propagates design nodes into trace analysis outputs', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'soipack-design-trace-'));
    try {
      const workDir = path.join(tempDir, 'work');
      const analysisDir = path.join(tempDir, 'analysis');
      const designCsvPath = path.join(tempDir, 'designs.csv');
      await fs.writeFile(
        designCsvPath,
        [
          'Design ID,Title,Status,Requirement IDs,Code Paths',
          'DES-CLI,Traceable Design,Implemented,"REQ-1; REQ-2","src/auth/login.ts"',
        ].join('\n'),
        'utf8',
      );

      const fixturesDir = path.resolve(__dirname, '../../../examples/minimal');
      const objectivesPath = path.resolve(
        __dirname,
        '../../../data/objectives/do178c_objectives.min.json',
      );

      await runImport({
        output: workDir,
        jira: path.join(fixturesDir, 'issues.csv'),
        designCsv: designCsvPath,
      });

      const analyzeResult = await runAnalyze({
        input: workDir,
        output: analysisDir,
        objectives: objectivesPath,
        level: 'C',
      });

      const traces = JSON.parse(
        await fs.readFile(analyzeResult.tracePath, 'utf8'),
      ) as Array<{ requirement: { id: string }; designs: Array<{ id: string }> }>;
      const traceByRequirement = new Map(traces.map((trace) => [trace.requirement.id, trace]));
      expect(traceByRequirement.get('REQ-1')?.designs.map((design) => design.id)).toEqual([
        'DES-CLI',
      ]);
      expect(traceByRequirement.get('REQ-2')?.designs.map((design) => design.id)).toEqual([
        'DES-CLI',
      ]);

      const snapshot = JSON.parse(
        await fs.readFile(analyzeResult.snapshotPath, 'utf8'),
      ) as {
        stats: { designs: { total: number } };
        traceGraph: { nodes: Array<{ type: string; id: string }> };
      };
      expect(snapshot.stats.designs.total).toBe(1);
      expect(
        snapshot.traceGraph.nodes.filter((node) => node.type === 'design').map((node) => node.id),
      ).toEqual(['DES-CLI']);
    } finally {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  });
});

describe('doors next importer', () => {
  it('fetches remote artifacts, deduplicates entries, and surfaces warnings', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'soipack-doors-import-'));
    try {
      const workDir = path.join(tempDir, 'work');
      const fetchSpy = jest.spyOn(adapters, 'fetchDoorsNextArtifacts').mockResolvedValue({
        data: {
          requirements: [
            {
              id: 'REQ-DOORS',
              title: 'Remote Requirement',
              description: 'Imported from DOORS Next',
              status: 'verified',
              type: 'System',
            },
          ],
          tests: [
            {
              id: 'TEST-1',
              name: 'Remote Test Execution',
              status: 'passed',
              requirementIds: ['REQ-DOORS'],
            },
            {
              id: 'TEST-1',
              name: 'Remote Test Execution Duplicate',
              status: 'passed',
              requirementIds: ['REQ-DOORS'],
            },
          ],
          designs: [
            {
              id: 'DES-1',
              title: 'Control Design',
              description: 'Imported from DOORS Next',
              status: 'implemented',
              type: 'System',
              requirementIds: ['REQ-DOORS'],
              codeRefs: ['src/controls/controller.c'],
            },
          ],
          relationships: [
            { fromId: 'DES-1', toId: 'REQ-DOORS', type: 'implementsRequirement' },
            { fromId: 'TEST-1', toId: 'REQ-DOORS', type: 'validatesRequirement' },
          ],
          etagCache: { 'https://doors.example.com/rm': 'etag-123' },
        },
        warnings: ['DOORS Next pagination aborted after 3 pages.'],
      });

      const result = await runImport({
        output: workDir,
        doorsNext: {
          baseUrl: 'https://doors.example.com',
          projectArea: 'Flight Controls',
          username: 'alice',
          password: 'secret',
        },
      });

      expect(fetchSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          baseUrl: 'https://doors.example.com',
          projectArea: 'Flight Controls',
          username: 'alice',
          password: 'secret',
        }),
      );

      expect(result.warnings).toEqual(
        expect.arrayContaining(['DOORS Next pagination aborted after 3 pages.']),
      );

      expect(result.workspace.requirements.map((req) => req.id)).toEqual(['REQ-DOORS']);
      expect(result.workspace.designs).toEqual([
        {
          id: 'DES-1',
          title: 'Control Design',
          description: 'Imported from DOORS Next',
          status: 'implemented',
          tags: ['type:system'],
          requirementRefs: ['REQ-DOORS'],
          codeRefs: ['src/controls/controller.c'],
        },
      ]);
      expect(result.workspace.testResults).toHaveLength(1);
      expect(result.workspace.testResults[0]).toEqual(
        expect.objectContaining({
          testId: 'TEST-1',
          requirementsRefs: ['REQ-DOORS'],
          status: 'passed',
        }),
      );

      expect(result.workspace.traceLinks).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ from: 'REQ-DOORS', to: 'TEST-1', type: 'verifies' }),
          expect.objectContaining({ from: 'REQ-DOORS', to: 'DES-1', type: 'implements' }),
        ]),
      );

      const traceEvidence = result.workspace.evidenceIndex.trace ?? [];
      expect(traceEvidence.some((entry) => entry.source === 'doorsNext')).toBe(true);
      const testEvidence = result.workspace.evidenceIndex.test ?? [];
      expect(testEvidence.some((entry) => entry.source === 'doorsNext')).toBe(true);

      expect(result.workspace.metadata.sources?.doorsNext).toEqual(
        expect.objectContaining({
          baseUrl: 'https://doors.example.com',
          projectArea: 'Flight Controls',
          requirements: 1,
          tests: 2,
          designs: 1,
          relationships: 2,
          etagCacheSize: 1,
        }),
      );
      expect(result.workspace.metadata.sources?.doorsNext?.etagCache).toEqual({
        'https://doors.example.com/rm': 'etag-123',
      });
      expect(result.workspace.metadata.inputs.doorsNext).toBe(
        'https://doors.example.com#Flight Controls',
      );
    } finally {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  });
});

describe('CLI localization', () => {
  afterEach(() => {
    setCliLocale('en');
  });

  it('localizes unexpected errors using the active locale', () => {
    const messages: string[] = [];
    const logger = {
      error: (_context: unknown, message?: unknown) => {
        if (typeof _context === 'string' && message === undefined) {
          messages.push(_context);
          return;
        }
        if (typeof message === 'string') {
          messages.push(message);
        }
      },
    } as unknown as Logger;

    setCliLocale('en');
    __internal.logCliError(logger, 42);
    expect(messages.pop()).toBe('An unexpected error occurred.');

    setCliLocale('tr');
    __internal.logCliError(logger, 42);
    expect(messages.pop()).toBe('Beklenmeyen bir hata oluştu.');
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
      signingKey: TEST_SIGNING_BUNDLE,
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
        signingKey: TEST_SIGNING_BUNDLE,
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

  const createManifest = (): ManifestWithSbom => ({
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
  ): Promise<{
    manifestPath: string;
    signaturePath: string;
    publicKeyPath: string;
    manifestContent: string;
    signatureContent: string;
  }> => {
    const manifestPath = path.join(tempDir, 'manifest.json');
    const signaturePath = path.join(tempDir, 'manifest.sig');
    const publicKeyPath = path.join(tempDir, 'public-key.pem');

    const manifestJson = overrides.manifestJson ?? `${JSON.stringify(manifest, null, 2)}\n`;
    await fs.writeFile(manifestPath, manifestJson, 'utf8');

    const signatureValue =
      overrides.signature ?? signManifestBundle(manifest, { bundlePem: TEST_SIGNING_BUNDLE }).signature;
    const signatureContent = `${signatureValue}\n`;
    await fs.writeFile(signaturePath, signatureContent, 'utf8');

    await fs.writeFile(publicKeyPath, TEST_SIGNING_PUBLIC_KEY, 'utf8');

    return {
      manifestPath,
      signaturePath,
      publicKeyPath,
      manifestContent: manifestJson,
      signatureContent,
    };
  };

  type PackageEntry = { path: string; data: string | Buffer };

  const digestFor = (content: string | Buffer): string => {
    const buffer = typeof content === 'string' ? Buffer.from(content, 'utf8') : content;
    return createHash('sha256').update(buffer).digest('hex');
  };

  const createManifestFromEntries = (entries: PackageEntry[]): ManifestWithSbom => ({
    files: entries.map((entry) => ({ path: entry.path, sha256: digestFor(entry.data) })),
    createdAt: '2024-01-01T00:00:00.000Z',
    toolVersion: '1.0.0-test',
  });

  const writeZipArchive = async (outputPath: string, entries: PackageEntry[]): Promise<void> => {
    await fs.mkdir(path.dirname(outputPath), { recursive: true });

    await new Promise<void>((resolve, reject) => {
      const zip = new ZipFile();
      const output = createWriteStream(outputPath);

      const handleError = (error: unknown) => {
        reject(error instanceof Error ? error : new Error(String(error)));
      };

      zip.outputStream.on('error', handleError);
      output.on('error', handleError);
      output.on('close', () => resolve());

      zip.outputStream.pipe(output);

      for (const entry of entries) {
        const buffer = typeof entry.data === 'string' ? Buffer.from(entry.data, 'utf8') : entry.data;
        zip.addBuffer(buffer, entry.path);
      }

      zip.end();
    });
  };

  it('returns success for a valid manifest signature', async () => {
    const manifest = createManifest();
    const { manifestPath, signaturePath, publicKeyPath } = await writeVerificationFiles(manifest);

    const result = await runVerify({ manifestPath, signaturePath, publicKeyPath });

    expect(result.isValid).toBe(true);
    expect(result.manifestId).toHaveLength(12);
    expect(result.packageIssues).toEqual([]);
    expect(result.sbom).toBeUndefined();
  });

  it('flags tampered manifests as invalid', async () => {
    const manifest = createManifest();
    const originalSignature = signManifestBundle(manifest, { bundlePem: TEST_SIGNING_BUNDLE }).signature;
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
    expect(result.packageIssues).toEqual([]);
    expect(result.sbom).toBeUndefined();
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

  it('validates package contents when provided', async () => {
    const dataEntries: PackageEntry[] = [
      { path: 'reports/compliance.json', data: '{"status":"ok"}\n' },
      { path: 'reports/gaps.html', data: '<html>gaps</html>' },
    ];

    const sbomContent = JSON.stringify({ spdxVersion: 'SPDX-2.3', files: [] });
    const sbomDigest = digestFor(sbomContent);
    const manifest = createManifestFromEntries(dataEntries);
    manifest.sbom = { path: 'sbom.spdx.json', algorithm: 'sha256', digest: sbomDigest };
    const { manifestPath, signaturePath, publicKeyPath, manifestContent, signatureContent } =
      await writeVerificationFiles(manifest);

    const packagePath = path.join(tempDir, 'valid-package.zip');
    await writeZipArchive(packagePath, [
      ...dataEntries,
      { path: 'manifest.json', data: manifestContent },
      { path: 'manifest.sig', data: signatureContent },
      { path: 'sbom.spdx.json', data: sbomContent },
    ]);

    const result = await runVerify({ manifestPath, signaturePath, publicKeyPath, packagePath });

    expect(result.isValid).toBe(true);
    expect(result.packageIssues).toEqual([]);
    expect(result.sbom).toEqual({
      path: 'sbom.spdx.json',
      algorithm: 'sha256',
      expectedDigest: sbomDigest,
      package: { digest: sbomDigest, matches: true },
    });
  });

  it('reports mismatched files when package content is tampered', async () => {
    const dataEntries: PackageEntry[] = [
      { path: 'reports/compliance.json', data: 'original compliance' },
      { path: 'reports/gaps.html', data: '<html>gaps</html>' },
    ];

    const manifest = createManifestFromEntries(dataEntries);
    const { manifestPath, signaturePath, publicKeyPath, manifestContent, signatureContent } =
      await writeVerificationFiles(manifest);

    const tamperedContent = 'tampered compliance';
    const packagePath = path.join(tempDir, 'tampered-package.zip');
    await writeZipArchive(packagePath, [
      { path: dataEntries[0].path, data: tamperedContent },
      dataEntries[1],
      { path: 'manifest.json', data: manifestContent },
      { path: 'manifest.sig', data: signatureContent },
    ]);

    const result = await runVerify({ manifestPath, signaturePath, publicKeyPath, packagePath });

    expect(result.isValid).toBe(true);
    expect(result.packageIssues).toEqual([
      `Dosya karması uyuşmuyor: ${dataEntries[0].path} (beklenen ${digestFor(
        dataEntries[0].data,
      )}, bulunan ${digestFor(tamperedContent)})`,
    ]);
    expect(result.sbom).toBeUndefined();
  });

  it('reports missing files when package omits manifest entries', async () => {
    const dataEntries: PackageEntry[] = [
      { path: 'reports/compliance.json', data: 'original compliance' },
      { path: 'reports/gaps.html', data: '<html>gaps</html>' },
    ];

    const manifest = createManifestFromEntries(dataEntries);
    const { manifestPath, signaturePath, publicKeyPath, manifestContent, signatureContent } =
      await writeVerificationFiles(manifest);

    const packagePath = path.join(tempDir, 'missing-file-package.zip');
    await writeZipArchive(packagePath, [
      dataEntries[1],
      { path: 'manifest.json', data: manifestContent },
      { path: 'manifest.sig', data: signatureContent },
    ]);

    const result = await runVerify({ manifestPath, signaturePath, publicKeyPath, packagePath });

    expect(result.isValid).toBe(true);
    expect(result.packageIssues).toEqual([
      `Manifest dosyası paket içinde bulunamadı: ${dataEntries[0].path}`,
    ]);
    expect(result.sbom).toBeUndefined();
  });

  it('reports SBOM mismatches from package contents', async () => {
    const dataEntries: PackageEntry[] = [
      { path: 'reports/compliance.json', data: 'original compliance' },
    ];

    const sbomContent = JSON.stringify({ spdxVersion: 'SPDX-2.3', files: [] });
    const expectedDigest = digestFor(sbomContent);
    const manifest = createManifestFromEntries(dataEntries);
    manifest.sbom = { path: 'sbom.spdx.json', algorithm: 'sha256', digest: expectedDigest };
    const { manifestPath, signaturePath, publicKeyPath, manifestContent, signatureContent } =
      await writeVerificationFiles(manifest);

    const tamperedSbom = `${sbomContent}tampered`;
    const tamperedDigest = digestFor(tamperedSbom);
    const packagePath = path.join(tempDir, 'sbom-mismatch.zip');
    await writeZipArchive(packagePath, [
      ...dataEntries,
      { path: 'manifest.json', data: manifestContent },
      { path: 'manifest.sig', data: signatureContent },
      { path: 'sbom.spdx.json', data: tamperedSbom },
    ]);

    const result = await runVerify({ manifestPath, signaturePath, publicKeyPath, packagePath });

    expect(result.isValid).toBe(true);
    expect(result.packageIssues).toEqual([
      `SBOM karması uyuşmuyor: sbom.spdx.json (beklenen ${expectedDigest}, bulunan ${tamperedDigest})`,
    ]);
    expect(result.sbom).toEqual({
      path: 'sbom.spdx.json',
      algorithm: 'sha256',
      expectedDigest: expectedDigest,
      package: { digest: tamperedDigest, matches: false },
    });
  });

  it('validates SBOM file digests when sbomPath is provided', async () => {
    const manifest = createManifest();
    const sbomContent = JSON.stringify({ spdxVersion: 'SPDX-2.3', files: [] });
    const sbomDigest = digestFor(sbomContent);
    manifest.sbom = { path: 'sbom.spdx.json', algorithm: 'sha256', digest: sbomDigest };

    const { manifestPath, signaturePath, publicKeyPath } = await writeVerificationFiles(manifest);
    const sbomPath = path.join(tempDir, 'sbom.spdx.json');
    await fs.writeFile(sbomPath, sbomContent, 'utf8');

    const result = await runVerify({ manifestPath, signaturePath, publicKeyPath, sbomPath });

    expect(result.isValid).toBe(true);
    expect(result.packageIssues).toEqual([]);
    expect(result.sbom).toEqual({
      path: 'sbom.spdx.json',
      algorithm: 'sha256',
      expectedDigest: sbomDigest,
      file: { path: sbomPath, digest: sbomDigest, matches: true },
    });
  });

  it('throws when sbomPath is provided without manifest metadata', async () => {
    const manifest = createManifest();
    const { manifestPath, signaturePath, publicKeyPath } = await writeVerificationFiles(manifest);
    const sbomPath = path.join(tempDir, 'unused.sbom');
    await fs.writeFile(sbomPath, '{}', 'utf8');

    await expect(
      runVerify({ manifestPath, signaturePath, publicKeyPath, sbomPath }),
    ).rejects.toThrow(/Manifest SBOM metaverisi/);
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

describe('structural coverage merging', () => {
  const getMerge = () =>
    (__internal as unknown as {
      mergeStructuralCoverage: (
        existing: StructuralCoverageSummary | undefined,
        incoming: StructuralCoverageSummary,
      ) => StructuralCoverageSummary;
    }).mergeStructuralCoverage;

  it('preserves LDRA decision coverage when merging with VectorCAST summaries lacking decisions', () => {
    const mergeStructuralCoverage = getMerge();
    const ldraSummary: StructuralCoverageSummary = {
      tool: 'ldra',
      files: [
        {
          path: 'src/module.c',
          stmt: { covered: 18, total: 20 },
          dec: { covered: 9, total: 10 },
        },
      ],
    };
    const vectorSummary: StructuralCoverageSummary = {
      tool: 'vectorcast',
      files: [
        {
          path: 'src/module.c',
          stmt: { covered: 20, total: 20 },
        },
      ],
    };

    const afterLdra = mergeStructuralCoverage(undefined, ldraSummary);
    const merged = mergeStructuralCoverage(afterLdra, vectorSummary);
    const mergedFile = merged.files.find((file) => file.path === 'src/module.c');

    expect(mergedFile?.dec).toEqual(ldraSummary.files[0]?.dec);
    expect(mergedFile?.mcdc).toBeUndefined();
  });

  it('retains VectorCAST MC/DC metrics when later LDRA summaries omit them', () => {
    const mergeStructuralCoverage = getMerge();
    const vectorSummary: StructuralCoverageSummary = {
      tool: 'vectorcast',
      files: [
        {
          path: 'src/module.c',
          stmt: { covered: 15, total: 20 },
          mcdc: { covered: 7, total: 8 },
        },
      ],
    };
    const ldraSummary: StructuralCoverageSummary = {
      tool: 'ldra',
      files: [
        {
          path: 'src/module.c',
          stmt: { covered: 18, total: 20 },
          dec: { covered: 9, total: 10 },
        },
      ],
    };

    const afterVector = mergeStructuralCoverage(undefined, vectorSummary);
    const merged = mergeStructuralCoverage(afterVector, ldraSummary);
    const mergedFile = merged.files.find((file) => file.path === 'src/module.c');

    expect(mergedFile?.mcdc).toEqual(vectorSummary.files[0]?.mcdc);
    expect(mergedFile?.dec).toEqual(ldraSummary.files[0]?.dec);
  });
});

describe('coverage evidence emission', () => {
  it('emits decision and MC/DC coverage evidence across supported adapters when metrics exist', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'soipack-coverage-'));
    const workDir = path.join(tempDir, 'workspace');
    const lcovPath = path.join(tempDir, 'coverage-evidence.lcov');
    const coberturaPath = path.join(tempDir, 'coverage-evidence.xml');
    const ldraPath = path.join(tempDir, 'coverage-evidence.ldra');

    await fs.writeFile(lcovPath, 'lcov');
    await fs.writeFile(coberturaPath, '<coverage></coverage>');
    await fs.writeFile(ldraPath, '{"coverage":true}');

    const percentage = (covered: number, total: number): number =>
      Number(((covered / total) * 100).toFixed(2));

    const lcovReport: CoverageReport = {
      totals: {
        statements: { covered: 30, total: 30, percentage: 100 },
        branches: { covered: 12, total: 15, percentage: percentage(12, 15) },
        mcdc: { covered: 6, total: 8, percentage: percentage(6, 8) },
      },
      files: [
        {
          file: 'src/module.c',
          statements: { covered: 30, total: 30, percentage: 100 },
          branches: { covered: 12, total: 15, percentage: percentage(12, 15) },
          mcdc: { covered: 6, total: 8, percentage: percentage(6, 8) },
        },
      ],
    };

    const coberturaReport: CoverageReport = {
      totals: {
        statements: { covered: 28, total: 30, percentage: percentage(28, 30) },
        branches: { covered: 10, total: 12, percentage: percentage(10, 12) },
        mcdc: { covered: 5, total: 7, percentage: percentage(5, 7) },
      },
      files: [
        {
          file: 'src/other.c',
          statements: { covered: 28, total: 30, percentage: percentage(28, 30) },
          branches: { covered: 10, total: 12, percentage: percentage(10, 12) },
          mcdc: { covered: 5, total: 7, percentage: percentage(5, 7) },
        },
      ],
    };

    const ldraCoverage: StructuralCoverageSummary = {
      tool: 'ldra',
      files: [
        {
          path: 'src/module.c',
          stmt: { covered: 20, total: 20 },
          dec: { covered: 9, total: 10 },
          mcdc: { covered: 7, total: 8 },
        },
      ],
    };

    jest.spyOn(adapters, 'importLcov').mockResolvedValue({ warnings: [], data: lcovReport });
    jest.spyOn(adapters, 'importCobertura').mockResolvedValue({ warnings: [], data: coberturaReport });
    jest.spyOn(adapters, 'fromLDRA').mockResolvedValue({ warnings: [], data: { coverage: ldraCoverage } });

    try {
      const result = await runImport({
        output: workDir,
        lcov: lcovPath,
        cobertura: coberturaPath,
        ldra: ldraPath,
      });

      const decisionEvidence = result.workspace.evidenceIndex.coverage_dec ?? [];
      expect(decisionEvidence.map((entry) => entry.source)).toEqual(
        expect.arrayContaining(['lcov', 'cobertura', 'ldra']),
      );

      const mcdcEvidence = result.workspace.evidenceIndex.coverage_mcdc ?? [];
      expect(mcdcEvidence.map((entry) => entry.source)).toEqual(
        expect.arrayContaining(['lcov', 'cobertura', 'ldra']),
      );
    } finally {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  });

  it('merges Simulink structural coverage and surfaces adapter warnings', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'soipack-simulink-'));
    const workspaceDir = path.join(tempDir, 'workspace');
    const simulinkPath = path.join(tempDir, 'simulink-coverage.json');
    await fs.writeFile(simulinkPath, '{"coverage":true}');

    const simulinkCoverage: StructuralCoverageSummary = {
      tool: 'simulink',
      files: [
        {
          path: 'models/control.slx',
          stmt: { covered: 45, total: 50 },
          dec: { covered: 20, total: 22 },
          mcdc: { covered: 10, total: 12 },
        },
        {
          path: 'models/sensor.slx',
          stmt: { covered: 30, total: 40 },
        },
      ],
      objectiveLinks: ['A-5-08', 'A-5-09', 'A-5-10'],
    };

    const simulinkSpy = jest
      .spyOn(adapters, 'fromSimulink')
      .mockResolvedValue({ data: { coverage: simulinkCoverage }, warnings: ['Simulink uyarısı'] });

    const result = await runImport({
      output: workspaceDir,
      simulink: simulinkPath,
    });

    expect(simulinkSpy).toHaveBeenCalledWith(simulinkPath);
    expect(result.workspace.structuralCoverage).toEqual(simulinkCoverage);
    expect(result.workspace.metadata.inputs.simulink).toMatch(/simulink-coverage\.json$/);
    expect(result.warnings).toEqual(expect.arrayContaining(['Simulink uyarısı']));

    const stmtEvidence = result.workspace.evidenceIndex.coverage_stmt ?? [];
    expect(stmtEvidence.some((entry) => entry.source === 'simulink')).toBe(true);
    const decEvidence = result.workspace.evidenceIndex.coverage_dec ?? [];
    expect(decEvidence.some((entry) => entry.source === 'simulink')).toBe(true);
    const mcdcEvidence = result.workspace.evidenceIndex.coverage_mcdc ?? [];
    expect(mcdcEvidence.some((entry) => entry.source === 'simulink')).toBe(true);
  });
});

describe('runFreeze', () => {
  class MockRequest extends EventEmitter {
    public payload = '';
    timeoutHandler?: () => void;

    write(chunk: string): void {
      this.payload += chunk;
    }

    end(): void {
      this.emit('finish');
    }

    setTimeout(_ms: number, handler: () => void): this {
      this.timeoutHandler = handler;
      return this;
    }
  }

  const createRequestMock = () => jest.fn() as jest.MockedFunction<typeof http.request>;

  it('sends a POST request to freeze configuration and returns the version metadata', async () => {
    const requestMock = createRequestMock();
    const mockRequest = new MockRequest();
    const versionResponse = {
      version: {
        id: '20240619T123456Z-deadbeef1234',
        createdAt: '2024-06-19T12:34:56.000Z',
        fingerprint: 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
        isFrozen: true,
        frozenAt: '2024-06-19T12:35:00.000Z',
      } satisfies SnapshotVersion,
    };

    requestMock.mockImplementation(((url: unknown, _options: unknown, callback: (res: http.IncomingMessage) => void) => {
      void url;
      const responseStream = new PassThrough();
      const response = Object.assign(responseStream, { statusCode: 200 }) as http.IncomingMessage;
      process.nextTick(() => {
        callback(response);
        responseStream.end(JSON.stringify(versionResponse));
      });
      return mockRequest as unknown as http.ClientRequest;
    }) as unknown as typeof http.request);

    const result = await runFreeze({
      baseUrl: 'http://localhost:8080',
      token: 'freeze-token',
      allowInsecureHttp: true,
      httpRequest: requestMock,
    });

    expect(result.version).toEqual(versionResponse.version);
    expect(mockRequest.payload).toBe('{}');
    expect(requestMock).toHaveBeenCalledTimes(1);
  });

  it('rejects when the server responds with an error', async () => {
    const requestMock = createRequestMock();
    const mockRequest = new MockRequest();

    requestMock.mockImplementation(((url: unknown, _options: unknown, callback: (res: http.IncomingMessage) => void) => {
      void url;
      const responseStream = new PassThrough();
      const response = Object.assign(responseStream, { statusCode: 409, statusMessage: 'Frozen' }) as http.IncomingMessage;
      process.nextTick(() => {
        callback(response);
        responseStream.end('already frozen');
      });
      return mockRequest as unknown as http.ClientRequest;
    }) as unknown as typeof http.request);

    await expect(
      runFreeze({
        baseUrl: 'http://localhost:8080',
        token: 'freeze-token',
        allowInsecureHttp: true,
        httpRequest: requestMock,
      }),
    ).rejects.toThrow('HTTP 409');
    expect(requestMock).toHaveBeenCalledTimes(1);
  });
});

describe('runRiskSimulate', () => {
  const metricsTemplate = {
    coverageHistory: [
      { timestamp: '2024-01-01T00:00:00Z', covered: 780, total: 1000 },
      { timestamp: '2024-02-01T00:00:00Z', covered: 820, total: 1000 },
      { timestamp: '2024-03-01T00:00:00Z', covered: 860, total: 1000 },
    ],
    testHistory: [
      { timestamp: '2024-01-01T00:00:00Z', passed: 94, failed: 6 },
      { timestamp: '2024-02-01T00:00:00Z', passed: 95, failed: 5 },
      { timestamp: '2024-03-01T00:00:00Z', passed: 97, failed: 3 },
    ],
  };

  let tempDir: string;
  let metricsPath: string;

  beforeAll(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'soipack-risk-'));
    metricsPath = path.join(tempDir, 'metrics.json');
  });

  afterAll(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  beforeEach(async () => {
    await fs.writeFile(metricsPath, JSON.stringify(metricsTemplate));
  });

  it('returns Monte Carlo summary with provided seed and iteration count', async () => {
    const result = await runRiskSimulate({ metricsPath, iterations: 250, seed: 2024 });

    expect(result.simulation.iterations).toBe(250);
    expect(result.simulation.seed).toBe(2024);
    expect(result.simulation.baseline.coverage).toBe(86);
    expect(result.simulation.baseline.failureRate).toBe(3);
    expect(result.simulation.percentiles.p90).toBeGreaterThanOrEqual(0);
    expect(result.simulation.percentiles.p90).toBeLessThanOrEqual(100);
  });

  it('applies coverage lift to the latest coverage sample', async () => {
    const base = await runRiskSimulate({ metricsPath, seed: 17 });
    const lifted = await runRiskSimulate({ metricsPath, seed: 17, coverageLift: 5 });
    const capped = await runRiskSimulate({ metricsPath, seed: 17, coverageLift: 50 });

    expect(lifted.simulation.baseline.coverage).toBe(base.simulation.baseline.coverage + 5);
    expect(capped.simulation.baseline.coverage).toBe(100);
    expect(lifted.simulation.mean).toBeLessThanOrEqual(base.simulation.mean);
  });

  it('throws when metrics are malformed', async () => {
    const invalidPath = path.join(tempDir, 'invalid-metrics.json');
    await fs.writeFile(
      invalidPath,
      JSON.stringify({ coverageHistory: [{ timestamp: '', covered: 'NaN', total: 0 }] }),
    );

    await expect(runRiskSimulate({ metricsPath: invalidPath })).rejects.toThrow(
      /coverageHistory\[0\]\.timestamp/,
    );
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
