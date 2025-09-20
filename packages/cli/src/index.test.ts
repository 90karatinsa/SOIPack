import os from 'os';
import path from 'path';
import { promises as fs } from 'fs';

import { Manifest } from '@soipack/core';
import { verifyManifestSignature } from '@soipack/packager';

import { exitCodes, runAnalyze, runImport, runPack, runReport } from './index';

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
  const objectivesPath = path.resolve(__dirname, '../../../data/objectives/do178c_objectives.min.json');
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
});
