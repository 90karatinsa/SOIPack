import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { Manifest } from '@soipack/core';
import {
  runAnalyze,
  runImport,
  runPack,
  runReport,
} from '../packages/cli/src/index';
import { verifyManifestSignatureDetailed } from '@soipack/packager';

const SAMPLE_ROOT = path.resolve(__dirname, '../data/samples');
const OBJECTIVES_PATH = path.resolve(
  __dirname,
  '../data/objectives/do178c_objectives.min.json',
);
const SIGNING_BUNDLE_PATH = path.resolve(__dirname, '../test/certs/dev.pem');

const ensureDir = async (target: string) => {
  await fs.mkdir(target, { recursive: true });
};

const createTempRoot = async (): Promise<string> => {
  return fs.mkdtemp(path.join(os.tmpdir(), 'soipack-demo-'));
};

const removeSafe = async (target: string) => {
  await fs.rm(target, { recursive: true, force: true });
};

const main = async () => {
  const tempRoot = await createTempRoot();
  const ingestDir = path.join(tempRoot, 'ingest');
  const analysisDir = path.join(tempRoot, 'analysis');
  const distDir = path.join(tempRoot, 'dist');
  const reportsDir = path.join(distDir, 'reports');
  const releaseDir = path.join(tempRoot, 'release');

  try {
    await Promise.all([
      ensureDir(ingestDir),
      ensureDir(analysisDir),
      ensureDir(distDir),
      ensureDir(releaseDir),
    ]);

    const importResult = await runImport({
      output: ingestDir,
      jira: path.join(SAMPLE_ROOT, 'jira-do178c.csv'),
      reqif: path.join(SAMPLE_ROOT, 'requirements-do178c.reqif'),
      junit: path.join(SAMPLE_ROOT, 'tests-do178c.xml'),
      lcov: path.join(SAMPLE_ROOT, 'coverage-do178c.lcov'),
      objectives: OBJECTIVES_PATH,
      projectName: 'DO-178C Autopilot Demo',
      projectVersion: '0.1.0',
      level: 'C',
    });

    if (importResult.workspace.requirements.length === 0) {
      throw new Error('İçe aktarılan gereksinimler boş döndü.');
    }

    await runAnalyze({
      input: ingestDir,
      output: analysisDir,
      level: 'C',
      objectives: OBJECTIVES_PATH,
      projectName: 'DO-178C Autopilot Demo',
      projectVersion: '0.1.0',
    });

    await runReport({
      input: analysisDir,
      output: reportsDir,
    });

    const signingBundle = await fs.readFile(SIGNING_BUNDLE_PATH, 'utf8');
    const packResult = await runPack({
      input: distDir,
      output: releaseDir,
      signingKey: signingBundle,
      packageName: 'do178c-demo.zip',
    });

    const manifestJson = await fs.readFile(packResult.manifestPath, 'utf8');
    const manifest = JSON.parse(manifestJson) as Manifest;
    const signature = (await fs.readFile(path.join(releaseDir, 'manifest.sig'), 'utf8')).trim();
    const verification = verifyManifestSignatureDetailed(manifest, signature);
    if (!verification.valid) {
      const reason = verification.reason ?? 'bilinmeyen';
      throw new Error(`Manifest imzası doğrulanamadı: ${reason}`);
    }

    console.log('DO-178C demo smoke testi tamamlandı.');
    console.log(`Çıktı klasörü: ${releaseDir}`);
  } finally {
    await removeSafe(ingestDir);
    await removeSafe(analysisDir);
    await removeSafe(distDir);
    await removeSafe(releaseDir);
    await removeSafe(tempRoot);
  }
};

main().catch((error) => {
  console.error('Demo smoke testi sırasında hata oluştu:', error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
