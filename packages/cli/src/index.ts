#!/usr/bin/env node
import fs from 'fs';
import { promises as fsPromises } from 'fs';
import path from 'path';
import { createHash } from 'crypto';
import process from 'process';

import {
  importCobertura,
  importGitMetadata,
  importJiraCsv,
  importJUnitXml,
  importLcov,
  importReqIF,
  BuildInfo,
  CoverageSummary,
  JiraRequirement,
  ReqIFRequirement,
  TestResult,
} from '@soipack/adapters';
import {
  CertificationLevel,
  Evidence,
  EvidenceSource,
  Manifest,
  Objective,
  ObjectiveArtifactType,
  Requirement,
  RequirementStatus,
  TraceLink,
  createRequirement,
} from '@soipack/core';
import {
  ComplianceSnapshot,
  EvidenceIndex,
  ImportBundle,
  RequirementTrace,
  TraceEngine,
  generateComplianceSnapshot,
} from '@soipack/engine';
import {
  renderComplianceMatrix,
  renderGaps,
  renderTraceMatrix,
} from '@soipack/report';
import { buildManifest, signManifest, verifyManifestSignature } from '@soipack/packager';
import { ZipFile } from 'yazl';
import YAML from 'yaml';
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';

import packageInfo from '../package.json';

import { createLogger } from './logging';
import type { Logger } from './logging';
import {
  DEFAULT_LICENSE_FILE,
  LicenseError,
  verifyLicenseFile,
  resolveLicensePath,
  type LicensePayload,
} from './license';
import { formatVersion } from './version';

const fixedTimestampSource = process.env.SOIPACK_DEMO_TIMESTAMP;
const parsedFixedTimestamp = fixedTimestampSource ? new Date(fixedTimestampSource) : undefined;
const hasFixedTimestamp = parsedFixedTimestamp !== undefined && !Number.isNaN(parsedFixedTimestamp.getTime());

const getCurrentDate = (): Date =>
  hasFixedTimestamp ? new Date(parsedFixedTimestamp!.getTime()) : new Date();

const getCurrentTimestamp = (): string => getCurrentDate().toISOString();

interface ImportPaths {
  jira?: string;
  reqif?: string;
  junit?: string;
  lcov?: string;
  cobertura?: string;
  git?: string;
}

export interface ImportOptions extends ImportPaths {
  output: string;
  objectives?: string;
  level?: CertificationLevel;
  projectName?: string;
  projectVersion?: string;
}

export interface ImportWorkspace {
  requirements: Requirement[];
  testResults: TestResult[];
  coverage?: CoverageSummary;
  traceLinks: TraceLink[];
  testToCodeMap: Record<string, string[]>;
  evidenceIndex: EvidenceIndex;
  git?: BuildInfo | null;
  metadata: {
    generatedAt: string;
    warnings: string[];
    inputs: ImportPaths;
    project?: {
      name?: string;
      version?: string;
    };
    targetLevel?: CertificationLevel;
    objectivesPath?: string;
  };
}

export interface ImportResult {
  workspace: ImportWorkspace;
  workspacePath: string;
  warnings: string[];
}

const exitCodes = {
  success: 0,
  missingEvidence: 2,
  error: 3,
  verificationFailed: 4,
} as const;

const ensureDirectory = async (directory: string): Promise<void> => {
  await fsPromises.mkdir(directory, { recursive: true });
};

const writeJsonFile = async (filePath: string, data: unknown): Promise<void> => {
  const serialized = `${JSON.stringify(data, null, 2)}\n`;
  await fsPromises.writeFile(filePath, serialized, 'utf8');
};

const readJsonFile = async <T>(filePath: string): Promise<T> => {
  const content = await fsPromises.readFile(filePath, 'utf8');
  return JSON.parse(content) as T;
};

const normalizeRelativePath = (filePath: string): string => {
  const absolute = path.resolve(filePath);
  const relative = path.relative(process.cwd(), absolute);
  const normalized = relative.length > 0 ? relative : '.';
  return normalized.split(path.sep).join('/');
};

const tokenize = (value: string): string[] =>
  value
    .split(/[^A-Za-z0-9_/.-]+/)
    .flatMap((segment) => segment.split(/[\\/]/))
    .map((segment) => segment.trim().toLowerCase())
    .filter((segment) => segment.length >= 2);

const createTestLookup = (tests: TestResult[]) => {
  const direct = new Map<string, string>();
  const lower = new Map<string, string>();
  const tokenIndex = new Map<string, Set<string>>();
  const visited = new Set<string>();

  const registerToken = (token: string, testId: string) => {
    if (!token) {
      return;
    }
    const existing = tokenIndex.get(token) ?? new Set<string>();
    existing.add(testId);
    tokenIndex.set(token, existing);
  };

  const registerCandidate = (raw: string | undefined, testId: string): void => {
    if (!raw) {
      return;
    }
    const trimmed = raw.trim();
    if (!trimmed) {
      return;
    }
    const key = `${testId}::${trimmed}`;
    if (visited.has(key)) {
      return;
    }
    visited.add(key);

    if (!direct.has(trimmed)) {
      direct.set(trimmed, testId);
    }
    const lowerTrimmed = trimmed.toLowerCase();
    if (!lower.has(lowerTrimmed)) {
      lower.set(lowerTrimmed, testId);
    }

    tokenize(trimmed).forEach((token) => registerToken(token, testId));

    const whitespaceToken = trimmed.split(/\s+/)[0];
    if (whitespaceToken && whitespaceToken !== trimmed) {
      registerCandidate(whitespaceToken, testId);
    }

    const hashIndex = trimmed.indexOf('#');
    if (hashIndex > 0) {
      registerCandidate(trimmed.slice(0, hashIndex), testId);
    }

    const colonIndex = trimmed.indexOf(':');
    if (colonIndex > 0) {
      registerCandidate(trimmed.slice(0, colonIndex), testId);
    }

    if (trimmed.includes('/')) {
      const base = trimmed.substring(trimmed.lastIndexOf('/') + 1);
      if (base && base !== trimmed) {
        registerCandidate(base, testId);
      }
    }
  };

  tests.forEach((test) => {
    registerCandidate(test.testId, test.testId);
    registerCandidate(test.className, test.testId);
    registerCandidate(test.name, test.testId);
  });

  const resolve = (testName: string): string | undefined => {
    const trimmed = testName.trim();
    if (!trimmed) {
      return undefined;
    }

    const directMatch = direct.get(trimmed) ?? direct.get(trimmed.replace(/^['"]|['"]$/g, ''));
    if (directMatch) {
      return directMatch;
    }

    const lowerTrimmed = trimmed.toLowerCase();
    const lowerMatch =
      lower.get(lowerTrimmed) ?? lower.get(lowerTrimmed.replace(/^['"]|['"]$/g, ''));
    if (lowerMatch) {
      return lowerMatch;
    }

    const tokens = tokenize(trimmed);
    if (tokens.length === 0) {
      return undefined;
    }

    const scores = new Map<string, number>();
    tokens.forEach((token) => {
      const ids = tokenIndex.get(token);
      if (!ids) {
        return;
      }
      ids.forEach((id) => {
        scores.set(id, (scores.get(id) ?? 0) + 1);
      });
    });

    if (scores.size === 0) {
      return undefined;
    }

    const sorted = Array.from(scores.entries()).sort((a, b) => b[1] - a[1]);
    if (sorted.length === 1 || sorted[0][1] > sorted[1][1]) {
      return sorted[0][0];
    }

    return undefined;
  };

  return { resolve };
};

const normalizeCoveragePath = (filePath: string, origin: string): string | undefined => {
  const trimmed = filePath.trim();
  if (!trimmed) {
    return undefined;
  }
  if (path.isAbsolute(trimmed)) {
    return normalizeRelativePath(trimmed);
  }

  const cwdResolved = path.resolve(trimmed);
  const originResolved = path.resolve(path.dirname(origin), trimmed);

  const cwdRelative = path.relative(process.cwd(), cwdResolved);
  const originRelative = path.relative(process.cwd(), originResolved);

  const normalized =
    originRelative.length > 0 && originRelative.length < cwdRelative.length
      ? originResolved
      : cwdResolved;

  return normalizeRelativePath(normalized);
};

const deriveTestToCodeMap = (
  tests: TestResult[],
  coverageMaps: Array<{ map: Record<string, string[]>; origin: string }>,
): Record<string, string[]> => {
  if (tests.length === 0 || coverageMaps.length === 0) {
    return {};
  }

  const lookup = createTestLookup(tests);
  const combined = new Map<string, Set<string>>();

  coverageMaps.forEach(({ map, origin }) => {
    Object.entries(map).forEach(([testName, files]) => {
      const resolvedTestId = lookup.resolve(testName);
      if (!resolvedTestId) {
        return;
      }
      files.forEach((file) => {
        const normalized = normalizeCoveragePath(file, origin);
        if (!normalized) {
          return;
        }
        const existing = combined.get(resolvedTestId) ?? new Set<string>();
        existing.add(normalized);
        combined.set(resolvedTestId, existing);
      });
    });
  });

  return Object.fromEntries(
    Array.from(combined.entries()).map(([testId, files]) => [testId, Array.from(files).sort()]),
  );
};

const createEvidence = (
  artifact: ObjectiveArtifactType,
  source: EvidenceSource,
  filePath: string,
  summary: string,
): { artifact: ObjectiveArtifactType; evidence: Evidence } => ({
  artifact,
  evidence: {
    source,
    path: normalizeRelativePath(filePath),
    summary,
    timestamp: getCurrentTimestamp(),
  },
});

const mergeEvidence = (
  index: EvidenceIndex,
  artifact: ObjectiveArtifactType,
  evidence: Evidence,
): void => {
  const existing = index[artifact] ?? [];
  index[artifact] = [...existing, evidence];
};

const requirementStatusFromJira = (status: string): RequirementStatus => {
  const normalized = status.trim().toLowerCase();
  if (!normalized) {
    return 'draft';
  }
  if (/(verify|validated|done|closed|accepted)/.test(normalized)) {
    return 'verified';
  }
  if (/(implement|in progress|coding|development)/.test(normalized)) {
    return 'implemented';
  }
  if (/(review|approved|ready)/.test(normalized)) {
    return 'approved';
  }
  return 'draft';
};

const toRequirementFromJira = (entry: JiraRequirement): Requirement => {
  const requirement = createRequirement(entry.id, entry.summary || entry.id, {
    description: entry.summary,
    status: requirementStatusFromJira(entry.status),
    tags: entry.priority ? [`priority:${entry.priority.toLowerCase()}`] : [],
  });
  return requirement;
};

const toRequirementFromReqif = (entry: ReqIFRequirement): Requirement =>
  createRequirement(entry.id, entry.text || entry.id, {
    description: entry.text,
    status: 'draft',
  });

const mergeRequirements = (sources: Requirement[][]): Requirement[] => {
  const merged = new Map<string, Requirement>();
  sources.forEach((list) => {
    list.forEach((requirement) => {
      merged.set(requirement.id, requirement);
    });
  });
  return Array.from(merged.values()).sort((a, b) => a.id.localeCompare(b.id));
};

const buildTraceLinksFromTests = (tests: TestResult[]): TraceLink[] => {
  const links: TraceLink[] = [];
  tests.forEach((test) => {
    const requirementRefs = test.requirementsRefs ?? [];
    requirementRefs.forEach((requirementId) => {
      links.push({ from: requirementId, to: test.testId, type: 'verifies' });
    });
  });
  return links;
};

export const runImport = async (options: ImportOptions): Promise<ImportResult> => {
  const warnings: string[] = [];
  const requirements: Requirement[][] = [];
  const evidenceIndex: EvidenceIndex = {};
  let coverage: CoverageSummary | undefined;
  let gitMetadata: BuildInfo | null | undefined;
  const testResults: TestResult[] = [];
  const coverageMaps: Array<{ map: Record<string, string[]>; origin: string }> = [];
  const normalizedInputs: ImportPaths = {
    jira: options.jira ? normalizeRelativePath(options.jira) : undefined,
    reqif: options.reqif ? normalizeRelativePath(options.reqif) : undefined,
    junit: options.junit ? normalizeRelativePath(options.junit) : undefined,
    lcov: options.lcov ? normalizeRelativePath(options.lcov) : undefined,
    cobertura: options.cobertura ? normalizeRelativePath(options.cobertura) : undefined,
    git: options.git ? normalizeRelativePath(options.git) : undefined,
  };
  const normalizedObjectivesPath = options.objectives ? path.resolve(options.objectives) : undefined;

  if (options.jira) {
    const result = await importJiraCsv(options.jira);
    warnings.push(...result.warnings);
    if (result.data.length > 0) {
      mergeEvidence(
        evidenceIndex,
        'traceability',
        createEvidence('traceability', 'jiraCsv', options.jira!, 'Jira gereksinim dışa aktarımı').evidence,
      );
    }
    requirements.push(result.data.map(toRequirementFromJira));
  }

  if (options.reqif) {
    const result = await importReqIF(options.reqif);
    warnings.push(...result.warnings);
    if (result.data.length > 0) {
      mergeEvidence(
        evidenceIndex,
        'traceability',
        createEvidence('traceability', 'reqif', options.reqif, 'ReqIF gereksinim paketi').evidence,
      );
    }
    requirements.push(result.data.map(toRequirementFromReqif));
  }

  if (options.junit) {
    const result = await importJUnitXml(options.junit);
    warnings.push(...result.warnings);
    testResults.push(...result.data);
    if (result.data.length > 0) {
      mergeEvidence(
        evidenceIndex,
        'testResults',
        createEvidence('testResults', 'junit', options.junit, 'JUnit test sonuçları').evidence,
      );
    }
  }

  if (options.lcov) {
    const result = await importLcov(options.lcov);
    warnings.push(...result.warnings);
    coverage = result.data;
    if (result.data.testMap) {
      coverageMaps.push({ map: result.data.testMap, origin: path.resolve(options.lcov) });
    }
    if (result.data.files.length > 0) {
      mergeEvidence(
        evidenceIndex,
        'coverage',
        createEvidence('coverage', 'lcov', options.lcov, 'LCOV kapsam raporu').evidence,
      );
    }
  }

  if (!coverage && options.cobertura) {
    const result = await importCobertura(options.cobertura);
    warnings.push(...result.warnings);
    coverage = result.data;
    if (result.data.testMap) {
      coverageMaps.push({ map: result.data.testMap, origin: path.resolve(options.cobertura) });
    }
    if (result.data.files.length > 0) {
      mergeEvidence(
        evidenceIndex,
        'coverage',
        createEvidence('coverage', 'cobertura', options.cobertura, 'Cobertura kapsam raporu').evidence,
      );
    }
  } else if (options.cobertura) {
    const result = await importCobertura(options.cobertura);
    warnings.push(...result.warnings);
    if (result.data.testMap) {
      coverageMaps.push({ map: result.data.testMap, origin: path.resolve(options.cobertura) });
    }
    if (result.data.files.length > 0) {
      mergeEvidence(
        evidenceIndex,
        'coverage',
        createEvidence('coverage', 'cobertura', options.cobertura, 'Cobertura kapsam raporu').evidence,
      );
    }
  }

  if (options.git) {
    const result = await importGitMetadata(options.git);
    warnings.push(...result.warnings);
    gitMetadata = result.data;
    if (result.data) {
      mergeEvidence(
        evidenceIndex,
        'git',
        createEvidence('git', 'git', options.git, 'Git depo başlığı').evidence,
      );
    }
  }

  const mergedRequirements = mergeRequirements(requirements);
  const traceLinks = buildTraceLinksFromTests(testResults);
  const testToCodeMap = deriveTestToCodeMap(testResults, coverageMaps);

  const workspace: ImportWorkspace = {
    requirements: mergedRequirements,
    testResults,
    coverage,
    traceLinks,
    testToCodeMap,
    evidenceIndex,
    git: gitMetadata,
    metadata: {
      generatedAt: getCurrentTimestamp(),
      warnings,
      inputs: normalizedInputs,
      project: options.projectName || options.projectVersion ? {
        name: options.projectName,
        version: options.projectVersion,
      } : undefined,
      targetLevel: options.level,
      objectivesPath: normalizedObjectivesPath,
    },
  };

  const outputDir = path.resolve(options.output);
  await ensureDirectory(outputDir);
  const workspacePath = path.join(outputDir, 'workspace.json');
  await writeJsonFile(workspacePath, workspace);

  return { workspace, workspacePath, warnings };
};

export interface AnalyzeOptions {
  input: string;
  output: string;
  objectives?: string;
  level?: CertificationLevel;
  projectName?: string;
  projectVersion?: string;
}

export interface AnalyzeResult {
  snapshotPath: string;
  tracePath: string;
  analysisPath: string;
  exitCode: number;
}

interface AnalysisMetadata {
  project?: {
    name?: string;
    version?: string;
  };
  level: CertificationLevel;
  generatedAt: string;
}

const loadObjectives = async (filePath: string): Promise<Objective[]> => {
  const content = await fsPromises.readFile(path.resolve(filePath), 'utf8');
  const data = JSON.parse(content) as Objective[];
  return data;
};

const filterObjectives = (objectives: Objective[], level: CertificationLevel): Objective[] => {
  return objectives.filter((objective) => objective.level[level]);
};

const buildImportBundle = (
  workspace: ImportWorkspace,
  objectives: Objective[],
): ImportBundle => ({
  requirements: workspace.requirements,
  objectives,
  testResults: workspace.testResults,
  coverage: workspace.coverage,
  evidenceIndex: workspace.evidenceIndex,
  traceLinks: workspace.traceLinks,
  testToCodeMap: workspace.testToCodeMap,
  generatedAt: workspace.metadata.generatedAt,
});

const collectRequirementTraces = (
  engine: TraceEngine,
  requirements: Requirement[],
): RequirementTrace[] => {
  return requirements.map((requirement) => engine.getRequirementTrace(requirement.id));
};

export const runAnalyze = async (options: AnalyzeOptions): Promise<AnalyzeResult> => {
  const inputDir = path.resolve(options.input);
  const workspacePath = path.join(inputDir, 'workspace.json');
  const workspace = await readJsonFile<ImportWorkspace>(workspacePath);

  const level = options.level ?? workspace.metadata.targetLevel ?? 'C';
  const fallbackObjectivesPath = path.resolve('data', 'objectives', 'do178c_objectives.min.json');
  const objectivesPathRaw = options.objectives ?? workspace.metadata.objectivesPath ?? fallbackObjectivesPath;
  const objectivesPath = path.resolve(objectivesPathRaw);
  const objectives = await loadObjectives(objectivesPath);
  const filteredObjectives = filterObjectives(objectives, level);

  const bundle = buildImportBundle(workspace, filteredObjectives);
  const snapshot = generateComplianceSnapshot(bundle);
  const engine = new TraceEngine(bundle);
  const traces = collectRequirementTraces(engine, workspace.requirements);

  const outputDir = path.resolve(options.output);
  await ensureDirectory(outputDir);

  const snapshotPath = path.join(outputDir, 'snapshot.json');
  const tracePath = path.join(outputDir, 'traces.json');
  const analysisPath = path.join(outputDir, 'analysis.json');

  const analysisMetadata: AnalysisMetadata = {
    project: options.projectName || options.projectVersion || workspace.metadata.project
      ? {
          name: options.projectName ?? workspace.metadata.project?.name,
          version: options.projectVersion ?? workspace.metadata.project?.version,
        }
      : undefined,
    level,
    generatedAt: getCurrentTimestamp(),
  };

  await writeJsonFile(snapshotPath, snapshot);
  await writeJsonFile(tracePath, traces);
  await writeJsonFile(analysisPath, {
    metadata: analysisMetadata,
    objectives: filteredObjectives,
    requirements: workspace.requirements,
    tests: workspace.testResults,
    coverage: workspace.coverage,
    evidenceIndex: workspace.evidenceIndex,
    git: workspace.git,
    inputs: workspace.metadata.inputs,
    warnings: workspace.metadata.warnings,
  });

  const hasMissingEvidence = snapshot.objectives.some((objective) => objective.status !== 'covered');
  const exitCode = hasMissingEvidence ? exitCodes.missingEvidence : exitCodes.success;

  return { snapshotPath, tracePath, analysisPath, exitCode };
};

export interface ReportOptions {
  input: string;
  output: string;
  manifestId?: string;
}

export interface ReportResult {
  complianceHtml: string;
  complianceJson: string;
  traceHtml: string;
  gapsHtml: string;
}

export const runReport = async (options: ReportOptions): Promise<ReportResult> => {
  const inputDir = path.resolve(options.input);
  const analysisPath = path.join(inputDir, 'analysis.json');
  const snapshotPath = path.join(inputDir, 'snapshot.json');
  const tracePath = path.join(inputDir, 'traces.json');

  const analysis = await readJsonFile<{
    metadata: AnalysisMetadata;
    objectives: Objective[];
    requirements: Requirement[];
    tests: TestResult[];
    coverage?: CoverageSummary;
    evidenceIndex: EvidenceIndex;
    git?: BuildInfo | null;
    inputs: ImportPaths;
    warnings: string[];
  }>(analysisPath);
  const snapshot = await readJsonFile<ComplianceSnapshot>(snapshotPath);
  const traces = await readJsonFile<RequirementTrace[]>(tracePath);

  const compliance = renderComplianceMatrix(snapshot, {
    objectivesMetadata: analysis.objectives,
    manifestId: options.manifestId,
    generatedAt: analysis.metadata.generatedAt,
    title: analysis.metadata.project?.name
      ? `${analysis.metadata.project.name} Uyum Matrisi`
      : 'SOIPack Uyum Matrisi',
  });
  const traceHtml = renderTraceMatrix(traces, {
    generatedAt: analysis.metadata.generatedAt,
    title: analysis.metadata.project?.name
      ? `${analysis.metadata.project.name} İzlenebilirlik Matrisi`
      : 'SOIPack İzlenebilirlik Matrisi',
    coverage: snapshot.requirementCoverage,
  });
  const gapsHtml = renderGaps(snapshot, {
    objectivesMetadata: analysis.objectives,
    manifestId: options.manifestId,
    generatedAt: analysis.metadata.generatedAt,
    title: analysis.metadata.project?.name
      ? `${analysis.metadata.project.name} Kanıt Boşlukları`
      : 'SOIPack Uyumluluk Boşlukları',
  });

  const outputDir = path.resolve(options.output);
  await ensureDirectory(outputDir);

  const complianceHtmlPath = path.join(outputDir, 'compliance.html');
  const complianceJsonPath = path.join(outputDir, 'compliance.json');
  const traceHtmlPath = path.join(outputDir, 'trace.html');
  const gapsHtmlPath = path.join(outputDir, 'gaps.html');

  await fsPromises.copyFile(snapshotPath, path.join(outputDir, 'snapshot.json'));
  await fsPromises.copyFile(tracePath, path.join(outputDir, 'traces.json'));

  await fsPromises.writeFile(complianceHtmlPath, compliance.html, 'utf8');
  await writeJsonFile(complianceJsonPath, compliance.json);
  await fsPromises.writeFile(traceHtmlPath, traceHtml, 'utf8');
  await fsPromises.writeFile(gapsHtmlPath, gapsHtml, 'utf8');
  await writeJsonFile(path.join(outputDir, 'analysis.json'), analysis);

  return {
    complianceHtml: complianceHtmlPath,
    complianceJson: complianceJsonPath,
    traceHtml: traceHtmlPath,
    gapsHtml: gapsHtmlPath,
  };
};

export interface PackOptions {
  input: string;
  output: string;
  signingKey: string;
  packageName?: string;
}

export interface PackResult {
  manifestPath: string;
  archivePath: string;
  manifestId: string;
}

const createArchive = async (
  files: Array<{ absolutePath: string; manifestPath: string }>,
  outputPath: string,
  manifestContent: string,
  signature?: string,
): Promise<void> => {
  await ensureDirectory(path.dirname(outputPath));
  const zip = new ZipFile();
  const output = fs.createWriteStream(outputPath);

  const completion = new Promise<void>((resolve, reject) => {
    output.on('close', () => resolve());
    output.on('error', (error) => reject(error));
    zip.outputStream.on('error', (error) => reject(error));
  });

  zip.outputStream.pipe(output);

  for (const file of files) {
    const options = hasFixedTimestamp ? { mtime: getCurrentDate() } : undefined;
    zip.addFile(file.absolutePath, file.manifestPath, options);
  }

  zip.addBuffer(Buffer.from(manifestContent, 'utf8'), 'manifest.json');
  if (signature) {
    const normalizedSignature = signature.endsWith('\n') ? signature : `${signature}\n`;
    const options = hasFixedTimestamp ? { mtime: getCurrentDate() } : undefined;
    zip.addBuffer(Buffer.from(normalizedSignature, 'utf8'), 'manifest.sig', options);
  }
  zip.end();

  await completion;
};

const directoryExists = async (target: string): Promise<boolean> => {
  try {
    const stats = await fsPromises.stat(target);
    return stats.isDirectory();
  } catch {
    return false;
  }
};

const resolveReportDirectory = async (inputDir: string): Promise<string> => {
  const candidate = path.join(inputDir, 'reports');
  if (await directoryExists(candidate)) {
    return candidate;
  }
  return inputDir;
};

const resolveEvidenceDirectories = async (inputDir: string, reportDir: string): Promise<string[]> => {
  if (inputDir === reportDir) {
    return [];
  }

  const entries = await fsPromises.readdir(inputDir, { withFileTypes: true });
  return entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => path.join(inputDir, entry.name))
    .filter((dir) => path.resolve(dir) !== path.resolve(reportDir));
};

export const runPack = async (options: PackOptions): Promise<PackResult> => {
  const inputDir = path.resolve(options.input);
  const outputDir = path.resolve(options.output);
  await ensureDirectory(outputDir);

  const reportDir = await resolveReportDirectory(inputDir);
  const evidenceDirs = await resolveEvidenceDirectories(inputDir, reportDir);
  const now = getCurrentDate();

  const { manifest, files } = await buildManifest({
    reportDir,
    evidenceDirs,
    toolVersion: packageInfo.version,
    now,
  });

  const manifestSerialized = `${JSON.stringify(manifest, null, 2)}\n`;
  const signature = signManifest(manifest, options.signingKey);
  const manifestHash = createHash('sha256').update(manifestSerialized).digest('hex');
  const manifestId = manifestHash.slice(0, 12);

  const manifestPath = path.join(outputDir, 'manifest.json');
  await fsPromises.writeFile(manifestPath, manifestSerialized, 'utf8');
  const signaturePath = path.join(outputDir, 'manifest.sig');
  await fsPromises.writeFile(signaturePath, `${signature}\n`, 'utf8');

  const archiveName = options.packageName ?? `soipack-${manifestId}.zip`;
  const archivePath = path.join(outputDir, archiveName);
  await createArchive(files, archivePath, manifestSerialized, `${signature}\n`);

  return { manifestPath, archivePath, manifestId };
};

export interface VerifyOptions {
  manifestPath: string;
  signaturePath: string;
  publicKeyPath: string;
}

export interface VerifyResult {
  isValid: boolean;
  manifestId: string;
}

const readUtf8File = async (filePath: string, errorMessage: string): Promise<string> => {
  try {
    return await fsPromises.readFile(filePath, 'utf8');
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(`${errorMessage}: ${reason}`);
  }
};

export const runVerify = async (options: VerifyOptions): Promise<VerifyResult> => {
  const manifestPath = path.resolve(options.manifestPath);
  const signaturePath = path.resolve(options.signaturePath);
  const publicKeyPath = path.resolve(options.publicKeyPath);

  const manifestRaw = await readUtf8File(manifestPath, 'Manifest dosyası okunamadı');

  let manifest: Manifest;
  try {
    manifest = JSON.parse(manifestRaw) as Manifest;
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(`Manifest JSON formatı çözümlenemedi: ${reason}`);
  }

  const signatureRaw = await readUtf8File(signaturePath, 'Manifest imza dosyası okunamadı');
  const signature = signatureRaw.trim();
  if (!signature) {
    throw new Error('Manifest imza dosyası boş.');
  }

  const publicKey = await readUtf8File(publicKeyPath, 'Genel anahtar dosyası okunamadı');

  const manifestId = createHash('sha256').update(manifestRaw).digest('hex').slice(0, 12);
  const isValid = verifyManifestSignature(manifest, signature, publicKey);

  return { isValid, manifestId };
};

interface RunConfig {
  project?: {
    name?: string;
    version?: string;
  };
  level?: CertificationLevel;
  objectives?: {
    file?: string;
  };
  inputs?: ImportPaths;
  output?: {
    work?: string;
    analysis?: string;
    reports?: string;
    release?: string;
  };
  pack?: {
    name?: string;
    input?: string;
  };
}

export const runPipeline = async (
  configPath: string,
  options: { signingKey: string },
  logger?: Logger,
): Promise<number> => {
  const absoluteConfig = path.resolve(configPath);
  const raw = await fsPromises.readFile(absoluteConfig, 'utf8');
  const config = YAML.parse(raw) as RunConfig;
  const baseDir = path.dirname(absoluteConfig);

  const level = config.level ?? 'C';
  const workDir = path.resolve(baseDir, config.output?.work ?? '.soipack/work');
  const analysisDir = path.resolve(baseDir, config.output?.analysis ?? '.soipack/out');
  const reportDir = path.resolve(baseDir, config.output?.reports ?? 'dist/reports');
  const releaseDir = path.resolve(baseDir, config.output?.release ?? 'release');

  const importResult = await runImport({
    output: workDir,
    jira: config.inputs?.jira ? path.resolve(baseDir, config.inputs.jira) : undefined,
    reqif: config.inputs?.reqif ? path.resolve(baseDir, config.inputs.reqif) : undefined,
    junit: config.inputs?.junit ? path.resolve(baseDir, config.inputs.junit) : undefined,
    lcov: config.inputs?.lcov ? path.resolve(baseDir, config.inputs.lcov) : undefined,
    cobertura: config.inputs?.cobertura ? path.resolve(baseDir, config.inputs.cobertura) : undefined,
    git: config.inputs?.git ? path.resolve(baseDir, config.inputs.git) : undefined,
    objectives: config.objectives?.file ? path.resolve(baseDir, config.objectives.file) : undefined,
    level,
    projectName: config.project?.name,
    projectVersion: config.project?.version,
  });

  if (importResult.warnings.length > 0) {
    importResult.warnings.forEach((warning) => {
      logger?.warn({ warning, command: 'run' }, 'İçe aktarma uyarısı alındı.');
    });
  }
  logger?.info(
    { workspacePath: importResult.workspacePath, command: 'run' },
    'Çalışma alanı hazırlandı.',
  );

  const analyzeResult = await runAnalyze({
    input: workDir,
    output: analysisDir,
    level,
    objectives: config.objectives?.file ? path.resolve(baseDir, config.objectives.file) : undefined,
    projectName: config.project?.name,
    projectVersion: config.project?.version,
  });

  const reportResult = await runReport({
    input: analysisDir,
    output: reportDir,
  });

  const packInput = config.pack?.input
    ? path.resolve(baseDir, config.pack.input)
    : path.resolve(baseDir, 'dist');
  const packResult = await runPack({
    input: packInput,
    output: releaseDir,
    packageName: config.pack?.name,
    signingKey: options.signingKey,
  });

  logger?.info(
    { complianceHtml: reportResult.complianceHtml, command: 'run' },
    'Raporlar üretildi.',
  );
  logger?.info(
    { manifestPath: packResult.manifestPath, command: 'run' },
    'Manifest kaydedildi.',
  );
  logger?.info(
    {
      archivePath: packResult.archivePath,
      manifestId: packResult.manifestId,
      command: 'run',
    },
    'Paket hazırlandı.',
  );

  if (analyzeResult.exitCode === exitCodes.missingEvidence) {
    logger?.warn(
      { command: 'run' },
      'Analiz hedefleri için eksik kanıt bulundu. Paket uyarı ile tamamlandı.',
    );
    return exitCodes.missingEvidence;
  }
  logger?.info({ command: 'run' }, 'Tüm hedef kanıtlar başarıyla toplandı.');
  return exitCodes.success;
};

interface GlobalArguments {
  verbose?: boolean;
  license?: string;
}

let sharedLogger: Logger | undefined;

const getLogger = (argv: yargs.ArgumentsCamelCase<unknown>): Logger => {
  if (!sharedLogger) {
    const { verbose } = argv as yargs.ArgumentsCamelCase<GlobalArguments>;
    sharedLogger = createLogger({ verbose: Boolean(verbose) });
  }
  return sharedLogger;
};

const getLicensePath = (argv: yargs.ArgumentsCamelCase<unknown>): string => {
  const { license } = argv as yargs.ArgumentsCamelCase<GlobalArguments>;
  const value = Array.isArray(license) ? license[0] : license;
  return resolveLicensePath(value as string | undefined);
};

const logLicenseValidated = (
  logger: Logger,
  license: LicensePayload,
  context: Record<string, unknown>,
): void => {
  logger.debug(
    {
      ...context,
      licenseId: license.licenseId,
      issuedTo: license.issuedTo,
      expiresAt: license.expiresAt,
    },
    'Lisans doğrulandı.',
  );
};

const logCliError = (
  logger: Logger,
  error: unknown,
  context: Record<string, unknown> = {},
): void => {
  if (error instanceof LicenseError) {
    logger.error({ ...context, err: error }, error.message);
    return;
  }

  if (error instanceof Error) {
    logger.error({ ...context, err: error }, error.message);
    return;
  }

  logger.error(
    {
      ...context,
      error: { message: String(error) },
    },
    'Beklenmeyen bir hata oluştu.',
  );
};

if (require.main === module) {
  const cli = yargs(hideBin(process.argv))
    .scriptName('soipack')
    .usage('$0 <command> [options]')
    .option('verbose', {
      describe: 'Ayrıntılı JSON log çıktısı.',
      type: 'boolean',
      global: true,
      default: false,
    })
    .option('license', {
      describe: 'Lisans anahtarı dosyasının yolu.',
      type: 'string',
      global: true,
      default: DEFAULT_LICENSE_FILE,
    })
    .version('version', 'Sürüm bilgisini gösterir.', formatVersion())
    .alias('version', 'V')
    .command(
      'import',
      'Gereksinim, test ve kapsam kanıtlarını çalışma alanına aktarır.',
      (y) =>
        y
          .option('jira', {
            describe: 'Jira CSV dışa aktarımının yolu.',
            type: 'string',
          })
          .option('reqif', {
            describe: 'ReqIF gereksinim paketi yolu.',
            type: 'string',
          })
          .option('junit', {
            describe: 'JUnit XML test sonuç dosyası.',
            type: 'string',
          })
          .option('lcov', {
            describe: 'LCOV kapsam raporu.',
            type: 'string',
          })
          .option('cobertura', {
            describe: 'Cobertura kapsam raporu.',
            type: 'string',
          })
          .option('git', {
            describe: 'Git deposu kök dizini.',
            type: 'string',
          })
          .option('objectives', {
            describe: 'Uyum hedefleri JSON dosyası.',
            type: 'string',
          })
          .option('level', {
            describe: 'Hedef seviye (A-E).',
            type: 'string',
          })
          .option('project-name', {
            describe: 'Proje adı.',
            type: 'string',
          })
          .option('project-version', {
            describe: 'Proje sürümü.',
            type: 'string',
          })
          .option('output', {
            alias: 'o',
            describe: 'Çıktı çalışma dizini.',
            type: 'string',
            demandOption: true,
          }),
      async (argv) => {
        const logger = getLogger(argv);
        const licensePath = getLicensePath(argv);
        const context = { command: 'import', licensePath, output: argv.output };

        try {
          const license = await verifyLicenseFile(licensePath);
          logLicenseValidated(logger, license, context);

          const result = await runImport({
            output: argv.output,
            jira: argv.jira,
            reqif: argv.reqif,
            junit: argv.junit,
            lcov: argv.lcov,
            cobertura: argv.cobertura,
            git: argv.git,
            objectives: argv.objectives,
            level: argv.level as CertificationLevel | undefined,
            projectName: argv.projectName as string | undefined,
            projectVersion: argv.projectVersion as string | undefined,
          });

          if (result.warnings.length > 0) {
            result.warnings.forEach((warning) => {
              logger.warn({ ...context, warning }, 'İçe aktarma uyarısı alındı.');
            });
          }

          logger.info(
            { ...context, workspacePath: result.workspacePath },
            'Çalışma alanı kaydedildi.',
          );
          process.exitCode = exitCodes.success;
        } catch (error) {
          logCliError(logger, error, context);
          process.exitCode = exitCodes.error;
        }
      },
    )
    .command(
      'analyze',
      'Çalışma alanını kullanarak uyum analizi üretir.',
      (y) =>
        y
          .option('input', {
            alias: 'i',
            describe: 'Import çıktısının bulunduğu dizin.',
            type: 'string',
            demandOption: true,
          })
          .option('output', {
            alias: 'o',
            describe: 'Analiz çıktılarının yazılacağı dizin.',
            type: 'string',
            demandOption: true,
          })
          .option('objectives', {
            describe: 'Uyum hedefleri JSON dosyası.',
            type: 'string',
          })
          .option('level', {
            describe: 'Hedef seviye (A-E).',
            type: 'string',
          })
          .option('project-name', {
            describe: 'Proje adı.',
            type: 'string',
          })
          .option('project-version', {
            describe: 'Proje sürümü.',
            type: 'string',
          }),
      async (argv) => {
        const logger = getLogger(argv);
        const licensePath = getLicensePath(argv);
        const context = {
          command: 'analyze',
          licensePath,
          input: argv.input,
          output: argv.output,
        };

        try {
          const license = await verifyLicenseFile(licensePath);
          logLicenseValidated(logger, license, context);

          const result = await runAnalyze({
            input: argv.input,
            output: argv.output,
            objectives: argv.objectives,
            level: argv.level as CertificationLevel | undefined,
            projectName: argv.projectName as string | undefined,
            projectVersion: argv.projectVersion as string | undefined,
          });

          logger.info({ ...context, exitCode: result.exitCode }, 'Analiz tamamlandı.');
          process.exitCode = result.exitCode;
        } catch (error) {
          logCliError(logger, error, context);
          process.exitCode = exitCodes.error;
        }
      },
    )
    .command(
      'report',
      'Analiz sonuçlarından HTML/JSON raporları üretir.',
      (y) =>
        y
          .option('input', {
            alias: 'i',
            describe: 'Analiz çıktısı dizini.',
            type: 'string',
            demandOption: true,
          })
          .option('output', {
            alias: 'o',
            describe: 'Raporların yazılacağı dizin.',
            type: 'string',
            demandOption: true,
          }),
      async (argv) => {
        const logger = getLogger(argv);
        const licensePath = getLicensePath(argv);
        const context = {
          command: 'report',
          licensePath,
          input: argv.input,
          output: argv.output,
        };

        try {
          const license = await verifyLicenseFile(licensePath);
          logLicenseValidated(logger, license, context);

          const result = await runReport({
            input: argv.input,
            output: argv.output,
          });

          logger.info(
            { ...context, complianceHtml: result.complianceHtml },
            'Uyum raporu oluşturuldu.',
          );
          process.exitCode = exitCodes.success;
        } catch (error) {
          logCliError(logger, error, context);
          process.exitCode = exitCodes.error;
        }
      },
    )
    .command(
      'pack',
      'Rapor klasörünü zip paketine dönüştürür.',
      (y) =>
        y
          .option('input', {
            alias: 'i',
            describe: 'Paketlenecek kök dizin.',
            type: 'string',
            demandOption: true,
          })
          .option('output', {
            alias: 'o',
            describe: 'Paketin yazılacağı dizin.',
            type: 'string',
            demandOption: true,
          })
          .option('name', {
            describe: 'Çıktı paketi dosya adı.',
            type: 'string',
          })
          .option('signing-key', {
            describe: 'Ed25519 özel anahtar PEM dosyası.',
            type: 'string',
            demandOption: true,
          }),
      async (argv) => {
        const logger = getLogger(argv);
        const licensePath = getLicensePath(argv);
        const context = {
          command: 'pack',
          licensePath,
          input: argv.input,
          output: argv.output,
          name: argv.name,
          signingKeyPath: argv.signingKey,
        };

        try {
          const license = await verifyLicenseFile(licensePath);
          logLicenseValidated(logger, license, context);

          const signingKeyOption = Array.isArray(argv.signingKey)
            ? argv.signingKey[0]
            : argv.signingKey;
          const signingKeyPath = path.resolve(signingKeyOption as string);
          context.signingKeyPath = signingKeyPath;
          const signingKey = await fsPromises.readFile(signingKeyPath, 'utf8');

          const result = await runPack({
            input: argv.input,
            output: argv.output,
            packageName: argv.name,
            signingKey,
          });

          logger.info(
            {
              ...context,
              archivePath: result.archivePath,
              manifestPath: result.manifestPath,
              manifestId: result.manifestId,
            },
            'Paket oluşturuldu.',
          );
          process.exitCode = exitCodes.success;
        } catch (error) {
          logCliError(logger, error, context);
          process.exitCode = exitCodes.error;
        }
      },
    )
    .command(
      'verify',
      'Manifest imzasını doğrular.',
      (y) =>
        y
          .option('manifest', {
            describe: 'Doğrulanacak manifest JSON dosyası.',
            type: 'string',
            demandOption: true,
          })
          .option('signature', {
            describe: 'Manifest imza dosyası (manifest.sig).',
            type: 'string',
            demandOption: true,
          })
          .option('public-key', {
            describe: 'Ed25519 kamu anahtarı PEM dosyası.',
            type: 'string',
            demandOption: true,
          }),
      async (argv) => {
        const logger = getLogger(argv);
        const manifestOption = Array.isArray(argv.manifest) ? argv.manifest[0] : argv.manifest;
        const signatureOption = Array.isArray(argv.signature) ? argv.signature[0] : argv.signature;
        const publicKeyOption = Array.isArray(argv.publicKey) ? argv.publicKey[0] : argv.publicKey;

        const manifestPath = path.resolve(manifestOption as string);
        const signaturePath = path.resolve(signatureOption as string);
        const publicKeyPath = path.resolve(publicKeyOption as string);

        const context = {
          command: 'verify',
          manifestPath,
          signaturePath,
          publicKeyPath,
        };

        try {
          const result = await runVerify({
            manifestPath,
            signaturePath,
            publicKeyPath,
          });

          if (result.isValid) {
            logger.info({ ...context, manifestId: result.manifestId }, 'Manifest imzası doğrulandı.');
            console.log(`Manifest imzası doğrulandı (ID: ${result.manifestId}).`);
            process.exitCode = exitCodes.success;
          } else {
            logger.warn({ ...context, manifestId: result.manifestId }, 'Manifest imzası doğrulanamadı.');
            console.error(`Manifest imzası doğrulanamadı (ID: ${result.manifestId}).`);
            process.exitCode = exitCodes.verificationFailed;
          }
        } catch (error) {
          logCliError(logger, error, context);
          const message = error instanceof Error ? error.message : String(error);
          console.error(`Manifest doğrulaması sırasında hata oluştu: ${message}`);
          process.exitCode = exitCodes.error;
        }
      },
    )
    .command(
      'run',
      'YAML konfigürasyonu ile uçtan uca içe aktarım → analiz → rapor → paket akışını çalıştırır.',
      (y) =>
        y
          .option('config', {
            alias: 'c',
            describe: 'soipack.config.yaml yolu.',
            type: 'string',
            demandOption: true,
          })
          .option('signing-key', {
            describe: 'Ed25519 özel anahtar PEM dosyası.',
            type: 'string',
            demandOption: true,
          }),
      async (argv) => {
        const logger = getLogger(argv);
        const licensePath = getLicensePath(argv);
        const context = {
          command: 'run',
          licensePath,
          config: argv.config,
          signingKeyPath: argv.signingKey,
        };

        try {
          const license = await verifyLicenseFile(licensePath);
          logLicenseValidated(logger, license, context);

          const signingKeyOption = Array.isArray(argv.signingKey)
            ? argv.signingKey[0]
            : argv.signingKey;
          const signingKeyPath = path.resolve(signingKeyOption as string);
          context.signingKeyPath = signingKeyPath;
          const signingKey = await fsPromises.readFile(signingKeyPath, 'utf8');

          const exitCode = await runPipeline(argv.config, { signingKey }, logger);
          process.exitCode = exitCode;
        } catch (error) {
          logCliError(logger, error, context);
          process.exitCode = exitCodes.error;
        }
      },
    )
    .demandCommand(1, 'Bir komut seçmelisiniz.')
    .strict()
    .help()
    .wrap(100);

  cli.parse();
}

export { exitCodes };
