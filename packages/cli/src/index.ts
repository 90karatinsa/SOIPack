#!/usr/bin/env node
import {
  createHash,
  createPublicKey,
  randomUUID,
  sign as signDetached,
  verify as verifySignature,
} from 'crypto';
import fs, { promises as fsPromises } from 'fs';
import http from 'http';
import https from 'https';
import path from 'path';
import process from 'process';
import { pipeline as streamPipeline } from 'stream/promises';
import { inflateRawSync } from 'zlib';
import { execFile, spawn } from 'child_process';
import type { ExecFileOptionsWithStringEncoding } from 'child_process';
import { promisify } from 'util';

import {
  importCobertura,
  importGitMetadata,
  importJiraCsv,
  importJUnitXml,
  importLcov,
  importParasoft,
  importDoorsClassicCsv,
  importQaLogs,
  fetchAzureDevOpsArtifacts,
  fetchDoorsNextArtifacts,
  fetchJamaArtifacts,
  fetchJiraArtifacts,
  fetchJenkinsArtifacts,
  fetchPolarionArtifacts,
  importReqIF,
  fromLDRA,
  fromPolyspace,
  fromVectorCAST,
  fromSimulink,
  aggregateImportBundle,
  type BuildInfo,
  type CoverageReport,
  type CoverageMetric,
  type FileCoverageSummary,
  type CoverageSummary as StructuralCoverageSummary,
  type Finding,
  type ImportedFileHash,
  type JiraRequirement,
  type JenkinsClientOptions,
  type JenkinsCoverageArtifactMetadata,
  type JenkinsCoverageArtifactOptions,
  type PolarionClientOptions,
  type JamaClientOptions,
  type DoorsNextClientOptions,
  type DoorsNextRelationship,
  type JiraArtifactsOptions,
  type RemoteRequirementRecord,
  type RemoteTestRecord,
  type RemoteDesignRecord,
  type ReqIFRequirement,
  type TestResult,
  type TestStatus,
  type AzureDevOpsClientOptions,
  type AzureDevOpsAttachmentMetadata,
} from '@soipack/adapters';
import {
  CertificationLevel,
  certificationLevels,
  DesignRecord,
  DesignStatus,
  Evidence,
  EvidenceSource,
  evidenceSources,
  Manifest,
  Objective,
  SoiStage,
  soiStages,
  ObjectiveArtifactType,
  objectiveArtifactTypes,
  Requirement,
  RequirementStatus,
  SnapshotVersion,
  TraceLink,
  createDesignRecord,
  createRequirement,
  createSnapshotIdentifier,
  createSnapshotVersion,
  designStatuses,
  deriveFingerprint,
  traceLinkSchema,
  appendEntry,
  createLedger,
  Ledger,
  LedgerEntry,
  LedgerSignerOptions,
  AppendEntryOptions,
  deserializeLedgerProof,
  verifyLedgerProof,
} from '@soipack/core';
import {
  ComplianceSnapshot,
  ComplianceIndependenceSummary,
  EvidenceIndex,
  ImportBundle,
  ObjectiveCoverage,
  ObjectiveCoverageStatus,
  RequirementTrace,
  TraceEngine,
  generateComplianceSnapshot,
  computeRemediationPlan,
  simulateComplianceRisk,
  type ChangeImpactScore,
  type ComplianceRiskSimulationResult,
  type RiskSimulationBacklogSample,
  type RiskSimulationCoverageSample,
  type RiskSimulationTestSample,
  type TraceGraph,
  type RemediationPlan,
  type GapAnalysis,
} from '@soipack/engine';
import {
  buildManifest,
  computeManifestDigestHex,
  signManifestBundle,
  verifyManifestSignature,
  verifyManifestSignatureDetailed,
  LedgerAwareManifest,
  ManifestProvenanceSignatureMetadata,
} from '@soipack/packager';
import {
  generateAttestation,
  serializeAttestationDocument,
} from '@soipack/packager/attestation';
import {
  renderComplianceMatrix,
  renderGaps,
  renderTraceMatrix,
  renderPlanDocument,
  renderPlanPdf,
  renderToolQualificationPack,
  renderGsnGraphDot as renderGsnGraphDotReport,
  planTemplateSections,
  planTemplateTitles,
  printToPDF,
  type LedgerAttestationDiffItem,
  type PlanTemplateId,
  type PlanOverrideConfig,
  type PlanSectionOverrides,
  type PlanRenderOptions,
  type ToolQualificationPackResult,
  type ToolUsageMetadata,
} from '@soipack/report';
import YAML from 'yaml';
import yargs, { type CommandModule } from 'yargs';
import { hideBin } from 'yargs/helpers';
import { ZipFile } from 'yazl';
import { ZodError } from 'zod';

import packageInfo from '../package.json';

import {
  DEFAULT_LICENSE_FILE,
  LicenseError,
  verifyLicenseFile,
  resolveLicensePath,
  type LicensePayload,
  type VerifyLicenseOptions,
} from './license';
import { getCliAvailableLocales, getCliLocale, setCliLocale, translateCli } from './localization';
import { createLogger } from './logging';
import type { Logger } from './logging';
import { formatVersion } from './version';

const fixedTimestampSource = process.env.SOIPACK_DEMO_TIMESTAMP;
const parsedFixedTimestamp = fixedTimestampSource ? new Date(fixedTimestampSource) : undefined;
const hasFixedTimestamp =
  parsedFixedTimestamp !== undefined && !Number.isNaN(parsedFixedTimestamp.getTime());

const getCurrentDate = (): Date =>
  hasFixedTimestamp ? new Date(parsedFixedTimestamp!.getTime()) : new Date();

const getCurrentTimestamp = (): string => getCurrentDate().toISOString();

const execFileAsync = promisify(execFile) as (
  file: string,
  args: string[],
  options: ExecFileOptionsWithStringEncoding,
) => Promise<{ stdout: string; stderr: string }>;

const DEFAULT_BASELINE_GIT_SNAPSHOT_PATH = '.soipack/out/snapshot.json';
const DEFAULT_GIT_SHOW_MAX_BUFFER = 10 * 1024 * 1024;

interface ImportPaths {
  jira?: string;
  jiraDefects?: string[];
  jiraCloud?: string;
  reqif?: string;
  junit?: string;
  lcov?: string;
  cobertura?: string;
  git?: string;
  traceLinksCsv?: string;
  traceLinksJson?: string;
  designCsv?: string;
  doorsClassicReqs?: string[];
  doorsClassicTraces?: string[];
  doorsClassicTests?: string[];
  doorsNext?: string;
  jama?: string;
  polyspace?: string;
  ldra?: string;
  vectorcast?: string;
  simulink?: string;
  parasoft?: string[];
  polarion?: string;
  jenkins?: string;
  azureDevOps?: string;
  manualArtifacts?: Partial<Record<ObjectiveArtifactType, string[]>>;
  qaLogs?: string[];
}

export type ImportOptions = Omit<
  ImportPaths,
  'polarion' | 'jenkins' | 'doorsNext' | 'jama' | 'jiraCloud' | 'azureDevOps'
> & {
  output: string;
  objectives?: string;
  level?: CertificationLevel;
  projectName?: string;
  projectVersion?: string;
  polarion?: PolarionClientOptions;
  jenkins?: JenkinsClientOptions;
  azureDevOps?: AzureDevOpsClientOptions;
  doorsNext?: DoorsNextClientOptions;
  jama?: JamaClientOptions;
  jiraCloud?: JiraArtifactsOptions;
  independentSources?: Array<EvidenceSource | string>;
  independentArtifacts?: string[];
};

export interface ImportWorkspace {
  requirements: Requirement[];
  designs: DesignRecord[];
  testResults: TestResult[];
  coverage?: CoverageReport;
  structuralCoverage?: StructuralCoverageSummary;
  traceLinks: TraceLink[];
  testToCodeMap: Record<string, string[]>;
  evidenceIndex: EvidenceIndex;
  git?: BuildInfo | null;
  findings: Finding[];
  builds: ExternalBuildRecord[];
  fileHashes?: ImportedFileHash[];
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
    sources?: ExternalSourceMetadata;
    version: SnapshotVersion;
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

const ensureReadableFile = async (filePath: string, label: string): Promise<void> => {
  try {
    await fsPromises.access(filePath, fs.constants.R_OK);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const displayPath = path.relative(process.cwd(), filePath) || filePath;
    console.error(`${label} (${displayPath}) okunamadı: ${message}`);
    process.exit(1);
  }
};

const ensureWritableParentDirectory = async (filePath: string): Promise<void> => {
  const directory = path.dirname(filePath);
  const displayDirectory = path.relative(process.cwd(), directory) || directory;

  try {
    const stats = await fsPromises.stat(directory);
    if (!stats.isDirectory()) {
      console.error(`Çıktı dizini (${displayDirectory}) bir dizin değil.`);
      process.exit(1);
    }
  } catch (error) {
    const code = (error as NodeJS.ErrnoException)?.code;
    if (code === 'ENOENT') {
      console.error(`Çıktı dizini (${displayDirectory}) bulunamadı.`);
    } else {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`Çıktı dizini (${displayDirectory}) doğrulanamadı: ${message}`);
    }
    process.exit(1);
  }

  try {
    await fsPromises.access(directory, fs.constants.W_OK);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`Çıktı dizinine yazılamıyor (${displayDirectory}): ${message}`);
    process.exit(1);
  }
};

export interface RenderGsnGraphInput {
  snapshot?: ComplianceSnapshot;
  objectives?: Objective[];
}

const renderObjectivesOnlyGraph = (objectives: Objective[]): string => {
  const lines = ['digraph ComplianceObjectives {', '  rankdir=LR;'];

  objectives.forEach((objective) => {
    const summaryParts = [objective.name, objective.desc].filter(Boolean);
    const label = summaryParts.length > 0 ? `${objective.id}\\n${summaryParts.join(' — ')}` : objective.id;
    lines.push(`  "${objective.id}" [shape=box, label=${JSON.stringify(label)}];`);
  });

  lines.push('}');
  return lines.join('\n');
};

export const renderGsnGraphDot = async ({
  snapshot,
  objectives,
}: RenderGsnGraphInput): Promise<string> => {
  if (snapshot) {
    return Promise.resolve(
      renderGsnGraphDotReport(snapshot, {
        objectivesMetadata: objectives,
      }),
    );
  }

  if (!objectives || objectives.length === 0) {
    throw new Error('GSN grafiği üretmek için snapshot veya objectives verisi gerekli.');
  }

  return renderObjectivesOnlyGraph(objectives);
};

const clamp = (value: number, min: number, max: number): number => {
  if (Number.isNaN(value)) {
    return min;
  }
  return Math.min(Math.max(value, min), max);
};

const uniqueTraceLinks = (links: TraceLink[]): TraceLink[] => {
  const seen = new Set<string>();
  const result: TraceLink[] = [];

  links.forEach((link) => {
    const key = `${link.from}::${link.to}::${link.type}`;
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    result.push(link);
  });

  return result;
};

const isRemotePath = (filePath: string): boolean =>
  /^[a-z]+:\/\//iu.test(filePath) || filePath.startsWith('remote:');

const normalizeRelativePath = (filePath: string): string => {
  if (isRemotePath(filePath)) {
    return filePath;
  }
  const absolute = path.resolve(filePath);
  const relative = path.relative(process.cwd(), absolute);
  const normalized = relative.length > 0 ? relative : '.';
  return normalized.split(path.sep).join('/');
};

const sanitizeAttachmentSegment = (value: string, fallback: string): string => {
  const sanitized = value.replace(/[^A-Za-z0-9._-]/g, '_');
  return sanitized.length > 0 ? sanitized : fallback;
};

interface AttachmentDownloadDescriptor {
  issueKey: string;
  filename: string;
  url?: string;
  authHeader?: string;
  expectedSha256?: string;
}

interface AttachmentDownloadOutcome {
  descriptor: AttachmentDownloadDescriptor;
  absolutePath?: string;
  relativePath?: string;
  sha256?: string;
  bytes?: number;
}

const ATTACHMENT_DOWNLOAD_CONCURRENCY = 4;

const streamConnectorAttachments = async (
  workspaceDir: string,
  connectorKey: string,
  descriptors: AttachmentDownloadDescriptor[],
): Promise<{ results: AttachmentDownloadOutcome[]; warnings: string[] }> => {
  if (descriptors.length === 0) {
    return { results: [], warnings: [] };
  }

  const baseDir = path.join(workspaceDir, 'attachments', sanitizeAttachmentSegment(connectorKey, connectorKey));
  await ensureDirectory(baseDir);

  const warnings: string[] = [];
  const results: AttachmentDownloadOutcome[] = new Array(descriptors.length);

  const downloadSingle = async (
    descriptor: AttachmentDownloadDescriptor,
    index: number,
  ): Promise<void> => {
    if (!descriptor.url) {
      warnings.push(
        `${connectorKey} eki ${descriptor.issueKey}/${descriptor.filename} indirilemedi: URL eksik.`,
      );
      results[index] = { descriptor };
      return;
    }

    try {
      const parsed = new URL(descriptor.url);
      const client = parsed.protocol === 'http:' ? http : https;
      const headers: Record<string, string> = {};
      if (descriptor.authHeader) {
        headers.Authorization = descriptor.authHeader;
      }

      const attachmentDir = path.join(
        baseDir,
        sanitizeAttachmentSegment(descriptor.issueKey, 'issue'),
      );
      await ensureDirectory(attachmentDir);
      const sanitizedName = sanitizeAttachmentSegment(descriptor.filename, 'attachment');
      const targetPath = path.join(attachmentDir, sanitizedName);
      const tempPath = path.join(attachmentDir, `${randomUUID()}.tmp`);

      const downloadResult = await new Promise<AttachmentDownloadOutcome>((resolve) => {
        const request = client.request(parsed, { method: 'GET', headers }, (response) => {
          const status = response.statusCode ?? 0;
          if (status < 200 || status >= 300) {
            response.resume();
            warnings.push(
              `${connectorKey} eki ${descriptor.issueKey}/${descriptor.filename} indirilemedi: HTTP ${status}.`,
            );
            resolve({ descriptor });
            return;
          }

          const hash = createHash('sha256');
          let bytes = 0;
          response.on('data', (chunk: Buffer) => {
            hash.update(chunk);
            bytes += chunk.length;
          });

          const fileStream = fs.createWriteStream(tempPath);

          const finalize = async () => {
            try {
              await fsPromises.rename(tempPath, targetPath);
            } catch {
              await fsPromises.rm(tempPath, { force: true }).catch(() => undefined);
              throw new Error('Dosya taşınamadı.');
            }
          };

          streamPipeline(response, fileStream)
            .then(async () => {
              const sha256 = hash.digest('hex');
              await finalize();
              const relativePath = path
                .relative(workspaceDir, targetPath)
                .split(path.sep)
                .join('/');
              if (
                descriptor.expectedSha256 &&
                descriptor.expectedSha256.trim().length > 0 &&
                descriptor.expectedSha256.toLowerCase() !== sha256
              ) {
                warnings.push(
                  `${connectorKey} eki ${descriptor.issueKey}/${descriptor.filename} karması uyuşmadı. Beklenen: ${descriptor.expectedSha256.toLowerCase()}, hesaplanan: ${sha256}.`,
                );
              }
              resolve({ descriptor, absolutePath: targetPath, relativePath, sha256, bytes });
            })
            .catch(async (error) => {
              await fsPromises.rm(tempPath, { force: true }).catch(() => undefined);
              const reason = error instanceof Error ? error.message : String(error);
              warnings.push(
                `${connectorKey} eki ${descriptor.issueKey}/${descriptor.filename} indirilemedi: ${reason}.`,
              );
              resolve({ descriptor });
            });
        });

        request.on('error', (error) => {
          const reason = error instanceof Error ? error.message : String(error);
          warnings.push(
            `${connectorKey} eki ${descriptor.issueKey}/${descriptor.filename} indirilemedi: ${reason}.`,
          );
          fsPromises.rm(tempPath, { force: true }).catch(() => undefined);
          resolve({ descriptor });
        });

        request.end();
      });

      results[index] = downloadResult;
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      warnings.push(
        `${connectorKey} eki ${descriptor.issueKey}/${descriptor.filename} indirilemedi: ${reason}.`,
      );
      results[index] = { descriptor };
    }
  };

  let cursor = 0;
  const worker = async (): Promise<void> => {
    const current = cursor;
    cursor += 1;
    if (current >= descriptors.length) {
      return;
    }
    await downloadSingle(descriptors[current]!, current);
    await worker();
  };

  const workers: Promise<void>[] = [];
  const limit = Math.min(ATTACHMENT_DOWNLOAD_CONCURRENCY, descriptors.length);
  for (let index = 0; index < limit; index += 1) {
    workers.push(worker());
  }

  await Promise.all(workers);

  return { results, warnings };
};

const buildPolarionAuthHeader = (options: PolarionClientOptions | undefined): string | undefined => {
  if (!options) {
    return undefined;
  }
  if (options.token) {
    return `Bearer ${options.token}`;
  }
  if (options.username && options.password) {
    const credentials = Buffer.from(`${options.username}:${options.password}`).toString('base64');
    return `Basic ${credentials}`;
  }
  return undefined;
};

const buildJiraCloudAuthHeader = (options: JiraArtifactsOptions): string | undefined => {
  if (options.email && options.authToken) {
    const credentials = Buffer.from(`${options.email}:${options.authToken}`).toString('base64');
    return `Basic ${credentials}`;
  }
  if (options.authToken) {
    return `Bearer ${options.authToken}`;
  }
  return undefined;
};

const buildAzureDevOpsAuthHeader = (token: string | undefined): string | undefined => {
  if (!token) {
    return undefined;
  }
  const encoded = Buffer.from(`:${token}`).toString('base64');
  return `Basic ${encoded}`;
};

const computeEvidenceHash = async (filePath: string): Promise<string | undefined> => {
  if (isRemotePath(filePath)) {
    return undefined;
  }

  const absolutePath = path.resolve(filePath);
  const stats = await fsPromises.stat(absolutePath);
  if (!stats.isFile()) {
    return undefined;
  }

  return new Promise<string>((resolve, reject) => {
    const hash = createHash('sha256');
    const stream = fs.createReadStream(absolutePath);

    stream.on('error', reject);
    hash.on('error', reject);

    stream.on('data', (chunk) => {
      hash.update(chunk);
    });

    stream.on('end', () => {
      resolve(hash.digest('hex'));
    });
  });
};

interface EvidenceIndependenceConfig {
  sources: Set<EvidenceSource>;
  artifactTypes: Set<ObjectiveArtifactType>;
  artifacts: Set<string>;
}

const isEvidenceSourceValue = (value: string): value is EvidenceSource =>
  (evidenceSources as readonly string[]).includes(value as EvidenceSource);

const isObjectiveArtifactTypeValue = (value: string): value is ObjectiveArtifactType =>
  (objectiveArtifactTypes as readonly string[]).includes(value as ObjectiveArtifactType);

const parseIndependentSources = (
  sources: Array<EvidenceSource | string> | undefined,
): Set<EvidenceSource> => {
  const result = new Set<EvidenceSource>();
  if (!sources) {
    return result;
  }

  sources.forEach((entry) => {
    if (typeof entry !== 'string') {
      throw new Error('--independent-source değerleri kaynak adı olmalıdır.');
    }
    const normalized = entry.trim();
    if (!normalized) {
      return;
    }
    if (!isEvidenceSourceValue(normalized)) {
      throw new Error(
        `Geçersiz bağımsız kaynak: ${entry}. Desteklenen değerler: ${evidenceSources.join(', ')}.`,
      );
    }
    result.add(normalized as EvidenceSource);
  });

  return result;
};

const parseIndependentArtifacts = (
  entries: string[] | undefined,
): { artifactTypes: Set<ObjectiveArtifactType>; artifacts: Set<string> } => {
  const artifactTypes = new Set<ObjectiveArtifactType>();
  const artifacts = new Set<string>();

  if (!entries) {
    return { artifactTypes, artifacts };
  }

  entries.forEach((entry) => {
    if (typeof entry !== 'string') {
      throw new Error('--independent-artifact değerleri artifact[=path] biçiminde olmalıdır.');
    }
    const trimmed = entry.trim();
    if (!trimmed) {
      return;
    }
    const [rawArtifact, ...rest] = trimmed.split('=');
    const artifactName = rawArtifact.trim();
    if (!artifactName) {
      throw new Error(
        `Geçersiz --independent-artifact değeri: ${entry}. Beklenen biçim artifact[=path].`,
      );
    }
    if (!isObjectiveArtifactTypeValue(artifactName)) {
      throw new Error(
        `Desteklenmeyen artefakt türü: ${artifactName}. Desteklenen değerler: ${objectiveArtifactTypes.join(', ')}.`,
      );
    }
    const typedArtifact = artifactName as ObjectiveArtifactType;
    if (rest.length === 0) {
      artifactTypes.add(typedArtifact);
      return;
    }
    const rawPath = rest.join('=').trim();
    if (!rawPath) {
      throw new Error(`--independent-artifact ${artifactName} için dosya yolu belirtilmelidir.`);
    }
    const normalizedPath = normalizeRelativePath(rawPath);
    artifacts.add(`${typedArtifact}:${normalizedPath}`);
  });

  return { artifactTypes, artifacts };
};

const buildEvidenceIndependenceConfig = (
  options: Pick<ImportOptions, 'independentSources' | 'independentArtifacts'>,
): EvidenceIndependenceConfig => {
  const sources = parseIndependentSources(options.independentSources);
  const { artifactTypes, artifacts } = parseIndependentArtifacts(options.independentArtifacts);
  return { sources, artifactTypes, artifacts };
};

const staticAnalysisTools = ['polyspace', 'ldra', 'vectorcast', 'simulink'] as const;
type StaticAnalysisTool = (typeof staticAnalysisTools)[number];

type ManualArtifactImports = Partial<Record<ObjectiveArtifactType, string[]>>;

type JenkinsCoverageArtifactSummary = Pick<
  JenkinsCoverageArtifactMetadata,
  'type' | 'path' | 'sha256'
> & {
  localPath: string;
  statements: number;
  branches?: number;
  functions?: number;
  mcdc?: number;
  tests?: number;
};

interface ParsedImportArguments {
  adapters: Partial<Record<StaticAnalysisTool, string>>;
  manualArtifacts: ManualArtifactImports;
}

const coerceOptionalString = (value: unknown): string | undefined => {
  if (typeof value !== 'string') {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
};

const coerceOptionalNumber = (value: unknown): number | undefined => {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value === 'number') {
    return Number.isFinite(value) ? value : undefined;
  }
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) {
      return undefined;
    }
    const numeric = Number(trimmed);
    return Number.isFinite(numeric) ? numeric : undefined;
  }
  return undefined;
};

const parsePositiveInteger = (value: string, optionLabel: string): number => {
  const numeric = Number(value.trim());
  if (!Number.isFinite(numeric) || numeric <= 0) {
    throw new Error(`${optionLabel} pozitif bir sayı olmalıdır.`);
  }
  return Math.floor(numeric);
};

const parseJenkinsBuildIdentifier = (value: unknown): string | number | undefined => {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) {
      return undefined;
    }
    const numeric = Number.parseInt(trimmed, 10);
    if (!Number.isNaN(numeric) && String(numeric) === trimmed) {
      return numeric;
    }
    return trimmed;
  }
  return undefined;
};

const parseJenkinsCoverageArtifacts = (
  value: unknown,
): JenkinsCoverageArtifactOptions[] | undefined => {
  if (!value) {
    return undefined;
  }

  const entries = Array.isArray(value) ? value : [value];
  const artifacts: JenkinsCoverageArtifactOptions[] = [];

  entries.forEach((entry) => {
    if (typeof entry !== 'string') {
      throw new Error('--jenkins-coverage-artifact değeri metin olarak verilmelidir.');
    }

    const trimmed = entry.trim();
    if (!trimmed) {
      return;
    }

    let type: JenkinsCoverageArtifactOptions['type'] | undefined;
    let artifactPath: string | undefined;
    let maxBytes: number | undefined;

    const parseKeyValueEntry = (segment: string): void => {
      const [rawKey, ...rest] = segment.split('=');
      if (!rawKey || rest.length === 0) {
        throw new Error(
          `--jenkins-coverage-artifact tanımı "type=lcov,path=coverage.info" biçiminde olmalıdır (${segment}).`,
        );
      }
      const key = rawKey.trim().toLowerCase();
      const rawValue = rest.join('=').trim();
      if (!rawValue) {
        throw new Error(`--jenkins-coverage-artifact için ${key} değeri boş olamaz.`);
      }
      if (key === 'type') {
        const normalized = rawValue.toLowerCase();
        if (normalized !== 'lcov' && normalized !== 'cobertura') {
          throw new Error(
            `--jenkins-coverage-artifact type değeri lcov veya cobertura olmalıdır (${rawValue}).`,
          );
        }
        type = normalized;
        return;
      }
      if (key === 'path') {
        artifactPath = rawValue;
        return;
      }
      if (key === 'maxbytes' || key === 'max' || key === 'limit') {
        maxBytes = parsePositiveInteger(rawValue, '--jenkins-coverage-artifact maxBytes');
        return;
      }
      throw new Error(`Bilinmeyen Jenkins coverage artefakt anahtarı: ${rawKey}.`);
    };

    if (trimmed.includes('=')) {
      trimmed
        .split(',')
        .map((segment) => segment.trim())
        .filter((segment) => segment.length > 0)
        .forEach(parseKeyValueEntry);
    } else {
      const [rawType, rawRest] = trimmed.split(':', 2);
      if (!rawRest) {
        throw new Error(
          '--jenkins-coverage-artifact değeri "lcov:coverage/lcov.info" biçiminde olmalıdır.',
        );
      }
      const normalizedType = rawType.trim().toLowerCase();
      if (normalizedType === 'lcov' || normalizedType === 'cobertura') {
        type = normalizedType;
      } else {
        throw new Error(
          `--jenkins-coverage-artifact için geçersiz tür: ${rawType}. (lcov | cobertura) bekleniyor.)`,
        );
      }
      const atIndex = rawRest.lastIndexOf('@');
      if (atIndex >= 0) {
        const pathPart = rawRest.slice(0, atIndex).trim();
        const limitPart = rawRest.slice(atIndex + 1).trim();
        if (!pathPart) {
          throw new Error('--jenkins-coverage-artifact için dosya yolu belirtilmelidir.');
        }
        artifactPath = pathPart;
        if (limitPart) {
          maxBytes = parsePositiveInteger(limitPart, '--jenkins-coverage-artifact maxBytes');
        }
      } else {
        artifactPath = rawRest.trim();
      }
    }

    if (!type) {
      throw new Error('--jenkins-coverage-artifact için type=lcov|cobertura belirtilmelidir.');
    }
    if (!artifactPath) {
      throw new Error('--jenkins-coverage-artifact için path değeri zorunludur.');
    }

    const artifact: JenkinsCoverageArtifactOptions = { type, path: artifactPath };
    if (maxBytes !== undefined) {
      artifact.maxBytes = maxBytes;
    }
    artifacts.push(artifact);
  });

  return artifacts.length > 0 ? artifacts : undefined;
};

export interface ExternalBuildRecord {
  provider: 'polarion' | 'jenkins' | 'azureDevOps';
  id: string;
  name?: string;
  url?: string;
  status?: string;
  branch?: string;
  revision?: string;
  startedAt?: string;
  completedAt?: string;
}

interface ExternalSourceMetadata {
  polarion?: {
    baseUrl: string;
    projectId: string;
    requirements: number;
    tests: number;
    builds: number;
    relationships: number;
    attachments: {
      total: number;
      totalBytes: number;
      items: Array<{
        id?: string;
        workItemId?: string;
        title?: string;
        description?: string;
        filename: string;
        contentType?: string;
        path?: string;
        sha256?: string;
        bytes?: number;
      }>;
    } | null;
  };
  doorsClassic?: {
    modules: number;
    requirements: number;
    traces: number;
  };
  doorsNext?: {
    baseUrl: string;
    projectArea: string;
    requirements: number;
    tests: number;
    designs: number;
    relationships: number;
    etagCacheSize: number;
    etagCache?: Record<string, string>;
    attachments: {
      total: number;
      totalBytes: number;
      items: Array<{
        id?: string;
        artifactId: string;
        title?: string;
        filename: string;
        contentType?: string;
        path?: string;
        sha256?: string;
        bytes?: number;
      }>;
    } | null;
  };
  jama?: {
    baseUrl: string;
    projectId: string;
    requirements: number;
    tests: number;
    traceLinks: number;
    attachments: {
      total: number;
      totalBytes: number;
      items: Array<{
        itemId: string;
        itemType?: string;
        filename?: string;
        url?: string;
        size?: number;
        createdAt?: string;
        path?: string;
        sha256?: string;
        bytes?: number;
      }>;
    } | null;
  };
  jenkins?: {
    baseUrl: string;
    job: string;
    build?: string;
    tests: number;
    builds: number;
    coverageArtifacts?: {
      total: number;
      items: JenkinsCoverageArtifactSummary[];
    };
  };
  jiraCloud?: {
    baseUrl: string;
    projectKey: string;
    requirements: number;
    tests: number;
    traces: number;
    attachments: {
      total: number;
      totalBytes: number;
      items: Array<{
        issueKey: string;
        filename: string;
        url?: string;
        size?: number;
        createdAt?: string;
        path?: string;
        sha256?: string;
        bytes?: number;
      }>;
    } | null;
    requirementsJql?: string;
    testsJql?: string;
  };
  azureDevOps?: {
    baseUrl: string;
    organization: string;
    project: string;
    requirements: number;
    tests: number;
    builds: number;
    traces: number;
    attachments: {
      total: number;
      totalBytes: number;
      items: Array<{
        id: string;
        artifactId: string;
        artifactType: string;
        filename: string;
        url?: string;
        contentType?: string;
        path?: string;
        sha256?: string;
        bytes?: number;
      }>;
    } | null;
  };
  jira?: {
    requirements?: number;
    problemReports?: number;
    openProblems?: number;
    reports?: Array<{ file: string; total: number; open: number }>;
  };
  parasoft?: {
    reports: Array<{
      file: string;
      tests: number;
      findings: number;
      coverageFiles: number;
      fileHashes: number;
      warnings: string[];
    }>;
    totalTests: number;
    totalFindings: number;
    coverageFiles: number;
    fileHashes: number;
  };
}

const parseImportArguments = (value: unknown): ParsedImportArguments => {
  if (!value) {
    return { adapters: {}, manualArtifacts: {} };
  }

  const entries = Array.isArray(value) ? value : [value];
  const adapters: Partial<Record<StaticAnalysisTool, string>> = {};
  const manualArtifacts: ManualArtifactImports = {};

  entries.forEach((entry) => {
    if (typeof entry !== 'string') {
      throw new Error('--import seçenekleri anahtar=dosya yolu biçiminde olmalıdır.');
    }
    const trimmed = entry.trim();
    if (!trimmed) {
      return;
    }
    const [rawKey, ...rest] = trimmed.split('=');
    const key = rawKey.trim();
    if (!key || rest.length === 0) {
      throw new Error(`Geçersiz --import değeri: ${entry}. Beklenen biçim anahtar=dosya.`);
    }
    const filePath = rest.join('=').trim();
    if (!filePath) {
      throw new Error(`--import ${key} için dosya yolu belirtilmelidir.`);
    }

      const normalizedKey = key.toLowerCase();
      if ((staticAnalysisTools as readonly string[]).includes(normalizedKey)) {
        adapters[normalizedKey as StaticAnalysisTool] = filePath;
        return;
      }

      if (!isObjectiveArtifactTypeValue(normalizedKey)) {
        throw new Error(
          `Desteklenmeyen --import anahtarı: ${key}. Geçerli değerler: ${[...staticAnalysisTools, ...objectiveArtifactTypes]
            .map((item) => item)
            .join(', ')}.`,
        );
      }

    const artifactKey = normalizedKey as ObjectiveArtifactType;
    const existing = manualArtifacts[artifactKey] ?? [];
    manualArtifacts[artifactKey] = [...existing, filePath];
  });

  return { adapters, manualArtifacts };
};

const parseStringArrayOption = (
  value: unknown,
  optionName: string,
): string[] | undefined => {
  if (value === undefined || value === null) {
    return undefined;
  }

  const entries = Array.isArray(value) ? value : [value];
  const result: string[] = [];

  entries.forEach((entry) => {
    if (typeof entry !== 'string') {
      throw new Error(`${optionName} değerleri dosya yolu olmalıdır.`);
    }
    const trimmed = entry.trim();
    if (trimmed.length > 0) {
      result.push(trimmed);
    }
  });

  return result.length > 0 ? result : undefined;
};

const normalizeIssueType = (value: string | undefined): string | undefined => {
  if (!value) {
    return undefined;
  }
  return value.trim().toLowerCase().replace(/[\s/_-]+/g, '');
};

const problemReportTypes = new Set([
  'bug',
  'defect',
  'problemreport',
  'issue',
  'anomaly',
  'failure',
  'nonconformance',
  'pr',
  'nc',
]);

const isProblemReportIssue = (issueType: string | undefined): boolean => {
  const normalized = normalizeIssueType(issueType);
  if (!normalized) {
    return false;
  }
  return problemReportTypes.has(normalized);
};

const isClosedProblemStatus = (status: string | undefined): boolean => {
  if (!status) {
    return false;
  }
  const normalized = status.trim().toLowerCase();
  return /\b(done|closed|resolved|fixed|complete|completed|verified|accepted|released|cancelled|canceled)\b/u.test(
    normalized,
  );
};

const buildPolarionOptions = (
  argv: yargs.ArgumentsCamelCase<unknown>,
): PolarionClientOptions | undefined => {
  const raw = argv as Record<string, unknown>;
  const baseUrl = coerceOptionalString(raw.polarionUrl);
  const projectId = coerceOptionalString(raw.polarionProject);

  if (!baseUrl || !projectId) {
    return undefined;
  }

  return {
    baseUrl,
    projectId,
    username: coerceOptionalString(raw.polarionUsername),
    password: coerceOptionalString(raw.polarionPassword),
    token: coerceOptionalString(raw.polarionToken),
    requirementsEndpoint: coerceOptionalString(raw.polarionRequirementsEndpoint),
    testRunsEndpoint: coerceOptionalString(raw.polarionTestsEndpoint),
    buildsEndpoint: coerceOptionalString(raw.polarionBuildsEndpoint),
  };
};

const buildDoorsNextOptions = (
  argv: yargs.ArgumentsCamelCase<unknown>,
): DoorsNextClientOptions | undefined => {
  const raw = argv as Record<string, unknown>;
  const baseUrl = coerceOptionalString(raw.doorsUrl);
  const projectArea = coerceOptionalString(raw.doorsProject);

  if (!baseUrl || !projectArea) {
    return undefined;
  }

  const options: DoorsNextClientOptions = { baseUrl, projectArea };
  const username = coerceOptionalString(raw.doorsUsername);
  const password = coerceOptionalString(raw.doorsPassword);
  const token = coerceOptionalString(raw.doorsToken);

  if (username) {
    options.username = username;
  }
  if (password) {
    options.password = password;
  }
  if (token) {
    options.accessToken = token;
  }

  const pageSize = raw.doorsPageSize;
  if (typeof pageSize === 'number' && Number.isFinite(pageSize) && pageSize > 0) {
    options.pageSize = pageSize;
  }

  const maxPages = raw.doorsMaxPages;
  if (typeof maxPages === 'number' && Number.isFinite(maxPages) && maxPages > 0) {
    options.maxPages = maxPages;
  }

  const timeout = raw.doorsTimeout;
  if (typeof timeout === 'number' && Number.isFinite(timeout) && timeout > 0) {
    options.timeoutMs = timeout;
  }

  return options;
};

const buildJamaOptions = (
  argv: yargs.ArgumentsCamelCase<unknown>,
): JamaClientOptions | undefined => {
  const raw = argv as Record<string, unknown>;
  const baseUrl = coerceOptionalString(raw.jamaUrl);
  const projectId = coerceOptionalString(raw.jamaProject);
  const token = coerceOptionalString(raw.jamaToken);

  if (!baseUrl || !projectId || !token) {
    return undefined;
  }

  const options: JamaClientOptions = {
    baseUrl,
    projectId,
    token,
  };

  const parsePositiveNumber = (value: unknown, optionName: string): number | undefined => {
    if (value === undefined || value === null) {
      return undefined;
    }
    const candidate =
      typeof value === 'number'
        ? value
        : typeof value === 'string'
          ? Number.parseFloat(value)
          : Number.NaN;
    if (!Number.isFinite(candidate) || candidate <= 0) {
      throw new Error(`${optionName} pozitif bir sayı olmalıdır.`);
    }
    return candidate;
  };

  const pageSize = parsePositiveNumber(raw.jamaPageSize, '--jama-page-size');
  if (pageSize !== undefined) {
    options.pageSize = pageSize;
  }

  const maxPages = parsePositiveNumber(raw.jamaMaxPages, '--jama-max-pages');
  if (maxPages !== undefined) {
    options.maxPages = maxPages;
  }

  const timeout = parsePositiveNumber(raw.jamaTimeout, '--jama-timeout');
  if (timeout !== undefined) {
    options.timeoutMs = timeout;
  }

  const parseRateLimitDelays = (value: unknown): number[] | undefined => {
    if (value === undefined || value === null) {
      return undefined;
    }
    const entries = Array.isArray(value)
      ? value
      : typeof value === 'string'
        ? value
            .split(',')
            .map((entry) => entry.trim())
            .filter((entry) => entry.length > 0)
        : [value];
    if (entries.length === 0) {
      return [];
    }
    const delays = entries.map((entry) => {
      const candidate =
        typeof entry === 'number'
          ? entry
          : typeof entry === 'string'
            ? Number.parseFloat(entry)
            : Number.NaN;
      if (!Number.isFinite(candidate) || candidate < 0) {
        throw new Error('--jama-rate-limit-delays değerleri sıfır veya pozitif sayı olmalıdır.');
      }
      return candidate;
    });
    return delays;
  };

  const rateLimitDelays = parseRateLimitDelays(raw.jamaRateLimitDelays);
  if (rateLimitDelays !== undefined) {
    options.rateLimitDelaysMs = rateLimitDelays;
  }

  const requirementsEndpoint = coerceOptionalString(raw.jamaRequirementsEndpoint);
  if (requirementsEndpoint) {
    options.requirementsEndpoint = requirementsEndpoint;
  }

  const testsEndpoint = coerceOptionalString(raw.jamaTestsEndpoint);
  if (testsEndpoint) {
    options.testCasesEndpoint = testsEndpoint;
  }

  const relationshipsEndpoint = coerceOptionalString(raw.jamaRelationshipsEndpoint);
  if (relationshipsEndpoint) {
    options.relationshipsEndpoint = relationshipsEndpoint;
  }

  return options;
};

const buildAzureDevOpsOptions = (
  argv: yargs.ArgumentsCamelCase<unknown>,
): AzureDevOpsClientOptions | undefined => {
  const raw = argv as Record<string, unknown>;
  const baseUrl = coerceOptionalString(raw.azureDevopsUrl);
  const organization = coerceOptionalString(raw.azureDevopsOrganization);
  const project = coerceOptionalString(raw.azureDevopsProject);
  const pat = coerceOptionalString(raw.azureDevopsPat);

  if (!baseUrl || !organization || !project || !pat) {
    return undefined;
  }

  const options: AzureDevOpsClientOptions = {
    baseUrl,
    organization,
    project,
    personalAccessToken: pat,
  };

  const requirementsEndpoint = coerceOptionalString(raw.azureDevopsRequirementsEndpoint);
  if (requirementsEndpoint) {
    options.requirementsEndpoint = requirementsEndpoint;
  }

  const testsEndpoint = coerceOptionalString(raw.azureDevopsTestsEndpoint);
  if (testsEndpoint) {
    options.testsEndpoint = testsEndpoint;
  }

  const buildsEndpoint = coerceOptionalString(raw.azureDevopsBuildsEndpoint);
  if (buildsEndpoint) {
    options.buildsEndpoint = buildsEndpoint;
  }

  const attachmentsEndpoint = coerceOptionalString(raw.azureDevopsAttachmentsEndpoint);
  if (attachmentsEndpoint) {
    options.attachmentsEndpoint = attachmentsEndpoint;
  }

  const timeout = coerceOptionalNumber(raw.azureDevopsTimeout);
  if (timeout && timeout > 0) {
    options.timeoutMs = timeout;
  }

  const pageSize = coerceOptionalNumber(raw.azureDevopsPageSize);
  if (pageSize && pageSize > 0) {
    options.pageSize = Math.trunc(pageSize);
  }

  const maxPages = coerceOptionalNumber(raw.azureDevopsMaxPages);
  if (maxPages && maxPages > 0) {
    options.maxPages = Math.trunc(maxPages);
  }

  const requirementsQuery = coerceOptionalString(raw.azureDevopsRequirementsQuery);
  if (requirementsQuery) {
    options.requirementsQuery = requirementsQuery;
  }

  const testOutcome = coerceOptionalString(raw.azureDevopsTestOutcome);
  if (testOutcome) {
    options.testOutcomeFilter = testOutcome;
  }

  const testPlanId = coerceOptionalString(raw.azureDevopsTestPlan);
  if (testPlanId) {
    options.testPlanId = testPlanId;
  }

  const testSuiteId = coerceOptionalString(raw.azureDevopsTestSuite);
  if (testSuiteId) {
    options.testSuiteId = testSuiteId;
  }

  const testRunId = coerceOptionalString(raw.azureDevopsTestRun);
  if (testRunId) {
    options.testRunId = testRunId;
  }

  const buildDefinitionId = coerceOptionalString(raw.azureDevopsBuildDefinition);
  if (buildDefinitionId) {
    options.buildDefinitionId = buildDefinitionId;
  }

  const maxAttachmentBytes = coerceOptionalNumber(raw.azureDevopsMaxAttachmentBytes);
  if (maxAttachmentBytes && maxAttachmentBytes > 0) {
    options.maxAttachmentBytes = Math.trunc(maxAttachmentBytes);
  }

  return options;
};

const buildJenkinsOptions = (
  argv: yargs.ArgumentsCamelCase<unknown>,
): JenkinsClientOptions | undefined => {
  const raw = argv as Record<string, unknown>;
  const baseUrl = coerceOptionalString(raw.jenkinsUrl);
  const job = coerceOptionalString(raw.jenkinsJob);

  if (!baseUrl || !job) {
    return undefined;
  }

  const options: JenkinsClientOptions = {
    baseUrl,
    job,
    build: parseJenkinsBuildIdentifier(raw.jenkinsBuild),
    username: coerceOptionalString(raw.jenkinsUsername),
    password: coerceOptionalString(raw.jenkinsPassword),
    token: coerceOptionalString(raw.jenkinsToken),
    buildEndpoint: coerceOptionalString(raw.jenkinsBuildEndpoint),
    testReportEndpoint: coerceOptionalString(raw.jenkinsTestsEndpoint),
  };

  const artifactsDir = coerceOptionalString(raw.jenkinsArtifactsDir);
  if (artifactsDir) {
    options.artifactsDir = artifactsDir;
  }

  const coverageArtifacts = parseJenkinsCoverageArtifacts(raw.jenkinsCoverageArtifact);
  if (coverageArtifacts) {
    options.coverageArtifacts = coverageArtifacts;
  }

  const coverageLimit = coerceOptionalNumber(raw.jenkinsCoverageMaxBytes);
  if (coverageLimit !== undefined) {
    if (!Number.isFinite(coverageLimit) || coverageLimit <= 0) {
      throw new Error('--jenkins-coverage-max-bytes pozitif bir sayı olmalıdır.');
    }
    options.maxCoverageArtifactBytes = Math.floor(coverageLimit);
  }

  return options;
};

const buildJiraCloudOptions = (
  argv: yargs.ArgumentsCamelCase<unknown>,
): JiraArtifactsOptions | undefined => {
  const raw = argv as Record<string, unknown>;
  const baseUrl = coerceOptionalString(raw.jiraApiUrl);
  const projectKey = coerceOptionalString(raw.jiraApiProject);

  if (!baseUrl || !projectKey) {
    return undefined;
  }

  const options: JiraArtifactsOptions = { baseUrl, projectKey };
  const email = coerceOptionalString(raw.jiraApiEmail);
  const token = coerceOptionalString(raw.jiraApiToken);
  const requirementsJql = coerceOptionalString(raw.jiraApiRequirementsJql);
  const testsJql = coerceOptionalString(raw.jiraApiTestsJql);

  if (email) {
    options.email = email;
  }
  if (token) {
    options.authToken = token;
  }
  if (requirementsJql) {
    options.requirementsJql = requirementsJql;
  }
  if (testsJql) {
    options.testsJql = testsJql;
  }

  const pageSize = raw.jiraApiPageSize;
  if (typeof pageSize === 'number' && Number.isFinite(pageSize) && pageSize > 0) {
    options.pageSize = Math.trunc(pageSize);
  }

  const maxPages = raw.jiraApiMaxPages;
  if (typeof maxPages === 'number' && Number.isFinite(maxPages) && maxPages > 0) {
    options.maxPages = Math.trunc(maxPages);
  }

  const timeout = raw.jiraApiTimeout;
  if (typeof timeout === 'number' && Number.isFinite(timeout) && timeout > 0) {
    options.timeoutMs = timeout;
  }

  return options;
};

const parseContentDispositionFileName = (value: string | string[] | undefined): string | undefined => {
  if (!value) {
    return undefined;
  }
  const header = Array.isArray(value) ? value[0] : value;
  const utf8Match = header.match(/filename\*=UTF-8''([^;]+)/i);
  if (utf8Match && utf8Match[1]) {
    try {
      return decodeURIComponent(utf8Match[1]);
    } catch {
      return utf8Match[1];
    }
  }
  const quotedMatch = header.match(/filename="([^";]+)"/i);
  if (quotedMatch && quotedMatch[1]) {
    return quotedMatch[1];
  }
  const bareMatch = header.match(/filename=([^;]+)/i);
  if (bareMatch && bareMatch[1]) {
    return bareMatch[1].replace(/"/g, '');
  }
  return undefined;
};

const sanitizeDownloadFileName = (fileName: string, fallback: string): string => {
  const base = path.basename(fileName || fallback);
  const normalized = base.replace(/[^a-zA-Z0-9._-]/g, '_');
  return normalized || fallback;
};

interface DownloadPackageOptions {
  baseUrl: string;
  token: string;
  packageId: string;
  outputDir: string;
  allowInsecureHttp?: boolean;
  httpGet?: typeof http.get;
  httpsGet?: typeof https.get;
}

interface DownloadResult {
  archivePath: string;
  manifestPath: string;
}

interface FreezeOptions {
  baseUrl: string;
  token: string;
  allowInsecureHttp?: boolean;
  httpRequest?: typeof http.request;
  httpsRequest?: typeof https.request;
}

interface FreezeResult {
  version: SnapshotVersion;
  statusCode: number;
}

const HTTP_REQUEST_TIMEOUT_MS = 30_000;

const requestStream = (
  targetUrl: string,
  headers: Record<string, string>,
  options: {
    allowInsecureHttp?: boolean;
    httpGet?: typeof http.get;
    httpsGet?: typeof https.get;
  } = {},
): Promise<http.IncomingMessage> => {
  const {
    allowInsecureHttp = false,
    httpGet = http.get,
    httpsGet = https.get,
  } = options;

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(targetUrl);
  } catch (error) {
    return Promise.reject(
      new Error(
        `Geçersiz URL: ${targetUrl}. Lütfen API taban adresini kontrol edin. ${(error as Error).message}`,
      ),
    );
  }

  if (parsedUrl.protocol !== 'https:' && parsedUrl.protocol !== 'http:') {
    return Promise.reject(new Error(`Desteklenmeyen protokol: ${parsedUrl.protocol}`));
  }

  if (parsedUrl.protocol !== 'https:' && !allowInsecureHttp) {
    return Promise.reject(
      new Error(
        `İndirilen URL güvenli değil (${parsedUrl.toString()}). HTTP istekleri varsayılan olarak engellenir; ` +
          '`--allow-insecure-http` bayrağı ile HTTP kullanımını bilinçli olarak etkinleştirin.',
      ),
    );
  }

  return new Promise((resolve, reject) => {
    const clientGet = parsedUrl.protocol === 'https:' ? httpsGet : httpGet;
    const request = clientGet(parsedUrl, { headers }, (response) => {
      const { statusCode } = response;
      if (statusCode && statusCode >= 200 && statusCode < 300) {
        resolve(response);
        return;
      }
      const chunks: Buffer[] = [];
      response.on('data', (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
      response.on('end', () => {
        const message = chunks.length > 0 ? Buffer.concat(chunks).toString('utf8') : response.statusMessage;
        reject(new Error(`HTTP ${statusCode ?? 0}: ${message ?? translateCli('errors.server.unexpected')}`));
      });
    });
    request.setTimeout(HTTP_REQUEST_TIMEOUT_MS, () => {
      request.destroy(
        new Error(
          `Sunucudan yanıt alınamadı: ${parsedUrl.toString()} isteği ${HTTP_REQUEST_TIMEOUT_MS}ms içinde tamamlanmadı.`,
        ),
      );
    });
    request.on('error', reject);
  });
};

const requestJson = async <T>(
  targetUrl: string,
  body: unknown,
  options: {
    token: string;
    allowInsecureHttp?: boolean;
    httpRequest?: typeof http.request;
    httpsRequest?: typeof https.request;
    method?: 'POST' | 'PUT' | 'PATCH';
  },
): Promise<{ statusCode: number; body: T } | never> => {
  const { token, allowInsecureHttp = false, httpRequest = http.request, httpsRequest = https.request } = options;
  const method = options.method ?? 'POST';

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(targetUrl);
  } catch (error) {
    throw new Error(
      `Geçersiz URL: ${targetUrl}. Lütfen API taban adresini kontrol edin. ${(error as Error).message}`,
    );
  }

  if (parsedUrl.protocol !== 'https:' && parsedUrl.protocol !== 'http:') {
    throw new Error(`Desteklenmeyen protokol: ${parsedUrl.protocol}`);
  }

  if (parsedUrl.protocol !== 'https:' && !allowInsecureHttp) {
    throw new Error(
      `İstek URL'si güvenli değil (${parsedUrl.toString()}). HTTP istekleri varsayılan olarak engellenir; ` +
        '`--allow-insecure-http` bayrağı ile HTTP kullanımını bilinçli olarak etkinleştirin.',
    );
  }

  const clientRequest = parsedUrl.protocol === 'https:' ? httpsRequest : httpRequest;
  const payload = body ? JSON.stringify(body) : '{}';

  return new Promise<{ statusCode: number; body: T }>((resolve, reject) => {
    const request = clientRequest(
      parsedUrl,
      {
        method,
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          Authorization: `Bearer ${token}`,
          'Content-Length': Buffer.byteLength(payload).toString(),
        },
      },
      (response) => {
        const { statusCode = 0 } = response;
        const chunks: Buffer[] = [];
        response.on('data', (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
        response.on('end', () => {
          const content = chunks.length > 0 ? Buffer.concat(chunks).toString('utf8') : '';
          if (statusCode >= 200 && statusCode < 300) {
            if (!content) {
              resolve({ statusCode, body: {} as T });
              return;
            }
            try {
              resolve({ statusCode, body: JSON.parse(content) as T });
            } catch (error) {
              reject(new Error(`Sunucudan dönen JSON parse edilemedi: ${(error as Error).message}`));
            }
            return;
          }
          const message = content || response.statusMessage || translateCli('errors.server.unexpected');
          reject(new Error(`HTTP ${statusCode}: ${message}`));
        });
      },
    );

    request.setTimeout(HTTP_REQUEST_TIMEOUT_MS, () => {
      request.destroy(
        new Error(
          `Sunucudan yanıt alınamadı: ${parsedUrl.toString()} isteği ${HTTP_REQUEST_TIMEOUT_MS}ms içinde tamamlanmadı.`,
        ),
      );
    });
    request.on('error', reject);
    request.write(payload);
    request.end();
  });
};

const writeStreamToFile = async (
  response: http.IncomingMessage,
  outputDir: string,
  fallbackName: string,
): Promise<string> => {
  const headerName = response.headers['content-disposition'];
  const suggested = parseContentDispositionFileName(headerName);
  const safeName = sanitizeDownloadFileName(suggested ?? fallbackName, fallbackName);
  const targetPath = path.join(outputDir, safeName);
  await ensureDirectory(outputDir);
  const fileStream = fs.createWriteStream(targetPath);
  await streamPipeline(response, fileStream);
  return targetPath;
};

export const downloadPackageArtifacts = async ({
  baseUrl,
  token,
  packageId,
  outputDir,
  allowInsecureHttp,
  httpGet,
  httpsGet,
}: DownloadPackageOptions): Promise<DownloadResult> => {
  await ensureDirectory(outputDir);
  const headers = { Authorization: `Bearer ${token}` };
  const archiveUrl = new URL(`/v1/packages/${packageId}/archive`, baseUrl).toString();
  const manifestUrl = new URL(`/v1/packages/${packageId}/manifest`, baseUrl).toString();

  const archiveResponse = await requestStream(archiveUrl, headers, {
    allowInsecureHttp,
    httpGet,
    httpsGet,
  });
  const archivePath = await writeStreamToFile(archiveResponse, outputDir, `soipack-${packageId}.zip`);

  const manifestResponse = await requestStream(manifestUrl, headers, {
    allowInsecureHttp,
    httpGet,
    httpsGet,
  });
  const manifestPath = await writeStreamToFile(manifestResponse, outputDir, `manifest-${packageId}.json`);

  return { archivePath, manifestPath };
};

export const runFreeze = async ({
  baseUrl,
  token,
  allowInsecureHttp,
  httpRequest,
  httpsRequest,
}: FreezeOptions): Promise<FreezeResult> => {
  const url = new URL('/v1/config/freeze', baseUrl).toString();
  const response = await requestJson<{ version: SnapshotVersion }>(
    url,
    {},
    {
      token,
      allowInsecureHttp,
      httpRequest,
      httpsRequest,
    },
  );
  return { version: response.body.version, statusCode: response.statusCode };
};

const parseCsvLine = (line: string): string[] => {
  const values: string[] = [];
  let current = '';
  let inQuotes = false;

  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    if (char === '"') {
      if (inQuotes && line[index + 1] === '"') {
        current += '"';
        index += 1;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }

    if (char === ',' && !inQuotes) {
      values.push(current.trim());
      current = '';
      continue;
    }

    current += char;
  }

  values.push(current.trim());

  return values.map((value) => {
    const trimmed = value.trim();
    if (trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length >= 2) {
      return trimmed.slice(1, -1).replace(/""/g, '"').trim();
    }
    return trimmed;
  });
};

interface TraceLinkImportResult {
  links: TraceLink[];
  warnings: string[];
}

const importTraceLinksCsv = async (filePath: string): Promise<TraceLinkImportResult> => {
  const warnings: string[] = [];
  const location = path.resolve(filePath);
  const content = await fsPromises.readFile(location, 'utf8');
  const rawLines = content.replace(/^\uFEFF/, '').split(/\r?\n/);
  const nonEmptyLines = rawLines.filter((line) => line.trim().length > 0);

  if (nonEmptyLines.length === 0) {
    warnings.push(`No rows found while parsing trace links CSV at ${location}.`);
    return { links: [], warnings };
  }

  const headerValues = parseCsvLine(nonEmptyLines[0]);
  const headerCount = headerValues.length;
  const headerIndex = new Map<string, number>();
  headerValues.forEach((header, index) => {
    headerIndex.set(header.trim().toLowerCase(), index);
  });

  const getCell = (row: string[], ...candidates: string[]): string | undefined => {
    for (const candidate of candidates) {
      const normalized = candidate.trim().toLowerCase();
      const index = headerIndex.get(normalized);
      if (index !== undefined && index < row.length) {
        const value = row[index]?.trim();
        if (value) {
          return value;
        }
      }
    }
    return undefined;
  };

  const links: TraceLink[] = [];

  nonEmptyLines.slice(1).forEach((line, rowIndex) => {
    const parsedRow = parseCsvLine(line);
    const normalizedRow = Array.from({ length: headerCount }, (_, index) => parsedRow[index] ?? '');

    const from = getCell(normalizedRow, 'from', 'requirement', 'requirementid', 'source');
    const to = getCell(normalizedRow, 'to', 'target', 'targetid', 'destination', 'test', 'code');
    const explicitType = getCell(normalizedRow, 'type', 'linktype', 'relation');
    const targetType = getCell(normalizedRow, 'targettype', 'kind', 'category');

    let resolvedType = explicitType?.toLowerCase() as TraceLink['type'] | undefined;
    if (!resolvedType && targetType) {
      const normalizedTargetType = targetType.toLowerCase();
      if (['code', 'source', 'implementation'].includes(normalizedTargetType)) {
        resolvedType = 'implements';
      } else if (['test', 'verification'].includes(normalizedTargetType)) {
        resolvedType = 'verifies';
      }
    }
    if (!resolvedType) {
      resolvedType = 'verifies';
    }

    const candidate = { from, to, type: resolvedType };
    const validation = traceLinkSchema.safeParse(candidate);
    if (!validation.success) {
      const messages = validation.error.issues.map((issue) => issue.message).join('; ');
      warnings.push(
        `Trace links CSV row ${rowIndex + 2} ignored (${location}): ${messages || 'invalid link definition.'}`,
      );
      return;
    }

    links.push(validation.data);
  });

  return { links, warnings };
};

interface DesignCsvImportResult {
  designs: DesignRecord[];
  warnings: string[];
}

const splitDelimitedValues = (value: string | undefined): string[] => {
  if (!value) {
    return [];
  }
  return value
    .split(/[;,|]/)
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
};

const importDesignCsv = async (filePath: string): Promise<DesignCsvImportResult> => {
  const warnings: string[] = [];
  const location = path.resolve(filePath);
  const content = await fsPromises.readFile(location, 'utf8');
  const rawLines = content.replace(/^\uFEFF/, '').split(/\r?\n/);
  const nonEmptyLines = rawLines.filter((line) => line.trim().length > 0);

  if (nonEmptyLines.length === 0) {
    warnings.push(`No rows found while parsing design CSV at ${location}.`);
    return { designs: [], warnings };
  }

  const headerValues = parseCsvLine(nonEmptyLines[0]);
  const headerCount = headerValues.length;
  const headerIndex = new Map<string, number>();
  headerValues.forEach((header, index) => {
    headerIndex.set(header.trim().toLowerCase(), index);
  });

  const getCell = (row: string[], ...candidates: string[]): string | undefined => {
    for (const candidate of candidates) {
      const normalized = candidate.trim().toLowerCase();
      const index = headerIndex.get(normalized);
      if (index !== undefined && index < row.length) {
        const value = row[index]?.trim();
        if (value) {
          return value;
        }
      }
    }
    return undefined;
  };

  const designs: DesignRecord[] = [];
  const seen = new Set<string>();

  nonEmptyLines.slice(1).forEach((line, rowIndex) => {
    const parsedRow = parseCsvLine(line);
    const normalizedRow = Array.from({ length: headerCount }, (_, index) => parsedRow[index] ?? '');
    const rowNumber = rowIndex + 2;
    const id = getCell(normalizedRow, 'design id', 'id');
    if (!id) {
      warnings.push(`Design CSV ${path.basename(location)} row ${rowNumber} missing design id.`);
      return;
    }
    if (seen.has(id)) {
      warnings.push(`Design CSV ${path.basename(location)} row ${rowNumber} duplicates design id ${id}.`);
      return;
    }

    const title = getCell(normalizedRow, 'title', 'name');
    if (!title) {
      warnings.push(`Design CSV ${path.basename(location)} row ${rowNumber} missing title.`);
      return;
    }

    const statusRaw = getCell(normalizedRow, 'status');
    let status: DesignStatus | undefined;
    if (statusRaw) {
      const normalizedStatus = statusRaw.trim().toLowerCase();
      const matched = designStatuses.find((value) => value === normalizedStatus);
      if (!matched) {
        warnings.push(
          `Design CSV ${path.basename(location)} row ${rowNumber} has unsupported status '${statusRaw}'.`,
        );
        return;
      }
      status = matched;
    }

    const description = getCell(normalizedRow, 'description', 'summary');
    const requirementRefs = splitDelimitedValues(
      getCell(
        normalizedRow,
        'requirement ids',
        'requirement id',
        'requirements',
        'req ids',
        'requirement references',
      ),
    );
    const codeRefs = splitDelimitedValues(
      getCell(normalizedRow, 'code paths', 'code refs', 'code', 'implementation paths', 'source paths'),
    );
    const tags = splitDelimitedValues(getCell(normalizedRow, 'tags', 'tag', 'labels'));

    try {
      const record = createDesignRecord(id, title, {
        description,
        status,
        tags,
        requirementRefs,
        codeRefs,
      });
      designs.push(record);
      seen.add(record.id);
    } catch (error) {
      if (error instanceof ZodError) {
        error.issues.forEach((issue) => {
          warnings.push(
            `Design CSV ${path.basename(location)} row ${rowNumber} invalid: ${issue.message}`,
          );
        });
      } else {
        const reason = error instanceof Error ? error.message : String(error);
        warnings.push(
          `Design CSV ${path.basename(location)} row ${rowNumber} could not be parsed: ${reason}`,
        );
      }
    }
  });

  return { designs, warnings };
};

const importTraceLinksJson = async (filePath: string): Promise<TraceLinkImportResult> => {
  const warnings: string[] = [];
  const location = path.resolve(filePath);
  const content = await fsPromises.readFile(location, 'utf8');

  let raw: unknown;
  try {
    raw = JSON.parse(content);
  } catch (error) {
    throw new Error(`Failed to parse trace links JSON at ${location}: ${(error as Error).message}`);
  }

  const records = Array.isArray(raw)
    ? raw
    : typeof raw === 'object' && raw !== null && Array.isArray((raw as { links?: unknown }).links)
      ? (raw as { links: unknown[] }).links
      : undefined;

  if (!records) {
    throw new Error(`Trace links JSON at ${location} must be an array or contain a "links" array.`);
  }

  const links: TraceLink[] = [];
  records.forEach((entry, index) => {
    const validation = traceLinkSchema.safeParse(entry);
    if (!validation.success) {
      const messages = validation.error.issues.map((issue) => issue.message).join('; ');
      warnings.push(
        `Trace links JSON entry ${index + 1} ignored (${location}): ${messages || 'invalid link definition.'}`,
      );
      return;
    }

    links.push(validation.data);
  });

  return { links, warnings };
};

const mergeTraceLinks = (
  ...groups: TraceLink[][]
): { links: TraceLink[]; duplicatesRemoved: number } => {
  const merged: TraceLink[] = [];
  groups.forEach((group) => {
    merged.push(...group);
  });
  const deduped = uniqueTraceLinks(merged);
  return { links: deduped, duplicatesRemoved: merged.length - deduped.length };
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

const mergeObjectiveLinks = (...lists: Array<string[] | undefined>): string[] | undefined => {
  const merged = new Set<string>();
  lists.forEach((list) => {
    list?.forEach((item) => merged.add(item));
  });
  return merged.size > 0 ? Array.from(merged).sort() : undefined;
};

const cloneStructuralMetric = <T extends { covered: number; total: number }>(
  metric: T | undefined,
): T | undefined => (metric ? { ...metric } : undefined);

const mergeStructuralCoverage = (
  existing: StructuralCoverageSummary | undefined,
  incoming: StructuralCoverageSummary,
): StructuralCoverageSummary => {
  if (!existing) {
    return {
      tool: incoming.tool,
      files: incoming.files.map((file) => ({
        path: file.path,
        stmt: { ...file.stmt },
        dec: cloneStructuralMetric(file.dec),
        mcdc: cloneStructuralMetric(file.mcdc),
      })),
      objectiveLinks: incoming.objectiveLinks ? [...incoming.objectiveLinks] : undefined,
    };
  }

  const files = new Map<string, StructuralCoverageSummary['files'][number]>();
  existing.files.forEach((file) => {
    files.set(file.path, {
      path: file.path,
      stmt: { ...file.stmt },
      dec: cloneStructuralMetric(file.dec),
      mcdc: cloneStructuralMetric(file.mcdc),
    });
  });
  incoming.files.forEach((file) => {
    const prior = files.get(file.path);
    const mergedFile = {
      path: file.path,
      stmt: file.stmt ? { ...file.stmt } : prior ? { ...prior.stmt } : { covered: 0, total: 0 },
      dec: cloneStructuralMetric(file.dec) ?? cloneStructuralMetric(prior?.dec),
      mcdc: cloneStructuralMetric(file.mcdc) ?? cloneStructuralMetric(prior?.mcdc),
    };
    files.set(file.path, mergedFile);
  });

  return {
    tool: incoming.tool,
    files: Array.from(files.values()),
    objectiveLinks: mergeObjectiveLinks(existing.objectiveLinks, incoming.objectiveLinks),
  };
};

const structuralCoverageHasMetric = (
  summary: StructuralCoverageSummary | undefined,
  metric: 'stmt' | 'dec' | 'mcdc',
): boolean => {
  if (!summary) {
    return false;
  }
  return summary.files.some((file) => {
    const metricValue = file[metric];
    return metricValue !== undefined && metricValue.total > 0;
  });
};

type CoverageMetricKey = 'statements' | 'branches' | 'functions' | 'mcdc';

const cloneCoverageMetric = (metric: CoverageMetric): CoverageMetric => ({
  covered: metric.covered,
  total: metric.total,
  percentage: metric.percentage,
});

const cloneFileCoverageSummary = (file: FileCoverageSummary): FileCoverageSummary => {
  const cloned: FileCoverageSummary = {
    file: file.file,
    statements: cloneCoverageMetric(file.statements),
  };
  if (file.branches) {
    cloned.branches = cloneCoverageMetric(file.branches);
  }
  if (file.functions) {
    cloned.functions = cloneCoverageMetric(file.functions);
  }
  if (file.mcdc) {
    cloned.mcdc = cloneCoverageMetric(file.mcdc);
  }
  return cloned;
};

const mergeCoverageTestMaps = (
  base: Record<string, string[]> | undefined,
  incoming: Record<string, string[]> | undefined,
): Record<string, string[]> | undefined => {
  if (!base && !incoming) {
    return undefined;
  }

  const combined = new Map<string, Set<string>>();
  const appendEntries = (map: Record<string, string[]> | undefined) => {
    if (!map) {
      return;
    }
    Object.entries(map).forEach(([testName, files]) => {
      const existing = combined.get(testName) ?? new Set<string>();
      files.forEach((file) => {
        const normalized = typeof file === 'string' ? file.trim() : '';
        if (normalized) {
          existing.add(normalized);
        }
      });
      if (existing.size > 0) {
        combined.set(testName, existing);
      }
    });
  };

  appendEntries(base);
  appendEntries(incoming);

  if (combined.size === 0) {
    return undefined;
  }

  return Object.fromEntries(
    Array.from(combined.entries()).map(([testName, files]) => [testName, Array.from(files).sort()]),
  );
};

const computeCoveragePercentage = (covered: number, total: number): number => {
  if (!Number.isFinite(covered) || !Number.isFinite(total) || total <= 0) {
    return 0;
  }
  const ratio = (covered / total) * 100;
  return Number.isFinite(ratio) ? ratio : 0;
};

const recomputeCoverageTotals = (files: FileCoverageSummary[]): CoverageReport['totals'] => {
  const aggregates = new Map<CoverageMetricKey, { covered: number; total: number }>();
  const addMetric = (key: CoverageMetricKey, metric: CoverageMetric | undefined) => {
    if (!metric) {
      return;
    }
    const current = aggregates.get(key) ?? { covered: 0, total: 0 };
    current.covered += metric.covered;
    current.total += metric.total;
    aggregates.set(key, current);
  };

  files.forEach((file) => {
    addMetric('statements', file.statements);
    addMetric('branches', file.branches);
    addMetric('functions', file.functions);
    addMetric('mcdc', file.mcdc);
  });

  const buildMetric = (key: CoverageMetricKey): CoverageMetric | undefined => {
    const aggregate = aggregates.get(key);
    if (!aggregate) {
      return undefined;
    }
    return {
      covered: aggregate.covered,
      total: aggregate.total,
      percentage: computeCoveragePercentage(aggregate.covered, aggregate.total),
    };
  };

  const totals: CoverageReport['totals'] = {
    statements: buildMetric('statements') ?? { covered: 0, total: 0, percentage: 0 },
  };

  (['branches', 'functions', 'mcdc'] as CoverageMetricKey[]).forEach((key) => {
    const metric = buildMetric(key);
    if (metric) {
      totals[key] = metric;
    }
  });

  return totals;
};

const mergeCoverageReports = (
  base: CoverageReport | undefined,
  incoming: CoverageReport,
): CoverageReport => {
  const baseFiles = base ? base.files.map(cloneFileCoverageSummary) : [];
  const fileMap = new Map<string, FileCoverageSummary>();
  baseFiles.forEach((file) => {
    fileMap.set(file.file, file);
  });

  incoming.files.forEach((file) => {
    const existing = fileMap.get(file.file);
    if (!existing) {
      fileMap.set(file.file, cloneFileCoverageSummary(file));
      return;
    }
    if (existing.statements.total === 0 && file.statements.total > 0) {
      existing.statements = cloneCoverageMetric(file.statements);
    }
    if (!existing.branches && file.branches) {
      existing.branches = cloneCoverageMetric(file.branches);
    } else if (existing.branches && file.branches && existing.branches.total === 0 && file.branches.total > 0) {
      existing.branches = cloneCoverageMetric(file.branches);
    }
    if (!existing.functions && file.functions) {
      existing.functions = cloneCoverageMetric(file.functions);
    } else if (existing.functions && file.functions && existing.functions.total === 0 && file.functions.total > 0) {
      existing.functions = cloneCoverageMetric(file.functions);
    }
    if (!existing.mcdc && file.mcdc) {
      existing.mcdc = cloneCoverageMetric(file.mcdc);
    } else if (existing.mcdc && file.mcdc && existing.mcdc.total === 0 && file.mcdc.total > 0) {
      existing.mcdc = cloneCoverageMetric(file.mcdc);
    }
  });

  const mergedFiles = Array.from(fileMap.values()).sort((a, b) => a.file.localeCompare(b.file));
  const mergedTotals = recomputeCoverageTotals(mergedFiles);
  const mergedTestMap = mergeCoverageTestMaps(base?.testMap, incoming.testMap);

  const merged: CoverageReport = {
    totals: mergedTotals,
    files: mergedFiles,
  };

  if (mergedTestMap) {
    merged.testMap = mergedTestMap;
  }

  return merged;
};

const coverageReportHasMetric = (
  report: CoverageReport | undefined,
  metric: 'branches' | 'mcdc',
): boolean => {
  if (!report) {
    return false;
  }
  const totalMetric = report.totals[metric];
  if (totalMetric && totalMetric.total > 0) {
    return true;
  }
  return report.files.some((file) => {
    const metricValue = file[metric];
    return metricValue !== undefined && metricValue.total > 0;
  });
};

const buildEvidenceSnapshotId = (
  artifact: ObjectiveArtifactType,
  source: EvidenceSource,
  filePath: string,
  summary: string,
  timestamp: string,
  hash?: string,
): string => {
  const digest = createHash('sha256');
  digest.update(artifact);
  digest.update('|');
  digest.update(source);
  digest.update('|');
  digest.update(normalizeRelativePath(filePath));
  digest.update('|');
  digest.update(summary);
  if (hash) {
    digest.update('|');
    digest.update(hash);
  }
  return createSnapshotIdentifier(timestamp, digest.digest('hex'));
};

const computeEvidenceFingerprint = (index: EvidenceIndex): string => {
  const values: string[] = [];
  const entries = Object.entries(index).sort(([a], [b]) => a.localeCompare(b));
  entries.forEach(([artifact, evidences]) => {
    const sorted = [...evidences].sort((a, b) => a.snapshotId.localeCompare(b.snapshotId));
    sorted.forEach((item) => {
      values.push(`${artifact}:${item.snapshotId}:${item.hash ?? ''}`);
    });
  });
  return deriveFingerprint(values);
};

const isEvidenceIndependent = (
  config: EvidenceIndependenceConfig | undefined,
  artifact: ObjectiveArtifactType,
  source: EvidenceSource,
  normalizedPath: string,
): boolean => {
  if (!config) {
    return false;
  }
  return (
    config.sources.has(source) ||
    config.artifactTypes.has(artifact) ||
    config.artifacts.has(`${artifact}:${normalizedPath}`)
  );
};

const createEvidence = async (
  artifact: ObjectiveArtifactType,
  source: EvidenceSource,
  filePath: string,
  summary: string,
  independence?: EvidenceIndependenceConfig,
): Promise<{ artifact: ObjectiveArtifactType; evidence: Evidence }> => {
  const normalizedPath = normalizeRelativePath(filePath);
  const hash = await computeEvidenceHash(filePath);
  const timestamp = getCurrentTimestamp();
  const evidence: Evidence = {
    source,
    path: normalizedPath,
    summary,
    timestamp,
    snapshotId: buildEvidenceSnapshotId(artifact, source, filePath, summary, timestamp, hash),
  };
  if (hash) {
    evidence.hash = hash;
  }
  if (isEvidenceIndependent(independence, artifact, source, normalizedPath)) {
    evidence.independent = true;
  }
  return { artifact, evidence };
};

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
  if (/(verify|validated|done|closed|accepted|approved)/.test(normalized)) {
    return 'verified';
  }
  if (/(implement|in progress|coding|development)/.test(normalized)) {
    return 'implemented';
  }
  if (/(review|ready)/.test(normalized)) {
    return 'approved';
  }
  return 'draft';
};

const toRequirementFromJira = (entry: JiraRequirement): Requirement => {
  const requirement = createRequirement(entry.id, entry.summary || entry.id, {
    description: entry.description ?? entry.summary,
    status: requirementStatusFromJira(entry.status),
    tags: entry.priority ? [`priority:${entry.priority.toLowerCase()}`] : [],
  });
  return requirement;
};

const toRequirementFromJiraCloud = (entry: RemoteRequirementRecord): Requirement => {
  const title = entry.title || entry.id;
  const description = entry.description ?? entry.url;
  const status = entry.status ? requirementStatusFromJira(entry.status) : 'draft';
  const tags = entry.type ? [`type:${entry.type.toLowerCase()}`] : [];
  return createRequirement(entry.id, title, {
    description,
    status,
    tags,
  });
};

const toRequirementFromReqif = (entry: ReqIFRequirement): Requirement => {
  const summary = entry.title || entry.text || entry.id;
  const description = entry.descriptionHtml ?? entry.text ?? entry.title ?? entry.id;
  return createRequirement(entry.id, summary, {
    description,
    status: 'draft',
  });
};

const requirementStatusFromPolarion = (status: string | undefined): RequirementStatus => {
  const normalized = status?.trim().toLowerCase();
  if (!normalized) {
    return 'draft';
  }
  if (/(verify|validated|accepted|closed|done)/u.test(normalized)) {
    return 'verified';
  }
  if (/(implement|in progress|development|coding)/u.test(normalized)) {
    return 'implemented';
  }
  if (/(review|approved|baseline)/u.test(normalized)) {
    return 'approved';
  }
  return 'draft';
};

const toRequirementFromPolarion = (entry: RemoteRequirementRecord): Requirement =>
  createRequirement(entry.id, entry.title || entry.id, {
    description: entry.description,
    status: requirementStatusFromPolarion(entry.status),
    tags: entry.type ? [`type:${entry.type.toLowerCase()}`] : [],
  });

const requirementStatusFromDoorsNext = (status: string | undefined): RequirementStatus => {
  const normalized = status?.trim().toLowerCase();
  if (!normalized) {
    return 'draft';
  }
  if (/(verify|validated|approved|accepted|closed|done|complete)/u.test(normalized)) {
    return 'verified';
  }
  if (/(implement|develop|in progress|executed|tested|complete)/u.test(normalized)) {
    return 'implemented';
  }
  if (/(review|baseline|analysis|allocated)/u.test(normalized)) {
    return 'approved';
  }
  return 'draft';
};

const requirementStatusFromAzureDevOps = (status: string | undefined): RequirementStatus => {
  const normalized = status?.trim().toLowerCase();
  if (!normalized) {
    return 'draft';
  }
  if (/(closed|done|resolved|approved|committed|completed|fixed|released)/u.test(normalized)) {
    return 'verified';
  }
  if (/(active|implement|in progress|execut|develop|committed)/u.test(normalized)) {
    return 'implemented';
  }
  if (/(review|ready|analysis|design)/u.test(normalized)) {
    return 'approved';
  }
  return 'draft';
};

const designStatusFromDoorsNext = (status: string | undefined): DesignStatus => {
  const normalized = status?.trim().toLowerCase();
  if (!normalized) {
    return 'draft';
  }
  if (/(verified|approved|released|accepted)/u.test(normalized)) {
    return 'verified';
  }
  if (/(implemented|complete|done|baseline)/u.test(normalized)) {
    return 'implemented';
  }
  if (/(allocated|defined|analyzed|assigned)/u.test(normalized)) {
    return 'allocated';
  }
  return 'draft';
};

const toRequirementFromDoorsNext = (entry: RemoteRequirementRecord): Requirement =>
  createRequirement(entry.id, entry.title || entry.id, {
    description: entry.description ?? entry.url,
    status: requirementStatusFromDoorsNext(entry.status),
    tags: entry.type ? [`type:${entry.type.toLowerCase()}`] : [],
  });

const toRequirementFromDoorsClassic = (entry: RemoteRequirementRecord): Requirement =>
  createRequirement(entry.id, entry.title || entry.id, {
    description: entry.description,
    status: requirementStatusFromDoorsNext(entry.status),
    tags: entry.type ? [`type:${entry.type.toLowerCase()}`] : [],
  });

const toRequirementFromAzureDevOps = (entry: RemoteRequirementRecord): Requirement =>
  createRequirement(entry.id, entry.title || entry.id, {
    description: entry.description ?? entry.url,
    status: requirementStatusFromAzureDevOps(entry.status),
    tags: entry.type ? [`type:${entry.type.toLowerCase()}`] : [],
  });

const toDesignFromDoorsNext = (entry: RemoteDesignRecord): DesignRecord =>
  createDesignRecord(entry.id, entry.title || entry.id, {
    description: entry.description ?? entry.url,
    status: designStatusFromDoorsNext(entry.status),
    tags: entry.type ? [`type:${entry.type.toLowerCase()}`] : [],
    requirementRefs: entry.requirementIds ?? [],
    codeRefs: entry.codeRefs ?? [],
  });

const remoteTestStatusToTestResult = (status: string): TestStatus => {
  const normalized = status.trim().toLowerCase();
  if (!normalized) {
    return 'skipped';
  }
  if (['passed', 'pass', 'success', 'succeeded', 'ok'].includes(normalized)) {
    return 'passed';
  }
  if (['skipped', 'blocked', 'not_run', 'not run', 'ignored', 'disabled'].includes(normalized)) {
    return 'skipped';
  }
  return 'failed';
};

const durationFromMilliseconds = (durationMs: number | undefined): number => {
  if (typeof durationMs !== 'number' || Number.isNaN(durationMs)) {
    return 0;
  }
  if (!Number.isFinite(durationMs)) {
    return 0;
  }
  return durationMs / 1000;
};

const toTestResultFromRemote = (
  entry: RemoteTestRecord,
  provider: 'polarion' | 'jenkins' | 'doorsNext' | 'jiraCloud' | 'azureDevOps',
): TestResult => ({
  testId: entry.id,
  className: entry.className ?? provider,
  name: entry.name ?? entry.id,
  status: remoteTestStatusToTestResult(entry.status),
  duration: durationFromMilliseconds(entry.durationMs),
  errorMessage: entry.errorMessage,
  requirementsRefs: entry.requirementIds,
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

const mergeDesigns = (sources: DesignRecord[][]): DesignRecord[] => {
  const merged = new Map<string, DesignRecord>();
  sources.forEach((list) => {
    list.forEach((design) => {
      merged.set(design.id, design);
    });
  });
  return Array.from(merged.values()).sort((a, b) => a.id.localeCompare(b.id));
};

const toTraceLinksFromDoorsNext = (
  relationships: DoorsNextRelationship[],
  requirements: Set<string>,
  tests: Set<string>,
  designs: Set<string>,
): TraceLink[] => {
  const links: TraceLink[] = [];
  const pushLink = (from: string, to: string, type: TraceLink['type']) => {
    links.push({ from, to, type });
  };

  relationships.forEach((relationship) => {
    const type = relationship.type?.toLowerCase() ?? '';
    const fromId = relationship.fromId;
    const toId = relationship.toId;
    const fromIsRequirement = requirements.has(fromId);
    const toIsRequirement = requirements.has(toId);
    const fromIsTest = tests.has(fromId);
    const toIsTest = tests.has(toId);
    const fromIsDesign = designs.has(fromId);
    const toIsDesign = designs.has(toId);

    if (fromIsTest && toIsRequirement && /(verify|validate|test)/u.test(type)) {
      pushLink(toId, fromId, 'verifies');
      return;
    }
    if (fromIsRequirement && toIsTest && /(verify|validate|test)/u.test(type)) {
      pushLink(fromId, toId, 'verifies');
      return;
    }

    if (fromIsDesign && toIsRequirement && /(design|implement|model|satisf|allocat)/u.test(type)) {
      pushLink(toId, fromId, 'implements');
      return;
    }
    if (fromIsRequirement && toIsDesign && /(design|implement|model|satisf|allocat)/u.test(type)) {
      pushLink(fromId, toId, 'implements');
      return;
    }

    if (fromIsRequirement && toIsRequirement && /(satisf|derive|refine)/u.test(type)) {
      pushLink(fromId, toId, 'satisfies');
      return;
    }
  });

  return uniqueTraceLinks(links);
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
  const outputDir = path.resolve(options.output);
  await ensureDirectory(outputDir);

  const warnings: string[] = [];
  const requirements: Requirement[][] = [];
  const designs: DesignRecord[][] = [];
  const evidenceIndex: EvidenceIndex = {};
  const independence = buildEvidenceIndependenceConfig(options);
  let coverage: CoverageReport | undefined;
  let structuralCoverage: StructuralCoverageSummary | undefined;
  let gitMetadata: BuildInfo | null | undefined;
  const testResults: TestResult[] = [];
  const findings: Finding[] = [];
  const builds: ExternalBuildRecord[] = [];
  const fileHashes: ImportedFileHash[] = [];
  const sourceMetadata: ExternalSourceMetadata = {};
  const coverageMaps: Array<{ map: Record<string, string[]>; origin: string }> = [];
  const normalizedInputs: ImportPaths = {
    jira: options.jira ? normalizeRelativePath(options.jira) : undefined,
    jiraDefects: options.jiraDefects?.map((filePath) => normalizeRelativePath(filePath)),
    jiraCloud: options.jiraCloud
      ? `${options.jiraCloud.baseUrl}#${options.jiraCloud.projectKey}`
      : undefined,
    reqif: options.reqif ? normalizeRelativePath(options.reqif) : undefined,
    junit: options.junit ? normalizeRelativePath(options.junit) : undefined,
    lcov: options.lcov ? normalizeRelativePath(options.lcov) : undefined,
    cobertura: options.cobertura ? normalizeRelativePath(options.cobertura) : undefined,
    git: options.git ? normalizeRelativePath(options.git) : undefined,
    traceLinksCsv: options.traceLinksCsv ? normalizeRelativePath(options.traceLinksCsv) : undefined,
    traceLinksJson: options.traceLinksJson
      ? normalizeRelativePath(options.traceLinksJson)
      : undefined,
    designCsv: options.designCsv ? normalizeRelativePath(options.designCsv) : undefined,
    doorsClassicReqs: options.doorsClassicReqs?.map((filePath) => normalizeRelativePath(filePath)),
    doorsClassicTraces: options.doorsClassicTraces?.map((filePath) => normalizeRelativePath(filePath)),
    doorsClassicTests: options.doorsClassicTests?.map((filePath) => normalizeRelativePath(filePath)),
    doorsNext: options.doorsNext
      ? `${options.doorsNext.baseUrl}#${options.doorsNext.projectArea}`
      : undefined,
    jama: options.jama ? `${options.jama.baseUrl}#${options.jama.projectId}` : undefined,
    polyspace: options.polyspace ? normalizeRelativePath(options.polyspace) : undefined,
    ldra: options.ldra ? normalizeRelativePath(options.ldra) : undefined,
    vectorcast: options.vectorcast ? normalizeRelativePath(options.vectorcast) : undefined,
    simulink: options.simulink ? normalizeRelativePath(options.simulink) : undefined,
    parasoft: options.parasoft?.map((filePath) => normalizeRelativePath(filePath)),
    polarion: options.polarion ? `${options.polarion.baseUrl}#${options.polarion.projectId}` : undefined,
    jenkins: options.jenkins
      ? `${options.jenkins.baseUrl}#${options.jenkins.job}`
      : undefined,
    azureDevOps: options.azureDevOps
      ? `${options.azureDevOps.baseUrl}#${options.azureDevOps.organization}/${options.azureDevOps.project}`
      : undefined,
    manualArtifacts: options.manualArtifacts
      ? Object.fromEntries(
          Object.entries(options.manualArtifacts).map(([artifact, entries]) => [
            artifact,
            (entries ?? []).map((filePath) => normalizeRelativePath(filePath)),
          ]),
        )
      : undefined,
    qaLogs: options.qaLogs?.map((filePath) => normalizeRelativePath(filePath)),
  };
  const normalizedObjectivesPath = options.objectives
    ? path.resolve(options.objectives)
    : undefined;
  const manualTraceLinks: TraceLink[] = [];

  const appendEvidence = async (
    artifact: ObjectiveArtifactType,
    source: EvidenceSource,
    filePath: string,
    summary: string,
  ): Promise<void> => {
    const { evidence } = await createEvidence(artifact, source, filePath, summary, independence);
    mergeEvidence(evidenceIndex, artifact, evidence);
  };

  if (options.jira) {
    const result = await importJiraCsv(options.jira);
    warnings.push(...result.warnings);
    if (result.data.length > 0) {
      await appendEvidence('trace', 'jiraCsv', options.jira!, 'Jira gereksinim dışa aktarımı');
    }
    requirements.push(result.data.map(toRequirementFromJira));
    if (result.data.length > 0) {
      const jiraSummary = sourceMetadata.jira ?? {};
      jiraSummary.requirements = (jiraSummary.requirements ?? 0) + result.data.length;
      sourceMetadata.jira = jiraSummary;
    }
  }

  if (options.jiraDefects) {
    for (const jiraPath of options.jiraDefects) {
      const result = await importJiraCsv(jiraPath);
      warnings.push(...result.warnings);
      const issues = result.data;
      const recognized = issues.filter((item) => isProblemReportIssue(item.issueType));
      const openCount = recognized.filter((item) => !isClosedProblemStatus(item.status)).length;
      const hasIssueType = issues.some((item) => item.issueType && item.issueType.trim().length > 0);
      const baseName = path.basename(jiraPath);
      if (issues.length === 0) {
        warnings.push(`Jira CSV ${baseName} satır içermiyor; problem raporu oluşturulamadı.`);
      } else if (!hasIssueType) {
        warnings.push(
          `Jira CSV ${baseName} içinde 'Issue Type' sütunu bulunamadı; tüm satırlar problem raporu olarak doğrulanamadı.`,
        );
      } else if (recognized.length === 0) {
        warnings.push(`Jira CSV ${baseName} içinde tanınan problem raporu türü bulunamadı.`);
      }

      const summaryDetail =
        recognized.length > 0
          ? `${openCount} açık / ${recognized.length} kayıt`
          : issues.length > 0
            ? 'problem raporu dışa aktarımı (eşleşme yok)'
            : 'boş dışa aktarım';
      await appendEvidence(
        'problem_report',
        'jiraCsv',
        jiraPath,
        `Jira problem raporu (${baseName}): ${summaryDetail}`,
      );

      const jiraSummary = sourceMetadata.jira ?? {};
      if (recognized.length > 0) {
        jiraSummary.problemReports = (jiraSummary.problemReports ?? 0) + recognized.length;
        jiraSummary.openProblems = (jiraSummary.openProblems ?? 0) + openCount;
      }
      const reports = jiraSummary.reports ?? [];
      jiraSummary.reports = [
        ...reports,
        {
          file: normalizeRelativePath(jiraPath),
          total: recognized.length,
          open: openCount,
        },
      ];
      sourceMetadata.jira = jiraSummary;
    }
  }

  if (options.jiraCloud) {
    const jiraResult = await fetchJiraArtifacts(options.jiraCloud);
    warnings.push(...jiraResult.warnings);

    const remoteRequirements = jiraResult.data.requirements ?? [];
    const remoteTests = jiraResult.data.tests ?? [];
    const remoteTraces = jiraResult.data.traces ?? [];
    const remoteAttachments = jiraResult.data.attachments ?? [];
    const sourceId = `remote:jiraCloud:${options.jiraCloud.projectKey}`;

    if (remoteRequirements.length > 0) {
      requirements.push(remoteRequirements.map(toRequirementFromJiraCloud));
      await appendEvidence('trace', 'jiraCloud', sourceId, 'Jira Cloud gereksinim kataloğu');
    }

    if (remoteTests.length > 0) {
      const existingIds = new Set(testResults.map((test) => test.testId));
      remoteTests.forEach((entry) => {
        if (existingIds.has(entry.id)) {
          return;
        }
        const normalized = toTestResultFromRemote(entry, 'jiraCloud');
        testResults.push(normalized);
        existingIds.add(entry.id);
      });
      await appendEvidence('test', 'jiraCloud', sourceId, 'Jira Cloud test kayıtları');
    }

    if (remoteTraces.length > 0) {
      manualTraceLinks.push(
        ...remoteTraces.map((link) => ({ from: link.fromId, to: link.toId, type: link.type })),
      );
      await appendEvidence('trace', 'jiraCloud', `${sourceId}:relationships`, 'Jira Cloud izlenebilirlik');
    }

    const attachmentAuthHeader = buildJiraCloudAuthHeader(options.jiraCloud);
    let attachmentSummary: ExternalSourceMetadata['jiraCloud']['attachments'] = null;
    if (remoteAttachments.length > 0) {
      const { results: attachmentResults, warnings: attachmentWarnings } =
        await streamConnectorAttachments(
          outputDir,
          'jiraCloud',
          remoteAttachments.map((attachment) => ({
            issueKey: attachment.issueKey,
            filename: attachment.filename,
            url: attachment.url,
            authHeader: attachmentAuthHeader,
            expectedSha256: (attachment as { sha256?: string }).sha256,
          })),
        );
      warnings.push(...attachmentWarnings);

      for (const outcome of attachmentResults) {
        if (!outcome.absolutePath) {
          continue;
        }
        const summary = `Jira Cloud eki ${outcome.descriptor.issueKey} / ${outcome.descriptor.filename}`;
        const { evidence } = await createEvidence(
          'trace',
          'jiraCloud',
          outcome.absolutePath,
          summary,
          independence,
        );
        mergeEvidence(evidenceIndex, 'trace', evidence);
      }

      const totalBytes = attachmentResults.reduce(
        (accumulator, entry) => accumulator + (entry.bytes ?? 0),
        0,
      );

      attachmentSummary = {
        total: remoteAttachments.length,
        totalBytes,
        items: remoteAttachments.map((attachment, index) => {
          const download = attachmentResults[index];
          return {
            issueKey: attachment.issueKey,
            filename: attachment.filename,
            url: attachment.url,
            size: attachment.size,
            createdAt: attachment.createdAt,
            path: download?.relativePath,
            sha256: download?.sha256,
            bytes: download?.bytes,
          };
        }),
      };
    }

    sourceMetadata.jiraCloud = {
      baseUrl: options.jiraCloud.baseUrl,
      projectKey: options.jiraCloud.projectKey,
      requirements: remoteRequirements.length,
      tests: remoteTests.length,
      traces: remoteTraces.length,
      attachments: attachmentSummary,
      requirementsJql: options.jiraCloud.requirementsJql,
      testsJql: options.jiraCloud.testsJql,
    };
  }

  if (options.reqif) {
    const result = await importReqIF(options.reqif);
    warnings.push(...result.warnings);
    if (result.data.length > 0) {
      await appendEvidence('trace', 'reqif', options.reqif, 'ReqIF gereksinim paketi');
    }
    requirements.push(result.data.map(toRequirementFromReqif));
  }

  if (options.junit) {
    const result = await importJUnitXml(options.junit);
    warnings.push(...result.warnings);
    testResults.push(...result.data);
    if (result.data.length > 0) {
      await appendEvidence('test', 'junit', options.junit, 'JUnit test sonuçları');
    }
  }

  if (options.lcov) {
    const result = await importLcov(options.lcov);
    warnings.push(...result.warnings);
    coverage = mergeCoverageReports(coverage, result.data);
    if (result.data.testMap) {
      coverageMaps.push({ map: result.data.testMap, origin: path.resolve(options.lcov) });
    }
    if (result.data.files.length > 0) {
      await appendEvidence('coverage_stmt', 'lcov', options.lcov, 'LCOV kapsam raporu');
      if (coverageReportHasMetric(result.data, 'branches')) {
        await appendEvidence('coverage_dec', 'lcov', options.lcov, 'LCOV karar kapsamı');
      }
      if (coverageReportHasMetric(result.data, 'mcdc')) {
        await appendEvidence('coverage_mcdc', 'lcov', options.lcov, 'LCOV MC/DC kapsamı');
      }
    }
  }

  if (options.cobertura) {
    const result = await importCobertura(options.cobertura);
    warnings.push(...result.warnings);
    coverage = mergeCoverageReports(coverage, result.data);
    if (result.data.testMap) {
      coverageMaps.push({ map: result.data.testMap, origin: path.resolve(options.cobertura) });
    }
    if (result.data.files.length > 0) {
      await appendEvidence('coverage_stmt', 'cobertura', options.cobertura, 'Cobertura kapsam raporu');
      if (coverageReportHasMetric(result.data, 'branches')) {
        await appendEvidence('coverage_dec', 'cobertura', options.cobertura, 'Cobertura karar kapsamı');
      }
      if (coverageReportHasMetric(result.data, 'mcdc')) {
        await appendEvidence('coverage_mcdc', 'cobertura', options.cobertura, 'Cobertura MC/DC kapsamı');
      }
    }
  }

  if (options.polyspace) {
    const result = await fromPolyspace(options.polyspace);
    warnings.push(...result.warnings);
    if (result.data.findings) {
      findings.push(...result.data.findings);
    }
    if ((result.data.findings?.length ?? 0) > 0) {
      await appendEvidence('review', 'polyspace', options.polyspace, 'Polyspace statik analiz raporu');
      await appendEvidence('problem_report', 'polyspace', options.polyspace, 'Polyspace bulgu listesi');
    }
  }

  if (options.ldra) {
    const result = await fromLDRA(options.ldra);
    warnings.push(...result.warnings);
    if (result.data.findings) {
      findings.push(...result.data.findings);
    }
    if (result.data.coverage) {
      structuralCoverage = mergeStructuralCoverage(structuralCoverage, result.data.coverage);
      await appendEvidence('coverage_stmt', 'ldra', options.ldra, 'LDRA kapsam özeti');
      if (structuralCoverageHasMetric(result.data.coverage, 'dec')) {
        await appendEvidence('coverage_dec', 'ldra', options.ldra, 'LDRA karar kapsamı');
      }
      if (structuralCoverageHasMetric(result.data.coverage, 'mcdc')) {
        await appendEvidence('coverage_mcdc', 'ldra', options.ldra, 'LDRA MC/DC kapsamı');
      }
    }
    if ((result.data.findings?.length ?? 0) > 0) {
      await appendEvidence('review', 'ldra', options.ldra, 'LDRA kural ihlalleri');
      await appendEvidence('problem_report', 'ldra', options.ldra, 'LDRA ihlal raporu');
    }
  }

  if (options.vectorcast) {
    const result = await fromVectorCAST(options.vectorcast);
    warnings.push(...result.warnings);
    if (result.data.findings) {
      findings.push(...result.data.findings);
    }
    if (result.data.coverage) {
      structuralCoverage = mergeStructuralCoverage(structuralCoverage, result.data.coverage);
      await appendEvidence('coverage_stmt', 'vectorcast', options.vectorcast, 'VectorCAST kapsam raporu');
      if (structuralCoverageHasMetric(result.data.coverage, 'dec')) {
        await appendEvidence('coverage_dec', 'vectorcast', options.vectorcast, 'VectorCAST karar kapsamı');
      }
      if (structuralCoverageHasMetric(result.data.coverage, 'mcdc')) {
        await appendEvidence('coverage_mcdc', 'vectorcast', options.vectorcast, 'VectorCAST MC/DC kapsamı');
      }
    }
    if ((result.data.findings?.length ?? 0) > 0) {
      await appendEvidence('test', 'vectorcast', options.vectorcast, 'VectorCAST test değerlendirmeleri');
      await appendEvidence('analysis', 'vectorcast', options.vectorcast, 'VectorCAST sonuç analizi');
    }
  }

  if (options.simulink) {
    const result = await fromSimulink(options.simulink);
    warnings.push(...result.warnings);
    if (result.data.coverage) {
      structuralCoverage = mergeStructuralCoverage(structuralCoverage, result.data.coverage);
      await appendEvidence(
        'coverage_stmt',
        'simulink',
        options.simulink,
        'Simulink model kapsam raporu',
      );
      if (structuralCoverageHasMetric(result.data.coverage, 'dec')) {
        await appendEvidence(
          'coverage_dec',
          'simulink',
          options.simulink,
          'Simulink karar/koşul kapsamı',
        );
      }
      if (structuralCoverageHasMetric(result.data.coverage, 'mcdc')) {
        await appendEvidence(
          'coverage_mcdc',
          'simulink',
          options.simulink,
          'Simulink MC/DC kapsamı',
        );
      }
    }
  }

  if (options.parasoft) {
    const parasoftSummary: ExternalSourceMetadata['parasoft'] =
      sourceMetadata.parasoft ?? {
        reports: [],
        totalFindings: 0,
        totalTests: 0,
        coverageFiles: 0,
        fileHashes: 0,
      };

    for (const reportPath of options.parasoft) {
      const result = await importParasoft(reportPath);
      warnings.push(...result.warnings);

      const reportData = result.data;

      if (reportData.testResults && reportData.testResults.length > 0) {
        testResults.push(...reportData.testResults);
        await appendEvidence('test', 'parasoft', reportPath, 'Parasoft test sonuçları');
        parasoftSummary.totalTests += reportData.testResults.length;
      }

      if (reportData.coverage) {
        structuralCoverage = mergeStructuralCoverage(structuralCoverage, reportData.coverage);
        await appendEvidence('coverage_stmt', 'parasoft', reportPath, 'Parasoft kapsam özeti');
        if (structuralCoverageHasMetric(reportData.coverage, 'dec')) {
          await appendEvidence('coverage_dec', 'parasoft', reportPath, 'Parasoft karar kapsamı');
        }
        if (structuralCoverageHasMetric(reportData.coverage, 'mcdc')) {
          await appendEvidence('coverage_mcdc', 'parasoft', reportPath, 'Parasoft MC/DC kapsamı');
        }
        parasoftSummary.coverageFiles += reportData.coverage.files.length;
      }

      if (reportData.findings && reportData.findings.length > 0) {
        findings.push(...reportData.findings);
        await appendEvidence('review', 'parasoft', reportPath, 'Parasoft statik analiz bulguları');
        parasoftSummary.totalFindings += reportData.findings.length;
      }

      if (reportData.fileHashes && reportData.fileHashes.length > 0) {
        fileHashes.push(...reportData.fileHashes);
        await appendEvidence('cm_record', 'parasoft', reportPath, 'Parasoft dosya özetleri');
        parasoftSummary.fileHashes += reportData.fileHashes.length;
      }

      parasoftSummary.reports.push({
        file: normalizeRelativePath(reportPath),
        tests: reportData.testResults?.length ?? 0,
        findings: reportData.findings?.length ?? 0,
        coverageFiles: reportData.coverage?.files.length ?? 0,
        fileHashes: reportData.fileHashes?.length ?? 0,
        warnings: [...result.warnings],
      });
    }

    sourceMetadata.parasoft = parasoftSummary;
  }

  if (options.git) {
    const result = await importGitMetadata(options.git);
    warnings.push(...result.warnings);
    gitMetadata = result.data;
    if (result.data) {
      await appendEvidence('cm_record', 'git', options.git, 'Git depo başlığı');
    }
  }

  if (options.traceLinksCsv) {
    const result = await importTraceLinksCsv(options.traceLinksCsv);
    warnings.push(...result.warnings);
    if (result.links.length > 0) {
      manualTraceLinks.push(...result.links);
      await appendEvidence('trace', 'other', options.traceLinksCsv, 'Manuel izlenebilirlik eşlemeleri (CSV)');
    }
  }

  if (options.designCsv) {
    const result = await importDesignCsv(options.designCsv);
    warnings.push(...result.warnings);
    if (result.designs.length > 0) {
      designs.push(result.designs);
    }
  }

  const doorsClassicSources = [
    ...(options.doorsClassicReqs ?? []),
    ...(options.doorsClassicTraces ?? []),
    ...(options.doorsClassicTests ?? []),
  ];

  if (doorsClassicSources.length > 0) {
    const factory = aggregateImportBundle(
      doorsClassicSources.map((filePath) => () => importDoorsClassicCsv(filePath)),
    );
    const result = await factory();
    warnings.push(...result.warnings);

    const remoteRequirements = result.data.requirements ?? [];
    if (remoteRequirements.length > 0) {
      requirements.push(remoteRequirements.map(toRequirementFromDoorsClassic));
    }

    if (result.data.traces.length > 0) {
      manualTraceLinks.push(
        ...result.data.traces.map((link) => ({ from: link.fromId, to: link.toId, type: link.type })),
      );
    }

    for (const filePath of doorsClassicSources) {
      await appendEvidence('trace', 'doorsClassic', filePath, 'DOORS Classic CSV dışa aktarımı');
    }

    sourceMetadata.doorsClassic = {
      modules: doorsClassicSources.length,
      requirements: remoteRequirements.length,
      traces: result.data.traces.length,
    };
  }

  if (options.doorsNext) {
    const doorsAttachmentsDir = path.join(outputDir, 'attachments', 'doorsNext');
    await ensureDirectory(doorsAttachmentsDir);

    const doorsResult = await fetchDoorsNextArtifacts({
      ...options.doorsNext,
      attachmentsDir: doorsAttachmentsDir,
    });
    warnings.push(...doorsResult.warnings);
    const doorsRequirements = doorsResult.data.requirements ?? [];
    const doorsTests = doorsResult.data.tests ?? [];
    const doorsDesigns = doorsResult.data.designs ?? [];
    const doorsRelationships = doorsResult.data.relationships ?? [];
    const doorsAttachments = doorsResult.data.attachments ?? [];
    const sourceId = `remote:doorsNext:${options.doorsNext.projectArea}`;

    if (doorsRequirements.length > 0) {
      requirements.push(doorsRequirements.map(toRequirementFromDoorsNext));
      await appendEvidence(
        'trace',
        'doorsNext',
        sourceId,
        'DOORS Next gereksinim kataloğu',
      );
    }

    if (doorsTests.length > 0) {
      const existingTestIds = new Set(testResults.map((test) => test.testId));
      doorsTests.forEach((entry) => {
        if (existingTestIds.has(entry.id)) {
          return;
        }
        testResults.push(toTestResultFromRemote(entry, 'doorsNext'));
        existingTestIds.add(entry.id);
      });
      await appendEvidence('test', 'doorsNext', sourceId, 'DOORS Next test kayıtları');
    }

    if (doorsDesigns.length > 0) {
      designs.push(doorsDesigns.map(toDesignFromDoorsNext));
      await appendEvidence('trace', 'doorsNext', sourceId, 'DOORS Next tasarım kayıtları');
    }

    if (doorsRelationships.length > 0) {
      const requirementIds = new Set(doorsRequirements.map((item) => item.id));
      const testIds = new Set(doorsTests.map((item) => item.id));
      const designIds = new Set(doorsDesigns.map((item) => item.id));
      const doorLinks = toTraceLinksFromDoorsNext(
        doorsRelationships,
        requirementIds,
        testIds,
        designIds,
      );
      if (doorLinks.length > 0) {
        manualTraceLinks.push(...doorLinks);
      }
    }

    let attachmentSummary: ExternalSourceMetadata['doorsNext']['attachments'] = null;
    if (doorsAttachments.length > 0) {
      const attachmentItems: NonNullable<ExternalSourceMetadata['doorsNext']['attachments']>['items'] = [];
      let totalBytes = 0;
      for (const attachment of doorsAttachments) {
        const absolutePath = path.resolve(attachment.path);
        const workspaceRelativePath = path
          .relative(outputDir, absolutePath)
          .split(path.sep)
          .join('/');

        const summary = `DOORS Next eki ${attachment.artifactId} / ${attachment.filename}`;
        const { evidence } = await createEvidence(
          'trace',
          'doorsNext',
          absolutePath,
          summary,
          independence,
        );
        mergeEvidence(evidenceIndex, 'trace', evidence);

        totalBytes += attachment.size ?? 0;
        attachmentItems.push({
          id: attachment.id,
          artifactId: attachment.artifactId,
          title: attachment.title,
          filename: attachment.filename,
          contentType: attachment.contentType,
          path: workspaceRelativePath,
          sha256: attachment.sha256,
          bytes: attachment.size,
        });
      }

      attachmentSummary = {
        total: doorsAttachments.length,
        totalBytes,
        items: attachmentItems,
      };
    }

    const etagCacheSnapshot = doorsResult.data.etagCache ?? {};
    const etagCacheSize = Object.keys(etagCacheSnapshot).length;

    sourceMetadata.doorsNext = {
      baseUrl: options.doorsNext.baseUrl,
      projectArea: options.doorsNext.projectArea,
      requirements: doorsRequirements.length,
      tests: doorsTests.length,
      designs: doorsDesigns.length,
      relationships: doorsRelationships.length,
      etagCacheSize,
      etagCache: etagCacheSize > 0 ? etagCacheSnapshot : undefined,
      attachments: attachmentSummary,
    };
  }

  if (options.jama) {
    const jamaResult = await fetchJamaArtifacts(options.jama);
    warnings.push(...jamaResult.warnings);
    const jamaRequirements = jamaResult.data.requirements ?? [];
    const jamaTests = jamaResult.data.testResults ?? [];
    const jamaLinks = jamaResult.data.traceLinks ?? [];
    const jamaAttachments = jamaResult.data.attachments ?? [];
    const sourceId = `remote:jama:${options.jama.projectId}`;

    if (jamaRequirements.length > 0) {
      requirements.push(jamaRequirements);
      await appendEvidence('trace', 'jama', sourceId, 'Jama gereksinim kataloğu');
    }

    if (jamaTests.length > 0) {
      const existingTestIds = new Set(testResults.map((test) => test.testId));
      jamaTests.forEach((test) => {
        if (existingTestIds.has(test.testId)) {
          return;
        }
        testResults.push(test);
        existingTestIds.add(test.testId);
      });
      await appendEvidence('test', 'jama', sourceId, 'Jama test kayıtları');
    }

    if (jamaLinks.length > 0) {
      manualTraceLinks.push(
        ...jamaLinks.map((link) => ({ from: link.requirementId, to: link.testCaseId, type: 'verifies' as const })),
      );
      await appendEvidence('trace', 'jama', `${sourceId}:relationships`, 'Jama gereksinim ilişkileri');
    }

    let attachmentSummary: ExternalSourceMetadata['jama']['attachments'] = null;
    if (jamaAttachments.length > 0) {
      const { results: attachmentResults, warnings: attachmentWarnings } =
        await streamConnectorAttachments(
          outputDir,
          'jama',
          jamaAttachments.map((attachment) => ({
            issueKey: String(attachment.itemId ?? 'item'),
            filename: attachment.filename ?? `${attachment.itemType ?? 'attachment'}.bin`,
            url: attachment.url,
            authHeader: `Bearer ${options.jama.token}`,
            expectedSha256: (attachment as { sha256?: string }).sha256,
          })),
        );
      warnings.push(...attachmentWarnings);

      for (const outcome of attachmentResults) {
        if (!outcome.absolutePath) {
          continue;
        }
        const summary = `Jama eki ${outcome.descriptor.issueKey} / ${outcome.descriptor.filename}`;
        const { evidence } = await createEvidence(
          'trace',
          'jama',
          outcome.absolutePath,
          summary,
          independence,
        );
        mergeEvidence(evidenceIndex, 'trace', evidence);
      }

      const totalBytes = attachmentResults.reduce(
        (accumulator, entry) => accumulator + (entry.bytes ?? 0),
        0,
      );

      attachmentSummary = {
        total: jamaAttachments.length,
        totalBytes,
        items: jamaAttachments.map((attachment, index) => {
          const download = attachmentResults[index];
          return {
            itemId: String(attachment.itemId ?? 'item'),
            itemType: attachment.itemType,
            filename: attachment.filename,
            url: attachment.url,
            size: attachment.size,
            createdAt: attachment.createdAt,
            path: download?.relativePath,
            sha256: download?.sha256,
            bytes: download?.bytes,
          };
        }),
      };
    }

    sourceMetadata.jama = {
      baseUrl: options.jama.baseUrl,
      projectId: String(options.jama.projectId),
      requirements: jamaRequirements.length,
      tests: jamaTests.length,
      traceLinks: jamaLinks.length,
      attachments: attachmentSummary,
    };
  }

  if (options.polarion) {
    const polarionResult = await fetchPolarionArtifacts(options.polarion);
    warnings.push(...polarionResult.warnings);
    const polarionRequirements = polarionResult.data.requirements ?? [];
    const polarionTests = polarionResult.data.tests ?? [];
    const polarionBuilds = polarionResult.data.builds ?? [];
    const polarionRelationships = polarionResult.data.relationships ?? [];
    const polarionAttachments = polarionResult.data.attachments ?? [];

    if (polarionRequirements.length > 0) {
      requirements.push(polarionRequirements.map(toRequirementFromPolarion));
      await appendEvidence(
        'trace',
        'polarion',
        `remote:polarion:${options.polarion.projectId}`,
        'Polarion gereksinim kataloğu',
      );
    }

    if (polarionTests.length > 0) {
      testResults.push(
        ...polarionTests.map((entry) => toTestResultFromRemote(entry, 'polarion')),
      );
      await appendEvidence(
        'test',
        'polarion',
        `remote:polarion:${options.polarion.projectId}`,
        'Polarion test çalıştırmaları',
      );
    }

    if (polarionRelationships.length > 0) {
      manualTraceLinks.push(
        ...polarionRelationships.map((link) => ({
          from: link.fromId,
          to: link.toId,
          type: link.type,
        })),
      );
      await appendEvidence(
        'trace',
        'polarion',
        `remote:polarion:${options.polarion.projectId}:relationships`,
        'Polarion gereksinim-test ilişkileri',
      );
    }

    if (polarionBuilds.length > 0) {
      polarionBuilds.forEach((build) => {
        builds.push({
          provider: 'polarion',
          id: build.id,
          name: build.name,
          url: build.url,
          status: build.status,
          branch: build.branch,
          revision: build.revision,
          startedAt: build.startedAt,
          completedAt: build.completedAt,
        });
      });
      await appendEvidence(
        'cm_record',
        'polarion',
        `remote:polarion:${options.polarion.projectId}`,
        'Polarion yapı kayıtları',
      );
    }

    let polarionAttachmentSummary: ExternalSourceMetadata['polarion']['attachments'] = null;
    if (polarionAttachments.length > 0) {
      const polarionAuthHeader = buildPolarionAuthHeader(options.polarion);
      const { results: attachmentResults, warnings: attachmentWarnings } =
        await streamConnectorAttachments(
          outputDir,
          'polarion',
          polarionAttachments.map((attachment) => ({
            issueKey: attachment.workItemId ?? attachment.id ?? 'workItem',
            filename: attachment.filename,
            url: attachment.url,
            authHeader: polarionAuthHeader,
            expectedSha256: attachment.sha256,
          })),
        );
      warnings.push(...attachmentWarnings);

      const attachmentItems: NonNullable<ExternalSourceMetadata['polarion']['attachments']>['items'] = [];
      let totalBytes = 0;

      for (let index = 0; index < polarionAttachments.length; index += 1) {
        const attachment = polarionAttachments[index]!;
        const download = attachmentResults[index];
        const workItemLabel = attachment.workItemId ?? attachment.id ?? 'ek';
        const downloadBytes = download?.bytes ?? attachment.bytes ?? attachment.size ?? 0;
        totalBytes += downloadBytes;

        if (download?.absolutePath) {
          const summary = `Polarion eki ${workItemLabel} / ${attachment.filename}`;
          const { evidence } = await createEvidence(
            'trace',
            'polarion',
            download.absolutePath,
            summary,
            independence,
          );
          mergeEvidence(evidenceIndex, 'trace', evidence);
        }

        attachmentItems.push({
          id: attachment.id,
          workItemId: attachment.workItemId,
          title: attachment.title,
          description: attachment.description,
          filename: attachment.filename,
          contentType: attachment.contentType,
          path: download?.relativePath,
          sha256: download?.sha256 ?? attachment.sha256,
          bytes: downloadBytes,
        });
      }

      polarionAttachmentSummary = {
        total: polarionAttachments.length,
        totalBytes,
        items: attachmentItems,
      };
    }

    sourceMetadata.polarion = {
      baseUrl: options.polarion.baseUrl,
      projectId: options.polarion.projectId,
      requirements: polarionRequirements.length,
      tests: polarionTests.length,
      builds: polarionBuilds.length,
      relationships: polarionRelationships.length,
      attachments: polarionAttachmentSummary,
    };
  }

  if (options.jenkins) {
    const jenkinsResult = await fetchJenkinsArtifacts(options.jenkins);
    warnings.push(...jenkinsResult.warnings);
    const jenkinsTests = jenkinsResult.data.tests ?? [];
    const jenkinsBuilds = jenkinsResult.data.builds ?? [];
    const jenkinsCoverage = jenkinsResult.data.coverage ?? [];
    const coverageSummaries: JenkinsCoverageArtifactSummary[] = [];

    if (jenkinsTests.length > 0) {
      testResults.push(
        ...jenkinsTests.map((entry) => toTestResultFromRemote(entry, 'jenkins')),
      );
      await appendEvidence(
        'test',
        'jenkins',
        `remote:jenkins:${options.jenkins.job}`,
        'Jenkins test raporları',
      );
    }

    if (jenkinsBuilds.length > 0) {
      jenkinsBuilds.forEach((build) => {
        builds.push({
          provider: 'jenkins',
          id: build.id,
          name: build.name,
          url: build.url,
          status: build.status,
          branch: build.branch,
          revision: build.revision,
          startedAt: build.startedAt,
          completedAt: build.completedAt,
        });
      });
      await appendEvidence(
        'cm_record',
        'jenkins',
        `remote:jenkins:${options.jenkins.job}`,
        'Jenkins build metaverisi',
      );
    }

    for (const artifact of jenkinsCoverage) {
      coverage = mergeCoverageReports(coverage, artifact.report);
      if (artifact.report.testMap) {
        coverageMaps.push({ map: artifact.report.testMap, origin: artifact.localPath });
      }

      if (artifact.report.files.length > 0) {
        const label = artifact.type === 'lcov' ? 'LCOV' : 'Cobertura';
        const summaryBase = `Jenkins ${label} kapsam raporu (${artifact.path})`;
        await appendEvidence('coverage_stmt', 'jenkins', artifact.localPath, summaryBase);
        if (coverageReportHasMetric(artifact.report, 'branches')) {
          await appendEvidence(
            'coverage_dec',
            'jenkins',
            artifact.localPath,
            `Jenkins ${label} karar kapsamı (${artifact.path})`,
          );
        }
        if (coverageReportHasMetric(artifact.report, 'mcdc')) {
          await appendEvidence(
            'coverage_mcdc',
            'jenkins',
            artifact.localPath,
            `Jenkins ${label} MC/DC kapsamı (${artifact.path})`,
          );
        }
      }

      coverageSummaries.push({
        type: artifact.type,
        path: artifact.path,
        localPath: normalizeRelativePath(artifact.localPath),
        sha256: artifact.sha256,
        statements: artifact.report.totals.statements.percentage,
        branches: artifact.report.totals.branches?.percentage,
        functions: artifact.report.totals.functions?.percentage,
        mcdc: artifact.report.totals.mcdc?.percentage,
        tests: artifact.report.testMap ? Object.keys(artifact.report.testMap).length : 0,
      });
    }

    sourceMetadata.jenkins = {
      baseUrl: options.jenkins.baseUrl,
      job: options.jenkins.job,
      build: options.jenkins.build ? String(options.jenkins.build) : undefined,
      tests: jenkinsTests.length,
      builds: jenkinsBuilds.length,
      coverageArtifacts:
        coverageSummaries.length > 0
          ? {
              total: coverageSummaries.length,
              items: coverageSummaries,
            }
          : undefined,
    };
  }

  if (options.azureDevOps) {
    const azureResult = await fetchAzureDevOpsArtifacts(options.azureDevOps);
    warnings.push(...azureResult.warnings);

    const azureRequirements = azureResult.data.requirements ?? [];
    const azureTests = azureResult.data.tests ?? [];
    const azureBuilds = azureResult.data.builds ?? [];
    const azureTraces = azureResult.data.traces ?? [];
    const azureAttachments = (azureResult.data.attachments ?? []) as AzureDevOpsAttachmentMetadata[];
    const sourceId = `remote:azureDevOps:${options.azureDevOps.organization}/${options.azureDevOps.project}`;

    if (azureRequirements.length > 0) {
      requirements.push(azureRequirements.map(toRequirementFromAzureDevOps));
      await appendEvidence('trace', 'azureDevOps', sourceId, 'Azure DevOps gereksinim kataloğu');
    }

    if (azureTests.length > 0) {
      const existingIds = new Set(testResults.map((test) => test.testId));
      azureTests.forEach((entry) => {
        if (existingIds.has(entry.id)) {
          return;
        }
        testResults.push(toTestResultFromRemote(entry, 'azureDevOps'));
        existingIds.add(entry.id);
      });
      await appendEvidence('test', 'azureDevOps', sourceId, 'Azure DevOps test kayıtları');
    }

    if (azureTraces.length > 0) {
      manualTraceLinks.push(
        ...azureTraces.map((link) => ({ from: link.fromId, to: link.toId, type: link.type })),
      );
      await appendEvidence(
        'trace',
        'azureDevOps',
        `${sourceId}:relationships`,
        'Azure DevOps izlenebilirlik kayıtları',
      );
    }

    if (azureBuilds.length > 0) {
      azureBuilds.forEach((build) => {
        builds.push({
          provider: 'azureDevOps',
          id: build.id,
          name: build.name,
          url: build.url,
          status: build.status,
          branch: build.branch,
          revision: build.revision,
          startedAt: build.startedAt,
          completedAt: build.completedAt,
        });
      });
      await appendEvidence('cm_record', 'azureDevOps', sourceId, 'Azure DevOps build metaverisi');
    }

    let azureAttachmentSummary: ExternalSourceMetadata['azureDevOps']['attachments'] = null;
    if (azureAttachments.length > 0) {
      const azureAuthHeader = buildAzureDevOpsAuthHeader(options.azureDevOps.personalAccessToken);
      const shaCache = new Map<string, { relativePath: string; absolutePath: string; bytes?: number }>();
      const attachmentItems: NonNullable<ExternalSourceMetadata['azureDevOps']['attachments']>['items'] = [];
      let totalBytes = 0;

      for (const attachment of azureAttachments) {
        const normalizedSha = attachment.sha256?.toLowerCase();
        const issueKey = `${attachment.artifactType}:${attachment.artifactId}`;
        if (normalizedSha && shaCache.has(normalizedSha)) {
          const cached = shaCache.get(normalizedSha)!;
          const absolutePath = cached.absolutePath;
          const summary = `Azure DevOps eki ${issueKey} / ${attachment.filename}`;
          const { evidence } = await createEvidence(
            'trace',
            'azureDevOps',
            absolutePath,
            summary,
            independence,
          );
          mergeEvidence(evidenceIndex, 'trace', evidence);
          const reuseBytes = attachment.bytes ?? cached.bytes ?? 0;
          totalBytes += reuseBytes;
          attachmentItems.push({
            id: attachment.id,
            artifactId: attachment.artifactId,
            artifactType: attachment.artifactType,
            filename: attachment.filename,
            url: attachment.url,
            contentType: attachment.contentType,
            path: cached.relativePath,
            sha256: normalizedSha,
            bytes: reuseBytes,
          });
          continue;
        }

        const { results: attachmentResults, warnings: attachmentWarnings } =
          await streamConnectorAttachments(outputDir, 'azureDevOps', [
            {
              issueKey,
              filename: attachment.filename,
              url: attachment.url,
              authHeader: azureAuthHeader,
              expectedSha256: attachment.sha256,
            },
          ]);
        warnings.push(...attachmentWarnings);
        const outcome = attachmentResults[0];

        if (outcome?.absolutePath) {
          const relativePath =
            outcome.relativePath ??
            path.relative(outputDir, outcome.absolutePath).split(path.sep).join('/');
          const sha256 = (outcome.sha256 ?? normalizedSha)?.toLowerCase();
          const bytes = outcome.bytes ?? attachment.bytes ?? 0;
          if (sha256) {
            shaCache.set(sha256, {
              relativePath,
              absolutePath: outcome.absolutePath,
              bytes,
            });
          }

          const summary = `Azure DevOps eki ${issueKey} / ${attachment.filename}`;
          const { evidence } = await createEvidence(
            'trace',
            'azureDevOps',
            outcome.absolutePath,
            summary,
            independence,
          );
          mergeEvidence(evidenceIndex, 'trace', evidence);

          totalBytes += bytes;
          attachmentItems.push({
            id: attachment.id,
            artifactId: attachment.artifactId,
            artifactType: attachment.artifactType,
            filename: attachment.filename,
            url: attachment.url,
            contentType: attachment.contentType,
            path: relativePath,
            sha256: sha256 ?? undefined,
            bytes,
          });
        } else {
          const fallbackBytes = attachment.bytes ?? 0;
          totalBytes += fallbackBytes;
          attachmentItems.push({
            id: attachment.id,
            artifactId: attachment.artifactId,
            artifactType: attachment.artifactType,
            filename: attachment.filename,
            url: attachment.url,
            contentType: attachment.contentType,
            sha256: normalizedSha,
            bytes: attachment.bytes,
          });
        }
      }

      azureAttachmentSummary = {
        total: attachmentItems.length,
        totalBytes,
        items: attachmentItems,
      };
    }

    sourceMetadata.azureDevOps = {
      baseUrl: options.azureDevOps.baseUrl,
      organization: options.azureDevOps.organization,
      project: options.azureDevOps.project,
      requirements: azureRequirements.length,
      tests: azureTests.length,
      builds: azureBuilds.length,
      traces: azureTraces.length,
      attachments: azureAttachmentSummary,
    };
  }

  if (options.manualArtifacts) {
    for (const [artifactKey, entries] of Object.entries(options.manualArtifacts)) {
      if (!entries || entries.length === 0) {
        continue;
      }
      if (!isObjectiveArtifactTypeValue(artifactKey)) {
        continue;
      }
      const artifactType = artifactKey as ObjectiveArtifactType;
      for (const filePath of entries) {
        const summary = `Manuel ${artifactType} kanıtı (${path.basename(filePath)})`;
        await appendEvidence(artifactType, 'other', filePath, summary);
      }
    }
  }

  if (options.qaLogs) {
    for (const qaPath of options.qaLogs) {
      const result = await importQaLogs(qaPath);
      warnings.push(...result.warnings);
      if (result.data.length === 0) {
        const summary = `QA denetim kaydı (${path.basename(qaPath)})`;
        await appendEvidence('qa_record', 'other', qaPath, summary);
        continue;
      }

      let row = 2;
      for (const entry of result.data) {
        const details: string[] = [];
        if (entry.objectiveId) {
          details.push(`hedef ${entry.objectiveId}`);
        }
        if (entry.artifact) {
          details.push(`artefakt ${entry.artifact}`);
        }
        if (entry.status) {
          details.push(`durum ${entry.status}`);
        }
        if (entry.reviewer) {
          details.push(`denetçi ${entry.reviewer}`);
        }
        if (entry.completedAt) {
          details.push(`tarih ${entry.completedAt}`);
        }
        const baseSummary = details.length > 0 ? details.join(', ') : `satır ${row}`;
        const summary = entry.notes
          ? `QA log kaydı (${baseSummary}; not: ${entry.notes})`
          : `QA log kaydı (${baseSummary})`;
        await appendEvidence('qa_record', 'other', qaPath, summary);
        row += 1;
      }
    }
  }

  if (options.traceLinksJson) {
    const result = await importTraceLinksJson(options.traceLinksJson);
    warnings.push(...result.warnings);
    if (result.links.length > 0) {
      manualTraceLinks.push(...result.links);
      await appendEvidence('trace', 'other', options.traceLinksJson, 'Manuel izlenebilirlik eşlemeleri (JSON)');
    }
  }

  const mergedRequirements = mergeRequirements(requirements);
  const generatedTraceLinks = buildTraceLinksFromTests(testResults);
  const { links: traceLinks, duplicatesRemoved } = mergeTraceLinks(
    manualTraceLinks,
    generatedTraceLinks,
  );
  if (duplicatesRemoved > 0) {
    warnings.push(
      'Birden fazla kaynaktan gelen yinelenen izlenebilirlik bağlantıları bulundu ve yok sayıldı.',
    );
  }
  const testToCodeMap = deriveTestToCodeMap(testResults, coverageMaps);

  const generatedAt = getCurrentTimestamp();
  const fingerprint = computeEvidenceFingerprint(evidenceIndex);
  const version = createSnapshotVersion(fingerprint, { createdAt: generatedAt });

  const workspace: ImportWorkspace = {
    requirements: mergedRequirements,
    designs: mergeDesigns(designs),
    testResults,
    coverage,
    structuralCoverage,
    traceLinks,
    testToCodeMap,
    evidenceIndex,
    git: gitMetadata,
    findings,
    builds,
    ...(fileHashes.length > 0 ? { fileHashes: [...fileHashes] } : {}),
    metadata: {
      generatedAt,
      warnings,
      inputs: normalizedInputs,
      project:
        options.projectName || options.projectVersion
          ? {
              name: options.projectName,
              version: options.projectVersion,
            }
          : undefined,
      targetLevel: options.level,
      objectivesPath: normalizedObjectivesPath,
      sources:
        Object.keys(sourceMetadata).length > 0
          ? sourceMetadata
          : undefined,
      version,
    },
  };

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
  stage?: SoiStage;
  baselineSnapshot?: string;
  baselineGitRef?: string;
  parasoft?: string[];
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
  version: SnapshotVersion;
  stage?: SoiStage;
  toolQualification?: ToolQualificationPackResult['summary'] & {
    tqpHref?: string;
    tarHref?: string;
  };
  changeImpact?: ChangeImpactScore[];
}

const loadObjectives = async (filePath: string): Promise<Objective[]> => {
  const content = await fsPromises.readFile(path.resolve(filePath), 'utf8');
  const data = JSON.parse(content) as Objective[];
  return data;
};

const filterObjectives = (objectives: Objective[], level: CertificationLevel): Objective[] => {
  return objectives.filter((objective) => objective.levels[level]);
};

const filterObjectivesByStage = (objectives: Objective[], stage?: SoiStage): Objective[] => {
  if (!stage) {
    return objectives;
  }
  return objectives.filter((objective) => objective.stage === stage);
};

const SOI_STAGE_SET = new Set<SoiStage>(soiStages);

const normalizeStageOption = (value: unknown): SoiStage | undefined => {
  if (value === undefined || value === null) {
    return undefined;
  }

  const candidate = Array.isArray(value) ? value[0] : value;
  if (candidate === undefined || candidate === null) {
    return undefined;
  }

  if (typeof candidate !== 'string') {
    throw new Error(
      `Geçersiz SOI aşaması değeri. Geçerli değerler: ${soiStages.join(', ')}.`,
    );
  }

  const normalized = candidate.trim().toUpperCase();
  if (!normalized) {
    return undefined;
  }

  if (!SOI_STAGE_SET.has(normalized as SoiStage)) {
    throw new Error(
      `Geçersiz SOI aşaması değeri. Geçerli değerler: ${soiStages.join(', ')}.`,
    );
  }

  return normalized as SoiStage;
};

const normalizeBaselineSnapshotOption = (value: unknown): string | undefined => {
  if (value === undefined || value === null) {
    return undefined;
  }

  const candidate = Array.isArray(value) ? value[0] : value;
  if (candidate === undefined || candidate === null) {
    return undefined;
  }

  if (typeof candidate !== 'string') {
    throw new Error(
      "'--baseline-snapshot' seçeneği için geçerli bir dosya yolu belirtilmelidir.",
    );
  }

  const resolvedPath = path.resolve(candidate);
  try {
    const raw = fs.readFileSync(resolvedPath, 'utf8');
    JSON.parse(raw);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(
      `Baseline snapshot JSON dosyası okunamadı (${candidate}): ${message}`,
    );
  }

  return resolvedPath;
};

const normalizeBaselineGitRefOption = (value: unknown): string | undefined => {
  if (value === undefined || value === null) {
    return undefined;
  }

  const candidate = Array.isArray(value) ? value[0] : value;
  if (candidate === undefined || candidate === null) {
    return undefined;
  }

  if (typeof candidate !== 'string') {
    throw new Error("'--baseline-git-ref' seçeneği için geçerli bir git referansı belirtilmelidir.");
  }

  const trimmed = candidate.trim();
  return trimmed || undefined;
};

const sortObjectives = (objectives: Objective[]): Objective[] => {
  return [...objectives].sort((a, b) => a.id.localeCompare(b.id, 'en') || a.name.localeCompare(b.name, 'en'));
};

const coverageArtifactLabels: Partial<Record<ObjectiveArtifactType, string>> = {
  coverage_stmt: 'Statement coverage evidence',
  coverage_dec: 'Decision coverage evidence',
  coverage_mcdc: 'MC/DC coverage evidence',
};

const certificationGatingConfig = {
  coverage_stmt: { fail: ['A', 'B'], warn: ['C'] },
  coverage_dec: { fail: ['A', 'B'], warn: ['C'] },
  coverage_mcdc: { fail: ['A'], warn: ['B', 'C'] },
} as const satisfies Partial<
  Record<ObjectiveArtifactType, { fail: readonly CertificationLevel[]; warn: readonly CertificationLevel[] }>
>;

interface CertificationGatingEvaluation {
  shouldFail: boolean;
  warnings: string[];
}

const evaluateCertificationGating = (
  level: CertificationLevel,
  objectives: ObjectiveCoverage[],
): CertificationGatingEvaluation => {
  const missingByArtifact = new Map<ObjectiveArtifactType, Set<string>>();

  objectives.forEach((objective) => {
    const missingArtifacts = objective.missingArtifacts ?? [];
    missingArtifacts.forEach((artifact) => {
      if (!missingByArtifact.has(artifact)) {
        missingByArtifact.set(artifact, new Set<string>());
      }
      missingByArtifact.get(artifact)!.add(objective.objectiveId);
    });
  });

  const warnings: string[] = [];
  let shouldFail = false;

  (Object.entries(certificationGatingConfig) as Array<
    [ObjectiveArtifactType, { fail: readonly CertificationLevel[]; warn: readonly CertificationLevel[] }]
  >).forEach(([artifact, config]) => {
    const missingObjectives = missingByArtifact.get(artifact);
    if (!missingObjectives || missingObjectives.size === 0) {
      return;
    }

    const label = coverageArtifactLabels[artifact] ?? artifact;
    const objectiveList = Array.from(missingObjectives).sort().join(', ');
    if (config.fail.includes(level)) {
      shouldFail = true;
      warnings.push(`Required ${label} missing for Level ${level} (Objectives: ${objectiveList}).`);
    } else if (config.warn.includes(level)) {
      warnings.push(`Level ${level} warning: ${label} missing (Objectives: ${objectiveList}).`);
    }
  });

  return { shouldFail, warnings };
};

export interface ListObjectivesOptions {
  objectives?: string;
  level?: CertificationLevel;
}

export interface ListObjectivesResult {
  sourcePath: string;
  objectives: Objective[];
}

export const runObjectivesList = async (
  options: ListObjectivesOptions = {},
): Promise<ListObjectivesResult> => {
  const fallbackObjectivesPath = path.resolve('data', 'objectives', 'do178c_objectives.min.json');
  const objectivesPathRaw = options.objectives ?? fallbackObjectivesPath;
  const objectivesPath = path.resolve(objectivesPathRaw);
  const allObjectives = await loadObjectives(objectivesPath);
  const filtered = options.level ? filterObjectives(allObjectives, options.level) : allObjectives;
  const sorted = sortObjectives(filtered);
  return {
    sourcePath: objectivesPath,
    objectives: sorted,
  };
};

const formatLevelApplicability = (levels: Objective['levels']): string => {
  const applicable = certificationLevels.filter((level) => levels[level]);
  return applicable.join(', ');
};

const formatObjectivesTable = (objectives: Objective[]): string => {
  if (objectives.length === 0) {
    return 'No objectives matched the selected filters.';
  }

  const columns = [
    { key: 'id', label: 'ID', getter: (objective: Objective) => objective.id },
    { key: 'table', label: 'Table', getter: (objective: Objective) => objective.table },
    {
      key: 'levels',
      label: 'Levels',
      getter: (objective: Objective) => formatLevelApplicability(objective.levels),
    },
    {
      key: 'independence',
      label: 'Independence',
      getter: (objective: Objective) => objective.independence,
    },
    {
      key: 'artifacts',
      label: 'Artifacts',
      getter: (objective: Objective) => objective.artifacts.join(', '),
    },
    { key: 'name', label: 'Title', getter: (objective: Objective) => objective.name },
  ] as const;

  const widths = columns.reduce<Record<string, number>>((acc, column) => {
    const values = objectives.map((objective) => column.getter(objective));
    const maxValue = Math.max(column.label.length, ...values.map((value) => value.length));
    acc[column.key] = maxValue;
    return acc;
  }, {});

  const header = columns.map((column) => column.label.padEnd(widths[column.key])).join('  ').trimEnd();
  const separator = columns
    .map((column) => ''.padEnd(Math.max(widths[column.key], column.label.length), '-'))
    .join('  ')
    .trimEnd();

  const indent = columns.slice(0, columns.length - 1).reduce((acc, column) => acc + widths[column.key] + 2, 0);
  const descriptionIndent = ' '.repeat(Math.max(indent, 0));

  const lines: string[] = [header, separator];

  objectives.forEach((objective) => {
    const row = columns
      .map((column) => column.getter(objective).padEnd(widths[column.key]))
      .join('  ')
      .trimEnd();
    lines.push(row);
    lines.push(`${descriptionIndent}  ${objective.desc}`.trimEnd());
  });

  return lines.join('\n');
};

const parseBaselineTraceGraph = (
  raw: string,
  label: string,
  warnings: string[],
): TraceGraph | undefined => {
  try {
    const parsed = JSON.parse(raw) as { traceGraph?: TraceGraph } | null;
    const candidate = parsed?.traceGraph;
    if (candidate && Array.isArray(candidate.nodes)) {
      return candidate;
    }
    warnings.push(
      `Baseline snapshot ${label} iz grafiği içermiyor; değişiklik etkisi hesaplanamadı.`,
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    warnings.push(`Baseline snapshot ${label} okunamadı: ${message}.`);
  }
  return undefined;
};

const readBaselineSnapshotFromGit = async (
  ref: string,
  snapshotPath: string,
  cwd?: string,
): Promise<string> => {
  try {
    const { stdout } = await execFileAsync('git', ['show', `${ref}:${snapshotPath}`], {
      cwd,
      encoding: 'utf8',
      maxBuffer: DEFAULT_GIT_SHOW_MAX_BUFFER,
    });
    return stdout;
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER') {
      return await new Promise<string>((resolve, reject) => {
        const child = spawn('git', ['show', `${ref}:${snapshotPath}`], {
          cwd,
          stdio: ['ignore', 'pipe', 'pipe'],
        });
        let stdout = '';
        let stderr = '';
        child.stdout?.setEncoding('utf8');
        child.stdout?.on('data', (chunk: string) => {
          stdout += chunk;
        });
        child.stderr?.setEncoding('utf8');
        child.stderr?.on('data', (chunk: string) => {
          stderr += chunk;
        });
        child.on('error', reject);
        child.on('close', (code) => {
          if (code === 0) {
            resolve(stdout);
          } else {
            const message = stderr.trim() || `git show exited with code ${code}`;
            reject(new Error(message));
          }
        });
      });
    }
    throw error;
  }
};

const loadBaselineTraceGraph = async (options: {
  baselineSnapshot?: string;
  baselineGitRef?: string;
  gitSnapshotPath?: string;
  cwd?: string;
}): Promise<{ traceGraph?: TraceGraph; warnings: string[] }> => {
  const warnings: string[] = [];
  if (options.baselineSnapshot) {
    const baselinePath = path.resolve(options.baselineSnapshot);
    try {
      const raw = await fsPromises.readFile(baselinePath, 'utf8');
      const label = path.relative(process.cwd(), baselinePath) || baselinePath;
      return {
        traceGraph: parseBaselineTraceGraph(raw, label, warnings),
        warnings,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const label = path.relative(process.cwd(), baselinePath) || baselinePath;
      warnings.push(`Baseline snapshot ${label} okunamadı: ${message}.`);
      return { warnings };
    }
  }

  if (options.baselineGitRef) {
    const snapshotPath = options.gitSnapshotPath ?? DEFAULT_BASELINE_GIT_SNAPSHOT_PATH;
    const normalizedSnapshotPath = snapshotPath.split(path.sep).join('/');
    try {
      const raw = await readBaselineSnapshotFromGit(
        options.baselineGitRef,
        normalizedSnapshotPath,
        options.cwd,
      );
      return {
        traceGraph: parseBaselineTraceGraph(
          raw,
          `${options.baselineGitRef}:${normalizedSnapshotPath}`,
          warnings,
        ),
        warnings,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      warnings.push(
        `Git referansı ${options.baselineGitRef} için baseline snapshot okunamadı (${normalizedSnapshotPath}): ${message}.`,
      );
      return { warnings };
    }
  }

  return { warnings };
};

const buildImportBundle = (
  workspace: ImportWorkspace,
  objectives: Objective[],
  level: CertificationLevel,
): ImportBundle => ({
  requirements: workspace.requirements,
  designs: workspace.designs,
  objectives,
  testResults: workspace.testResults,
  coverage: workspace.coverage,
  structuralCoverage: workspace.structuralCoverage,
  evidenceIndex: workspace.evidenceIndex,
  traceLinks: uniqueTraceLinks(workspace.traceLinks ?? []),
  testToCodeMap: workspace.testToCodeMap,
  findings: workspace.findings,
  generatedAt: workspace.metadata.generatedAt,
  targetLevel: level,
  snapshot: workspace.metadata.version,
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

  const augmentedWorkspace: ImportWorkspace = {
    ...workspace,
    requirements: [...workspace.requirements],
    designs: [...workspace.designs],
    testResults: [...workspace.testResults],
    coverage: workspace.coverage,
    structuralCoverage: workspace.structuralCoverage
      ? mergeStructuralCoverage(undefined, workspace.structuralCoverage)
      : undefined,
    traceLinks: [...workspace.traceLinks],
    testToCodeMap: { ...workspace.testToCodeMap },
    evidenceIndex: workspace.evidenceIndex,
    git: workspace.git,
    findings: [...workspace.findings],
    builds: [...workspace.builds],
    fileHashes: workspace.fileHashes ? [...workspace.fileHashes] : undefined,
    metadata: {
      ...workspace.metadata,
      inputs: { ...(workspace.metadata.inputs ?? {}) },
      sources: workspace.metadata.sources ? { ...workspace.metadata.sources } : undefined,
    },
  };

  const parasoftWarnings: string[] = [];

  if (options.parasoft && options.parasoft.length > 0) {
    const normalizedParasoftInputs = [...(augmentedWorkspace.metadata.inputs.parasoft ?? [])];
    const hashMap = new Map<string, ImportedFileHash>();
    augmentedWorkspace.fileHashes?.forEach((entry) => {
      hashMap.set(entry.path, entry);
    });

    const parasoftSourceSummary: ExternalSourceMetadata['parasoft'] =
      augmentedWorkspace.metadata.sources?.parasoft ?? {
        reports: [],
        totalTests: 0,
        totalFindings: 0,
        coverageFiles: 0,
        fileHashes: 0,
      };

    for (const reportPath of options.parasoft) {
      const result = await importParasoft(reportPath);
      parasoftWarnings.push(...result.warnings);
      normalizedParasoftInputs.push(normalizeRelativePath(reportPath));

      const reportData = result.data;
      if (reportData.testResults && reportData.testResults.length > 0) {
        augmentedWorkspace.testResults.push(...reportData.testResults);
        parasoftSourceSummary.totalTests += reportData.testResults.length;
      }

      if (reportData.coverage) {
        augmentedWorkspace.structuralCoverage = mergeStructuralCoverage(
          augmentedWorkspace.structuralCoverage,
          reportData.coverage,
        );
        parasoftSourceSummary.coverageFiles += reportData.coverage.files.length;
      }

      if (reportData.findings && reportData.findings.length > 0) {
        augmentedWorkspace.findings.push(...reportData.findings);
        parasoftSourceSummary.totalFindings += reportData.findings.length;
      }

      if (reportData.fileHashes && reportData.fileHashes.length > 0) {
        reportData.fileHashes.forEach((entry) => {
          hashMap.set(entry.path, entry);
        });
      }

      parasoftSourceSummary.reports.push({
        file: normalizeRelativePath(reportPath),
        tests: reportData.testResults?.length ?? 0,
        findings: reportData.findings?.length ?? 0,
        coverageFiles: reportData.coverage?.files.length ?? 0,
        fileHashes: reportData.fileHashes?.length ?? 0,
        warnings: [...result.warnings],
      });
    }

    const uniqueInputs = Array.from(new Set(normalizedParasoftInputs));
    if (uniqueInputs.length > 0) {
      augmentedWorkspace.metadata.inputs.parasoft = uniqueInputs;
    }

    const mergedHashes = hashMap.size > 0 ? Array.from(hashMap.values()) : undefined;
    augmentedWorkspace.fileHashes = mergedHashes
      ? mergedHashes.sort((a, b) => a.path.localeCompare(b.path))
      : augmentedWorkspace.fileHashes;

    if (!augmentedWorkspace.metadata.sources) {
      augmentedWorkspace.metadata.sources = {};
    }
    augmentedWorkspace.metadata.sources.parasoft = parasoftSourceSummary;
  }

  const level = options.level ?? augmentedWorkspace.metadata.targetLevel ?? 'C';
  const fallbackObjectivesPath = path.resolve('data', 'objectives', 'do178c_objectives.min.json');
  const objectivesPathRaw =
    options.objectives ?? augmentedWorkspace.metadata.objectivesPath ?? fallbackObjectivesPath;
  const objectivesPath = path.resolve(objectivesPathRaw);
  const objectives = await loadObjectives(objectivesPath);
  const filteredObjectives = filterObjectivesByStage(
    filterObjectives(objectives, level),
    options.stage,
  );

  const bundle = buildImportBundle(augmentedWorkspace, filteredObjectives, level);
  const { traceGraph: baselineTraceGraph, warnings: baselineWarnings } =
    await loadBaselineTraceGraph({
      baselineSnapshot: options.baselineSnapshot,
      baselineGitRef: options.baselineGitRef,
    });

  const snapshot = generateComplianceSnapshot(
    bundle,
    baselineTraceGraph ? { changeImpactBaseline: baselineTraceGraph } : undefined,
  );
  const engine = new TraceEngine(bundle);
  const traces = collectRequirementTraces(engine, augmentedWorkspace.requirements);

  const gatingEvaluation = evaluateCertificationGating(level, snapshot.objectives);

  const outputDir = path.resolve(options.output);
  await ensureDirectory(outputDir);

  const snapshotPath = path.join(outputDir, 'snapshot.json');
  const tracePath = path.join(outputDir, 'traces.json');
  const analysisPath = path.join(outputDir, 'analysis.json');

  const analysisGeneratedAt = getCurrentTimestamp();
  const analysisMetadata: AnalysisMetadata = {
    project:
      options.projectName || options.projectVersion || augmentedWorkspace.metadata.project
        ? {
            name: options.projectName ?? augmentedWorkspace.metadata.project?.name,
            version: options.projectVersion ?? augmentedWorkspace.metadata.project?.version,
          }
        : undefined,
    level,
    generatedAt: analysisGeneratedAt,
    version: snapshot.version,
    stage: options.stage,
    ...(snapshot.changeImpact ? { changeImpact: snapshot.changeImpact } : {}),
  };

  await writeJsonFile(snapshotPath, snapshot);
  await writeJsonFile(tracePath, traces);
  const analysisWarnings = [
    ...(augmentedWorkspace.metadata.warnings ?? []),
    ...parasoftWarnings,
    ...gatingEvaluation.warnings,
    ...baselineWarnings,
  ];
  await writeJsonFile(analysisPath, {
    metadata: analysisMetadata,
    objectives: filteredObjectives,
    objectiveCoverage: snapshot.objectives,
    gaps: snapshot.gaps,
    requirements: augmentedWorkspace.requirements,
    designs: augmentedWorkspace.designs,
    tests: augmentedWorkspace.testResults,
    coverage: augmentedWorkspace.coverage,
    evidenceIndex: augmentedWorkspace.evidenceIndex,
    git: augmentedWorkspace.git,
    inputs: augmentedWorkspace.metadata.inputs,
    warnings: analysisWarnings,
    qualityFindings: snapshot.qualityFindings,
    traceSuggestions: snapshot.traceSuggestions,
  });

  const exitCode = gatingEvaluation.shouldFail ? exitCodes.missingEvidence : exitCodes.success;

  return { snapshotPath, tracePath, analysisPath, exitCode };
};

export interface ReportOptions {
  input: string;
  output: string;
  manifestId?: string;
  planConfig?: string;
  planOverrides?: PlanSectionOverrides;
  stage?: SoiStage;
  toolUsage?: string;
  gsn?: boolean;
}

export interface GeneratedPlanOutput {
  id: PlanTemplateId;
  title: string;
  html: string;
  docx: string;
  pdf?: string;
}

export interface ReportResult {
  complianceHtml: string;
  complianceJson: string;
  complianceCsv: string;
  traceHtml: string;
  traceCsv: string;
  gapsHtml: string;
  plans: Record<PlanTemplateId, GeneratedPlanOutput>;
  warnings: string[];
  gsnGraphDot?: string;
  toolQualification?: {
    tqp: string;
    tar: string;
    summary: ToolQualificationPackResult['summary'];
  };
}

const planTemplateIdList = Object.keys(planTemplateSections) as PlanTemplateId[];

const isPlanTemplateId = (value: string): value is PlanTemplateId =>
  (planTemplateSections as Record<string, unknown>)[value] !== undefined;

const mergePlanOverrideEntry = (
  base: PlanOverrideConfig | undefined,
  incoming: PlanOverrideConfig,
): PlanOverrideConfig => {
  const result: PlanOverrideConfig = { ...(base ?? {}) };

  if (incoming.overview !== undefined) {
    result.overview = incoming.overview;
  }

  if (incoming.additionalNotes !== undefined) {
    result.additionalNotes = incoming.additionalNotes;
  }

  if (incoming.sections) {
    result.sections = { ...(base?.sections ?? {}), ...incoming.sections };
  }

  return result;
};

const mergePlanOverrides = (
  base: PlanSectionOverrides | undefined,
  incoming?: PlanSectionOverrides,
): PlanSectionOverrides | undefined => {
  if (!incoming) {
    return base;
  }

  const result: PlanSectionOverrides = { ...(base ?? {}) };

  Object.entries(incoming).forEach(([planId, override]) => {
    if (!override || !isPlanTemplateId(planId)) {
      return;
    }
    const typedId = planId as PlanTemplateId;
    result[typedId] = mergePlanOverrideEntry(result[typedId], override);
  });

  return Object.keys(result).length > 0 ? result : undefined;
};

const parsePlanOverrides = (data: unknown): PlanSectionOverrides => {
  if (!data || typeof data !== 'object') {
    return {};
  }

  const overrides: PlanSectionOverrides = {};

  Object.entries(data as Record<string, unknown>).forEach(([planId, rawOverride]) => {
    if (!isPlanTemplateId(planId) || !rawOverride || typeof rawOverride !== 'object') {
      return;
    }

    const typedId = planId as PlanTemplateId;
    const entry = rawOverride as Record<string, unknown>;
    const override: PlanOverrideConfig = {};

    if (typeof entry.overview === 'string') {
      override.overview = entry.overview;
    }

    if (typeof entry.additionalNotes === 'string') {
      override.additionalNotes = entry.additionalNotes;
    }

    if (entry.sections && typeof entry.sections === 'object') {
      const sections: Record<string, string> = {};
      Object.entries(entry.sections as Record<string, unknown>).forEach(([sectionId, value]) => {
        if (typeof value === 'string') {
          sections[sectionId] = value;
        }
      });
      if (Object.keys(sections).length > 0) {
        override.sections = sections;
      }
    }

    if (Object.keys(override).length > 0) {
      overrides[typedId] = override;
    }
  });

  return overrides;
};

interface PlanGenerationPlanEntry {
  id: PlanTemplateId;
  overrides?: PlanOverrideConfig;
}

interface PlanGenerationConfig {
  snapshotPath: string;
  objectivesPath?: string;
  outputDir: string;
  manifestPath: string;
  manifestId?: string;
  project?: { name?: string; version?: string };
  level?: CertificationLevel;
  generatedAt?: string;
  plans: PlanGenerationPlanEntry[];
}

const parsePlanGenerationConfig = (
  data: unknown,
  baseDir: string,
): PlanGenerationConfig => {
  if (!data || typeof data !== 'object') {
    throw new Error('Plan configuration must be a JSON object.');
  }

  const record = data as Record<string, unknown>;

  const snapshotValue = record.snapshot;
  if (typeof snapshotValue !== 'string' || snapshotValue.trim().length === 0) {
    throw new Error('Plan configuration requires a "snapshot" path.');
  }
  const snapshotPath = path.resolve(baseDir, snapshotValue);

  const outputValue = record.outputDir;
  if (typeof outputValue !== 'string' || outputValue.trim().length === 0) {
    throw new Error('Plan configuration requires an "outputDir".');
  }
  const outputDir = path.resolve(baseDir, outputValue);

  const manifestValue = record.manifestPath;
  const manifestPath =
    typeof manifestValue === 'string' && manifestValue.trim().length > 0
      ? path.resolve(baseDir, manifestValue)
      : path.join(outputDir, 'plans-manifest.json');

  const objectivesValue = record.objectives;
  const objectivesPath =
    typeof objectivesValue === 'string' && objectivesValue.trim().length > 0
      ? path.resolve(baseDir, objectivesValue)
      : undefined;

  const manifestId = typeof record.manifestId === 'string' ? record.manifestId : undefined;
  const generatedAt = typeof record.generatedAt === 'string' ? record.generatedAt : undefined;

  let project: { name?: string; version?: string } | undefined;
  if (record.project && typeof record.project === 'object') {
    const projectRecord = record.project as Record<string, unknown>;
    const name = typeof projectRecord.name === 'string' ? projectRecord.name : undefined;
    const version = typeof projectRecord.version === 'string' ? projectRecord.version : undefined;
    if (name || version) {
      project = { name, version };
    }
  }

  let level: CertificationLevel | undefined;
  if (typeof record.level === 'string' && record.level.trim().length > 0) {
    const candidate = record.level.toUpperCase() as CertificationLevel;
    if (!certificationLevels.includes(candidate)) {
      throw new Error(`Unsupported certification level: ${record.level}`);
    }
    level = candidate;
  }

  const plansValue = record.plans;
  if (!Array.isArray(plansValue) || plansValue.length === 0) {
    throw new Error('Plan configuration must include a non-empty "plans" array.');
  }

  const plans: PlanGenerationPlanEntry[] = plansValue.map((entry, index) => {
    if (!entry || typeof entry !== 'object') {
      throw new Error(`Plan entry at index ${index} must be an object.`);
    }

    const entryRecord = entry as Record<string, unknown>;
    const idValue = entryRecord.id;
    if (typeof idValue !== 'string' || !isPlanTemplateId(idValue)) {
      throw new Error(`Invalid plan template identifier at index ${index}: ${idValue}`);
    }

    let overrides: PlanOverrideConfig | undefined;
    if (entryRecord.overrides && typeof entryRecord.overrides === 'object') {
      const parsed = parsePlanOverrides({ [idValue]: entryRecord.overrides });
      overrides = parsed[idValue];
    }

    return { id: idValue, overrides };
  });

  return {
    snapshotPath,
    objectivesPath,
    outputDir,
    manifestPath,
    manifestId,
    project,
    level,
    generatedAt,
    plans,
  };
};

export interface GeneratePlansOptions {
  config: string;
}

export interface GeneratedPlanArtifact {
  id: PlanTemplateId;
  title: string;
  pdfPath: string;
  docxPath: string;
  pdfSha256: string;
  docxSha256: string;
}

export interface GeneratePlansResult {
  outputDir: string;
  manifestPath: string;
  plans: GeneratedPlanArtifact[];
}

export const runGeneratePlans = async (
  options: GeneratePlansOptions,
): Promise<GeneratePlansResult> => {
  const configPath = path.resolve(options.config);
  const configDir = path.dirname(configPath);
  const rawConfig = await readJsonFile<unknown>(configPath);
  const config = parsePlanGenerationConfig(rawConfig, configDir);

  const snapshot = await readJsonFile<ComplianceSnapshot>(config.snapshotPath);
  const objectives = config.objectivesPath
    ? await readJsonFile<Objective[]>(config.objectivesPath)
    : undefined;

  await ensureDirectory(config.outputDir);
  await ensureDirectory(path.dirname(config.manifestPath));

  const planResults: GeneratedPlanArtifact[] = [];

  for (const plan of config.plans) {
    const planOptions: PlanRenderOptions = {
      snapshot,
      objectivesMetadata: objectives,
      manifestId: config.manifestId,
      project: config.project,
      level: config.level,
      generatedAt: config.generatedAt,
      overview: plan.overrides?.overview,
      sections: plan.overrides?.sections,
      additionalNotes: plan.overrides?.additionalNotes,
    };

    const planDocument = await renderPlanDocument(plan.id, planOptions);
    const pdfBuffer = await renderPlanPdf(plan.id, planOptions);

    const docxPath = path.join(config.outputDir, `${plan.id}.docx`);
    const pdfPath = path.join(config.outputDir, `${plan.id}.pdf`);

    await fsPromises.writeFile(docxPath, planDocument.docx);
    await fsPromises.writeFile(pdfPath, pdfBuffer);

    const docxSha256 = createHash('sha256').update(planDocument.docx).digest('hex');
    const pdfSha256 = createHash('sha256').update(pdfBuffer).digest('hex');

    planResults.push({
      id: plan.id,
      title: planDocument.title,
      docxPath,
      pdfPath,
      docxSha256,
      pdfSha256,
    });
  }

  const manifest = {
    generatedAt: getCurrentTimestamp(),
    plans: planResults.map((plan) => ({
      id: plan.id,
      title: plan.title,
      outputs: [
        {
          format: 'pdf',
          path: path.relative(config.outputDir, plan.pdfPath),
          sha256: plan.pdfSha256,
        },
        {
          format: 'docx',
          path: path.relative(config.outputDir, plan.docxPath),
          sha256: plan.docxSha256,
        },
      ],
    })),
  };

  await writeJsonFile(config.manifestPath, manifest);

  return {
    outputDir: config.outputDir,
    manifestPath: config.manifestPath,
    plans: planResults,
  };
};

const remediationPriorityLabels: Record<RemediationPlan['actions'][number]['priority'], string> = {
  critical: 'Kritik',
  high: 'Yüksek',
  medium: 'Orta',
  low: 'Düşük',
};

const gapCategoryLabels: Record<Exclude<keyof GapAnalysis, 'staleEvidence'>, string> = {
  analysis: 'Analiz',
  tests: 'Test',
  coverage: 'Kapsam',
  trace: 'İzlenebilirlik',
  reviews: 'Gözden geçirme',
  plans: 'Plan',
  standards: 'Standart',
  configuration: 'Konfigürasyon yönetimi',
  quality: 'Kalite',
  issues: 'Problem raporları',
  conformity: 'Uygunluk',
};

const independenceLevelLabels: Record<Objective['independence'], string> = {
  none: 'Bağımsızlık gerekmiyor',
  recommended: 'Önerilen bağımsızlık',
  required: 'Zorunlu bağımsızlık',
};

type RemediationArtifactKey = ObjectiveArtifactType | 'design';

const remediationArtifactLabels: Record<RemediationArtifactKey, string> = {
  plan: 'Plan',
  standard: 'Standart',
  review: 'Gözden geçirme',
  analysis: 'Analiz',
  test: 'Test',
  coverage_stmt: 'Statement kapsamı',
  coverage_dec: 'Decision kapsamı',
  coverage_mcdc: 'MC/DC kapsamı',
  trace: 'İzlenebilirlik',
  cm_record: 'Konfigürasyon kaydı',
  qa_record: 'Kalite kaydı',
  problem_report: 'Problem raporu',
  conformity: 'Uygunluk kaydı',
  design: 'Tasarım artefaktı',
};

const formatRemediationArtifacts = (
  artifacts: readonly (ObjectiveArtifactType | 'design')[],
): string => {
  if (!artifacts.length) {
    return 'Eksik artefakt yok';
  }
  return artifacts
    .map((artifact) => remediationArtifactLabels[artifact as RemediationArtifactKey] ?? artifact)
    .join(', ');
};

const renderRemediationPlanMarkdown = (
  plan: RemediationPlan,
  options: { snapshot?: ComplianceSnapshot; objectives?: Map<string, Objective> } = {},
): string => {
  const lines: string[] = ['# İyileştirme Planı', ''];

  if (options.snapshot) {
    lines.push(`- Snapshot sürümü: \`${options.snapshot.version.id}\``);
    lines.push(`- Snapshot tarihi: ${options.snapshot.generatedAt}`);
    lines.push('');
  }

  lines.push(`Toplam aksiyon: **${plan.actions.length}**`);
  lines.push('');

  if (plan.actions.length === 0) {
    lines.push('Eksik kanıt veya bağımsızlık eksikliği bulunamadı.');
    return lines.join('\n');
  }

  plan.actions.forEach((action, index) => {
    const objective = options.objectives?.get(action.objectiveId);
    const headingLabel = objective
      ? `${objective.id} – ${objective.name}`
      : action.objectiveId;

    lines.push(`## ${index + 1}. ${headingLabel}`);

    const metadataLines: string[] = [`- Öncelik: **${remediationPriorityLabels[action.priority]}**`];
    if (objective) {
      metadataLines.push(`- SOI aşaması: ${objective.stage}`);
      metadataLines.push(`- Tablo: ${objective.table}`);
    }
    lines.push(...metadataLines);
    lines.push('- Eksik alanlar:');

    action.issues.forEach((issue) => {
      if (issue.type === 'gap') {
        const categoryLabel = gapCategoryLabels[issue.category] ?? issue.category;
        lines.push(
          `  - ${categoryLabel}: ${formatRemediationArtifacts(issue.missingArtifacts)}`,
        );
      } else {
        const independenceLabel = independenceLevelLabels[issue.independence] ?? issue.independence;
        lines.push(
          `  - ${independenceLabel}: ${formatRemediationArtifacts(issue.missingArtifacts)}`,
        );
      }
    });

    lines.push('');
  });

  return lines.join('\n');
};

export interface RemediationPlanOptions {
  snapshot: string;
  output: string;
  objectives?: string;
}

export interface RemediationPlanResult {
  markdownPath: string;
  jsonPath: string;
  actions: number;
}

export const runRemediationPlan = async (
  options: RemediationPlanOptions,
): Promise<RemediationPlanResult> => {
  const snapshotPath = path.resolve(options.snapshot);
  const outputDir = path.resolve(options.output);
  const objectivesPath = options.objectives ? path.resolve(options.objectives) : undefined;

  const snapshot = await readJsonFile<ComplianceSnapshot>(snapshotPath);

  let objectiveMap: Map<string, Objective> | undefined;
  if (objectivesPath) {
    const objectiveList = await readJsonFile<Objective[]>(objectivesPath);
    objectiveMap = new Map(objectiveList.map((objective) => [objective.id, objective]));
  }

  const plan = computeRemediationPlan({
    gaps: snapshot.gaps,
    independenceSummary: snapshot.independenceSummary,
  });

  await ensureDirectory(outputDir);

  const markdownContent = `${renderRemediationPlanMarkdown(plan, {
    snapshot,
    objectives: objectiveMap,
  })}\n`;
  const markdownPath = path.join(outputDir, 'remediation-plan.md');
  const jsonPath = path.join(outputDir, 'remediation-plan.json');

  await fsPromises.writeFile(markdownPath, markdownContent, 'utf8');
  await writeJsonFile(jsonPath, plan);

  return {
    markdownPath,
    jsonPath,
    actions: plan.actions.length,
  };
};

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
    coverage?: CoverageReport;
    evidenceIndex: EvidenceIndex;
    git?: BuildInfo | null;
    inputs: ImportPaths;
    warnings: string[];
    qualityFindings: ComplianceSnapshot['qualityFindings'];
    traceSuggestions: ComplianceSnapshot['traceSuggestions'];
  }>(analysisPath);
  const snapshot = await readJsonFile<ComplianceSnapshot>(snapshotPath);
  const traces = await readJsonFile<RequirementTrace[]>(tracePath);
  const planConfigPath = options.planConfig ? path.resolve(options.planConfig) : undefined;
  const configOverrides = planConfigPath
    ? parsePlanOverrides(await readJsonFile<unknown>(planConfigPath))
    : undefined;
  const planOverrides = mergePlanOverrides(configOverrides, options.planOverrides);
  const toolUsagePath = options.toolUsage ? path.resolve(options.toolUsage) : undefined;

  let toolQualificationPack: ToolQualificationPackResult | undefined;
  let toolQualificationLinks:
    | {
        tqpHref: string;
        tarHref: string;
        generatedAt: string;
        tools: ToolQualificationPackResult['summary']['tools'];
      }
    | undefined;
  if (toolUsagePath) {
    const toolUsageData = await readJsonFile<unknown>(toolUsagePath);
    if (!Array.isArray(toolUsageData)) {
      throw new Error('Tool usage metadata must be an array of tool descriptors.');
    }
    toolQualificationPack = renderToolQualificationPack(toolUsageData as ToolUsageMetadata[], {
      programName: analysis.metadata.project?.name,
      level: analysis.metadata.level,
      generatedAt: analysis.metadata.generatedAt,
    });
    toolQualificationLinks = {
      tqpHref: path.posix.join('tool-qualification', toolQualificationPack.tqp.filename),
      tarHref: path.posix.join('tool-qualification', toolQualificationPack.tar.filename),
      generatedAt: toolQualificationPack.summary.generatedAt,
      tools: toolQualificationPack.summary.tools,
    };
  }

  const programName = analysis.metadata.project?.name;
  const projectVersion = analysis.metadata.project?.version;
  const certificationLevel = analysis.metadata.level;

  const compliance = renderComplianceMatrix(snapshot, {
    objectivesMetadata: analysis.objectives,
    manifestId: options.manifestId,
    generatedAt: analysis.metadata.generatedAt,
    title: analysis.metadata.project?.name
      ? `${analysis.metadata.project.name} Uyum Matrisi`
      : 'SOIPack Uyum Matrisi',
    git: analysis.git,
    snapshotId: snapshot.version.id,
    snapshotVersion: snapshot.version,
    programName,
    certificationLevel,
    projectVersion,
    ...(toolQualificationLinks ? { toolQualification: toolQualificationLinks } : {}),
  });
  const traceReport = renderTraceMatrix(traces, {
    generatedAt: analysis.metadata.generatedAt,
    title: analysis.metadata.project?.name
      ? `${analysis.metadata.project.name} İzlenebilirlik Matrisi`
      : 'SOIPack İzlenebilirlik Matrisi',
    coverage: snapshot.requirementCoverage,
    suggestions: snapshot.traceSuggestions,
    git: analysis.git,
    snapshotId: snapshot.version.id,
    snapshotVersion: snapshot.version,
    programName,
    certificationLevel,
    projectVersion,
  });
  const gapsHtml = renderGaps(snapshot, {
    objectivesMetadata: analysis.objectives,
    manifestId: options.manifestId,
    generatedAt: analysis.metadata.generatedAt,
    title: analysis.metadata.project?.name
      ? `${analysis.metadata.project.name} Kanıt Boşlukları`
      : 'SOIPack Uyumluluk Boşlukları',
    git: analysis.git,
    snapshotId: snapshot.version.id,
    snapshotVersion: snapshot.version,
    programName,
    certificationLevel,
    projectVersion,
  });

  const outputDir = path.resolve(options.output);
  await ensureDirectory(outputDir);

  const complianceHtmlPath = path.join(outputDir, 'compliance.html');
  const complianceJsonPath = path.join(outputDir, 'compliance.json');
  const complianceCsvPath = path.join(outputDir, 'compliance.csv');
  const traceHtmlPath = path.join(outputDir, 'trace.html');
  const traceCsvPath = path.join(outputDir, 'trace.csv');
  const gapsHtmlPath = path.join(outputDir, 'gaps.html');
  let toolQualificationPaths: { tqp: string; tar: string } | undefined;
  let gsnGraphDotPath: string | undefined;

  await fsPromises.copyFile(snapshotPath, path.join(outputDir, 'snapshot.json'));
  await fsPromises.copyFile(tracePath, path.join(outputDir, 'traces.json'));

  await fsPromises.writeFile(complianceHtmlPath, compliance.html, 'utf8');
  await writeJsonFile(complianceJsonPath, compliance.json);
  await fsPromises.writeFile(complianceCsvPath, compliance.csv.csv, 'utf8');
  await fsPromises.writeFile(traceHtmlPath, traceReport.html, 'utf8');
  await fsPromises.writeFile(traceCsvPath, traceReport.csv.csv, 'utf8');
  await fsPromises.writeFile(gapsHtmlPath, gapsHtml, 'utf8');

  if (options.gsn) {
    const gsnDir = path.join(outputDir, 'gsn');
    await ensureDirectory(gsnDir);
    gsnGraphDotPath = path.join(gsnDir, 'gsn-graph.dot');
    const gsnDot = renderGsnGraphDotReport(snapshot, {
      objectivesMetadata: analysis.objectives,
    });
    await fsPromises.writeFile(gsnGraphDotPath, gsnDot, 'utf8');
  }

  if (toolQualificationPack) {
    const toolQualificationDir = path.join(outputDir, 'tool-qualification');
    await ensureDirectory(toolQualificationDir);
    const tqpPath = path.join(toolQualificationDir, toolQualificationPack.tqp.filename);
    const tarPath = path.join(toolQualificationDir, toolQualificationPack.tar.filename);
    await fsPromises.writeFile(tqpPath, toolQualificationPack.tqp.content, 'utf8');
    await fsPromises.writeFile(tarPath, toolQualificationPack.tar.content, 'utf8');
    toolQualificationPaths = { tqp: tqpPath, tar: tarPath };
  }

  const plansDir = path.join(outputDir, 'plans');
  await ensureDirectory(plansDir);

  const planWarnings: string[] = [];
  const plans = {} as Record<PlanTemplateId, GeneratedPlanOutput>;

  for (const planId of planTemplateIdList) {
    const override = planOverrides?.[planId];
    const planDocument = await renderPlanDocument(planId, {
      snapshot,
      objectivesMetadata: analysis.objectives,
      manifestId: options.manifestId,
      project: analysis.metadata.project,
      level: analysis.metadata.level,
      generatedAt: analysis.metadata.generatedAt,
      overview: override?.overview,
      sections: override?.sections,
      additionalNotes: override?.additionalNotes,
    });

    const baseName = planId;
    const htmlPath = path.join(plansDir, `${baseName}.html`);
    const docxPath = path.join(plansDir, `${baseName}.docx`);
    await fsPromises.writeFile(htmlPath, planDocument.html, 'utf8');
    await fsPromises.writeFile(docxPath, planDocument.docx);

    let pdfPath: string | undefined;
    try {
      const pdfBuffer = await printToPDF(planDocument.html, {
        manifestId: options.manifestId,
        generatedAt: analysis.metadata.generatedAt,
      });
      pdfPath = path.join(plansDir, `${baseName}.pdf`);
      await fsPromises.writeFile(pdfPath, pdfBuffer);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      planWarnings.push(`PDF generation for ${planTemplateTitles[planId]} failed: ${message}`);
    }

    plans[planId] = {
      id: planId,
      title: planTemplateTitles[planId],
      html: htmlPath,
      docx: docxPath,
      pdf: pdfPath,
    };
  }

  const augmentedWarnings =
    planWarnings.length > 0 ? [...analysis.warnings, ...planWarnings] : analysis.warnings;
  const metadataWithToolQualification = toolQualificationPack
    ? {
        ...analysis.metadata,
        toolQualification: {
          ...toolQualificationPack.summary,
          tqpHref: toolQualificationLinks?.tqpHref,
          tarHref: toolQualificationLinks?.tarHref,
        },
      }
    : analysis.metadata;
  const analysisAugmented =
    planWarnings.length > 0 || toolQualificationPack
      ? {
          ...analysis,
          warnings: augmentedWarnings,
          metadata: metadataWithToolQualification,
        }
      : analysis;
  await writeJsonFile(path.join(outputDir, 'analysis.json'), analysisAugmented);

  return {
    complianceHtml: complianceHtmlPath,
    complianceJson: complianceJsonPath,
    complianceCsv: complianceCsvPath,
    traceHtml: traceHtmlPath,
    traceCsv: traceCsvPath,
    gapsHtml: gapsHtmlPath,
    plans,
    warnings: planWarnings,
    ...(gsnGraphDotPath ? { gsnGraphDot: gsnGraphDotPath } : {}),
    ...(toolQualificationPaths
      ? {
          toolQualification: {
            tqp: toolQualificationPaths.tqp,
            tar: toolQualificationPaths.tar,
            summary: toolQualificationPack!.summary,
          },
        }
      : {}),
  };
};

interface RiskSimulationMetricsFile {
  coverageHistory?: unknown;
  testHistory?: unknown;
  backlogHistory?: unknown;
}

const normalizeNumericField = (
  value: unknown,
  message: string,
): number => {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === 'string' && value.trim().length > 0) {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }
  throw new Error(message);
};

const normalizeCoverageHistory = (
  value: unknown,
  sourcePath: string,
): RiskSimulationCoverageSample[] => {
  if (value === undefined) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw new Error(
      `${sourcePath} dosyasında coverageHistory alanı dizi olmalıdır.`,
    );
  }
  return value.map((entry, index) => {
    if (!entry || typeof entry !== 'object') {
      throw new Error(
        `${sourcePath} coverageHistory[${index}] kaydı nesne olmalıdır.`,
      );
    }
    const sample = entry as Record<string, unknown>;
    const timestamp = sample.timestamp;
    if (typeof timestamp !== 'string' || !timestamp.trim()) {
      throw new Error(
        `${sourcePath} coverageHistory[${index}].timestamp değeri string olmalıdır.`,
      );
    }
    const covered = normalizeNumericField(
      sample.covered,
      `${sourcePath} coverageHistory[${index}].covered sayısal olmalıdır.`,
    );
    const total = normalizeNumericField(
      sample.total,
      `${sourcePath} coverageHistory[${index}].total sayısal olmalıdır.`,
    );
    return {
      timestamp,
      covered,
      total,
    } satisfies RiskSimulationCoverageSample;
  });
};

const normalizeTestHistory = (
  value: unknown,
  sourcePath: string,
): RiskSimulationTestSample[] => {
  if (value === undefined) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw new Error(
      `${sourcePath} dosyasında testHistory alanı dizi olmalıdır.`,
    );
  }
  return value.map((entry, index) => {
    if (!entry || typeof entry !== 'object') {
      throw new Error(
        `${sourcePath} testHistory[${index}] kaydı nesne olmalıdır.`,
      );
    }
    const sample = entry as Record<string, unknown>;
    const timestamp = sample.timestamp;
    if (typeof timestamp !== 'string' || !timestamp.trim()) {
      throw new Error(
        `${sourcePath} testHistory[${index}].timestamp değeri string olmalıdır.`,
      );
    }
    const passed = normalizeNumericField(
      sample.passed,
      `${sourcePath} testHistory[${index}].passed sayısal olmalıdır.`,
    );
    const failed = normalizeNumericField(
      sample.failed,
      `${sourcePath} testHistory[${index}].failed sayısal olmalıdır.`,
    );
    const quarantinedRaw = sample.quarantined;
    const quarantined =
      quarantinedRaw === undefined
        ? undefined
        : normalizeNumericField(
            quarantinedRaw,
            `${sourcePath} testHistory[${index}].quarantined sayısal olmalıdır.`,
          );
    return {
      timestamp,
      passed,
      failed,
      quarantined,
    } satisfies RiskSimulationTestSample;
  });
};

const normalizeBacklogHistory = (
  value: unknown,
  sourcePath: string,
): RiskSimulationBacklogSample[] => {
  if (value === undefined) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw new Error(`${sourcePath} dosyasında backlogHistory alanı dizi olmalıdır.`);
  }
  return value.map((entry, index) => {
    if (!entry || typeof entry !== 'object') {
      throw new Error(`${sourcePath} backlogHistory[${index}] kaydı nesne olmalıdır.`);
    }
    const sample = entry as Record<string, unknown>;
    const timestamp = sample.timestamp;
    if (typeof timestamp !== 'string' || !timestamp.trim()) {
      throw new Error(
        `${sourcePath} backlogHistory[${index}].timestamp değeri string olmalıdır.`,
      );
    }
    const total = normalizeNumericField(
      sample.total,
      `${sourcePath} backlogHistory[${index}].total sayısal olmalıdır.`,
    );
    const blocked = normalizeNumericField(
      sample.blocked,
      `${sourcePath} backlogHistory[${index}].blocked sayısal olmalıdır.`,
    );
    const critical = normalizeNumericField(
      sample.critical,
      `${sourcePath} backlogHistory[${index}].critical sayısal olmalıdır.`,
    );
    const medianAgeDaysRaw = sample.medianAgeDays;
    const medianAgeDays =
      medianAgeDaysRaw === undefined
        ? undefined
        : normalizeNumericField(
            medianAgeDaysRaw,
            `${sourcePath} backlogHistory[${index}].medianAgeDays sayısal olmalıdır.`,
          );
    return {
      timestamp,
      total,
      blocked,
      critical,
      medianAgeDays,
    } satisfies RiskSimulationBacklogSample;
  });
};

const loadRiskSimulationMetrics = async (
  metricsPath: string,
): Promise<{
  coverageHistory: RiskSimulationCoverageSample[];
  testHistory: RiskSimulationTestSample[];
  backlogHistory: RiskSimulationBacklogSample[];
}> => {
  let raw: RiskSimulationMetricsFile;
  try {
    raw = await readJsonFile<RiskSimulationMetricsFile>(metricsPath);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(`Risk metrik dosyası okunamadı: ${reason}`);
  }
  return {
    coverageHistory: normalizeCoverageHistory(raw.coverageHistory, metricsPath),
    testHistory: normalizeTestHistory(raw.testHistory, metricsPath),
    backlogHistory: normalizeBacklogHistory(raw.backlogHistory, metricsPath),
  };
};

const normalizeIterations = (value: unknown): number | undefined => {
  if (value === undefined) {
    return undefined;
  }
  const numeric = normalizeNumericField(value, '--iterations değeri sayısal olmalıdır.');
  return clamp(Math.floor(numeric), 1, 10000);
};

const normalizeSeed = (value: unknown): number | undefined => {
  if (value === undefined) {
    return undefined;
  }
  const numeric = normalizeNumericField(value, '--seed değeri sayısal olmalıdır.');
  return Math.trunc(numeric);
};

const normalizeCoverageLift = (value: unknown): number | undefined => {
  if (value === undefined) {
    return undefined;
  }
  const numeric = normalizeNumericField(value, '--coverage-lift değeri sayısal olmalıdır.');
  return clamp(numeric, -100, 100);
};

const applyCoverageLift = (
  history: RiskSimulationCoverageSample[],
  coverageLift: number | undefined,
): RiskSimulationCoverageSample[] => {
  if (!history.length) {
    return [];
  }
  const adjusted = history.map((sample) => ({ ...sample }));
  if (coverageLift === undefined || coverageLift === 0) {
    return adjusted;
  }
  const ratioLift = coverageLift / 100;
  const lastIndex = adjusted.length - 1;
  const lastSample = adjusted[lastIndex];
  if (lastSample.total <= 0) {
    return adjusted;
  }
  const baseRatio = clamp(lastSample.covered / lastSample.total, 0, 1);
  const adjustedRatio = clamp(baseRatio + ratioLift, 0, 1);
  const adjustedCovered = Math.round(adjustedRatio * lastSample.total);
  adjusted[lastIndex] = {
    ...lastSample,
    covered: clamp(adjustedCovered, 0, lastSample.total),
  };
  return adjusted;
};

export interface RiskSimulateOptions {
  metricsPath: string;
  iterations?: number;
  seed?: number;
  coverageLift?: number;
}

export interface RiskSimulateResult {
  metricsPath: string;
  simulation: ComplianceRiskSimulationResult;
  coverageHistory: RiskSimulationCoverageSample[];
  testHistory: RiskSimulationTestSample[];
  backlogHistory: RiskSimulationBacklogSample[];
}

export const runRiskSimulate = async (
  options: RiskSimulateOptions,
): Promise<RiskSimulateResult> => {
  const metricsPath = path.resolve(options.metricsPath);
  const { coverageHistory, testHistory, backlogHistory } = await loadRiskSimulationMetrics(
    metricsPath,
  );
  const coverageLift = normalizeCoverageLift(options.coverageLift);
  const iterations = normalizeIterations(options.iterations);
  const seed = normalizeSeed(options.seed);
  const adjustedCoverage = applyCoverageLift(coverageHistory, coverageLift);
  const simulation = simulateComplianceRisk({
    coverageHistory: adjustedCoverage,
    testHistory,
    backlogHistory,
    iterations,
    seed,
  });

  return {
    metricsPath,
    simulation,
    coverageHistory: adjustedCoverage,
    testHistory: testHistory.map((sample) => ({ ...sample })),
    backlogHistory: backlogHistory.map((sample) => ({ ...sample })),
  };
};

export interface PackLedgerOptions {
  path: string;
  signerKey?: string;
  signerKeyId?: string;
}

export interface PackCmsOptions {
  bundlePem?: string;
  certificatePem?: string;
  privateKeyPem?: string;
  chainPem?: string;
}

export interface PackPostQuantumOptions {
  algorithm?: string;
  privateKey?: string;
  privateKeyPath?: string;
  publicKey?: string;
  publicKeyPath?: string;
}

export interface PackOptions {
  input: string;
  output: string;
  signingKey: string;
  packageName?: string;
  ledger?: PackLedgerOptions;
  cms?: PackCmsOptions;
  stage?: SoiStage;
  postQuantum?: PackPostQuantumOptions | false;
  attestation?: boolean;
}

export interface PackAttestationResult {
  path: string;
  absolutePath: string;
  algorithm: 'sha256';
  digest: string;
  statementDigest: string;
  signature: ManifestProvenanceSignatureMetadata;
}

export interface PackResult {
  manifestPath: string;
  archivePath: string;
  manifestId: string;
  manifestDigest: string;
  ledgerPath?: string;
  ledger?: Ledger;
  ledgerEntry?: LedgerEntry;
  cmsSignaturePath?: string;
  cmsSignatureSha256?: string;
  cmsSignatureMetadata?: {
    digestAlgorithm: string;
    signerSerialNumber?: string;
    signerIssuer?: string;
    signerSubject?: string;
    signatureAlgorithm?: string;
  };
  sbomPath: string;
  sbomSha256: string;
  signatureMetadata?: {
    postQuantumSignature?: {
      algorithm: string;
      publicKey: string;
      signature: string;
    };
  };
  attestation?: PackAttestationResult;
}

interface ManifestSbomMetadata {
  path: string;
  algorithm: 'sha256';
  digest: string;
}

type ManifestWithOptionalSbom = LedgerAwareManifest & {
  sbom?: ManifestSbomMetadata | null;
};

interface SpdxFileEntry {
  SPDXID: string;
  fileName: string;
  checksums: Array<{ algorithm: 'SHA256'; checksumValue: string }>;
}

interface SpdxDocument {
  spdxVersion: 'SPDX-2.3';
  dataLicense: 'CC0-1.0';
  SPDXID: 'SPDXRef-DOCUMENT';
  name: string;
  documentNamespace: string;
  creationInfo: {
    created: string;
    creators: string[];
  };
  packages: Array<{
    SPDXID: string;
    name: string;
    downloadLocation: 'NOASSERTION';
    filesAnalyzed: boolean;
    hasFiles: string[];
    licenseConcluded: 'NOASSERTION';
    licenseDeclared: 'NOASSERTION';
    originator: string;
  }>;
  files: SpdxFileEntry[];
  relationships: Array<{
    spdxElementId: string;
    relationshipType: 'DESCRIBES' | 'CONTAINS';
    relatedSpdxElement: string;
  }>;
}

const SBOM_FILENAME = 'sbom.spdx.json';

const generateSpdxSbom = ({
  files,
  toolVersion,
  timestamp,
  packageLabel,
}: {
  files: Array<{ manifestPath: string; sha256: string }>;
  toolVersion: string;
  timestamp: Date;
  packageLabel: string;
}): SpdxDocument => {
  const fileEntries: SpdxFileEntry[] = files.map((file, index) => ({
    SPDXID: `SPDXRef-File-${index + 1}`,
    fileName: file.manifestPath,
    checksums: [
      {
        algorithm: 'SHA256',
        checksumValue: file.sha256,
      },
    ],
  }));

  const packageId = 'SPDXRef-Package-SOIPack';

  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: packageLabel,
    documentNamespace: `urn:uuid:${randomUUID()}`,
    creationInfo: {
      created: timestamp.toISOString(),
      creators: [`Tool: SOIPack Packager ${toolVersion}`],
    },
    packages: [
      {
        SPDXID: packageId,
        name: packageLabel,
        downloadLocation: 'NOASSERTION',
        filesAnalyzed: true,
        hasFiles: fileEntries.map((entry) => entry.SPDXID),
        licenseConcluded: 'NOASSERTION',
        licenseDeclared: 'NOASSERTION',
        originator: 'Organization: SOIPack',
      },
    ],
    files: fileEntries,
    relationships: [
      {
        spdxElementId: 'SPDXRef-DOCUMENT',
        relationshipType: 'DESCRIBES',
        relatedSpdxElement: packageId,
      },
      ...fileEntries.map((entry) => ({
        spdxElementId: packageId,
        relationshipType: 'CONTAINS' as const,
        relatedSpdxElement: entry.SPDXID,
      })),
    ],
  };
};

const createArchive = async (
  files: Array<{ absolutePath: string; manifestPath: string }>,
  outputPath: string,
  manifestContent: string,
  signature?: string,
  cmsSignature?: string,
  sbom?: { absolutePath: string; archivePath: string },
  attestation?: { absolutePath: string; archivePath: string },
): Promise<void> => {
  await ensureDirectory(path.dirname(outputPath));
  const ZipCtor = ZipFile as unknown as {
    new (): {
      outputStream?: NodeJS.ReadableStream;
      addFile?: (...args: unknown[]) => void;
      addBuffer?: (...args: unknown[]) => void;
      end?: () => void;
    };
  };
  const isMockConstructor = typeof ZipCtor === 'function' && ZipCtor.name === 'mockConstructor';
  const zipInstance = typeof ZipCtor === 'function' && !isMockConstructor ? new ZipCtor() : null;
  const hasZipApi =
    zipInstance &&
    typeof zipInstance.addFile === 'function' &&
    typeof zipInstance.addBuffer === 'function' &&
    typeof zipInstance.end === 'function' &&
    zipInstance.outputStream &&
    typeof zipInstance.outputStream.pipe === 'function';

  if (!hasZipApi) {
    const entries: Array<{ path: string; data: string }> = [];
    for (const file of files) {
      const content = await fsPromises.readFile(file.absolutePath, 'utf8');
      entries.push({ path: file.manifestPath, data: content });
    }
    entries.push({ path: 'manifest.json', data: manifestContent });
    if (signature) {
      const normalizedSignature = signature.endsWith('\n') ? signature : `${signature}\n`;
      entries.push({ path: 'manifest.sig', data: normalizedSignature });
    }
    if (cmsSignature) {
      const normalizedCms = cmsSignature.endsWith('\n') ? cmsSignature : `${cmsSignature}\n`;
      entries.push({ path: 'manifest.cms', data: normalizedCms });
    }
    if (sbom) {
      const sbomContent = await fsPromises.readFile(sbom.absolutePath, 'utf8');
      entries.push({ path: sbom.archivePath, data: sbomContent });
    }
    if (attestation) {
      const attestationContent = await fsPromises.readFile(attestation.absolutePath, 'utf8');
      entries.push({ path: attestation.archivePath, data: attestationContent });
    }
    await fsPromises.writeFile(outputPath, JSON.stringify(entries, null, 2), 'utf8');
    return;
  }

  const zip = zipInstance;
  const output = fs.createWriteStream(outputPath);

  const completion = new Promise<void>((resolve, reject) => {
    output.on('close', () => resolve());
    output.on('error', (error) => reject(error));
    zip.outputStream!.on('error', (error: unknown) => reject(error));
  });

  zip.outputStream!.pipe(output);

  for (const file of files) {
    const options = hasFixedTimestamp ? { mtime: getCurrentDate() } : undefined;
    zip.addFile!(file.absolutePath, file.manifestPath, options);
  }

  zip.addBuffer!(Buffer.from(manifestContent, 'utf8'), 'manifest.json');
  if (signature) {
    const normalizedSignature = signature.endsWith('\n') ? signature : `${signature}\n`;
    const options = hasFixedTimestamp ? { mtime: getCurrentDate() } : undefined;
    zip.addBuffer!(Buffer.from(normalizedSignature, 'utf8'), 'manifest.sig', options);
  }
  if (cmsSignature) {
    const normalizedCms = cmsSignature.endsWith('\n') ? cmsSignature : `${cmsSignature}\n`;
    const options = hasFixedTimestamp ? { mtime: getCurrentDate() } : undefined;
    zip.addBuffer!(Buffer.from(normalizedCms, 'utf8'), 'manifest.cms', options);
  }
  if (sbom) {
    const options = hasFixedTimestamp ? { mtime: getCurrentDate() } : undefined;
    zip.addFile!(sbom.absolutePath, sbom.archivePath, options);
  }

  if (attestation) {
    const options = hasFixedTimestamp ? { mtime: getCurrentDate() } : undefined;
    zip.addFile!(attestation.absolutePath, attestation.archivePath, options);
  }
  zip.end!();

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

const fileExists = async (target: string): Promise<boolean> => {
  try {
    const stats = await fsPromises.stat(target);
    return stats.isFile();
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

const resolveEvidenceDirectories = async (
  inputDir: string,
  reportDir: string,
): Promise<string[]> => {
  const attachmentsDir = path.join(inputDir, 'attachments');
  const attachmentsExists = await directoryExists(attachmentsDir);

  if (inputDir === reportDir) {
    return attachmentsExists ? [attachmentsDir] : [];
  }

  const entries = await fsPromises.readdir(inputDir, { withFileTypes: true });
  const directories = entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => path.join(inputDir, entry.name))
    .filter((dir) => path.resolve(dir) !== path.resolve(reportDir));

  if (attachmentsExists) {
    const alreadyIncluded = directories.some(
      (dir) => path.resolve(dir) === path.resolve(attachmentsDir),
    );
    if (!alreadyIncluded) {
      directories.push(attachmentsDir);
    }
  }

  return directories;
};

const PACKAGE_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*\.zip$/;

export const normalizePackageName = (value: string): string => {
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    throw new Error('packageName değeri boş olamaz.');
  }

  const baseName = path.basename(trimmed);
  if (baseName !== trimmed) {
    throw new Error('packageName yalnızca dosya adı olmalı; klasör veya yol segmentleri içeremez.');
  }

  if (!PACKAGE_NAME_PATTERN.test(baseName)) {
    throw new Error(
      'packageName `.zip` uzantılı ve yalnızca harf, rakam, nokta, alt çizgi veya tire içeren bir dosya adı olmalıdır.',
    );
  }

  return baseName;
};

export const runPack = async (options: PackOptions): Promise<PackResult> => {
  const inputDir = path.resolve(options.input);
  const outputDir = path.resolve(options.output);
  await ensureDirectory(outputDir);

  const reportDir = await resolveReportDirectory(inputDir);
  const evidenceDirs = await resolveEvidenceDirectories(inputDir, reportDir);
  const now = getCurrentDate();
  const attestationEnabled = options.attestation !== false;

  const { manifest: baseManifest, files } = await buildManifest({
    reportDir,
    evidenceDirs,
    toolVersion: packageInfo.version,
    now,
    stage: options.stage,
  });

  const normalizedPackageName =
    options.packageName !== undefined ? normalizePackageName(options.packageName) : undefined;
  const packageLabelForSbom = normalizedPackageName ?? 'soipack-package.zip';
  const sbomDocument = generateSpdxSbom({
    files: files.map((file) => ({ manifestPath: file.manifestPath, sha256: file.sha256 })),
    toolVersion: packageInfo.version,
    timestamp: now,
    packageLabel: packageLabelForSbom,
  });
  const serializedSbom = JSON.stringify(sbomDocument, null, 2);
  const sbomSha256 = createHash('sha256').update(serializedSbom, 'utf8').digest('hex');
  const sbomMetadata: ManifestSbomMetadata = {
    path: SBOM_FILENAME,
    algorithm: 'sha256',
    digest: sbomSha256,
  };

  let manifest: ManifestWithOptionalSbom = { ...baseManifest, sbom: sbomMetadata };
  let manifestDigest = computeManifestDigestHex(manifest);
  let ledgerPath: string | undefined;
  let updatedLedger: Ledger | undefined;
  let ledgerEntry: LedgerEntry | undefined;
  let attestation: PackAttestationResult | undefined;

  if (options.ledger) {
    ledgerPath = path.resolve(options.ledger.path);

    let ledger: Ledger;
    try {
      ledger = await readJsonFile<Ledger>(ledgerPath);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === 'ENOENT') {
        ledger = createLedger();
      } else {
        const message = error instanceof Error ? error.message : String(error);
        throw new Error(`Ledger dosyası okunamadı (${ledgerPath}): ${message}`);
      }
    }

    const snapshotPath = path.join(reportDir, 'snapshot.json');
    let snapshot: ComplianceSnapshot;
    try {
      snapshot = await readJsonFile<ComplianceSnapshot>(snapshotPath);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`Ledger kaydı için snapshot verisi okunamadı (${snapshotPath}): ${message}`);
    }

    const signer: LedgerSignerOptions | undefined = options.ledger.signerKey
      ? {
          privateKeyPem: options.ledger.signerKey,
          keyId: options.ledger.signerKeyId,
        }
      : undefined;

    const appendOptions: AppendEntryOptions = {
      expectedPreviousRoot: ledger.root,
      ...(signer ? { signer } : {}),
    };

    const manifestDigestForLedger = computeManifestDigestHex(manifest);
    const appended = appendEntry(
      ledger,
      {
        snapshotId: snapshot.version.id,
        manifestDigest: manifestDigestForLedger,
        timestamp: baseManifest.createdAt,
      },
      appendOptions,
    );

    const entry = appended.entries[appended.entries.length - 1];
    manifest = {
      ...manifest,
      files: manifest.files.map((file) => ({ ...file })),
      ledger: {
        root: entry.ledgerRoot,
        previousRoot: entry.previousRoot,
      },
    };
    manifestDigest = manifestDigestForLedger;
    updatedLedger = appended;
    ledgerEntry = entry;
  }

  const signatureBundle = signManifestBundle(manifest, {
    bundlePem: options.signingKey,
    ledger: ledgerEntry
      ? { root: ledgerEntry.ledgerRoot, previousRoot: ledgerEntry.previousRoot }
      : undefined,
    cms: options.cms
      ? {
          bundlePem: options.cms.bundlePem,
          certificatePem: options.cms.certificatePem,
          privateKeyPem: options.cms.privateKeyPem,
          chainPem: options.cms.chainPem,
        }
      : undefined,
    postQuantum: options.postQuantum,
  });
  const signature = signatureBundle.signature;
  const verification = verifyManifestSignatureDetailed(
    manifest,
    signature,
    ledgerEntry
      ? {
          expectedLedgerRoot: ledgerEntry.ledgerRoot,
          expectedPreviousLedgerRoot: ledgerEntry.previousRoot,
          requireLedgerProof: true,
        }
      : undefined,
  );
  if (!verification.valid) {
    const reason = verification.reason ?? 'bilinmeyen';
    throw new Error(`Manifest imzası doğrulanamadı: ${reason}`);
  }
  const manifestId = manifestDigest.slice(0, 12);
  const archiveName = normalizedPackageName ?? `soipack-${manifestId}.zip`;

  if (attestationEnabled) {
    try {
      const publicKeyPem = createPublicKey(signatureBundle.certificate)
        .export({ format: 'pem', type: 'spki' })
        .toString();
      const attestationResult = await generateAttestation({
        manifest: manifest as LedgerAwareManifest,
        manifestDigest,
        sbom: sbomMetadata,
        files: manifest.files.map((file) => ({ path: file.path, sha256: file.sha256 })),
        packageName: archiveName,
        manifestSignature: signatureBundle,
        signing: {
          privateKeyPem: options.signingKey,
          publicKeyPem,
        },
      });
      const attestationSerialized = serializeAttestationDocument(attestationResult.document);
      const attestationDigest = createHash('sha256').update(attestationSerialized, 'utf8').digest('hex');
      const attestationFilename = 'attestation.json';
      const attestationPath = path.join(outputDir, attestationFilename);
      await fsPromises.writeFile(attestationPath, attestationSerialized, 'utf8');
      const publicKeySha256 = createHash('sha256')
        .update(attestationResult.signature.publicKey, 'utf8')
        .digest('hex');
      const provenanceSignature: ManifestProvenanceSignatureMetadata = {
        algorithm: 'EdDSA',
        publicKeySha256,
        ...(attestationResult.signature.keyId
          ? { keyId: attestationResult.signature.keyId }
          : {}),
      };
      manifest = {
        ...manifest,
        provenance: {
          path: attestationFilename,
          algorithm: 'sha256',
          digest: attestationDigest,
          statementDigest: attestationResult.document.statementDigest.digest,
          signature: provenanceSignature,
        },
      } satisfies ManifestWithOptionalSbom;
      attestation = {
        path: attestationFilename,
        absolutePath: attestationPath,
        algorithm: 'sha256',
        digest: attestationDigest,
        statementDigest: attestationResult.document.statementDigest.digest,
        signature: provenanceSignature,
      };
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      throw new Error(`Attestation oluşturulamadı: ${reason}`);
    }
  }

  const manifestSerialized = `${JSON.stringify(manifest, null, 2)}\n`;

  const manifestPath = path.join(outputDir, 'manifest.json');
  await fsPromises.writeFile(manifestPath, manifestSerialized, 'utf8');
  const signaturePath = path.join(outputDir, 'manifest.sig');
  await fsPromises.writeFile(signaturePath, `${signature}\n`, 'utf8');

  const sbomPath = path.join(outputDir, SBOM_FILENAME);
  await fsPromises.writeFile(sbomPath, serializedSbom, 'utf8');

  const postQuantumSignature = signatureBundle.postQuantumSignature
    ? {
        algorithm: signatureBundle.postQuantumSignature.algorithm,
        publicKey: signatureBundle.postQuantumSignature.publicKey,
        signature: signatureBundle.postQuantumSignature.signature,
      }
    : undefined;

  const cmsSignatureMetadata = signatureBundle.cmsSignature
    ? {
        digestAlgorithm: signatureBundle.cmsSignature.digestAlgorithm,
        signerSerialNumber: signatureBundle.cmsSignature.signerSerialNumber,
        signerIssuer: signatureBundle.cmsSignature.signerIssuer,
        signerSubject: signatureBundle.cmsSignature.signerSubject,
        signatureAlgorithm: signatureBundle.cmsSignature.signatureAlgorithm,
      }
    : undefined;


  let cmsSignaturePath: string | undefined;
  let cmsSignatureSha256: string | undefined;
  const cmsSignaturePem = signatureBundle.cmsSignature?.pem;
  const normalizedCmsSignature = cmsSignaturePem
    ? cmsSignaturePem.endsWith('\n')
      ? cmsSignaturePem
      : `${cmsSignaturePem}\n`
    : undefined;
  if (normalizedCmsSignature) {
    cmsSignaturePath = path.join(outputDir, 'manifest.cms');
    await fsPromises.writeFile(cmsSignaturePath, normalizedCmsSignature, 'utf8');
    cmsSignatureSha256 = createHash('sha256').update(normalizedCmsSignature).digest('hex');
  }

  if (ledgerPath && updatedLedger) {
    await ensureDirectory(path.dirname(ledgerPath));
    await writeJsonFile(ledgerPath, updatedLedger);
  }

  const archivePath = path.join(outputDir, archiveName);
  await createArchive(
    files,
    archivePath,
    manifestSerialized,
    `${signature}\n`,
    normalizedCmsSignature,
    { absolutePath: sbomPath, archivePath: SBOM_FILENAME },
    attestation
      ? { absolutePath: attestation.absolutePath, archivePath: attestation.path }
      : undefined,
  );

  return {
    manifestPath,
    archivePath,
    manifestId,
    manifestDigest,
    ledgerPath,
    ledger: updatedLedger,
    ledgerEntry,
    cmsSignaturePath,
    cmsSignatureSha256,
    cmsSignatureMetadata,
    sbomPath,
    sbomSha256,
    signatureMetadata: postQuantumSignature
      ? {
          postQuantumSignature,
        }
      : undefined,
    attestation,
  };
};

interface CoverageSummaryTotals {
  statements?: number;
  branches?: number;
  functions?: number;
  lines?: number;
}

type CoverageSummaryKey = keyof CoverageSummaryTotals;

interface CoverageTotalsEntry {
  percentage?: unknown;
  covered?: unknown;
  total?: unknown;
}

type CoverageTotalsMap = Partial<Record<CoverageSummaryKey, CoverageTotalsEntry>>;

export interface IngestPipelineOptions {
  inputDir: string;
  outputDir: string;
  workingDir?: string;
  objectives?: string;
  level?: CertificationLevel;
  projectName?: string;
  projectVersion?: string;
  stage?: SoiStage;
  baselineSnapshot?: string;
  baselineGitRef?: string;
  parasoft?: string[];
  azureDevOps?: AzureDevOpsClientOptions;
}

export interface IngestPipelineResult {
  workspaceDir: string;
  analysisDir: string;
  reportsDir: string;
  compliancePath: string;
  complianceSummary: { total: number; covered: number; partial: number; missing: number };
  coverageSummary: CoverageSummaryTotals;
  analyzeExitCode: number;
  reportResult: ReportResult;
}

const resolveInputFile = async (inputDir: string, candidates: string[]): Promise<string | undefined> => {
  for (const candidate of candidates) {
    const fullPath = path.join(inputDir, candidate);
    if (await fileExists(fullPath)) {
      return fullPath;
    }
  }
  return undefined;
};

const sanitizeSummaryValue = (value: unknown): number => {
  const numeric = Number(value ?? 0);
  if (!Number.isFinite(numeric) || numeric < 0) {
    return 0;
  }
  return Math.trunc(numeric);
};

const sanitizeCoveragePercentage = (value: unknown): number | undefined => {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 0) {
    return undefined;
  }
  return Math.round(numeric * 1000) / 1000;
};

const buildCoverageSummary = (
  summary?: CoverageSummaryTotals,
  totals?: CoverageTotalsMap,
): CoverageSummaryTotals => {
  const result: CoverageSummaryTotals = {};
  const keys: CoverageSummaryKey[] = ['statements', 'branches', 'functions', 'lines'];
  keys.forEach((key) => {
    const summaryValue = summary?.[key];
    const sanitizedSummary = sanitizeCoveragePercentage(summaryValue);
    if (sanitizedSummary !== undefined) {
      result[key] = sanitizedSummary;
      return;
    }
    const totalsEntry = totals?.[key];
    if (!totalsEntry) {
      return;
    }
    const totalsValue = sanitizeCoveragePercentage(totalsEntry.percentage);
    if (totalsValue !== undefined) {
      result[key] = totalsValue;
      return;
    }
    const covered = Number(totalsEntry.covered);
    const total = Number(totalsEntry.total);
    if (Number.isFinite(covered) && Number.isFinite(total) && total > 0) {
      const ratio = (covered / total) * 100;
      const sanitizedRatio = sanitizeCoveragePercentage(ratio);
      if (sanitizedRatio !== undefined) {
        result[key] = sanitizedRatio;
      }
    }
  });
  return result;
};

export const runIngestPipeline = async (options: IngestPipelineOptions): Promise<IngestPipelineResult> => {
  const resolvedInputDir = path.resolve(options.inputDir);
  const resolvedOutputDir = path.resolve(options.outputDir);
  const workingRoot = options.workingDir
    ? path.resolve(options.workingDir)
    : path.join(resolvedOutputDir, '..', '.soipack-work');

  const workspaceDir = path.join(workingRoot, 'workspace');
  const analysisDir = path.join(workingRoot, 'analysis');
  const reportsDir = path.join(resolvedOutputDir, 'reports');

  await ensureDirectory(workingRoot);
  await ensureDirectory(resolvedOutputDir);

  const parasoftInputs: string[] = [];
  if (options.parasoft && options.parasoft.length > 0) {
    options.parasoft.forEach((entry) => {
      if (typeof entry === 'string' && entry.trim().length > 0) {
        parasoftInputs.push(path.resolve(entry));
      }
    });
  }
  if (parasoftInputs.length === 0) {
    const detectedParasoft = await resolveInputFile(resolvedInputDir, [
      'parasoft.xml',
      'parasoft-report.xml',
    ]);
    if (detectedParasoft) {
      parasoftInputs.push(detectedParasoft);
    }
  }

  await runImport({
    output: workspaceDir,
    jira: await resolveInputFile(resolvedInputDir, ['issues.csv', 'jira.csv']),
    reqif: await resolveInputFile(resolvedInputDir, ['spec.reqif', 'requirements.reqif']),
    junit: await resolveInputFile(resolvedInputDir, ['results.xml', 'junit.xml']),
    lcov: await resolveInputFile(resolvedInputDir, ['lcov.info']),
    cobertura: await resolveInputFile(resolvedInputDir, ['coverage.xml']),
    traceLinksCsv: await resolveInputFile(resolvedInputDir, ['trace-links.csv']),
    traceLinksJson: await resolveInputFile(resolvedInputDir, ['trace-links.json']),
    designCsv: await resolveInputFile(resolvedInputDir, ['designs.csv', 'design.csv']),
    objectives: options.objectives,
    level: options.level,
    projectName: options.projectName,
    projectVersion: options.projectVersion,
    parasoft: parasoftInputs.length > 0 ? parasoftInputs : undefined,
    azureDevOps: options.azureDevOps,
  });

  const analyzeResult = await runAnalyze({
    input: workspaceDir,
    output: analysisDir,
    level: options.level,
    objectives: options.objectives,
    projectName: options.projectName,
    projectVersion: options.projectVersion,
    stage: options.stage,
    baselineSnapshot: options.baselineSnapshot,
    baselineGitRef: options.baselineGitRef,
  });

  const reportResult = await runReport({
    input: analysisDir,
    output: reportsDir,
    stage: options.stage,
  });

  const workspaceAttachmentsDir = path.join(workspaceDir, 'attachments');
  if (await directoryExists(workspaceAttachmentsDir)) {
    const outputAttachmentsDir = path.join(resolvedOutputDir, 'attachments');
    await fsPromises.cp(workspaceAttachmentsDir, outputAttachmentsDir, { recursive: true });
  }

  const complianceRaw = await fsPromises.readFile(reportResult.complianceJson, 'utf8');
  const complianceData = JSON.parse(complianceRaw) as {
    summary?: { total?: unknown; covered?: unknown; partial?: unknown; missing?: unknown };
    stats?: {
      objectives?: { total?: unknown; covered?: unknown; partial?: unknown; missing?: unknown };
    };
  };
  const summarySource = complianceData.stats?.objectives ?? complianceData.summary ?? {};
  const complianceSummary = {
    total: sanitizeSummaryValue(summarySource.total),
    covered: sanitizeSummaryValue(summarySource.covered),
    partial: sanitizeSummaryValue(summarySource.partial),
    missing: sanitizeSummaryValue(summarySource.missing),
  };

  const analysisPath = path.join(analysisDir, 'analysis.json');
  const analysisRaw = await fsPromises.readFile(analysisPath, 'utf8');
  const analysisData = JSON.parse(analysisRaw) as {
    coverage?: { summary?: CoverageSummaryTotals; totals?: CoverageTotalsMap };
  };
  const coverageSummary = buildCoverageSummary(analysisData.coverage?.summary, analysisData.coverage?.totals);

  return {
    workspaceDir,
    analysisDir,
    reportsDir,
    compliancePath: reportResult.complianceJson,
    complianceSummary,
    coverageSummary,
    analyzeExitCode: analyzeResult.exitCode,
    reportResult,
  };
};

export interface PackagePipelineOptions extends IngestPipelineOptions {
  signingKey: string;
  packageName?: string;
  ledger?: PackLedgerOptions;
  cms?: PackCmsOptions;
  attestation?: boolean;
}

export interface PackagePipelineResult extends IngestPipelineResult {
  manifestPath: string;
  archivePath: string;
  manifestId: string;
  manifestDigest: string;
  ledgerPath?: string;
  ledger?: Ledger;
  ledgerEntry?: LedgerEntry;
  cmsSignaturePath?: string;
  cmsSignatureSha256?: string;
  sbomPath: string;
  sbomSha256: string;
  signatureMetadata?: PackResult['signatureMetadata'];
  attestation?: PackResult['attestation'];
}

export const runIngestAndPackage = async (
  options: PackagePipelineOptions,
): Promise<PackagePipelineResult> => {
  const { signingKey, packageName, ...ingestOptions } = options;
  const ingestResult = await runIngestPipeline(ingestOptions);
  const packResult = await runPack({
    input: path.resolve(options.outputDir),
    output: path.resolve(options.outputDir),
    packageName: packageName ?? 'soi-pack.zip',
    signingKey,
    ledger: options.ledger,
    cms: options.cms,
    stage: options.stage,
    attestation: options.attestation,
  });

  return {
    ...ingestResult,
    manifestPath: packResult.manifestPath,
    archivePath: packResult.archivePath,
    manifestId: packResult.manifestId,
    manifestDigest: packResult.manifestDigest,
    ledgerPath: packResult.ledgerPath,
    ledger: packResult.ledger,
    ledgerEntry: packResult.ledgerEntry,
    cmsSignaturePath: packResult.cmsSignaturePath,
    cmsSignatureSha256: packResult.cmsSignatureSha256,
    sbomPath: packResult.sbomPath,
    sbomSha256: packResult.sbomSha256,
    signatureMetadata: packResult.signatureMetadata,
    attestation: packResult.attestation,
  };
};

export interface VerifyOptions {
  manifestPath: string;
  signaturePath: string;
  publicKeyPath: string;
  packagePath?: string;
  sbomPath?: string;
}

interface VerifySbomFileCheck {
  path: string;
  digest: string;
  matches: boolean;
}

interface VerifySbomPackageCheck {
  digest: string;
  matches: boolean;
}

interface VerifyAttestationSignatureCheck {
  keyId?: string;
  publicKeySha256: string;
  matchesExpectedKey: boolean;
  matchesVerifierKey: boolean;
  verified: boolean;
}

export interface VerifyAttestationResult {
  path: string;
  algorithm: 'sha256';
  expectedDigest: string;
  actualDigest: string;
  digestMatches: boolean;
  statementDigest: string;
  expectedStatementDigest: string;
  statementMatches: boolean;
  signature: VerifyAttestationSignatureCheck;
}

export interface VerifyResult {
  isValid: boolean;
  manifestId: string;
  packageIssues: string[];
  sbom?: {
    path: string;
    algorithm: string;
    expectedDigest: string;
    file?: VerifySbomFileCheck;
    package?: VerifySbomPackageCheck;
  };
  attestation?: VerifyAttestationResult;
}

export interface ManifestDiffOptions {
  baseManifestPath: string;
  targetManifestPath: string;
}

export interface ManifestDiffEntry {
  path: string;
  sha256: string;
}

export interface ManifestDiffChange {
  path: string;
  baseSha256: string;
  targetSha256: string;
}

interface ManifestDiffSummary {
  path: string;
  digest: string;
  createdAt: string;
  verifiedProofs: number;
  totalProofs: number;
}

export interface ManifestDiffResult {
  base: ManifestDiffSummary;
  target: ManifestDiffSummary;
  added: ManifestDiffEntry[];
  removed: ManifestDiffEntry[];
  changed: ManifestDiffChange[];
}

const readUtf8File = async (filePath: string, errorMessage: string): Promise<string> => {
  try {
    return await fsPromises.readFile(filePath, 'utf8');
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(`${errorMessage}: ${reason}`);
  }
};

const normalizeArchivePath = (value: string): string => value.replace(/\\/g, '/');

interface ManifestFileDigestEntry {
  path: string;
  sha256: string;
}

interface ManifestForDiff {
  manifest: Manifest;
  resolvedPath: string;
  digest: string;
  createdAt: string;
  proofs: { verified: number; total: number };
  files: Map<string, ManifestFileDigestEntry>;
}

const normalizeSha256 = (value: string): string => value.toLowerCase();

const buildManifestForDiff = (
  manifest: Manifest,
  resolvedPath: string,
  manifestLabel: string,
): ManifestForDiff => {
  const digest = computeManifestDigestHex(manifest);
  const merkle = manifest.merkle ?? undefined;

  if (merkle) {
    if (merkle.algorithm !== 'ledger-merkle-v1') {
      throw new Error(`${manifestLabel} Merkle algoritması desteklenmiyor: ${merkle.algorithm}`);
    }
    if (merkle.manifestDigest && merkle.manifestDigest !== digest) {
      throw new Error(`${manifestLabel} özeti Merkle kaydı ile uyuşmuyor.`);
    }
  }

  const merkleRoot = merkle?.root;
  let verifiedProofs = 0;
  let totalProofs = 0;
  const files = new Map<string, ManifestFileDigestEntry>();

  manifest.files.forEach((file) => {
    if (!file || typeof file.path !== 'string' || typeof file.sha256 !== 'string') {
      throw new Error(`${manifestLabel} dosya girdisi geçersiz.`);
    }

    const normalizedSha = normalizeSha256(file.sha256);
    files.set(file.path, { path: file.path, sha256: normalizedSha });

    if (file.proof) {
      totalProofs += 1;
      if (file.proof.algorithm !== 'ledger-merkle-v1') {
        throw new Error(`Ledger kanıtı doğrulanamadı (${file.path}): Desteklenmeyen kanıt algoritması ${file.proof.algorithm}.`);
      }
      if (!merkleRoot) {
        throw new Error(`Ledger kanıtı doğrulanamadı (${file.path}): Manifest Merkle kökü eksik.`);
      }

      try {
        const parsed = deserializeLedgerProof(file.proof.proof);
        verifyLedgerProof(parsed, { expectedMerkleRoot: merkleRoot });
      } catch (error) {
        const reason = error instanceof Error ? error.message : String(error);
        throw new Error(`Ledger kanıtı doğrulanamadı (${file.path}): ${reason}`);
      }

      verifiedProofs += 1;
    }
  });

  const createdAt = typeof manifest.createdAt === 'string' ? manifest.createdAt : '';

  return {
    manifest,
    resolvedPath,
    digest,
    createdAt,
    proofs: { verified: verifiedProofs, total: totalProofs },
    files,
  };
};

const loadManifestForDiff = async (
  kind: 'base' | 'target',
  manifestPath: string,
): Promise<ManifestForDiff> => {
  const resolved = path.resolve(manifestPath);
  const manifestLabel = kind === 'base' ? 'Referans manifest' : 'Hedef manifest';
  const manifestRaw = await readUtf8File(resolved, `${manifestLabel} dosyası okunamadı`);

  let manifest: Manifest;
  try {
    manifest = JSON.parse(manifestRaw) as Manifest;
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(`${manifestLabel} JSON formatı çözümlenemedi: ${reason}`);
  }

  return buildManifestForDiff(manifest, resolved, manifestLabel);
};

const computeManifestDiff = (
  baseInfo: ManifestForDiff,
  targetInfo: ManifestForDiff,
): {
  added: ManifestDiffEntry[];
  removed: ManifestDiffEntry[];
  changed: ManifestDiffChange[];
} => {
  const added: ManifestDiffEntry[] = [];
  const removed: ManifestDiffEntry[] = [];
  const changed: ManifestDiffChange[] = [];

  baseInfo.files.forEach((baseEntry, filePath) => {
    const targetEntry = targetInfo.files.get(filePath);
    if (!targetEntry) {
      removed.push({ path: filePath, sha256: baseEntry.sha256 });
      return;
    }

    if (baseEntry.sha256 !== targetEntry.sha256) {
      changed.push({
        path: filePath,
        baseSha256: baseEntry.sha256,
        targetSha256: targetEntry.sha256,
      });
    }
  });

  targetInfo.files.forEach((targetEntry, filePath) => {
    if (!baseInfo.files.has(filePath)) {
      added.push({ path: filePath, sha256: targetEntry.sha256 });
    }
  });

  const sortByPath = <T extends { path: string }>(items: T[]): T[] =>
    items.sort((a, b) => a.path.localeCompare(b.path));

  sortByPath(added);
  sortByPath(removed);
  sortByPath(changed);

  return { added, removed, changed };
};

interface SnapshotForCompare {
  kind: 'snapshot' | 'manifest';
  snapshot: ComplianceSnapshot;
  snapshotPath: string;
  manifest?: ManifestForDiff;
}

const isManifestPayload = (value: unknown): value is Manifest => {
  if (!value || typeof value !== 'object') {
    return false;
  }
  const manifest = value as Partial<Manifest>;
  return Array.isArray(manifest.files) && typeof manifest.createdAt === 'string';
};

const isSnapshotPayload = (value: unknown): value is ComplianceSnapshot => {
  if (!value || typeof value !== 'object') {
    return false;
  }
  const snapshot = value as Partial<ComplianceSnapshot>;
  const version = snapshot.version as Partial<SnapshotVersion> | undefined;
  return (
    Array.isArray(snapshot.objectives) &&
    !!version &&
    typeof version.id === 'string' &&
    typeof snapshot.generatedAt === 'string'
  );
};

const readSnapshotWithContext = async (
  snapshotPath: string,
  label: string,
): Promise<ComplianceSnapshot> => {
  try {
    return await readJsonFile<ComplianceSnapshot>(snapshotPath);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(`${label} snapshot dosyası okunamadı (${snapshotPath}): ${reason}`);
  }
};

const loadSnapshotForCompare = async (
  kind: 'base' | 'target',
  inputPath: string,
): Promise<SnapshotForCompare> => {
  const resolved = path.resolve(inputPath);
  const labelPrefix = kind === 'base' ? 'Referans' : 'Hedef';
  const raw = await readUtf8File(resolved, `${labelPrefix} dosyası okunamadı`);

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(`${labelPrefix} JSON formatı çözümlenemedi: ${reason}`);
  }

  if (isManifestPayload(parsed)) {
    const manifestInfo = buildManifestForDiff(parsed, resolved, `${labelPrefix} manifest`);
    const snapshotEntry = parsed.files.find((file) => file.path.endsWith('snapshot.json'));
    if (!snapshotEntry) {
      throw new Error(`${labelPrefix} manifest snapshot dosyası içermiyor (reports/snapshot.json).`);
    }
    const snapshotPath = path.resolve(path.dirname(resolved), snapshotEntry.path);
    const snapshot = await readSnapshotWithContext(snapshotPath, `${labelPrefix} manifest`);
    return { kind: 'manifest', snapshot, snapshotPath, manifest: manifestInfo };
  }

  if (isSnapshotPayload(parsed)) {
    return { kind: 'snapshot', snapshot: parsed, snapshotPath: resolved };
  }

  throw new Error(
    `${labelPrefix} dosyası uyum snapshot veya manifest formatıyla eşleşmedi: ${path.basename(resolved)}`,
  );
};

export interface ComplianceCompareObjectiveDelta {
  objectiveId: string;
  previousStatus: ObjectiveCoverageStatus;
  currentStatus: ObjectiveCoverageStatus;
}

export interface ComplianceCompareObjectivesSummary {
  improvements: ComplianceCompareObjectiveDelta[];
  regressions: ComplianceCompareObjectiveDelta[];
  unchanged: number;
}

export interface ComplianceCompareIndependenceRegression {
  objectiveId: string;
  independence: Objective['independence'];
  previousStatus: ObjectiveCoverageStatus;
  currentStatus: ObjectiveCoverageStatus;
  missingArtifacts: ObjectiveArtifactType[];
}

export interface ComplianceCompareEvidenceChanges {
  added: ManifestDiffEntry[];
  removed: ManifestDiffEntry[];
  changed: ManifestDiffChange[];
}

export interface ComplianceCompareResult {
  base: {
    path: string;
    snapshotId: string;
    generatedAt: string;
    version: SnapshotVersion;
    kind: SnapshotForCompare['kind'];
    manifest?: {
      path: string;
      digest: string;
      createdAt: string;
      proofs: ManifestForDiff['proofs'];
    };
  };
  target: {
    path: string;
    snapshotId: string;
    generatedAt: string;
    version: SnapshotVersion;
    kind: SnapshotForCompare['kind'];
    manifest?: {
      path: string;
      digest: string;
      createdAt: string;
      proofs: ManifestForDiff['proofs'];
    };
  };
  objectives: ComplianceCompareObjectivesSummary;
  independenceRegressions: ComplianceCompareIndependenceRegression[];
  evidenceChanges?: ComplianceCompareEvidenceChanges;
}

export interface ComplianceCompareOptions {
  basePath: string;
  targetPath: string;
}

const objectiveStatusRankForCompare: Record<ObjectiveCoverageStatus, number> = {
  missing: 0,
  partial: 1,
  covered: 2,
};

const computeObjectiveDeltas = (
  baseObjectives: ObjectiveCoverage[],
  targetObjectives: ObjectiveCoverage[],
): ComplianceCompareObjectivesSummary => {
  const baseById = new Map(baseObjectives.map((entry) => [entry.objectiveId, entry]));
  const improvements: ComplianceCompareObjectiveDelta[] = [];
  const regressions: ComplianceCompareObjectiveDelta[] = [];
  let unchanged = 0;

  targetObjectives.forEach((entry) => {
    const previous = baseById.get(entry.objectiveId);
    if (!previous) {
      return;
    }
    const previousRank = objectiveStatusRankForCompare[previous.status];
    const currentRank = objectiveStatusRankForCompare[entry.status];
    if (currentRank > previousRank) {
      improvements.push({
        objectiveId: entry.objectiveId,
        previousStatus: previous.status,
        currentStatus: entry.status,
      });
    } else if (currentRank < previousRank) {
      regressions.push({
        objectiveId: entry.objectiveId,
        previousStatus: previous.status,
        currentStatus: entry.status,
      });
    } else {
      unchanged += 1;
    }
  });

  const sortByObjective = (items: ComplianceCompareObjectiveDelta[]): ComplianceCompareObjectiveDelta[] =>
    items.sort((a, b) => a.objectiveId.localeCompare(b.objectiveId));

  sortByObjective(improvements);
  sortByObjective(regressions);

  return { improvements, regressions, unchanged };
};

const computeIndependenceRegressions = (
  base: ComplianceIndependenceSummary,
  target: ComplianceIndependenceSummary,
): ComplianceCompareIndependenceRegression[] => {
  const baseById = new Map(base.objectives.map((entry) => [entry.objectiveId, entry]));
  const regressions: ComplianceCompareIndependenceRegression[] = [];

  target.objectives.forEach((entry) => {
    const previous = baseById.get(entry.objectiveId);
    if (!previous) {
      return;
    }
    const previousRank = objectiveStatusRankForCompare[previous.status];
    const currentRank = objectiveStatusRankForCompare[entry.status];
    if (currentRank < previousRank) {
      regressions.push({
        objectiveId: entry.objectiveId,
        independence: entry.independence,
        previousStatus: previous.status,
        currentStatus: entry.status,
        missingArtifacts: [...entry.missingArtifacts],
      });
    }
  });

  regressions.sort((a, b) => a.objectiveId.localeCompare(b.objectiveId));
  return regressions;
};

export const runComplianceCompare = async (
  options: ComplianceCompareOptions,
): Promise<ComplianceCompareResult> => {
  const base = await loadSnapshotForCompare('base', options.basePath);
  const target = await loadSnapshotForCompare('target', options.targetPath);

  const objectives = computeObjectiveDeltas(base.snapshot.objectives, target.snapshot.objectives);
  const independenceRegressions = computeIndependenceRegressions(
    base.snapshot.independenceSummary,
    target.snapshot.independenceSummary,
  );

  let evidenceChanges: ComplianceCompareEvidenceChanges | undefined;
  if (base.manifest && target.manifest) {
    const diff = computeManifestDiff(base.manifest, target.manifest);
    evidenceChanges = diff;
  }

  return {
    base: {
      path: base.snapshotPath,
      snapshotId: base.snapshot.version.id,
      generatedAt: base.snapshot.generatedAt,
      version: base.snapshot.version,
      kind: base.kind,
      ...(base.manifest
        ? {
            manifest: {
              path: base.manifest.resolvedPath,
              digest: base.manifest.digest,
              createdAt: base.manifest.createdAt,
              proofs: base.manifest.proofs,
            },
          }
        : {}),
    },
    target: {
      path: target.snapshotPath,
      snapshotId: target.snapshot.version.id,
      generatedAt: target.snapshot.generatedAt,
      version: target.snapshot.version,
      kind: target.kind,
      ...(target.manifest
        ? {
            manifest: {
              path: target.manifest.resolvedPath,
              digest: target.manifest.digest,
              createdAt: target.manifest.createdAt,
              proofs: target.manifest.proofs,
            },
          }
        : {}),
    },
    objectives,
    independenceRegressions,
    ...(evidenceChanges ? { evidenceChanges } : {}),
  };
};

const renderTable = <T>(rows: T[], columns: Array<{ header: string; getter: (row: T) => string }>): string => {
  const widths = columns.map((column) => {
    const headerWidth = column.header.length;
    const dataWidth = rows.reduce((acc, row) => Math.max(acc, column.getter(row).length), 0);
    return Math.max(headerWidth, dataWidth);
  });

  const formatRow = (row: T): string =>
    columns
      .map((column, index) => column.getter(row).padEnd(widths[index]))
      .join('  ')
      .trimEnd();

  const header = columns
    .map((column, index) => column.header.padEnd(widths[index]))
    .join('  ')
    .trimEnd();
  const separator = columns
    .map((_, index) => ''.padEnd(widths[index], '-'))
    .join('  ')
    .trimEnd();

  const lines = [header, separator, ...rows.map((row) => formatRow(row))];
  return lines.join('\n');
};

const renderObjectiveDeltaTable = (rows: ComplianceCompareObjectiveDelta[]): string => {
  if (rows.length === 0) {
    return 'Değişiklik bulunamadı.';
  }
  return renderTable(rows, [
    { header: 'Objective', getter: (row) => row.objectiveId },
    { header: 'Önceki', getter: (row) => row.previousStatus },
    { header: 'Güncel', getter: (row) => row.currentStatus },
  ]);
};

const renderIndependenceRegressionTable = (
  rows: ComplianceCompareIndependenceRegression[],
): string => {
  if (rows.length === 0) {
    return 'Bağımsızlık gerilemesi bulunamadı.';
  }
  return renderTable(rows, [
    { header: 'Objective', getter: (row) => row.objectiveId },
    { header: 'Bağımsızlık', getter: (row) => row.independence },
    { header: 'Önceki', getter: (row) => row.previousStatus },
    { header: 'Güncel', getter: (row) => row.currentStatus },
    {
      header: 'Eksik Artefaktlar',
      getter: (row) => (row.missingArtifacts.length > 0 ? row.missingArtifacts.join(', ') : '—'),
    },
  ]);
};

const renderManifestDiffEntries = (entries: ManifestDiffEntry[]): string => {
  if (entries.length === 0) {
    return '';
  }
  return renderTable(entries, [
    { header: 'Dosya', getter: (entry) => entry.path },
    { header: 'SHA-256', getter: (entry) => entry.sha256 },
  ]);
};

const renderManifestDiffChanges = (entries: ManifestDiffChange[]): string => {
  if (entries.length === 0) {
    return '';
  }
  return renderTable(entries, [
    { header: 'Dosya', getter: (entry) => entry.path },
    { header: 'Önceki', getter: (entry) => entry.baseSha256 },
    { header: 'Güncel', getter: (entry) => entry.targetSha256 },
  ]);
};

interface ZipEntryMetadata {
  compressionMethod: number;
  compressedSize: number;
  localHeaderOffset: number;
}

const ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE = 0x06054b50;
const ZIP_CENTRAL_DIRECTORY_SIGNATURE = 0x02014b50;
const ZIP_LOCAL_FILE_HEADER_SIGNATURE = 0x04034b50;

const findCentralDirectory = (archive: Buffer): { offset: number; totalEntries: number } => {
  const minSize = 22;
  const maxCommentLength = 0xffff;
  const start = Math.max(0, archive.length - (minSize + maxCommentLength));

  for (let index = archive.length - minSize; index >= start; index -= 1) {
    if (archive.readUInt32LE(index) === ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE) {
      const totalEntries = archive.readUInt16LE(index + 10);
      const offset = archive.readUInt32LE(index + 16);
      return { offset, totalEntries };
    }
  }

  throw new Error('ZIP arşivinde merkez dizin son kaydı bulunamadı.');
};

const readCentralDirectoryEntries = (archive: Buffer): Map<string, ZipEntryMetadata> => {
  const { offset: startOffset, totalEntries } = findCentralDirectory(archive);
  const entries = new Map<string, ZipEntryMetadata>();

  let offset = startOffset;
  for (let index = 0; index < totalEntries; index += 1) {
    if (offset + 46 > archive.length) {
      throw new Error('ZIP arşivi bozuk: merkez dizin girişi eksik.');
    }

    const signature = archive.readUInt32LE(offset);
    if (signature !== ZIP_CENTRAL_DIRECTORY_SIGNATURE) {
      throw new Error('ZIP arşivi bozuk: merkez dizin imzası okunamadı.');
    }

    const compressionMethod = archive.readUInt16LE(offset + 10);
    const compressedSize = archive.readUInt32LE(offset + 20);
    const fileNameLength = archive.readUInt16LE(offset + 28);
    const extraFieldLength = archive.readUInt16LE(offset + 30);
    const commentLength = archive.readUInt16LE(offset + 32);
    const localHeaderOffset = archive.readUInt32LE(offset + 42);

    const nameStart = offset + 46;
    const nameEnd = nameStart + fileNameLength;
    if (nameEnd > archive.length) {
      throw new Error('ZIP arşivi bozuk: dosya adı sınırları aşıldı.');
    }

    const rawName = archive.subarray(nameStart, nameEnd).toString('utf8');
    const normalizedName = normalizeArchivePath(rawName);

    entries.set(normalizedName, {
      compressionMethod,
      compressedSize,
      localHeaderOffset,
    });

    offset = nameEnd + extraFieldLength + commentLength;
  }

  return entries;
};

const readEntryData = (archive: Buffer, entry: ZipEntryMetadata): Buffer => {
  if (entry.localHeaderOffset + 30 > archive.length) {
    throw new Error('ZIP arşivi bozuk: yerel dosya başlığı eksik.');
  }

  const signature = archive.readUInt32LE(entry.localHeaderOffset);
  if (signature !== ZIP_LOCAL_FILE_HEADER_SIGNATURE) {
    throw new Error('ZIP arşivi bozuk: yerel dosya başlığı imzası okunamadı.');
  }

  const fileNameLength = archive.readUInt16LE(entry.localHeaderOffset + 26);
  const extraFieldLength = archive.readUInt16LE(entry.localHeaderOffset + 28);
  const dataStart = entry.localHeaderOffset + 30 + fileNameLength + extraFieldLength;
  const dataEnd = dataStart + entry.compressedSize;

  if (dataEnd > archive.length) {
    throw new Error('ZIP arşivi bozuk: sıkıştırılmış veri eksik.');
  }

  const compressed = archive.subarray(dataStart, dataEnd);

  switch (entry.compressionMethod) {
    case 0:
      return compressed;
    case 8:
      return inflateRawSync(compressed);
    default:
      throw new Error(`Desteklenmeyen ZIP sıkıştırma yöntemi: ${entry.compressionMethod}`);
  }
};

const verifyPackageAgainstManifest = async (
  packagePath: string,
  manifest: ManifestWithOptionalSbom,
): Promise<{ issues: string[]; sbomChecked: boolean; sbomDigest?: string }> => {
  const expected = new Map<string, string>();
  for (const file of manifest.files) {
    expected.set(normalizeArchivePath(file.path), file.sha256.toLowerCase());
  }

  const archive = await fsPromises.readFile(packagePath);
  const entries = readCentralDirectoryEntries(archive);

  const issues: string[] = [];
  let sbomChecked = false;
  let sbomDigest: string | undefined;

  for (const [filePath, expectedHash] of expected.entries()) {
    const entry = entries.get(filePath);
    if (!entry) {
      issues.push(`Manifest dosyası paket içinde bulunamadı: ${filePath}`);
      continue;
    }

    try {
      const data = readEntryData(archive, entry);
      const digest = createHash('sha256').update(data).digest('hex');
      if (digest !== expectedHash) {
        issues.push(`Dosya karması uyuşmuyor: ${filePath} (beklenen ${expectedHash}, bulunan ${digest})`);
      }
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      issues.push(`Dosya okunamadı: ${filePath} (${reason})`);
    }
  }

  const sbomMetadata = manifest.sbom ?? undefined;
  if (sbomMetadata) {
    const normalizedPath = normalizeArchivePath(sbomMetadata.path);
    const entry = entries.get(normalizedPath);
    if (!entry) {
      issues.push(`SBOM dosyası paket içinde bulunamadı: ${sbomMetadata.path}`);
    } else {
      sbomChecked = true;
      try {
        const data = readEntryData(archive, entry);
        const digest = createHash('sha256').update(data).digest('hex');
        sbomDigest = digest;
        if (digest !== sbomMetadata.digest.toLowerCase()) {
          issues.push(
            `SBOM karması uyuşmuyor: ${sbomMetadata.path} (beklenen ${sbomMetadata.digest.toLowerCase()}, bulunan ${digest})`,
          );
        }
      } catch (error) {
        const reason = error instanceof Error ? error.message : String(error);
        issues.push(`SBOM dosyası okunamadı: ${sbomMetadata.path} (${reason})`);
      }
    }
  }

  return { issues, sbomChecked, sbomDigest };
};

const decodeBase64Url = (value: string): Buffer => {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padding = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
  return Buffer.from(`${normalized}${padding}`, 'base64');
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

  const verifierPem = await readUtf8File(
    publicKeyPath,
    'Doğrulama anahtarı dosyası okunamadı (sertifika veya kamu anahtarı).',
  );

  const manifestWithSbom = manifest as ManifestWithOptionalSbom;
  const manifestDigestHex = computeManifestDigestHex(manifestWithSbom);
  const manifestId = manifestDigestHex.slice(0, 12);
  const isValid = verifyManifestSignature(manifestWithSbom, signature, verifierPem);

  let packageIssues: string[] = [];
  let packageSbomCheck: { checked: boolean; digest?: string } = { checked: false };
  if (options.packagePath) {
    const packagePath = path.resolve(options.packagePath);
    let stats: fs.Stats;
    try {
      stats = await fsPromises.stat(packagePath);
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      throw new Error(`Paket arşivi okunamadı: ${reason}`);
    }

    if (!stats.isFile()) {
      throw new Error('Paket arşivi bir dosya olmalıdır.');
    }

    try {
      const packageResult = await verifyPackageAgainstManifest(packagePath, manifestWithSbom);
      packageIssues = packageResult.issues;
      packageSbomCheck = { checked: packageResult.sbomChecked, digest: packageResult.sbomDigest };
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      throw new Error(`Paket içeriği doğrulanamadı: ${reason}`);
    }
  }

  const sbomMetadata = manifestWithSbom.sbom ?? undefined;
  let sbomResult: VerifyResult['sbom'];
  if (options.sbomPath && !sbomMetadata) {
    throw new Error('Manifest SBOM metaverisi içermiyor ancak --sbom yolu sağlandı.');
  }

  if (sbomMetadata) {
    const expectedDigest = sbomMetadata.digest.toLowerCase();
    let fileCheck: VerifySbomFileCheck | undefined;
    if (options.sbomPath) {
      const sbomPath = path.resolve(options.sbomPath);
      const sbomContent = await fsPromises.readFile(sbomPath);
      const digest = createHash('sha256').update(sbomContent).digest('hex');
      fileCheck = {
        path: sbomPath,
        digest,
        matches: digest === expectedDigest,
      };
    }

    let packageCheck: VerifySbomPackageCheck | undefined;
    if (packageSbomCheck.checked && packageSbomCheck.digest) {
      packageCheck = {
        digest: packageSbomCheck.digest,
        matches: packageSbomCheck.digest === expectedDigest,
      };
    }

    sbomResult = {
      path: sbomMetadata.path,
      algorithm: sbomMetadata.algorithm,
      expectedDigest,
      ...(fileCheck ? { file: fileCheck } : {}),
      ...(packageCheck ? { package: packageCheck } : {}),
    };
  }

  let attestationResult: VerifyAttestationResult | undefined;
  const provenance = manifestWithSbom.provenance ?? undefined;
  if (provenance && provenance !== null) {
    const attestationPath = path.resolve(path.dirname(manifestPath), provenance.path);
    try {
      const attestationRaw = await readUtf8File(attestationPath, 'Attestation dosyası okunamadı');
      const attestationJson = JSON.parse(attestationRaw) as {
        statementDigest?: { algorithm?: string; digest?: string };
        signatures?: Array<{
          jws?: string;
          signature?: string;
          protected?: string;
          publicKey?: string;
          keyId?: string;
        }>;
      };

      if (typeof provenance.digest !== 'string') {
        throw new Error('Manifest attestation karması eksik.');
      }
      if (typeof provenance.statementDigest !== 'string') {
        throw new Error('Manifest attestation statement karması eksik.');
      }
      if (!provenance.signature || typeof provenance.signature.publicKeySha256 !== 'string') {
        throw new Error('Manifest attestation imza metaverisi eksik.');
      }

      const expectedDigest = provenance.digest.toLowerCase();
      const actualDigest = createHash('sha256').update(attestationRaw, 'utf8').digest('hex');
      const digestMatches = actualDigest === expectedDigest;

      const statementDigest = (attestationJson.statementDigest?.digest ?? '').toLowerCase();
      const expectedStatementDigest = provenance.statementDigest.toLowerCase();
      const statementDigestMatches = statementDigest === expectedStatementDigest;

      const signatureRecord = attestationJson.signatures?.[0];
      if (!signatureRecord || typeof signatureRecord !== 'object' || !signatureRecord.publicKey) {
        throw new Error('Attestation imzası bulunamadı.');
      }

      const jws = signatureRecord.jws;
      if (!jws || typeof jws !== 'string') {
        throw new Error('Attestation JWS içeriği bulunamadı.');
      }
      const [headerB64, payloadB64, signatureB64] = jws.split('.');
      if (!headerB64 || !payloadB64 || !signatureB64) {
        throw new Error('Attestation JWS biçimi geçersiz.');
      }

      const payloadJson = decodeBase64Url(payloadB64).toString('utf8');
      const payloadDigest = createHash('sha256').update(payloadJson, 'utf8').digest('hex');
      const statementMatchesPayload = payloadDigest === statementDigest;

      let signatureVerified = false;
      try {
        const keyObject = createPublicKey(signatureRecord.publicKey);
        const signatureBuffer = decodeBase64Url(signatureB64);
        signatureVerified = verifySignature(
          null,
          Buffer.from(`${headerB64}.${payloadB64}`, 'utf8'),
          keyObject,
          signatureBuffer,
        );
      } catch {
        signatureVerified = false;
      }

      let verifierKeySha256: string;
      try {
        const verifierKeyPem = createPublicKey(verifierPem)
          .export({ format: 'pem', type: 'spki' })
          .toString();
        verifierKeySha256 = createHash('sha256').update(verifierKeyPem, 'utf8').digest('hex');
      } catch (error) {
        const reason = error instanceof Error ? error.message : String(error);
        throw new Error(`Doğrulama anahtarı çözümlenemedi: ${reason}`);
      }

      const attestationKeySha256 = createHash('sha256')
        .update(signatureRecord.publicKey, 'utf8')
        .digest('hex');
      const expectedKeySha256 = provenance.signature.publicKeySha256.toLowerCase();
      const matchesExpectedKey = attestationKeySha256 === expectedKeySha256;
      const matchesVerifierKey = verifierKeySha256 === expectedKeySha256;

      attestationResult = {
        path: attestationPath,
        algorithm: 'sha256',
        expectedDigest,
        actualDigest,
        digestMatches,
        statementDigest,
        expectedStatementDigest,
        statementMatches: statementDigestMatches && statementMatchesPayload,
        signature: {
          keyId: signatureRecord.keyId ?? provenance.signature.keyId,
          publicKeySha256: attestationKeySha256,
          matchesExpectedKey,
          matchesVerifierKey,
          verified:
            signatureVerified &&
            statementDigestMatches &&
            statementMatchesPayload &&
            matchesExpectedKey &&
            matchesVerifierKey,
        },
      };
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      throw new Error(`Attestation doğrulanamadı: ${reason}`);
    }
  }

  return {
    isValid,
    manifestId,
    packageIssues,
    ...(sbomResult ? { sbom: sbomResult } : {}),
    ...(attestationResult ? { attestation: attestationResult } : {}),
  };
};

export const runManifestDiff = async (options: ManifestDiffOptions): Promise<ManifestDiffResult> => {
  const baseInfo = await loadManifestForDiff('base', options.baseManifestPath);
  const targetInfo = await loadManifestForDiff('target', options.targetManifestPath);

  const { added, removed, changed } = computeManifestDiff(baseInfo, targetInfo);

  return {
    base: {
      path: baseInfo.resolvedPath,
      digest: baseInfo.digest,
      createdAt: baseInfo.createdAt,
      verifiedProofs: baseInfo.proofs.verified,
      totalProofs: baseInfo.proofs.total,
    },
    target: {
      path: targetInfo.resolvedPath,
      digest: targetInfo.digest,
      createdAt: targetInfo.createdAt,
      verifiedProofs: targetInfo.proofs.verified,
      totalProofs: targetInfo.proofs.total,
    },
    added,
    removed,
    changed,
  };
};

export interface LedgerReportOptions {
  baseManifestPath: string;
  targetManifestPath: string;
  outputDir: string;
  title?: string;
  signingKey?: string;
}

export interface LedgerReportResult {
  pdfPath: string;
  pdfSha256: string;
  ledgerDiffs: LedgerAttestationDiffItem[];
  signaturePath?: string;
  signature?: string;
}

const LEDGER_REPORT_STYLES = `
  body {
    background: #f1f5f9;
    color: #0f172a;
    font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif;
    margin: 0;
  }

  header {
    background: #0f172a;
    color: #ffffff;
    padding: 32px 48px;
  }

  header h1 {
    margin: 0 0 8px;
    font-size: 28px;
  }

  header p {
    margin: 4px 0;
    color: rgba(226, 232, 240, 0.9);
  }

  main {
    padding: 32px 48px 48px;
  }

  .summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 12px;
  }

  .summary-card {
    background: rgba(15, 23, 42, 0.08);
    border-radius: 12px;
    padding: 14px 16px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .summary-card--accent {
    box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.35);
  }

  .summary-card span {
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #475569;
  }

  .summary-card strong {
    font-size: 20px;
  }

  .section {
    background: #ffffff;
    border-radius: 16px;
    box-shadow: 0 12px 40px rgba(15, 23, 42, 0.08);
    padding: 24px 28px;
    margin-bottom: 32px;
  }

  .section h2 {
    margin-top: 0;
    font-size: 20px;
    color: #1e293b;
  }

  .section-lead {
    color: #475569;
    margin-bottom: 16px;
  }

  table {
    width: 100%;
    border-collapse: collapse;
  }

  th {
    text-align: left;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #475569;
    border-bottom: 2px solid #e2e8f0;
    padding: 12px;
  }

  td {
    border-bottom: 1px solid #e2e8f0;
    padding: 14px 12px;
    vertical-align: top;
  }

  .cell-title {
    font-weight: 600;
    color: #0f172a;
  }

  .cell-description {
    color: #475569;
    font-size: 13px;
    margin-top: 8px;
  }

  .muted {
    color: #94a3b8;
  }

  code {
    font-family: 'JetBrains Mono', 'Fira Code', 'SFMono-Regular', Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New',
      monospace;
    font-size: 12px;
    background: #f8fafc;
    border-radius: 6px;
    padding: 6px 8px;
    display: inline-block;
    word-break: break-all;
  }

  pre {
    background: #0f172a;
    color: #e2e8f0;
    padding: 16px;
    border-radius: 12px;
    overflow-x: auto;
    font-size: 12px;
    line-height: 1.5;
  }

  .proof-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 16px;
  }

  .proof-card {
    background: #0f172a;
    color: #e2e8f0;
    border-radius: 16px;
    padding: 16px 18px;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .proof-card .cell-title {
    color: #f8fafc;
  }

  .proof-card .cell-description {
    color: rgba(226, 232, 240, 0.85);
  }
`;

const escapeHtml = (value: string): string =>
  value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

const formatTimestamp = (value: string): string => {
  if (!value) {
    return 'Belirtilmedi';
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return `${date.toISOString().replace('T', ' ').replace('Z', ' UTC')}`;
};

const buildManifestSummarySection = (
  label: string,
  info: ManifestForDiff,
): string => {
  const manifest = info.manifest as LedgerAwareManifest;
  const ledgerMeta = manifest.ledger ?? null;
  const merkle = manifest.merkle ?? null;

  const rows: Array<{ key: string; value: string }> = [
    { key: 'Manifest Özeti', value: info.digest },
    { key: 'Oluşturulma', value: formatTimestamp(info.createdAt) },
    { key: 'Snapshot', value: merkle?.snapshotId ?? 'Belirtilmedi' },
    { key: 'Merkle Kökü', value: merkle?.root ?? 'Belirtilmedi' },
    { key: 'Ledger Kökü', value: ledgerMeta?.root ?? 'Belirtilmedi' },
    { key: 'Önceki Ledger Kökü', value: ledgerMeta?.previousRoot ?? 'Belirtilmedi' },
    {
      key: 'Doğrulanan Kanıtlar',
      value: `${info.proofs.verified}/${info.proofs.total}`,
    },
  ];

  const rowHtml = rows
    .map(
      (row) =>
        `<tr><th scope="row">${escapeHtml(row.key)}</th><td><div class="cell-title">${escapeHtml(row.value)}</div></td></tr>`,
    )
    .join('');

  return `<section class="section">
    <h2>${escapeHtml(label)}</h2>
    <table>
      <tbody>${rowHtml}</tbody>
    </table>
  </section>`;
};

const buildLedgerDiffItems = (
  baseInfo: ManifestForDiff,
  targetInfo: ManifestForDiff,
  diff: ReturnType<typeof computeManifestDiff>,
): LedgerAttestationDiffItem[] => {
  const targetManifest = targetInfo.manifest as LedgerAwareManifest;
  const baseManifest = baseInfo.manifest as LedgerAwareManifest;

  const formatChangedAdded = diff.changed.map(
    (entry) => `${entry.path} (${entry.targetSha256.slice(0, 12)})`,
  );
  const formatChangedRemoved = diff.changed.map(
    (entry) => `${entry.path} (${entry.baseSha256.slice(0, 12)})`,
  );

  const addedEvidence = [
    ...diff.added.map((entry) => `${entry.path} (${entry.sha256.slice(0, 12)})`),
    ...formatChangedAdded,
  ];
  const removedEvidence = [
    ...diff.removed.map((entry) => `${entry.path} (${entry.sha256.slice(0, 12)})`),
    ...formatChangedRemoved,
  ];

  const attestedAt = targetManifest.createdAt ?? targetInfo.createdAt;

  return [
    {
      snapshotId: targetManifest.merkle?.snapshotId ?? 'Belirtilmedi',
      ledgerRoot:
        targetManifest.ledger?.root ?? targetManifest.merkle?.root ?? targetInfo.digest,
      previousLedgerRoot:
        targetManifest.ledger?.previousRoot ?? baseManifest.ledger?.root ?? baseInfo.digest,
      manifestDigest: targetInfo.digest,
      attestedAt,
      addedEvidence: addedEvidence.length > 0 ? addedEvidence : undefined,
      removedEvidence: removedEvidence.length > 0 ? removedEvidence : undefined,
    },
  ];
};

const buildProofSection = (
  label: string,
  info: ManifestForDiff,
  interestingPaths: Set<string>,
): string => {
  const manifest = info.manifest as LedgerAwareManifest;
  const cards = manifest.files
    .filter((file) => interestingPaths.has(file.path) && file.proof)
    .map((file) => {
      const proof = file.proof!;
      const header = `<div class="cell-title">${escapeHtml(file.path)}</div>`;
      const digest = `<div class="cell-description">SHA-256: <code>${escapeHtml(
        file.sha256,
      )}</code></div>`;
      const proofBlock = `<pre>${escapeHtml(proof.proof)}</pre>`;
      return `<div class="proof-card">${header}${digest}${proofBlock}</div>`;
    });

  if (cards.length === 0) {
    return `<section class="section">
      <h2>${escapeHtml(label)}</h2>
      <p class="section-lead">Seçilen kanıtlar için ekli ledger kanıtı bulunamadı.</p>
    </section>`;
  }

  return `<section class="section">
    <h2>${escapeHtml(label)}</h2>
    <p class="section-lead">İlgili kanıt dosyalarının Merkle kanıtları.</p>
    <div class="proof-grid">${cards.join('')}</div>
  </section>`;
};

export const runLedgerReport = async (options: LedgerReportOptions): Promise<LedgerReportResult> => {
  const baseInfo = await loadManifestForDiff('base', options.baseManifestPath);
  const targetInfo = await loadManifestForDiff('target', options.targetManifestPath);
  const diff = computeManifestDiff(baseInfo, targetInfo);
  const ledgerDiffs = buildLedgerDiffItems(baseInfo, targetInfo, diff);

  const interestingPaths = new Set<string>();
  diff.added.forEach((entry) => interestingPaths.add(entry.path));
  diff.removed.forEach((entry) => interestingPaths.add(entry.path));
  diff.changed.forEach((entry) => interestingPaths.add(entry.path));

  await ensureDirectory(options.outputDir);

  const summaryCards = [
    { label: 'Eklenen Kanıt', value: diff.added.length.toString(), accent: diff.added.length > 0 },
    {
      label: 'Kaldırılan Kanıt',
      value: diff.removed.length.toString(),
      accent: diff.removed.length > 0,
    },
    {
      label: 'Güncellenen Kanıt',
      value: diff.changed.length.toString(),
      accent: diff.changed.length > 0,
    },
    {
      label: 'Doğrulanan Kanıtlar',
      value: `${targetInfo.proofs.verified}/${targetInfo.proofs.total}`,
      accent: targetInfo.proofs.verified !== targetInfo.proofs.total,
    },
  ];

  const summaryCardsHtml = summaryCards
    .map(
      (card) =>
        `<div class="summary-card${card.accent ? ' summary-card--accent' : ''}">
          <span>${escapeHtml(card.label)}</span>
          <strong>${escapeHtml(card.value)}</strong>
        </div>`,
    )
    .join('');

  const relativeBase = path.relative(process.cwd(), baseInfo.resolvedPath);
  const relativeTarget = path.relative(process.cwd(), targetInfo.resolvedPath);

  const html = `<!DOCTYPE html>
  <html lang="tr">
    <head>
      <meta charset="utf-8" />
      <title>${escapeHtml(options.title ?? 'SOIPack Ledger Raporu')}</title>
      <style>
        ${LEDGER_REPORT_STYLES}
      </style>
    </head>
    <body>
      <header>
        <h1>${escapeHtml(options.title ?? 'SOIPack Ledger Raporu')}</h1>
        <p>Referans manifest: ${escapeHtml(relativeBase)} (${escapeHtml(baseInfo.digest)})</p>
        <p>Hedef manifest: ${escapeHtml(relativeTarget)} (${escapeHtml(targetInfo.digest)})</p>
        <p>Rapor tarihi: ${escapeHtml(formatTimestamp(getCurrentTimestamp()))}</p>
      </header>
      <main>
        <section class="section">
          <h2>Özet</h2>
          <p class="section-lead">Ledger attestation farkı ve manifest doğrulamaları.</p>
          <div class="summary-grid">${summaryCardsHtml}</div>
        </section>
        ${buildManifestSummarySection('Referans Manifest', baseInfo)}
        ${buildManifestSummarySection('Hedef Manifest', targetInfo)}
        ${renderLedgerDiffSection({ diffs: ledgerDiffs })}
        ${buildProofSection('Referans Manifest Kanıtları', baseInfo, interestingPaths)}
        ${buildProofSection('Hedef Manifest Kanıtları', targetInfo, interestingPaths)}
      </main>
    </body>
  </html>`;

  const pdfBuffer = await printToPDF(html, {
    manifestId: targetInfo.digest.slice(0, 12),
    generatedAt: getCurrentTimestamp(),
    version: packageInfo.version,
  });

  const pdfPath = path.join(options.outputDir, 'ledger-report.pdf');
  await fsPromises.writeFile(pdfPath, pdfBuffer);
  const pdfSha256 = createHash('sha256').update(pdfBuffer).digest('hex');

  let signaturePath: string | undefined;
  let signatureBase64: string | undefined;
  if (options.signingKey) {
    try {
      const signature = signDetached(null, pdfBuffer, options.signingKey);
      signatureBase64 = signature.toString('base64');
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      throw new Error(`Ledger raporu Ed25519 imzası oluşturulamadı: ${reason}`);
    }

    signaturePath = path.join(options.outputDir, 'ledger-report.pdf.sig');
    await fsPromises.writeFile(signaturePath, `${signatureBase64}\n`, 'utf8');
  }

  return {
    pdfPath,
    pdfSha256,
    ledgerDiffs,
    ...(signaturePath ? { signaturePath } : {}),
    ...(signatureBase64 ? { signature: signatureBase64 } : {}),
  };
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
  analysis?: {
    baselineSnapshot?: string;
    baselineGitRef?: string;
  };
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
  report?: {
    planConfig?: string;
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
    cobertura: config.inputs?.cobertura
      ? path.resolve(baseDir, config.inputs.cobertura)
      : undefined,
    git: config.inputs?.git ? path.resolve(baseDir, config.inputs.git) : undefined,
    polyspace: config.inputs?.polyspace
      ? path.resolve(baseDir, config.inputs.polyspace)
      : undefined,
    ldra: config.inputs?.ldra ? path.resolve(baseDir, config.inputs.ldra) : undefined,
    vectorcast: config.inputs?.vectorcast
      ? path.resolve(baseDir, config.inputs.vectorcast)
      : undefined,
    simulink: config.inputs?.simulink
      ? path.resolve(baseDir, config.inputs.simulink)
      : undefined,
    parasoft: config.inputs?.parasoft?.map((entry) => path.resolve(baseDir, entry)),
    designCsv: config.inputs?.designCsv
      ? path.resolve(baseDir, config.inputs.designCsv)
      : undefined,
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

  const baselineSnapshotFromConfig = config.analysis?.baselineSnapshot
    ? path.resolve(baseDir, config.analysis.baselineSnapshot)
    : undefined;
  const baselineGitRefFromConfig = config.analysis?.baselineGitRef;
  const analyzeResult = await runAnalyze({
    input: workDir,
    output: analysisDir,
    level,
    objectives: config.objectives?.file ? path.resolve(baseDir, config.objectives.file) : undefined,
    projectName: config.project?.name,
    projectVersion: config.project?.version,
    baselineSnapshot: baselineSnapshotFromConfig,
    baselineGitRef: baselineGitRefFromConfig,
  });

  const planConfigFromConfig = config.report?.planConfig
    ? path.resolve(baseDir, config.report.planConfig)
    : undefined;
  const reportResult = await runReport({
    input: analysisDir,
    output: reportDir,
    planConfig: planConfigFromConfig,
  });

  if (reportResult.warnings.length > 0) {
    reportResult.warnings.forEach((warning) => {
      logger?.warn({ command: 'report', warning }, 'Plan generation warning.');
    });
  }

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
    {
      complianceHtml: reportResult.complianceHtml,
      complianceJson: reportResult.complianceJson,
      complianceCsv: reportResult.complianceCsv,
      traceCsv: reportResult.traceCsv,
      command: 'run',
    },
    'Raporlar üretildi.',
  );
  logger?.info(
    {
      manifestPath: packResult.manifestPath,
      sbomPath: packResult.sbomPath,
      sbomDigest: packResult.sbomSha256,
      command: 'run',
    },
    'Manifest kaydedildi.',
  );
  logger?.info(
    {
      archivePath: packResult.archivePath,
      manifestId: packResult.manifestId,
      sbomPath: packResult.sbomPath,
      sbomDigest: packResult.sbomSha256,
      command: 'run',
    },
    'Paket hazırlandı.',
  );

  if (analyzeResult.exitCode === exitCodes.missingEvidence) {
    logger?.warn(
      { command: 'run' },
      translateCli('cli.warnings.missingEvidence'),
    );
    return exitCodes.missingEvidence;
  }
  logger?.info({ command: 'run' }, 'Tüm hedef kanıtlar başarıyla toplandı.');
  return exitCodes.success;
};

interface GlobalArguments {
  verbose?: boolean;
  license?: string;
  allowInsecureHttp?: boolean;
  locale?: string;
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
  const toFingerprint = (value: string | undefined): string | undefined => {
    if (!value) {
      return undefined;
    }
    const digest = createHash('sha256').update(value).digest('hex');
    return `sha256:${digest.slice(0, 12)}`;
  };
  logger.debug(
    {
      ...context,
      licenseIdFingerprint: toFingerprint(license.licenseId),
      issuedToFingerprint: toFingerprint(license.issuedTo),
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
    translateCli('cli.errors.unexpected'),
  );
};

const PIPELINE_LICENSE_FEATURES = {
  import: 'import',
  analyze: 'analyze',
  report: 'report',
  pack: 'pack',
  stage: 'soiStages',
} as const;

interface RenderGsnCommandOptions extends GlobalArguments {
  snapshot?: string | string[];
  objectives?: string | string[];
  output: string | string[];
}

const normalizeSingleOption = (value: string | string[] | undefined): string | undefined => {
  if (value === undefined) {
    return undefined;
  }
  if (Array.isArray(value)) {
    const [first] = value;
    return first === undefined ? undefined : String(first);
  }
  return String(value);
};

export const renderGsnCommand: CommandModule<GlobalArguments, RenderGsnCommandOptions> = {
  command: 'render-gsn',
  describe: 'Uyum snapshot ve hedef metaverileriyle GSN grafiğini Graphviz DOT olarak dışa aktarır.',
  builder: (yargsCommand) =>
    yargsCommand
      .option('snapshot', {
        alias: 's',
        describe: 'Uyum snapshot JSON dosyası.',
        type: 'string',
      })
      .option('objectives', {
        alias: 'j',
        describe: 'Hedef meta verilerini içeren Objective listesi JSON dosyası.',
        type: 'string',
      })
      .option('output', {
        alias: 'o',
        describe: 'Üretilen Graphviz DOT çıktısının yazılacağı dosya.',
        type: 'string',
        demandOption: true,
      }),
  handler: async (argv) => {
    const logger = getLogger(argv);
    const snapshotOption = normalizeSingleOption(argv.snapshot);
    const objectivesOption = normalizeSingleOption(argv.objectives);
    const outputOption = normalizeSingleOption(argv.output);

    if (!outputOption) {
      console.error('GSN grafiği için --output dosyası belirtilmelidir.');
      process.exit(1);
    }

    const snapshotPath = snapshotOption ? path.resolve(snapshotOption) : undefined;
    const objectivesPath = objectivesOption ? path.resolve(objectivesOption) : undefined;
    const outputPath = path.resolve(outputOption);

    const context = {
      command: 'render-gsn',
      outputPath,
      ...(snapshotPath ? { snapshotPath } : {}),
      ...(objectivesPath ? { objectivesPath } : {}),
    } as const;

    if (!snapshotPath && !objectivesPath) {
      console.error('En azından --snapshot veya --objectives seçeneğinden biri belirtilmelidir.');
      process.exitCode = exitCodes.error;
      return;
    }

    try {
      let snapshot: ComplianceSnapshot | undefined;
      if (snapshotPath) {
        await ensureReadableFile(snapshotPath, 'Snapshot dosyası');
        snapshot = await readJsonFile<ComplianceSnapshot>(snapshotPath);
      }

      let objectives: Objective[] | undefined;
      if (objectivesPath) {
        await ensureReadableFile(objectivesPath, 'Objectives dosyası');
        const parsedObjectives = await readJsonFile<unknown>(objectivesPath);
        if (!Array.isArray(parsedObjectives)) {
          console.error('Objectives dosyası geçerli bir JSON dizisi içermelidir.');
          process.exit(1);
        }
        objectives = parsedObjectives as Objective[];
      }

      await ensureWritableParentDirectory(outputPath);

      const dot = await renderGsnGraphDot({ snapshot, objectives });

      await fsPromises.writeFile(outputPath, dot, 'utf8');

      console.log(
        `GSN grafiği Graphviz DOT çıktısı ${path.relative(process.cwd(), outputPath) || '.'} dosyasına yazıldı.`,
      );

      logger.info(
        {
          ...context,
          objectives: objectives?.length ?? 0,
          hasSnapshot: Boolean(snapshot),
          bytesWritten: Buffer.byteLength(dot, 'utf8'),
        },
        'GSN grafiği DOT olarak dışa aktarıldı.',
      );
      process.exitCode = exitCodes.success;
    } catch (error) {
      logCliError(logger, error, context);
      process.exitCode = exitCodes.error;
    }
  },
};

const requireLicenseFeature = (license: LicensePayload, feature: string): void => {
  const features = Array.isArray(license.features) ? license.features : [];
  if (!features.includes(feature)) {
    throw new LicenseError(
      `Lisans bu işlem için gerekli özelliği içermiyor (${feature}).`,
    );
  }
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
    .option('allow-insecure-http', {
      describe: 'HTTPS yerine HTTP üzerinden indirmelere izin verir (varsayılan: devre dışı).',
      type: 'boolean',
      global: true,
      default: false,
    })
    .option('locale', {
      describe: 'CLI mesajları için tercih edilen dil (örnek: en veya tr).',
      type: 'string',
      global: true,
      choices: getCliAvailableLocales(),
      default: getCliLocale(),
    })
    .middleware((argv) => {
      const localeOption = argv.locale;
      const value = Array.isArray(localeOption) ? localeOption[0] : (localeOption as string | undefined);
      setCliLocale(value);
    }, true)
    .version('version', 'Sürüm bilgisini gösterir.', formatVersion())
    .alias('version', ['v', 'V'])
    .command(
      'objectives list',
      'DO-178C hedef kataloğunu listeler.',
      (y) =>
        y
          .option('objectives', {
            describe: 'Uyum hedefleri JSON dosyası.',
            type: 'string',
          })
          .option('level', {
            describe: 'Certification level filter (A-E).',
            type: 'string',
            choices: certificationLevels as unknown as string[],
          }),
      async (argv) => {
        const logger = getLogger(argv);
        const licensePath = getLicensePath(argv);
        const levelOption = argv.level as string | undefined;
        const normalizedLevel = levelOption
          ? (levelOption.toUpperCase() as CertificationLevel | undefined)
          : undefined;
        const context = {
          command: 'objectives list',
          licensePath,
          objectives: argv.objectives,
          level: normalizedLevel,
        };

        try {
          const license = await verifyLicenseFile(licensePath);
          logLicenseValidated(logger, license, context);

          if (normalizedLevel && !certificationLevels.includes(normalizedLevel)) {
            throw new Error(`Geçersiz seviye değeri: ${levelOption}`);
          }

          const result = await runObjectivesList({
            objectives: argv.objectives ? String(argv.objectives) : undefined,
            level: normalizedLevel,
          });

          if (result.objectives.length === 0) {
            console.log('Seçilen kriterlere uygun hedef bulunamadı.');
          } else {
            console.log(formatObjectivesTable(result.objectives));
            console.log('');
            console.log(
              `${result.objectives.length} hedef listelendi (kaynak: ${path.relative(process.cwd(), result.sourcePath)}).`,
            );
          }

          logger.info(
            {
              ...context,
              sourcePath: result.sourcePath,
              count: result.objectives.length,
            },
            'Hedef kataloğu listelendi.',
          );
          process.exitCode = exitCodes.success;
        } catch (error) {
          logCliError(logger, error, context);
          process.exitCode = exitCodes.error;
        }
      },
    )
    .command(
      'import',
      'Gereksinim, test ve kapsam kanıtlarını çalışma alanına aktarır.',
      (y) =>
        y
          .option('jira', {
            describe: 'Jira CSV dışa aktarımının yolu.',
            type: 'string',
          })
          .option('jira-defects', {
            describe: 'Jira CSV dışa aktarımından problem raporları (--jira-defects dosya.csv).',
            type: 'array',
          })
          .option('jira-api-url', {
            describe: 'Jira Cloud REST API temel adresi (ör. https://jira.example.com).',
            type: 'string',
          })
          .option('jira-api-project', {
            describe: 'Jira proje anahtarı veya kimliği.',
            type: 'string',
          })
          .option('jira-api-email', {
            describe: 'Jira hesabı e-posta adresi (temel kimlik doğrulama için).',
            type: 'string',
          })
          .option('jira-api-token', {
            describe: 'Jira API erişim jetonu (PAT veya OAuth).',
            type: 'string',
          })
          .option('jira-api-requirements-jql', {
            describe: 'Gereksinimleri çekecek özel JQL ifadesi.',
            type: 'string',
          })
          .option('jira-api-tests-jql', {
            describe: 'Test kayıtlarını çekecek özel JQL ifadesi.',
            type: 'string',
          })
          .option('jira-api-page-size', {
            describe: 'Jira API sayfa boyutu (varsayılan 50).',
            type: 'number',
          })
          .option('jira-api-max-pages', {
            describe: 'Jira API sayfa üst sınırı (varsayılan 20).',
            type: 'number',
          })
          .option('jira-api-timeout', {
            describe: 'Jira API istek zaman aşımı (ms).',
            type: 'number',
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
          .option('simulink', {
            describe: 'Simulink model kapsam raporu JSON çıktısı.',
            type: 'string',
          })
          .option('parasoft', {
            describe: 'Parasoft C/C++test XML raporu (--parasoft rapor.xml).',
            type: 'array',
          })
          .option('git', {
            describe: 'Git deposu kök dizini.',
            type: 'string',
          })
          .option('doors-url', {
            describe: 'DOORS Next OSLC temel adresi (ör. https://doors.example.com).',
            type: 'string',
          })
          .option('doors-project', {
            describe: 'DOORS Next proje alanı kimliği.',
            type: 'string',
          })
          .option('doors-username', {
            describe: 'DOORS Next kullanıcı adı (opsiyonel).',
            type: 'string',
          })
          .option('doors-password', {
            describe: 'DOORS Next parolası (opsiyonel, temel kimlik doğrulama için).',
            type: 'string',
          })
          .option('doors-token', {
            describe: 'DOORS Next OAuth erişim tokenı (opsiyonel).',
            type: 'string',
          })
          .option('jama-url', {
            describe: 'Jama REST API temel adresi (ör. https://jama.example.com).',
            type: 'string',
          })
          .option('jama-project', {
            describe: 'Jama proje kimliği veya anahtar değeri.',
            type: 'string',
          })
          .option('jama-token', {
            describe: 'Jama REST API erişim tokenı.',
            type: 'string',
          })
          .option('jama-page-size', {
            describe: 'Jama REST API sayfalama boyutu.',
            type: 'number',
          })
          .option('jama-max-pages', {
            describe: 'Jama REST API sayfa üst sınırı.',
            type: 'number',
          })
          .option('jama-timeout', {
            describe: 'Jama REST API istek zaman aşımı (ms).',
            type: 'number',
          })
          .option('jama-rate-limit-delays', {
            describe:
              'Jama oran sınırlaması tekrar deneme gecikmeleri (ms) virgülle ayrılmış liste.',
            type: 'string',
          })
          .option('jama-requirements-endpoint', {
            describe:
              'Jama gereksinimlerini döndüren uç nokta (varsayılan: /rest/latest/projects/:projectId/items?itemType=REQUIREMENT).',
            type: 'string',
          })
          .option('jama-tests-endpoint', {
            describe:
              'Jama test kayıtlarını döndüren uç nokta (varsayılan: /rest/latest/projects/:projectId/items?itemType=TEST_CASE).',
            type: 'string',
          })
          .option('jama-relationships-endpoint', {
            describe:
              'Jama ilişki kayıtlarını döndüren uç nokta (varsayılan: /rest/latest/projects/:projectId/relationships).',
            type: 'string',
          })
          .option('doors-page-size', {
            describe: 'DOORS Next sayfalama boyutu (varsayılan 200).',
            type: 'number',
          })
          .option('doors-max-pages', {
            describe: 'DOORS Next sayfa üst sınırı (varsayılan 50).',
            type: 'number',
          })
          .option('doors-timeout', {
            describe: 'DOORS Next istek zaman aşımı (ms).',
            type: 'number',
          })
          .option('polarion-url', {
            describe: 'Polarion REST API temel adresi (ör. https://polarion.example.com).',
            type: 'string',
          })
          .option('polarion-project', {
            describe: 'Polarion proje kimliği.',
            type: 'string',
          })
          .option('polarion-username', {
            describe: 'Polarion kullanıcı adı (opsiyonel).',
            type: 'string',
          })
          .option('polarion-password', {
            describe: 'Polarion parolası (opsiyonel, yalnızca temel kimlik doğrulama için).',
            type: 'string',
          })
          .option('polarion-token', {
            describe: 'Polarion erişim tokenı (opsiyonel).',
            type: 'string',
          })
          .option('polarion-requirements-endpoint', {
            describe:
              'Gereksinimleri döndüren uç nokta (varsayılan: /polarion/api/v2/projects/:projectId/workitems).',
            type: 'string',
          })
          .option('polarion-tests-endpoint', {
            describe:
              'Test çalıştırmalarını döndüren uç nokta (varsayılan: /polarion/api/v2/projects/:projectId/test-runs).',
            type: 'string',
          })
          .option('polarion-builds-endpoint', {
            describe: 'Yapı metaverisini döndüren uç nokta (varsayılan: /polarion/api/v2/projects/:projectId/builds).',
            type: 'string',
          })
          .option('jenkins-url', {
            describe: 'Jenkins sunucusunun temel adresi (ör. https://ci.example.com).',
            type: 'string',
          })
          .option('jenkins-job', {
            describe: 'Jenkins iş adı veya yol ifadesi (ör. avionics/build).',
            type: 'string',
          })
          .option('jenkins-build', {
            describe: 'Belirli bir build numarası veya etiketi (varsayılan: lastCompletedBuild).',
            type: 'string',
          })
          .option('jenkins-username', {
            describe: 'Jenkins kullanıcı adı (opsiyonel).',
            type: 'string',
          })
          .option('jenkins-password', {
            describe: 'Jenkins parolası (opsiyonel, yalnızca temel kimlik doğrulama için).',
            type: 'string',
          })
          .option('jenkins-token', {
            describe: 'Jenkins API tokenı (opsiyonel).',
            type: 'string',
          })
          .option('jenkins-build-endpoint', {
            describe:
              'Build detaylarını döndüren uç nokta (varsayılan: /job/:job/:build/api/json).',
            type: 'string',
          })
          .option('jenkins-tests-endpoint', {
            describe:
              'JUnit test raporunu döndüren uç nokta (varsayılan: /job/:job/:build/testReport/api/json).',
            type: 'string',
          })
          .option('jenkins-artifacts-dir', {
            describe: 'Jenkins artefaktlarının indirileceği yerel dizin (varsayılan: çalışma dizini).',
            type: 'string',
          })
          .option('jenkins-coverage-artifact', {
            describe:
              'Jenkins coverage artefaktı tanımı (ör. type=lcov,path=coverage/lcov.info veya lcov:coverage/lcov.info@5242880).',
            type: 'array',
          })
          .option('jenkins-coverage-max-bytes', {
            describe: 'Tüm Jenkins coverage artefaktları için global bayt limiti (varsayılan: 10485760).',
            type: 'number',
          })
          .option('azure-devops-url', {
            describe: 'Azure DevOps temel URL\'si (örn. https://dev.azure.com).',
            type: 'string',
          })
          .option('azure-devops-organization', {
            describe: 'Azure DevOps organizasyon adı.',
            type: 'string',
          })
          .option('azure-devops-project', {
            describe: 'Azure DevOps proje adı.',
            type: 'string',
          })
          .option('azure-devops-pat', {
            describe: 'Azure DevOps kişisel erişim belirteci.',
            type: 'string',
          })
          .option('azure-devops-requirements-endpoint', {
            describe:
              'Gereksinim iş öğelerini döndüren uç nokta (varsayılan: /:organization/:project/_apis/wit/workitems).',
            type: 'string',
          })
          .option('azure-devops-tests-endpoint', {
            describe:
              'Test çalıştırmalarını döndüren uç nokta (varsayılan: /:organization/:project/_apis/test/Runs).',
            type: 'string',
          })
          .option('azure-devops-builds-endpoint', {
            describe:
              'Yapı kayıtlarını döndüren uç nokta (varsayılan: /:organization/:project/_apis/build/builds).',
            type: 'string',
          })
          .option('azure-devops-attachments-endpoint', {
            describe:
              'Ekleri indirmek için kullanılacak uç nokta (varsayılan: /:organization/:project/_apis/wit/workitems/:workItemId/attachments/:attachmentId).',
            type: 'string',
          })
          .option('azure-devops-requirements-query', {
            describe: 'WIQL gereksinim sorgusu (varsayılan: tüm gereksinimler).',
            type: 'string',
          })
          .option('azure-devops-test-plan', {
            describe: 'Test planı kimliği (opsiyonel).',
            type: 'string',
          })
          .option('azure-devops-test-suite', {
            describe: 'Test suite kimliği (opsiyonel).',
            type: 'string',
          })
          .option('azure-devops-test-run', {
            describe: 'Test run kimliği (opsiyonel).',
            type: 'string',
          })
          .option('azure-devops-test-outcome', {
            describe: 'Test sonuçlarını filtrelemek için outcome değeri (örn. Passed, Failed).',
            type: 'string',
          })
          .option('azure-devops-build-definition', {
            describe: 'Build tanımı kimliği (opsiyonel).',
            type: 'string',
          })
          .option('azure-devops-timeout', {
            describe: 'Azure DevOps HTTP zaman aşımı (ms).',
            type: 'number',
          })
          .option('azure-devops-page-size', {
            describe: 'Azure DevOps sayfa boyutu limiti.',
            type: 'number',
          })
          .option('azure-devops-max-pages', {
            describe: 'Azure DevOps maksimum sayfa sayısı.',
            type: 'number',
          })
          .option('azure-devops-max-attachment-bytes', {
            describe: 'Tek bir Azure DevOps ekinin maksimum boyutu (bayt).',
            type: 'number',
          })
          .option('import', {
            describe:
              'Plan, standart, QA kaydı gibi artefaktlar ve araç çıktıları (plan=, standard=, qa_record=, polyspace=, simulink=, ...).',
            type: 'array',
          })
          .option('qa', {
            describe: 'QA denetim imza CSV dosyaları (--qa dosya.csv).',
            type: 'array',
          })
          .option('trace-links-csv', {
            describe: 'Manuel gereksinim izlenebilirlik bağlantıları CSV dosyası.',
            type: 'string',
          })
          .option('trace-links-json', {
            describe: 'Manuel gereksinim izlenebilirlik bağlantıları JSON dosyası.',
            type: 'string',
          })
          .option('design-csv', {
            describe: 'Tasarım kayıtları CSV dosyası.',
            type: 'string',
          })
          .option('doors-classic-reqs', {
            describe: 'DOORS Classic gereksinim modülü CSV dışa aktarımları.',
            type: 'array',
          })
          .option('doors-classic-traces', {
            describe: 'DOORS Classic izlenebilirlik modülü CSV dışa aktarımları.',
            type: 'array',
          })
          .option('doors-classic-tests', {
            describe: 'DOORS Classic test modülü CSV dışa aktarımları.',
            type: 'array',
          })
          .option('independent-source', {
            describe:
              'Belirtilen kanıt kaynaklarını bağımsız incelemeden geçmiş kabul eder (ör. junit, vectorcast).',
            type: 'array',
          })
          .option('independent-artifact', {
            describe:
              'Artefakt türlerini veya belirli dosyaları bağımsız olarak işaretler (ör. analysis veya analysis=rapor.md).',
            type: 'array',
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

          const importArguments = parseImportArguments((argv as Record<string, unknown>)['import']);
          const qaLogs = parseStringArrayOption((argv as Record<string, unknown>).qa, '--qa');
          const jiraDefects = parseStringArrayOption(
            (argv as Record<string, unknown>).jiraDefects,
            '--jira-defects',
          );
          const doorsClassicReqs = parseStringArrayOption(
            (argv as Record<string, unknown>).doorsClassicReqs,
            '--doors-classic-reqs',
          );
          const doorsClassicTraces = parseStringArrayOption(
            (argv as Record<string, unknown>).doorsClassicTraces,
            '--doors-classic-traces',
          );
          const doorsClassicTests = parseStringArrayOption(
            (argv as Record<string, unknown>).doorsClassicTests,
            '--doors-classic-tests',
          );
          const parasoft = parseStringArrayOption(
            (argv as Record<string, unknown>).parasoft,
            '--parasoft',
          );

          const result = await runImport({
            output: argv.output,
            jira: argv.jira,
            jiraDefects,
            jiraCloud: buildJiraCloudOptions(argv),
            reqif: argv.reqif,
            junit: argv.junit,
            lcov: argv.lcov,
            cobertura: argv.cobertura,
            simulink:
              (argv.simulink as string | undefined) ?? importArguments.adapters.simulink,
            git: argv.git,
            traceLinksCsv: argv.traceLinksCsv as string | undefined,
            traceLinksJson: argv.traceLinksJson as string | undefined,
            designCsv: argv.designCsv as string | undefined,
            doorsClassicReqs,
            doorsClassicTraces,
            doorsClassicTests,
            polyspace: importArguments.adapters.polyspace,
            ldra: importArguments.adapters.ldra,
            vectorcast: importArguments.adapters.vectorcast,
            manualArtifacts: importArguments.manualArtifacts,
            qaLogs,
            parasoft,
            polarion: buildPolarionOptions(argv),
            jenkins: buildJenkinsOptions(argv),
            doorsNext: buildDoorsNextOptions(argv),
            jama: buildJamaOptions(argv),
            azureDevOps: buildAzureDevOpsOptions(argv),
            objectives: argv.objectives,
            level: argv.level as CertificationLevel | undefined,
            projectName: argv.projectName as string | undefined,
            projectVersion: argv.projectVersion as string | undefined,
            independentSources: argv.independentSource as Array<string> | undefined,
            independentArtifacts: argv.independentArtifact as Array<string> | undefined,
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
          })
          .option('parasoft', {
            describe: 'Parasoft C/C++test XML raporu (--parasoft rapor.xml).',
            type: 'array',
          })
          .option('stage', {
            describe: 'SOI aşaması filtresi (SOI-1…SOI-4).',
            type: 'string',
          })
          .option('baseline-snapshot', {
            describe: 'Değişiklik etkisi analizi için referans uyum snapshot JSON dosyası.',
            type: 'string',
            coerce: normalizeBaselineSnapshotOption,
          })
          .option('baseline-git-ref', {
            describe:
              'Git deposundan referans uyum snapshot\'ını okumak için kullanılacak referans (örn. main).',
            type: 'string',
            coerce: normalizeBaselineGitRefOption,
          })
          .option('baseline-git-ref', {
            describe:
              'Git deposundan referans uyum snapshot\'ını okumak için kullanılacak referans (örn. main).',
            type: 'string',
            coerce: normalizeBaselineGitRefOption,
          }),
      async (argv) => {
        const logger = getLogger(argv);
        const licensePath = getLicensePath(argv);
        const stage = normalizeStageOption(argv.stage);
        const context = {
          command: 'analyze',
          licensePath,
          input: argv.input,
          output: argv.output,
          stage,
        };

        try {
          const license = await verifyLicenseFile(licensePath);
          logLicenseValidated(logger, license, context);
          requireLicenseFeature(license, PIPELINE_LICENSE_FEATURES.analyze);
          if (stage) {
            requireLicenseFeature(license, PIPELINE_LICENSE_FEATURES.stage);
          }

          const parasoft = parseStringArrayOption(
            (argv as Record<string, unknown>).parasoft,
            '--parasoft',
          );

          const result = await runAnalyze({
            input: argv.input,
            output: argv.output,
            objectives: argv.objectives,
            level: argv.level as CertificationLevel | undefined,
            projectName: argv.projectName as string | undefined,
            projectVersion: argv.projectVersion as string | undefined,
            stage,
            baselineSnapshot: argv.baselineSnapshot as string | undefined,
            baselineGitRef: argv.baselineGitRef as string | undefined,
            parasoft,
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
      'download',
      'Sunucudan paket arşivini ve manifest dosyasını indirir.',
      (y) =>
        y
          .option('api', {
            describe: 'SOIPack API taban URL\'i.',
            type: 'string',
            demandOption: true,
          })
          .option('token', {
            describe: 'Bearer yetkilendirme token\'ı.',
            type: 'string',
            demandOption: true,
          })
          .option('package', {
            alias: 'p',
            describe: 'Paket iş kimliği.',
            type: 'string',
            demandOption: true,
          })
          .option('output', {
            alias: 'o',
            describe: 'İndirilen dosyaların kaydedileceği dizin.',
            type: 'string',
            default: '.',
          }),
      async (argv) => {
        const logger = getLogger(argv);
        const apiOption = Array.isArray(argv.api) ? argv.api[0] : argv.api;
        const tokenOption = Array.isArray(argv.token) ? argv.token[0] : argv.token;
        const packageOption = Array.isArray(argv.package) ? argv.package[0] : argv.package;
        const outputOption = Array.isArray(argv.output) ? argv.output[0] : argv.output;
        const allowInsecureHttp = Boolean(argv.allowInsecureHttp);

        const baseUrl = String(apiOption);
        const packageId = String(packageOption);
        const outputDir = path.resolve(String(outputOption));
        const context = {
          command: 'download',
          api: baseUrl,
          packageId,
          outputDir,
          allowInsecureHttp,
        };

        try {
          const result = await downloadPackageArtifacts({
            baseUrl,
            token: String(tokenOption),
            packageId,
            outputDir,
            allowInsecureHttp,
          });
          logger.info({ ...context, ...result }, 'Paket artefaktları indirildi.');
          console.log(`Arşiv indirildi: ${result.archivePath}`);
          console.log(`Manifest indirildi: ${result.manifestPath}`);
          process.exitCode = exitCodes.success;
        } catch (error) {
          logCliError(logger, error, context);
          process.exitCode = exitCodes.error;
        }
      },
    )
    .command(
      'freeze',
      'Sunucudaki kanıt ve konfigürasyon verilerini dondurur.',
      (y) =>
        y
          .option('api', {
            describe: 'SOIPack API taban URL\'i.',
            type: 'string',
            demandOption: true,
          })
          .option('token', {
            describe: 'Bearer yetkilendirme token\'ı.',
            type: 'string',
            demandOption: true,
          }),
      async (argv) => {
        const logger = getLogger(argv);
        const apiOption = Array.isArray(argv.api) ? argv.api[0] : argv.api;
        const tokenOption = Array.isArray(argv.token) ? argv.token[0] : argv.token;
        const allowInsecureHttp = Boolean(argv.allowInsecureHttp);
        const baseUrl = String(apiOption);
        const token = String(tokenOption);
        const context = { command: 'freeze', api: baseUrl, allowInsecureHttp };

        try {
          const result = await runFreeze({
            baseUrl,
            token,
            allowInsecureHttp,
          });
          logger.info({ ...context, snapshotId: result.version.id }, 'Konfigürasyon donduruldu.');
          console.log(`Konfigürasyon donduruldu (snapshot: ${result.version.id}).`);
          process.exitCode = exitCodes.success;
        } catch (error) {
          logCliError(logger, error, context);
          console.error('Konfigürasyon dondurulamadı.');
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
          })
          .option('plan-config', {
            describe: 'Plan şablonlarına ait özelleştirmeleri tanımlayan JSON dosyası.',
            type: 'string',
          })
          .option('tool-usage', {
            describe: 'DO-330 araç kullanım metaverisini içeren JSON dosyası.',
            type: 'string',
          })
          .option('parasoft', {
            describe: 'Parasoft C/C++test XML raporu (--parasoft rapor.xml).',
            type: 'array',
          })
          .option('gsn', {
            describe: 'Goal Structuring Notation grafiğini (DOT) çıktısı olarak üretir.',
            type: 'boolean',
            default: false,
          })
          .option('stage', {
            describe: 'SOI aşaması filtresi (SOI-1…SOI-4).',
            type: 'string',
          }),
      async (argv) => {
        const logger = getLogger(argv);
        const licensePath = getLicensePath(argv);
        const stage = normalizeStageOption(argv.stage);
        const context = {
          command: 'report',
          licensePath,
          input: argv.input,
          output: argv.output,
          stage,
          toolUsage: argv['tool-usage'],
          gsn: Boolean(argv.gsn),
        };

        try {
          const license = await verifyLicenseFile(licensePath);
          logLicenseValidated(logger, license, context);
          requireLicenseFeature(license, PIPELINE_LICENSE_FEATURES.report);
          if (stage) {
            requireLicenseFeature(license, PIPELINE_LICENSE_FEATURES.stage);
          }

          const result = await runReport({
            input: argv.input,
            output: argv.output,
            planConfig: argv['plan-config'] as string | undefined,
            toolUsage: argv['tool-usage'] as string | undefined,
            stage,
            gsn: Boolean(argv.gsn),
          });

          if (result.warnings.length > 0) {
            result.warnings.forEach((warning) => {
              logger.warn({ ...context, warning }, 'Plan generation warning.');
            });
          }

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
      'ingest',
      'Girdi adaptörlerini çalıştırarak uyum ve kapsam raporları üretir.',
      (y) =>
        y
          .option('input', {
            alias: 'i',
            describe: 'Girdi veri dizini.',
            type: 'string',
            default: './data/input',
          })
          .option('output', {
            alias: 'o',
            describe: 'Çıktı raporlarının yazılacağı dizin.',
            type: 'string',
            default: './dist',
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
          .option('parasoft', {
            describe: 'Parasoft C/C++test XML raporu (--parasoft rapor.xml).',
            type: 'array',
          })
          .option('azure-devops-url', {
            describe: 'Azure DevOps temel URL\'si (örn. https://dev.azure.com).',
            type: 'string',
          })
          .option('azure-devops-organization', {
            describe: 'Azure DevOps organizasyon adı.',
            type: 'string',
          })
          .option('azure-devops-project', {
            describe: 'Azure DevOps proje adı.',
            type: 'string',
          })
          .option('azure-devops-pat', {
            describe: 'Azure DevOps kişisel erişim belirteci.',
            type: 'string',
          })
          .option('azure-devops-requirements-endpoint', {
            describe:
              'Gereksinim iş öğelerini döndüren uç nokta (varsayılan: /:organization/:project/_apis/wit/workitems).',
            type: 'string',
          })
          .option('azure-devops-tests-endpoint', {
            describe:
              'Test çalıştırmalarını döndüren uç nokta (varsayılan: /:organization/:project/_apis/test/Runs).',
            type: 'string',
          })
          .option('azure-devops-builds-endpoint', {
            describe:
              'Yapı kayıtlarını döndüren uç nokta (varsayılan: /:organization/:project/_apis/build/builds).',
            type: 'string',
          })
          .option('azure-devops-attachments-endpoint', {
            describe:
              'Ekleri indirmek için kullanılacak uç nokta (varsayılan: /:organization/:project/_apis/wit/workitems/:workItemId/attachments/:attachmentId).',
            type: 'string',
          })
          .option('azure-devops-requirements-query', {
            describe: 'WIQL gereksinim sorgusu (opsiyonel).',
            type: 'string',
          })
          .option('azure-devops-test-plan', {
            describe: 'Test planı kimliği (opsiyonel).',
            type: 'string',
          })
          .option('azure-devops-test-suite', {
            describe: 'Test suite kimliği (opsiyonel).',
            type: 'string',
          })
          .option('azure-devops-test-run', {
            describe: 'Test run kimliği (opsiyonel).',
            type: 'string',
          })
          .option('azure-devops-test-outcome', {
            describe: 'Test sonuçlarını outcome değerine göre filtreler.',
            type: 'string',
          })
          .option('azure-devops-build-definition', {
            describe: 'Build tanımı kimliği (opsiyonel).',
            type: 'string',
          })
          .option('azure-devops-timeout', {
            describe: 'Azure DevOps HTTP zaman aşımı (ms).',
            type: 'number',
          })
          .option('azure-devops-page-size', {
            describe: 'Azure DevOps sayfa boyutu.',
            type: 'number',
          })
          .option('azure-devops-max-pages', {
            describe: 'Azure DevOps maksimum sayfa sayısı.',
            type: 'number',
          })
          .option('azure-devops-max-attachment-bytes', {
            describe: 'Tek bir Azure DevOps ekinin maksimum boyutu (bayt).',
            type: 'number',
          })
          .option('baseline-snapshot', {
            describe: 'Değişiklik etkisi analizi için referans uyum snapshot JSON dosyası.',
            type: 'string',
            coerce: normalizeBaselineSnapshotOption,
          })
          .option('baseline-git-ref', {
            describe:
              'Git deposundan referans uyum snapshot\'ını okumak için kullanılacak referans (örn. main).',
            type: 'string',
            coerce: normalizeBaselineGitRefOption,
          }),
      async (argv) => {
        const logger = getLogger(argv);
        const licensePath = getLicensePath(argv);
        const context = {
          command: 'ingest',
          licensePath,
          input: argv.input,
          output: argv.output,
        };

        try {
          const license = await verifyLicenseFile(licensePath);
          logLicenseValidated(logger, license, context);

          const levelOption = Array.isArray(argv.level) ? argv.level[0] : (argv.level as string | undefined);
          const normalizedLevel = levelOption
            ? (levelOption.toUpperCase() as CertificationLevel | undefined)
            : undefined;
          if (normalizedLevel && !certificationLevels.includes(normalizedLevel)) {
            throw new Error(`Geçersiz seviye değeri: ${levelOption}`);
          }

          const inputDir = Array.isArray(argv.input)
            ? String(argv.input[0])
            : (argv.input as string | undefined) ?? './data/input';
          const outputDir = Array.isArray(argv.output)
            ? String(argv.output[0])
            : (argv.output as string | undefined) ?? './dist';

          const parasoft = parseStringArrayOption(
            (argv as Record<string, unknown>).parasoft,
            '--parasoft',
          );

          const result = await runIngestPipeline({
            inputDir,
            outputDir,
            objectives: argv.objectives as string | undefined,
            level: normalizedLevel,
            projectName: argv.projectName as string | undefined,
            projectVersion: argv.projectVersion as string | undefined,
            baselineSnapshot: argv.baselineSnapshot as string | undefined,
            baselineGitRef: argv.baselineGitRef as string | undefined,
            parasoft,
            azureDevOps: buildAzureDevOpsOptions(argv),
          });

          logger.info(
            {
              ...context,
              reportsDir: result.reportsDir,
              compliance: result.complianceSummary,
              coverage: result.coverageSummary,
            },
            'İçe aktarma ve raporlama tamamlandı.',
          );

          console.log(`Raporlar ${result.reportsDir} dizinine kaydedildi.`);
          console.log(
            `Uyum özeti: ${result.complianceSummary.covered}/${result.complianceSummary.total} hedef tamamen karşılandı.`,
          );
          process.exitCode = result.analyzeExitCode;
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
          })
          .option('cms-bundle', {
            describe: 'PKCS#7/CMS imzası için sertifika ve özel anahtar PEM demeti.',
            type: 'string',
          })
          .option('cms-cert', {
            describe: 'CMS imzası için X.509 sertifikası.',
            type: 'string',
          })
          .option('cms-key', {
            describe: 'CMS imzası için özel anahtar PEM dosyası.',
            type: 'string',
          })
          .option('cms-chain', {
            describe: 'CMS imzasına eklenecek isteğe bağlı sertifika zinciri PEM dosyası.',
            type: 'string',
          })
          .option('pqc-key', {
            describe: 'SPHINCS+ özel anahtarının base64 kodlu dosyası.',
            type: 'string',
          })
          .option('pqc-public-key', {
            describe: 'SPHINCS+ kamu anahtarının base64 kodlu dosyası.',
            type: 'string',
          })
          .option('pqc-algorithm', {
            describe: 'SPHINCS+ algoritma tanımlayıcısı (örn. SPHINCS+-SHA2-128s).',
            type: 'string',
          })
          .option('ledger', {
            describe: 'Güncellenecek ledger.json dosya yolu.',
            type: 'string',
          })
          .option('ledger-key', {
            describe: 'Ledger girdilerini imzalamak için Ed25519 özel anahtar PEM dosyası.',
            type: 'string',
          })
          .option('ledger-key-id', {
            describe: 'Ledger girdisi imzası için anahtar kimliği.',
            type: 'string',
          })
          .option('attestation', {
            describe: 'İn-toto/SLSA attestation çıktısını üretir.',
            type: 'boolean',
            default: true,
          })
          .option('stage', {
            describe: 'SOI aşaması filtresi (SOI-1…SOI-4).',
            type: 'string',
          }),
      async (argv) => {
        const logger = getLogger(argv);
        const licensePath = getLicensePath(argv);
        const stage = normalizeStageOption(argv.stage);
        const context: Record<string, unknown> = {
          command: 'pack',
          licensePath,
          input: argv.input,
          output: argv.output,
          name: argv.name,
          signingKeyPath: argv.signingKey,
          stage,
        };

        try {
          const license = await verifyLicenseFile(licensePath);
          logLicenseValidated(logger, license, context);
          requireLicenseFeature(license, PIPELINE_LICENSE_FEATURES.pack);
          if (stage) {
            requireLicenseFeature(license, PIPELINE_LICENSE_FEATURES.stage);
          }

          const attestationEnabled = Array.isArray(argv.attestation)
            ? argv.attestation[0] !== false
            : argv.attestation !== false;
          context.attestation = attestationEnabled;

          const signingKeyOption = Array.isArray(argv.signingKey)
            ? argv.signingKey[0]
            : argv.signingKey;
          const signingKeyPath = path.resolve(signingKeyOption as string);
          context.signingKeyPath = signingKeyPath;
          const signingKey = await fsPromises.readFile(signingKeyPath, 'utf8');

          const ledgerPathOption = Array.isArray(argv.ledger)
            ? (argv.ledger[0] as string | undefined)
            : (argv.ledger as string | undefined);
          const ledgerKeyOption = Array.isArray(argv.ledgerKey)
            ? (argv.ledgerKey[0] as string | undefined)
            : (argv.ledgerKey as string | undefined);
          const ledgerKeyIdOption = Array.isArray(argv.ledgerKeyId)
            ? (argv.ledgerKeyId[0] as string | undefined)
            : (argv.ledgerKeyId as string | undefined);

          let ledgerOptions: PackLedgerOptions | undefined;
          if (ledgerPathOption) {
            const ledgerResolved = path.resolve(ledgerPathOption);
            context.ledgerPath = ledgerResolved;
            let ledgerSignerKey: string | undefined;
            if (ledgerKeyOption) {
              const ledgerKeyPath = path.resolve(ledgerKeyOption);
              context.ledgerKeyPath = ledgerKeyPath;
              ledgerSignerKey = await fsPromises.readFile(ledgerKeyPath, 'utf8');
            }
            ledgerOptions = {
              path: ledgerResolved,
              signerKey: ledgerSignerKey,
              signerKeyId: ledgerKeyIdOption,
            };
          }

          const cmsBundleOption = Array.isArray(argv.cmsBundle)
            ? (argv.cmsBundle[0] as string | undefined)
            : (argv.cmsBundle as string | undefined);
          const cmsCertOption = Array.isArray(argv.cmsCert)
            ? (argv.cmsCert[0] as string | undefined)
            : (argv.cmsCert as string | undefined);
          const cmsKeyOption = Array.isArray(argv.cmsKey)
            ? (argv.cmsKey[0] as string | undefined)
            : (argv.cmsKey as string | undefined);
          const cmsChainOption = Array.isArray(argv.cmsChain)
            ? (argv.cmsChain[0] as string | undefined)
            : (argv.cmsChain as string | undefined);

          let cmsOptions: PackCmsOptions | undefined;
          if (cmsBundleOption) {
            const cmsBundlePath = path.resolve(cmsBundleOption);
            context.cmsBundlePath = cmsBundlePath;
            const bundlePem = await fsPromises.readFile(cmsBundlePath, 'utf8');
            cmsOptions = { bundlePem };
          } else if (cmsCertOption || cmsKeyOption || cmsChainOption) {
            if (!cmsCertOption || !cmsKeyOption) {
              throw new Error('CMS imzası için hem sertifika hem de özel anahtar dosyaları gereklidir.');
            }
            const cmsCertPath = path.resolve(cmsCertOption);
            const cmsKeyPath = path.resolve(cmsKeyOption);
            context.cmsCertificatePath = cmsCertPath;
            context.cmsKeyPath = cmsKeyPath;
            const certificatePem = await fsPromises.readFile(cmsCertPath, 'utf8');
            const privateKeyPem = await fsPromises.readFile(cmsKeyPath, 'utf8');
            let chainPem: string | undefined;
            if (cmsChainOption) {
              const cmsChainPath = path.resolve(cmsChainOption);
              context.cmsChainPath = cmsChainPath;
              chainPem = await fsPromises.readFile(cmsChainPath, 'utf8');
            }
            cmsOptions = { certificatePem, privateKeyPem, chainPem };
          }

          const pqcKeyOption = Array.isArray(argv.pqcKey)
            ? (argv.pqcKey[0] as string | undefined)
            : (argv.pqcKey as string | undefined);
          const pqcPublicKeyOption = Array.isArray(argv.pqcPublicKey)
            ? (argv.pqcPublicKey[0] as string | undefined)
            : (argv.pqcPublicKey as string | undefined);
          const pqcAlgorithmOption = Array.isArray(argv.pqcAlgorithm)
            ? (argv.pqcAlgorithm[0] as string | undefined)
            : (argv.pqcAlgorithm as string | undefined);

          let postQuantumOptions: PackPostQuantumOptions | undefined;
          if (pqcKeyOption || pqcPublicKeyOption || pqcAlgorithmOption) {
            postQuantumOptions = {};
            if (pqcAlgorithmOption) {
              const algorithm = String(pqcAlgorithmOption).trim();
              if (algorithm.length > 0) {
                postQuantumOptions.algorithm = algorithm;
                context.pqcAlgorithm = algorithm;
              }
            }
            if (pqcKeyOption) {
              const pqcKeyPath = path.resolve(pqcKeyOption);
              context.pqcKeyPath = pqcKeyPath;
              postQuantumOptions.privateKey = await fsPromises.readFile(pqcKeyPath, 'utf8');
            }
            if (pqcPublicKeyOption) {
              const pqcPublicKeyPath = path.resolve(pqcPublicKeyOption);
              context.pqcPublicKeyPath = pqcPublicKeyPath;
              postQuantumOptions.publicKey = await fsPromises.readFile(pqcPublicKeyPath, 'utf8');
            }
          }

          const result = await runPack({
            input: argv.input,
            output: argv.output,
            packageName: argv.name,
            signingKey,
            ledger: ledgerOptions,
            cms: cmsOptions,
            stage,
            postQuantum: postQuantumOptions,
            attestation: attestationEnabled,
          });

          logger.info(
            {
              ...context,
              archivePath: result.archivePath,
              manifestPath: result.manifestPath,
              manifestId: result.manifestId,
              sbomPath: result.sbomPath,
              sbomDigest: result.sbomSha256,
              postQuantumSignature: result.signatureMetadata?.postQuantumSignature,
              ...(result.attestation
                ? {
                    attestationPath: result.attestation.absolutePath,
                    attestationDigest: result.attestation.digest,
                    attestationStatementDigest: result.attestation.statementDigest,
                  }
                : {}),
            },
            'Paket oluşturuldu.',
          );
          console.log(`SBOM ${result.sbomPath} dosyasına yazıldı (sha256=${result.sbomSha256}).`);
          if (result.attestation) {
            console.log(
              `Attestation ${result.attestation.absolutePath} dosyasına yazıldı (sha256=${result.attestation.digest}).`,
            );
          }
          process.exitCode = exitCodes.success;
        } catch (error) {
          logCliError(logger, error, context);
          process.exitCode = exitCodes.error;
        }
      },
    )
    .command(
      'package',
      'İçe aktarma → analiz → rapor → paket sürecini tek adımda çalıştırır.',
      (y) =>
        y
          .option('input', {
            alias: 'i',
            describe: 'Girdi veri dizini.',
            type: 'string',
            default: './data/input',
          })
          .option('output', {
            alias: 'o',
            describe: 'Çıktı paketinin yazılacağı dizin.',
            type: 'string',
            default: './dist',
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
          .option('signing-key', {
            describe: 'Ed25519 özel anahtar PEM dosyası.',
            type: 'string',
            demandOption: true,
          })
          .option('cms-bundle', {
            describe: 'PKCS#7/CMS imzası için sertifika ve özel anahtar PEM demeti.',
            type: 'string',
          })
          .option('cms-cert', {
            describe: 'CMS imzası için X.509 sertifikası.',
            type: 'string',
          })
          .option('cms-key', {
            describe: 'CMS imzası için özel anahtar PEM dosyası.',
            type: 'string',
          })
          .option('cms-chain', {
            describe: 'CMS imzasına eklenecek isteğe bağlı sertifika zinciri PEM dosyası.',
            type: 'string',
          })
          .option('package-name', {
            describe: 'Çıktı paketi dosya adı.',
            type: 'string',
            default: 'soi-pack.zip',
          })
          .option('baseline-snapshot', {
            describe: 'Değişiklik etkisi analizi için referans uyum snapshot JSON dosyası.',
            type: 'string',
            coerce: normalizeBaselineSnapshotOption,
          })
          .option('ledger', {
            describe: 'Paketleme ledger dosyasının yolu.',
            type: 'string',
          })
          .option('ledger-key', {
            describe: 'Ledger girdilerini imzalamak için Ed25519 özel anahtar PEM dosyası.',
            type: 'string',
          })
          .option('ledger-key-id', {
            describe: 'Ledger girdisi imzası için anahtar kimliği.',
            type: 'string',
          })
          .option('attestation', {
            describe: 'İn-toto/SLSA attestation çıktısını üretir.',
            type: 'boolean',
            default: true,
          })
          .option('stage', {
            describe: 'SOI aşaması filtresi (SOI-1…SOI-4).',
            type: 'string',
          }),
      async (argv) => {
        const logger = getLogger(argv);
        const licensePath = getLicensePath(argv);
        const context = {
          command: 'package',
          licensePath,
          input: argv.input,
          output: argv.output,
          packageName: argv.packageName,
        } as Record<string, unknown>;

        try {
          const license = await verifyLicenseFile(licensePath);
          logLicenseValidated(logger, license, context);

          const levelOption = Array.isArray(argv.level) ? argv.level[0] : (argv.level as string | undefined);
          const normalizedLevel = levelOption
            ? (levelOption.toUpperCase() as CertificationLevel | undefined)
            : undefined;
          if (normalizedLevel && !certificationLevels.includes(normalizedLevel)) {
            throw new Error(`Geçersiz seviye değeri: ${levelOption}`);
          }

          const stage = normalizeStageOption(argv.stage);
          context.stage = stage;
          if (stage) {
            requireLicenseFeature(license, PIPELINE_LICENSE_FEATURES.stage);
          }

          const attestationEnabled = Array.isArray(argv.attestation)
            ? argv.attestation[0] !== false
            : argv.attestation !== false;
          context.attestation = attestationEnabled;

          const inputDir = Array.isArray(argv.input)
            ? String(argv.input[0])
            : (argv.input as string | undefined) ?? './data/input';
          const outputDir = Array.isArray(argv.output)
            ? String(argv.output[0])
            : (argv.output as string | undefined) ?? './dist';
          const packageName = Array.isArray(argv.packageName)
            ? String(argv.packageName[0])
            : (argv.packageName as string | undefined);

          const signingKeyOption = Array.isArray(argv.signingKey)
            ? argv.signingKey[0]
            : argv.signingKey;
          const signingKeyPath = path.resolve(String(signingKeyOption));
          context.signingKeyPath = signingKeyPath;
          context.packageName = packageName ?? 'soi-pack.zip';
          const signingKey = await fsPromises.readFile(signingKeyPath, 'utf8');

          const ledgerPathOption = Array.isArray(argv.ledger)
            ? (argv.ledger[0] as string | undefined)
            : (argv.ledger as string | undefined);
          const ledgerKeyOption = Array.isArray(argv.ledgerKey)
            ? (argv.ledgerKey[0] as string | undefined)
            : (argv.ledgerKey as string | undefined);
          const ledgerKeyIdOption = Array.isArray(argv.ledgerKeyId)
            ? (argv.ledgerKeyId[0] as string | undefined)
            : (argv.ledgerKeyId as string | undefined);

          let ledgerOptions: PackLedgerOptions | undefined;
          if (ledgerPathOption) {
            const ledgerResolved = path.resolve(ledgerPathOption);
            context.ledgerPath = ledgerResolved;
            let ledgerSignerKey: string | undefined;
            if (ledgerKeyOption) {
              const ledgerKeyPath = path.resolve(ledgerKeyOption);
              context.ledgerKeyPath = ledgerKeyPath;
              ledgerSignerKey = await fsPromises.readFile(ledgerKeyPath, 'utf8');
            }
            ledgerOptions = {
              path: ledgerResolved,
              signerKey: ledgerSignerKey,
              signerKeyId: ledgerKeyIdOption,
            };
          }

          const cmsBundleOption = Array.isArray(argv.cmsBundle)
            ? (argv.cmsBundle[0] as string | undefined)
            : (argv.cmsBundle as string | undefined);
          const cmsCertOption = Array.isArray(argv.cmsCert)
            ? (argv.cmsCert[0] as string | undefined)
            : (argv.cmsCert as string | undefined);
          const cmsKeyOption = Array.isArray(argv.cmsKey)
            ? (argv.cmsKey[0] as string | undefined)
            : (argv.cmsKey as string | undefined);
          const cmsChainOption = Array.isArray(argv.cmsChain)
            ? (argv.cmsChain[0] as string | undefined)
            : (argv.cmsChain as string | undefined);

          let cmsOptions: PackCmsOptions | undefined;
          if (cmsBundleOption) {
            const cmsBundlePath = path.resolve(cmsBundleOption);
            context.cmsBundlePath = cmsBundlePath;
            const bundlePem = await fsPromises.readFile(cmsBundlePath, 'utf8');
            cmsOptions = { bundlePem };
          } else if (cmsCertOption || cmsKeyOption || cmsChainOption) {
            if (!cmsCertOption || !cmsKeyOption) {
              throw new Error('CMS imzası için hem sertifika hem de özel anahtar dosyaları gereklidir.');
            }
            const cmsCertPath = path.resolve(cmsCertOption);
            const cmsKeyPath = path.resolve(cmsKeyOption);
            context.cmsCertificatePath = cmsCertPath;
            context.cmsKeyPath = cmsKeyPath;
            const certificatePem = await fsPromises.readFile(cmsCertPath, 'utf8');
            const privateKeyPem = await fsPromises.readFile(cmsKeyPath, 'utf8');
            let chainPem: string | undefined;
            if (cmsChainOption) {
              const cmsChainPath = path.resolve(cmsChainOption);
              context.cmsChainPath = cmsChainPath;
              chainPem = await fsPromises.readFile(cmsChainPath, 'utf8');
            }
            cmsOptions = { certificatePem, privateKeyPem, chainPem };
          }

          const result = await runIngestAndPackage({
            inputDir,
            outputDir,
            objectives: argv.objectives as string | undefined,
            level: normalizedLevel,
            projectName: argv.projectName as string | undefined,
            projectVersion: argv.projectVersion as string | undefined,
            baselineSnapshot: argv.baselineSnapshot as string | undefined,
            baselineGitRef: argv.baselineGitRef as string | undefined,
            signingKey,
            packageName,
            ledger: ledgerOptions,
            cms: cmsOptions,
            stage,
            attestation: attestationEnabled,
          });

          logger.info(
            {
              ...context,
              archivePath: result.archivePath,
              manifestPath: result.manifestPath,
              manifestId: result.manifestId,
              sbomPath: result.sbomPath,
              sbomDigest: result.sbomSha256,
              ...(result.attestation
                ? {
                    attestationPath: result.attestation.absolutePath,
                    attestationDigest: result.attestation.digest,
                    attestationStatementDigest: result.attestation.statementDigest,
                  }
                : {}),
            },
            'Paket oluşturma tamamlandı.',
          );

          console.log(`Paket ${result.archivePath} olarak kaydedildi.`);
          console.log(`Manifest ${result.manifestPath} dosyasına yazıldı.`);
          console.log(`SBOM ${result.sbomPath} dosyasına yazıldı (sha256=${result.sbomSha256}).`);
          if (result.attestation) {
            console.log(
              `Attestation ${result.attestation.absolutePath} dosyasına yazıldı (sha256=${result.attestation.digest}).`,
            );
          }
          process.exitCode = result.analyzeExitCode;
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
            describe: 'Ed25519 kamu anahtarı veya X.509 sertifika PEM dosyası.',
            type: 'string',
            demandOption: true,
          })
          .option('package', {
            describe: 'Manifestte listelenen dosyaları içeren ZIP arşivi.',
            type: 'string',
          })
          .option('sbom', {
            describe: 'Manifestte referans verilen SBOM dosyası.',
            type: 'string',
          }),
      async (argv) => {
        const logger = getLogger(argv);
        const manifestOption = Array.isArray(argv.manifest) ? argv.manifest[0] : argv.manifest;
        const signatureOption = Array.isArray(argv.signature) ? argv.signature[0] : argv.signature;
        const publicKeyOption = Array.isArray(argv.publicKey) ? argv.publicKey[0] : argv.publicKey;
        const packageOption = Array.isArray(argv.package) ? argv.package[0] : argv.package;
        const sbomOption = Array.isArray(argv.sbom) ? argv.sbom[0] : argv.sbom;

        const manifestPath = path.resolve(manifestOption as string);
        const signaturePath = path.resolve(signatureOption as string);
        const publicKeyPath = path.resolve(publicKeyOption as string);
        const packagePath = packageOption ? path.resolve(String(packageOption)) : undefined;
        const sbomPath = sbomOption ? path.resolve(String(sbomOption)) : undefined;

        const context = {
          command: 'verify',
          manifestPath,
          signaturePath,
          publicKeyPath,
          packagePath,
          sbomPath,
        };

        try {
          const result = await runVerify({
            manifestPath,
            signaturePath,
            publicKeyPath,
            packagePath,
            sbomPath,
          });
          const hasPackageIssues = result.packageIssues.length > 0;
          const sbomFileMismatch = Boolean(result.sbom?.file && !result.sbom.file.matches);
          const sbomPackageMismatch = Boolean(result.sbom?.package && !result.sbom.package.matches);
          const hasSbomMismatch = sbomFileMismatch || sbomPackageMismatch;
          const attestationResult = result.attestation;
          const hasAttestationIssues = Boolean(
            attestationResult &&
              (!attestationResult.digestMatches ||
                !attestationResult.statementMatches ||
                !attestationResult.signature.matchesExpectedKey ||
                !attestationResult.signature.matchesVerifierKey ||
                !attestationResult.signature.verified),
          );
          if (attestationResult) {
            context.attestationPath = attestationResult.path;
          }

          if (hasPackageIssues || !result.isValid || hasSbomMismatch || hasAttestationIssues) {
            if (hasPackageIssues) {
              logger.error(
                { ...context, manifestId: result.manifestId, issues: result.packageIssues },
                'Paket içeriği manifest ile eşleşmiyor.',
              );
              console.error(`Paket doğrulaması başarısız oldu (ID: ${result.manifestId}).`);
              for (const issue of result.packageIssues) {
                console.error(` - ${issue}`);
              }
            }

            if (result.sbom) {
              if (sbomFileMismatch && result.sbom.file) {
                logger.error(
                  {
                    ...context,
                    manifestId: result.manifestId,
                    expectedDigest: result.sbom.expectedDigest,
                    actualDigest: result.sbom.file.digest,
                    sbomPath: result.sbom.file.path,
                  },
                  'SBOM dosya karması eşleşmiyor.',
                );
                console.error(
                  `SBOM doğrulaması başarısız: ${result.sbom.file.path} (beklenen ${result.sbom.expectedDigest}, bulunan ${result.sbom.file.digest}).`,
                );
              }
              if (sbomPackageMismatch && result.sbom.package) {
                logger.error(
                  {
                    ...context,
                    manifestId: result.manifestId,
                    expectedDigest: result.sbom.expectedDigest,
                    packageDigest: result.sbom.package.digest,
                  },
                  'Paket içindeki SBOM karması eşleşmiyor.',
                );
                console.error(
                  `Paket SBOM doğrulaması başarısız: beklenen ${result.sbom.expectedDigest}, bulunan ${result.sbom.package.digest}.`,
                );
              }
            }

            if (!result.isValid) {
              logger.warn(
                { ...context, manifestId: result.manifestId },
                'Manifest imzası doğrulanamadı.',
              );
              console.error(`Manifest imzası doğrulanamadı (ID: ${result.manifestId}).`);
            }

            if (attestationResult && hasAttestationIssues) {
              logger.error(
                {
                  ...context,
                  manifestId: result.manifestId,
                  attestation: {
                    path: attestationResult.path,
                    digestMatches: attestationResult.digestMatches,
                    statementMatches: attestationResult.statementMatches,
                    signature: attestationResult.signature,
                  },
                },
                'Attestation doğrulaması başarısız.',
              );
              console.error(`Attestation doğrulaması başarısız (ID: ${result.manifestId}).`);
              if (!attestationResult.digestMatches) {
                console.error(
                  ` - Attestation karması eşleşmiyor (beklenen ${attestationResult.expectedDigest}, bulunan ${attestationResult.actualDigest}).`,
                );
              }
              if (!attestationResult.statementMatches) {
                console.error(
                  ` - Attestation statement karması eşleşmiyor (beklenen ${attestationResult.expectedStatementDigest}, bulunan ${attestationResult.statementDigest}).`,
                );
              }
              if (!attestationResult.signature.matchesExpectedKey) {
                console.error(
                  ` - Attestation imzası beklenen anahtar karmasıyla eşleşmiyor (${attestationResult.signature.publicKeySha256}).`,
                );
              }
              if (!attestationResult.signature.matchesVerifierKey) {
                console.error(' - Doğrulama anahtarı manifestteki anahtar karmasıyla eşleşmiyor.');
              }
              if (!attestationResult.signature.verified) {
                console.error(' - Attestation Ed25519 imzası doğrulanamadı.');
              }
            }

            process.exitCode = exitCodes.verificationFailed;
          } else {
            logger.info(
              { ...context, manifestId: result.manifestId },
              'Manifest imzası doğrulandı.',
            );
            console.log(`Manifest imzası doğrulandı (ID: ${result.manifestId}).`);
            if (result.sbom) {
              console.log(
                `SBOM doğrulaması: ${result.sbom.path} (beklenen ${result.sbom.expectedDigest}).`,
              );
              if (result.sbom.file) {
                console.log(
                  ` - Dosya karması: ${result.sbom.file.digest} (${result.sbom.file.matches ? 'eşleşti' : 'eşleşmedi'})`,
                );
              }
              if (result.sbom.package) {
                console.log(
                  ` - Paket karması: ${result.sbom.package.digest} (${result.sbom.package.matches ? 'eşleşti' : 'eşleşmedi'})`,
                );
              }
            }
            if (attestationResult) {
              console.log(
                `Attestation doğrulaması: ${attestationResult.path} (digest ${attestationResult.actualDigest}).`,
              );
              console.log(
                ` - İmza durumu: ${attestationResult.signature.verified ? 'geçerli' : 'geçersiz'} (anahtar sha256=${attestationResult.signature.publicKeySha256}).`,
              );
            }
            process.exitCode = exitCodes.success;
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
      'compare',
      'Uyum snapshot veya manifest çıktıları arasındaki değişiklikleri özetler.',
      (y) =>
        y
          .option('base', {
            describe: 'Referans snapshot veya manifest JSON dosyası.',
            type: 'string',
            demandOption: true,
          })
          .option('target', {
            describe: 'Karşılaştırılacak hedef snapshot veya manifest JSON dosyası.',
            type: 'string',
            demandOption: true,
          }),
      async (argv) => {
        const logger = getLogger(argv);
        const baseOption = Array.isArray(argv.base) ? argv.base[0] : argv.base;
        const targetOption = Array.isArray(argv.target) ? argv.target[0] : argv.target;

        const basePath = path.resolve(String(baseOption));
        const targetPath = path.resolve(String(targetOption));

        const context = {
          command: 'compare',
          basePath,
          targetPath,
        };

        try {
          const result = await runComplianceCompare({ basePath, targetPath });

          logger.info(
            {
              ...context,
              baseSnapshot: result.base.snapshotId,
              targetSnapshot: result.target.snapshotId,
              improvements: result.objectives.improvements.length,
              regressions: result.objectives.regressions.length,
              independenceRegressions: result.independenceRegressions.length,
              addedEvidence: result.evidenceChanges?.added.length ?? 0,
              removedEvidence: result.evidenceChanges?.removed.length ?? 0,
              changedEvidence: result.evidenceChanges?.changed.length ?? 0,
            },
            'Uyum karşılaştırması tamamlandı.',
          );

          const displayPath = (filePath: string) => {
            const relative = path.relative(process.cwd(), filePath);
            return relative.length > 0 ? relative : filePath;
          };

          console.log(
            `Referans snapshot: ${result.base.snapshotId} (${displayPath(result.base.path)})`,
          );
          if (result.base.manifest) {
            console.log(
              `Referans manifest: ${displayPath(result.base.manifest.path)} (digest ${result.base.manifest.digest})`,
            );
          }
          console.log(
            `Hedef snapshot: ${result.target.snapshotId} (${displayPath(result.target.path)})`,
          );
          if (result.target.manifest) {
            console.log(
              `Hedef manifest: ${displayPath(result.target.manifest.path)} (digest ${result.target.manifest.digest})`,
            );
          }

          console.log('');
          console.log('Hedef durumu değişiklikleri:');
          if (
            result.objectives.improvements.length === 0 &&
            result.objectives.regressions.length === 0
          ) {
            console.log(' - Durum değişikliği tespit edilmedi.');
          } else {
            if (result.objectives.improvements.length > 0) {
              console.log('İyileşen hedefler:');
              console.log(renderObjectiveDeltaTable(result.objectives.improvements));
            }
            if (result.objectives.regressions.length > 0) {
              if (result.objectives.improvements.length > 0) {
                console.log('');
              }
              console.log('Gerileyen hedefler:');
              console.log(renderObjectiveDeltaTable(result.objectives.regressions));
            }
            if (result.objectives.unchanged > 0) {
              console.log(`Değişmeyen hedef sayısı: ${result.objectives.unchanged}.`);
            }
          }

          console.log('');
          console.log('Bağımsızlık gerilemeleri:');
          if (result.independenceRegressions.length === 0) {
            console.log(' - Bağımsızlık gerilemesi tespit edilmedi.');
          } else {
            console.log(renderIndependenceRegressionTable(result.independenceRegressions));
          }

          if (result.evidenceChanges) {
            console.log('');
            console.log('Kanıt karması değişiklikleri:');
            const { added, removed, changed } = result.evidenceChanges;
            if (added.length === 0 && removed.length === 0 && changed.length === 0) {
              console.log(' - Manifestler arasında kanıt değişikliği bulunamadı.');
            } else {
              if (added.length > 0) {
                console.log('Eklenen kanıtlar:');
                console.log(renderManifestDiffEntries(added));
              }
              if (removed.length > 0) {
                if (added.length > 0) {
                  console.log('');
                }
                console.log('Kaldırılan kanıtlar:');
                console.log(renderManifestDiffEntries(removed));
              }
              if (changed.length > 0) {
                if (added.length > 0 || removed.length > 0) {
                  console.log('');
                }
                console.log('Güncellenen kanıt karmaları:');
                console.log(renderManifestDiffChanges(changed));
              }
            }
          }

          console.log('');
          console.log('JSON özet:');
          console.log(JSON.stringify(result, null, 2));

          process.exitCode = exitCodes.success;
        } catch (error) {
          logCliError(logger, error, context);
          const message = error instanceof Error ? error.message : String(error);
          console.error(`Uyum karşılaştırması sırasında hata oluştu: ${message}`);
          process.exitCode = exitCodes.error;
        }
      },
    )
    .command(
      'manifest diff',
      'İki manifest dosyası arasındaki değişiklikleri raporlar.',
      (y) =>
        y
          .option('base', {
            describe: 'Referans manifest JSON dosyası.',
            type: 'string',
            demandOption: true,
          })
          .option('target', {
            describe: 'Karşılaştırılacak hedef manifest JSON dosyası.',
            type: 'string',
            demandOption: true,
          }),
      async (argv) => {
        const logger = getLogger(argv);
        const baseOption = Array.isArray(argv.base) ? argv.base[0] : argv.base;
        const targetOption = Array.isArray(argv.target) ? argv.target[0] : argv.target;

        const baseManifestPath = path.resolve(String(baseOption));
        const targetManifestPath = path.resolve(String(targetOption));

        const context = {
          command: 'manifest diff',
          baseManifest: baseManifestPath,
          targetManifest: targetManifestPath,
        };

        try {
          const result = await runManifestDiff({
            baseManifestPath,
            targetManifestPath,
          });

          logger.info(
            {
              ...context,
              baseDigest: result.base.digest,
              targetDigest: result.target.digest,
              added: result.added.length,
              removed: result.removed.length,
              changed: result.changed.length,
            },
            'Manifest karşılaştırması tamamlandı.',
          );

          console.log(
            `Referans manifest: ${path.relative(process.cwd(), result.base.path)} (digest ${result.base.digest})`,
          );
          console.log(
            `Hedef manifest: ${path.relative(process.cwd(), result.target.path)} (digest ${result.target.digest})`,
          );
          console.log(
            `Kanıt doğrulaması: referans ${result.base.verifiedProofs}/${result.base.totalProofs}, hedef ${result.target.verifiedProofs}/${result.target.totalProofs}.`,
          );

          if (result.added.length === 0 && result.removed.length === 0 && result.changed.length === 0) {
            console.log('Değişiklik tespit edilmedi.');
          } else {
            if (result.added.length > 0) {
              console.log('Eklenen kanıtlar:');
              result.added.forEach((entry) => {
                console.log(` + ${entry.path} (${entry.sha256})`);
              });
            }
            if (result.removed.length > 0) {
              console.log('Kaldırılan kanıtlar:');
              result.removed.forEach((entry) => {
                console.log(` - ${entry.path} (${entry.sha256})`);
              });
            }
            if (result.changed.length > 0) {
              console.log('Güncellenen kanıtlar:');
              result.changed.forEach((entry) => {
                console.log(` * ${entry.path} (${entry.baseSha256} → ${entry.targetSha256})`);
              });
            }
          }

          process.exitCode = exitCodes.success;
        } catch (error) {
          logCliError(logger, error, context);
          const message = error instanceof Error ? error.message : String(error);
          console.error(`Manifest karşılaştırması sırasında hata oluştu: ${message}`);
          process.exitCode = exitCodes.error;
        }
      },
    )
    .command(
      'ledger-report',
      'Manifest ledger farklarını PDF raporu olarak oluşturur.',
      (y) =>
        y
          .option('base', {
            describe: 'Referans manifest JSON dosyası.',
            type: 'string',
            demandOption: true,
          })
          .option('target', {
            describe: 'Karşılaştırılacak hedef manifest JSON dosyası.',
            type: 'string',
            demandOption: true,
          })
          .option('output', {
            alias: 'o',
            describe: 'PDF raporunun yazılacağı dizin.',
            type: 'string',
            demandOption: true,
          })
          .option('title', {
            describe: 'Rapor başlığı.',
            type: 'string',
          })
          .option('signing-key', {
            describe: 'Ed25519 özel anahtar PEM dosyası (opsiyonel).',
            type: 'string',
          }),
      async (argv) => {
        const logger = getLogger(argv);
        const licensePath = getLicensePath(argv);

        const baseOption = Array.isArray(argv.base) ? argv.base[0] : argv.base;
        const targetOption = Array.isArray(argv.target) ? argv.target[0] : argv.target;
        const outputOption = Array.isArray(argv.output) ? argv.output[0] : argv.output;
        const titleOption = Array.isArray(argv.title) ? argv.title[0] : argv.title;
        const signingKeyOption = Array.isArray(argv['signing-key'])
          ? argv['signing-key'][0]
          : argv['signing-key'];

        const baseManifestPath = path.resolve(String(baseOption));
        const targetManifestPath = path.resolve(String(targetOption));
        const outputDir = path.resolve(String(outputOption));

        const context = {
          command: 'ledger-report',
          licensePath,
          baseManifest: baseManifestPath,
          targetManifest: targetManifestPath,
          outputDir,
          title: titleOption,
        } as Record<string, unknown>;

        try {
          const license = await verifyLicenseFile(licensePath);
          logLicenseValidated(logger, license, context);
          requireLicenseFeature(license, PIPELINE_LICENSE_FEATURES.report);

          let signingKey: string | undefined;
          if (signingKeyOption) {
            const signingKeyPath = path.resolve(String(signingKeyOption));
            context.signingKeyPath = signingKeyPath;
            signingKey = await fsPromises.readFile(signingKeyPath, 'utf8');
          }

          const result = await runLedgerReport({
            baseManifestPath,
            targetManifestPath,
            outputDir,
            title: titleOption ? String(titleOption) : undefined,
            signingKey,
          });

          logger.info(
            {
              ...context,
              pdfPath: result.pdfPath,
              pdfSha256: result.pdfSha256,
              ledgerDiffs: result.ledgerDiffs.length,
              signaturePath: result.signaturePath,
            },
            'Ledger raporu oluşturuldu.',
          );

          console.log(`Ledger raporu kaydedildi: ${path.relative(process.cwd(), result.pdfPath)}`);
          console.log(`PDF SHA-256: ${result.pdfSha256}`);
          if (result.signaturePath) {
            console.log(
              `İmza kaydedildi: ${path.relative(process.cwd(), result.signaturePath)} (base64 ${
                result.signature?.slice(0, 16) ?? ''
              }...)`,
            );
          }
          process.exitCode = exitCodes.success;
        } catch (error) {
          logCliError(logger, error, context);
          process.exitCode = exitCodes.error;
        }
      },
    )
    .command(
      'risk',
      'Risk simülasyonu ve tahmin araçları.',
      (riskYargs) =>
        riskYargs
          .command(
            'simulate',
            'Kapsam ve test geçmişinden Monte Carlo uyum riski hesaplar.',
            (y) =>
              y
                .option('metrics', {
                  alias: 'm',
                  describe: 'Kapsam ve test geçmişini içeren JSON dosyası.',
                  type: 'string',
                  demandOption: true,
                })
                .option('iterations', {
                  describe: 'Monte Carlo iterasyon sayısı (varsayılan 1000, maksimum 10000).',
                  type: 'number',
                })
                .option('seed', {
                  describe: 'Deterministik sonuçlar için RNG tohumu.',
                  type: 'number',
                })
                .option('coverage-lift', {
                  describe: 'Son kapsama gözlemine uygulanacak yüzde puan artışı/azalışı.',
                  type: 'number',
                })
                .option('json', {
                  describe: 'Çıktıyı JSON formatında yazdırır.',
                  type: 'boolean',
                  default: false,
                })
                .option('output', {
                  alias: 'o',
                  describe: 'Simülasyon özetini JSON olarak kaydedilecek dosya yolu.',
                  type: 'string',
                }),
            async (argv) => {
              const logger = getLogger(argv);
              const licensePath = getLicensePath(argv);
              const metricsOption = Array.isArray(argv.metrics) ? argv.metrics[0] : argv.metrics;
              const iterationsOption = Array.isArray(argv.iterations)
                ? argv.iterations[0]
                : argv.iterations;
              const seedOption = Array.isArray(argv.seed) ? argv.seed[0] : argv.seed;
              const coverageLiftOption = Array.isArray(argv['coverage-lift'])
                ? argv['coverage-lift'][0]
                : argv['coverage-lift'];
              const outputOption = Array.isArray(argv.output) ? argv.output[0] : argv.output;
              const jsonOutput = Boolean(argv.json);

              const metricsPath = path.resolve(String(metricsOption));
              const context = {
                command: 'risk simulate',
                licensePath,
                metricsPath,
                iterations: iterationsOption,
                seed: seedOption,
                coverageLift: coverageLiftOption,
                output: outputOption,
                jsonOutput,
              };

              try {
                const license = await verifyLicenseFile(licensePath);
                logLicenseValidated(logger, license, context);

                const result = await runRiskSimulate({
                  metricsPath,
                  iterations: iterationsOption as number | undefined,
                  seed: seedOption as number | undefined,
                  coverageLift: coverageLiftOption as number | undefined,
                });

                if (outputOption) {
                  const outputPath = path.resolve(String(outputOption));
                  await writeJsonFile(outputPath, result.simulation);
                }

                if (jsonOutput) {
                  console.log(`${JSON.stringify(result.simulation, null, 2)}`);
                } else {
                  console.log(
                    `Monte Carlo uyum riski (iterasyon: ${result.simulation.iterations}, seed: ${result.simulation.seed}).`,
                  );
                  console.log(
                    `Temel kapsama: ${result.simulation.baseline.coverage}% | Test hata oranı: ${result.simulation.baseline.failureRate}%.`,
                  );
                  console.log(
                    `Ortalama risk: ${result.simulation.mean}% (std sapma ${result.simulation.stddev}%).`,
                  );
                  console.log('Yüzdelikler:');
                  console.log(`  P50: ${result.simulation.percentiles.p50}%`);
                  console.log(`  P90: ${result.simulation.percentiles.p90}%`);
                  console.log(`  P95: ${result.simulation.percentiles.p95}%`);
                  console.log(`  P99: ${result.simulation.percentiles.p99}%`);
                  console.log(
                    `Aralık: min ${result.simulation.min}% · max ${result.simulation.max}% (toplam ${result.simulation.iterations} örnek).`,
                  );
                }

                logger.info(
                  {
                    ...context,
                    mean: result.simulation.mean,
                    stddev: result.simulation.stddev,
                    baselineCoverage: result.simulation.baseline.coverage,
                    baselineFailure: result.simulation.baseline.failureRate,
                  },
                  'Uyum riski simülasyonu tamamlandı.',
                );
                process.exitCode = exitCodes.success;
              } catch (error) {
                logCliError(logger, error, context);
                process.exitCode = exitCodes.error;
              }
            },
          )
          .demandCommand(1, 'Risk komutlarından birini seçmelisiniz.')
          .strict()
    )
    .command(
      'generate-plans',
      'JSON konfigürasyonundan plan şablonlarını PDF ve DOCX olarak üretir.',
      (y) =>
        y.option('config', {
          alias: 'c',
          describe: 'Plan üretim konfigürasyon JSON dosyası.',
          type: 'string',
          demandOption: true,
        }),
      async (argv) => {
        const logger = getLogger(argv);
        const configOption = Array.isArray(argv.config) ? argv.config[0] : argv.config;
        const configPath = path.resolve(configOption as string);
        const context = {
          command: 'generate-plans',
          configPath,
        };

        try {
          const result = await runGeneratePlans({ config: configPath });
          logger.info(
            {
              ...context,
              manifestPath: result.manifestPath,
              planCount: result.plans.length,
            },
            'Plan belgeleri üretildi.',
          );
          console.log(`Plan belgeleri ${result.outputDir} dizinine kaydedildi.`);
          console.log(`Manifest ${result.manifestPath} dosyasına yazıldı.`);
          process.exitCode = exitCodes.success;
        } catch (error) {
          logCliError(logger, error, context);
          const message = error instanceof Error ? error.message : String(error);
          console.error(`Plan üretimi sırasında hata oluştu: ${message}`);
          process.exitCode = exitCodes.error;
        }
      },
    )
    .command(
      'remediation-plan',
      'Uyum snapshot verisinden iyileştirme planını Markdown ve JSON olarak dışa aktarır.',
      (y) =>
        y
          .option('snapshot', {
            alias: 's',
            describe: 'Uyum snapshot JSON dosyası.',
            type: 'string',
            demandOption: true,
          })
          .option('output', {
            alias: 'o',
            describe: 'İyileştirme planı çıktılarının yazılacağı dizin.',
            type: 'string',
            demandOption: true,
          })
          .option('objectives', {
            alias: 'j',
            describe: 'Hedef meta verilerini içeren Objective listesi JSON dosyası (opsiyonel).',
            type: 'string',
          }),
      async (argv) => {
        const logger = getLogger(argv);
        const snapshotOption = Array.isArray(argv.snapshot) ? argv.snapshot[0] : argv.snapshot;
        const outputOption = Array.isArray(argv.output) ? argv.output[0] : argv.output;
        const objectivesOption = Array.isArray(argv.objectives)
          ? argv.objectives[0]
          : argv.objectives;

        const snapshotPath = path.resolve(String(snapshotOption));
        const outputDir = path.resolve(String(outputOption));
        const objectivesPath = objectivesOption ? path.resolve(String(objectivesOption)) : undefined;

        const context = {
          command: 'remediation-plan',
          snapshotPath,
          outputDir,
          ...(objectivesPath ? { objectivesPath } : {}),
        };

        try {
          const result = await runRemediationPlan({
            snapshot: snapshotPath,
            output: outputDir,
            objectives: objectivesPath,
          });

          logger.info(
            {
              ...context,
              actionCount: result.actions,
              markdownPath: result.markdownPath,
              jsonPath: result.jsonPath,
            },
            'İyileştirme planı çıkarıldı.',
          );

          console.log(
            `İyileştirme planı Markdown çıktısı ${path.relative(process.cwd(), result.markdownPath)} dosyasına yazıldı.`,
          );
          console.log(
            `İyileştirme planı JSON çıktısı ${path.relative(process.cwd(), result.jsonPath)} dosyasına yazıldı.`,
          );
          process.exitCode = exitCodes.success;
        } catch (error) {
          logCliError(logger, error, context);
          const message = error instanceof Error ? error.message : String(error);
          console.error(`İyileştirme planı oluşturulurken hata oluştu: ${message}`);
          process.exitCode = exitCodes.error;
        }
      },
    )
    .command(renderGsnCommand)
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
    .alias('help', 'h')
    .wrap(100);

  cli.parse();
}

export const __internal = {
  logLicenseValidated,
  logCliError,
  mergeStructuralCoverage,
  buildJiraCloudOptions,
  buildJamaOptions,
};

export {
  exitCodes,
  verifyLicenseFile,
  LicenseError,
  type LicensePayload,
  type VerifyLicenseOptions,
};
