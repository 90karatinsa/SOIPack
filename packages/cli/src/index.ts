#!/usr/bin/env node
import { createHash } from 'crypto';
import fs, { promises as fsPromises } from 'fs';
import http from 'http';
import https from 'https';
import path from 'path';
import process from 'process';
import { pipeline as streamPipeline } from 'stream/promises';
import { inflateRawSync } from 'zlib';

import {
  importCobertura,
  importGitMetadata,
  importJiraCsv,
  importJUnitXml,
  importLcov,
  importDoorsClassicCsv,
  importQaLogs,
  fetchDoorsNextArtifacts,
  fetchJenkinsArtifacts,
  fetchPolarionArtifacts,
  importReqIF,
  fromLDRA,
  fromPolyspace,
  fromVectorCAST,
  aggregateImportBundle,
  type BuildInfo,
  type CoverageReport,
  type CoverageSummary as StructuralCoverageSummary,
  type Finding,
  type JiraRequirement,
  type JenkinsClientOptions,
  type PolarionClientOptions,
  type DoorsNextClientOptions,
  type DoorsNextRelationship,
  type RemoteRequirementRecord,
  type RemoteTestRecord,
  type RemoteDesignRecord,
  type ReqIFRequirement,
  type TestResult,
  type TestStatus,
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
} from '@soipack/core';
import {
  ComplianceSnapshot,
  EvidenceIndex,
  ImportBundle,
  ObjectiveCoverage,
  RequirementTrace,
  TraceEngine,
  generateComplianceSnapshot,
} from '@soipack/engine';
import {
  buildManifest,
  computeManifestDigestHex,
  signManifestBundle,
  verifyManifestSignature,
  verifyManifestSignatureDetailed,
  LedgerAwareManifest,
} from '@soipack/packager';
import {
  renderComplianceMatrix,
  renderGaps,
  renderTraceMatrix,
  renderPlanDocument,
  renderPlanPdf,
  planTemplateSections,
  planTemplateTitles,
  printToPDF,
  type PlanTemplateId,
  type PlanOverrideConfig,
  type PlanSectionOverrides,
  type PlanRenderOptions,
} from '@soipack/report';
import YAML from 'yaml';
import yargs from 'yargs';
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

interface ImportPaths {
  jira?: string;
  jiraDefects?: string[];
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
  polyspace?: string;
  ldra?: string;
  vectorcast?: string;
  polarion?: string;
  jenkins?: string;
  manualArtifacts?: Partial<Record<ObjectiveArtifactType, string[]>>;
  qaLogs?: string[];
}

export type ImportOptions = Omit<ImportPaths, 'polarion' | 'jenkins' | 'doorsNext'> & {
  output: string;
  objectives?: string;
  level?: CertificationLevel;
  projectName?: string;
  projectVersion?: string;
  polarion?: PolarionClientOptions;
  jenkins?: JenkinsClientOptions;
  doorsNext?: DoorsNextClientOptions;
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

const staticAnalysisTools = ['polyspace', 'ldra', 'vectorcast'] as const;
type StaticAnalysisTool = (typeof staticAnalysisTools)[number];

type ManualArtifactImports = Partial<Record<ObjectiveArtifactType, string[]>>;

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

export interface ExternalBuildRecord {
  provider: 'polarion' | 'jenkins';
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
  };
  jenkins?: {
    baseUrl: string;
    job: string;
    build?: string;
    tests: number;
    builds: number;
  };
  jira?: {
    requirements?: number;
    problemReports?: number;
    openProblems?: number;
    reports?: Array<{ file: string; total: number; open: number }>;
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

const buildJenkinsOptions = (
  argv: yargs.ArgumentsCamelCase<unknown>,
): JenkinsClientOptions | undefined => {
  const raw = argv as Record<string, unknown>;
  const baseUrl = coerceOptionalString(raw.jenkinsUrl);
  const job = coerceOptionalString(raw.jenkinsJob);

  if (!baseUrl || !job) {
    return undefined;
  }

  return {
    baseUrl,
    job,
    build: parseJenkinsBuildIdentifier(raw.jenkinsBuild),
    username: coerceOptionalString(raw.jenkinsUsername),
    password: coerceOptionalString(raw.jenkinsPassword),
    token: coerceOptionalString(raw.jenkinsToken),
    buildEndpoint: coerceOptionalString(raw.jenkinsBuildEndpoint),
    testReportEndpoint: coerceOptionalString(raw.jenkinsTestsEndpoint),
  };
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
    description: entry.description ?? entry.summary,
    status: requirementStatusFromJira(entry.status),
    tags: entry.priority ? [`priority:${entry.priority.toLowerCase()}`] : [],
  });
  return requirement;
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
  provider: 'polarion' | 'jenkins' | 'doorsNext',
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
  const sourceMetadata: ExternalSourceMetadata = {};
  const coverageMaps: Array<{ map: Record<string, string[]>; origin: string }> = [];
  const normalizedInputs: ImportPaths = {
    jira: options.jira ? normalizeRelativePath(options.jira) : undefined,
    jiraDefects: options.jiraDefects?.map((filePath) => normalizeRelativePath(filePath)),
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
    polyspace: options.polyspace ? normalizeRelativePath(options.polyspace) : undefined,
    ldra: options.ldra ? normalizeRelativePath(options.ldra) : undefined,
    vectorcast: options.vectorcast ? normalizeRelativePath(options.vectorcast) : undefined,
    polarion: options.polarion ? `${options.polarion.baseUrl}#${options.polarion.projectId}` : undefined,
    jenkins: options.jenkins
      ? `${options.jenkins.baseUrl}#${options.jenkins.job}`
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
    coverage = result.data;
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

  if (!coverage && options.cobertura) {
    const result = await importCobertura(options.cobertura);
    warnings.push(...result.warnings);
    coverage = result.data;
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
  } else if (options.cobertura) {
    const result = await importCobertura(options.cobertura);
    warnings.push(...result.warnings);
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
    const doorsResult = await fetchDoorsNextArtifacts(options.doorsNext);
    warnings.push(...doorsResult.warnings);
    const doorsRequirements = doorsResult.data.requirements ?? [];
    const doorsTests = doorsResult.data.tests ?? [];
    const doorsDesigns = doorsResult.data.designs ?? [];
    const doorsRelationships = doorsResult.data.relationships ?? [];
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
    };
  }

  if (options.polarion) {
    const polarionResult = await fetchPolarionArtifacts(options.polarion);
    warnings.push(...polarionResult.warnings);
    const polarionRequirements = polarionResult.data.requirements ?? [];
    const polarionTests = polarionResult.data.tests ?? [];
    const polarionBuilds = polarionResult.data.builds ?? [];

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

    sourceMetadata.polarion = {
      baseUrl: options.polarion.baseUrl,
      projectId: options.polarion.projectId,
      requirements: polarionRequirements.length,
      tests: polarionTests.length,
      builds: polarionBuilds.length,
    };
  }

  if (options.jenkins) {
    const jenkinsResult = await fetchJenkinsArtifacts(options.jenkins);
    warnings.push(...jenkinsResult.warnings);
    const jenkinsTests = jenkinsResult.data.tests ?? [];
    const jenkinsBuilds = jenkinsResult.data.builds ?? [];

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

    sourceMetadata.jenkins = {
      baseUrl: options.jenkins.baseUrl,
      job: options.jenkins.job,
      build: options.jenkins.build ? String(options.jenkins.build) : undefined,
      tests: jenkinsTests.length,
      builds: jenkinsBuilds.length,
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
  stage?: SoiStage;
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

  const level = options.level ?? workspace.metadata.targetLevel ?? 'C';
  const fallbackObjectivesPath = path.resolve('data', 'objectives', 'do178c_objectives.min.json');
  const objectivesPathRaw =
    options.objectives ?? workspace.metadata.objectivesPath ?? fallbackObjectivesPath;
  const objectivesPath = path.resolve(objectivesPathRaw);
  const objectives = await loadObjectives(objectivesPath);
  const filteredObjectives = filterObjectivesByStage(
    filterObjectives(objectives, level),
    options.stage,
  );

  const bundle = buildImportBundle(workspace, filteredObjectives, level);
  const snapshot = generateComplianceSnapshot(bundle);
  const engine = new TraceEngine(bundle);
  const traces = collectRequirementTraces(engine, workspace.requirements);

  const gatingEvaluation = evaluateCertificationGating(level, snapshot.objectives);

  const outputDir = path.resolve(options.output);
  await ensureDirectory(outputDir);

  const snapshotPath = path.join(outputDir, 'snapshot.json');
  const tracePath = path.join(outputDir, 'traces.json');
  const analysisPath = path.join(outputDir, 'analysis.json');

  const analysisGeneratedAt = getCurrentTimestamp();
  const analysisMetadata: AnalysisMetadata = {
    project:
      options.projectName || options.projectVersion || workspace.metadata.project
        ? {
            name: options.projectName ?? workspace.metadata.project?.name,
            version: options.projectVersion ?? workspace.metadata.project?.version,
          }
        : undefined,
    level,
    generatedAt: analysisGeneratedAt,
    version: snapshot.version,
    stage: options.stage,
  };

  await writeJsonFile(snapshotPath, snapshot);
  await writeJsonFile(tracePath, traces);
  const analysisWarnings = [...workspace.metadata.warnings, ...gatingEvaluation.warnings];
  await writeJsonFile(analysisPath, {
    metadata: analysisMetadata,
    objectives: filteredObjectives,
    objectiveCoverage: snapshot.objectives,
    gaps: snapshot.gaps,
    requirements: workspace.requirements,
    designs: workspace.designs,
    tests: workspace.testResults,
    coverage: workspace.coverage,
    evidenceIndex: workspace.evidenceIndex,
    git: workspace.git,
    inputs: workspace.metadata.inputs,
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
  traceHtml: string;
  traceCsv: string;
  gapsHtml: string;
  plans: Record<PlanTemplateId, GeneratedPlanOutput>;
  warnings: string[];
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
  });

  const outputDir = path.resolve(options.output);
  await ensureDirectory(outputDir);

  const complianceHtmlPath = path.join(outputDir, 'compliance.html');
  const complianceJsonPath = path.join(outputDir, 'compliance.json');
  const traceHtmlPath = path.join(outputDir, 'trace.html');
  const traceCsvPath = path.join(outputDir, 'trace.csv');
  const gapsHtmlPath = path.join(outputDir, 'gaps.html');

  await fsPromises.copyFile(snapshotPath, path.join(outputDir, 'snapshot.json'));
  await fsPromises.copyFile(tracePath, path.join(outputDir, 'traces.json'));

  await fsPromises.writeFile(complianceHtmlPath, compliance.html, 'utf8');
  await writeJsonFile(complianceJsonPath, compliance.json);
  await fsPromises.writeFile(traceHtmlPath, traceReport.html, 'utf8');
  await fsPromises.writeFile(traceCsvPath, traceReport.csv.csv, 'utf8');
  await fsPromises.writeFile(gapsHtmlPath, gapsHtml, 'utf8');

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

  const analysisWithPlanWarnings =
    planWarnings.length > 0
      ? { ...analysis, warnings: [...analysis.warnings, ...planWarnings] }
      : analysis;
  await writeJsonFile(path.join(outputDir, 'analysis.json'), analysisWithPlanWarnings);

  return {
    complianceHtml: complianceHtmlPath,
    complianceJson: complianceJsonPath,
    traceHtml: traceHtmlPath,
    traceCsv: traceCsvPath,
    gapsHtml: gapsHtmlPath,
    plans,
    warnings: planWarnings,
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

export interface PackOptions {
  input: string;
  output: string;
  signingKey: string;
  packageName?: string;
  ledger?: PackLedgerOptions;
  cms?: PackCmsOptions;
  stage?: SoiStage;
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
}

const createArchive = async (
  files: Array<{ absolutePath: string; manifestPath: string }>,
  outputPath: string,
  manifestContent: string,
  signature?: string,
  cmsSignature?: string,
): Promise<void> => {
  await ensureDirectory(path.dirname(outputPath));
  const zip = new ZipFile();
  const output = fs.createWriteStream(outputPath);

  const completion = new Promise<void>((resolve, reject) => {
    output.on('close', () => resolve());
    output.on('error', (error) => reject(error));
    zip.outputStream.on('error', (error: unknown) => reject(error));
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
  if (cmsSignature) {
    const normalizedCms = cmsSignature.endsWith('\n') ? cmsSignature : `${cmsSignature}\n`;
    const options = hasFixedTimestamp ? { mtime: getCurrentDate() } : undefined;
    zip.addBuffer(Buffer.from(normalizedCms, 'utf8'), 'manifest.cms', options);
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
  if (inputDir === reportDir) {
    return [];
  }

  const entries = await fsPromises.readdir(inputDir, { withFileTypes: true });
  return entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => path.join(inputDir, entry.name))
    .filter((dir) => path.resolve(dir) !== path.resolve(reportDir));
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

  const { manifest: baseManifest, files } = await buildManifest({
    reportDir,
    evidenceDirs,
    toolVersion: packageInfo.version,
    now,
  });

  let manifest: LedgerAwareManifest = baseManifest;
  let manifestDigest = computeManifestDigestHex(baseManifest);
  let ledgerPath: string | undefined;
  let updatedLedger: Ledger | undefined;
  let ledgerEntry: LedgerEntry | undefined;

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

    const manifestDigestForLedger = computeManifestDigestHex(baseManifest);
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
      ...baseManifest,
      files: baseManifest.files.map((file) => ({ ...file })),
      ledger: {
        root: entry.ledgerRoot,
        previousRoot: entry.previousRoot,
      },
    };
    manifestDigest = manifestDigestForLedger;
    updatedLedger = appended;
    ledgerEntry = entry;
  }

  const manifestSerialized = `${JSON.stringify(manifest, null, 2)}\n`;
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
  const manifestHash = createHash('sha256').update(manifestSerialized).digest('hex');
  const manifestId = manifestHash.slice(0, 12);

  const manifestPath = path.join(outputDir, 'manifest.json');
  await fsPromises.writeFile(manifestPath, manifestSerialized, 'utf8');
  const signaturePath = path.join(outputDir, 'manifest.sig');
  await fsPromises.writeFile(signaturePath, `${signature}\n`, 'utf8');

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

  const archiveName =
    options.packageName !== undefined
      ? normalizePackageName(options.packageName)
      : `soipack-${manifestId}.zip`;
  const archivePath = path.join(outputDir, archiveName);
  await createArchive(
    files,
    archivePath,
    manifestSerialized,
    `${signature}\n`,
    normalizedCmsSignature,
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
  });

  const analyzeResult = await runAnalyze({
    input: workspaceDir,
    output: analysisDir,
    level: options.level,
    objectives: options.objectives,
    projectName: options.projectName,
    projectVersion: options.projectVersion,
    stage: options.stage,
  });

  const reportResult = await runReport({
    input: analysisDir,
    output: reportsDir,
    stage: options.stage,
  });

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
  };
};

export interface VerifyOptions {
  manifestPath: string;
  signaturePath: string;
  publicKeyPath: string;
  packagePath?: string;
}

export interface VerifyResult {
  isValid: boolean;
  manifestId: string;
  packageIssues: string[];
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
  manifest: Manifest,
): Promise<string[]> => {
  const expected = new Map<string, string>();
  for (const file of manifest.files) {
    expected.set(normalizeArchivePath(file.path), file.sha256.toLowerCase());
  }

  const archive = await fsPromises.readFile(packagePath);
  const entries = readCentralDirectoryEntries(archive);

  const issues: string[] = [];

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

  return issues;
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

  const manifestId = createHash('sha256').update(manifestRaw).digest('hex').slice(0, 12);
  const isValid = verifyManifestSignature(manifest, signature, verifierPem);

  let packageIssues: string[] = [];
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
      packageIssues = await verifyPackageAgainstManifest(packagePath, manifest);
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      throw new Error(`Paket içeriği doğrulanamadı: ${reason}`);
    }
  }

  return { isValid, manifestId, packageIssues };
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

  const analyzeResult = await runAnalyze({
    input: workDir,
    output: analysisDir,
    level,
    objectives: config.objectives?.file ? path.resolve(baseDir, config.objectives.file) : undefined,
    projectName: config.project?.name,
    projectVersion: config.project?.version,
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
    { complianceHtml: reportResult.complianceHtml, command: 'run' },
    'Raporlar üretildi.',
  );
  logger?.info({ manifestPath: packResult.manifestPath, command: 'run' }, 'Manifest kaydedildi.');
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
    .alias('version', 'V')
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
          .option('import', {
            describe:
              'Plan, standart, QA kaydı gibi artefaktlar ve araç çıktıları (plan=, standard=, qa_record=, polyspace=, ...).',
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

          const result = await runImport({
            output: argv.output,
            jira: argv.jira,
            jiraDefects,
            reqif: argv.reqif,
            junit: argv.junit,
            lcov: argv.lcov,
            cobertura: argv.cobertura,
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
            polarion: buildPolarionOptions(argv),
            jenkins: buildJenkinsOptions(argv),
            doorsNext: buildDoorsNextOptions(argv),
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
          .option('stage', {
            describe: 'SOI aşaması filtresi (SOI-1…SOI-4).',
            type: 'string',
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

          const result = await runAnalyze({
            input: argv.input,
            output: argv.output,
            objectives: argv.objectives,
            level: argv.level as CertificationLevel | undefined,
            projectName: argv.projectName as string | undefined,
            projectVersion: argv.projectVersion as string | undefined,
            stage,
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
            stage,
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

          const result = await runIngestPipeline({
            inputDir,
            outputDir,
            objectives: argv.objectives as string | undefined,
            level: normalizedLevel,
            projectName: argv.projectName as string | undefined,
            projectVersion: argv.projectVersion as string | undefined,
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

          const result = await runPack({
            input: argv.input,
            output: argv.output,
            packageName: argv.name,
            signingKey,
            ledger: ledgerOptions,
            cms: cmsOptions,
            stage,
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
            signingKey,
            packageName,
            ledger: ledgerOptions,
            cms: cmsOptions,
            stage,
          });

          logger.info(
            {
              ...context,
              archivePath: result.archivePath,
              manifestPath: result.manifestPath,
              manifestId: result.manifestId,
            },
            'Paket oluşturma tamamlandı.',
          );

          console.log(`Paket ${result.archivePath} olarak kaydedildi.`);
          console.log(`Manifest ${result.manifestPath} dosyasına yazıldı.`);
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
          }),
      async (argv) => {
        const logger = getLogger(argv);
        const manifestOption = Array.isArray(argv.manifest) ? argv.manifest[0] : argv.manifest;
        const signatureOption = Array.isArray(argv.signature) ? argv.signature[0] : argv.signature;
        const publicKeyOption = Array.isArray(argv.publicKey) ? argv.publicKey[0] : argv.publicKey;
        const packageOption = Array.isArray(argv.package) ? argv.package[0] : argv.package;

        const manifestPath = path.resolve(manifestOption as string);
        const signaturePath = path.resolve(signatureOption as string);
        const publicKeyPath = path.resolve(publicKeyOption as string);
        const packagePath = packageOption ? path.resolve(String(packageOption)) : undefined;

        const context = {
          command: 'verify',
          manifestPath,
          signaturePath,
          publicKeyPath,
          packagePath,
        };

        try {
          const result = await runVerify({
            manifestPath,
            signaturePath,
            publicKeyPath,
            packagePath,
          });
          const hasPackageIssues = result.packageIssues.length > 0;

          if (hasPackageIssues || !result.isValid) {
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

            if (!result.isValid) {
              logger.warn(
                { ...context, manifestId: result.manifestId },
                'Manifest imzası doğrulanamadı.',
              );
              console.error(`Manifest imzası doğrulanamadı (ID: ${result.manifestId}).`);
            }

            process.exitCode = exitCodes.verificationFailed;
          } else {
            logger.info(
              { ...context, manifestId: result.manifestId },
              'Manifest imzası doğrulandı.',
            );
            console.log(`Manifest imzası doğrulandı (ID: ${result.manifestId}).`);
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

export const __internal = {
  logLicenseValidated,
  logCliError,
  mergeStructuralCoverage,
};

export {
  exitCodes,
  verifyLicenseFile,
  LicenseError,
  type LicensePayload,
  type VerifyLicenseOptions,
};
