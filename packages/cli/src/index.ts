#!/usr/bin/env node
import { createHash } from 'crypto';
import fs, { promises as fsPromises } from 'fs';
import http from 'http';
import https from 'https';
import path from 'path';
import process from 'process';
import { pipeline as streamPipeline } from 'stream/promises';

import {
  importCobertura,
  importGitMetadata,
  importJiraCsv,
  importJUnitXml,
  importLcov,
  fetchJenkinsArtifacts,
  fetchPolarionArtifacts,
  importReqIF,
  fromLDRA,
  fromPolyspace,
  fromVectorCAST,
  type BuildInfo,
  type CoverageReport,
  type CoverageSummary as StructuralCoverageSummary,
  type Finding,
  type JiraRequirement,
  type JenkinsClientOptions,
  type PolarionClientOptions,
  type RemoteBuildRecord,
  type RemoteRequirementRecord,
  type RemoteTestRecord,
  type ReqIFRequirement,
  type TestResult,
  type TestStatus,
} from '@soipack/adapters';
import {
  CertificationLevel,
  certificationLevels,
  Evidence,
  EvidenceSource,
  Manifest,
  Objective,
  ObjectiveArtifactType,
  Requirement,
  RequirementStatus,
  TraceLink,
  createRequirement,
  traceLinkSchema,
} from '@soipack/core';
import {
  ComplianceSnapshot,
  EvidenceIndex,
  ImportBundle,
  RequirementTrace,
  TraceEngine,
  generateComplianceSnapshot,
} from '@soipack/engine';
import { buildManifest, signManifest, verifyManifestSignature } from '@soipack/packager';
import {
  renderComplianceMatrix,
  renderGaps,
  renderTraceMatrix,
  renderPlanDocument,
  planTemplateSections,
  planTemplateTitles,
  printToPDF,
  type PlanTemplateId,
  type PlanOverrideConfig,
  type PlanSectionOverrides,
} from '@soipack/report';
import YAML from 'yaml';
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';
import { ZipFile } from 'yazl';

import packageInfo from '../package.json';

import {
  DEFAULT_LICENSE_FILE,
  LicenseError,
  verifyLicenseFile,
  resolveLicensePath,
  type LicensePayload,
  type VerifyLicenseOptions,
} from './license';
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
  reqif?: string;
  junit?: string;
  lcov?: string;
  cobertura?: string;
  git?: string;
  traceLinksCsv?: string;
  traceLinksJson?: string;
  polyspace?: string;
  ldra?: string;
  vectorcast?: string;
  polarion?: string;
  jenkins?: string;
}

export type ImportOptions = Omit<ImportPaths, 'polarion' | 'jenkins'> & {
  output: string;
  objectives?: string;
  level?: CertificationLevel;
  projectName?: string;
  projectVersion?: string;
  polarion?: PolarionClientOptions;
  jenkins?: JenkinsClientOptions;
};

export interface ImportWorkspace {
  requirements: Requirement[];
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

const normalizeRelativePath = (filePath: string): string => {
  if (/^[a-z]+:\/\//iu.test(filePath) || filePath.startsWith('remote:')) {
    return filePath;
  }
  const absolute = path.resolve(filePath);
  const relative = path.relative(process.cwd(), absolute);
  const normalized = relative.length > 0 ? relative : '.';
  return normalized.split(path.sep).join('/');
};

const staticAnalysisTools = ['polyspace', 'ldra', 'vectorcast'] as const;
type StaticAnalysisTool = (typeof staticAnalysisTools)[number];

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
  jenkins?: {
    baseUrl: string;
    job: string;
    build?: string;
    tests: number;
    builds: number;
  };
}

const parseAdapterImportArgs = (
  value: unknown,
): Partial<Record<StaticAnalysisTool, string>> => {
  if (!value) {
    return {};
  }

  const entries = Array.isArray(value) ? value : [value];
  const imports: Partial<Record<StaticAnalysisTool, string>> = {};

  entries.forEach((entry) => {
    if (typeof entry !== 'string') {
      throw new Error('--import seçenekleri tool=path biçiminde olmalıdır.');
    }
    const [toolName, ...rest] = entry.split('=');
    if (!toolName || rest.length === 0) {
      throw new Error(`Geçersiz --import değeri: ${entry}. Beklenen biçim tool=path.`);
    }
    const normalizedTool = toolName.trim().toLowerCase() as StaticAnalysisTool;
    if (!staticAnalysisTools.includes(normalizedTool)) {
      throw new Error(
        `Desteklenmeyen --import aracı: ${toolName}. (polyspace, ldra, vectorcast)`,
      );
    }
    const resolvedPath = rest.join('=').trim();
    if (!resolvedPath) {
      throw new Error(`--import ${normalizedTool} için dosya yolu belirtilmelidir.`);
    }
    imports[normalizedTool] = resolvedPath;
  });

  return imports;
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
        reject(new Error(`HTTP ${statusCode ?? 0}: ${message ?? 'Beklenmeyen sunucu hatası'}`));
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

const mergeStructuralCoverage = (
  existing: StructuralCoverageSummary | undefined,
  incoming: StructuralCoverageSummary,
): StructuralCoverageSummary => {
  if (!existing) {
    return {
      tool: incoming.tool,
      files: incoming.files.map((file) => ({ ...file })),
      objectiveLinks: incoming.objectiveLinks ? [...incoming.objectiveLinks] : undefined,
    };
  }

  const files = new Map<string, StructuralCoverageSummary['files'][number]>();
  existing.files.forEach((file) => {
    files.set(file.path, { ...file });
  });
  incoming.files.forEach((file) => {
    files.set(file.path, { ...file });
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
    description: entry.description ?? entry.summary,
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
  provider: 'polarion' | 'jenkins',
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
    reqif: options.reqif ? normalizeRelativePath(options.reqif) : undefined,
    junit: options.junit ? normalizeRelativePath(options.junit) : undefined,
    lcov: options.lcov ? normalizeRelativePath(options.lcov) : undefined,
    cobertura: options.cobertura ? normalizeRelativePath(options.cobertura) : undefined,
    git: options.git ? normalizeRelativePath(options.git) : undefined,
    traceLinksCsv: options.traceLinksCsv ? normalizeRelativePath(options.traceLinksCsv) : undefined,
    traceLinksJson: options.traceLinksJson
      ? normalizeRelativePath(options.traceLinksJson)
      : undefined,
    polyspace: options.polyspace ? normalizeRelativePath(options.polyspace) : undefined,
    ldra: options.ldra ? normalizeRelativePath(options.ldra) : undefined,
    vectorcast: options.vectorcast ? normalizeRelativePath(options.vectorcast) : undefined,
    polarion: options.polarion ? `${options.polarion.baseUrl}#${options.polarion.projectId}` : undefined,
    jenkins: options.jenkins
      ? `${options.jenkins.baseUrl}#${options.jenkins.job}`
      : undefined,
  };
  const normalizedObjectivesPath = options.objectives
    ? path.resolve(options.objectives)
    : undefined;
  const manualTraceLinks: TraceLink[] = [];

  if (options.jira) {
    const result = await importJiraCsv(options.jira);
    warnings.push(...result.warnings);
    if (result.data.length > 0) {
      mergeEvidence(
        evidenceIndex,
        'trace',
        createEvidence('trace', 'jiraCsv', options.jira!, 'Jira gereksinim dışa aktarımı').evidence,
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
        'trace',
        createEvidence('trace', 'reqif', options.reqif, 'ReqIF gereksinim paketi').evidence,
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
        'test',
        createEvidence('test', 'junit', options.junit, 'JUnit test sonuçları').evidence,
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
        'coverage_stmt',
        createEvidence('coverage_stmt', 'lcov', options.lcov, 'LCOV kapsam raporu').evidence,
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
        'coverage_stmt',
        createEvidence('coverage_stmt', 'cobertura', options.cobertura, 'Cobertura kapsam raporu')
          .evidence,
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
        'coverage_stmt',
        createEvidence('coverage_stmt', 'cobertura', options.cobertura, 'Cobertura kapsam raporu')
          .evidence,
      );
    }
  }

  if (options.polyspace) {
    const result = await fromPolyspace(options.polyspace);
    warnings.push(...result.warnings);
    if (result.data.findings) {
      findings.push(...result.data.findings);
    }
    if ((result.data.findings?.length ?? 0) > 0) {
      mergeEvidence(
        evidenceIndex,
        'review',
        createEvidence('review', 'polyspace', options.polyspace, 'Polyspace statik analiz raporu')
          .evidence,
      );
      mergeEvidence(
        evidenceIndex,
        'problem_report',
        createEvidence('problem_report', 'polyspace', options.polyspace, 'Polyspace bulgu listesi')
          .evidence,
      );
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
      mergeEvidence(
        evidenceIndex,
        'coverage_stmt',
        createEvidence('coverage_stmt', 'ldra', options.ldra, 'LDRA kapsam özeti').evidence,
      );
    }
    if ((result.data.findings?.length ?? 0) > 0) {
      mergeEvidence(
        evidenceIndex,
        'review',
        createEvidence('review', 'ldra', options.ldra, 'LDRA kural ihlalleri').evidence,
      );
      mergeEvidence(
        evidenceIndex,
        'problem_report',
        createEvidence('problem_report', 'ldra', options.ldra, 'LDRA ihlal raporu').evidence,
      );
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
      mergeEvidence(
        evidenceIndex,
        'coverage_stmt',
        createEvidence('coverage_stmt', 'vectorcast', options.vectorcast, 'VectorCAST kapsam raporu')
          .evidence,
      );
      if (structuralCoverageHasMetric(result.data.coverage, 'dec')) {
        mergeEvidence(
          evidenceIndex,
          'coverage_dec',
          createEvidence('coverage_dec', 'vectorcast', options.vectorcast, 'VectorCAST karar kapsamı')
            .evidence,
        );
      }
      if (structuralCoverageHasMetric(result.data.coverage, 'mcdc')) {
        mergeEvidence(
          evidenceIndex,
          'coverage_mcdc',
          createEvidence('coverage_mcdc', 'vectorcast', options.vectorcast, 'VectorCAST MC/DC kapsamı')
            .evidence,
        );
      }
    }
    if ((result.data.findings?.length ?? 0) > 0) {
      mergeEvidence(
        evidenceIndex,
        'test',
        createEvidence('test', 'vectorcast', options.vectorcast, 'VectorCAST test değerlendirmeleri')
          .evidence,
      );
      mergeEvidence(
        evidenceIndex,
        'analysis',
        createEvidence('analysis', 'vectorcast', options.vectorcast, 'VectorCAST sonuç analizi')
          .evidence,
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
        'cm_record',
        createEvidence('cm_record', 'git', options.git, 'Git depo başlığı').evidence,
      );
    }
  }

  if (options.traceLinksCsv) {
    const result = await importTraceLinksCsv(options.traceLinksCsv);
    warnings.push(...result.warnings);
    if (result.links.length > 0) {
      manualTraceLinks.push(...result.links);
      mergeEvidence(
        evidenceIndex,
        'trace',
        createEvidence('trace', 'other', options.traceLinksCsv, 'Manuel izlenebilirlik eşlemeleri (CSV)')
          .evidence,
      );
    }
  }

  if (options.polarion) {
    const polarionResult = await fetchPolarionArtifacts(options.polarion);
    warnings.push(...polarionResult.warnings);
    const polarionRequirements = polarionResult.data.requirements ?? [];
    const polarionTests = polarionResult.data.tests ?? [];
    const polarionBuilds = polarionResult.data.builds ?? [];

    if (polarionRequirements.length > 0) {
      requirements.push(polarionRequirements.map(toRequirementFromPolarion));
      mergeEvidence(
        evidenceIndex,
        'trace',
        createEvidence(
          'trace',
          'polarion',
          `remote:polarion:${options.polarion.projectId}`,
          'Polarion gereksinim kataloğu',
        ).evidence,
      );
    }

    if (polarionTests.length > 0) {
      testResults.push(
        ...polarionTests.map((entry) => toTestResultFromRemote(entry, 'polarion')),
      );
      mergeEvidence(
        evidenceIndex,
        'test',
        createEvidence(
          'test',
          'polarion',
          `remote:polarion:${options.polarion.projectId}`,
          'Polarion test çalıştırmaları',
        ).evidence,
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
      mergeEvidence(
        evidenceIndex,
        'cm_record',
        createEvidence(
          'cm_record',
          'polarion',
          `remote:polarion:${options.polarion.projectId}`,
          'Polarion yapı kayıtları',
        ).evidence,
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
      mergeEvidence(
        evidenceIndex,
        'test',
        createEvidence(
          'test',
          'jenkins',
          `remote:jenkins:${options.jenkins.job}`,
          'Jenkins test raporları',
        ).evidence,
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
      mergeEvidence(
        evidenceIndex,
        'cm_record',
        createEvidence(
          'cm_record',
          'jenkins',
          `remote:jenkins:${options.jenkins.job}`,
          'Jenkins build metaverisi',
        ).evidence,
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

  if (options.traceLinksJson) {
    const result = await importTraceLinksJson(options.traceLinksJson);
    warnings.push(...result.warnings);
    if (result.links.length > 0) {
      manualTraceLinks.push(...result.links);
      mergeEvidence(
        evidenceIndex,
        'trace',
        createEvidence('trace', 'other', options.traceLinksJson, 'Manuel izlenebilirlik eşlemeleri (JSON)')
          .evidence,
      );
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

  const workspace: ImportWorkspace = {
    requirements: mergedRequirements,
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
      generatedAt: getCurrentTimestamp(),
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
  return objectives.filter((objective) => objective.levels[level]);
};

const sortObjectives = (objectives: Objective[]): Objective[] => {
  return [...objectives].sort((a, b) => a.id.localeCompare(b.id, 'en') || a.name.localeCompare(b.name, 'en'));
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
    return 'Seçilen filtre kriterleriyle eşleşen hedef bulunamadı.';
  }

  const columns = [
    { key: 'id', label: 'ID', getter: (objective: Objective) => objective.id },
    { key: 'table', label: 'Tablo', getter: (objective: Objective) => objective.table },
    {
      key: 'levels',
      label: 'Seviyeler',
      getter: (objective: Objective) => formatLevelApplicability(objective.levels),
    },
    {
      key: 'independence',
      label: 'Bağımsızlık',
      getter: (objective: Objective) => objective.independence,
    },
    {
      key: 'artifacts',
      label: 'Artefaktlar',
      getter: (objective: Objective) => objective.artifacts.join(', '),
    },
    { key: 'name', label: 'Başlık', getter: (objective: Objective) => objective.name },
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
  objectives,
  testResults: workspace.testResults,
  coverage: workspace.coverage,
  structuralCoverage: workspace.structuralCoverage,
  evidenceIndex: workspace.evidenceIndex,
  traceLinks: uniqueTraceLinks(workspace.traceLinks ?? []),
  testToCodeMap: workspace.testToCodeMap,
  generatedAt: workspace.metadata.generatedAt,
  targetLevel: level,
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
  const filteredObjectives = filterObjectives(objectives, level);

  const bundle = buildImportBundle(workspace, filteredObjectives, level);
  const snapshot = generateComplianceSnapshot(bundle);
  const engine = new TraceEngine(bundle);
  const traces = collectRequirementTraces(engine, workspace.requirements);

  const outputDir = path.resolve(options.output);
  await ensureDirectory(outputDir);

  const snapshotPath = path.join(outputDir, 'snapshot.json');
  const tracePath = path.join(outputDir, 'traces.json');
  const analysisPath = path.join(outputDir, 'analysis.json');

  const analysisMetadata: AnalysisMetadata = {
    project:
      options.projectName || options.projectVersion || workspace.metadata.project
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
    qualityFindings: snapshot.qualityFindings,
  });

  const hasMissingEvidence = snapshot.objectives.some(
    (objective) => objective.status !== 'covered',
  );
  const exitCode = hasMissingEvidence ? exitCodes.missingEvidence : exitCodes.success;

  return { snapshotPath, tracePath, analysisPath, exitCode };
};

export interface ReportOptions {
  input: string;
  output: string;
  manifestId?: string;
  planConfig?: string;
  planOverrides?: PlanSectionOverrides;
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
  });
  const traceHtml = renderTraceMatrix(traces, {
    generatedAt: analysis.metadata.generatedAt,
    title: analysis.metadata.project?.name
      ? `${analysis.metadata.project.name} İzlenebilirlik Matrisi`
      : 'SOIPack İzlenebilirlik Matrisi',
    coverage: snapshot.requirementCoverage,
    git: analysis.git,
  });
  const gapsHtml = renderGaps(snapshot, {
    objectivesMetadata: analysis.objectives,
    manifestId: options.manifestId,
    generatedAt: analysis.metadata.generatedAt,
    title: analysis.metadata.project?.name
      ? `${analysis.metadata.project.name} Kanıt Boşlukları`
      : 'SOIPack Uyumluluk Boşlukları',
    git: analysis.git,
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
    gapsHtml: gapsHtmlPath,
    plans,
    warnings: planWarnings,
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

  const archiveName =
    options.packageName !== undefined
      ? normalizePackageName(options.packageName)
      : `soipack-${manifestId}.zip`;
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
  allowInsecureHttp?: boolean;
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
    .option('allow-insecure-http', {
      describe: 'HTTPS yerine HTTP üzerinden indirmelere izin verir (varsayılan: devre dışı).',
      type: 'boolean',
      global: true,
      default: false,
    })
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
            describe: 'Seviye filtresi (A-E).',
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
            describe: 'Statik analiz ve kapsam raporları (polyspace=, ldra=, vectorcast=).',
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

          const adapterImports = parseAdapterImportArgs(
            (argv as Record<string, unknown>)['import'],
          );

          const result = await runImport({
            output: argv.output,
            jira: argv.jira,
            reqif: argv.reqif,
            junit: argv.junit,
            lcov: argv.lcov,
            cobertura: argv.cobertura,
            git: argv.git,
            traceLinksCsv: argv.traceLinksCsv as string | undefined,
            traceLinksJson: argv.traceLinksJson as string | undefined,
            polyspace: adapterImports.polyspace,
            ldra: adapterImports.ldra,
            vectorcast: adapterImports.vectorcast,
            polarion: buildPolarionOptions(argv),
            jenkins: buildJenkinsOptions(argv),
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
            planConfig: argv['plan-config'] as string | undefined,
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
            logger.info(
              { ...context, manifestId: result.manifestId },
              'Manifest imzası doğrulandı.',
            );
            console.log(`Manifest imzası doğrulandı (ID: ${result.manifestId}).`);
            process.exitCode = exitCodes.success;
          } else {
            logger.warn(
              { ...context, manifestId: result.manifestId },
              'Manifest imzası doğrulanamadı.',
            );
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

export const __internal = {
  logLicenseValidated,
};

export {
  exitCodes,
  verifyLicenseFile,
  LicenseError,
  type LicensePayload,
  type VerifyLicenseOptions,
};
