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
import { renderComplianceMatrix, renderGaps, renderTraceMatrix } from '@soipack/report';
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
  const absolute = path.resolve(filePath);
  const relative = path.relative(process.cwd(), absolute);
  const normalized = relative.length > 0 ? relative : '.';
  return normalized.split(path.sep).join('/');
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
    traceLinksCsv: options.traceLinksCsv ? normalizeRelativePath(options.traceLinksCsv) : undefined,
    traceLinksJson: options.traceLinksJson
      ? normalizeRelativePath(options.traceLinksJson)
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
        'traceability',
        createEvidence('traceability', 'jiraCsv', options.jira!, 'Jira gereksinim dışa aktarımı')
          .evidence,
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
        createEvidence('coverage', 'cobertura', options.cobertura, 'Cobertura kapsam raporu')
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
        'coverage',
        createEvidence('coverage', 'cobertura', options.cobertura, 'Cobertura kapsam raporu')
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
        'git',
        createEvidence('git', 'git', options.git, 'Git depo başlığı').evidence,
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
        'traceability',
        createEvidence(
          'traceability',
          'other',
          options.traceLinksCsv,
          'Manuel izlenebilirlik eşlemeleri (CSV)',
        ).evidence,
      );
    }
  }

  if (options.traceLinksJson) {
    const result = await importTraceLinksJson(options.traceLinksJson);
    warnings.push(...result.warnings);
    if (result.links.length > 0) {
      manualTraceLinks.push(...result.links);
      mergeEvidence(
        evidenceIndex,
        'traceability',
        createEvidence(
          'traceability',
          'other',
          options.traceLinksJson,
          'Manuel izlenebilirlik eşlemeleri (JSON)',
        ).evidence,
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
    traceLinks,
    testToCodeMap,
    evidenceIndex,
    git: gitMetadata,
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

const buildImportBundle = (workspace: ImportWorkspace, objectives: Objective[]): ImportBundle => ({
  requirements: workspace.requirements,
  objectives,
  testResults: workspace.testResults,
  coverage: workspace.coverage,
  evidenceIndex: workspace.evidenceIndex,
  traceLinks: uniqueTraceLinks(workspace.traceLinks ?? []),
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
  const objectivesPathRaw =
    options.objectives ?? workspace.metadata.objectivesPath ?? fallbackObjectivesPath;
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
