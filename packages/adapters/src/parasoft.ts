import { promises as fs } from 'fs';
import path from 'path';

import type {
  CoverageSummary,
  Finding,
  ImportedBundle,
  ImportedFileHash,
  ParseResult,
  TestResult,
} from './types';
import { parseXml } from './utils/xml';

type FindingSeverity = NonNullable<Finding['severity']>;

export interface ParasoftImportOptions {
  minSeverity?: FindingSeverity;
}

interface ParasoftReportRoot {
  parasoftReport?: ParasoftReportNode;
  report?: ParasoftReportNode;
  module?: ParasoftModule | ParasoftModule[];
}

interface ParasoftReportNode {
  module?: ParasoftModule | ParasoftModule[];
}

interface ParasoftModule {
  name?: string;
  testCases?: { testCase?: ParasoftTestCase | ParasoftTestCase[] } | ParasoftTestCase | ParasoftTestCase[];
  tests?: { testCase?: ParasoftTestCase | ParasoftTestCase[] } | ParasoftTestCase | ParasoftTestCase[];
  results?: { testCase?: ParasoftTestCase | ParasoftTestCase[] } | ParasoftTestCase | ParasoftTestCase[];
  findings?: { finding?: ParasoftFinding | ParasoftFinding[] } | ParasoftFinding | ParasoftFinding[];
  staticAnalysis?: { finding?: ParasoftFinding | ParasoftFinding[] } | ParasoftFinding | ParasoftFinding[];
  coverage?: { file?: ParasoftCoverageFile | ParasoftCoverageFile[] } | ParasoftCoverageFile | ParasoftCoverageFile[];
  files?: { file?: ParasoftCoverageFile | ParasoftCoverageFile[] } | ParasoftCoverageFile | ParasoftCoverageFile[];
}

interface ParasoftTestCase {
  id?: string;
  uid?: string;
  name?: string;
  suite?: string;
  classname?: string;
  verdict?: string;
  result?: string;
  status?: string;
  durationMs?: unknown;
  duration?: unknown;
  time?: unknown;
  requirement?: unknown;
  requirements?: unknown;
  requirementsRef?: unknown;
  requirementIds?: unknown;
  message?: unknown;
  failure?: unknown;
  error?: unknown;
  details?: unknown;
}

interface ParasoftFinding {
  id?: string;
  rule?: string;
  severity?: string;
  file?: string;
  path?: string;
  line?: unknown;
  column?: unknown;
  function?: string;
  functionName?: string;
  message?: unknown;
  description?: unknown;
  status?: string;
}

interface ParasoftCoverageFile {
  path?: string;
  file?: string;
  name?: string;
  hash?: string;
  checksum?: string;
  metric?: ParasoftCoverageMetric | ParasoftCoverageMetric[];
  metrics?: { metric?: ParasoftCoverageMetric | ParasoftCoverageMetric[] };
  coverage?: ParasoftCoverageMetric | ParasoftCoverageMetric[];
}

interface ParasoftCoverageMetric {
  type?: string;
  name?: string;
  metric?: string;
  category?: string;
  covered?: unknown;
  total?: unknown;
  coveredUnits?: unknown;
  totalUnits?: unknown;
  coveredElements?: unknown;
  totalElements?: unknown;
}

const findingObjectiveLinks = ['A-5-05', 'A-5-14'];
const coverageObjectiveLinks = {
  stmt: 'A-5-08',
  dec: 'A-5-09',
  mcdc: 'A-5-10',
} as const;

const severityRanks: Record<FindingSeverity, number> = {
  info: 0,
  warn: 1,
  error: 2,
};

const ensureArray = <T>(value: T | T[] | undefined | null): T[] => {
  if (!value) {
    return [];
  }
  return Array.isArray(value) ? value : [value];
};

const getTextContent = (value: unknown): string | undefined => {
  if (typeof value === 'string') {
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  }
  if (value && typeof value === 'object') {
    const text = (value as { ['#text']?: unknown })['#text'];
    if (typeof text === 'string') {
      const trimmed = text.trim();
      return trimmed.length > 0 ? trimmed : undefined;
    }
  }
  return undefined;
};

const normalizeSeverity = (raw: string | undefined): Finding['severity'] | undefined => {
  if (!raw) {
    return undefined;
  }
  const normalized = raw.trim().toLowerCase();
  if (!normalized) {
    return undefined;
  }
  if (['info', 'information', 'informational', 'low', 'advisory', 'minor'].includes(normalized)) {
    return 'info';
  }
  if (
    ['warn', 'warning', 'medium', 'moderate', 'major', 'priority2', 'p2'].includes(normalized)
  ) {
    return 'warn';
  }
  if (
    [
      'error',
      'high',
      'critical',
      'severe',
      'failure',
      'priority1',
      'p1',
      'very high',
    ].includes(normalized)
  ) {
    return 'error';
  }
  return undefined;
};

const normalizeFindingStatus = (raw: string | undefined): Finding['status'] => {
  if (!raw) {
    return undefined;
  }
  const normalized = raw.trim().toLowerCase();
  if (!normalized) {
    return undefined;
  }
  if (['open', 'justified', 'closed', 'proved', 'unproved'].includes(normalized)) {
    return normalized as Finding['status'];
  }
  return undefined;
};

const meetsSeverityThreshold = (
  severity: Finding['severity'] | undefined,
  minSeverity: FindingSeverity,
): boolean => {
  if (!severity) {
    return false;
  }
  return severityRanks[severity as FindingSeverity] >= severityRanks[minSeverity];
};

const parseNumber = (value: unknown): number | undefined => {
  if (typeof value === 'number') {
    return Number.isFinite(value) ? value : undefined;
  }
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) {
      return undefined;
    }
    const normalized = trimmed.endsWith('%') ? trimmed.slice(0, -1) : trimmed;
    const sanitized = normalized.replace(/,/g, '');
    const parsed = Number.parseFloat(sanitized);
    if (!Number.isFinite(parsed)) {
      return undefined;
    }
    return parsed;
  }
  return undefined;
};

const parseLineNumber = (value: unknown): number | undefined => {
  const parsed = parseNumber(value);
  if (parsed === undefined) {
    return undefined;
  }
  const rounded = Math.trunc(parsed);
  return rounded >= 0 ? rounded : undefined;
};

const parseDurationSeconds = (entry: ParasoftTestCase): number => {
  const durationMsCandidates = [entry.durationMs];
  const durationSecondsCandidates = [entry.duration, entry.time];

  for (const candidate of durationMsCandidates) {
    const numeric = parseNumber(candidate);
    if (numeric !== undefined) {
      return Math.max(0, numeric / 1000);
    }
  }

  for (const candidate of durationSecondsCandidates) {
    const numeric = parseNumber(candidate);
    if (numeric !== undefined) {
      return Math.max(0, numeric);
    }
  }

  return 0;
};

const parseRequirementValues = (value: unknown): string[] => {
  if (!value) {
    return [];
  }
  if (typeof value === 'string') {
    return value
      .split(/[;,\s]+/u)
      .map((item) => item.trim())
      .filter((item) => item.length > 0);
  }
  if (Array.isArray(value)) {
    return value
      .flatMap((item) => parseRequirementValues(item))
      .filter((item): item is string => typeof item === 'string' && item.length > 0);
  }
  if (typeof value === 'object') {
    const obj = value as { requirement?: unknown; id?: unknown; ['#text']?: unknown };
    if (obj.id && typeof obj.id === 'string') {
      const trimmed = obj.id.trim();
      return trimmed ? [trimmed] : [];
    }
    if (obj.requirement) {
      return parseRequirementValues(obj.requirement);
    }
    if (typeof obj['#text'] === 'string') {
      return parseRequirementValues(obj['#text']);
    }
  }
  return [];
};

const normalizeVerdict = (entry: ParasoftTestCase): TestResult['status'] => {
  const candidates = [entry.verdict, entry.result, entry.status].filter(
    (value): value is string => typeof value === 'string' && value.trim().length > 0,
  );
  const normalized = candidates.map((item) => item.trim().toLowerCase());
  if (normalized.some((value) => ['pass', 'passed', 'success', 'ok'].includes(value))) {
    return 'passed';
  }
  if (
    normalized.some((value) => ['fail', 'failed', 'error', 'timeout', 'crash'].includes(value)) ||
    getTextContent(entry.failure) !== undefined ||
    getTextContent(entry.error) !== undefined
  ) {
    return 'failed';
  }
  if (
    normalized.some((value) => ['skipped', 'notrun', 'not run', 'inconclusive', 'na', 'n/a'].includes(value))
  ) {
    return 'skipped';
  }
  return 'skipped';
};

const selectTestId = (entry: ParasoftTestCase, moduleName: string, index: number): string => {
  const candidates = [entry.id, entry.uid, entry.name];
  for (const candidate of candidates) {
    if (typeof candidate === 'string' && candidate.trim().length > 0) {
      return candidate.trim();
    }
  }
  return `${moduleName || 'module'}-test-${index + 1}`;
};

const selectClassName = (entry: ParasoftTestCase, moduleName: string): string => {
  const candidates = [entry.classname, entry.suite, moduleName];
  for (const candidate of candidates) {
    if (typeof candidate === 'string' && candidate.trim().length > 0) {
      return candidate.trim();
    }
  }
  return moduleName || 'Parasoft';
};

const selectTestName = (entry: ParasoftTestCase, fallbackId: string): string => {
  if (typeof entry.name === 'string' && entry.name.trim().length > 0) {
    return entry.name.trim();
  }
  return fallbackId;
};

const extractTestError = (entry: ParasoftTestCase): string | undefined => {
  const candidates = [entry.message, entry.failure, entry.error, entry.details];
  for (const candidate of candidates) {
    const text = getTextContent(candidate);
    if (text) {
      return text;
    }
  }
  return undefined;
};

const extractFindingEntries = (source: unknown): ParasoftFinding[] => {
  return ensureArray(source)
    .filter((item): item is ParasoftFinding | { finding?: ParasoftFinding | ParasoftFinding[] } => item !== undefined)
    .flatMap((item) => {
      const container = item as { finding?: ParasoftFinding | ParasoftFinding[] };
      if (container.finding !== undefined) {
        return ensureArray(container.finding).filter(
          (entry): entry is ParasoftFinding => entry !== undefined,
        );
      }
      return [item as ParasoftFinding];
    });
};

const toTestResults = (
  module: ParasoftModule,
  moduleName: string,
  warnings: string[],
): TestResult[] => {
  const rawCollection =
    module.testCases ?? module.tests ?? module.results ?? ({ testCase: [] } as const);
  const entries = ensureArray(
    (rawCollection as { testCase?: ParasoftTestCase | ParasoftTestCase[] }).testCase ??
      (Array.isArray(rawCollection) ? (rawCollection as ParasoftTestCase[]) : undefined) ??
      (rawCollection as ParasoftTestCase | ParasoftTestCase[]),
  ).filter((item): item is ParasoftTestCase => !!item);

  return entries.map((entry, index) => {
    const status = normalizeVerdict(entry);
    const testId = selectTestId(entry, moduleName, index);
    const duration = parseDurationSeconds(entry);
    const className = selectClassName(entry, moduleName);
    const name = selectTestName(entry, testId);
    const requirementCandidates = [
      entry.requirement,
      entry.requirements,
      entry.requirementsRef,
      entry.requirementIds,
    ];
    const requirements = requirementCandidates
      .flatMap((value) => parseRequirementValues(value))
      .filter((item, idx, arr) => arr.indexOf(item) === idx);

    const result: TestResult = {
      testId,
      className,
      name,
      status,
      duration,
      ...(requirements.length > 0 ? { requirementsRefs: requirements } : {}),
    };

    if (status === 'failed') {
      const errorMessage = extractTestError(entry);
      if (errorMessage) {
        result.errorMessage = errorMessage;
      }
    }

    return result;
  });
};

const toFinding = (
  entry: ParasoftFinding,
  index: number,
  warnings: string[],
  options: Required<ParasoftImportOptions>,
): Finding | null => {
  if (!entry.id) {
    warnings.push(`Parasoft bulgusu #${index + 1} yok sayıldı: kimlik alanı eksik.`);
    return null;
  }

  const severity = normalizeSeverity(entry.severity);
  if (!meetsSeverityThreshold(severity, options.minSeverity)) {
    return null;
  }

  const message =
    getTextContent(entry.message) ??
    getTextContent(entry.description) ??
    getTextContent((entry as { ['#text']?: unknown })['#text']) ??
    '';
  if (!message) {
    warnings.push(`Parasoft bulgusu ${entry.id} boş mesaj içeriyor.`);
  }

  const line = parseLineNumber(entry.line);

  return {
    tool: 'parasoft',
    id: String(entry.id),
    file: entry.file ?? entry.path,
    func: entry.function ?? entry.functionName,
    line,
    classification: entry.rule,
    severity,
    status: normalizeFindingStatus(entry.status),
    message,
    objectiveLinks: [...findingObjectiveLinks],
  };
};

interface AggregatedCoverage {
  stmt?: { covered: number; total: number };
  dec?: { covered: number; total: number };
  mcdc?: { covered: number; total: number };
}

const mergeCoverageMetric = (
  target: AggregatedCoverage,
  key: keyof AggregatedCoverage,
  value: { covered: number; total: number },
): void => {
  const existing = target[key];
  if (existing) {
    existing.covered += value.covered;
    existing.total += value.total;
  } else {
    target[key] = { covered: value.covered, total: value.total };
  }
};

const parseCoverageMetric = (
  metric: ParasoftCoverageMetric,
  filePath: string,
  metricType: string,
  warnings: string[],
): { covered: number; total: number } | undefined => {
  const coveredCandidate = metric.covered ?? metric.coveredUnits ?? metric.coveredElements;
  const totalCandidate = metric.total ?? metric.totalUnits ?? metric.totalElements;
  const coveredRaw = parseNumber(coveredCandidate);
  const totalRaw = parseNumber(totalCandidate);
  if (coveredRaw === undefined || totalRaw === undefined) {
    warnings.push(
      `Parasoft kapsam metriği ${filePath} (${metricType}) için sayısal değer okunamadı.`,
    );
    return undefined;
  }
  const covered = Math.max(0, Math.round(coveredRaw));
  const total = Math.max(0, Math.round(totalRaw));
  return { covered, total };
};

const selectCoverageMetricType = (metric: ParasoftCoverageMetric): keyof AggregatedCoverage | undefined => {
  const name = metric.type ?? metric.name ?? metric.metric ?? metric.category;
  if (!name || typeof name !== 'string') {
    return undefined;
  }
  const normalized = name.trim().toLowerCase();
  if (['line', 'lines', 'stmt', 'statement', 'statements'].includes(normalized)) {
    return 'stmt';
  }
  if (['branch', 'branches', 'decision', 'decisions'].includes(normalized)) {
    return 'dec';
  }
  if (['mcdc', 'mc/dc', 'modified condition/decision'].includes(normalized)) {
    return 'mcdc';
  }
  return undefined;
};

const selectFilePath = (entry: ParasoftCoverageFile): string | undefined => {
  const candidates = [entry.path, entry.file, entry.name];
  for (const candidate of candidates) {
    if (typeof candidate === 'string' && candidate.trim().length > 0) {
      return candidate.trim();
    }
  }
  return undefined;
};

const collectCoverage = (
  module: ParasoftModule,
  warnings: string[],
  fileHashes: Map<string, ImportedFileHash>,
): AggregatedCoverageMap => {
  const coverageEntries =
    module.coverage ?? module.files ?? ({ file: [] } as const);
  const rawFiles = ensureArray(
    (coverageEntries as { file?: ParasoftCoverageFile | ParasoftCoverageFile[] }).file ??
      (Array.isArray(coverageEntries) ? (coverageEntries as ParasoftCoverageFile[]) : undefined) ??
      (coverageEntries as ParasoftCoverageFile | ParasoftCoverageFile[]),
  ).filter((item): item is ParasoftCoverageFile => !!item);

  const aggregated: AggregatedCoverageMap = new Map();

  rawFiles.forEach((entry, index) => {
    const filePath = selectFilePath(entry);
    if (!filePath) {
      warnings.push(`Parasoft kapsam kaydı #${index + 1} yok sayıldı: dosya yolu eksik.`);
      return;
    }

    const hashCandidate = entry.hash ?? entry.checksum;
    if (typeof hashCandidate === 'string' && hashCandidate.trim().length > 0) {
      const normalizedHash = hashCandidate.trim().toLowerCase();
      const existing = fileHashes.get(filePath);
      if (!existing) {
        fileHashes.set(filePath, { artifact: 'cm_record', path: filePath, hash: normalizedHash });
      } else if (existing.hash !== normalizedHash) {
        warnings.push(
          `Parasoft dosyası ${filePath} için birden fazla karma değeri bulundu; ilk değer korunacak.`,
        );
      }
    }

    const metrics = ensureArray(
      entry.metric ?? entry.coverage ?? entry.metrics?.metric ?? ([] as ParasoftCoverageMetric[]),
    ).filter((metric): metric is ParasoftCoverageMetric => !!metric);

    if (metrics.length === 0) {
      return;
    }

    const aggregatedMetrics = aggregated.get(filePath) ?? ({} as AggregatedCoverage);

    metrics.forEach((metric) => {
      const metricType = selectCoverageMetricType(metric);
      if (!metricType) {
        return;
      }
      const parsed = parseCoverageMetric(metric, filePath, metricType, warnings);
      if (!parsed) {
        return;
      }
      mergeCoverageMetric(aggregatedMetrics, metricType, parsed);
    });

    aggregated.set(filePath, aggregatedMetrics);
  });

  return aggregated;
};

type AggregatedCoverageMap = Map<string, AggregatedCoverage>;

const toCoverageSummary = (coverageMap: AggregatedCoverageMap): CoverageSummary | undefined => {
  if (coverageMap.size === 0) {
    return undefined;
  }

  const files: CoverageSummary['files'] = [];
  const objectiveLinkSet = new Set<string>();

  coverageMap.forEach((metrics, filePath) => {
    if (!metrics.stmt) {
      return;
    }
    const fileEntry: CoverageSummary['files'][number] = {
      path: filePath,
      stmt: metrics.stmt,
    };
    if (metrics.dec && metrics.dec.total > 0) {
      fileEntry.dec = metrics.dec;
      objectiveLinkSet.add(coverageObjectiveLinks.dec);
    }
    if (metrics.mcdc && metrics.mcdc.total > 0) {
      fileEntry.mcdc = metrics.mcdc;
      objectiveLinkSet.add(coverageObjectiveLinks.mcdc);
    }
    objectiveLinkSet.add(coverageObjectiveLinks.stmt);
    files.push(fileEntry);
  });

  if (files.length === 0) {
    return undefined;
  }

  files.sort((a, b) => a.path.localeCompare(b.path));

  return {
    tool: 'parasoft',
    files,
    objectiveLinks: Array.from(objectiveLinkSet),
  };
};

const extractModules = (root: ParasoftReportRoot): ParasoftModule[] => {
  const candidateRoots = [root.parasoftReport, root.report, root];
  for (const candidate of candidateRoots) {
    if (!candidate) {
      continue;
    }
    const modules = ensureArray((candidate as ParasoftReportNode).module);
    if (modules.length > 0) {
      return modules;
    }
  }
  return [];
};

const resolveModuleName = (module: ParasoftModule, index: number): string => {
  if (typeof module.name === 'string' && module.name.trim().length > 0) {
    return module.name.trim();
  }
  return `Module-${index + 1}`;
};

export const importParasoft = async (
  filePath: string,
  options: ParasoftImportOptions = {},
): Promise<ParseResult<ImportedBundle>> => {
  const absolutePath = path.resolve(filePath);
  const warnings: string[] = [];
  const content = await fs.readFile(absolutePath, 'utf8');

  let raw: ParasoftReportRoot;
  try {
    raw = parseXml<ParasoftReportRoot>(content);
  } catch (error) {
    throw new Error(
      `Parasoft C/C++test raporu XML olarak parse edilemedi (${absolutePath}): ${(error as Error).message}`,
    );
  }

  const modules = extractModules(raw);
  if (modules.length === 0) {
    warnings.push('Parasoft raporunda modül bulunamadı.');
  }

  const severityOption: Required<ParasoftImportOptions> = {
    minSeverity: options.minSeverity ?? 'info',
  };

  const testResults: TestResult[] = [];
  const findings: Finding[] = [];
  const coverageMap: AggregatedCoverageMap = new Map();
  const fileHashes = new Map<string, ImportedFileHash>();

  modules.forEach((module, index) => {
    const moduleName = resolveModuleName(module, index);

    const moduleTests = toTestResults(module, moduleName, warnings);
    testResults.push(...moduleTests);

    const findingSources = [module.findings, module.staticAnalysis];
    let moduleFindingIndex = 0;
    findingSources.forEach((source) => {
      extractFindingEntries(source).forEach((entry) => {
        const finding = toFinding(entry, moduleFindingIndex, warnings, severityOption);
        moduleFindingIndex += 1;
        if (finding) {
          findings.push(finding);
        }
      });
    });

    const moduleCoverage = collectCoverage(module, warnings, fileHashes);
    moduleCoverage.forEach((metrics, filePath) => {
      const existing = coverageMap.get(filePath);
      if (!existing) {
        coverageMap.set(filePath, { ...metrics });
        return;
      }
      (['stmt', 'dec', 'mcdc'] as const).forEach((key) => {
        const metric = metrics[key];
        if (!metric) {
          return;
        }
        mergeCoverageMetric(existing, key, metric);
      });
    });
  });

  const coverage = toCoverageSummary(coverageMap);
  const fileHashList = Array.from(fileHashes.values()).sort((a, b) => a.path.localeCompare(b.path));

  return {
    data: {
      coverage,
      findings,
      testResults,
      fileHashes: fileHashList,
    },
    warnings,
  };
};

export type { ParasoftImportOptions as ImportParasoftOptions };
