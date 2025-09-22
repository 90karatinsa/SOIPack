import { promises as fs } from 'fs';
import path from 'path';

import type { CoverageSummary, Finding, ImportedBundle, ParseResult } from './types';

interface VectorcastCoverageMetric {
  covered?: number;
  total?: number;
}

interface VectorcastCoverageEntry {
  path?: string;
  stmt?: VectorcastCoverageMetric;
  dec?: VectorcastCoverageMetric;
  mcdc?: VectorcastCoverageMetric;
}

interface VectorcastFinding {
  id?: string;
  file?: string;
  func?: string;
  line?: number;
  sev?: string;
  msg?: string;
}

interface VectorcastReport {
  project?: string;
  files?: VectorcastCoverageEntry[];
  findings?: VectorcastFinding[];
}

const coverageObjectiveLinks = ['A-5-08', 'A-5-09', 'A-5-10'];
const findingObjectiveLinks = ['A-5-06', 'A-5-11'];

const normalizeSeverity = (value: string | undefined): Finding['severity'] => {
  if (!value) {
    return undefined;
  }
  const normalized = value.trim().toLowerCase();
  if (normalized === 'info') {
    return 'info';
  }
  if (normalized === 'warn' || normalized === 'warning') {
    return 'warn';
  }
  if (normalized === 'error' || normalized === 'critical') {
    return 'error';
  }
  return undefined;
};

const toFinding = (entry: VectorcastFinding): Finding | null => {
  if (!entry.id) {
    return null;
  }
  return {
    tool: 'vectorcast',
    id: String(entry.id),
    file: entry.file,
    func: entry.func,
    line: typeof entry.line === 'number' ? entry.line : undefined,
    severity: normalizeSeverity(entry.sev),
    message: entry.msg ?? '',
    objectiveLinks: [...findingObjectiveLinks],
  };
};

const toCoverageMetric = (metric: VectorcastCoverageMetric | undefined) => {
  if (!metric) {
    return undefined;
  }
  const covered = Number(metric.covered ?? 0);
  const total = Number(metric.total ?? 0);
  if (Number.isNaN(covered) || Number.isNaN(total)) {
    return undefined;
  }
  return { covered, total };
};

const toCoverage = (entries: VectorcastCoverageEntry[] | undefined): CoverageSummary | undefined => {
  if (!entries || entries.length === 0) {
    return undefined;
  }

  const files = entries
    .map((entry) => {
      if (!entry.path || !entry.stmt) {
        return undefined;
      }
      const stmt = toCoverageMetric(entry.stmt);
      if (!stmt) {
        return undefined;
      }
      const dec = toCoverageMetric(entry.dec);
      const mcdc = toCoverageMetric(entry.mcdc);
      const fileEntry: CoverageSummary['files'][number] = {
        path: entry.path,
        stmt,
        ...(dec && dec.total > 0 ? { dec } : {}),
        ...(mcdc && mcdc.total > 0 ? { mcdc } : {}),
      };
      return fileEntry;
    })
    .filter((item): item is CoverageSummary['files'][number] => item !== undefined);

  if (files.length === 0) {
    return undefined;
  }

  return {
    tool: 'vectorcast',
    files,
    objectiveLinks: [...coverageObjectiveLinks],
  };
};

export const fromVectorCAST = async (filePath: string): Promise<ParseResult<ImportedBundle>> => {
  const warnings: string[] = [];
  const absolutePath = path.resolve(filePath);
  const content = await fs.readFile(absolutePath, 'utf8');

  let raw: VectorcastReport;
  try {
    raw = JSON.parse(content) as VectorcastReport;
  } catch (error) {
    throw new Error(`VectorCAST raporu JSON parse edilemedi (${absolutePath}): ${(error as Error).message}`);
  }

  const findings: Finding[] = [];
  const rawFindings = Array.isArray(raw.findings) ? raw.findings : [];
  rawFindings.forEach((entry, index) => {
    const finding = toFinding(entry);
    if (!finding) {
      warnings.push(`VectorCAST bulgusu #${index + 1} yok sayıldı: kimlik alanı eksik.`);
      return;
    }
    if (!finding.message) {
      warnings.push(`VectorCAST bulgusu ${finding.id} boş mesaj içeriyor.`);
    }
    findings.push(finding);
  });

  const coverage = toCoverage(raw.files);

  return {
    data: {
      findings,
      coverage,
    },
    warnings,
  };
};
