import { promises as fs } from 'fs';
import path from 'path';

import type { CoverageSummary, Finding, ImportedBundle, ParseResult } from './types';

interface LdraViolation {
  id?: string;
  file?: string;
  func?: string;
  line?: number;
  rule?: string;
  sev?: string;
  msg?: string;
}

interface LdraCoverageEntry {
  path?: string;
  stmt?: { covered?: number; total?: number };
  dec?: { covered?: number; total?: number };
  mcdc?: { covered?: number; total?: number };
}

interface LdraReport {
  project?: string;
  violations?: LdraViolation[];
  unit_tests?: { files?: LdraCoverageEntry[] };
}

const defaultObjectiveLinks = ['A-5-05', 'A-5-08', 'A-5-14'];

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

const toFinding = (entry: LdraViolation): Finding | null => {
  if (!entry.id) {
    return null;
  }
  return {
    tool: 'ldra',
    id: String(entry.id),
    file: entry.file,
    func: entry.func,
    line: typeof entry.line === 'number' ? entry.line : undefined,
    classification: entry.rule,
    severity: normalizeSeverity(entry.sev),
    message: entry.msg ?? '',
    objectiveLinks: [...defaultObjectiveLinks],
  };
};

const toCoverageMetric = (
  metric: LdraCoverageEntry['stmt'],
): { covered: number; total: number } | undefined => {
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

const toCoverage = (entries: LdraCoverageEntry[] | undefined): CoverageSummary | undefined => {
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
      return {
        path: entry.path,
        stmt,
        ...(dec && dec.total > 0 ? { dec } : {}),
        ...(mcdc && mcdc.total > 0 ? { mcdc } : {}),
      };
    })
    .filter((item): item is CoverageSummary['files'][number] => item !== undefined);

  if (files.length === 0) {
    return undefined;
  }

  return {
    tool: 'ldra',
    files,
    objectiveLinks: ['A-5-08'],
  };
};

export const fromLDRA = async (filePath: string): Promise<ParseResult<ImportedBundle>> => {
  const warnings: string[] = [];
  const absolutePath = path.resolve(filePath);
  const content = await fs.readFile(absolutePath, 'utf8');

  let raw: LdraReport;
  try {
    raw = JSON.parse(content) as LdraReport;
  } catch (error) {
    throw new Error(`LDRA TBvision raporu JSON parse edilemedi (${absolutePath}): ${(error as Error).message}`);
  }

  const findings: Finding[] = [];
  const violations = Array.isArray(raw.violations) ? raw.violations : [];
  violations.forEach((entry, index) => {
    const finding = toFinding(entry);
    if (!finding) {
      warnings.push(`LDRA ihlali #${index + 1} yok sayıldı: kimlik alanı eksik.`);
      return;
    }
    if (!finding.message) {
      warnings.push(`LDRA ihlali ${finding.id} boş mesaj içeriyor.`);
    }
    findings.push(finding);
  });

  const coverage = toCoverage(raw.unit_tests?.files);

  return {
    data: {
      findings,
      coverage,
    },
    warnings,
  };
};
