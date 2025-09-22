import { promises as fs } from 'fs';
import path from 'path';

import type { Finding, ImportedBundle, ParseResult } from './types';

interface PolyspaceFinding {
  id?: string;
  file?: string;
  func?: string;
  line?: number;
  class?: string;
  severity?: string;
  status?: string;
  message?: string;
}

interface PolyspaceReport {
  project?: string;
  results?: PolyspaceFinding[];
}

const defaultObjectiveLinks = ['A-5-05', 'A-5-14'];

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

const normalizeStatus = (value: string | undefined): Finding['status'] => {
  if (!value) {
    return undefined;
  }
  const normalized = value.trim().toLowerCase();
  if (normalized === 'proved' || normalized === 'unproved' || normalized === 'justified') {
    return normalized as Finding['status'];
  }
  return undefined;
};

const toFinding = (entry: PolyspaceFinding): Finding | null => {
  if (!entry.id) {
    return null;
  }

  return {
    tool: 'polyspace',
    id: String(entry.id),
    file: entry.file,
    func: entry.func,
    line: typeof entry.line === 'number' ? entry.line : undefined,
    classification: entry.class,
    severity: normalizeSeverity(entry.severity),
    status: normalizeStatus(entry.status),
    message: entry.message ?? '',
    objectiveLinks: [...defaultObjectiveLinks],
  };
};

export const fromPolyspace = async (filePath: string): Promise<ParseResult<ImportedBundle>> => {
  const warnings: string[] = [];
  const absolutePath = path.resolve(filePath);
  const content = await fs.readFile(absolutePath, 'utf8');

  let raw: PolyspaceReport;
  try {
    raw = JSON.parse(content) as PolyspaceReport;
  } catch (error) {
    throw new Error(`Polyspace raporu JSON parse edilemedi (${absolutePath}): ${(error as Error).message}`);
  }

  const findings: Finding[] = [];
  const entries = Array.isArray(raw.results) ? raw.results : [];
  entries.forEach((entry, index) => {
    const finding = toFinding(entry);
    if (!finding) {
      warnings.push(`Polyspace sonucu #${index + 1} yok sayıldı: geçerli bir kimlik bulunamadı.`);
      return;
    }
    if (!finding.message) {
      warnings.push(`Polyspace sonucu ${finding.id} boş mesaj içeriyor.`);
    }
    findings.push(finding);
  });

  return {
    data: {
      findings,
    },
    warnings,
  };
};
