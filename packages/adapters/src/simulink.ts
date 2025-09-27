import { promises as fs } from 'fs';
import path from 'path';

import type { CoverageSummary, ImportedBundle, ParseResult } from './types';

interface SimulinkMetric {
  covered?: number | string | null;
  total?: number | string | null;
}

interface SimulinkMetricsBlock {
  statements?: SimulinkMetric;
  execution?: SimulinkMetric;
  decision?: SimulinkMetric;
  condition?: SimulinkMetric;
  mcdc?: SimulinkMetric;
}

interface SimulinkArtifactEntry {
  id?: string;
  name?: string;
  path?: string;
  file?: string;
  metrics?: SimulinkMetricsBlock | null;
}

interface SimulinkReport {
  artifacts?: SimulinkArtifactEntry[] | null;
  files?: SimulinkArtifactEntry[] | null;
  warnings?: unknown;
  model?: string;
}

const objectiveLinks = ['A-5-08', 'A-5-09', 'A-5-10'];

const toNumber = (value: unknown): number | undefined => {
  if (typeof value === 'number') {
    return Number.isFinite(value) ? value : undefined;
  }
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) {
      return undefined;
    }
    const parsed = Number(trimmed);
    return Number.isFinite(parsed) ? parsed : undefined;
  }
  return undefined;
};

const normalizeMetric = (
  metric: SimulinkMetric | undefined | null,
  context: string,
  field: string,
  warnings: string[],
): { covered: number; total: number } | undefined => {
  if (!metric) {
    return undefined;
  }
  const covered = toNumber(metric.covered);
  const total = toNumber(metric.total);
  if (covered === undefined || total === undefined) {
    warnings.push(
      `Simulink kapsam metrikleri ${context} için okunamadı (${field} alanı sayısal değil).`,
    );
    return undefined;
  }
  if (covered < 0 || total < 0) {
    warnings.push(
      `Simulink kapsam metrikleri ${context} için negatif değer içeriyor (${field}).`,
    );
    return undefined;
  }
  return { covered, total };
};

const extractArtifacts = (report: SimulinkReport): SimulinkArtifactEntry[] => {
  if (Array.isArray(report.artifacts) && report.artifacts.length > 0) {
    return report.artifacts;
  }
  if (Array.isArray(report.files) && report.files.length > 0) {
    return report.files;
  }
  return [];
};

const selectPath = (entry: SimulinkArtifactEntry): string | undefined => {
  const candidates = [entry.path, entry.file, entry.name, entry.id];
  const chosen = candidates.find((value) => typeof value === 'string' && value.trim().length > 0);
  return chosen ? chosen.trim() : undefined;
};

const buildCoverage = (
  entries: SimulinkArtifactEntry[],
  warnings: string[],
): CoverageSummary | undefined => {
  const files: CoverageSummary['files'] = [];

  entries.forEach((entry, index) => {
    const pathValue = selectPath(entry);
    if (!pathValue) {
      warnings.push(`Simulink kapsam kaydı #${index + 1} yok sayıldı: yol bilgisi eksik.`);
      return;
    }

    const context = `'${pathValue}'`;
    const metrics = entry.metrics ?? undefined;
    const stmt = normalizeMetric(metrics?.statements ?? metrics?.execution, context, 'statements', warnings);
    if (!stmt) {
      warnings.push(`Simulink kapsam kaydı ${context} atlandı: ifade kapsamı eksik.`);
      return;
    }

    const decisionMetric = metrics?.decision ?? metrics?.condition;
    const dec = normalizeMetric(decisionMetric, context, 'decision', warnings);
    const mcdc = normalizeMetric(metrics?.mcdc, context, 'mcdc', warnings);

    const fileEntry: CoverageSummary['files'][number] = {
      path: pathValue,
      stmt,
      ...(dec && dec.total > 0 ? { dec } : {}),
      ...(mcdc && mcdc.total > 0 ? { mcdc } : {}),
    };
    files.push(fileEntry);
  });

  if (files.length === 0) {
    return undefined;
  }

  return {
    tool: 'simulink',
    files,
    objectiveLinks: [...objectiveLinks],
  };
};

const extractWarnings = (raw: unknown): string[] => {
  if (!raw) {
    return [];
  }
  if (Array.isArray(raw)) {
    return raw
      .map((entry) => {
        if (typeof entry === 'string') {
          return entry;
        }
        if (entry && typeof entry === 'object') {
          return JSON.stringify(entry);
        }
        return String(entry);
      })
      .filter((item) => item.trim().length > 0);
  }
  if (typeof raw === 'string') {
    return raw.trim() ? [raw] : [];
  }
  return [JSON.stringify(raw)];
};

export const fromSimulink = async (filePath: string): Promise<ParseResult<ImportedBundle>> => {
  const absolutePath = path.resolve(filePath);
  const warnings: string[] = [];
  const content = await fs.readFile(absolutePath, 'utf8');

  let report: SimulinkReport;
  try {
    report = JSON.parse(content) as SimulinkReport;
  } catch (error) {
    throw new Error(
      `Simulink kapsam raporu JSON olarak okunamadı (${absolutePath}): ${(error as Error).message}`,
    );
  }

  const coverage = buildCoverage(extractArtifacts(report), warnings);
  const externalWarnings = extractWarnings(report.warnings);
  warnings.push(...externalWarnings);

  return {
    data: {
      coverage,
    },
    warnings,
  };
};
