import { promises as fs } from 'fs';
import path from 'path';

import { JiraRequirement, ParseResult } from './types';
import { parseCsv } from './utils/csv';

const HEADER_CANDIDATES = {
  id: ['Issue key', 'Key', 'ID'],
  summary: ['Summary', 'Title'],
  status: ['Status', 'State'],
  priority: ['Priority'],
  links: ['Issue Links', 'Linked Issues'],
} as const;

type HeaderKey = keyof typeof HEADER_CANDIDATES;

const normalizeValue = (value: string | undefined): string => value?.trim() ?? '';

const splitLinks = (value: string | undefined): string[] => {
  if (!value) {
    return [];
  }
  return value
    .split(/[,;\s]+/)
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
};

const resolveHeaderIndexes = (headers: string[]): Partial<Record<HeaderKey, number>> => {
  const mapping: Partial<Record<HeaderKey, number>> = {};

  (Object.keys(HEADER_CANDIDATES) as HeaderKey[]).forEach((key) => {
    const candidates = HEADER_CANDIDATES[key] as readonly string[];
    const index = headers.findIndex((header) =>
      (candidates as readonly string[]).some(
        (candidate) => candidate.toLowerCase() === header.trim().toLowerCase(),
      ),
    );
    if (index >= 0) {
      mapping[key] = index;
    }
  });

  return mapping;
};

const sanitizeRow = (row: string[], expectedLength: number): string[] => {
  if (row.length >= expectedLength) {
    return row;
  }
  return [...row, ...new Array(expectedLength - row.length).fill('')];
};

export const importJiraCsv = async (filePath: string): Promise<ParseResult<JiraRequirement[]>> => {
  const warnings: string[] = [];
  const location = path.resolve(filePath);
  const content = await fs.readFile(location, 'utf8');
  const rows = parseCsv(content).filter((row) => row.some((cell) => cell.trim().length > 0));

  if (rows.length === 0) {
    warnings.push(`No data rows found while parsing Jira CSV at ${location}.`);
    return { data: [], warnings };
  }

  const headerRow = rows.shift() ?? [];
  const headerIndexes = resolveHeaderIndexes(headerRow);

  if (headerIndexes.id === undefined || headerIndexes.summary === undefined || headerIndexes.status === undefined) {
    warnings.push('CSV file is missing one of the required columns: id, summary, status.');
  }

  const expectedLength = headerRow.length;
  const requirements: JiraRequirement[] = [];

  rows.forEach((row, rowIndex) => {
    const normalizedRow = sanitizeRow(row, expectedLength);
    const id = normalizeValue(headerIndexes.id !== undefined ? normalizedRow[headerIndexes.id] : undefined);
    const summary = normalizeValue(
      headerIndexes.summary !== undefined ? normalizedRow[headerIndexes.summary] : undefined,
    );
    const status = normalizeValue(headerIndexes.status !== undefined ? normalizedRow[headerIndexes.status] : undefined);
    if (!id) {
      warnings.push(`Row ${rowIndex + 2} is missing an id and was skipped.`);
      return;
    }
    if (!summary) {
      warnings.push(`Row ${rowIndex + 2} is missing a summary.`);
    }
    if (!status) {
      warnings.push(`Row ${rowIndex + 2} is missing a status.`);
    }

    const priority = normalizeValue(
      headerIndexes.priority !== undefined ? normalizedRow[headerIndexes.priority] : undefined,
    );
    const links = splitLinks(headerIndexes.links !== undefined ? normalizedRow[headerIndexes.links] : undefined);

    requirements.push({
      id,
      summary,
      status,
      priority: priority || undefined,
      links,
    });
  });

  return { data: requirements, warnings };
};
