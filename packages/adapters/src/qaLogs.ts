import { promises as fs } from 'fs';
import path from 'path';

import { ParseResult } from './types';
import { parseCsv } from './utils/csv';

const HEADER_CANDIDATES = {
  objectiveId: ['Objective', 'Objective ID', 'objective', 'objective_id'],
  artifact: ['Artifact', 'Artifact Type', 'Artifact Name'],
  reviewer: ['Reviewer', 'QA Reviewer', 'Auditor', 'Signed By'],
  status: ['Status', 'Decision', 'Result'],
  completedAt: ['Completed At', 'Completed On', 'Signed At', 'Date'],
  notes: ['Notes', 'Comments', 'Remarks'],
} as const;

type HeaderKey = keyof typeof HEADER_CANDIDATES;

export interface QaLogEntry {
  objectiveId: string;
  artifact?: string;
  reviewer?: string;
  status: string;
  completedAt?: string;
  notes?: string;
}

const normalizeHeader = (value: string): string => value.trim().toLowerCase();

const resolveHeaderIndexes = (headers: string[]): Partial<Record<HeaderKey, number>> => {
  const mapping: Partial<Record<HeaderKey, number>> = {};
  headers.forEach((header, index) => {
    const normalized = normalizeHeader(header);
    (Object.keys(HEADER_CANDIDATES) as HeaderKey[]).forEach((key) => {
      const candidates = HEADER_CANDIDATES[key];
      if (candidates.some((candidate) => normalizeHeader(candidate) === normalized)) {
        if (mapping[key] === undefined) {
          mapping[key] = index;
        }
      }
    });
  });
  return mapping;
};

const coerceValue = (value: string | undefined): string => (value ?? '').trim();

const normalizeRow = (row: string[], expectedLength: number): string[] => {
  if (row.length >= expectedLength) {
    return row;
  }
  return [...row, ...new Array(expectedLength - row.length).fill('')];
};

export const importQaLogs = async (filePath: string): Promise<ParseResult<QaLogEntry[]>> => {
  const warnings: string[] = [];
  const location = path.resolve(filePath);
  const content = await fs.readFile(location, 'utf8');
  const rows = parseCsv(content).filter((row) => row.some((cell) => cell.trim().length > 0));

  if (rows.length === 0) {
    warnings.push(`No QA records found while parsing ${location}.`);
    return { data: [], warnings };
  }

  const headerRow = rows.shift() ?? [];
  const headerIndexes = resolveHeaderIndexes(headerRow);

  if (headerIndexes.objectiveId === undefined) {
    warnings.push('CSV file is missing an Objective column.');
  }
  if (headerIndexes.status === undefined) {
    warnings.push('CSV file is missing a Status column.');
  }

  const expectedLength = headerRow.length;
  const entries: QaLogEntry[] = [];

  rows.forEach((row, rowIndex) => {
    const normalizedRow = normalizeRow(row, expectedLength);
    const objectiveId = coerceValue(
      headerIndexes.objectiveId !== undefined ? normalizedRow[headerIndexes.objectiveId] : undefined,
    );
    const status = coerceValue(
      headerIndexes.status !== undefined ? normalizedRow[headerIndexes.status] : undefined,
    );

    if (!objectiveId) {
      warnings.push(`Row ${rowIndex + 2} is missing an objective id and was skipped.`);
      return;
    }

    if (!status) {
      warnings.push(`Row ${rowIndex + 2} is missing a status.`);
    }

    const entry: QaLogEntry = { objectiveId, status };

    const artifact = coerceValue(
      headerIndexes.artifact !== undefined ? normalizedRow[headerIndexes.artifact] : undefined,
    );
    if (artifact) {
      entry.artifact = artifact;
    }

    const reviewer = coerceValue(
      headerIndexes.reviewer !== undefined ? normalizedRow[headerIndexes.reviewer] : undefined,
    );
    if (reviewer) {
      entry.reviewer = reviewer;
    }

    const completedAt = coerceValue(
      headerIndexes.completedAt !== undefined ? normalizedRow[headerIndexes.completedAt] : undefined,
    );
    if (completedAt) {
      entry.completedAt = completedAt;
    }

    const notes = coerceValue(
      headerIndexes.notes !== undefined ? normalizedRow[headerIndexes.notes] : undefined,
    );
    if (notes) {
      entry.notes = notes;
    }

    entries.push(entry);
  });

  return { data: entries, warnings };
};
