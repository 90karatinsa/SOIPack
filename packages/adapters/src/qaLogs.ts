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

export type QaLogStatus = 'approved' | 'pending' | 'rejected';

export interface QaLogEntry {
  objectiveId: string;
  artifact?: string;
  reviewer?: string;
  status: QaLogStatus;
  completedAt?: string;
  notes?: string;
}

const stripDiacritics = (value: string): string => value.normalize('NFKD').replace(/[\u0300-\u036f]/g, '');

const normalizeStatusToken = (value: string): string =>
  stripDiacritics(value)
    .replace(/[_-]/g, ' ')
    .replace(/[.,;:]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();

const STATUS_ALIASES: Record<QaLogStatus, string[]> = {
  approved: ['approved', 'approve', 'approved.', 'accepted', 'pass', 'passed', 'compliant', 'onaylandi', 'onaylanmis'],
  pending: [
    'pending',
    'in review',
    'under review',
    'awaiting',
    'open',
    'beklemede',
    'bekliyor',
    'gozden gecirme',
    'taslak',
  ],
  rejected: ['rejected', 'reject', 'declined', 'failed', 'fail', 'red', 'reddedildi', 'uygunsuz', 'olumsuz'],
};

const normalizeStatus = (value: string): QaLogStatus | undefined => {
  const token = normalizeStatusToken(value);
  if (!token) {
    return undefined;
  }
  for (const [status, aliases] of Object.entries(STATUS_ALIASES) as Array<[QaLogStatus, string[]]>) {
    if (aliases.includes(token)) {
      return status;
    }
  }
  return undefined;
};

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

    let canonicalStatus: QaLogStatus = 'pending';
    if (!status) {
      warnings.push(`Row ${rowIndex + 2} is missing a status.`);
    } else {
      const normalizedStatus = normalizeStatus(status);
      if (normalizedStatus) {
        canonicalStatus = normalizedStatus;
      } else {
        warnings.push(
          `Row ${rowIndex + 2} has unknown status "${status}"; defaulting to "pending". Accepted values: approved/pending/rejected.`,
        );
      }
    }

    const entry: QaLogEntry = { objectiveId, status: canonicalStatus };

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
