import { promises as fs } from 'fs';
import path from 'path';

import type { TraceLinkType } from '@soipack/core';

import type { ParseResult, RemoteRequirementRecord, RemoteTraceLink } from './types';
import { parseCsv } from './utils/csv';

export interface DoorsClassicImportBundle {
  requirements: RemoteRequirementRecord[];
  traces: RemoteTraceLink[];
}

type HeaderKey =
  | 'absoluteNumber'
  | 'identifier'
  | 'heading'
  | 'text'
  | 'shortText'
  | 'status'
  | 'type'
  | 'level'
  | 'links';

const HEADER_CANDIDATES: Record<HeaderKey, readonly string[]> = {
  absoluteNumber: ['Absolute Number', 'AbsoluteNumber'],
  identifier: ['Object Identifier', 'Object ID', 'ID', 'Identifier'],
  heading: ['Object Heading', 'Heading', 'Title'],
  text: ['Object Text', 'Description', 'Body', 'Object Body'],
  shortText: ['Object Short Text', 'Short Text', 'Summary'],
  status: ['Object Status', 'Status'],
  type: ['Object Type', 'Type'],
  level: ['Object Level', 'Level', 'Hierarchy Level'],
  links: ['Outgoing Links', 'Links', 'Link Targets', 'Object Links'],
};

const sanitizeRow = (row: string[], expectedLength: number): string[] => {
  if (row.length >= expectedLength) {
    return row;
  }
  return [...row, ...new Array(expectedLength - row.length).fill('')];
};

const normalizeHeader = (value: string): string => value.trim().toLowerCase();

const resolveHeaderIndexes = (headers: string[]): Partial<Record<HeaderKey, number>> => {
  const mapping: Partial<Record<HeaderKey, number>> = {};
  (Object.keys(HEADER_CANDIDATES) as HeaderKey[]).forEach((key) => {
    const candidates = HEADER_CANDIDATES[key];
    const index = headers.findIndex((header) =>
      candidates.some((candidate) => normalizeHeader(candidate) === normalizeHeader(header)),
    );
    if (index >= 0) {
      mapping[key] = index;
    }
  });
  return mapping;
};

const readFileWithEncoding = async (filePath: string): Promise<string> => {
  const buffer = await fs.readFile(filePath);
  if (buffer.length === 0) {
    return '';
  }
  const utf8 = buffer.toString('utf8');
  const reconverted = Buffer.from(utf8, 'utf8');
  if (reconverted.length === buffer.length && reconverted.equals(buffer)) {
    return utf8.replace(/^\uFEFF/, '');
  }
  return buffer.toString('latin1').replace(/^\uFEFF/, '');
};

const normalizeWhitespace = (value: string | undefined): string | undefined => {
  if (!value) {
    return undefined;
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return undefined;
  }
  return trimmed.replace(/\s+/g, ' ');
};

const normalizeIdentifier = (value: string | undefined): string | undefined => {
  const normalized = normalizeWhitespace(value);
  if (!normalized) {
    return undefined;
  }
  return normalized;
};

const selectTitle = (
  heading: string | undefined,
  shortText: string | undefined,
  text: string | undefined,
  fallback: string,
): string => {
  return heading ?? shortText ?? text ?? fallback;
};

const parentAbsoluteNumber = (absoluteNumber: string | undefined): string | undefined => {
  if (!absoluteNumber) {
    return undefined;
  }
  const trimmed = absoluteNumber.trim();
  const separatorIndex = trimmed.lastIndexOf('.');
  if (separatorIndex === -1) {
    return undefined;
  }
  return trimmed.slice(0, separatorIndex);
};

const mapLinkType = (value: string | undefined): TraceLinkType => {
  const normalized = value?.trim().toLowerCase() ?? '';
  if (/(verif|test|validation)/u.test(normalized)) {
    return 'verifies';
  }
  if (/(implement|design|code|realization)/u.test(normalized)) {
    return 'implements';
  }
  return 'satisfies';
};

const parseLinkTargets = (value: string | undefined, sourceId: string): RemoteTraceLink[] => {
  if (!value) {
    return [];
  }

  return value
    .split(/[\r\n;,]+/u)
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0)
    .map((entry) => {
      const arrowSplit = entry.split(/->|=>/u);
      const targetCandidate = arrowSplit[arrowSplit.length - 1]?.trim() ?? '';
      const match = targetCandidate.match(/^(?<id>[^()]+?)(?:\s*\((?<type>[^)]+)\))?$/u);
      if (!match || !match.groups) {
        return undefined;
      }
      const targetId = normalizeIdentifier(match.groups.id);
      if (!targetId) {
        return undefined;
      }
      const linkType = mapLinkType(match.groups.type);
      return { fromId: sourceId, toId: targetId, type: linkType } satisfies RemoteTraceLink;
    })
    .filter((link): link is RemoteTraceLink => Boolean(link));
};

export const importDoorsClassicCsv = async (
  filePath: string,
): Promise<ParseResult<DoorsClassicImportBundle>> => {
  const warnings: string[] = [];
  const location = path.resolve(filePath);
  const content = await readFileWithEncoding(location);
  const rows = parseCsv(content).filter((row) => row.some((cell) => cell.trim().length > 0));

  if (rows.length === 0) {
    warnings.push(`No data rows found while parsing DOORS Classic CSV at ${location}.`);
    return { data: { requirements: [], traces: [] }, warnings };
  }

  const headerRow = rows.shift() ?? [];
  const headerIndexes = resolveHeaderIndexes(headerRow);

  if (headerIndexes.identifier === undefined) {
    warnings.push('CSV file is missing the Object Identifier column.');
  }
  if (headerIndexes.heading === undefined && headerIndexes.shortText === undefined && headerIndexes.text === undefined) {
    warnings.push('CSV file is missing a heading, short text, or text column.');
  }

  const expectedLength = headerRow.length;
  const bundle: DoorsClassicImportBundle = { requirements: [], traces: [] };
  const absoluteNumberToId = new Map<string, string>();
  const seenRequirementIds = new Set<string>();

  rows.forEach((row, rowIndex) => {
    const normalizedRow = sanitizeRow(row, expectedLength);
    const rawId = headerIndexes.identifier !== undefined ? normalizedRow[headerIndexes.identifier] : '';
    const identifier = normalizeIdentifier(rawId);

    if (!identifier) {
      warnings.push(`Row ${rowIndex + 2} is missing an Object Identifier and was skipped.`);
      return;
    }

    if (seenRequirementIds.has(identifier)) {
      warnings.push(`Duplicate requirement identifier "${identifier}" encountered at row ${rowIndex + 2}.`);
      return;
    }
    seenRequirementIds.add(identifier);

    const absoluteNumber = headerIndexes.absoluteNumber !== undefined
      ? normalizeWhitespace(normalizedRow[headerIndexes.absoluteNumber])
      : undefined;
    const heading = headerIndexes.heading !== undefined ? normalizeWhitespace(normalizedRow[headerIndexes.heading]) : undefined;
    const shortText = headerIndexes.shortText !== undefined ? normalizeWhitespace(normalizedRow[headerIndexes.shortText]) : undefined;
    const text = headerIndexes.text !== undefined ? normalizeWhitespace(normalizedRow[headerIndexes.text]) : undefined;
    const status = headerIndexes.status !== undefined ? normalizeWhitespace(normalizedRow[headerIndexes.status]) : undefined;
    const type = headerIndexes.type !== undefined ? normalizeWhitespace(normalizedRow[headerIndexes.type]) : undefined;
    const linksRaw = headerIndexes.links !== undefined ? normalizedRow[headerIndexes.links] : undefined;

    const requirement: RemoteRequirementRecord = {
      id: identifier,
      title: selectTitle(heading, shortText, text, identifier),
      description: text ?? shortText ?? undefined,
      status: status ?? undefined,
      type: type ?? undefined,
    };

    bundle.requirements.push(requirement);

    if (absoluteNumber) {
      absoluteNumberToId.set(absoluteNumber, identifier);
      const parentNumber = parentAbsoluteNumber(absoluteNumber);
      if (parentNumber) {
        const parentId = absoluteNumberToId.get(parentNumber);
        if (parentId) {
          bundle.traces.push({ fromId: identifier, toId: parentId, type: 'satisfies' });
        } else {
          warnings.push(
            `Row ${rowIndex + 2} references parent absolute number ${parentNumber}, but it was not found.`,
          );
        }
      }
    }

    const externalLinks = parseLinkTargets(linksRaw, identifier);
    if (externalLinks.length > 0) {
      bundle.traces.push(...externalLinks);
    }
  });

  return { data: bundle, warnings };
};
