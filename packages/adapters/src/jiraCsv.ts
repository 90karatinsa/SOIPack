import { promises as fs } from 'fs';
import path from 'path';

import { JiraRequirement, ParseResult } from './types';
import { parseCsv } from './utils/csv';

const HEADER_CANDIDATES = {
  id: ['Issue key', 'Key', 'ID'],
  summary: ['Summary', 'Title'],
  status: ['Status', 'State'],
  issueType: ['Issue Type', 'Type'],
  priority: ['Priority'],
  links: ['Issue Links', 'Linked Issues'],
  components: ['Component/s', 'Components'],
  labels: ['Labels'],
  epicLink: ['Epic Link'],
  description: ['Description'],
  attachments: ['Attachment', 'Attachments'],
  parent: ['Parent', 'Parent ID', 'Parent Key'],
} as const;

type HeaderKey = keyof typeof HEADER_CANDIDATES;

const normalizeHeaderName = (value: string): string => value.trim().toLowerCase();

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

const splitList = (value: string | undefined, pattern = /[,;]+/): string[] => {
  if (!value) {
    return [];
  }
  return value
    .split(pattern)
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
};

const splitAttachments = (value: string | undefined): string[] => splitList(value, /[\r\n;,]+/);

const resolveHeaderIndexes = (headers: string[]): Partial<Record<HeaderKey, number>> => {
  const mapping: Partial<Record<HeaderKey, number>> = {};

  (Object.keys(HEADER_CANDIDATES) as HeaderKey[]).forEach((key) => {
    const candidates = HEADER_CANDIDATES[key] as readonly string[];
    const index = headers.findIndex((header) =>
      (candidates as readonly string[]).some(
        (candidate) => normalizeHeaderName(candidate) === normalizeHeaderName(header),
      ),
    );
    if (index >= 0) {
      mapping[key] = index;
    }
  });

  return mapping;
};

interface ResolvedCustomField {
  name: string;
  index: number;
}

const resolveCustomFieldIndexes = (
  headers: string[],
  mappings: Record<string, string | string[]> | undefined,
): { fields: ResolvedCustomField[]; warnings: string[] } => {
  if (!mappings) {
    return { fields: [], warnings: [] };
  }

  const normalizedHeaders = headers.map((header) => normalizeHeaderName(header));
  const fields: ResolvedCustomField[] = [];
  const warnings: string[] = [];

  Object.entries(mappings).forEach(([fieldName, mapping]) => {
    const candidates = Array.isArray(mapping) ? mapping : [mapping];
    const normalizedCandidates = candidates
      .map((candidate) => normalizeHeaderName(candidate))
      .filter((candidate) => candidate.length > 0);
    const index = normalizedHeaders.findIndex((header) => normalizedCandidates.includes(header));

    if (index >= 0) {
      fields.push({ name: fieldName, index });
      return;
    }

    warnings.push(
      `Custom field "${fieldName}" did not match any headers (tried: ${candidates
        .map((candidate) => `"${candidate}"`)
        .join(', ')}).`,
    );
  });

  return { fields, warnings };
};

const sanitizeRow = (row: string[], expectedLength: number): string[] => {
  if (row.length >= expectedLength) {
    return row;
  }
  return [...row, ...new Array(expectedLength - row.length).fill('')];
};

export interface JiraCsvOptions {
  customFieldMappings?: Record<string, string | string[]>;
}

export const importJiraCsv = async (
  filePath: string,
  options: JiraCsvOptions = {},
): Promise<ParseResult<JiraRequirement[]>> => {
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
  const { fields: customFieldIndexes, warnings: customFieldWarnings } = resolveCustomFieldIndexes(
    headerRow,
    options.customFieldMappings,
  );
  warnings.push(...customFieldWarnings);

  if (headerIndexes.id === undefined || headerIndexes.summary === undefined || headerIndexes.status === undefined) {
    warnings.push('CSV file is missing one of the required columns: id, summary, status.');
  }

  const expectedLength = headerRow.length;
  const requirements: JiraRequirement[] = [];
  const parentReferences: Array<{ childId: string; parentId: string }> = [];

  rows.forEach((row, rowIndex) => {
    const normalizedRow = sanitizeRow(row, expectedLength);
    const id = normalizeValue(headerIndexes.id !== undefined ? normalizedRow[headerIndexes.id] : undefined);
    const summary = normalizeValue(
      headerIndexes.summary !== undefined ? normalizedRow[headerIndexes.summary] : undefined,
    );
    const status = normalizeValue(headerIndexes.status !== undefined ? normalizedRow[headerIndexes.status] : undefined);
    const issueType = normalizeValue(
      headerIndexes.issueType !== undefined ? normalizedRow[headerIndexes.issueType] : undefined,
    );
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
    const description = normalizeValue(
      headerIndexes.description !== undefined ? normalizedRow[headerIndexes.description] : undefined,
    );
    const components =
      headerIndexes.components !== undefined ? splitList(normalizedRow[headerIndexes.components]) : [];
    const labels = headerIndexes.labels !== undefined ? splitList(normalizedRow[headerIndexes.labels]) : [];
    const epicLink = normalizeValue(
      headerIndexes.epicLink !== undefined ? normalizedRow[headerIndexes.epicLink] : undefined,
    );
    const attachments =
      headerIndexes.attachments !== undefined ? splitAttachments(normalizedRow[headerIndexes.attachments]) : [];
    const parentId = normalizeValue(
      headerIndexes.parent !== undefined ? normalizedRow[headerIndexes.parent] : undefined,
    );

    const customFields: Record<string, string | string[] | undefined> = {};
    customFieldIndexes.forEach(({ name, index }) => {
      const value = normalizeValue(normalizedRow[index]);
      if (value) {
        customFields[name] = value;
      }
    });

    const requirement: JiraRequirement = {
      id,
      summary,
      status,
      priority: priority || undefined,
      links,
    };

    if (issueType) {
      requirement.issueType = issueType;
    }

    if (description) {
      requirement.description = description;
    }
    if (components.length > 0) {
      requirement.components = components;
    }
    if (labels.length > 0) {
      requirement.labels = labels;
    }
    if (epicLink) {
      requirement.epicLink = epicLink;
    }
    if (attachments.length > 0) {
      requirement.attachments = attachments;
    }
    if (parentId) {
      requirement.parentId = parentId;
      parentReferences.push({ childId: id, parentId });
    }
    if (Object.keys(customFields).length > 0) {
      requirement.customFields = customFields;
    }

    requirements.push(requirement);
  });

  if (parentReferences.length > 0) {
    const requirementIndex = new Map<string, JiraRequirement>();
    requirements.forEach((requirement) => {
      requirementIndex.set(requirement.id, requirement);
    });

    parentReferences.forEach(({ childId, parentId }) => {
      const parent = requirementIndex.get(parentId);
      if (!parent) {
        warnings.push(`Parent issue ${parentId} referenced by ${childId} was not found in the CSV.`);
        return;
      }

      if (!parent.children) {
        parent.children = [];
      }

      if (!parent.children.includes(childId)) {
        parent.children.push(childId);
      }
    });
  }

  return { data: requirements, warnings };
};
