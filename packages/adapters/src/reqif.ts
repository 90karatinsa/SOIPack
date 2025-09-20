import { promises as fs } from 'fs';
import path from 'path';

import { ParseResult, ReqIFRequirement } from './types';
import { parseXml } from './utils/xml';

type UnknownRecord = Record<string, unknown>;

const toArray = <T>(value: T | T[] | undefined): T[] => {
  if (value === undefined) {
    return [];
  }
  return Array.isArray(value) ? value : [value];
};

const flatten = (value: unknown): string => {
  if (value === null || value === undefined) {
    return '';
  }
  if (typeof value === 'string') {
    return value;
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => flatten(item)).join(' ');
  }
  if (typeof value === 'object') {
    return Object.values(value as UnknownRecord)
      .map((item) => flatten(item))
      .join(' ');
  }
  return '';
};

const extractRequirementText = (specObject: UnknownRecord): string => {
  const values = specObject.VALUES as UnknownRecord | undefined;
  if (!values) {
    return '';
  }

  const possibleKeys = Object.keys(values);
  for (const key of possibleKeys) {
    const entries = toArray((values as UnknownRecord)[key] as UnknownRecord | UnknownRecord[] | undefined);
    for (const entry of entries) {
      const value = flatten((entry as UnknownRecord)['THE-VALUE']);
      if (value.trim().length > 0) {
        return value.trim();
      }
    }
  }

  return '';
};

export const importReqIF = async (filePath: string): Promise<ParseResult<ReqIFRequirement[]>> => {
  const warnings: string[] = [];
  const location = path.resolve(filePath);
  const content = await fs.readFile(location, 'utf8');

  let raw: UnknownRecord;
  try {
    raw = parseXml<UnknownRecord>(content);
  } catch (error) {
    warnings.push(`Failed to parse ReqIF XML at ${location}: ${(error as Error).message}`);
    return { data: [], warnings };
  }

  const root = (raw['REQ-IF'] ?? raw) as UnknownRecord;
  const coreContent = root['CORE-CONTENT'] as UnknownRecord | undefined;
  const specObjectsContainer = coreContent?.['SPEC-OBJECTS'] as UnknownRecord | undefined;
  const specObjects = toArray(specObjectsContainer?.['SPEC-OBJECT'] as UnknownRecord | UnknownRecord[] | undefined);

  if (specObjects.length === 0) {
    warnings.push(`No SPEC-OBJECT entries found in ReqIF file at ${location}.`);
    return { data: [], warnings };
  }

  const requirements: ReqIFRequirement[] = specObjects.map((specObject, index) => {
    const identifier = ((specObject as UnknownRecord).IDENTIFIER as string | undefined) ?? `item-${index + 1}`;
    const text = extractRequirementText(specObject as UnknownRecord);
    if (!text) {
      warnings.push(`SPEC-OBJECT ${identifier} does not contain a THE-VALUE entry.`);
    }
    return {
      id: identifier,
      text,
    };
  });

  return { data: requirements, warnings };
};
