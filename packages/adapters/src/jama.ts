import { Requirement, type RequirementStatus } from '@soipack/core';

import type { ParseResult, TestResult, TestStatus } from './types';
import { HttpError, requestJson, type HttpRequestOptions } from './utils/http';

export interface JamaClientOptions {
  baseUrl: string;
  projectId: string | number;
  token: string;
  pageSize?: number;
  maxPages?: number;
  timeoutMs?: number;
  rateLimitDelaysMs?: number[];
  requirementsEndpoint?: string;
  testCasesEndpoint?: string;
  relationshipsEndpoint?: string;
}

export interface JamaTraceLink {
  requirementId: string;
  testCaseId: string;
  relationshipType?: string;
}

export interface JamaImportBundle {
  requirements: Requirement[];
  objectives: [];
  testResults: TestResult[];
  traceLinks: JamaTraceLink[];
  evidenceIndex: Record<string, never[]>;
  generatedAt: string;
}

interface JamaItemLocation {
  url?: string | null;
}

interface JamaItem {
  id: number | string;
  documentKey?: string | null;
  itemType?: { key?: string | null } | string | null;
  type?: { key?: string | null } | string | null;
  fields?: Record<string, unknown> | null;
  modifiedDate?: string | null;
  location?: JamaItemLocation | null;
}

interface JamaRelationshipEndpoint {
  id?: number | string | null;
  itemType?: { key?: string | null } | string | null;
}

interface JamaRelationshipRecord {
  id: number | string;
  relationshipType?: string | null;
  fromItem?: JamaRelationshipEndpoint | null;
  toItem?: JamaRelationshipEndpoint | null;
}

interface PaginatedResponse<T> {
  data?: T[] | null;
  meta?: { pageInfo?: { next?: string | null; hasMore?: boolean | null } | null } | null;
  links?: { next?: { href?: string | null } | string | null } | null;
}

const DEFAULT_PAGE_SIZE = 50;
const DEFAULT_MAX_PAGES = 100;
const DEFAULT_RATE_LIMIT_DELAYS_MS = [250, 500, 1000, 2000];

const defaultEndpoints = {
  requirements: '/rest/latest/projects/:projectId/items?itemType=REQUIREMENT',
  testCases: '/rest/latest/projects/:projectId/items?itemType=TEST_CASE',
  relationships: '/rest/latest/projects/:projectId/relationships',
} as const;

const sleep = async (ms: number): Promise<void> => {
  if (ms <= 0) {
    return;
  }
  await new Promise((resolve) => setTimeout(resolve, ms));
};

const parseRetryAfter = (error: HttpError): number | undefined => {
  const header = error.headers?.['retry-after'];
  if (!header) {
    return undefined;
  }

  const value = Array.isArray(header) ? header[0] : header;
  if (!value) {
    return undefined;
  }

  const seconds = Number.parseFloat(value);
  if (Number.isFinite(seconds) && seconds >= 0) {
    return seconds * 1000;
  }

  const absolute = Date.parse(value);
  if (!Number.isNaN(absolute)) {
    const delta = absolute - Date.now();
    return delta > 0 ? delta : undefined;
  }

  return undefined;
};

const requestWithBackoff = async <T>(
  options: HttpRequestOptions,
  rateLimitDelays: number[],
  attempt = 0,
): Promise<T> => {
  try {
    return await requestJson<T>(options);
  } catch (error) {
    if (error instanceof HttpError && error.statusCode === 429 && attempt < rateLimitDelays.length) {
      const retryDelay = parseRetryAfter(error) ?? rateLimitDelays[attempt];
      if (retryDelay > 0) {
        await sleep(retryDelay);
      }
      return requestWithBackoff(options, rateLimitDelays, attempt + 1);
    }
    throw error;
  }
};

const applyProjectTemplate = (template: string, projectId: string | number): string => {
  if (!template.includes(':projectId')) {
    return template;
  }
  return template.replace(/:projectId/gu, encodeURIComponent(String(projectId)));
};

const createEndpointUrl = (
  baseUrl: string,
  projectId: string | number,
  template: string,
  pageSize: number,
): URL => {
  const resolvedTemplate = applyProjectTemplate(template, projectId);
  const url = new URL(resolvedTemplate, baseUrl);
  if (!url.searchParams.has('pageSize')) {
    url.searchParams.set('pageSize', String(pageSize));
  }
  return url;
};

const extractNextCursor = (payload: PaginatedResponse<unknown>): string | undefined => {
  const next = payload.meta?.pageInfo?.next;
  if (next && typeof next === 'string' && next.trim().length > 0) {
    return next;
  }
  const link = payload.links?.next;
  if (typeof link === 'string' && link.trim().length > 0) {
    return link;
  }
  if (link && typeof link === 'object' && typeof link.href === 'string' && link.href.trim().length > 0) {
    return link.href;
  }
  return undefined;
};

const extractItems = <T>(payload: PaginatedResponse<T>): T[] => {
  if (!payload.data) {
    return [];
  }
  if (Array.isArray(payload.data)) {
    return payload.data as T[];
  }
  return [];
};

const fetchPaginated = async <T>(
  initialUrl: URL,
  headers: Record<string, string>,
  options: { timeoutMs?: number; rateLimitDelays: number[]; maxPages: number },
): Promise<T[]> => {
  const results: T[] = [];
  let currentUrl: URL | undefined = initialUrl;
  let pageCount = 0;

  while (currentUrl && pageCount < options.maxPages) {
    const payload = await requestWithBackoff<PaginatedResponse<T>>(
      { url: currentUrl, headers, timeoutMs: options.timeoutMs },
      options.rateLimitDelays,
    );

    results.push(...extractItems<T>(payload));
    const nextCursor = extractNextCursor(payload);
    if (!nextCursor) {
      break;
    }
    currentUrl = new URL(nextCursor, currentUrl);
    pageCount += 1;
  }

  return results;
};

const toRequirementStatus = (raw: unknown): RequirementStatus => {
  if (typeof raw !== 'string') {
    return 'draft';
  }
  const normalized = raw.trim().toLowerCase();
  if (normalized === 'approved') {
    return 'approved';
  }
  if (normalized === 'implemented') {
    return 'implemented';
  }
  if (normalized === 'verified') {
    return 'verified';
  }
  return 'draft';
};

const toTestStatus = (raw: unknown): TestStatus => {
  if (typeof raw !== 'string') {
    return 'skipped';
  }
  const normalized = raw.trim().toLowerCase();
  if (['pass', 'passed', 'success', 'successful'].includes(normalized)) {
    return 'passed';
  }
  if (['fail', 'failed', 'error'].includes(normalized)) {
    return 'failed';
  }
  if (['blocked', 'not run', 'pending'].includes(normalized)) {
    return 'skipped';
  }
  return 'skipped';
};

const htmlToText = (value: unknown): string | undefined => {
  if (typeof value !== 'string') {
    return undefined;
  }
  const stripped = value
    .replace(/<\s*br\s*\/?>/giu, '\n')
    .replace(/<[^>]+>/gu, ' ')
    .replace(/&nbsp;/gu, ' ')
    .replace(/\s+/gu, ' ')
    .trim();
  return stripped.length > 0 ? stripped : undefined;
};

const normalizeRequirement = (
  item: JamaItem,
  warnings: string[],
): { requirement: Requirement; rawId: string; url?: string } => {
  const fields = item.fields ?? {};
  const documentKey = typeof item.documentKey === 'string' && item.documentKey.trim().length > 0
    ? item.documentKey.trim()
    : undefined;
  const id = documentKey ?? String(item.id);
  const nameValue = fields.name ?? fields.title;
  const name = typeof nameValue === 'string' && nameValue.trim().length > 0 ? nameValue.trim() : undefined;
  if (!name) {
    warnings.push(`Requirement ${id} is missing a name.`);
  }
  const status = toRequirementStatus(fields.status);
  const tagsValue = fields.tags ?? fields.tag ?? fields.categories;
  const tags = Array.isArray(tagsValue)
    ? (tagsValue as unknown[])
        .map((tag) => (typeof tag === 'string' ? tag.trim() : ''))
        .filter((tag) => tag.length > 0)
    : [];
  const requirement: Requirement = {
    id,
    title: name ?? id,
    description: htmlToText(fields.description ?? fields.text ?? fields.notes),
    status,
    tags,
  };
  const url =
    typeof item.location?.url === 'string' && item.location?.url.trim().length > 0
      ? item.location.url.trim()
      : undefined;
  return { requirement, rawId: String(item.id), url };
};

const normalizeTestCase = (
  item: JamaItem,
  warnings: string[],
): { testResult: TestResult; rawId: string; url?: string } => {
  const fields = item.fields ?? {};
  const documentKey = typeof item.documentKey === 'string' && item.documentKey.trim().length > 0
    ? item.documentKey.trim()
    : undefined;
  const id = documentKey ?? String(item.id);
  const nameValue = fields.name ?? fields.title;
  const name = typeof nameValue === 'string' && nameValue.trim().length > 0 ? nameValue.trim() : undefined;
  if (!name) {
    warnings.push(`Test case ${id} is missing a name.`);
  }
  const durationValue = fields.executionTime ?? fields.duration ?? fields.durationMs;
  const duration = typeof durationValue === 'number' ? durationValue : 0;
  const status = toTestStatus(fields.status ?? fields.testStatus);
  const testResult: TestResult = {
    testId: id,
    className: 'jama',
    name: name ?? id,
    status,
    duration,
  };
  if (typeof fields.failureMessage === 'string' && fields.failureMessage.trim().length > 0) {
    testResult.errorMessage = fields.failureMessage.trim();
  }
  const url =
    typeof item.location?.url === 'string' && item.location?.url.trim().length > 0
      ? item.location.url.trim()
      : undefined;
  return { testResult, rawId: String(item.id), url };
};

const resolveEndpoint = (
  baseUrl: string,
  projectId: string | number,
  endpoint: string | undefined,
  fallback: keyof typeof defaultEndpoints,
  pageSize: number,
): URL => createEndpointUrl(baseUrl, projectId, endpoint ?? defaultEndpoints[fallback], pageSize);

export const fetchJamaArtifacts = async (
  options: JamaClientOptions,
): Promise<ParseResult<JamaImportBundle>> => {
  const warnings: string[] = [];
  const pageSize = Math.max(1, options.pageSize ?? DEFAULT_PAGE_SIZE);
  const maxPages = Math.max(1, options.maxPages ?? DEFAULT_MAX_PAGES);
  const rateLimitDelays = (options.rateLimitDelaysMs ?? DEFAULT_RATE_LIMIT_DELAYS_MS).map((delay) =>
    delay < 0 ? 0 : delay,
  );

  const headers: Record<string, string> = {
    Authorization: `Bearer ${options.token}`,
  };

  const requirementUrl = resolveEndpoint(
    options.baseUrl,
    options.projectId,
    options.requirementsEndpoint,
    'requirements',
    pageSize,
  );
  const requirementsRaw = await fetchPaginated<JamaItem>(requirementUrl, headers, {
    timeoutMs: options.timeoutMs,
    rateLimitDelays,
    maxPages,
  });

  const testCaseUrl = resolveEndpoint(
    options.baseUrl,
    options.projectId,
    options.testCasesEndpoint,
    'testCases',
    pageSize,
  );
  const testCasesRaw = await fetchPaginated<JamaItem>(testCaseUrl, headers, {
    timeoutMs: options.timeoutMs,
    rateLimitDelays,
    maxPages,
  });

  const relationshipsUrl = resolveEndpoint(
    options.baseUrl,
    options.projectId,
    options.relationshipsEndpoint,
    'relationships',
    pageSize,
  );
  const relationshipsRaw = await fetchPaginated<JamaRelationshipRecord>(relationshipsUrl, headers, {
    timeoutMs: options.timeoutMs,
    rateLimitDelays,
    maxPages,
  });

  const requirementMap = new Map<string, Requirement>();
  const requirementIdByRaw = new Map<string, string>();
  requirementsRaw.forEach((item) => {
    const { requirement, rawId } = normalizeRequirement(item, warnings);
    requirementMap.set(requirement.id, requirement);
    requirementIdByRaw.set(rawId, requirement.id);
  });

  const testResultMap = new Map<string, TestResult>();
  const testIdByRaw = new Map<string, string>();
  testCasesRaw.forEach((item) => {
    const { testResult, rawId } = normalizeTestCase(item, warnings);
    testResultMap.set(testResult.testId, testResult);
    testIdByRaw.set(rawId, testResult.testId);
  });

  const traceLinks: JamaTraceLink[] = [];
  const testRequirementRefs = new Map<string, Set<string>>();

  relationshipsRaw.forEach((relationship) => {
    const fromId = relationship.fromItem?.id;
    const toId = relationship.toItem?.id;
    if (fromId === null || fromId === undefined || toId === null || toId === undefined) {
      warnings.push('Encountered relationship with missing endpoint identifiers.');
      return;
    }
    const fromRaw = String(fromId);
    const toRaw = String(toId);
    const fromRequirement = requirementIdByRaw.get(fromRaw);
    const toRequirement = requirementIdByRaw.get(toRaw);
    const fromTest = testIdByRaw.get(fromRaw);
    const toTest = testIdByRaw.get(toRaw);

    if (fromRequirement && toTest) {
      traceLinks.push({
        requirementId: fromRequirement,
        testCaseId: toTest,
        relationshipType: relationship.relationshipType ?? undefined,
      });
      if (!testRequirementRefs.has(toTest)) {
        testRequirementRefs.set(toTest, new Set<string>());
      }
      testRequirementRefs.get(toTest)?.add(fromRequirement);
      return;
    }

    if (fromTest && toRequirement) {
      traceLinks.push({
        requirementId: toRequirement,
        testCaseId: fromTest,
        relationshipType: relationship.relationshipType ?? undefined,
      });
      if (!testRequirementRefs.has(fromTest)) {
        testRequirementRefs.set(fromTest, new Set<string>());
      }
      testRequirementRefs.get(fromTest)?.add(toRequirement);
      return;
    }

    warnings.push(
      `Skipped relationship ${relationship.id} because related items could not be resolved to requirements and test cases.`,
    );
  });

  testRequirementRefs.forEach((requirementIds, testId) => {
    const target = testResultMap.get(testId);
    if (target) {
      target.requirementsRefs = Array.from(requirementIds);
    }
  });

  const data: JamaImportBundle = {
    requirements: Array.from(requirementMap.values()),
    objectives: [],
    testResults: Array.from(testResultMap.values()),
    traceLinks,
    evidenceIndex: {},
    generatedAt: new Date().toISOString(),
  };

  return { data, warnings };
};
