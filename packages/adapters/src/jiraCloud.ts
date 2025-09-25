import { HttpError, type HttpRequestOptions, requestJson } from './utils/http';

const DEFAULT_PAGE_SIZE = 50;
const DEFAULT_MAX_PAGES = 20;
const DEFAULT_RATE_LIMIT_DELAYS_MS = [500, 1000, 2000, 4000];

const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => {
    setTimeout(resolve, ms);
  });

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
  attempt: number,
  rateLimitDelays: number[],
): Promise<T> => {
  try {
    return await requestJson<T>(options);
  } catch (error) {
    if (error instanceof HttpError && error.statusCode === 429 && attempt < rateLimitDelays.length) {
      const retryDelay = parseRetryAfter(error) ?? rateLimitDelays[attempt];
      if (retryDelay > 0) {
        await sleep(retryDelay);
      }
      return requestWithBackoff(options, attempt + 1, rateLimitDelays);
    }
    throw error;
  }
};

interface JiraIssueFieldUser {
  displayName?: string | null;
}

interface JiraIssueFieldStatus {
  name?: string | null;
  statusCategory?: {
    name?: string | null;
  } | null;
}

interface JiraIssueFieldPriority {
  name?: string | null;
}

interface JiraIssueAttachment {
  id?: string | number;
  filename?: string | null;
  size?: number | null;
  mimeType?: string | null;
  content?: string | null;
  created?: string | null;
}

interface JiraIssueFields {
  summary?: string | null;
  status?: JiraIssueFieldStatus | null;
  assignee?: JiraIssueFieldUser | null;
  updated?: string | null;
  priority?: JiraIssueFieldPriority | null;
  issuetype?: { name?: string | null } | null;
  attachment?: JiraIssueAttachment[] | null;
}

interface JiraIssue {
  id: string;
  key: string;
  fields: JiraIssueFields;
}

interface JiraSearchResponse {
  startAt?: number;
  maxResults?: number;
  total?: number;
  issues?: JiraIssue[];
}

interface JiraTransitionRecord {
  id: string;
  name: string;
  to?: {
    name?: string | null;
    statusCategory?: {
      name?: string | null;
    } | null;
  } | null;
}

interface JiraTransitionResponse {
  transitions?: JiraTransitionRecord[];
}

export interface JiraChangeRequestTransition {
  id: string;
  name: string;
  toStatus: string;
  category?: string;
}

export interface JiraChangeRequestAttachment {
  id: string;
  filename: string;
  url?: string;
  size?: number;
  mimeType?: string;
  createdAt?: string;
}

export interface JiraChangeRequest {
  id: string;
  key: string;
  summary: string;
  status: string;
  statusCategory?: string;
  assignee?: string | null;
  updatedAt?: string;
  priority?: string | null;
  issueType?: string | null;
  url: string;
  transitions: JiraChangeRequestTransition[];
  attachments: JiraChangeRequestAttachment[];
}

export interface JiraCloudClientOptions {
  baseUrl: string;
  projectKey: string;
  authToken?: string;
  email?: string;
  jql?: string;
  pageSize?: number;
  maxPages?: number;
  timeoutMs?: number;
  rateLimitDelaysMs?: number[];
}

const buildAuthHeader = (options: JiraCloudClientOptions): string | undefined => {
  if (options.email && options.authToken) {
    const credentials = Buffer.from(`${options.email}:${options.authToken}`).toString('base64');
    return `Basic ${credentials}`;
  }
  if (options.authToken) {
    return `Bearer ${options.authToken}`;
  }
  return undefined;
};

const normalizeSummary = (issue: JiraIssue): string => issue.fields.summary?.trim() || issue.key;

const normalizeStatus = (issue: JiraIssue): { name: string; category?: string } => {
  const statusName = issue.fields.status?.name?.trim();
  const statusCategory = issue.fields.status?.statusCategory?.name?.trim();
  return { name: statusName || 'Bilinmiyor', category: statusCategory || undefined };
};

const normalizeAttachments = (attachments: JiraIssueAttachment[] | null | undefined): JiraChangeRequestAttachment[] => {
  if (!attachments || attachments.length === 0) {
    return [];
  }
  return attachments.map((attachment) => ({
    id: attachment.id !== undefined ? String(attachment.id) : 'unknown',
    filename: attachment.filename?.trim() || 'attachment',
    url: attachment.content ?? undefined,
    size: typeof attachment.size === 'number' ? attachment.size : undefined,
    mimeType: attachment.mimeType ?? undefined,
    createdAt: attachment.created ?? undefined,
  }));
};

const normalizeTransitions = (
  transitions: JiraTransitionRecord[] | null | undefined,
): JiraChangeRequestTransition[] => {
  if (!transitions || transitions.length === 0) {
    return [];
  }
  return transitions.map((transition) => ({
    id: transition.id,
    name: transition.name,
    toStatus: transition.to?.name ?? 'Bilinmiyor',
    category: transition.to?.statusCategory?.name ?? undefined,
  }));
};

const buildIssueUrl = (options: JiraCloudClientOptions, issue: JiraIssue): string => {
  try {
    return new URL(`/browse/${issue.key}`, options.baseUrl).toString();
  } catch {
    return issue.key;
  }
};

export const fetchJiraChangeRequests = async (
  options: JiraCloudClientOptions,
): Promise<JiraChangeRequest[]> => {
  const headers: Record<string, string> = { Accept: 'application/json' };
  const authHeader = buildAuthHeader(options);
  if (authHeader) {
    headers.Authorization = authHeader;
  }

  const pageSize = options.pageSize && options.pageSize > 0 ? Math.trunc(options.pageSize) : DEFAULT_PAGE_SIZE;
  const maxPages = options.maxPages && options.maxPages > 0 ? Math.trunc(options.maxPages) : DEFAULT_MAX_PAGES;
  const rateLimitDelays =
    options.rateLimitDelaysMs && options.rateLimitDelaysMs.length > 0
      ? options.rateLimitDelaysMs
      : DEFAULT_RATE_LIMIT_DELAYS_MS;

  const defaultJql = `project = "${options.projectKey}" AND issuetype in ("Change Request", "Problem") AND "Compliance Standard" = "DO-178C" ORDER BY updated DESC`;
  const jql = options.jql?.trim().length ? options.jql : defaultJql;

  const changeRequests: JiraChangeRequest[] = [];
  let startAt = 0;

  for (let page = 0; page < maxPages; page += 1) {
    const searchUrl = new URL('/rest/api/3/search', options.baseUrl);
    searchUrl.searchParams.set('jql', jql);
    searchUrl.searchParams.set('startAt', String(startAt));
    searchUrl.searchParams.set('maxResults', String(pageSize));
    searchUrl.searchParams.set('fields', 'summary,status,assignee,updated,priority,issuetype,attachment');

    const searchResponse = await requestWithBackoff<JiraSearchResponse>(
      {
        url: searchUrl,
        headers,
        timeoutMs: options.timeoutMs,
      },
      0,
      rateLimitDelays,
    );

    const issues = searchResponse.issues ?? [];
    if (issues.length === 0) {
      break;
    }

    const transitionPayloads = await Promise.all(
      issues.map(async (issue) => {
        const transitionsUrl = new URL(`/rest/api/3/issue/${issue.id}/transitions`, options.baseUrl);
        transitionsUrl.searchParams.set('expand', 'transitions.fields');
        try {
          const response = await requestWithBackoff<JiraTransitionResponse>(
            {
              url: transitionsUrl,
              headers,
              timeoutMs: options.timeoutMs,
            },
            0,
            rateLimitDelays,
          );
          return normalizeTransitions(response.transitions);
        } catch (error) {
          if (error instanceof HttpError && error.statusCode === 404) {
            return [];
          }
          throw error;
        }
      }),
    );

    issues.forEach((issue, index) => {
      const status = normalizeStatus(issue);
      changeRequests.push({
        id: issue.id,
        key: issue.key,
        summary: normalizeSummary(issue),
        status: status.name,
        statusCategory: status.category,
        assignee: issue.fields.assignee?.displayName ?? undefined,
        updatedAt: issue.fields.updated ?? undefined,
        priority: issue.fields.priority?.name ?? undefined,
        issueType: issue.fields.issuetype?.name ?? undefined,
        url: buildIssueUrl(options, issue),
        transitions: transitionPayloads[index] ?? [],
        attachments: normalizeAttachments(issue.fields.attachment),
      });
    });

    startAt += issues.length;
    const total = searchResponse.total ?? startAt;
    if (startAt >= total) {
      break;
    }
  }

  return changeRequests;
};

