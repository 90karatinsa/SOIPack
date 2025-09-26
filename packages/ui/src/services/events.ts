import { buildAuthHeaders, resolveApiUrl, type AuthCredentials } from './api';

export type ComplianceEventType =
  | 'riskProfile'
  | 'ledgerEntry'
  | 'queueState'
  | 'manifestProof';

export interface ComplianceEventBase {
  tenantId: string;
  emittedAt?: string;
  id?: string;
}

export interface RiskFactorBreakdown {
  factor: string;
  contribution: number;
  weight: number;
  details?: string;
}

export interface ComplianceDeltaChange {
  objectiveId: string;
  previousStatus: 'missing' | 'partial' | 'covered';
  currentStatus: 'missing' | 'partial' | 'covered';
}

export interface ComplianceDeltaBoundary {
  version: { id: string };
  generatedAt?: string;
}

export interface ComplianceDeltaStep {
  from?: ComplianceDeltaBoundary;
  to: ComplianceDeltaBoundary;
  improvements: ComplianceDeltaChange[];
  regressions: ComplianceDeltaChange[];
}

export interface ComplianceDeltaSummary {
  steps: ComplianceDeltaStep[];
  latest?: ComplianceDeltaStep;
  totals: { improvements: number; regressions: number };
}

export interface ToolQualificationAlert {
  toolId: string;
  toolName?: string;
  category?: string;
  tql?: string | null;
  pendingActivities: number;
  message?: string;
}

export interface ToolQualificationAlertSummary {
  pendingTools: number;
  alerts: ToolQualificationAlert[];
  updatedAt?: string;
}

export interface ComplianceRiskEvent extends ComplianceEventBase {
  type: 'riskProfile';
  profile: {
    score: number;
    classification: string;
    breakdown: RiskFactorBreakdown[];
    missingSignals: string[];
    complianceDelta?: ComplianceDeltaSummary;
    toolQualification?: ToolQualificationAlertSummary;
  };
}

export interface ComplianceLedgerEvent extends ComplianceEventBase {
  type: 'ledgerEntry';
  entry: {
    index: number;
    snapshotId: string;
    manifestDigest: string;
    timestamp: string;
    merkleRoot: string;
    previousRoot?: string | null;
    ledgerRoot?: string | null;
    evidence: Array<{
      id: string;
      hash: string;
      uri?: string | null;
    }>;
  };
}

export interface ComplianceQueueEvent extends ComplianceEventBase {
  type: 'queueState';
  jobs: Array<{
    id: string;
    kind: 'import' | 'analyze' | 'report' | 'pack';
    status: 'queued' | 'running' | 'completed' | 'failed';
    hash: string;
    createdAt: string;
    updatedAt: string;
  }>;
  counts: Record<'queued' | 'running' | 'completed' | 'failed', number>;
}

export interface ManifestMerkleSummary {
  algorithm: 'ledger-merkle-v1';
  root: string;
  manifestDigest: string;
  snapshotId: string;
}

export interface ComplianceManifestProofEvent extends ComplianceEventBase {
  type: 'manifestProof';
  manifestId: string;
  jobId?: string;
  merkle?: ManifestMerkleSummary | null;
  files: Array<{ path: string; sha256: string; hasProof: boolean; verified: boolean }>;
}

export type ComplianceEvent =
  | ComplianceRiskEvent
  | ComplianceLedgerEvent
  | ComplianceQueueEvent
  | ComplianceManifestProofEvent;

export type EventStreamStatus = 'connecting' | 'open' | 'retrying' | 'closed';

export interface StatusContext {
  attempt?: number;
  delayMs?: number;
  reason?: 'network' | 'completed' | 'client';
}

export interface ComplianceStreamOptions extends AuthCredentials {
  onEvent?: (event: ComplianceEvent) => void;
  onError?: (error: Error) => void;
  onStatusChange?: (status: EventStreamStatus, context?: StatusContext) => void;
  signal?: AbortSignal;
  backoff?: {
    initialDelayMs?: number;
    maxDelayMs?: number;
    multiplier?: number;
  };
}

export interface ComplianceEventStreamHandle {
  close: () => void;
  getState: () => {
    connected: boolean;
    retries: number;
    lastEventId?: string;
  };
}

class UnauthorizedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnauthorizedError';
  }
}

const DEFAULT_ENDPOINT = '/v1/stream/compliance';
const DEFAULT_INITIAL_DELAY = 1000;
const DEFAULT_MAX_DELAY = 10000;
const DEFAULT_MULTIPLIER = 2;

const createSseUrl = (): string => resolveApiUrl(DEFAULT_ENDPOINT);

const parseSseBuffer = (
  buffer: string,
): {
  messages: Array<{ id?: string; event?: string; data?: string }>;
  remainder: string;
} => {
  const normalized = buffer.replace(/\r\n/g, '\n');
  const segments = normalized.split('\n\n');
  const remainder = segments.pop() ?? '';
  const messages: Array<{ id?: string; event?: string; data?: string }> = [];
  segments.forEach((segment) => {
    if (!segment.trim()) {
      return;
    }
    const lines = segment.split('\n');
    const dataLines: string[] = [];
    let eventName: string | undefined;
    let eventId: string | undefined;
    lines.forEach((line) => {
      if (!line) {
        return;
      }
      if (line.startsWith(':')) {
        return;
      }
      if (line.startsWith('event:')) {
        eventName = line.slice(6).trim();
        return;
      }
      if (line.startsWith('id:')) {
        eventId = line.slice(3).trim();
        return;
      }
      if (line.startsWith('data:')) {
        dataLines.push(line.slice(5));
      }
    });
    if (dataLines.length === 0) {
      return;
    }
    messages.push({ id: eventId, event: eventName, data: dataLines.join('\n') });
  });
  return { messages, remainder };
};

const parseEventPayload = (data: string): ComplianceEvent | null => {
  try {
    const payload = JSON.parse(data) as ComplianceEvent;
    if (!payload || typeof payload !== 'object') {
      return null;
    }
    if (
      payload.type === 'riskProfile' ||
      payload.type === 'ledgerEntry' ||
      payload.type === 'queueState' ||
      payload.type === 'manifestProof'
    ) {
      return payload;
    }
    return null;
  } catch (error) {
    console.warn('SSE payload JSON parse failed', error);
    return null;
  }
};

export function createComplianceEventStream(options: ComplianceStreamOptions): ComplianceEventStreamHandle {
  const {
    token,
    license,
    onEvent,
    onError,
    onStatusChange,
    signal,
    backoff,
  } = options;

  let aborted = false;
  let currentController: AbortController | null = null;
  let retryTimer: NodeJS.Timeout | null = null;
  let retries = 0;
  let lastEventId: string | undefined;
  let connected = false;

  const initialDelay = Math.max(0, backoff?.initialDelayMs ?? DEFAULT_INITIAL_DELAY);
  const maxDelay = Math.max(initialDelay || DEFAULT_INITIAL_DELAY, backoff?.maxDelayMs ?? DEFAULT_MAX_DELAY);
  const multiplier = Math.max(1, backoff?.multiplier ?? DEFAULT_MULTIPLIER);

  const cleanupTimer = () => {
    if (retryTimer) {
      clearTimeout(retryTimer);
      retryTimer = null;
    }
  };

  const updateStatus = (status: EventStreamStatus, context?: StatusContext) => {
    onStatusChange?.(status, context);
  };

  const handleError = (error: Error) => {
    if (aborted) {
      return;
    }
    onError?.(error);
  };

  const scheduleReconnect = (reason: 'network' | 'completed') => {
    if (aborted) {
      return;
    }
    retries += 1;
    const delayMs = Math.min(maxDelay, (initialDelay || DEFAULT_INITIAL_DELAY) * Math.pow(multiplier, Math.max(0, retries - 1)));
    updateStatus('retrying', { attempt: retries, delayMs, reason });
    cleanupTimer();
    retryTimer = setTimeout(() => {
      retryTimer = null;
      void connect();
    }, delayMs);
  };

  const connect = async (): Promise<void> => {
    if (aborted) {
      return;
    }
    cleanupTimer();
    currentController?.abort();
    const controller = new AbortController();
    currentController = controller;
    if (signal) {
      if (signal.aborted) {
        aborted = true;
        controller.abort();
        return;
      }
      signal.addEventListener('abort', () => {
        aborted = true;
        controller.abort();
      }, { once: true });
    }

    try {
      updateStatus('connecting', { attempt: retries + 1 });
      const headers = buildAuthHeaders({ token, license });
      const response = await fetch(createSseUrl(), {
        method: 'GET',
        headers: {
          ...headers,
          Accept: 'text/event-stream',
          ...(lastEventId ? { 'Last-Event-ID': lastEventId } : {}),
        },
        signal: controller.signal,
        cache: 'no-store',
      });

      if (response.status === 401 || response.status === 403) {
        throw new UnauthorizedError('Kimlik doğrulama başarısız oldu.');
      }

      if (!response.ok) {
        throw new Error(`Etkinlik akışı bağlantısı başarısız oldu: ${response.status} ${response.statusText}`);
      }

      const body = response.body;
      if (!body) {
        throw new Error('Sunucu SSE bağlantısı için geçerli bir yanıt döndürmedi.');
      }

      retries = 0;
      connected = true;
      updateStatus('open', { attempt: 1 });

      const reader = body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (!aborted) {
        const { value, done } = await reader.read();
        if (done) {
          if (buffer) {
            const { messages } = parseSseBuffer(`${buffer}\n\n`);
            messages.forEach((message) => {
              if (message.id) {
                lastEventId = message.id;
              }
              if (!message.data) {
                return;
              }
              const payload = parseEventPayload(message.data);
              if (payload) {
                onEvent?.(payload);
              }
            });
          }
          connected = false;
          if (!aborted) {
            scheduleReconnect('completed');
          }
          break;
        }
        buffer += decoder.decode(value, { stream: true });
        const { messages, remainder } = parseSseBuffer(buffer);
        buffer = remainder;
        messages.forEach((message) => {
          if (message.id) {
            lastEventId = message.id;
          }
          if (!message.data) {
            return;
          }
          const payload = parseEventPayload(message.data);
          if (payload) {
            onEvent?.(payload);
          }
        });
      }
    } catch (error) {
      connected = false;
      if (error instanceof UnauthorizedError) {
        cleanupTimer();
        handleError(error);
        aborted = true;
        updateStatus('closed', { reason: 'client' });
        return;
      }
      if (error instanceof DOMException && error.name === 'AbortError') {
        return;
      }
      if (aborted) {
        return;
      }
      const err = error instanceof Error ? error : new Error(String(error));
      handleError(err);
      scheduleReconnect('network');
    }
  };

  void connect();

  return {
    close: () => {
      if (aborted) {
        return;
      }
      aborted = true;
      connected = false;
      cleanupTimer();
      currentController?.abort();
      updateStatus('closed', { reason: 'client' });
    },
    getState: () => ({ connected, retries, lastEventId }),
  };
}
