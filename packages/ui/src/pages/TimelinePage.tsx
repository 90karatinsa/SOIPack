import { useEffect, useMemo, useReducer } from 'react';

import {
  createComplianceEventStream,
  type ComplianceEvent,
  type EventStreamStatus,
  type StatusContext,
} from '../services/events';

interface TimelinePageProps {
  token: string;
  license: string;
  isAuthorized: boolean;
}

type TimelineStatus = 'idle' | EventStreamStatus | 'error';

interface TimelineEntry {
  id: string;
  type: ComplianceEvent['type'];
  title: string;
  description: string;
  timestamp: string;
  tenantId: string;
  typeLabel: string;
}

interface TimelineState {
  status: TimelineStatus;
  events: TimelineEntry[];
  reconnectDelayMs?: number;
  lastError?: string;
}

type TimelineAction =
  | { type: 'reset' }
  | { type: 'status'; status: EventStreamStatus; context?: StatusContext }
  | { type: 'event'; event: ComplianceEvent }
  | { type: 'error'; message: string };

const MAX_TIMELINE_EVENTS = 50;

const initialState: TimelineState = {
  status: 'idle',
  events: [],
};

let eventCounter = 0;

const shortHash = (value: string, length = 10): string => {
  if (!value) {
    return '';
  }
  return value.length > length ? `${value.slice(0, length)}…` : value;
};

const describeEvent = (event: ComplianceEvent): TimelineEntry => {
  const baseId = event.id ?? `${event.type}-${eventCounter++}`;
  const timestamp =
    event.emittedAt ?? (event.type === 'ledgerEntry' ? event.entry.timestamp : new Date().toISOString());

  if (event.type === 'riskProfile') {
    const topFactor = event.profile.breakdown[0]?.factor;
    const missingSignals = event.profile.missingSignals.length;
    return {
      id: baseId,
      type: event.type,
      title: `Risk skoru ${event.profile.score}`,
      description: `Sınıflandırma: ${event.profile.classification}${
        topFactor ? ` • En baskın etken: ${topFactor}` : ''
      }${missingSignals > 0 ? ` • Eksik sinyaller: ${missingSignals}` : ''}`,
      timestamp,
      tenantId: event.tenantId,
      typeLabel: 'Risk Profili',
    };
  }

  if (event.type === 'ledgerEntry') {
    return {
      id: baseId,
      type: event.type,
      title: 'Ledger kaydı eklendi',
      description: `Snapshot ${event.entry.snapshotId} • Merkle ${shortHash(event.entry.merkleRoot)}${
        event.entry.ledgerRoot ? ` • Ledger ${shortHash(event.entry.ledgerRoot)}` : ''
      }`,
      timestamp,
      tenantId: event.tenantId,
      typeLabel: 'Ledger',
    };
  }

  const queued = event.counts.queued ?? 0;
  const running = event.counts.running ?? 0;
  const completed = event.counts.completed ?? 0;
  const failed = event.counts.failed ?? 0;
  const activeJobs = event.jobs
    .slice(0, 3)
    .map((job) => `${job.kind}#${shortHash(job.id, 6)} → ${job.status}`)
    .join(', ');
  const parts = [
    `Bekleyen: ${queued}`,
    `Çalışan: ${running}`,
    `Tamamlanan: ${completed}`,
    `Hatalı: ${failed}`,
  ];
  if (activeJobs) {
    parts.push(`Aktif: ${activeJobs}`);
  }

  return {
    id: baseId,
    type: event.type,
    title: 'Kuyruk durumu güncellendi',
    description: parts.join(' • '),
    timestamp,
    tenantId: event.tenantId,
    typeLabel: 'İş Kuyruğu',
  };
};

const reducer = (state: TimelineState, action: TimelineAction): TimelineState => {
  switch (action.type) {
    case 'reset':
      return { ...initialState };
    case 'status': {
      if (action.status === 'retrying') {
        return {
          ...state,
          status: 'retrying',
          reconnectDelayMs: action.context?.delayMs,
        };
      }
      if (action.status === 'closed') {
        return {
          ...state,
          status: 'closed',
          reconnectDelayMs: undefined,
        };
      }
      if (action.status === 'open') {
        return {
          ...state,
          status: 'open',
          reconnectDelayMs: undefined,
          lastError: undefined,
        };
      }
      return {
        ...state,
        status: 'connecting',
        reconnectDelayMs: undefined,
      };
    }
    case 'event': {
      const entry = describeEvent(action.event);
      const filtered = state.events.filter((existing) => existing.id !== entry.id);
      return {
        ...state,
        events: [entry, ...filtered].slice(0, MAX_TIMELINE_EVENTS),
      };
    }
    case 'error':
      return {
        ...state,
        status: 'error',
        lastError: action.message,
        reconnectDelayMs: undefined,
      };
    default:
      return state;
  }
};

const getStatusMessage = (state: TimelineState, isAuthorized: boolean): string => {
  if (!isAuthorized) {
    return 'Gerçek zamanlı zaman çizelgesi için geçerli bir token ve lisans gereklidir.';
  }

  switch (state.status) {
    case 'idle':
      return 'Gerçek zamanlı bağlantı bekleniyor.';
    case 'connecting':
      return 'Gerçek zamanlı bağlantı kuruluyor…';
    case 'open':
      return 'Canlı akış aktif. Yeni olaylar anında görünecek.';
    case 'retrying': {
      const seconds = state.reconnectDelayMs ? Math.ceil(state.reconnectDelayMs / 1000) : null;
      return seconds
        ? `Bağlantı koptu, ${seconds} saniye içinde yeniden denenecek.`
        : 'Bağlantı koptu, yeniden bağlanma deneniyor.';
    }
    case 'closed':
      return 'Akış kapatıldı. Yeniden bağlanmak için sekmeyi değiştirin.';
    case 'error':
      return state.lastError ? `Bağlantı hatası: ${state.lastError}` : 'Bağlantı hatası oluştu.';
    default:
      return 'Gerçek zamanlı bağlantı bekleniyor.';
  }
};

export function TimelinePage({ token, license, isAuthorized }: TimelinePageProps) {
  const [state, dispatch] = useReducer(reducer, initialState);

  useEffect(() => {
    if (!isAuthorized) {
      dispatch({ type: 'reset' });
      return;
    }

    dispatch({ type: 'status', status: 'connecting' });

    const handle = createComplianceEventStream({
      token,
      license,
      onEvent: (event) => dispatch({ type: 'event', event }),
      onStatusChange: (status, context) => dispatch({ type: 'status', status, context }),
      onError: (error) => dispatch({ type: 'error', message: error instanceof Error ? error.message : String(error) }),
    });

    return () => {
      handle.close();
    };
  }, [token, license, isAuthorized]);

  const statusMessage = useMemo(() => getStatusMessage(state, isAuthorized), [state, isAuthorized]);

  const hasEvents = state.events.length > 0;

  return (
    <section className="space-y-4 rounded-3xl border border-slate-800 bg-slate-900/70 p-6 shadow-lg shadow-slate-950/30">
      <header className="space-y-2">
        <h2 className="text-2xl font-semibold text-white">Gerçek zamanlı zaman çizelgesi</h2>
        <p className="text-sm text-slate-300">
          Sunucudan gelen risk profilleri, ledger kayıtları ve kuyruk durumları bu akışta canlı olarak gösterilir.
        </p>
      </header>

      <div className="rounded-2xl border border-slate-800 bg-slate-950/60 p-4 text-sm text-slate-200" role="status">
        {statusMessage}
      </div>

      {!isAuthorized ? (
        <p className="text-sm text-slate-400">
          Token ve lisans doğrulaması yapılmadan canlı zaman çizelgesi etkinleştirilemez.
        </p>
      ) : hasEvents ? (
        <ul className="space-y-4">
          {state.events.map((entry) => (
            <li
              key={entry.id}
              className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4 shadow-md shadow-slate-950/30"
            >
              <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                <div>
                  <p className="text-sm font-semibold text-white">{entry.title}</p>
                  <p className="mt-1 text-xs text-slate-300">{entry.description}</p>
                </div>
                <div className="text-right text-xs text-slate-400">
                  <span className="block text-[10px] uppercase tracking-wide text-slate-500">{entry.typeLabel}</span>
                  <time dateTime={entry.timestamp}>{entry.timestamp}</time>
                </div>
              </div>
              <p className="mt-3 text-[10px] uppercase tracking-wide text-slate-500">Tenant: {entry.tenantId}</p>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-sm text-slate-300">
          Henüz bir olay alınmadı. Kuyruk yeni işlediğinde kayıtlar burada görünecek.
        </p>
      )}

      {state.status === 'error' && state.lastError && isAuthorized && (
        <div className="rounded-2xl border border-rose-800/40 bg-rose-950/30 p-4 text-sm text-rose-100">
          Bağlantı hatası: {state.lastError}
        </div>
      )}
    </section>
  );
}
