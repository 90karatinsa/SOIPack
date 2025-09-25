import { useEffect, useMemo, useReducer } from 'react';

import { useRbac } from '../providers/RbacProvider';
import {
  createComplianceEventStream,
  type ComplianceEvent,
  type ComplianceLedgerEvent,
  type ComplianceRiskEvent,
  type EventStreamStatus,
  type StatusContext,
} from '../services/events';

interface RiskCockpitPageProps {
  token: string;
  license: string;
  isAuthorized: boolean;
}

type RiskCockpitStatus = 'idle' | EventStreamStatus | 'error';

interface HeatmapCell {
  factor: string;
  weight: number;
  contribution: number;
  impact: number;
  percentage: number;
  details?: string;
}

interface LedgerDiff {
  id: string;
  snapshotId: string;
  timestamp: string;
  merkleRoot: string;
  ledgerRoot: string | null;
  previousRoot: string | null;
  diffIndex: number | null;
  previousTail: string | null;
  currentTail: string | null;
}

interface RiskSummary {
  score: number;
  classification: string;
  missingSignals: number;
}

interface RiskCockpitState {
  status: RiskCockpitStatus;
  heatmap: HeatmapCell[];
  ledgerDiffs: LedgerDiff[];
  summary?: RiskSummary;
  reconnectDelayMs?: number;
  lastError?: string;
}

type RiskCockpitAction =
  | { type: 'reset' }
  | { type: 'status'; status: EventStreamStatus; context?: StatusContext }
  | { type: 'event'; event: ComplianceEvent }
  | { type: 'error'; message: string };

const MAX_LEDGER_DIFFS = 8;

const initialState: RiskCockpitState = {
  status: 'idle',
  heatmap: [],
  ledgerDiffs: [],
};

const toFixed = (value: number, digits: number): number =>
  Number(Number.isFinite(value) ? value.toFixed(digits) : value);

const calculateHeatmap = (event: ComplianceRiskEvent): { cells: HeatmapCell[]; summary: RiskSummary } => {
  const breakdown = event.profile.breakdown ?? [];
  const totalImpact = breakdown.reduce((total, item) => total + item.contribution * item.weight, 0);

  const cells: HeatmapCell[] = breakdown
    .map((item) => {
      const impact = item.contribution * item.weight;
      const percentage = totalImpact > 0 ? Math.round((impact / totalImpact) * 100) : 0;
      return {
        factor: item.factor,
        weight: toFixed(item.weight, 2),
        contribution: toFixed(item.contribution, 2),
        impact: toFixed(impact, 3),
        percentage,
        details: item.details,
      };
    })
    .sort((a, b) => b.impact - a.impact);

  return {
    cells,
    summary: {
      score: event.profile.score,
      classification: event.profile.classification,
      missingSignals: event.profile.missingSignals?.length ?? 0,
    },
  };
};

const findDiffIndex = (previousRoot: string | null, ledgerRoot: string | null): number | null => {
  if (!previousRoot || !ledgerRoot) {
    return null;
  }
  const limit = Math.min(previousRoot.length, ledgerRoot.length);
  for (let index = 0; index < limit; index += 1) {
    if (previousRoot[index] !== ledgerRoot[index]) {
      return index;
    }
  }
  if (previousRoot.length === ledgerRoot.length) {
    return null;
  }
  return limit;
};

const describeLedgerDiff = (event: ComplianceLedgerEvent): LedgerDiff => {
  const { entry } = event;
  const diffIndex = findDiffIndex(entry.previousRoot ?? null, entry.ledgerRoot ?? null);
  const previousTail = diffIndex !== null && entry.previousRoot ? entry.previousRoot.slice(diffIndex) : null;
  const currentTail = diffIndex !== null && entry.ledgerRoot ? entry.ledgerRoot.slice(diffIndex) : null;

  return {
    id: `${entry.snapshotId}-${entry.index}`,
    snapshotId: entry.snapshotId,
    timestamp: entry.timestamp,
    merkleRoot: entry.merkleRoot,
    ledgerRoot: entry.ledgerRoot ?? null,
    previousRoot: entry.previousRoot ?? null,
    diffIndex,
    previousTail,
    currentTail,
  };
};

const reducer = (state: RiskCockpitState, action: RiskCockpitAction): RiskCockpitState => {
  switch (action.type) {
    case 'reset':
      return { ...initialState };
    case 'status': {
      if (action.status === 'retrying') {
        return { ...state, status: 'retrying', reconnectDelayMs: action.context?.delayMs };
      }
      if (action.status === 'open') {
        return { ...state, status: 'open', reconnectDelayMs: undefined, lastError: undefined };
      }
      if (action.status === 'closed') {
        return { ...state, status: 'closed', reconnectDelayMs: undefined };
      }
      return { ...state, status: 'connecting', reconnectDelayMs: undefined };
    }
    case 'event': {
      if (action.event.type === 'riskProfile') {
        const { cells, summary } = calculateHeatmap(action.event);
        return {
          ...state,
          heatmap: cells,
          summary,
        };
      }
      if (action.event.type === 'ledgerEntry') {
        const diff = describeLedgerDiff(action.event);
        const existing = state.ledgerDiffs.filter((item) => item.id !== diff.id);
        return {
          ...state,
          ledgerDiffs: [diff, ...existing].slice(0, MAX_LEDGER_DIFFS),
        };
      }
      return state;
    }
    case 'error':
      return { ...state, status: 'error', lastError: action.message, reconnectDelayMs: undefined };
    default:
      return state;
  }
};

const getStatusMessage = (state: RiskCockpitState, isAuthorized: boolean): string => {
  if (!isAuthorized) {
    return 'Canlı risk akışı için geçerli token ve lisans gereklidir.';
  }

  switch (state.status) {
    case 'idle':
      return 'Risk akışı bekleniyor.';
    case 'connecting':
      return 'Risk akışı bağlanıyor…';
    case 'open':
      return 'Canlı risk akışı aktif. Yeni veriler otomatik olarak güncellenecek.';
    case 'retrying': {
      const seconds = state.reconnectDelayMs ? Math.ceil(state.reconnectDelayMs / 1000) : null;
      return seconds
        ? `Bağlantı koptu, ${seconds} saniye içinde yeniden denenecek.`
        : 'Bağlantı koptu, yeniden bağlanma deneniyor.';
    }
    case 'closed':
      return 'Akış kapatıldı. Sayfayı yenileyerek yeniden bağlanabilirsiniz.';
    case 'error':
      return state.lastError ? `Bağlantı hatası: ${state.lastError}` : 'Bağlantı hatası oluştu.';
    default:
      return 'Risk akışı bekleniyor.';
  }
};

const shortHash = (value: string | null, length = 8): string => {
  if (!value) {
    return '—';
  }
  if (value.length <= length * 2) {
    return value;
  }
  return `${value.slice(0, length)}…${value.slice(-length)}`;
};

export function RiskCockpitPage({ token, license, isAuthorized }: RiskCockpitPageProps) {
  const [state, dispatch] = useReducer(reducer, initialState);
  const { roles } = useRbac();

  const hasRoles = roles.size > 0;
  const canViewRisk = !hasRoles || roles.has('risk:read') || roles.has('admin');
  const canViewLedger = !hasRoles || roles.has('ledger:read') || roles.has('admin');

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
      onError: (error) =>
        dispatch({ type: 'error', message: error instanceof Error ? error.message : String(error) }),
    });

    return () => {
      handle.close();
    };
  }, [token, license, isAuthorized]);

  const statusMessage = useMemo(() => getStatusMessage(state, isAuthorized), [state, isAuthorized]);

  return (
    <section className="space-y-6 rounded-3xl border border-slate-800 bg-slate-900/70 p-6 shadow-lg shadow-slate-950/30">
      <header className="space-y-2">
        <h2 className="text-2xl font-semibold text-white">Risk kokpiti</h2>
        <p className="text-sm text-slate-300">
          Risk skorları ve ledger kök değişimleri gerçek zamanlı olarak bu panelde özetlenir.
        </p>
      </header>

      <div className="rounded-2xl border border-slate-800 bg-slate-950/60 p-4 text-sm text-slate-200" role="status">
        {statusMessage}
      </div>

      {!isAuthorized ? (
        <p className="text-sm text-slate-400">
          Token ve lisans doğrulaması yapılmadan risk kokpiti etkinleştirilemez.
        </p>
      ) : (
        <div className="grid gap-6 lg:grid-cols-2">
          <section className="space-y-3">
            <header className="flex items-baseline justify-between">
              <div>
                <h3 className="text-lg font-semibold text-white">Risk Isı Haritası</h3>
                <p className="text-xs text-slate-400">
                  Faktör bazında ağırlıklandırılmış etkiler son alınan risk profiline göre hesaplanır.
                </p>
              </div>
              {state.summary && (
                <dl className="text-right text-xs text-slate-300">
                  <div>
                    <dt className="font-semibold uppercase tracking-wide text-slate-500">Skor</dt>
                    <dd className="text-base font-bold text-brand">{state.summary.score}</dd>
                  </div>
                  <div className="mt-1">
                    <dt className="font-semibold uppercase tracking-wide text-slate-500">Sınıf</dt>
                    <dd>{state.summary.classification}</dd>
                  </div>
                  <div className="mt-1">
                    <dt className="font-semibold uppercase tracking-wide text-slate-500">Eksik sinyal</dt>
                    <dd>{state.summary.missingSignals}</dd>
                  </div>
                </dl>
              )}
            </header>

            {!canViewRisk ? (
              <p className="text-sm text-slate-400">Risk verilerine erişim yetkiniz yok.</p>
            ) : state.heatmap.length > 0 ? (
              <ul className="space-y-3">
                {state.heatmap.map((cell) => (
                  <li
                    key={cell.factor}
                    className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4 shadow shadow-slate-950/30"
                  >
                    <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                      <div>
                        <p className="text-sm font-semibold text-white">{cell.factor}</p>
                        {cell.details && <p className="mt-1 text-xs text-slate-400">{cell.details}</p>}
                      </div>
                      <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-right text-xs text-slate-300 sm:w-64">
                        <div>
                          <dt className="font-semibold uppercase tracking-wide text-slate-500">Ağırlık</dt>
                          <dd>{cell.weight.toFixed(2)}</dd>
                        </div>
                        <div>
                          <dt className="font-semibold uppercase tracking-wide text-slate-500">Katkı</dt>
                          <dd>{cell.contribution.toFixed(2)}</dd>
                        </div>
                        <div>
                          <dt className="font-semibold uppercase tracking-wide text-slate-500">Etki</dt>
                          <dd>{cell.impact.toFixed(2)}</dd>
                        </div>
                        <div>
                          <dt className="font-semibold uppercase tracking-wide text-slate-500">Pay</dt>
                          <dd>%{cell.percentage}</dd>
                        </div>
                      </dl>
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-slate-300">
                Henüz risk profili alınmadı. Akıştan ilk skor geldiğinde ısı haritası güncellenecektir.
              </p>
            )}
          </section>

          <section className="space-y-3">
            <header className="flex items-baseline justify-between">
              <div>
                <h3 className="text-lg font-semibold text-white">Ledger kök farkları</h3>
                <p className="text-xs text-slate-400">
                  Her kayıt için bir önceki ve yeni ledger kökü arasındaki fark konumunu görüntüler.
                </p>
              </div>
            </header>

            {!canViewLedger ? (
              <p className="text-sm text-slate-400">Ledger verilerine erişim yetkiniz yok.</p>
            ) : state.ledgerDiffs.length > 0 ? (
              <ul className="space-y-3">
                {state.ledgerDiffs.map((diff) => (
                  <li
                    key={diff.id}
                    className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4 shadow shadow-slate-950/30"
                  >
                    <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                      <div>
                        <p className="text-sm font-semibold text-white">Snapshot {diff.snapshotId}</p>
                        <p className="text-xs text-slate-400">Merkle: {shortHash(diff.merkleRoot)}</p>
                        <p className="text-xs text-slate-400">Zaman damgası: {diff.timestamp}</p>
                      </div>
                      <div className="text-right text-xs text-slate-300">
                        <p>
                          <span className="font-semibold uppercase tracking-wide text-slate-500">Fark pozisyonu:</span>{' '}
                          {diff.diffIndex ?? '—'}
                        </p>
                      </div>
                    </div>
                    <p className="mt-3 text-xs text-slate-300">Önceki kök: {shortHash(diff.previousRoot)}</p>
                    <p className="text-xs text-slate-300">Yeni kök: {shortHash(diff.ledgerRoot)}</p>
                    {diff.diffIndex !== null && (
                      <p className="mt-2 text-xs text-slate-200">
                        Önceki: {diff.previousTail ?? '—'} → Yeni: {diff.currentTail ?? '—'}
                      </p>
                    )}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-slate-300">
                Henüz ledger kaydı alınmadı. Yeni manifestler eklendiğinde farklar burada listelenecek.
              </p>
            )}
          </section>
        </div>
      )}

      {state.status === 'error' && state.lastError && isAuthorized && (
        <div className="rounded-2xl border border-rose-800/40 bg-rose-950/30 p-4 text-sm text-rose-100">
          Bağlantı hatası: {state.lastError}
        </div>
      )}
    </section>
  );
}

export default RiskCockpitPage;
