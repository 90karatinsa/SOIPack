import { useEffect, useMemo, useReducer } from 'react';

import { useRbac } from '../providers/RbacProvider';
import {
  createComplianceEventStream,
  type ComplianceDeltaSummary,
  type ComplianceEvent,
  type ComplianceLedgerEvent,
  type ComplianceRiskEvent,
  type EventStreamStatus,
  type StatusContext,
  type ToolQualificationAlertSummary,
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

interface DeltaTrendItem {
  label: string;
  window?: string;
  improvements: number;
  regressions: number;
}

interface DeltaRegressionItem {
  objectiveId: string;
  changeLabel: string;
  stepLabel: string;
  status: 'missing' | 'partial' | 'covered';
}

interface DeltaPanelState {
  totalsLabel: string;
  totals: { improvements: number; regressions: number };
  sparklineValues: number[];
  sparklineLabel: string;
  trend: DeltaTrendItem[];
  regressions: DeltaRegressionItem[];
}

interface ToolAlertItem {
  toolId: string;
  toolName: string;
  pendingActivities: number;
  message?: string;
  category?: string;
  tql?: string | null;
}

interface ToolAlertState {
  pendingTools: number;
  alerts: ToolAlertItem[];
  updatedAt?: string;
}

interface RiskCockpitState {
  status: RiskCockpitStatus;
  heatmap: HeatmapCell[];
  ledgerDiffs: LedgerDiff[];
  summary?: RiskSummary;
  reconnectDelayMs?: number;
  lastError?: string;
  delta?: DeltaPanelState;
  toolAlerts?: ToolAlertState;
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

const deltaStatusLabels: Record<'missing' | 'partial' | 'covered', string> = {
  missing: 'Eksik',
  partial: 'Kısmen Karşılandı',
  covered: 'Tam Karşılandı',
};

const regressionBadgeClasses: Record<'missing' | 'partial' | 'covered', string> = {
  missing: 'bg-rose-500/20 text-rose-200',
  partial: 'bg-amber-500/20 text-amber-200',
  covered: 'bg-emerald-500/20 text-emerald-200',
};

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

const formatTimestamp = (value?: string): string | undefined => {
  if (!value) {
    return undefined;
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  const [isoDate, isoTime] = date.toISOString().split('T');
  return `${isoDate} ${isoTime.slice(0, 5)} UTC`;
};

const buildDeltaPanel = (summary?: ComplianceDeltaSummary): DeltaPanelState | undefined => {
  if (!summary || summary.steps.length === 0) {
    return undefined;
  }

  const trend: DeltaTrendItem[] = summary.steps.map((step) => {
    const fromId = step.from?.version.id ?? 'Önceki';
    const toId = step.to.version.id;
    const fromDate = formatTimestamp(step.from?.generatedAt);
    const toDate = formatTimestamp(step.to.generatedAt);
    const window = [fromDate, toDate].filter(Boolean).join(' → ') || undefined;
    return {
      label: `${fromId} → ${toId}`,
      window,
      improvements: step.improvements.length,
      regressions: step.regressions.length,
    };
  });

  const sparklineValues = trend.map((entry) => entry.regressions);
  const regressions: DeltaRegressionItem[] = summary.steps.flatMap((step) => {
    const stepLabelParts = [`${step.from?.version.id ?? 'Önceki'} → ${step.to.version.id}`];
    const fromDate = formatTimestamp(step.from?.generatedAt);
    const toDate = formatTimestamp(step.to.generatedAt);
    const window = [fromDate, toDate].filter(Boolean).join(' → ');
    if (window) {
      stepLabelParts.push(`(${window})`);
    }
    const stepLabel = stepLabelParts.join(' ');
    return step.regressions.map((change) => ({
      objectiveId: change.objectiveId,
      changeLabel: `${deltaStatusLabels[change.previousStatus]} → ${deltaStatusLabels[change.currentStatus]}`,
      stepLabel,
      status: change.currentStatus,
    }));
  });

  return {
    totalsLabel: `İyileşme ${summary.totals.improvements} • Gerileme ${summary.totals.regressions}`,
    totals: summary.totals,
    sparklineValues,
    sparklineLabel: `Regresyon trendi: ${sparklineValues.join(', ')}`,
    trend,
    regressions: regressions.slice(0, 6),
  };
};

const buildToolAlerts = (summary?: ToolQualificationAlertSummary): ToolAlertState | undefined => {
  if (!summary) {
    return undefined;
  }

  const alerts = (summary.alerts ?? []).map((alert) => ({
    toolId: alert.toolId,
    toolName: alert.toolName ?? alert.toolId,
    pendingActivities: alert.pendingActivities,
    message: alert.message,
    category: alert.category,
    tql: alert.tql ?? null,
  }));

  return {
    pendingTools: summary.pendingTools,
    alerts,
    updatedAt: formatTimestamp(summary.updatedAt),
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
          delta: buildDeltaPanel(action.event.profile.complianceDelta),
          toolAlerts: buildToolAlerts(action.event.profile.toolQualification),
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
  const canViewDelta = canViewRisk && canViewLedger;

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
  const deltaPanel = state.delta;
  const sparklineMax = deltaPanel && deltaPanel.sparklineValues.length > 0
    ? Math.max(...deltaPanel.sparklineValues, 1)
    : 1;
  const toolAlerts = state.toolAlerts;

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
            ) : (
              <>
                {state.heatmap.length > 0 ? (
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
                {canViewDelta && deltaPanel && (
                  <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4 shadow shadow-slate-950/30">
                    <header className="flex items-baseline justify-between">
                      <div>
                        <h4 className="text-sm font-semibold text-white">Uyum delta eğrisi</h4>
                        <p className="text-xs text-slate-400">{deltaPanel.totalsLabel}</p>
                      </div>
                      <div className="text-right text-xs text-slate-300">
                        <p className="font-semibold text-emerald-300">+{deltaPanel.totals.improvements}</p>
                        <p className="font-semibold text-rose-300">-{deltaPanel.totals.regressions}</p>
                      </div>
                    </header>
                    <div className="mt-3 flex h-16 items-end gap-1" role="img" aria-label={deltaPanel.sparklineLabel}>
                      {deltaPanel.sparklineValues.map((value, index) => {
                        const height = Math.max(6, Math.round((value / sparklineMax) * 56));
                        return (
                          <span
                            key={`delta-bar-${index}-${value}`}
                            className="w-3 rounded-full bg-rose-500/60"
                            style={{ height: `${height}px` }}
                          />
                        );
                      })}
                    </div>
                    <ul className="mt-4 space-y-2 text-xs text-slate-300">
                      {deltaPanel.trend.map((entry) => (
                        <li
                          key={entry.label}
                          className="flex items-start justify-between gap-3 rounded-xl border border-slate-800/60 bg-slate-900/50 p-3"
                        >
                          <div>
                            <p className="font-semibold text-white">{entry.label}</p>
                            {entry.window && <p className="text-[11px] text-slate-400">{entry.window}</p>}
                          </div>
                          <div className="text-right">
                            <p className="font-semibold text-emerald-300">+{entry.improvements}</p>
                            <p className="font-semibold text-rose-300">-{entry.regressions}</p>
                          </div>
                        </li>
                      ))}
                    </ul>
                    <div className="mt-4">
                      <h5 className="text-xs font-semibold uppercase tracking-wide text-slate-400">Kritik gerilemeler</h5>
                      {deltaPanel.regressions.length ? (
                        <ul className="mt-2 space-y-2 text-xs text-slate-300">
                          {deltaPanel.regressions.map((regression) => (
                            <li
                              key={`${regression.objectiveId}-${regression.stepLabel}`}
                              className="rounded-xl border border-slate-800/60 bg-slate-900/50 p-3"
                            >
                              <div className="flex items-center justify-between gap-3">
                                <p className="font-semibold text-white">{regression.objectiveId}</p>
                                <span
                                  className={`inline-flex items-center rounded-full px-2 py-1 text-[11px] font-semibold ${regressionBadgeClasses[regression.status]}`}
                                >
                                  {regression.changeLabel}
                                </span>
                              </div>
                              <p className="mt-1 text-[11px] text-slate-400">{regression.stepLabel}</p>
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <p className="mt-2 text-xs text-slate-400">Gerileme kaydı bulunmuyor.</p>
                      )}
                    </div>
                  </div>
                )}
                {canViewDelta && toolAlerts && (
                  <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4 shadow shadow-slate-950/30">
                    <header className="flex items-baseline justify-between">
                      <div>
                        <h4 className="text-sm font-semibold text-white">Araç niteliklendirme uyarıları</h4>
                        {toolAlerts.updatedAt && (
                          <p className="text-xs text-slate-400">Son güncelleme: {toolAlerts.updatedAt}</p>
                        )}
                      </div>
                      <span
                        className={`inline-flex items-center rounded-full px-2 py-1 text-xs font-semibold ${
                          toolAlerts.pendingTools > 0
                            ? 'bg-amber-500/20 text-amber-200'
                            : 'bg-emerald-500/20 text-emerald-200'
                        }`}
                      >
                        Açık araç: {toolAlerts.pendingTools}
                      </span>
                    </header>
                    {toolAlerts.alerts.length ? (
                      <ul className="mt-3 space-y-3 text-xs text-slate-300">
                        {toolAlerts.alerts.map((alert) => (
                          <li
                            key={alert.toolId}
                            className="rounded-xl border border-slate-800/60 bg-slate-900/50 p-3"
                          >
                            <div className="flex items-center justify-between gap-3">
                              <div>
                                <p className="font-semibold text-white">{alert.toolName}</p>
                                <p className="text-[11px] text-slate-400">{alert.toolId}</p>
                              </div>
                              <span className="inline-flex items-center rounded-full bg-rose-500/20 px-2 py-1 text-[11px] font-semibold text-rose-200">
                                Açık aktivite: {alert.pendingActivities}
                              </span>
                            </div>
                            <div className="mt-1 space-x-2 text-[11px] text-slate-400">
                              {alert.category && <span>{alert.category}</span>}
                              {alert.tql && <span>TQL {alert.tql}</span>}
                            </div>
                            {alert.message && <p className="mt-1 text-[11px] text-slate-400">{alert.message}</p>}
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="mt-3 text-xs text-slate-400">Araç niteliklendirme uyarısı bulunmuyor.</p>
                    )}
                  </div>
                )}
              </>
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
