import { type ChangeEvent, useEffect, useMemo, useReducer, useRef, useState } from 'react';

import { useRbac } from '../providers/RbacProvider';
import {
  fetchStageRiskForecast,
  getManifestProof,
  type ManifestMerkleProofPayload,
  type StageRiskForecastEntry,
} from '../services/api';
import {
  createComplianceEventStream,
  type ComplianceDeltaSummary,
  type ComplianceEvent,
  type ComplianceLedgerEvent,
  type ComplianceRiskEvent,
  type ComplianceManifestProofEvent,
  type EventStreamStatus,
  type ManifestMerkleSummary,
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

interface ProofExplorerFileState {
  path: string;
  sha256: string;
  hasProof: boolean;
  verified: boolean;
  proof?: ManifestMerkleProofPayload | null;
  loading?: boolean;
  error?: string;
}

interface ProofExplorerState {
  manifestId: string;
  jobId?: string;
  merkle: ManifestMerkleSummary | null;
  files: ProofExplorerFileState[];
  selectedPath: string | null;
  lastUpdated?: string;
}

interface StageRiskPanelState {
  status: 'idle' | 'loading' | 'ready' | 'error';
  forecasts: StageRiskForecastEntry[];
  updatedAt?: string;
  error?: string;
}

interface RiskSandboxParams {
  coverageLift: number;
  failureRate: number;
  iterations: number;
}

interface RiskSandboxDistributionBucket {
  failures: number;
  probability: number;
}

interface RiskSandboxClassificationShare {
  classification: 'nominal' | 'guarded' | 'elevated' | 'critical';
  share: number;
}

interface RiskSandboxResult {
  iterations: number;
  averageRisk: number;
  regressionProbability: number;
  expectedFailures: number;
  distribution: RiskSandboxDistributionBucket[];
  classifications: RiskSandboxClassificationShare[];
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
  proofExplorer?: ProofExplorerState;
}

type RiskCockpitAction =
  | { type: 'reset' }
  | { type: 'status'; status: EventStreamStatus; context?: StatusContext }
  | { type: 'event'; event: ComplianceEvent }
  | { type: 'error'; message: string }
  | { type: 'select-proof'; path: string | null }
  | { type: 'proof-loading'; manifestId: string; path: string }
  | {
      type: 'proof-loaded';
      manifestId: string;
      path: string;
      proof: ManifestMerkleProofPayload;
      merkle?: ManifestMerkleSummary | null;
    }
  | { type: 'proof-error'; manifestId: string; path: string; message: string };

const MAX_LEDGER_DIFFS = 8;

const initialState: RiskCockpitState = {
  status: 'idle',
  heatmap: [],
  ledgerDiffs: [],
  proofExplorer: undefined,
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

const stageClassificationBadgeClasses: Record<string, string> = {
  nominal: 'bg-emerald-500/20 text-emerald-200',
  guarded: 'bg-amber-500/20 text-amber-200',
  elevated: 'bg-orange-500/20 text-orange-200',
  critical: 'bg-rose-500/20 text-rose-200',
};

const factorMetricBadgeClass =
  'inline-flex items-center gap-1 rounded-full border border-slate-800/60 bg-slate-900/70 px-2 py-1 text-[11px] font-semibold text-slate-200 shadow-sm shadow-slate-950/20';

const createRandomGenerator = (seed: number): (() => number) => {
  let state = seed >>> 0;
  if (state === 0) {
    state = 0x811c9dc5;
  }
  return () => {
    state = (state * 1664525 + 1013904223) >>> 0;
    return state / 0x100000000;
  };
};

const clamp01 = (value: number): number => {
  if (!Number.isFinite(value)) {
    return 0;
  }
  if (value <= 0) {
    return 0;
  }
  if (value >= 1) {
    return 1;
  }
  return value;
};

const classifyRiskScore = (score: number): 'nominal' | 'guarded' | 'elevated' | 'critical' => {
  if (score >= 0.75) {
    return 'critical';
  }
  if (score >= 0.5) {
    return 'elevated';
  }
  if (score >= 0.25) {
    return 'guarded';
  }
  return 'nominal';
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

export const runRiskSandboxSimulation = (
  forecasts: StageRiskForecastEntry[],
  params: RiskSandboxParams,
): RiskSandboxResult => {
  const iterations = Math.max(1, Math.floor(params.iterations));
  const stages = forecasts.length;
  const coverageFactor = clamp01(1 - params.coverageLift / 100);
  const failureFactor = 1 + params.failureRate / 100;
  const seedBase =
    Math.round(params.coverageLift * 977 + params.failureRate * 761 + stages * 389 + iterations) >>> 0;
  const random = createRandomGenerator(seedBase);
  const distributionCounts = Array.from({ length: stages + 1 }, () => 0);
  const classificationCounts: Record<'nominal' | 'guarded' | 'elevated' | 'critical', number> = {
    nominal: 0,
    guarded: 0,
    elevated: 0,
    critical: 0,
  };

  let accumulatedRisk = 0;
  let accumulatedFailures = 0;
  let regressionIterations = 0;

  for (let iteration = 0; iteration < iterations; iteration += 1) {
    let triggered = 0;
    forecasts.forEach((forecast) => {
      const baseProbability = clamp01((forecast.probability ?? 0) / 100);
      const adjusted = clamp01(baseProbability * failureFactor * coverageFactor);
      if (random() < adjusted) {
        triggered += 1;
      }
    });
    const riskScore = stages > 0 ? triggered / stages : 0;
    accumulatedRisk += riskScore;
    accumulatedFailures += triggered;
    distributionCounts[triggered] += 1;
    classificationCounts[classifyRiskScore(riskScore)] += 1;
    if (triggered > 0) {
      regressionIterations += 1;
    }
  }

  const distribution: RiskSandboxDistributionBucket[] = distributionCounts.map((count, failures) => ({
    failures,
    probability: count / iterations,
  }));

  const classifications: RiskSandboxClassificationShare[] = (
    Object.entries(classificationCounts) as Array<
      ['nominal' | 'guarded' | 'elevated' | 'critical', number]
    >
  )
    .map(([classification, count]) => ({
      classification,
      share: count / iterations,
    }))
    .sort((a, b) => {
      const order: Record<string, number> = { nominal: 0, guarded: 1, elevated: 2, critical: 3 };
      return order[a.classification] - order[b.classification];
    });

  return {
    iterations,
    averageRisk: (accumulatedRisk / iterations) * 100,
    regressionProbability: (regressionIterations / iterations) * 100,
    expectedFailures: stages > 0 ? accumulatedFailures / iterations : 0,
    distribution,
    classifications,
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
      if (action.event.type === 'manifestProof') {
        const manifestEvent: ComplianceManifestProofEvent = action.event;
        const previous = state.proofExplorer;
        const previousByPath = new Map(
          (previous?.files ?? []).map((file) => [file.path, file] as const),
        );
        const files: ProofExplorerFileState[] = manifestEvent.files.map((file) => {
          const existing = previousByPath.get(file.path);
          const base: ProofExplorerFileState = {
            path: file.path,
            sha256: file.sha256,
            hasProof: file.hasProof,
            verified: file.verified,
            proof: file.hasProof ? existing?.proof ?? null : null,
            loading: file.hasProof && existing?.loading && !existing?.proof ? existing.loading : false,
            error: file.hasProof ? existing?.error : undefined,
          };
          return base;
        });
        const previousSelection = previous?.selectedPath ?? null;
        const selectedPath =
          previousSelection && files.some((file) => file.path === previousSelection && file.hasProof)
            ? previousSelection
            : files.find((file) => file.hasProof)?.path ?? null;
        return {
          ...state,
          proofExplorer: {
            manifestId: manifestEvent.manifestId,
            jobId: manifestEvent.jobId,
            merkle: manifestEvent.merkle ?? null,
            files,
            selectedPath,
            lastUpdated: manifestEvent.emittedAt,
          },
        };
      }
      return state;
    }
    case 'error':
      return { ...state, status: 'error', lastError: action.message, reconnectDelayMs: undefined };
    case 'select-proof': {
      if (!state.proofExplorer) {
        return state;
      }
      if (!action.path) {
        return {
          ...state,
          proofExplorer: { ...state.proofExplorer, selectedPath: null },
        };
      }
      const exists = state.proofExplorer.files.some((file) => file.path === action.path);
      if (!exists) {
        return state;
      }
      return {
        ...state,
        proofExplorer: {
          ...state.proofExplorer,
          selectedPath: action.path,
          files: state.proofExplorer.files.map((file) =>
            file.path === action.path ? { ...file, error: undefined } : file,
          ),
        },
      };
    }
    case 'proof-loading': {
      if (!state.proofExplorer || state.proofExplorer.manifestId !== action.manifestId) {
        return state;
      }
      return {
        ...state,
        proofExplorer: {
          ...state.proofExplorer,
          files: state.proofExplorer.files.map((file) =>
            file.path === action.path
              ? { ...file, loading: true, error: undefined }
              : file,
          ),
        },
      };
    }
    case 'proof-loaded': {
      if (!state.proofExplorer || state.proofExplorer.manifestId !== action.manifestId) {
        return state;
      }
      return {
        ...state,
        proofExplorer: {
          ...state.proofExplorer,
          merkle: action.merkle ?? state.proofExplorer.merkle,
          files: state.proofExplorer.files.map((file) =>
            file.path === action.path
              ? { ...file, proof: action.proof, loading: false, error: undefined }
              : file,
          ),
        },
      };
    }
    case 'proof-error': {
      if (!state.proofExplorer || state.proofExplorer.manifestId !== action.manifestId) {
        return state;
      }
      return {
        ...state,
        proofExplorer: {
          ...state.proofExplorer,
          files: state.proofExplorer.files.map((file) =>
            file.path === action.path
              ? { ...file, loading: false, error: action.message }
              : file,
          ),
        },
      };
    }
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

interface ParsedMerkleProof {
  leafType: string;
  leafLabel: string;
  leafHash: string;
  path: Array<{ position: 'left' | 'right'; hash: string }>;
  merkleRoot: string;
}

const parseMerkleProof = (payload?: ManifestMerkleProofPayload | null): ParsedMerkleProof | null => {
  if (!payload) {
    return null;
  }
  try {
    const parsed = JSON.parse(payload.proof) as {
      leaf?: { type?: string; label?: string; hash?: string };
      path?: Array<{ position?: string; hash?: string }>;
      merkleRoot?: string;
    };
    if (!parsed || typeof parsed !== 'object') {
      return null;
    }
    const leafType = typeof parsed.leaf?.type === 'string' ? parsed.leaf.type : 'unknown';
    const leafLabel = typeof parsed.leaf?.label === 'string' ? parsed.leaf.label : '';
    const leafHash = typeof parsed.leaf?.hash === 'string' ? parsed.leaf.hash : '';
    if (!Array.isArray(parsed.path)) {
      return null;
    }
    const path = parsed.path
      .filter((node): node is { position: 'left' | 'right'; hash: string } =>
        Boolean(
          node &&
            (node.position === 'left' || node.position === 'right') &&
            typeof node.hash === 'string',
        ),
      )
      .map((node) => ({ position: node.position, hash: node.hash }));
    const merkleRoot = typeof parsed.merkleRoot === 'string' ? parsed.merkleRoot : payload.merkleRoot;
    return {
      leafType,
      leafLabel,
      leafHash,
      path,
      merkleRoot,
    };
  } catch {
    return null;
  }
};

export function RiskCockpitPage({ token, license, isAuthorized }: RiskCockpitPageProps) {
  const [state, dispatch] = useReducer(reducer, initialState);
  const { roles } = useRbac();
  const [stageRiskState, setStageRiskState] = useState<StageRiskPanelState>({
    status: 'idle',
    forecasts: [],
  });
  const [sandboxParams, setSandboxParams] = useState<RiskSandboxParams>({
    coverageLift: 12,
    failureRate: 8,
    iterations: 500,
  });
  const [sandboxResult, setSandboxResult] = useState<RiskSandboxResult | null>(null);
  const [sandboxLastRun, setSandboxLastRun] = useState<string | null>(null);
  const [sandboxError, setSandboxError] = useState<string | null>(null);

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

  useEffect(() => {
    if (!isAuthorized || !canViewRisk) {
      setStageRiskState({ status: 'idle', forecasts: [] });
      return;
    }

    let cancelled = false;
    const controller = new AbortController();
    setStageRiskState((prev) => ({
      status: 'loading',
      forecasts: prev.status === 'ready' ? prev.forecasts : [],
      updatedAt: prev.status === 'ready' ? prev.updatedAt : undefined,
    }));

    fetchStageRiskForecast({ token, license, signal: controller.signal })
      .then((response) => {
        if (cancelled) {
          return;
        }
        setStageRiskState({
          status: 'ready',
          forecasts: response.forecasts,
          updatedAt: response.generatedAt,
        });
      })
      .catch((error) => {
        if (cancelled) {
          return;
        }
        setStageRiskState({
          status: 'error',
          forecasts: [],
          error: error instanceof Error ? error.message : String(error),
        });
      });

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [token, license, isAuthorized, canViewRisk]);

  const statusMessage = useMemo(() => getStatusMessage(state, isAuthorized), [state, isAuthorized]);
  const deltaPanel = state.delta;
  const sparklineMax = deltaPanel && deltaPanel.sparklineValues.length > 0
    ? Math.max(...deltaPanel.sparklineValues, 1)
    : 1;
  const stageRisk = stageRiskState;
  const toolAlerts = state.toolAlerts;
  const proofExplorer = state.proofExplorer;
  const selectedProofEntry = useMemo(() => {
    if (!proofExplorer || !proofExplorer.selectedPath) {
      return null;
    }
    return proofExplorer.files.find((file) => file.path === proofExplorer.selectedPath) ?? null;
  }, [proofExplorer]);
  const parsedProof = useMemo(() => parseMerkleProof(selectedProofEntry?.proof), [selectedProofEntry?.proof]);
  const proofRequestRef = useRef<{ key: string; controller: AbortController } | null>(null);
  const sandboxLastRunLabel = useMemo(() => formatTimestamp(sandboxLastRun ?? undefined), [sandboxLastRun]);

  const handleSandboxRun = () => {
    if (!stageRisk.forecasts.length) {
      setSandboxError('Simülasyonu çalıştırmak için risk tahmini gereklidir.');
      setSandboxResult(null);
      setSandboxLastRun(null);
      return;
    }
    const result = runRiskSandboxSimulation(stageRisk.forecasts, sandboxParams);
    setSandboxResult(result);
    setSandboxLastRun(new Date().toISOString());
    setSandboxError(null);
  };

  const handleSandboxParamChange = (field: keyof RiskSandboxParams) =>
    (event: ChangeEvent<HTMLInputElement>) => {
      const value = Number(event.target.value);
      setSandboxParams((prev) => ({ ...prev, [field]: Number.isFinite(value) ? value : prev[field] }));
    };

  useEffect(() => {
    if (!isAuthorized) {
      return;
    }
    if (!proofExplorer || !selectedProofEntry || !selectedProofEntry.hasProof) {
      return;
    }
    if (selectedProofEntry.proof || selectedProofEntry.loading || selectedProofEntry.error) {
      return;
    }
    const requestKey = `${proofExplorer.manifestId}:${selectedProofEntry.path}`;
    if (proofRequestRef.current && proofRequestRef.current.key !== requestKey) {
      proofRequestRef.current.controller.abort();
      proofRequestRef.current = null;
    }
    const controller = new AbortController();
    proofRequestRef.current = { key: requestKey, controller };
    dispatch({ type: 'proof-loading', manifestId: proofExplorer.manifestId, path: selectedProofEntry.path });
    void getManifestProof({
      token,
      license,
      manifestId: proofExplorer.manifestId,
      filePath: selectedProofEntry.path,
      signal: controller.signal,
    })
      .then((response) => {
        if (controller.signal.aborted) {
          return;
        }
        if (proofRequestRef.current?.key === requestKey) {
          proofRequestRef.current = null;
        }
        dispatch({
          type: 'proof-loaded',
          manifestId: proofExplorer.manifestId,
          path: selectedProofEntry.path,
          proof: response.proof,
          merkle: response.merkle ?? null,
        });
      })
      .catch((error) => {
        if (controller.signal.aborted) {
          return;
        }
        if (proofRequestRef.current?.key === requestKey) {
          proofRequestRef.current = null;
        }
        dispatch({
          type: 'proof-error',
          manifestId: proofExplorer.manifestId,
          path: selectedProofEntry.path,
          message: error instanceof Error ? error.message : String(error),
        });
      });
  }, [
    proofExplorer,
    selectedProofEntry,
    isAuthorized,
    token,
    license,
  ]);

  useEffect(
    () => () => {
      if (proofRequestRef.current) {
        proofRequestRef.current.controller.abort();
        proofRequestRef.current = null;
      }
    },
    [],
  );

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
                  <ul className="space-y-3" aria-live="polite">
                    {state.heatmap.map((cell) => (
                      <li
                        key={cell.factor}
                        className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4 shadow shadow-slate-950/30 transition-colors"
                        aria-label={`Faktör ${cell.factor} ağırlık ${cell.weight.toFixed(2)}, katkı ${cell.contribution.toFixed(2)}, etki payı yüzde ${cell.percentage}`}
                      >
                        <div className="flex flex-col gap-3">
                          <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                            <div>
                              <p className="text-sm font-semibold text-white">{cell.factor}</p>
                              {cell.details && <p className="mt-1 text-xs text-slate-400">{cell.details}</p>}
                            </div>
                            <div className="flex flex-wrap justify-end gap-2 text-right text-[11px] text-slate-400">
                              <span className="rounded-full bg-slate-800/40 px-2 py-1 font-medium text-slate-300">
                                Etki {cell.impact.toFixed(2)}
                              </span>
                              <span className="rounded-full bg-slate-800/40 px-2 py-1 font-medium text-slate-300">
                                Pay %{cell.percentage}
                              </span>
                            </div>
                          </div>
                          <div
                            className="flex flex-wrap gap-2"
                            role="list"
                            aria-label={`${cell.factor} metrikleri`}
                          >
                            <span className={factorMetricBadgeClass} role="listitem">
                              Ağırlık {cell.weight.toFixed(2)}
                            </span>
                            <span className={factorMetricBadgeClass} role="listitem">
                              Katkı {cell.contribution.toFixed(2)}
                            </span>
                            <span className={factorMetricBadgeClass} role="listitem">
                              Etki {cell.impact.toFixed(2)}
                            </span>
                          </div>
                          <div>
                            <div className="flex items-center justify-between text-[11px] text-slate-400">
                              <span>Etki payı</span>
                              <span className="font-semibold text-slate-200">%{cell.percentage}</span>
                            </div>
                            <div
                              role="progressbar"
                              aria-label={`${cell.factor} etki payı`}
                              aria-valuenow={cell.percentage}
                              aria-valuemin={0}
                              aria-valuemax={100}
                              className="mt-2 h-2 w-full overflow-hidden rounded-full bg-slate-800"
                              data-testid={`risk-factor-share-${cell.factor}`}
                            >
                              <div
                                className="h-full rounded-full bg-brand transition-[width] duration-500 ease-out"
                                style={{ width: `${cell.percentage}%` }}
                              />
                            </div>
                          </div>
                        </div>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-sm text-slate-300">
                    Henüz risk profili alınmadı. Akıştan ilk skor geldiğinde ısı haritası güncellenecektir.
                  </p>
                )}
                <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4 shadow shadow-slate-950/30">
                  <header className="flex items-baseline justify-between">
                    <div>
                      <h4 className="text-sm font-semibold text-white">SOI aşama risk tahmini</h4>
                      <p className="text-xs text-slate-400">
                        Monte Carlo çıktıları ve regresyon trendleri 30 günlük ufukta harmanlanır.
                      </p>
                    </div>
                    {stageRisk.updatedAt && (
                      <p className="text-xs text-slate-400">Güncelleme: {stageRisk.updatedAt}</p>
                    )}
                  </header>
                  {stageRisk.status === 'loading' ? (
                    <p className="mt-3 text-xs text-slate-400">Veriler yükleniyor…</p>
                  ) : stageRisk.status === 'error' ? (
                    <p className="mt-3 text-xs text-rose-300">
                      Tahmin alınamadı: {stageRisk.error ?? 'Bilinmeyen hata'}
                    </p>
                  ) : stageRisk.forecasts.length === 0 ? (
                    <p className="mt-3 text-xs text-slate-400">Henüz tahmin bulunmuyor.</p>
                  ) : (
                    <ul className="mt-3 space-y-3 text-xs text-slate-300">
                      {stageRisk.forecasts.map((forecast) => {
                        const sparklineMaxLocal =
                          forecast.sparkline.length > 0
                            ? Math.max(
                                ...forecast.sparkline.map((point) => Math.max(point.regressionRatio, 0)),
                                0.01,
                              )
                            : 1;
                        const ariaLabel = `Regresyon oranı: ${forecast.sparkline
                          .map((point) => `%${Math.round(Math.max(0, point.regressionRatio) * 100)}`)
                          .join(', ')}`;
                        const badgeClass =
                          stageClassificationBadgeClasses[forecast.classification] ??
                          'bg-slate-700/40 text-slate-300';
                        return (
                          <li
                            key={forecast.stage}
                            className="rounded-xl border border-slate-800/60 bg-slate-900/50 p-3"
                          >
                            <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                              <div>
                                <p className="text-sm font-semibold text-white">{forecast.stage}</p>
                                <p className="text-[11px] text-slate-400">
                                  {forecast.horizonDays} günlük regresyon olasılığı
                                </p>
                              </div>
                              <div className="text-right">
                                <span
                                  className={`inline-flex items-center justify-end rounded-full px-2 py-1 text-[11px] font-semibold ${badgeClass}`}
                                >
                                  {forecast.classification}
                                </span>
                                <p className="mt-1 text-lg font-semibold text-white">%{forecast.probability}</p>
                              </div>
                            </div>
                            <p className="mt-2 text-[11px] text-slate-400">
                              {forecast.credibleInterval.confidence}% güven aralığı: %{forecast.credibleInterval.lower}{' '}
                              – %{forecast.credibleInterval.upper}
                            </p>
                            {forecast.sparkline.length > 0 && (
                              <div className="mt-3 flex h-12 items-end gap-1" role="img" aria-label={ariaLabel}>
                                {forecast.sparkline.map((point, index) => {
                                  const normalized = Math.max(point.regressionRatio, 0) / sparklineMaxLocal;
                                  const height = Math.max(6, Math.round(normalized * 48));
                                  return (
                                    <span
                                      key={`${forecast.stage}-spark-${index}`}
                                      className="w-2 rounded-full bg-amber-400/60"
                                      style={{ height: `${height}px` }}
                                      title={`${new Date(point.timestamp).toISOString().slice(0, 10)} – %${Math.round(
                                        Math.max(0, point.regressionRatio) * 100,
                                      )}`}
                                    />
                                  );
                                })}
                              </div>
                            )}
                          </li>
                        );
                      })}
                    </ul>
                  )}
                </div>
                <div
                  data-testid="risk-sandbox-card"
                  className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4 shadow shadow-slate-950/30"
                >
                  <header className="flex flex-col gap-1 sm:flex-row sm:items-baseline sm:justify-between">
                    <div>
                      <h4 className="text-sm font-semibold text-white">What-if Risk Sandbox</h4>
                      <p className="text-xs text-slate-400">
                        Kapsam ve test başarısızlığı varsayımlarını değiştirerek olası regresyon dağılımlarını
                        istemci tarafında simüle edin.
                      </p>
                    </div>
                    {sandboxLastRunLabel && (
                      <p className="text-xs text-slate-400">Son çalıştırma: {sandboxLastRunLabel}</p>
                    )}
                  </header>
                  <div className="mt-3 space-y-4">
                    <div>
                      <label
                        htmlFor="sandbox-coverage"
                        className="flex items-center justify-between text-xs font-semibold uppercase tracking-wide text-slate-400"
                      >
                        Projeksiyon kapsam artışı
                        <span className="text-slate-200">+%{sandboxParams.coverageLift}</span>
                      </label>
                      <input
                        id="sandbox-coverage"
                        type="range"
                        min={0}
                        max={50}
                        step={1}
                        value={sandboxParams.coverageLift}
                        onChange={handleSandboxParamChange('coverageLift')}
                        className="mt-2 w-full"
                      />
                      <p className="mt-1 text-[11px] text-slate-400">
                        Daha yüksek kapsam artışı değerleri regresyon olasılığının azalacağını varsayar.
                      </p>
                    </div>
                    <div>
                      <label
                        htmlFor="sandbox-failure"
                        className="flex items-center justify-between text-xs font-semibold uppercase tracking-wide text-slate-400"
                      >
                        Test başarısızlığı şiddeti
                        <span className="text-slate-200">+%{sandboxParams.failureRate}</span>
                      </label>
                      <input
                        id="sandbox-failure"
                        type="range"
                        min={0}
                        max={40}
                        step={1}
                        value={sandboxParams.failureRate}
                        onChange={handleSandboxParamChange('failureRate')}
                        className="mt-2 w-full"
                      />
                      <p className="mt-1 text-[11px] text-slate-400">
                        Daha yüksek şiddet varsayımı beklenen başarısızlık frekansını artırır.
                      </p>
                    </div>
                    <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                      <button
                        type="button"
                        onClick={handleSandboxRun}
                        className="inline-flex items-center justify-center rounded-full bg-brand px-4 py-2 text-sm font-semibold text-slate-950 shadow shadow-brand/40 transition hover:bg-brand/90"
                      >
                        Simülasyonu çalıştır
                      </button>
                      <p className="text-[11px] text-slate-400">İterasyon: {sandboxParams.iterations.toLocaleString('tr-TR')}</p>
                    </div>
                    {sandboxError && (
                      <p className="text-xs text-rose-300">{sandboxError}</p>
                    )}
                    {sandboxResult && (
                      <div className="space-y-4" data-testid="risk-sandbox-results">
                        <div className="grid gap-3 sm:grid-cols-2">
                          <div className="rounded-xl border border-slate-800/60 bg-slate-900/50 p-3">
                            <h5 className="text-xs font-semibold uppercase tracking-wide text-slate-400">Özet</h5>
                            <ul className="mt-2 space-y-1 text-xs text-slate-300">
                              <li data-testid="sandbox-average-risk">
                                Tahmini ortalama risk: %{sandboxResult.averageRisk.toFixed(1)}
                              </li>
                              <li data-testid="sandbox-regression-probability">
                                Regresyon olasılığı: %{sandboxResult.regressionProbability.toFixed(1)}
                              </li>
                              <li data-testid="sandbox-expected-failures">
                                Beklenen başarısız aşama: {sandboxResult.expectedFailures.toFixed(2)} /{' '}
                                {Math.max(1, stageRisk.forecasts.length)}
                              </li>
                            </ul>
                          </div>
                          <div className="rounded-xl border border-slate-800/60 bg-slate-900/50 p-3">
                            <h5 className="text-xs font-semibold uppercase tracking-wide text-slate-400">Sınıf payları</h5>
                            <ul className="mt-2 space-y-1 text-xs text-slate-300" data-testid="sandbox-classifications">
                              {sandboxResult.classifications.map((entry) => (
                                <li key={entry.classification} className="flex items-center justify-between">
                                  <span className="capitalize">{entry.classification}</span>
                                  <span>%{(entry.share * 100).toFixed(1)}</span>
                                </li>
                              ))}
                            </ul>
                          </div>
                        </div>
                        <div>
                          <h5 className="text-xs font-semibold uppercase tracking-wide text-slate-400">Regresyon dağılımı</h5>
                          <ul className="mt-2 space-y-2" data-testid="sandbox-distribution">
                            {sandboxResult.distribution.map((bucket) => (
                              <li key={`distribution-${bucket.failures}`} className="text-xs text-slate-300">
                                <div className="flex items-center justify-between">
                                  <span>{bucket.failures} regresyon</span>
                                  <span>%{(bucket.probability * 100).toFixed(1)}</span>
                                </div>
                                <div className="mt-1 h-2 rounded-full bg-slate-800/80">
                                  <div
                                    data-testid="sandbox-distribution-bar"
                                    data-failures={bucket.failures}
                                    className="h-2 rounded-full bg-brand/60"
                                    style={{
                                      width: `${Math.min(100, Math.max(0, bucket.probability * 100)).toFixed(1)}%`,
                                    }}
                                  />
                                </div>
                              </li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
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
            {!canViewLedger ? (
              <p className="text-sm text-slate-400">Ledger verilerine erişim yetkiniz yok.</p>
            ) : (
              <>
                <div
                  data-testid="proof-explorer-card"
                  className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4 shadow shadow-slate-950/30"
                >
                  <header className="flex flex-col gap-1 sm:flex-row sm:items-baseline sm:justify-between">
                    <div>
                      <h3 className="text-lg font-semibold text-white">Merkle kanıt gezgini</h3>
                      <p className="text-xs text-slate-400">
                        Manifest dosyalarının Merkle ağaç yolunu ve doğrulama sonuçlarını inceleyin.
                      </p>
                    </div>
                    {proofExplorer?.lastUpdated && (
                      <p className="text-xs text-slate-400">Güncelleme: {proofExplorer.lastUpdated}</p>
                    )}
                  </header>
                  {proofExplorer ? (
                    <div className="mt-3 space-y-4">
                      <dl className="grid gap-3 text-xs text-slate-300 sm:grid-cols-2">
                        <div>
                          <dt className="font-semibold uppercase tracking-wide text-slate-500">Manifest</dt>
                          <dd data-testid="proof-manifest-id" className="text-white">
                            {proofExplorer.manifestId}
                          </dd>
                        </div>
                        <div>
                          <dt className="font-semibold uppercase tracking-wide text-slate-500">Ledger iş ID</dt>
                          <dd>{proofExplorer.jobId ?? '—'}</dd>
                        </div>
                        <div>
                          <dt className="font-semibold uppercase tracking-wide text-slate-500">Merkle kökü</dt>
                          <dd>{shortHash(proofExplorer.merkle?.root ?? null)}</dd>
                        </div>
                        <div>
                          <dt className="font-semibold uppercase tracking-wide text-slate-500">Snapshot</dt>
                          <dd>{proofExplorer.merkle?.snapshotId ?? '—'}</dd>
                        </div>
                      </dl>
                      {proofExplorer.files.length > 0 ? (
                        <ul className="space-y-2" data-testid="proof-file-list">
                          {proofExplorer.files.map((file) => {
                            const isSelected = proofExplorer.selectedPath === file.path;
                            const statusLabel = !file.hasProof
                              ? 'Kanıt yok'
                              : file.verified
                              ? 'Doğrulandı'
                              : 'Beklemede';
                            return (
                              <li
                                key={file.path}
                                className={`rounded-xl border border-slate-800/60 bg-slate-900/50 p-3 text-xs transition ${
                                  isSelected ? 'border-brand/60 shadow shadow-brand/30' : ''
                                }`}
                              >
                                <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                                  <div>
                                    <button
                                      type="button"
                                      onClick={() => file.hasProof && dispatch({ type: 'select-proof', path: file.path })}
                                      disabled={!file.hasProof}
                                      aria-pressed={isSelected}
                                      className={`text-left text-sm font-semibold transition ${
                                        file.hasProof
                                          ? 'text-white hover:text-brand focus:outline-none focus:ring-2 focus:ring-brand/60'
                                          : 'text-slate-500'
                                      }`}
                                    >
                                      {file.path}
                                    </button>
                                    <p className="text-[11px] text-slate-400">SHA-256: {shortHash(file.sha256)}</p>
                                  </div>
                                  <div className="text-right">
                                    <span
                                      data-testid={`proof-status-${file.path}`}
                                      className={`inline-flex items-center rounded-full px-2 py-1 text-[11px] font-semibold ${
                                        !file.hasProof
                                          ? 'bg-slate-700/40 text-slate-300'
                                          : file.verified
                                          ? 'bg-emerald-500/20 text-emerald-200'
                                          : 'bg-amber-500/20 text-amber-200'
                                      }`}
                                    >
                                      {statusLabel}
                                    </span>
                                  </div>
                                </div>
                              </li>
                            );
                          })}
                        </ul>
                      ) : (
                        <p className="text-xs text-slate-300">
                          Manifest dosyaları yükleniyor. Kanıt olayları geldiğinde liste otomatik güncellenecek.
                        </p>
                      )}
                      <div className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-3 text-xs text-slate-200">
                        {selectedProofEntry ? (
                          <div className="space-y-2" data-testid="proof-details">
                            <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
                              <div>
                                <p className="text-sm font-semibold text-white">{selectedProofEntry.path}</p>
                                <p className="text-[11px] text-slate-400">
                                  Durum:{' '}
                                  {selectedProofEntry.loading
                                    ? 'Kanıt yükleniyor…'
                                    : selectedProofEntry.error
                                    ? `Hata: ${selectedProofEntry.error}`
                                    : selectedProofEntry.verified
                                    ? 'Merkle doğrulaması başarılı'
                                    : 'Doğrulama bekleniyor'}
                                </p>
                              </div>
                              {selectedProofEntry.error && (
                                <button
                                  type="button"
                                  onClick={() => dispatch({ type: 'select-proof', path: selectedProofEntry.path })}
                                  className="rounded-full border border-rose-500/40 px-2 py-1 text-[11px] font-semibold text-rose-200 hover:border-rose-400"
                                >
                                  Yeniden dene
                                </button>
                              )}
                            </div>
                            {parsedProof ? (
                              <div className="space-y-2">
                                <dl className="grid gap-2 sm:grid-cols-2">
                                  <div>
                                    <dt className="font-semibold uppercase tracking-wide text-slate-500">Yaprak etiketi</dt>
                                    <dd data-testid="proof-leaf-label">{parsedProof.leafLabel || '—'}</dd>
                                  </div>
                                  <div>
                                    <dt className="font-semibold uppercase tracking-wide text-slate-500">Yaprak tipi</dt>
                                    <dd>{parsedProof.leafType}</dd>
                                  </div>
                                  <div>
                                    <dt className="font-semibold uppercase tracking-wide text-slate-500">Yaprak hash</dt>
                                    <dd data-testid="proof-leaf-hash">{shortHash(parsedProof.leafHash)}</dd>
                                  </div>
                                  <div>
                                    <dt className="font-semibold uppercase tracking-wide text-slate-500">Kök hash</dt>
                                    <dd>{shortHash(parsedProof.merkleRoot)}</dd>
                                  </div>
                                </dl>
                                <div>
                                  <h5 className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">
                                    Kanıt yolu
                                  </h5>
                                  {parsedProof.path.length > 0 ? (
                                    <ul className="mt-1 space-y-1" data-testid="proof-path">
                                      {parsedProof.path.map((node, index) => (
                                        <li
                                          key={`${node.position}-${node.hash}-${index}`}
                                          data-testid="proof-path-node"
                                          className="flex items-center justify-between rounded-lg border border-slate-800/50 bg-slate-900/60 px-2 py-1"
                                        >
                                          <span className="font-semibold text-slate-200">{node.position.toUpperCase()}</span>
                                          <span className="font-mono text-[11px] text-slate-400">{shortHash(node.hash)}</span>
                                        </li>
                                      ))}
                                    </ul>
                                  ) : (
                                    <p className="mt-1 text-[11px] text-slate-400">Yol düğümü bulunamadı.</p>
                                  )}
                                </div>
                              </div>
                            ) : !selectedProofEntry.loading && !selectedProofEntry.error ? (
                              <p className="text-[11px] text-slate-400">
                                Kanıt çözümü bekleniyor. Kanıt dosyası doğrulandığında yol bilgisi burada gösterilecek.
                              </p>
                            ) : null}
                          </div>
                        ) : (
                          <p className="text-[11px] text-slate-400">
                            Kanıtları incelemek için listeden bir dosya seçin.
                          </p>
                        )}
                      </div>
                    </div>
                  ) : (
                    <p className="mt-3 text-xs text-slate-300">
                      Henüz Merkle kanıtı alınmadı. Paketleme tamamlandığında kanıtlar burada gösterilecek.
                    </p>
                  )}
                </div>

                <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4 shadow shadow-slate-950/30">
                  <header className="flex items-baseline justify-between">
                    <div>
                      <h3 className="text-lg font-semibold text-white">Ledger kök farkları</h3>
                      <p className="text-xs text-slate-400">
                        Her kayıt için bir önceki ve yeni ledger kökü arasındaki fark konumunu görüntüler.
                      </p>
                    </div>
                  </header>

                  {state.ledgerDiffs.length > 0 ? (
                    <ul className="mt-3 space-y-3">
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
                    <p className="mt-3 text-sm text-slate-300">
                      Henüz ledger kaydı alınmadı. Yeni manifestler eklendiğinde farklar burada listelenecek.
                    </p>
                  )}
                </div>
              </>
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
