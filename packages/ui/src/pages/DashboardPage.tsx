import { Alert, Badge, Button, Card, EmptyState, PageHeader, Skeleton, Table } from '@bora/ui-kit';
import { useCallback, useEffect, useMemo, useState, type ComponentProps } from 'react';

import { useT } from '../providers/I18nProvider';
import {
  ApiError,
  listJobs,
  listReviews,
  fetchComplianceSummary,
  fetchChangeRequests,
  fetchRemediationPlanSummary,
  fetchServiceMetadata,
  type ComplianceSummaryLatest,
  type ServiceMetadata,
  type QueueMetricsResponse,
  type ReviewResource,
  type ChangeRequestItem,
  type RemediationPlanSummary,
  type RemediationPlanPriority,
  type RemediationArtifactSummary,
} from '../services/api';

type DashboardPageProps = {
  token?: string;
  license?: string;
};

const CHANGE_IMPACT_DISPLAY_LIMIT = 5;
const REMEDIATION_ACTION_DISPLAY_LIMIT = 4;

interface QueueMetrics {
  total: number;
  queued: number;
  running: number;
  completed: number;
  failed: number;
}

const deriveQueueMetrics = (payload: QueueMetricsResponse): QueueMetrics => {
  const counts = payload.jobs.reduce(
    (acc, job) => {
      acc.total += 1;
      acc[job.status] = (acc[job.status] ?? 0) + 1;
      return acc;
    },
    { total: 0, queued: 0, running: 0, completed: 0, failed: 0 } as QueueMetrics,
  );
  return counts;
};

export default function DashboardPage({ token = '', license = '' }: DashboardPageProps) {
  const [queueState, setQueueState] = useState<{
    loading: boolean;
    error: string | null;
    metrics: QueueMetrics | null;
  }>({ loading: true, error: null, metrics: null });
  const [reviewState, setReviewState] = useState<{
    loading: boolean;
    error: string | null;
    reviews: ReviewResource[];
  }>({ loading: true, error: null, reviews: [] });
  const [complianceState, setComplianceState] = useState<{
    loading: boolean;
    error: string | null;
    summary: ComplianceSummaryLatest | null;
    computedAt: string | null;
  }>({ loading: true, error: null, summary: null, computedAt: null });
  const [changeRequestState, setChangeRequestState] = useState<{
    loading: boolean;
    error: string | null;
    items: ChangeRequestItem[];
    fetchedAt: string | null;
  }>({ loading: true, error: null, items: [], fetchedAt: null });
  const [remediationPlanState, setRemediationPlanState] = useState<{
    loading: boolean;
    error: string | null;
    plan: RemediationPlanSummary | null;
  }>({ loading: true, error: null, plan: null });
  const [serviceMetadataState, setServiceMetadataState] = useState<{
    loading: boolean;
    error: string | null;
    metadata: ServiceMetadata | null;
  }>({ loading: true, error: null, metadata: null });
  const t = useT();
  const trimmedToken = token.trim();
  const trimmedLicense = license.trim();

  useEffect(() => {
    if (!trimmedToken || !trimmedLicense) {
      setQueueState({ loading: false, error: t('dashboard.credentialsRequired'), metrics: null });
      setReviewState({ loading: false, error: t('dashboard.credentialsRequired'), reviews: [] });
      setComplianceState({
        loading: false,
        error: t('dashboard.credentialsRequired'),
        summary: null,
        computedAt: null,
      });
      setChangeRequestState({
        loading: false,
        error: t('dashboard.credentialsRequired'),
        items: [],
        fetchedAt: null,
      });
      setRemediationPlanState({
        loading: false,
        error: t('dashboard.credentialsRequired'),
        plan: null,
      });
      setServiceMetadataState({
        loading: false,
        error: t('dashboard.credentialsRequired'),
        metadata: null,
      });
      return;
    }

    const queueController = new AbortController();
    const reviewController = new AbortController();
    const complianceController = new AbortController();
    const changeRequestController = new AbortController();
    const remediationController = new AbortController();
    const serviceMetadataController = new AbortController();

    setQueueState((previous) => ({ ...previous, loading: true, error: null }));
    setReviewState((previous) => ({ ...previous, loading: true, error: null }));
    setComplianceState((previous) => ({ ...previous, loading: true, error: null }));
    setChangeRequestState((previous) => ({ ...previous, loading: true, error: null }));
    setRemediationPlanState((previous) => ({ ...previous, loading: true, error: null }));
    setServiceMetadataState((previous) => ({ ...previous, loading: true, error: null }));

    listJobs({
      token: trimmedToken,
      license: trimmedLicense,
      status: ['queued', 'running', 'completed', 'failed'],
      limit: 200,
      signal: queueController.signal,
    })
      .then((response) => {
        setQueueState({ loading: false, error: null, metrics: deriveQueueMetrics(response) });
      })
      .catch((error) => {
        if (queueController.signal.aborted) {
          return;
        }
        const message =
          error instanceof ApiError ? error.message : t('dashboard.queueError');
        setQueueState({ loading: false, error: message, metrics: null });
      });

    listReviews({
      token: trimmedToken,
      license: trimmedLicense,
      status: 'pending',
      limit: 10,
      signal: reviewController.signal,
    })
      .then((response) => {
        setReviewState({ loading: false, error: null, reviews: response.reviews });
      })
      .catch((error) => {
        if (reviewController.signal.aborted) {
          return;
        }
        const message =
          error instanceof ApiError ? error.message : t('dashboard.reviewError');
        setReviewState({ loading: false, error: message, reviews: [] });
      });

    fetchComplianceSummary({
      token: trimmedToken,
      license: trimmedLicense,
      signal: complianceController.signal,
    })
      .then((response) => {
        setComplianceState({
          loading: false,
          error: null,
          summary: response.latest,
          computedAt: response.computedAt,
        });
      })
      .catch((error) => {
        if (complianceController.signal.aborted) {
          return;
        }
        const message =
          error instanceof ApiError ? error.message : t('dashboard.complianceError');
        setComplianceState({ loading: false, error: message, summary: null, computedAt: null });
      });

    fetchChangeRequests({
      token: trimmedToken,
      license: trimmedLicense,
      signal: changeRequestController.signal,
    })
      .then((response) => {
        setChangeRequestState({
          loading: false,
          error: null,
          items: response.items,
          fetchedAt: response.fetchedAt,
        });
      })
      .catch((error) => {
        if (changeRequestController.signal.aborted) {
          return;
        }
        const message =
          error instanceof ApiError ? error.message : t('dashboard.changeRequestsError');
        setChangeRequestState({ loading: false, error: message, items: [], fetchedAt: null });
      });

    fetchRemediationPlanSummary({
      token: trimmedToken,
      license: trimmedLicense,
      signal: remediationController.signal,
    })
      .then((response) => {
        setRemediationPlanState({ loading: false, error: null, plan: response });
      })
      .catch((error) => {
        if (remediationController.signal.aborted) {
          return;
        }
        const message =
          error instanceof ApiError ? error.message : t('dashboard.remediationPlanError');
        setRemediationPlanState({ loading: false, error: message, plan: null });
      });

    fetchServiceMetadata({
      token: trimmedToken,
      license: trimmedLicense,
      signal: serviceMetadataController.signal,
    })
      .then((response) => {
        setServiceMetadataState({ loading: false, error: null, metadata: response });
      })
      .catch((error) => {
        if (serviceMetadataController.signal.aborted) {
          return;
        }
        const message = error instanceof ApiError ? error.message : t('dashboard.sbomError');
        setServiceMetadataState({ loading: false, error: message, metadata: null });
      });

    return () => {
      queueController.abort();
      reviewController.abort();
      complianceController.abort();
      changeRequestController.abort();
      remediationController.abort();
      serviceMetadataController.abort();
    };
  }, [trimmedToken, trimmedLicense, t]);

  const queueMetrics = queueState.metrics ?? {
    total: 0,
    queued: 0,
    running: 0,
    completed: 0,
    failed: 0,
  };

  const reviewRows = useMemo(
    () =>
      reviewState.reviews.map((review) => ({
        id: review.id,
        target: review.target.kind,
        approvers: review.approvers
          .map((approver) => `${approver.id} (${approver.status})`)
          .join(', '),
        updatedAt: new Date(review.updatedAt).toLocaleString(),
      })),
    [reviewState.reviews],
  );

  const complianceSummary = complianceState.summary;
  const complianceTimestamp =
    complianceSummary?.generatedAt ?? complianceSummary?.createdAt ?? complianceState.computedAt;
  const formattedComplianceTimestamp = complianceTimestamp
    ? new Date(complianceTimestamp).toLocaleString()
    : '—';
  const readinessPercent = complianceSummary?.summary.total
    ? Math.round((complianceSummary.summary.covered / complianceSummary.summary.total) * 100)
    : 0;
  const complianceReady =
    complianceSummary?.summary.missing === 0 &&
    complianceSummary?.gaps.openObjectiveCount === 0;
  const independenceSummary = complianceSummary?.independence ?? null;
  const independentObjectives = useMemo(
    () => independenceSummary?.objectives.filter((objective) => objective.independence !== 'none') ?? [],
    [independenceSummary],
  );
  const openIndependentObjectives = useMemo(
    () => independentObjectives.filter((objective) => objective.status !== 'covered'),
    [independentObjectives],
  );
  const independenceCounts = useMemo(
    () =>
      openIndependentObjectives.reduce(
        (acc, objective) => {
          if (objective.status === 'missing') {
            acc.missing += 1;
          } else if (objective.status === 'partial') {
            acc.partial += 1;
          }
          return acc;
        },
        { missing: 0, partial: 0 },
      ),
    [openIndependentObjectives],
  );
  const changeImpactEntries = complianceSummary?.changeImpact ?? [];
  const changeImpactSeverityBuckets = useMemo(
    () => [
      {
        id: 'critical' as const,
        threshold: 0.75,
        variant: 'error',
        label: t('dashboard.changeImpactSeverityCritical'),
      },
      {
        id: 'high' as const,
        threshold: 0.5,
        variant: 'warning',
        label: t('dashboard.changeImpactSeverityHigh'),
      },
      {
        id: 'medium' as const,
        threshold: 0.25,
        variant: 'info',
        label: t('dashboard.changeImpactSeverityMedium'),
      },
      {
        id: 'low' as const,
        threshold: 0,
        variant: 'neutral',
        label: t('dashboard.changeImpactSeverityLow'),
      },
    ],
    [t],
  );
  const changeImpactSummary = useMemo(() => {
    type SeverityKey = (typeof changeImpactSeverityBuckets)[number]['id'];
    const resolveBucket = (severity: number) => {
      for (const bucket of changeImpactSeverityBuckets) {
        if (severity >= bucket.threshold) {
          return bucket;
        }
      }
      return changeImpactSeverityBuckets[changeImpactSeverityBuckets.length - 1];
    };

    const counts = Object.fromEntries(
      changeImpactSeverityBuckets.map((bucket) => [bucket.id, 0] as const),
    ) as Record<SeverityKey, number>;

    changeImpactEntries.forEach((entry) => {
      const bucket = resolveBucket(entry.severity);
      counts[bucket.id] += 1;
    });

    const sorted = [...changeImpactEntries].sort((a, b) => {
      if (b.severity === a.severity) {
        return a.id.localeCompare(b.id);
      }
      return b.severity - a.severity;
    });

    const topEntries = sorted.slice(0, CHANGE_IMPACT_DISPLAY_LIMIT).map((entry) => ({
      entry,
      bucket: resolveBucket(entry.severity),
    }));

    return { counts, topEntries };
  }, [changeImpactEntries, changeImpactSeverityBuckets]);
  const changeImpactCounts = changeImpactSummary.counts;
  const changeImpactTopEntries = changeImpactSummary.topEntries;
  const changeImpactRemaining = Math.max(
    0,
    changeImpactEntries.length - changeImpactTopEntries.length,
  );
  const changeImpactTypeLabels = useMemo(
    () => ({
      requirement: t('dashboard.changeImpactType.requirement'),
      test: t('dashboard.changeImpactType.test'),
      code: t('dashboard.changeImpactType.code'),
      design: t('dashboard.changeImpactType.design'),
    }),
    [t],
  );
  const changeImpactStateLabels = useMemo(
    () => ({
      added: t('dashboard.changeImpactState.added'),
      removed: t('dashboard.changeImpactState.removed'),
      modified: t('dashboard.changeImpactState.modified'),
      impacted: t('dashboard.changeImpactState.impacted'),
    }),
    [t],
  );
  const formatChangeImpactReasons = (reasons: string[]) => {
    const filtered = reasons.filter((reason) => reason && reason.trim().length > 0);
    if (filtered.length === 0) {
      return t('dashboard.changeImpactNoReason');
    }
    if (filtered.length === 1) {
      return filtered[0];
    }
    if (filtered.length === 2) {
      return `${filtered[0]} • ${filtered[1]}`;
    }
    const remaining = filtered.length - 2;
    return `${filtered[0]} • ${filtered[1]} (+${remaining} ${t(
      'dashboard.changeImpactMoreReasons',
    )})`;
  };
  const remediationPlan = remediationPlanState.plan;
  const remediationActions = remediationPlan?.actions ?? [];
  const remediationGeneratedAt = remediationPlan?.generatedAt ?? null;
  const formattedRemediationGeneratedAt = remediationGeneratedAt
    ? new Date(remediationGeneratedAt).toLocaleString()
    : '—';
  const remediationTopActions = remediationActions.slice(0, REMEDIATION_ACTION_DISPLAY_LIMIT);
  const remediationRemaining = Math.max(0, remediationActions.length - remediationTopActions.length);
  const sbomMetadata = serviceMetadataState.metadata?.sbom ?? null;
  const rawSbomUrl = sbomMetadata?.url?.trim() ?? '';
  const sbomUrl = rawSbomUrl.length > 0 ? rawSbomUrl : null;
  const sbomSha256Value = sbomMetadata?.sha256?.trim() ?? '';
  const sbomSha256 = sbomSha256Value.length > 0 ? sbomSha256Value : null;
  const sbomVerified = sbomMetadata?.verified === true;
  const hasSbomMetadata = Boolean(sbomUrl || sbomSha256);
  const remediationPriorityLabels = useMemo(
    () => ({
      critical: t('dashboard.remediationPriority.critical'),
      high: t('dashboard.remediationPriority.high'),
      medium: t('dashboard.remediationPriority.medium'),
      low: t('dashboard.remediationPriority.low'),
    }),
    [t],
  );
  const handleCopySbomDigest = useCallback(async () => {
    if (!sbomSha256) {
      return;
    }
    if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
      try {
        await navigator.clipboard.writeText(sbomSha256);
      } catch {
        // Clipboard errors can be safely ignored.
      }
    }
  }, [sbomSha256]);
  const remediationPriorityVariants: Record<
    RemediationPlanPriority,
    ComponentProps<typeof Badge>['variant']
  > = {
    critical: 'error',
    high: 'warning',
    medium: 'info',
    low: 'neutral',
  };
  const remediationCategoryLabels = useMemo(
    () => ({
      analysis: t('dashboard.remediationIssue.gap.analysis'),
      tests: t('dashboard.remediationIssue.gap.tests'),
      coverage: t('dashboard.remediationIssue.gap.coverage'),
      trace: t('dashboard.remediationIssue.gap.trace'),
      reviews: t('dashboard.remediationIssue.gap.reviews'),
      plans: t('dashboard.remediationIssue.gap.plans'),
      standards: t('dashboard.remediationIssue.gap.standards'),
      configuration: t('dashboard.remediationIssue.gap.configuration'),
      quality: t('dashboard.remediationIssue.gap.quality'),
      issues: t('dashboard.remediationIssue.gap.issues'),
      conformity: t('dashboard.remediationIssue.gap.conformity'),
    }),
    [t],
  );
  const remediationIndependenceLabels = useMemo(
    () => ({
      required: t('dashboard.remediationIssue.independence.required'),
      recommended: t('dashboard.remediationIssue.independence.recommended'),
      none: t('dashboard.remediationIssue.independence.none'),
    }),
    [t],
  );
  const remediationArtifactLabels = useMemo(
    () => ({
      plan: t('dashboard.remediationArtifact.plan'),
      standard: t('dashboard.remediationArtifact.standard'),
      review: t('dashboard.remediationArtifact.review'),
      analysis: t('dashboard.remediationArtifact.analysis'),
      test: t('dashboard.remediationArtifact.test'),
      coverage_stmt: t('dashboard.remediationArtifact.coverage_stmt'),
      coverage_dec: t('dashboard.remediationArtifact.coverage_dec'),
      coverage_mcdc: t('dashboard.remediationArtifact.coverage_mcdc'),
      trace: t('dashboard.remediationArtifact.trace'),
      cm_record: t('dashboard.remediationArtifact.cm_record'),
      qa_record: t('dashboard.remediationArtifact.qa_record'),
      problem_report: t('dashboard.remediationArtifact.problem_report'),
      conformity: t('dashboard.remediationArtifact.conformity'),
      design: t('dashboard.remediationArtifact.design'),
    }),
    [t],
  );
  const resolveRemediationIssueLabel = (
    issue: RemediationPlanSummary['actions'][number]['issues'][number],
  ): string => {
    if (issue.type === 'gap') {
      return (
        remediationCategoryLabels[issue.category as keyof typeof remediationCategoryLabels] ?? issue.category
      );
    }
    return (
      remediationIndependenceLabels[issue.independence as keyof typeof remediationIndependenceLabels] ??
      issue.independence
    );
  };
  const resolveRemediationArtifactLabel = (artifact: RemediationArtifactSummary): string => {
    const localized =
      remediationArtifactLabels[artifact.key as keyof typeof remediationArtifactLabels] ?? artifact.label;
    return localized ?? artifact.key;
  };
  const buildObjectiveLink = (objectiveId: string, objectiveUrl?: string): string => {
    if (objectiveUrl && objectiveUrl.trim().length > 0) {
      return objectiveUrl;
    }
    return `#/compliance?objective=${encodeURIComponent(objectiveId)}`;
  };
  const remediationPlanCard = (
    <div
      className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-4"
      data-testid="remediation-plan-card"
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold text-white">{t('dashboard.remediationPlanTitle')}</h3>
          <p className="text-xs text-neutral-400">{t('dashboard.remediationPlanSubtitle')}</p>
        </div>
        <span className="text-xs text-neutral-500">
          {t('dashboard.remediationPlanGeneratedAt')} {formattedRemediationGeneratedAt}
        </span>
      </div>
      <div className="mt-3 space-y-3 text-sm text-neutral-300">
        {remediationPlanState.loading ? (
          <div data-testid="remediation-plan-loading" className="space-y-2">
            {Array.from({ length: 3 }).map((_, index) => (
              <Skeleton key={index} className="h-16 w-full" />
            ))}
          </div>
        ) : remediationPlanState.error ? (
          <Alert
            data-testid="remediation-plan-error"
            title={t('dashboard.remediationPlanErrorTitle')}
            description={remediationPlanState.error}
            variant="error"
          />
        ) : remediationActions.length === 0 ? (
          <p className="text-sm text-neutral-400" data-testid="remediation-plan-empty">
            {t('dashboard.remediationPlanEmpty')}
          </p>
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-2 text-xs text-neutral-300">
              <Badge variant="neutral" data-testid="remediation-plan-total">
                {t('dashboard.remediationPlanActionsTotal')}: {remediationActions.length}
              </Badge>
            </div>
            <ul className="space-y-3" data-testid="remediation-plan-list">
              {remediationTopActions.map((action) => {
                const objectiveHref = buildObjectiveLink(action.objectiveId, action.objectiveUrl);
                const subtitle: string[] = [];
                if (action.stage) {
                  subtitle.push(action.stage);
                }
                if (action.table) {
                  subtitle.push(action.table);
                }
                return (
                  <li
                    key={action.objectiveId}
                    className="rounded-lg border border-slate-800/60 bg-slate-900/30 p-3"
                    data-testid={`remediation-action-${action.objectiveId}`}
                  >
                    <div className="flex flex-wrap items-start justify-between gap-2">
                      <div className="min-w-0">
                        <a
                          href={objectiveHref}
                          target="_blank"
                          rel="noreferrer"
                          className="text-sm font-semibold text-white hover:underline"
                          data-testid={`remediation-objective-${action.objectiveId}`}
                        >
                          {action.objectiveName ?? action.objectiveId}
                        </a>
                        {subtitle.length > 0 ? (
                          <p className="text-xs text-neutral-400">{subtitle.join(' • ')}</p>
                        ) : null}
                      </div>
                      <Badge
                        variant={remediationPriorityVariants[action.priority]}
                        data-testid={`remediation-priority-${action.objectiveId}`}
                      >
                        {remediationPriorityLabels[action.priority]}
                      </Badge>
                    </div>
                    <div className="mt-2 space-y-2 text-xs text-neutral-300">
                      {action.issues.map((issue, issueIndex) => (
                        <div key={`${action.objectiveId}-issue-${issueIndex}`}>
                          <p className="font-semibold text-neutral-200">
                            {resolveRemediationIssueLabel(issue)}
                          </p>
                          {issue.missingArtifacts.length > 0 ? (
                            <div
                              className="mt-1 flex flex-wrap gap-2"
                              data-testid={`remediation-artifacts-${action.objectiveId}-${issueIndex}`}
                            >
                              {issue.missingArtifacts.map((artifact, artifactIndex) => {
                                const label = resolveRemediationArtifactLabel(artifact);
                                if (artifact.url) {
                                  return (
                                    <a
                                      key={`${artifact.key}-${artifactIndex}`}
                                      href={artifact.url}
                                      target="_blank"
                                      rel="noreferrer"
                                      className="rounded-full border border-brand/60 px-2 py-1 text-xs text-brand hover:bg-brand/10"
                                    >
                                      {label}
                                    </a>
                                  );
                                }
                                return (
                                  <span
                                    key={`${artifact.key}-${artifactIndex}`}
                                    className="rounded-full bg-slate-800/70 px-2 py-1 text-xs text-neutral-200"
                                  >
                                    {label}
                                  </span>
                                );
                              })}
                            </div>
                          ) : null}
                        </div>
                      ))}
                    </div>
                    {action.links.length > 0 ? (
                      <div className="mt-3 text-xs text-neutral-300">
                        <p className="text-xs uppercase tracking-wide text-neutral-500">
                          {t('dashboard.remediationPlanLinksLabel')}
                        </p>
                        <ul className="mt-1 space-y-1">
                          {action.links.map((link, linkIndex) => (
                            <li key={`${action.objectiveId}-link-${linkIndex}`}>
                              <a
                                href={link.url}
                                target="_blank"
                                rel="noreferrer"
                                className="text-brand hover:underline"
                              >
                                {link.label}
                              </a>
                            </li>
                          ))}
                        </ul>
                      </div>
                    ) : null}
                  </li>
                );
              })}
            </ul>
            {remediationRemaining > 0 ? (
              <p className="text-xs text-neutral-400" data-testid="remediation-plan-remaining">
                +{remediationRemaining} {t('dashboard.remediationPlanMoreActions')}
              </p>
            ) : null}
          </>
        )}
      </div>
    </div>
  );
  const changeRequests = changeRequestState.items;
  const resolveStatusVariant = (category?: string): 'success' | 'warning' | undefined => {
    if (!category) {
      return undefined;
    }
    const normalized = category.toLowerCase();
    if (normalized.includes('done') || normalized.includes('tamam')) {
      return 'success';
    }
    if (normalized.includes('progress') || normalized.includes('devam') || normalized.includes('to do')) {
      return 'warning';
    }
    return undefined;
  };
  const formatChangeRequestDate = (value?: string) =>
    value && value.trim().length > 0 ? new Date(value).toLocaleString() : '—';

  return (
    <div className="space-y-8">
      <PageHeader
        title={t('dashboard.title')}
        description={t('dashboard.description')}
        breadcrumb={[{ label: t('dashboard.title') }]}
      />

      <section className="space-y-4">
        <h2 className="text-lg font-semibold text-white">{t('dashboard.complianceReadiness')}</h2>
        {complianceState.loading ? (
          <div data-testid="compliance-loading" className="space-y-2">
            <Skeleton className="h-24 w-full" />
          </div>
        ) : complianceState.error ? (
          <div className="space-y-4">
            <Alert
              data-testid="compliance-error"
              title={t('dashboard.complianceErrorTitle')}
              description={complianceState.error}
              variant="error"
            />
            {remediationPlanCard}
          </div>
        ) : !complianceSummary ? (
          <div className="space-y-4">
            <EmptyState
              data-testid="compliance-empty"
              title={t('dashboard.complianceEmpty')}
              description=""
            />
            {remediationPlanCard}
          </div>
        ) : (
          <div className="space-y-4" data-testid="compliance-summary">
            <div className="flex flex-wrap items-center gap-3 text-sm text-neutral-300">
              <Badge
                data-testid="compliance-status"
                variant={complianceReady ? 'success' : 'warning'}
              >
                {complianceReady
                  ? t('dashboard.complianceStatusReady')
                  : t('dashboard.complianceStatusAttention')}
              </Badge>
              <span>
                {t('dashboard.complianceOpenObjectivesLabel')} {complianceSummary.gaps.openObjectiveCount}
              </span>
              <span>
                {t('dashboard.complianceLastComputed')} {formattedComplianceTimestamp}
              </span>
            </div>
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              <Card
                title={t('dashboard.complianceCoverage')}
                description={`${readinessPercent}%`}
              />
              <Card
                title={t('dashboard.complianceCovered')}
                description={complianceSummary.summary.covered.toString()}
              />
              <Card
                title={t('dashboard.compliancePartial')}
                description={complianceSummary.summary.partial.toString()}
              />
              <Card
                title={t('dashboard.complianceMissing')}
                description={complianceSummary.summary.missing.toString()}
              />
            </div>
            <div className="grid gap-4 xl:grid-cols-4">
              <div
                className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-4"
                data-testid="sbom-card"
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <h3 className="text-sm font-semibold text-white">{t('dashboard.sbomTitle')}</h3>
                    <p className="text-xs text-neutral-400">{t('dashboard.sbomSubtitle')}</p>
                  </div>
                  {hasSbomMetadata ? (
                    <Badge
                      variant={sbomVerified ? 'success' : 'warning'}
                      data-testid="sbom-verify-badge"
                    >
                      {sbomVerified ? t('dashboard.sbomVerified') : t('dashboard.sbomUnverified')}
                    </Badge>
                  ) : null}
                </div>
                <div className="mt-3 space-y-3 text-sm text-neutral-300">
                  {serviceMetadataState.loading ? (
                    <div data-testid="sbom-loading" className="space-y-2">
                      <Skeleton className="h-4 w-32" />
                      <Skeleton className="h-4 w-40" />
                    </div>
                  ) : serviceMetadataState.error ? (
                    <Alert
                      data-testid="sbom-error"
                      title={t('dashboard.sbomErrorTitle')}
                      description={serviceMetadataState.error}
                      variant="error"
                    />
                  ) : hasSbomMetadata ? (
                    <>
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-xs uppercase tracking-wide text-neutral-400">
                          {t('dashboard.sbomDigestLabel')}
                        </span>
                        <code
                          className="rounded bg-slate-900 px-2 py-1 font-mono text-xs text-emerald-300"
                          data-testid="sbom-digest"
                        >
                          {sbomSha256 ?? '—'}
                        </code>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={handleCopySbomDigest}
                          disabled={!sbomSha256}
                        >
                          {t('dashboard.sbomCopyDigest')}
                        </Button>
                      </div>
                      {sbomUrl ? (
                        <a
                          href={sbomUrl}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-2 text-sm text-brand hover:underline"
                          data-testid="sbom-download"
                        >
                          {t('dashboard.sbomDownload')}
                        </a>
                      ) : null}
                    </>
                  ) : (
                    <p className="text-sm text-neutral-400" data-testid="sbom-empty">
                      —
                    </p>
                  )}
                </div>
              </div>
              <div
                className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-4"
                data-testid="independence-card"
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <h3 className="text-sm font-semibold text-white">{t('dashboard.independenceTitle')}</h3>
                    <p className="text-xs text-neutral-400">{t('dashboard.independenceSubtitle')}</p>
                  </div>
                  {independenceSummary ? (
                    <div className="flex items-center gap-2">
                      <Badge
                        variant={independenceCounts.missing > 0 ? 'warning' : 'success'}
                        data-testid="independence-missing-count"
                      >
                        {t('dashboard.independenceMissing')}: {independenceCounts.missing}
                      </Badge>
                      <Badge
                        variant={independenceCounts.partial > 0 ? 'warning' : 'success'}
                        data-testid="independence-partial-count"
                      >
                        {t('dashboard.independencePartial')}: {independenceCounts.partial}
                      </Badge>
                    </div>
                  ) : null}
                </div>
                <div className="mt-3 space-y-2 text-sm text-neutral-300">
                  {independenceSummary ? (
                    openIndependentObjectives.length > 0 ? (
                      <>
                        <p className="text-xs uppercase tracking-wide text-neutral-400">
                          {t('dashboard.independenceOpenSummary')}
                        </p>
                        <ul className="space-y-2" data-testid="independence-open-list">
                          {openIndependentObjectives.map((objective) => (
                            <li key={objective.objectiveId} className="flex flex-wrap items-center gap-2">
                              <a
                                href={`#/compliance?objective=${encodeURIComponent(objective.objectiveId)}`}
                                target="_blank"
                                rel="noreferrer"
                                className="text-brand hover:underline"
                                data-testid={`independence-objective-${objective.objectiveId}`}
                              >
                                {objective.objectiveId}
                              </a>
                              <span className="text-xs text-neutral-400">
                                {objective.status === 'missing'
                                  ? t('dashboard.independenceMissing')
                                  : t('dashboard.independencePartial')}
                              </span>
                              {objective.missingArtifacts.length > 0 && (
                                <span className="text-xs text-neutral-500">
                                  ({objective.missingArtifacts.join(', ')})
                                </span>
                              )}
                            </li>
                          ))}
                        </ul>
                      </>
                    ) : (
                      <p className="text-sm text-emerald-300" data-testid="independence-all-clear">
                        {t('dashboard.independenceAllClear')}
                      </p>
                    )
                  ) : (
                    <p className="text-sm text-neutral-400" data-testid="independence-unavailable">
                      {t('dashboard.independenceUnavailable')}
                    </p>
                  )}
                </div>
              </div>
              <div
                className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-4"
                data-testid="change-impact-card"
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <h3
                      id="change-impact-heading"
                      className="text-sm font-semibold text-white"
                    >
                      {t('dashboard.changeImpactTitle')}
                    </h3>
                    <p className="text-xs text-neutral-400">{t('dashboard.changeImpactSubtitle')}</p>
                  </div>
                  {changeImpactEntries.length > 0 ? (
                    <div className="flex flex-wrap gap-2 text-xs text-neutral-300">
                      <Badge variant="neutral" data-testid="change-impact-total">
                        {t('dashboard.changeImpactTotalLabel')}: {changeImpactEntries.length}
                      </Badge>
                      {changeImpactSeverityBuckets.map((bucket) => {
                        const count = changeImpactCounts[bucket.id];
                        if (count === 0) {
                          return null;
                        }
                        return (
                          <Badge
                            key={bucket.id}
                            variant={bucket.variant}
                            data-testid={`change-impact-count-${bucket.id}`}
                          >
                            {bucket.label}: {count}
                          </Badge>
                        );
                      })}
                    </div>
                  ) : null}
                </div>
                <div className="mt-3 space-y-2 text-sm text-neutral-300">
                  {changeImpactEntries.length === 0 ? (
                    <p className="text-sm text-neutral-400" data-testid="change-impact-empty">
                      {t('dashboard.changeImpactEmpty')}
                    </p>
                  ) : (
                    <>
                      <p className="text-xs uppercase tracking-wide text-neutral-400">
                        {t('dashboard.changeImpactTopLabel')}
                      </p>
                      <ul
                        aria-labelledby="change-impact-heading"
                        className="space-y-2"
                        data-testid="change-impact-list"
                      >
                        {changeImpactTopEntries.map(({ entry, bucket }) => {
                          const reasons = formatChangeImpactReasons(entry.reasons);
                          const severityPercent = Math.round(entry.severity * 100);
                          const url = (entry as { url?: string }).url;
                          const stateLabel = changeImpactStateLabels[entry.state];
                          const typeLabel = changeImpactTypeLabels[entry.type];
                          return (
                            <li
                              key={entry.id}
                              className="rounded-lg border border-slate-800/60 bg-slate-900/30 p-3"
                              data-testid={`change-impact-entry-${entry.id}`}
                            >
                              <div className="flex flex-wrap items-center gap-2 text-xs">
                                <Badge variant={bucket.variant} data-testid={`change-impact-severity-${entry.id}`}>
                                  {bucket.label} • {severityPercent}%
                                </Badge>
                                <span className="text-neutral-400">{typeLabel}</span>
                                <span className="text-neutral-400">{stateLabel}</span>
                                <span className="font-medium text-white">
                                  {url ? (
                                    <a
                                      href={url}
                                      target="_blank"
                                      rel="noreferrer"
                                      className="text-brand hover:underline"
                                    >
                                      {entry.id}
                                    </a>
                                  ) : (
                                    entry.id
                                  )}
                                </span>
                              </div>
                              <p className="mt-2 text-xs text-neutral-300">{reasons}</p>
                            </li>
                          );
                        })}
                      </ul>
                      {changeImpactRemaining > 0 ? (
                        <p className="text-xs text-neutral-400" data-testid="change-impact-remaining">
                          +{changeImpactRemaining} {t('dashboard.changeImpactMoreEntries')}
                        </p>
                      ) : null}
                    </>
                  )}
                </div>
              </div>
              {remediationPlanCard}
            </div>
          </div>
        )}
      </section>

      <section className="space-y-4">
        <h2 className="text-lg font-semibold text-white">{t('dashboard.queueMetrics')}</h2>
        {queueState.loading ? (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4" data-testid="queue-loading">
            {Array.from({ length: 4 }).map((_, index) => (
              <Skeleton key={index} className="h-24 w-full" />
            ))}
          </div>
        ) : queueState.error ? (
          <Alert title={t('dashboard.queueErrorTitle')} description={queueState.error} variant="error" />
        ) : (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            <div data-testid="queue-total">
              <Card title={t('dashboard.queueTotal')} description={queueMetrics.total.toString()} />
            </div>
            <div data-testid="queue-queued">
              <Card title={t('dashboard.queueQueued')} description={queueMetrics.queued.toString()} />
            </div>
            <div data-testid="queue-running">
              <Card title={t('dashboard.queueRunning')} description={queueMetrics.running.toString()} />
            </div>
            <div data-testid="queue-completed">
              <Card title={t('dashboard.queueCompleted')} description={queueMetrics.completed.toString()} />
            </div>
          </div>
        )}
      </section>

      <section className="space-y-4">
        <h2 className="text-lg font-semibold text-white">{t('dashboard.changeRequests')}</h2>
        {changeRequestState.loading ? (
          <div data-testid="change-requests-loading" className="space-y-2">
            {Array.from({ length: 3 }).map((_, index) => (
              <Skeleton key={index} className="h-12 w-full" />
            ))}
          </div>
        ) : changeRequestState.error ? (
          <Alert
            data-testid="change-requests-error"
            title={t('dashboard.changeRequestsErrorTitle')}
            description={changeRequestState.error}
            variant="error"
          />
        ) : changeRequests.length === 0 ? (
          <EmptyState
            data-testid="change-requests-empty"
            title={t('dashboard.changeRequestsEmpty')}
            description=""
          />
        ) : (
          <div
            className="overflow-hidden rounded-xl border border-slate-800/60 bg-slate-900/40"
            data-testid="change-requests-table"
          >
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-slate-800 text-left text-sm">
                <thead className="bg-slate-900/80 text-xs uppercase tracking-wide text-slate-400">
                  <tr>
                    <th className="px-4 py-3">{t('dashboard.changeRequestsKey')}</th>
                    <th className="px-4 py-3">{t('dashboard.changeRequestsSummary')}</th>
                    <th className="px-4 py-3">{t('dashboard.changeRequestsStatus')}</th>
                    <th className="px-4 py-3">{t('dashboard.changeRequestsAssignee')}</th>
                    <th className="px-4 py-3">{t('dashboard.changeRequestsAttachments')}</th>
                    <th className="px-4 py-3">{t('dashboard.changeRequestsUpdatedAt')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 text-sm text-neutral-200">
                  {changeRequests.map((item) => (
                    <tr key={item.id} className="hover:bg-slate-900/60">
                      <td className="px-4 py-3">
                        <a
                          href={item.url}
                          target="_blank"
                          rel="noreferrer"
                          className="text-brand hover:underline"
                        >
                          {item.key}
                        </a>
                      </td>
                      <td className="px-4 py-3">{item.summary}</td>
                      <td className="px-4 py-3">
                        <Badge variant={resolveStatusVariant(item.statusCategory)}>{item.status}</Badge>
                      </td>
                      <td className="px-4 py-3">{item.assignee ?? '—'}</td>
                      <td
                        className="px-4 py-3"
                        data-testid={`change-request-attachments-${item.id}`}
                      >
                        {item.attachments.length}
                      </td>
                      <td className="px-4 py-3">{formatChangeRequestDate(item.updatedAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </section>

      <section className="space-y-4">
        <h2 className="text-lg font-semibold text-white">{t('dashboard.pendingReviews')}</h2>
        {reviewState.loading ? (
          <div data-testid="reviews-loading" className="space-y-2">
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
          </div>
        ) : reviewState.error ? (
          <Alert title={t('dashboard.reviewErrorTitle')} description={reviewState.error} variant="error" />
        ) : reviewRows.length === 0 ? (
          <EmptyState title={t('dashboard.noPendingReviews')} description="" />
        ) : (
          <div data-testid="pending-review-table">
            <Table
              columns={[
                { key: 'id', title: t('dashboard.reviewId') },
                { key: 'target', title: t('dashboard.reviewTarget') },
                { key: 'approvers', title: t('dashboard.reviewApprovers') },
                { key: 'updatedAt', title: t('dashboard.reviewUpdatedAt') },
              ]}
              rows={reviewRows}
            />
          </div>
        )}
      </section>
    </div>
  );
}
