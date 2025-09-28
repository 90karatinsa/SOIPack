import { Alert, Badge, Card, EmptyState, PageHeader, Skeleton, Table } from '@bora/ui-kit';
import { useEffect, useMemo, useState } from 'react';

import { useT } from '../providers/I18nProvider';
import {
  ApiError,
  listJobs,
  listReviews,
  fetchComplianceSummary,
  type ComplianceSummaryLatest,
  type QueueMetricsResponse,
  type ReviewResource,
} from '../services/api';

type DashboardPageProps = {
  token?: string;
  license?: string;
};

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
      return;
    }

    const queueController = new AbortController();
    const reviewController = new AbortController();
    const complianceController = new AbortController();

    setQueueState((previous) => ({ ...previous, loading: true, error: null }));
    setReviewState((previous) => ({ ...previous, loading: true, error: null }));
    setComplianceState((previous) => ({ ...previous, loading: true, error: null }));

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

    return () => {
      queueController.abort();
      reviewController.abort();
      complianceController.abort();
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
          <Alert
            data-testid="compliance-error"
            title={t('dashboard.complianceErrorTitle')}
            description={complianceState.error}
            variant="error"
          />
        ) : !complianceSummary ? (
          <EmptyState
            data-testid="compliance-empty"
            title={t('dashboard.complianceEmpty')}
            description=""
          />
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
