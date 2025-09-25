import { Alert, Card, EmptyState, PageHeader, Skeleton, Table } from '@bora/ui-kit';
import { useEffect, useMemo, useState } from 'react';

import { useT } from '../providers/I18nProvider';
import {
  ApiError,
  listJobs,
  listReviews,
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
  const t = useT();
  const trimmedToken = token.trim();
  const trimmedLicense = license.trim();

  useEffect(() => {
    if (!trimmedToken || !trimmedLicense) {
      setQueueState({ loading: false, error: t('dashboard.credentialsRequired'), metrics: null });
      setReviewState({ loading: false, error: t('dashboard.credentialsRequired'), reviews: [] });
      return;
    }

    const queueController = new AbortController();
    const reviewController = new AbortController();

    setQueueState((previous) => ({ ...previous, loading: true, error: null }));
    setReviewState((previous) => ({ ...previous, loading: true, error: null }));

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

    return () => {
      queueController.abort();
      reviewController.abort();
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

  return (
    <div className="space-y-8">
      <PageHeader
        title={t('dashboard.title')}
        description={t('dashboard.description')}
        breadcrumb={[{ label: t('dashboard.title') }]}
      />

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
