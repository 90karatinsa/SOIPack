import { render, screen, waitFor } from '@testing-library/react';
import React from 'react';

import { I18nProvider } from '../providers/I18nProvider';
import DashboardPage from './DashboardPage';
import { listJobs, listReviews, ApiError } from '../services/api';

jest.mock('../services/api', () => {
  const actual = jest.requireActual('../services/api');
  return {
    ...actual,
    listJobs: jest.fn(),
    listReviews: jest.fn(),
  };
});

describe('DashboardPage', () => {
  const mockListJobs = listJobs as jest.MockedFunction<typeof listJobs>;
  const mockListReviews = listReviews as jest.MockedFunction<typeof listReviews>;

  const renderDashboard = (props?: { token?: string; license?: string }) =>
    render(
      <I18nProvider>
        <DashboardPage token={props?.token ?? 'demo-token'} license={props?.license ?? 'demo-license'} />
      </I18nProvider>,
    );

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders queue metrics and pending reviews when data resolves', async () => {
    const now = new Date().toISOString();
    mockListJobs.mockResolvedValue({
      jobs: [
        { id: 'job-1', kind: 'analyze', status: 'queued', hash: 'h1', createdAt: now, updatedAt: now },
        { id: 'job-2', kind: 'report', status: 'running', hash: 'h2', createdAt: now, updatedAt: now },
        { id: 'job-3', kind: 'pack', status: 'completed', hash: 'h3', createdAt: now, updatedAt: now },
      ],
    });
    mockListReviews.mockResolvedValue({
      reviews: [
        {
          id: 'review-1',
          tenantId: 'tenant-1',
          status: 'pending',
          target: { kind: 'analyze', reference: null },
          approvers: [
            { id: 'approver-1', status: 'pending', approvedAt: null, rejectedAt: null },
          ],
          requiredArtifacts: [],
          changeRequests: [],
          hash: 'hash-1',
          createdAt: now,
          updatedAt: now,
        },
      ],
      hasMore: false,
      nextOffset: null,
    });

    renderDashboard();

    expect(screen.getByTestId('queue-loading')).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.queryByTestId('queue-loading')).not.toBeInTheDocument();
    });

    expect(mockListJobs).toHaveBeenCalledWith(
      expect.objectContaining({ token: 'demo-token', license: 'demo-license' }),
    );
    expect(mockListReviews).toHaveBeenCalled();

    expect(screen.getByTestId('queue-total')).toHaveTextContent('3');
    expect(screen.getByTestId('queue-queued')).toHaveTextContent('1');
    expect(screen.getByTestId('queue-running')).toHaveTextContent('1');
    expect(screen.getByTestId('queue-completed')).toHaveTextContent('1');

    expect(screen.getByTestId('pending-review-table')).toHaveTextContent('review-1');
    expect(screen.getByTestId('pending-review-table')).toHaveTextContent('approver-1');
  });

  it('shows error fallbacks when requests fail', async () => {
    const error = new ApiError(500, 'Queue failed');
    mockListJobs.mockRejectedValue(error);
    mockListReviews.mockRejectedValue(new ApiError(400, 'Review failed'));

    renderDashboard();

    await waitFor(() => {
      expect(screen.getByText(/Queue failed/)).toBeInTheDocument();
      expect(screen.getByText(/Review failed/)).toBeInTheDocument();
    });
  });

  it('skips loading when credentials are missing', async () => {
    renderDashboard({ token: '', license: '' });

    await waitFor(() => {
      expect(mockListJobs).not.toHaveBeenCalled();
      expect(mockListReviews).not.toHaveBeenCalled();
    });

    expect(screen.getAllByText(/kimlik|credential/i).length).toBeGreaterThan(0);
  });
});
