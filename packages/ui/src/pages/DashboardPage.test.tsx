import { render, screen, waitFor } from '@testing-library/react';
import React from 'react';

import { I18nProvider } from '../providers/I18nProvider';
import DashboardPage from './DashboardPage';
import { listJobs, listReviews, fetchComplianceSummary, fetchChangeRequests, ApiError } from '../services/api';

jest.mock('../services/api', () => {
  const actual = jest.requireActual('../services/api');
  return {
    ...actual,
    listJobs: jest.fn(),
    listReviews: jest.fn(),
    fetchComplianceSummary: jest.fn(),
    fetchChangeRequests: jest.fn(),
  };
});

describe('DashboardPage', () => {
  const mockListJobs = listJobs as jest.MockedFunction<typeof listJobs>;
  const mockListReviews = listReviews as jest.MockedFunction<typeof listReviews>;
  const mockFetchComplianceSummary = fetchComplianceSummary as jest.MockedFunction<
    typeof fetchComplianceSummary
  >;
  const mockFetchChangeRequests = fetchChangeRequests as jest.MockedFunction<typeof fetchChangeRequests>;

  const renderDashboard = (props?: { token?: string; license?: string }) =>
    render(
      <I18nProvider>
        <DashboardPage token={props?.token ?? 'demo-token'} license={props?.license ?? 'demo-license'} />
      </I18nProvider>,
    );

  beforeEach(() => {
    jest.clearAllMocks();
    mockFetchComplianceSummary.mockReset();
    mockFetchChangeRequests.mockReset();
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
    mockFetchComplianceSummary.mockResolvedValue({
      computedAt: now,
      latest: {
        id: 'summary-1',
        createdAt: now,
        summary: { total: 4, covered: 3, partial: 1, missing: 0 },
        coverage: { statements: 82 },
        gaps: { missingIds: [], partialIds: ['A-1-01'], openObjectiveCount: 1 },
        independence: {
          totals: { covered: 1, partial: 1, missing: 1 },
          objectives: [
            {
              objectiveId: 'A-1-01',
              status: 'covered',
              independence: 'recommended',
              missingArtifacts: [],
            },
            {
              objectiveId: 'A-1-02',
              status: 'partial',
              independence: 'required',
              missingArtifacts: ['trace'],
            },
            {
              objectiveId: 'A-1-03',
              status: 'missing',
              independence: 'recommended',
              missingArtifacts: ['test'],
            },
          ],
        },
      },
    });
    mockFetchChangeRequests.mockResolvedValue({
      fetchedAt: now,
      items: [
        {
          id: 'CR-1',
          key: 'CR-1',
          summary: 'Restore qualification evidence',
          status: 'In Progress',
          statusCategory: 'In Progress',
          assignee: 'alice',
          updatedAt: now,
          url: 'https://jira.example.com/browse/CR-1',
          transitions: [],
          attachments: [{ id: 'att-1', filename: 'report.pdf' }],
        },
      ],
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
    expect(mockFetchComplianceSummary).toHaveBeenCalledWith(
      expect.objectContaining({ token: 'demo-token', license: 'demo-license' }),
    );
    expect(mockFetchChangeRequests).toHaveBeenCalledWith(
      expect.objectContaining({ token: 'demo-token', license: 'demo-license' }),
    );

    expect(screen.getByTestId('compliance-summary')).toBeInTheDocument();
    expect(screen.getByText('Eylem Gerekli')).toBeInTheDocument();
    expect(screen.getByText('Hazırlık (%)')).toBeInTheDocument();
    expect(screen.getByTestId('compliance-summary')).toHaveTextContent('75%');
    expect(screen.getByText(/Açık hedefler:/)).toHaveTextContent('1');

    expect(screen.getByTestId('queue-total')).toHaveTextContent('3');
    expect(screen.getByTestId('queue-queued')).toHaveTextContent('1');
    expect(screen.getByTestId('queue-running')).toHaveTextContent('1');
    expect(screen.getByTestId('queue-completed')).toHaveTextContent('1');

    expect(screen.getByTestId('pending-review-table')).toHaveTextContent('review-1');
    expect(screen.getByTestId('pending-review-table')).toHaveTextContent('approver-1');
    const independenceCard = screen.getByTestId('independence-card');
    expect(independenceCard).toBeInTheDocument();
    expect(screen.getByTestId('independence-missing-count')).toHaveTextContent('Eksik: 1');
    expect(screen.getByTestId('independence-partial-count')).toHaveTextContent('Kısmi: 1');
    expect(screen.getByRole('link', { name: 'A-1-02' })).toHaveAttribute(
      'href',
      '#/compliance?objective=A-1-02',
    );
    expect(screen.getByTestId('independence-open-list')).toHaveTextContent('trace');

    const changeRequestsTable = screen.getByTestId('change-requests-table');
    expect(changeRequestsTable).toHaveTextContent('CR-1');
    expect(changeRequestsTable).toHaveTextContent('Restore qualification evidence');
    expect(screen.getByTestId('change-request-attachments-CR-1')).toHaveTextContent('1');
  });

  it('shows error fallbacks when requests fail', async () => {
    const error = new ApiError(500, 'Queue failed');
    mockListJobs.mockRejectedValue(error);
    mockListReviews.mockRejectedValue(new ApiError(400, 'Review failed'));
    mockFetchComplianceSummary.mockRejectedValue(new ApiError(503, 'Summary failed'));
    mockFetchChangeRequests.mockRejectedValue(new ApiError(500, 'Change requests failed'));

    renderDashboard();

    await waitFor(() => {
      expect(screen.getByText(/Queue failed/)).toBeInTheDocument();
      expect(screen.getByText(/Review failed/)).toBeInTheDocument();
      expect(screen.getByText(/Summary failed/)).toBeInTheDocument();
      expect(screen.getByText(/Change requests failed/)).toBeInTheDocument();
    });
  });

  it('skips loading when credentials are missing', async () => {
    renderDashboard({ token: '', license: '' });

    await waitFor(() => {
      expect(mockListJobs).not.toHaveBeenCalled();
      expect(mockListReviews).not.toHaveBeenCalled();
      expect(mockFetchComplianceSummary).not.toHaveBeenCalled();
      expect(mockFetchChangeRequests).not.toHaveBeenCalled();
    });

    expect(screen.getAllByText(/kimlik|credential/i).length).toBeGreaterThan(0);
  });

  it('marks compliance readiness as complete when no gaps remain', async () => {
    const now = new Date().toISOString();
    mockListJobs.mockResolvedValue({ jobs: [] });
    mockListReviews.mockResolvedValue({ reviews: [], hasMore: false, nextOffset: null });
    mockFetchComplianceSummary.mockResolvedValue({
      computedAt: now,
      latest: {
        id: 'summary-2',
        createdAt: now,
        summary: { total: 2, covered: 2, partial: 0, missing: 0 },
        coverage: { statements: 100 },
        gaps: { missingIds: [], partialIds: [], openObjectiveCount: 0 },
        independence: {
          totals: { covered: 2, partial: 0, missing: 0 },
          objectives: [],
        },
      },
    });
    mockFetchChangeRequests.mockResolvedValue({ fetchedAt: now, items: [] });

    renderDashboard();

    await waitFor(() => {
      expect(screen.getByTestId('compliance-summary')).toBeInTheDocument();
    });

    await waitFor(() => {
      expect(screen.getByText('Hazır')).toBeInTheDocument();
    });
    expect(screen.getByText(/Hazırlık \(%\)/)).toBeInTheDocument();
    expect(screen.getByTestId('compliance-summary')).toHaveTextContent('100%');
    expect(screen.getByTestId('independence-all-clear')).toBeInTheDocument();
    expect(screen.getByTestId('change-requests-empty')).toBeInTheDocument();
  });
});
