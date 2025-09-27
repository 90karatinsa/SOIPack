import { render, screen, waitFor, within, act, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import RiskCockpitPage, { runRiskSandboxSimulation } from './RiskCockpitPage';
import {
  createComplianceEventStream,
  type ComplianceEvent,
} from '../services/events';
import { fetchStageRiskForecast, getManifestProof } from '../services/api';

jest.mock('../services/events', () => {
  const actual = jest.requireActual('../services/events');
  return {
    ...actual,
    createComplianceEventStream: jest.fn(),
  };
});

jest.mock('../services/api', () => {
  const actual = jest.requireActual('../services/api');
  return {
    ...actual,
    getManifestProof: jest.fn(),
    fetchStageRiskForecast: jest.fn(),
  };
});

describe('RiskCockpitPage', () => {
  const mockCreateStream = createComplianceEventStream as jest.MockedFunction<
    typeof createComplianceEventStream
  >;
  const mockGetManifestProof = getManifestProof as jest.MockedFunction<typeof getManifestProof>;
  const mockFetchStageRiskForecast =
    fetchStageRiskForecast as jest.MockedFunction<typeof fetchStageRiskForecast>;

  let handlers: { onEvent?: (event: ComplianceEvent) => void } = {};

  const renderPage = () =>
    render(<RiskCockpitPage token="demo-token" license="demo-license" isAuthorized />);

  beforeEach(() => {
    jest.clearAllMocks();
    handlers = {};
    mockCreateStream.mockImplementation((options) => {
      handlers = { onEvent: options.onEvent };
      return {
        close: jest.fn(),
        getState: jest.fn(() => ({ connected: true, retries: 0 })),
      };
    });
    mockFetchStageRiskForecast.mockResolvedValue({ generatedAt: '2024-03-01T00:00:00Z', forecasts: [] });
  });

  it('renders proof explorer details when manifest proof events arrive', async () => {
    const sampleProof = {
      algorithm: 'ledger-merkle-v1' as const,
      merkleRoot: 'root-hash-1234567890',
      proof: JSON.stringify({
        leaf: {
          type: 'evidence',
          label: 'evidence:manifest:report.pdf',
          hash: 'leaf-hash-abcdef1234567890',
        },
        path: [
          { position: 'left', hash: 'left-node-hash-1' },
          { position: 'right', hash: 'right-node-hash-2' },
        ],
        merkleRoot: 'root-hash-1234567890',
      }),
    };

    mockGetManifestProof.mockResolvedValue({
      manifestId: 'manifest-1',
      jobId: 'job-1',
      path: 'report.pdf',
      sha256: 'sha256-report',
      proof: sampleProof,
      verified: true,
      merkle: {
        algorithm: 'ledger-merkle-v1',
        root: 'root-hash-1234567890',
        manifestDigest: 'digest-123',
        snapshotId: 'snapshot-1',
      },
    });

    renderPage();

    expect(mockCreateStream).toHaveBeenCalledWith(
      expect.objectContaining({ token: 'demo-token', license: 'demo-license' }),
    );

    const manifestEvent: ComplianceEvent = {
      type: 'manifestProof',
      tenantId: 'tenant-1',
      manifestId: 'manifest-1',
      jobId: 'job-1',
      merkle: {
        algorithm: 'ledger-merkle-v1',
        root: 'root-hash-1234567890',
        manifestDigest: 'digest-123',
        snapshotId: 'snapshot-1',
      },
      files: [
        { path: 'report.pdf', sha256: 'sha256-report', hasProof: true, verified: true },
        { path: 'logs/output.txt', sha256: 'sha256-logs', hasProof: false, verified: false },
      ],
    };

    await act(async () => {
      handlers.onEvent?.(manifestEvent);
    });

    await waitFor(() => expect(mockGetManifestProof).toHaveBeenCalledTimes(1));

    const explorer = await screen.findByTestId('proof-explorer-card');
    expect(explorer).toBeInTheDocument();
    expect(within(explorer).getByTestId('proof-manifest-id')).toHaveTextContent('manifest-1');
    expect(within(explorer).getByText('Doğrulandı')).toBeInTheDocument();
    expect(within(explorer).getByText('Kanıt yok')).toBeInTheDocument();

    await waitFor(() => expect(screen.getByTestId('proof-leaf-hash')).toBeInTheDocument());
    expect(screen.getByTestId('proof-leaf-label')).toHaveTextContent('report.pdf');
    expect(screen.getAllByTestId('proof-path-node')).toHaveLength(2);
  });

  it('allows switching proof selection and surfaces load errors', async () => {
    mockGetManifestProof
      .mockResolvedValueOnce({
        manifestId: 'manifest-2',
        jobId: 'job-2',
        path: 'report.pdf',
        sha256: 'sha-report',
        verified: true,
        proof: {
          algorithm: 'ledger-merkle-v1',
          merkleRoot: 'root-a',
          proof: JSON.stringify({ leaf: { type: 'evidence', label: 'report', hash: 'leaf-a' }, path: [] }),
        },
        merkle: null,
      })
      .mockRejectedValueOnce(new Error('Kanıt doğrulanamadı'))
      .mockResolvedValueOnce({
        manifestId: 'manifest-2',
        jobId: 'job-2',
        path: 'evidence.bin',
        sha256: 'sha-evidence',
        verified: false,
        proof: {
          algorithm: 'ledger-merkle-v1',
          merkleRoot: 'root-a',
          proof: JSON.stringify({
            leaf: { type: 'evidence', label: 'evidence.bin', hash: 'leaf-b' },
            path: [],
          }),
        },
        merkle: null,
      });

    renderPage();

    const manifestEvent: ComplianceEvent = {
      type: 'manifestProof',
      tenantId: 'tenant-2',
      manifestId: 'manifest-2',
      jobId: 'job-2',
      merkle: {
        algorithm: 'ledger-merkle-v1',
        root: 'root-a',
        manifestDigest: 'digest-a',
        snapshotId: 'snapshot-a',
      },
      files: [
        { path: 'report.pdf', sha256: 'sha-report', hasProof: true, verified: true },
        { path: 'evidence.bin', sha256: 'sha-evidence', hasProof: true, verified: false },
      ],
    };

    await act(async () => {
      handlers.onEvent?.(manifestEvent);
    });

    await waitFor(() => expect(mockGetManifestProof).toHaveBeenCalledTimes(1));

    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'evidence.bin' }));

    await waitFor(() => expect(mockGetManifestProof).toHaveBeenCalledTimes(2));
    await waitFor(() =>
      expect(screen.getByText(/Kanıt doğrulanamadı/)).toBeInTheDocument(),
    );

    const retryButton = screen.getByRole('button', { name: 'Yeniden dene' });
    await user.click(retryButton);
    await waitFor(() => expect(mockGetManifestProof).toHaveBeenCalledTimes(3));
  });

  it('renders stage risk forecast probabilities and intervals', async () => {
    mockFetchStageRiskForecast.mockResolvedValueOnce({
      generatedAt: '2024-03-15T10:00:00Z',
      forecasts: [
        {
          stage: 'SOI-1',
          probability: 23,
          classification: 'guarded',
          horizonDays: 30,
          credibleInterval: { lower: 12, upper: 34, confidence: 90 },
          sparkline: [
            { timestamp: '2024-02-01T00:00:00Z', regressionRatio: 0.12 },
            { timestamp: '2024-02-08T00:00:00Z', regressionRatio: 0.08 },
          ],
          updatedAt: '2024-03-15T09:30:00Z',
        },
      ],
    });

    renderPage();

    await waitFor(() => expect(mockFetchStageRiskForecast).toHaveBeenCalledTimes(1));

    expect(await screen.findByText('SOI-1')).toBeInTheDocument();
    expect(screen.getByText('guarded')).toBeInTheDocument();
    expect(screen.getByText('%23')).toBeInTheDocument();
    expect(screen.getByText(/90% güven aralığı: %12 – %34/)).toBeInTheDocument();
  });

  it('runs the what-if sandbox simulation when sliders are adjusted', async () => {
    const sandboxForecasts = [
      {
        stage: 'SOI-Alpha',
        probability: 35,
        classification: 'guarded' as const,
        horizonDays: 30,
        credibleInterval: { lower: 18, upper: 52, confidence: 90 },
        sparkline: [],
        updatedAt: '2024-04-10T00:00:00Z',
      },
      {
        stage: 'SOI-Beta',
        probability: 60,
        classification: 'elevated' as const,
        horizonDays: 30,
        credibleInterval: { lower: 40, upper: 75, confidence: 85 },
        sparkline: [],
        updatedAt: '2024-04-10T00:00:00Z',
      },
    ];

    mockFetchStageRiskForecast.mockResolvedValueOnce({
      generatedAt: '2024-04-10T00:00:00Z',
      forecasts: sandboxForecasts,
    });

    renderPage();

    await waitFor(() => expect(mockFetchStageRiskForecast).toHaveBeenCalledTimes(1));

    const coverageSlider = await screen.findByLabelText(/Projeksiyon kapsam artışı/i);
    const failureSlider = screen.getByLabelText(/Test başarısızlığı şiddeti/i);

    fireEvent.change(coverageSlider, { target: { value: '28' } });
    fireEvent.change(failureSlider, { target: { value: '22' } });

    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: /Simülasyonu çalıştır/i }));

    const expected = runRiskSandboxSimulation(sandboxForecasts, {
      coverageLift: 28,
      failureRate: 22,
      iterations: 500,
    });

    await waitFor(() =>
      expect(screen.getByTestId('sandbox-average-risk')).toHaveTextContent(
        `%${expected.averageRisk.toFixed(1)}`,
      ),
    );

    expect(screen.getByTestId('sandbox-regression-probability')).toHaveTextContent(
      `%${expected.regressionProbability.toFixed(1)}`,
    );
    expect(screen.getByTestId('sandbox-expected-failures')).toHaveTextContent(
      expected.expectedFailures.toFixed(2),
    );

    const distributionBars = screen.getAllByTestId('sandbox-distribution-bar');
    expect(distributionBars).toHaveLength(expected.distribution.length);
    expect(distributionBars[0]).toHaveAttribute(
      'data-failures',
      `${expected.distribution[0].failures}`,
    );

    const classificationList = screen.getByTestId('sandbox-classifications');
    const classificationItems = within(classificationList).getAllByRole('listitem');
    expect(classificationItems).toHaveLength(expected.classifications.length);
    expected.classifications.forEach((entry, index) => {
      expect(classificationItems[index]).toHaveTextContent(
        new RegExp(`${entry.classification}.*%${(entry.share * 100).toFixed(1)}`),
      );
    });
  });

  it('shows an error when stage risk forecast retrieval fails', async () => {
    mockFetchStageRiskForecast.mockRejectedValueOnce(new Error('Sunucu hatası'));

    renderPage();

    await waitFor(() =>
      expect(screen.getByText(/Tahmin alınamadı: Sunucu hatası/)).toBeInTheDocument(),
    );
  });
});
