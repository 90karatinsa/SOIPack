import {
  computeRiskProfile,
  predictCoverageDrift,
  simulateComplianceRisk,
  computeStageRiskForecast,
  type StageComplianceTrendPoint,
} from './risk';

describe('computeRiskProfile', () => {
  it('blends weighted signals and sorts contributors deterministically', () => {
    const profile = computeRiskProfile({
      coverage: { total: 100, missing: 10, partial: 20 },
      tests: { total: 50, failing: 5, quarantined: 3 },
      analysis: [{ severity: 'error' }, { severity: 'warn' }],
      audit: [
        { severity: 'medium', ageDays: 120 },
        { severity: 'high' },
      ],
    });

    expect(profile.score).toBeCloseTo(40.2, 1);
    expect(profile.classification).toBe('moderate');
    expect(profile.breakdown.map((entry) => entry.factor)).toEqual([
      'analysis',
      'audit',
      'coverage',
      'testing',
    ]);

    const coverageContribution = profile.breakdown.find((entry) => entry.factor === 'coverage');
    const testingContribution = profile.breakdown.find((entry) => entry.factor === 'testing');
    expect(coverageContribution?.contribution).toBeCloseTo(8, 1);
    expect(testingContribution?.contribution).toBeCloseTo(3.1, 1);
    expect(profile.missingSignals).toHaveLength(0);
  });

  it('penalizes missing data sources', () => {
    const profile = computeRiskProfile({});

    expect(profile.score).toBeGreaterThan(40);
    expect(profile.classification).toBe('moderate');
    expect(profile.missingSignals.sort()).toEqual([
      'analysis',
      'audit',
      'coverage',
      'testing',
    ]);
  });

  it('keeps factor ordering stable when contributions tie', () => {
    const profile = computeRiskProfile({
      coverage: { total: 20, missing: 0, partial: 0 },
      tests: { total: 10, failing: 0 },
      analysis: [],
      audit: [],
    });

    expect(profile.score).toBe(0);
    expect(profile.breakdown.map((entry) => entry.factor)).toEqual([
      'coverage',
      'testing',
      'analysis',
      'audit',
    ]);
  });
});

describe('predictCoverageDrift', () => {
  it('detects downward trends and projects future coverage', () => {
    const forecast = predictCoverageDrift(
      [
        { timestamp: '2024-01-01T00:00:00Z', coverage: 82 },
        { timestamp: '2024-01-08T00:00:00Z', coverage: 80 },
        { timestamp: '2024-01-15T00:00:00Z', coverage: 76 },
      ],
      { horizonDays: 7 },
    );

    expect(forecast.classification).toBe('declining');
    expect(forecast.projected).toBeLessThan(76);
    expect(forecast.slope).toBeLessThan(0);
    expect(forecast.confidence).toBeGreaterThan(0);
    expect(forecast.horizonDays).toBe(7);
  });

  it('returns stable forecasts when signals are flat', () => {
    const forecast = predictCoverageDrift([
      { timestamp: '2024-02-01T00:00:00Z', coverage: 80 },
      { timestamp: '2024-02-05T00:00:00Z', coverage: 80.1 },
      { timestamp: '2024-02-10T00:00:00Z', coverage: 80.05 },
    ]);

    expect(forecast.classification).toBe('stable');
    expect(Math.abs(forecast.slope)).toBeLessThan(0.2);
  });

  it('flags insufficient history as unknown', () => {
    const forecast = predictCoverageDrift([{ timestamp: '2024-01-01T00:00:00Z', coverage: null }]);

    expect(forecast.classification).toBe('unknown');
    expect(forecast.confidence).toBe(0);
  });
});

describe('simulateComplianceRisk', () => {
  it('produces deterministic percentiles with seeded input', () => {
    const result = simulateComplianceRisk({
      coverageHistory: [
        { timestamp: '2024-01-01T00:00:00Z', covered: 80, total: 100 },
        { timestamp: '2024-02-01T00:00:00Z', covered: 78, total: 100 },
        { timestamp: '2024-03-01T00:00:00Z', covered: 75, total: 100 },
      ],
      testHistory: [
        { timestamp: '2024-01-01T00:00:00Z', passed: 90, failed: 10 },
        { timestamp: '2024-02-01T00:00:00Z', passed: 88, failed: 12 },
        { timestamp: '2024-03-01T00:00:00Z', passed: 85, failed: 15 },
      ],
      iterations: 500,
      seed: 1337,
    });

    expect(result.iterations).toBe(500);
    expect(result.baseline.coverage).toBeCloseTo(75, 1);
    expect(result.baseline.failureRate).toBeCloseTo(15, 1);
    expect(result.percentiles.p90).toBeGreaterThan(result.percentiles.p50);
    expect(result.percentiles.p99).toBeLessThanOrEqual(100);
  });

  it('keeps probabilities low for stable histories', () => {
    const result = simulateComplianceRisk({
      coverageHistory: [
        { timestamp: '2024-01-01T00:00:00Z', covered: 96, total: 100 },
        { timestamp: '2024-02-01T00:00:00Z', covered: 97, total: 100 },
        { timestamp: '2024-03-01T00:00:00Z', covered: 97, total: 100 },
      ],
      testHistory: [
        { timestamp: '2024-01-01T00:00:00Z', passed: 98, failed: 2 },
        { timestamp: '2024-02-01T00:00:00Z', passed: 99, failed: 1 },
      ],
      iterations: 400,
      seed: 7,
    });

    expect(result.mean).toBeLessThan(35);
    expect(result.percentiles.p95).toBeLessThan(45);
  });
});

describe('computeStageRiskForecast', () => {
  const baseTrend: StageComplianceTrendPoint[] = [
    {
      stage: 'SOI-1',
      timestamp: '2024-02-01T00:00:00Z',
      regressions: 2,
      total: 20,
    },
    {
      stage: 'SOI-1',
      timestamp: '2024-02-15T00:00:00Z',
      regressions: 1,
      total: 18,
    },
    {
      stage: 'SOI-1',
      timestamp: '2024-03-01T00:00:00Z',
      regressions: 0,
      total: 15,
    },
    {
      stage: 'SOI-2',
      timestamp: '2024-03-01T00:00:00Z',
      regressions: 5,
      total: 10,
    },
  ];

  it('combines Bayesian posterior and Monte Carlo samples into a guarded outlook', () => {
    const forecast = computeStageRiskForecast({
      stage: 'SOI-1',
      trend: baseTrend,
      monteCarloProbabilities: [0.18, 0.2, 0.22],
    });

    expect(forecast.stage).toBe('SOI-1');
    expect(forecast.posterior.sampleSize).toBe(53);
    expect(forecast.probability).toBe(12);
    expect(forecast.classification).toBe('guarded');
    expect(forecast.credibleInterval.confidence).toBe(90);
    expect(forecast.credibleInterval.lower).toBeCloseTo(1.34, 2);
    expect(forecast.credibleInterval.upper).toBe(22);
    expect(forecast.sparkline).toHaveLength(3);
    expect(forecast.sparkline[0].regressionRatio).toBeCloseTo(0.1, 3);
    expect(forecast.updatedAt).toBe('2024-03-01T00:00:00.000Z');
  });

  it('falls back to simulation data when no trend history exists', () => {
    const forecast = computeStageRiskForecast({
      stage: 'SOI-2',
      trend: [],
      monteCarloProbabilities: [35, 45, 40],
      horizonDays: 45,
      confidenceLevel: 0.95,
    });

    expect(forecast.stage).toBe('SOI-2');
    expect(forecast.posterior.sampleSize).toBe(0);
    expect(forecast.horizonDays).toBe(45);
    expect(forecast.probability).toBe(40);
    expect(forecast.classification).toBe('elevated');
    expect(forecast.credibleInterval.confidence).toBe(95);
    expect(forecast.credibleInterval.lower).toBeLessThanOrEqual(10);
    expect(forecast.credibleInterval.upper).toBeGreaterThanOrEqual(45);
  });
});
