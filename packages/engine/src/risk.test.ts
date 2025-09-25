import { computeRiskProfile, predictCoverageDrift } from './risk';

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
