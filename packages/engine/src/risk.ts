import type { SoiStage } from '@soipack/core';

export type RiskFactor = 'coverage' | 'testing' | 'analysis' | 'audit';

export type StaticAnalysisSeverity = 'info' | 'warn' | 'error';
export type AuditFlagSeverity = 'low' | 'medium' | 'high' | 'critical';

export interface CoverageSignal {
  total: number;
  missing: number;
  partial: number;
}

export interface TestSignal {
  total: number;
  failing: number;
  quarantined?: number;
}

export interface StaticAnalysisSignal {
  severity: StaticAnalysisSeverity;
}

export interface AuditFlagSignal {
  severity: AuditFlagSeverity;
  acknowledged?: boolean;
  ageDays?: number;
}

export interface RiskInput {
  coverage?: CoverageSignal;
  tests?: TestSignal;
  analysis?: StaticAnalysisSignal[];
  audit?: AuditFlagSignal[];
}

export interface RiskBreakdownEntry {
  factor: RiskFactor;
  contribution: number;
  weight: number;
  details: string;
}

export interface RiskProfile {
  score: number;
  classification: 'low' | 'moderate' | 'high' | 'critical';
  breakdown: RiskBreakdownEntry[];
  missingSignals: RiskFactor[];
}

export interface CoverageSnapshot {
  timestamp: string;
  coverage: number | null | undefined;
}

export interface CoverageDriftForecast {
  slope: number;
  projected: number;
  classification: 'improving' | 'declining' | 'stable' | 'unknown';
  confidence: number;
  horizonDays: number;
}

export interface RiskSimulationCoverageSample {
  timestamp: string;
  covered: number;
  total: number;
}

export interface RiskSimulationTestSample {
  timestamp: string;
  passed: number;
  failed: number;
  quarantined?: number;
}

export interface ComplianceRiskSimulationOptions {
  coverageHistory: RiskSimulationCoverageSample[];
  testHistory: RiskSimulationTestSample[];
  iterations?: number;
  seed?: number;
}

export interface ComplianceRiskSimulationResult {
  iterations: number;
  mean: number;
  stddev: number;
  min: number;
  max: number;
  percentiles: {
    p50: number;
    p90: number;
    p95: number;
    p99: number;
  };
  baseline: {
    coverage: number;
    failureRate: number;
  };
  seed: number;
}

export interface StageComplianceTrendPoint {
  stage: SoiStage;
  timestamp: string;
  regressions: number;
  total: number;
}

export interface StageRiskForecastOptions {
  stage: SoiStage;
  trend: StageComplianceTrendPoint[];
  monteCarloProbabilities?: number[];
  horizonDays?: number;
  prior?: { alpha: number; beta: number };
  confidenceLevel?: number;
}

export interface StageRiskSparklinePoint {
  timestamp: string;
  regressionRatio: number;
}

export interface StageRiskForecast {
  stage: SoiStage;
  probability: number;
  classification: 'nominal' | 'guarded' | 'elevated' | 'critical';
  horizonDays: number;
  credibleInterval: {
    lower: number;
    upper: number;
    confidence: number;
  };
  posterior: {
    alpha: number;
    beta: number;
    sampleSize: number;
  };
  sparkline: StageRiskSparklinePoint[];
  updatedAt?: string;
}

const FACTOR_WEIGHTS: Record<RiskFactor, number> = {
  coverage: 0.4,
  testing: 0.25,
  analysis: 0.2,
  audit: 0.15,
};

const STATIC_ANALYSIS_WEIGHTS: Record<StaticAnalysisSeverity, number> = {
  info: 0.2,
  warn: 0.6,
  error: 1,
};

const AUDIT_FLAG_WEIGHTS: Record<AuditFlagSeverity, number> = {
  low: 0.3,
  medium: 0.6,
  high: 0.85,
  critical: 1,
};

const clamp = (value: number, min = 0, max = 1): number => {
  if (Number.isNaN(value)) {
    return min;
  }
  return Math.min(Math.max(value, min), max);
};

const round = (value: number, precision = 2): number => {
  const factor = 10 ** precision;
  return Math.round(value * factor) / factor;
};

const computeStd = (values: number[]): number => {
  if (values.length < 2) {
    return 0;
  }
  const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
  const variance = values.reduce((sum, value) => sum + (value - mean) ** 2, 0) / values.length;
  return Math.sqrt(variance);
};

const percentile = (sorted: number[], p: number): number => {
  if (sorted.length === 0) {
    return 0;
  }
  const index = (p / 100) * (sorted.length - 1);
  const lower = Math.floor(index);
  const upper = Math.ceil(index);
  if (lower === upper) {
    return sorted[lower];
  }
  const weight = index - lower;
  return sorted[lower] * (1 - weight) + sorted[upper] * weight;
};

const factorOrder: RiskFactor[] = ['coverage', 'testing', 'analysis', 'audit'];

export const computeRiskProfile = (input: RiskInput): RiskProfile => {
  const breakdown: RiskBreakdownEntry[] = [];
  const missingSignals = new Set<RiskFactor>();

  const coverage = input.coverage;
  if (!coverage || coverage.total <= 0) {
    const contribution = round(FACTOR_WEIGHTS.coverage * 100 * 0.6);
    breakdown.push({
      factor: 'coverage',
      contribution,
      weight: FACTOR_WEIGHTS.coverage * 100,
      details: 'Coverage metrics unavailable',
    });
    missingSignals.add('coverage');
  } else {
    const total = Math.max(coverage.total, 1);
    const gapRatio = clamp((coverage.missing + coverage.partial * 0.5) / total);
    const contribution = round(gapRatio * FACTOR_WEIGHTS.coverage * 100);
    breakdown.push({
      factor: 'coverage',
      contribution,
      weight: FACTOR_WEIGHTS.coverage * 100,
      details: `${coverage.missing} missing, ${coverage.partial} partial across ${total} items`,
    });
  }

  const tests = input.tests;
  if (!tests || tests.total <= 0) {
    const contribution = round(FACTOR_WEIGHTS.testing * 100 * 0.5);
    breakdown.push({
      factor: 'testing',
      contribution,
      weight: FACTOR_WEIGHTS.testing * 100,
      details: 'Test outcomes unavailable',
    });
    missingSignals.add('testing');
  } else {
    const total = Math.max(tests.total, 1);
    const failureRatio = clamp(tests.failing / total);
    const quarantineRatio = clamp((tests.quarantined ?? 0) / total) * 0.4;
    const contribution = round((failureRatio + quarantineRatio) * FACTOR_WEIGHTS.testing * 100);
    breakdown.push({
      factor: 'testing',
      contribution,
      weight: FACTOR_WEIGHTS.testing * 100,
      details: `${tests.failing} failing, ${tests.quarantined ?? 0} quarantined of ${total} tests`,
    });
  }

  const analysis = input.analysis;
  if (!analysis) {
    const contribution = round(FACTOR_WEIGHTS.analysis * 100 * 0.3);
    breakdown.push({
      factor: 'analysis',
      contribution,
      weight: FACTOR_WEIGHTS.analysis * 100,
      details: 'Static analysis data unavailable',
    });
    missingSignals.add('analysis');
  } else if (analysis.length === 0) {
    breakdown.push({
      factor: 'analysis',
      contribution: 0,
      weight: FACTOR_WEIGHTS.analysis * 100,
      details: 'No outstanding static analysis findings',
    });
  } else {
    const severities = analysis.map((finding) => STATIC_ANALYSIS_WEIGHTS[finding.severity] ?? 0.2);
    const average = severities.reduce((sum, value) => sum + value, 0) / analysis.length;
    const peak = Math.max(...severities);
    const blended = clamp(average * 0.7 + peak * 0.3);
    const contribution = round(blended * FACTOR_WEIGHTS.analysis * 100);
    breakdown.push({
      factor: 'analysis',
      contribution,
      weight: FACTOR_WEIGHTS.analysis * 100,
      details: `${analysis.length} findings (${analysis.map((item) => item.severity).join(', ')})`,
    });
  }

  const audit = input.audit;
  if (!audit) {
    const contribution = round(FACTOR_WEIGHTS.audit * 100 * 0.25);
    breakdown.push({
      factor: 'audit',
      contribution,
      weight: FACTOR_WEIGHTS.audit * 100,
      details: 'Audit history unavailable',
    });
    missingSignals.add('audit');
  } else if (audit.length === 0) {
    breakdown.push({
      factor: 'audit',
      contribution: 0,
      weight: FACTOR_WEIGHTS.audit * 100,
      details: 'No outstanding audit flags',
    });
  } else {
    const normalized = audit.map((flag) => {
      const base = AUDIT_FLAG_WEIGHTS[flag.severity] ?? 0.6;
      const aged = flag.ageDays && flag.ageDays > 90 ? clamp(base * 1.1) : base;
      const adjusted = flag.acknowledged ? aged * 0.7 : aged;
      return clamp(adjusted);
    });
    const average = normalized.reduce((sum, value) => sum + value, 0) / normalized.length;
    const peak = Math.max(...normalized);
    const blended = clamp(average * 0.6 + peak * 0.4);
    const contribution = round(blended * FACTOR_WEIGHTS.audit * 100);
    breakdown.push({
      factor: 'audit',
      contribution,
      weight: FACTOR_WEIGHTS.audit * 100,
      details: `${audit.length} active audit flags`,
    });
  }

  const sortedBreakdown = breakdown.sort((a, b) => {
    if (Math.abs(b.contribution - a.contribution) > 0.0001) {
      return b.contribution - a.contribution;
    }
    return factorOrder.indexOf(a.factor) - factorOrder.indexOf(b.factor);
  });

  const score = round(sortedBreakdown.reduce((total, entry) => total + entry.contribution, 0));
  const classification: RiskProfile['classification'] =
    score < 25 ? 'low' : score < 50 ? 'moderate' : score < 75 ? 'high' : 'critical';

  return {
    score,
    classification,
    breakdown: sortedBreakdown,
    missingSignals: Array.from(missingSignals),
  };
};

const MS_PER_DAY = 86_400_000;

export const predictCoverageDrift = (
  snapshots: CoverageSnapshot[],
  options: { horizonDays?: number } = {},
): CoverageDriftForecast => {
  const horizonDays = options.horizonDays ?? 14;
  const sanitized = snapshots
    .map((snapshot) => {
      const timestamp = Date.parse(snapshot.timestamp);
      if (Number.isNaN(timestamp)) {
        return null;
      }
      const coverage = snapshot.coverage;
      if (typeof coverage !== 'number' || Number.isNaN(coverage)) {
        return null;
      }
      return { time: timestamp, coverage };
    })
    .filter((entry): entry is { time: number; coverage: number } => entry !== null)
    .sort((a, b) => a.time - b.time);

  if (sanitized.length < 2) {
    const lastCoverage = sanitized[0]?.coverage ?? 0;
    return {
      slope: 0,
      projected: round(lastCoverage),
      classification: 'unknown',
      confidence: 0,
      horizonDays,
    };
  }

  const xMean = sanitized.reduce((sum, entry) => sum + entry.time, 0) / sanitized.length;
  const yMean = sanitized.reduce((sum, entry) => sum + entry.coverage, 0) / sanitized.length;

  let numerator = 0;
  let denominatorX = 0;
  let denominatorY = 0;
  sanitized.forEach((entry) => {
    const xDiff = entry.time - xMean;
    const yDiff = entry.coverage - yMean;
    numerator += xDiff * yDiff;
    denominatorX += xDiff * xDiff;
    denominatorY += yDiff * yDiff;
  });

  if (denominatorX === 0) {
    const latest = sanitized[sanitized.length - 1];
    return {
      slope: 0,
      projected: round(latest.coverage),
      classification: 'stable',
      confidence: 0,
      horizonDays,
    };
  }

  const slopePerMs = numerator / denominatorX;
  const slopePerDay = slopePerMs * MS_PER_DAY;
  const intercept = yMean - slopePerMs * xMean;

  const latest = sanitized[sanitized.length - 1];
  const projectionTime = latest.time + horizonDays * MS_PER_DAY;
  const projected = clamp(intercept + slopePerMs * projectionTime, 0, 100);

  let classification: CoverageDriftForecast['classification'];
  if (Math.abs(slopePerDay) < 0.1) {
    classification = 'stable';
  } else if (slopePerDay > 0) {
    classification = 'improving';
  } else {
    classification = 'declining';
  }

  let confidence = 0;
  if (denominatorX > 0 && denominatorY > 0) {
    const correlation = numerator / Math.sqrt(denominatorX * denominatorY);
    confidence = clamp(Math.abs(correlation));
  }

  const residual = sanitized.reduce((sum, entry) => {
    const predicted = intercept + slopePerMs * entry.time;
    const diff = entry.coverage - predicted;
    return sum + diff * diff;
  }, 0);
  const volatility = Math.sqrt(residual / sanitized.length);
  const adjustedConfidence = clamp(confidence * (1 - clamp(volatility / 100)));

  return {
    slope: round(slopePerDay, 3),
    projected: round(projected),
    classification,
    confidence: round(adjustedConfidence),
    horizonDays,
  };
};

interface SeededRandom {
  next: () => number;
  nextGaussian: () => number;
}

const createSeededRandom = (seed: number): SeededRandom => {
  let state = seed >>> 0 || 1;
  let spare: number | null = null;
  const next = () => {
    state = (state * 1664525 + 1013904223) >>> 0;
    return state / 0x100000000;
  };
  const nextGaussian = () => {
    if (spare !== null) {
      const value = spare;
      spare = null;
      return value;
    }
    let u = 0;
    let v = 0;
    while (u === 0) {
      u = next();
    }
    while (v === 0) {
      v = next();
    }
    const magnitude = Math.sqrt(-2.0 * Math.log(u));
    const angle = 2.0 * Math.PI * v;
    spare = magnitude * Math.sin(angle);
    return magnitude * Math.cos(angle);
  };
  return { next, nextGaussian };
};

const sanitizeCoverageHistory = (
  history: RiskSimulationCoverageSample[],
): Array<{ time: number; ratio: number }> => {
  return history
    .map((sample) => {
      const timestamp = Date.parse(sample.timestamp);
      if (!Number.isFinite(timestamp)) {
        return null;
      }
      const total = Math.max(1, sample.total);
      const ratio = clamp(sample.covered / total, 0, 1);
      return { time: timestamp, ratio };
    })
    .filter((entry): entry is { time: number; ratio: number } => entry !== null)
    .sort((a, b) => a.time - b.time);
};

const sanitizeTestHistory = (
  history: RiskSimulationTestSample[],
): Array<{ time: number; failureRatio: number }> => {
  return history
    .map((sample) => {
      const timestamp = Date.parse(sample.timestamp);
      const total = sample.passed + sample.failed + (sample.quarantined ?? 0);
      if (!Number.isFinite(timestamp) || total <= 0) {
        return null;
      }
      const ratio = clamp(sample.failed / total, 0, 1);
      return { time: timestamp, failureRatio: ratio };
    })
    .filter((entry): entry is { time: number; failureRatio: number } => entry !== null)
    .sort((a, b) => a.time - b.time);
};

export const simulateComplianceRisk = (
  options: ComplianceRiskSimulationOptions,
): ComplianceRiskSimulationResult => {
  const iterations = Math.max(1, Math.min(10000, Math.floor(options.iterations ?? 1000)));
  const seed = options.seed ?? 421337;
  const rng = createSeededRandom(seed);

  const coverageSeries = sanitizeCoverageHistory(options.coverageHistory);
  const coverageBaseline = coverageSeries.length
    ? coverageSeries[coverageSeries.length - 1].ratio
    : 0;
  const coverageDeltas = coverageSeries
    .map((entry, index) =>
      index === 0 ? null : entry.ratio - coverageSeries[index - 1].ratio,
    )
    .filter((delta): delta is number => typeof delta === 'number' && Number.isFinite(delta));
  const coverageStd = computeStd(coverageDeltas.length ? coverageDeltas : [0.02]) || 0.02;

  const testSeries = sanitizeTestHistory(options.testHistory);
  const failureBaseline = testSeries.length
    ? testSeries[testSeries.length - 1].failureRatio
    : 0;
  const failureDeltas = testSeries
    .map((entry, index) =>
      index === 0 ? null : entry.failureRatio - testSeries[index - 1].failureRatio,
    )
    .filter((delta): delta is number => typeof delta === 'number' && Number.isFinite(delta));
  const failureStd = computeStd(failureDeltas.length ? failureDeltas : [0.03]) || 0.03;

  const samples: number[] = [];

  for (let iteration = 0; iteration < iterations; iteration += 1) {
    const coverageDeltaBase =
      coverageDeltas.length > 0
        ? coverageDeltas[Math.floor(rng.next() * coverageDeltas.length)]
        : 0;
    const coverageNoise = coverageStd * 0.5 * rng.nextGaussian();
    const projectedCoverage = clamp(
      coverageBaseline + coverageDeltaBase + coverageNoise,
      0,
      1,
    );
    const coverageRegression = Math.max(0, coverageBaseline - projectedCoverage);

    const failureDeltaBase =
      failureDeltas.length > 0
        ? failureDeltas[Math.floor(rng.next() * failureDeltas.length)]
        : 0;
    const failureNoise = failureStd * 0.6 * rng.nextGaussian();
    const projectedFailure = clamp(
      failureBaseline + failureDeltaBase + failureNoise,
      0,
      1,
    );
    const failureRegression = Math.max(0, projectedFailure - failureBaseline);

    const combined = coverageRegression * 1.25 + failureRegression * 1.75;
    const probability = 1 / (1 + Math.exp(-6 * (combined - 0.15)));
    samples.push(round(probability * 100));
  }

  const mean = samples.reduce((sum, value) => sum + value, 0) / samples.length;
  const stddev = computeStd(samples);
  const sorted = [...samples].sort((a, b) => a - b);

  return {
    iterations,
    mean: round(mean),
    stddev: round(stddev),
    min: round(sorted[0]),
    max: round(sorted[sorted.length - 1]),
    percentiles: {
      p50: round(percentile(sorted, 50)),
      p90: round(percentile(sorted, 90)),
      p95: round(percentile(sorted, 95)),
      p99: round(percentile(sorted, 99)),
    },
    baseline: {
      coverage: round(coverageBaseline * 100),
      failureRate: round(failureBaseline * 100),
    },
    seed,
  };
};

const CONFIDENCE_Z_SCORES: Array<{ confidence: number; z: number }> = [
  { confidence: 0.8, z: 1.2816 },
  { confidence: 0.85, z: 1.4395 },
  { confidence: 0.9, z: 1.6449 },
  { confidence: 0.95, z: 1.96 },
  { confidence: 0.98, z: 2.3263 },
  { confidence: 0.99, z: 2.5758 },
];

const resolveZScore = (confidence: number): number => {
  const normalized = clamp(confidence, 0.5, 0.999);
  let closest = CONFIDENCE_Z_SCORES[0];
  for (const entry of CONFIDENCE_Z_SCORES) {
    if (Math.abs(entry.confidence - normalized) < Math.abs(closest.confidence - normalized)) {
      closest = entry;
    }
  }
  return closest.z;
};

const classifyStageProbability = (probability: number): StageRiskForecast['classification'] => {
  if (probability >= 60) {
    return 'critical';
  }
  if (probability >= 35) {
    return 'elevated';
  }
  if (probability >= 12) {
    return 'guarded';
  }
  return 'nominal';
};

const normalizeProbabilitySample = (value: number): number | null => {
  if (!Number.isFinite(value)) {
    return null;
  }
  const normalized = value > 1 ? value / 100 : value;
  if (!Number.isFinite(normalized)) {
    return null;
  }
  return clamp(normalized, 0, 1);
};

export const computeStageRiskForecast = ({
  stage,
  trend,
  monteCarloProbabilities,
  horizonDays = 30,
  prior = { alpha: 1, beta: 9 },
  confidenceLevel = 0.9,
}: StageRiskForecastOptions): StageRiskForecast => {
  const sanitizedTrend = trend
    .filter((point) => point.stage === stage)
    .map((point) => {
      const time = Date.parse(point.timestamp);
      if (!Number.isFinite(time)) {
        return null;
      }
      const regressions = Math.max(0, Math.round(point.regressions));
      const total = Math.max(regressions, Math.round(point.total));
      if (total <= 0) {
        return null;
      }
      return { time, regressions, total };
    })
    .filter((point): point is { time: number; regressions: number; total: number } => point !== null)
    .sort((a, b) => a.time - b.time);

  const lookbackWindow = 90 * MS_PER_DAY;
  const latestTime = sanitizedTrend[sanitizedTrend.length - 1]?.time ?? null;
  const trimmedTrend =
    latestTime === null
      ? sanitizedTrend
      : sanitizedTrend.filter((point) => latestTime - point.time <= lookbackWindow);

  let alpha = Math.max(0.0001, prior.alpha);
  let beta = Math.max(0.0001, prior.beta);
  let sampleSize = 0;

  trimmedTrend.forEach((point) => {
    alpha += point.regressions;
    beta += point.total - point.regressions;
    sampleSize += point.total;
  });

  const posteriorMean = alpha / (alpha + beta);
  const posteriorVariance = (alpha * beta) / ((alpha + beta) ** 2 * (alpha + beta + 1));
  const zScore = resolveZScore(confidenceLevel);
  const posteriorStd = Math.sqrt(Math.max(posteriorVariance, 0));
  let intervalLower = clamp(posteriorMean - zScore * posteriorStd, 0, 1);
  let intervalUpper = clamp(posteriorMean + zScore * posteriorStd, 0, 1);

  const normalizedMonteCarlo = (monteCarloProbabilities ?? [])
    .map((value) => normalizeProbabilitySample(value))
    .filter((value): value is number => value !== null);

  const simulationMean =
    normalizedMonteCarlo.length > 0
      ? normalizedMonteCarlo.reduce((sum, value) => sum + value, 0) / normalizedMonteCarlo.length
      : null;

  if (normalizedMonteCarlo.length > 0) {
    const sortedSamples = [...normalizedMonteCarlo].sort((a, b) => a - b);
    const lowerIndex = Math.max(
      0,
      Math.floor(((1 - confidenceLevel) / 2) * (sortedSamples.length - 1)),
    );
    const upperIndex = Math.min(
      sortedSamples.length - 1,
      Math.ceil(((1 + confidenceLevel) / 2) * (sortedSamples.length - 1)),
    );
    intervalLower = Math.min(intervalLower, sortedSamples[lowerIndex]);
    intervalUpper = Math.max(intervalUpper, sortedSamples[upperIndex]);
  }

  const trendWeight = sampleSize > 0 ? 0.6 : 0;
  const simulationWeight = normalizedMonteCarlo.length > 0 ? 0.4 : 0;
  const weightTotal = trendWeight + simulationWeight;
  const blendedMean =
    weightTotal > 0
      ? (posteriorMean * trendWeight + (simulationMean ?? posteriorMean) * simulationWeight) /
        weightTotal
      : posteriorMean;

  const probabilityPercent = Math.round(blendedMean * 100);
  const classification = classifyStageProbability(probabilityPercent);

  const sparkline: StageRiskSparklinePoint[] = trimmedTrend.map((point) => ({
    timestamp: new Date(point.time).toISOString(),
    regressionRatio: round(point.regressions / Math.max(1, point.total), 3),
  }));

  const updatedAt = latestTime ? new Date(latestTime).toISOString() : undefined;

  return {
    stage,
    probability: probabilityPercent,
    classification,
    horizonDays,
    credibleInterval: {
      lower: round(intervalLower * 100),
      upper: round(intervalUpper * 100),
      confidence: round(confidenceLevel * 100),
    },
    posterior: {
      alpha: round(alpha, 3),
      beta: round(beta, 3),
      sampleSize,
    },
    sparkline,
    updatedAt,
  };
};
