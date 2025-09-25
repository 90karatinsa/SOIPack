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
