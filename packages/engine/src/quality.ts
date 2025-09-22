import type { Requirement } from '@soipack/core';

import type { RequirementCoverageStatus, RequirementTrace } from './index';

export type QualityFindingSeverity = 'info' | 'warn' | 'error';
export type QualityFindingCategory = 'trace' | 'tests' | 'coverage';

export interface QualityFinding {
  id: string;
  severity: QualityFindingSeverity;
  category: QualityFindingCategory;
  message: string;
  requirementId?: string;
  recommendation?: string;
  relatedTests?: string[];
}

interface RequirementQualityContext {
  trace: RequirementTrace;
  coverage?: RequirementCoverageStatus;
}

const failingTests = (trace: RequirementTrace): RequirementTrace['tests'] =>
  trace.tests.filter((test) => test.status === 'failed');

const skippedTests = (trace: RequirementTrace): RequirementTrace['tests'] =>
  trace.tests.filter((test) => test.status === 'skipped');

const buildFindingId = (requirement: Requirement, suffix: string): string =>
  `${requirement.id}-${suffix}`;

const ensureUnique = (findings: QualityFinding[]): QualityFinding[] => {
  const seen = new Set<string>();
  const result: QualityFinding[] = [];
  findings.forEach((finding) => {
    if (seen.has(finding.id)) {
      return;
    }
    seen.add(finding.id);
    result.push(finding);
  });
  return result;
};

const evaluateRequirement = ({ trace, coverage }: RequirementQualityContext): QualityFinding[] => {
  const requirement = trace.requirement;
  const findings: QualityFinding[] = [];
  const linkedTests = trace.tests;
  const coverageStatus = coverage?.status;

  if (requirement.status === 'verified' && linkedTests.length === 0) {
    findings.push({
      id: buildFindingId(requirement, 'verified-no-tests'),
      severity: 'error',
      category: 'trace',
      requirementId: requirement.id,
      message: `${requirement.id} doğrulandı olarak işaretli ancak ilişkilendirilmiş test bulunamadı.`,
      recommendation:
        'Gereksinim ile ilişkili doğrulama testlerini izleyin veya gereksinim durumunu güncel hale getirin.',
    });
  }

  if (requirement.status === 'verified') {
    const failed = failingTests(trace);
    if (failed.length > 0) {
      findings.push({
        id: buildFindingId(requirement, 'verified-failing-tests'),
        severity: 'error',
        category: 'tests',
        requirementId: requirement.id,
        message: `${requirement.id} doğrulandı olarak işaretli ancak başarısız testler mevcut.`,
        recommendation: 'Başarısız testleri analiz edin ve gereksinim doğrulama kanıtını güncelleyin.',
        relatedTests: failed.map((test) => test.testId),
      });
    }

    const skipped = skippedTests(trace);
    if (skipped.length > 0) {
      findings.push({
        id: buildFindingId(requirement, 'verified-skipped-tests'),
        severity: 'warn',
        category: 'tests',
        requirementId: requirement.id,
        message: `${requirement.id} doğrulandı olarak işaretli ancak atlanan testler var.`,
        recommendation: 'Atlanan testlerin tekrar koşulmasını planlayın veya gereksinim durumunu yeniden değerlendirin.',
        relatedTests: skipped.map((test) => test.testId),
      });
    }
  }

  if (requirement.status === 'implemented' && linkedTests.length === 0) {
    findings.push({
      id: buildFindingId(requirement, 'implemented-no-tests'),
      severity: 'warn',
      category: 'trace',
      requirementId: requirement.id,
      message: `${requirement.id} uygulandı olarak işaretli ancak test bağlantısı yok.`,
      recommendation: 'Gereksinimi doğrulayan testleri planlayın veya durumu güncelleyin.',
    });
  }

  if ((requirement.status === 'implemented' || requirement.status === 'verified') && coverageStatus) {
    if (coverageStatus === 'missing') {
      findings.push({
        id: buildFindingId(requirement, 'coverage-missing'),
        severity: requirement.status === 'verified' ? 'error' : 'warn',
        category: 'coverage',
        requirementId: requirement.id,
        message: `${requirement.id} için kapsama verisi bulunamadı.`,
        recommendation: 'Kod izlerini ve kapsam raporlarını gereksinime bağlayın veya durumu yeniden değerlendirin.',
      });
    } else if (coverageStatus === 'partial' && requirement.status === 'verified') {
      findings.push({
        id: buildFindingId(requirement, 'coverage-partial'),
        severity: 'warn',
        category: 'coverage',
        requirementId: requirement.id,
        message: `${requirement.id} doğrulandı olarak işaretli ancak kapsam verisi kısmi.`,
        recommendation: 'Eksik kapsamı tamamlayın veya gereksinim durumunu güncelleyin.',
      });
    }
  }

  return findings;
};

export const evaluateQualityFindings = (
  traces: RequirementTrace[],
  coverage: RequirementCoverageStatus[],
): QualityFinding[] => {
  const coverageByRequirement = new Map<string, RequirementCoverageStatus>(
    coverage.map((entry) => [entry.requirement.id, entry]),
  );

  const findings = traces.flatMap((trace) =>
    evaluateRequirement({ trace, coverage: coverageByRequirement.get(trace.requirement.id) }),
  );

  return ensureUnique(findings);
};
