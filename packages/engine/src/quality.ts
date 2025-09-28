import type { Finding } from '@soipack/adapters';
import { requirementStatuses, type Requirement } from '@soipack/core';

import type { RequirementCoverageStatus, RequirementTrace } from './index';

export type QualityFindingSeverity = 'info' | 'warn' | 'error';
export type QualityFindingCategory = 'trace' | 'tests' | 'coverage' | 'analysis';

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

type RequirementStatusValue = (typeof requirementStatuses)[number];

const ambiguousLanguagePatterns: Array<{
  id: string;
  regex: RegExp;
  phrase?: string;
  phraseFromMatch?: boolean;
  recommendation?: string;
}> = [
  { id: 'placeholder-tbd', regex: /\bTBD\b/i, phrase: '"TBD"' },
  { id: 'placeholder-tba', regex: /\bTBA\b/i, phrase: '"TBA"' },
  { id: 'placeholder-tbc', regex: /\bTBC\b/i, phrase: '"TBC"' },
  { id: 'and-or', regex: /\band\/or\b/i, phrase: '"and/or"' },
  { id: 'as-appropriate', regex: /\bas appropriate\b/i, phrase: '"as appropriate"' },
  { id: 'as-necessary', regex: /\bas (?:necessary|required)\b/i, phraseFromMatch: true },
  { id: 'be-able-to', regex: /\bbe able to\b/i, phrase: '"be able to"' },
  { id: 'etc', regex: /\betc\./i, phrase: '"etc."' },
  {
    id: 'should-olmali',
    regex: /(?<![A-Za-zÇĞİÖŞÜçğıöşü])olmal[ıi](?![A-Za-zÇĞİÖŞÜçğıöşü])/iu,
    phraseFromMatch: true,
  },
  {
    id: 'as-needed-gerektiginde',
    regex: /(?<![A-Za-zÇĞİÖŞÜçğıöşü])gerekti(?:ğ|g)inde(?![A-Za-zÇĞİÖŞÜçğıöşü])/iu,
    phraseFromMatch: true,
  },
  {
    id: 'subjective-adjective',
    regex: /(?<![A-Za-zÇĞİÖŞÜçğıöşü])(adequate|sufficient|minimal|flexible|yeterli)(?![A-Za-zÇĞİÖŞÜçğıöşü])/iu,
    phraseFromMatch: true,
  },
];

const passiveVoicePattern = /\b(?:shall|will|must|should)\s+be\s+\w+(?:ed|en)\b/i;

const duplicateWarnThreshold = 0.6;
const duplicateErrorThreshold = 0.82;
const duplicateRecommendation =
  'Benzer gereksinimleri birleştirmeyi, kapsamlarını netleştirmeyi veya benzersiz kimlikler atamayı değerlendirin.';

const sanitizeRequirementText = (text: string): string => {
  return text
    .toLocaleLowerCase('tr-TR')
    .replace(/["'`]/g, ' ')
    .replace(/[^a-z0-9çğıöşüİı\s]/giu, ' ')
    .replace(/\s+/g, ' ')
    .trim();
};

const buildTrigrams = (text: string): Set<string> => {
  const sanitized = sanitizeRequirementText(text);
  if (sanitized.length === 0) {
    return new Set();
  }
  if (sanitized.length < 3) {
    return new Set([sanitized]);
  }
  const trigrams = new Set<string>();
  const padded = ` ${sanitized} `;
  for (let index = 0; index <= padded.length - 3; index += 1) {
    trigrams.add(padded.slice(index, index + 3));
  }
  return trigrams;
};

const computeJaccardSimilarity = (a: Set<string>, b: Set<string>): number => {
  if (a.size === 0 && b.size === 0) {
    return 0;
  }
  let intersection = 0;
  const larger = a.size >= b.size ? a : b;
  const smaller = larger === a ? b : a;
  smaller.forEach((value) => {
    if (larger.has(value)) {
      intersection += 1;
    }
  });
  const union = a.size + b.size - intersection;
  if (union <= 0) {
    return 0;
  }
  return intersection / union;
};

const placeholderRegexes = [
  /\bTBD\b/i,
  /\bTBA\b/i,
  /\bTBC\b/i,
  /\bto be determined\b/i,
  /\bto be defined\b/i,
  /\bto be decided\b/i,
  /\bpending\b/i,
  /\bplaceholder\b/i,
  /\bunder review\b/i,
];

const placeholderTagIndicators = new Set(['tbd', 'pending', 'placeholder', 'draft', 'wip']);
const statusTagSet = new Set<string>(requirementStatuses as readonly string[]);

const clarityRecommendation =
  'Belirsiz ifadeleri kaldırarak gereksinimi ölçülebilir ve doğrulanabilir hale getirin.';

const failingTests = (trace: RequirementTrace): RequirementTrace['tests'] =>
  trace.tests.filter((test) => test.status === 'failed');

const skippedTests = (trace: RequirementTrace): RequirementTrace['tests'] =>
  trace.tests.filter((test) => test.status === 'skipped');

const buildFindingId = (requirement: Requirement, suffix: string): string =>
  `${requirement.id}-${suffix}`;

const buildAnalysisFindingId = (tool: Finding['tool'], id: string): string =>
  `analysis-${tool}-${id}`;

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

const resolvedFindingStatuses = new Set(['closed', 'justified', 'proved']);

const isResolvedAnalysisFinding = (status: Finding['status']): boolean => {
  if (!status) {
    return false;
  }
  return resolvedFindingStatuses.has(status.trim().toLowerCase());
};

const toolLabels: Record<Finding['tool'], string> = {
  polyspace: 'Polyspace',
  ldra: 'LDRA',
  vectorcast: 'VectorCAST',
};

const normalizeAnalysisMessage = (finding: Finding): string => {
  const message = finding.message?.trim();
  if (message && message.length > 0) {
    return message;
  }
  return 'Detay sağlanmadı.';
};

const evaluateAnalysisFindings = (findings: Finding[]): QualityFinding[] => {
  return findings
    .filter((finding) => {
      const severity = finding.severity?.toLowerCase();
      if (severity !== 'error' && severity !== 'warn') {
        return false;
      }
      if (isResolvedAnalysisFinding(finding.status)) {
        return false;
      }
      return true;
    })
    .map((finding) => {
      const severity = finding.severity === 'error' ? 'error' : 'warn';
      return {
        id: buildAnalysisFindingId(finding.tool, finding.id),
        severity,
        category: 'analysis' as const,
        message: `${toolLabels[finding.tool]} bulgusu ${finding.id} (${finding.severity ?? 'bilinmiyor'}) açık durumda: ${normalizeAnalysisMessage(finding)}`,
        recommendation: 'Statik analiz bulgusunu giderin veya araçta kapatıp gerekçelendirin.',
      } satisfies QualityFinding;
    });
};

const evaluateRequirementClarity = (requirement: Requirement): QualityFinding[] => {
  const text = `${requirement.title} ${requirement.description ?? ''}`.trim();
  if (!text) {
    return [];
  }

  const findings: QualityFinding[] = [];

  const normalizedText = text.toLocaleLowerCase('tr-TR');

  ambiguousLanguagePatterns.forEach((pattern) => {
    const match = text.match(pattern.regex) ?? normalizedText.match(pattern.regex);
    if (!match) {
      return;
    }
    const phrase = pattern.phraseFromMatch ? `"${match[0].trim()}"` : pattern.phrase ?? `"${match[0].trim()}"`;
    findings.push({
      id: buildFindingId(requirement, `clarity-${pattern.id}`),
      severity: 'warn',
      category: 'analysis',
      requirementId: requirement.id,
      message: `${requirement.id} gereksinimi DO-178C netlik kriterleriyle uyumsuz ${phrase} ifadesini içeriyor.`,
      recommendation: pattern.recommendation ?? clarityRecommendation,
    });
  });

  const passiveMatch = text.match(passiveVoicePattern);
  if (passiveMatch) {
    findings.push({
      id: buildFindingId(requirement, 'clarity-passive-voice'),
      severity: 'warn',
      category: 'analysis',
      requirementId: requirement.id,
      message: `${requirement.id} gereksinimi pasif yapı (${passiveMatch[0]}) kullanıyor; DO-178C aktif ve doğrulanabilir ifadeler bekler.`,
      recommendation: 'Cümleyi etkin özneyle yeniden yazarak sorumluluğu açıkça belirtin.',
    });
  }

  const placeholderMatch = placeholderRegexes
    .map((regex) => text.match(regex))
    .find((match): match is RegExpMatchArray => Boolean(match));

  const normalizedTags = requirement.tags.map((tag) => tag.trim().toLowerCase()).filter((tag) => tag.length > 0);
  const placeholderTag = normalizedTags.find((tag) => placeholderTagIndicators.has(tag));
  const conflictingStatusTags = normalizedTags.filter(
    (tag): tag is RequirementStatusValue => statusTagSet.has(tag),
  );

  if (
    (placeholderMatch || placeholderTag) &&
    (requirement.status === 'implemented' || requirement.status === 'verified')
  ) {
    const severity: QualityFindingSeverity = requirement.status === 'verified' ? 'error' : 'warn';
    const evidence = placeholderMatch?.[0] ?? placeholderTag ?? 'belirsiz ifade';
    findings.push({
      id: buildFindingId(requirement, 'clarity-status-placeholder'),
      severity,
      category: 'analysis',
      requirementId: requirement.id,
      message: `${requirement.id} ${requirement.status} olarak işaretli ancak "${evidence}" gibi belirsiz yer tutucular içeriyor.`,
      recommendation: 'Durumu doğrulamadan önce gereksinim metnindeki yer tutucuları ve açık olmayan ifadeleri netleştirin.',
    });
  }

  const conflictingStatuses = conflictingStatusTags.filter((tag) => tag !== requirement.status);
  if (conflictingStatuses.length > 0) {
    findings.push({
      id: buildFindingId(requirement, 'clarity-status-tag-conflict'),
      severity: 'warn',
      category: 'analysis',
      requirementId: requirement.id,
      message: `${requirement.id} gereksinimi ${requirement.status} olarak işaretli ancak etiketlerde ${conflictingStatuses.join(', ')} durumları bulunuyor.`,
      recommendation: 'Gereksinim etiketlerini mevcut durumla uyumlu hale getirin veya statüyü gözden geçirin.',
    });
  }

  return ensureUnique(findings);
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

  return [...findings, ...evaluateRequirementClarity(requirement)];
};

const evaluateDuplicateRequirements = (traces: RequirementTrace[]): QualityFinding[] => {
  const findings: QualityFinding[] = [];
  const trigramCache = new Map<string, Set<string>>();

  const getRequirementText = (requirement: Requirement): string => {
    const base = `${requirement.title ?? ''} ${requirement.description ?? ''}`.trim();
    return base;
  };

  const getTrigrams = (requirement: Requirement): Set<string> => {
    const cached = trigramCache.get(requirement.id);
    if (cached) {
      return cached;
    }
    const text = getRequirementText(requirement);
    const grams = buildTrigrams(text);
    trigramCache.set(requirement.id, grams);
    return grams;
  };

  for (let index = 0; index < traces.length; index += 1) {
    const left = traces[index]?.requirement;
    if (!left) {
      continue;
    }
    const leftText = getRequirementText(left);
    if (!leftText || leftText.trim().length === 0) {
      continue;
    }
    const leftTrigrams = getTrigrams(left);
    if (leftTrigrams.size === 0) {
      continue;
    }

    for (let siblingIndex = index + 1; siblingIndex < traces.length; siblingIndex += 1) {
      const right = traces[siblingIndex]?.requirement;
      if (!right) {
        continue;
      }
      const rightText = getRequirementText(right);
      if (!rightText || rightText.trim().length === 0) {
        continue;
      }
      const rightTrigrams = getTrigrams(right);
      if (rightTrigrams.size === 0) {
        continue;
      }

      const similarity = computeJaccardSimilarity(leftTrigrams, rightTrigrams);
      if (similarity < duplicateWarnThreshold) {
        continue;
      }

      const severity: QualityFindingSeverity =
        similarity >= duplicateErrorThreshold ? 'error' : 'warn';
      const percentage = Math.round(similarity * 100);
      const sharedMessage = `%${percentage} benzerlik`; // for consistent rounding

      findings.push({
        id: `${left.id}-duplicate-${right.id}`,
        severity,
        category: 'analysis',
        requirementId: left.id,
        message: `${left.id} gereksinimi ${right.id} ile ${sharedMessage} gösteriyor; ifadeler neredeyse aynıdır.`,
        recommendation: duplicateRecommendation,
      });

      findings.push({
        id: `${right.id}-duplicate-${left.id}`,
        severity,
        category: 'analysis',
        requirementId: right.id,
        message: `${right.id} gereksinimi ${left.id} ile ${sharedMessage} gösteriyor; ifadeler neredeyse aynıdır.`,
        recommendation: duplicateRecommendation,
      });
    }
  }

  return findings;
};

export const evaluateQualityFindings = (
  traces: RequirementTrace[],
  coverage: RequirementCoverageStatus[],
  analysisFindings: Finding[] = [],
): QualityFinding[] => {
  const coverageByRequirement = new Map<string, RequirementCoverageStatus>(
    coverage.map((entry) => [entry.requirement.id, entry]),
  );

  const traceFindings = traces.flatMap((trace) =>
    evaluateRequirement({ trace, coverage: coverageByRequirement.get(trace.requirement.id) }),
  );
  const duplicateFindings = evaluateDuplicateRequirements(traces);
  const analysisQuality = evaluateAnalysisFindings(analysisFindings);

  return ensureUnique([...traceFindings, ...duplicateFindings, ...analysisQuality]);
};
