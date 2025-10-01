import type { Objective, ObjectiveArtifactType } from '@soipack/core';

import type { EvidenceIndex } from './index';

export type TraceabilityNodeType = 'requirement' | 'design' | 'code' | 'test';

export interface RequirementTraceRecord {
  id: string;
  name?: string;
  designRefs?: string[];
}

export interface DesignTraceRecord {
  id: string;
  name?: string;
  requirementRefs?: string[];
  codeRefs?: string[];
}

export interface CodeTraceRecord {
  id: string;
  name?: string;
  designRefs?: string[];
  testRefs?: string[];
}

export interface TestTraceRecord {
  id: string;
  name?: string;
  codeRefs?: string[];
  status?: string;
}

export interface TraceabilityModel {
  requirements: RequirementTraceRecord[];
  designs: DesignTraceRecord[];
  code: CodeTraceRecord[];
  tests: TestTraceRecord[];
}

export type GapSeverity = 'low' | 'medium' | 'high';

export interface RequirementGap {
  requirementId: string;
  requirementName?: string;
  missingDesign: boolean;
  missingCode: boolean;
  missingTests: boolean;
  severity: GapSeverity;
  designs: string[];
  code: string[];
  tests: string[];
}

export interface OrphanRecord {
  type: 'design' | 'code' | 'test';
  id: string;
  description: string;
}

export interface ConflictRecord {
  type: 'link';
  description: string;
  sourceType: TraceabilityNodeType;
  sourceId: string;
  targetType: TraceabilityNodeType;
  targetId: string;
  severity: GapSeverity;
}

export interface TraceabilityGapSummary {
  totalRequirements: number;
  withGaps: number;
  complete: number;
  highPriorityRequirements: string[];
}

export interface TraceabilityGapReport {
  requirementGaps: RequirementGap[];
  orphans: OrphanRecord[];
  conflicts: ConflictRecord[];
  summary: TraceabilityGapSummary;
}

const toSet = (values?: string[]): Set<string> => {
  if (!values) {
    return new Set();
  }

  const set = new Set<string>();
  values
    .map((value) => value.trim())
    .filter((value) => value.length > 0)
    .forEach((value) => set.add(value));
  return set;
};

const addLink = (map: Map<string, Set<string>>, key: string, value: string): void => {
  if (!map.has(key)) {
    map.set(key, new Set());
  }
  map.get(key)!.add(value);
};

const unionInto = (target: Map<string, Set<string>>, source: Map<string, Set<string>>): void => {
  for (const [key, values] of source) {
    for (const value of values) {
      addLink(target, key, value);
    }
  }
};

const sortStrings = (values: Iterable<string>): string[] => Array.from(values).sort((a, b) => a.localeCompare(b));

export class TraceabilityGapAnalyzer {
  private readonly requirementMap: Map<string, RequirementTraceRecord>;

  private readonly designMap: Map<string, DesignTraceRecord>;

  private readonly codeMap: Map<string, CodeTraceRecord>;

  private readonly testMap: Map<string, TestTraceRecord>;

  constructor(private readonly model: TraceabilityModel) {
    this.requirementMap = new Map(model.requirements.map((requirement) => [requirement.id, requirement]));
    this.designMap = new Map(model.designs.map((design) => [design.id, design]));
    this.codeMap = new Map(model.code.map((code) => [code.id, code]));
    this.testMap = new Map(model.tests.map((test) => [test.id, test]));
  }

  public analyze(): TraceabilityGapReport {
    const requirementDesignDirect = new Map<string, Set<string>>();
    const designRequirementDirect = new Map<string, Set<string>>();
    const designCodeDirect = new Map<string, Set<string>>();
    const codeDesignDirect = new Map<string, Set<string>>();
    const codeTestDirect = new Map<string, Set<string>>();
    const testCodeDirect = new Map<string, Set<string>>();

    this.model.requirements.forEach((requirement) => {
      toSet(requirement.designRefs).forEach((designId) => {
        addLink(requirementDesignDirect, requirement.id, designId);
      });
    });

    this.model.designs.forEach((design) => {
      toSet(design.requirementRefs).forEach((requirementId) => {
        addLink(designRequirementDirect, design.id, requirementId);
      });
      toSet(design.codeRefs).forEach((codeId) => {
        addLink(designCodeDirect, design.id, codeId);
      });
    });

    this.model.code.forEach((code) => {
      toSet(code.designRefs).forEach((designId) => {
        addLink(codeDesignDirect, code.id, designId);
      });
      toSet(code.testRefs).forEach((testId) => {
        addLink(codeTestDirect, code.id, testId);
      });
    });

    this.model.tests.forEach((test) => {
      toSet(test.codeRefs).forEach((codeId) => {
        addLink(testCodeDirect, test.id, codeId);
      });
    });

    const requirementToDesign = new Map<string, Set<string>>();
    unionInto(requirementToDesign, requirementDesignDirect);
    for (const [designId, requirementIds] of designRequirementDirect) {
      for (const requirementId of requirementIds) {
        addLink(requirementToDesign, requirementId, designId);
      }
    }

    const designToCode = new Map<string, Set<string>>();
    unionInto(designToCode, designCodeDirect);
    for (const [codeId, designIds] of codeDesignDirect) {
      for (const designId of designIds) {
        addLink(designToCode, designId, codeId);
      }
    }

    const codeToTestSymmetric = new Map<string, Set<string>>();
    for (const [codeId, testIds] of codeTestDirect) {
      for (const testId of testIds) {
        if (testCodeDirect.get(testId)?.has(codeId)) {
          addLink(codeToTestSymmetric, codeId, testId);
        }
      }
    }
    for (const [testId, codeIds] of testCodeDirect) {
      for (const codeId of codeIds) {
        if (codeTestDirect.get(codeId)?.has(testId)) {
          addLink(codeToTestSymmetric, codeId, testId);
        }
      }
    }

    const orphans: OrphanRecord[] = [];
    const linkedDesigns = new Set<string>();
    const linkedCode = new Set<string>();
    const linkedTests = new Set<string>();

    for (const designIds of requirementToDesign.values()) {
      for (const designId of designIds) {
        linkedDesigns.add(designId);
      }
    }

    for (const codeIds of designToCode.values()) {
      for (const codeId of codeIds) {
        linkedCode.add(codeId);
      }
    }

    for (const testIds of codeToTestSymmetric.values()) {
      for (const testId of testIds) {
        linkedTests.add(testId);
      }
    }

    this.model.designs.forEach((design) => {
      if (!linkedDesigns.has(design.id)) {
        orphans.push({
          type: 'design',
          id: design.id,
          description: `Tasarım ${design.id} hiçbir gereksinime bağlı değil.`,
        });
      }
    });

    this.model.code.forEach((code) => {
      if (!linkedCode.has(code.id)) {
        orphans.push({
          type: 'code',
          id: code.id,
          description: `Kod bileşeni ${code.id} için ilişkili tasarım bulunamadı.`,
        });
      }
    });

    this.model.tests.forEach((test) => {
      const hasDirectReference = toSet(test.codeRefs).size > 0;
      if (!linkedTests.has(test.id) && !hasDirectReference) {
        orphans.push({
          type: 'test',
          id: test.id,
          description: `Test ${test.id} herhangi bir kod bileşenine izlenmiyor.`,
        });
      }
    });

    const requirementGaps: RequirementGap[] = [];
    this.model.requirements.forEach((requirement) => {
      const designs = requirementToDesign.get(requirement.id) ?? new Set<string>();
      const codes = new Set<string>();
      for (const designId of designs) {
        const related = designToCode.get(designId);
        if (related) {
          related.forEach((codeId) => codes.add(codeId));
        }
      }
      const tests = new Set<string>();
      for (const codeId of codes) {
        const relatedTests = codeToTestSymmetric.get(codeId);
        if (relatedTests) {
          relatedTests.forEach((testId) => tests.add(testId));
        }
      }

      const missingDesign = designs.size === 0;
      const missingCode = missingDesign || codes.size === 0;
      const missingTests = missingDesign || tests.size === 0;

      if (missingDesign || missingCode || missingTests) {
        let severity: GapSeverity = 'low';
        if (missingTests) {
          severity = 'high';
        } else if (missingCode) {
          severity = 'medium';
        }

        requirementGaps.push({
          requirementId: requirement.id,
          requirementName: requirement.name,
          missingDesign,
          missingCode,
          missingTests,
          severity,
          designs: sortStrings(designs),
          code: sortStrings(codes),
          tests: sortStrings(tests),
        });
      }
    });

    const conflicts: ConflictRecord[] = [];
    const seenConflictKeys = new Set<string>();
    const registerConflict = (
      sourceType: TraceabilityNodeType,
      sourceId: string,
      targetType: TraceabilityNodeType,
      targetId: string,
      description: string,
      severity: GapSeverity,
    ): void => {
      const key = `${sourceType}:${sourceId}->${targetType}:${targetId}`;
      if (seenConflictKeys.has(key)) {
        return;
      }
      seenConflictKeys.add(key);
      conflicts.push({ type: 'link', sourceType, sourceId, targetType, targetId, description, severity });
    };

    const ensureRequirementExists = (
      requirementId: string,
      contextType: TraceabilityNodeType,
      contextId: string,
    ): void => {
      if (!this.requirementMap.has(requirementId)) {
        registerConflict(
          contextType,
          contextId,
          'requirement',
          requirementId,
          `Gereksinim ${requirementId} tanımlı değil.`,
          'high',
        );
      }
    };

    const ensureDesignExists = (designId: string, context: string): void => {
      if (!this.designMap.has(designId)) {
        registerConflict('requirement', context, 'design', designId, `Tasarım ${designId} tanımlı değil.`, 'high');
      }
    };

    const ensureCodeExists = (codeId: string, contextType: TraceabilityNodeType, contextId: string): void => {
      if (!this.codeMap.has(codeId)) {
        registerConflict(contextType, contextId, 'code', codeId, `Kod bileşeni ${codeId} tanımlı değil.`, 'high');
      }
    };

    const ensureTestExists = (testId: string, contextId: string): void => {
      if (!this.testMap.has(testId)) {
        registerConflict('code', contextId, 'test', testId, `Test ${testId} tanımlı değil.`, 'high');
      }
    };

    for (const [requirementId, designIds] of requirementDesignDirect) {
      for (const designId of designIds) {
        ensureDesignExists(designId, requirementId);
        if (!designRequirementDirect.get(designId)?.has(requirementId)) {
          registerConflict(
            'requirement',
            requirementId,
            'design',
            designId,
            `Gereksinim ${requirementId} ve tasarım ${designId} bağlantısı tek yönlü.`,
            'medium',
          );
        }
      }
    }

    for (const [designId, requirementIds] of designRequirementDirect) {
      for (const requirementId of requirementIds) {
        ensureRequirementExists(requirementId, 'design', designId);
        if (!requirementDesignDirect.get(requirementId)?.has(designId)) {
          registerConflict(
            'design',
            designId,
            'requirement',
            requirementId,
            `Tasarım ${designId} gereksinim ${requirementId} tarafından referans edilmiyor.`,
            'medium',
          );
        }
      }
    }

    for (const [designId, codeIds] of designCodeDirect) {
      for (const codeId of codeIds) {
        ensureCodeExists(codeId, 'design', designId);
        if (!codeDesignDirect.get(codeId)?.has(designId)) {
          registerConflict(
            'design',
            designId,
            'code',
            codeId,
            `Tasarım ${designId} ve kod ${codeId} bağlantısı karşılıklı değil.`,
            'medium',
          );
        }
      }
    }

    for (const [codeId, designIds] of codeDesignDirect) {
      for (const designId of designIds) {
        if (!designCodeDirect.get(designId)?.has(codeId)) {
          registerConflict(
            'code',
            codeId,
            'design',
            designId,
            `Kod ${codeId} için tasarım ${designId} referansı tek yönlü.`,
            'medium',
          );
        }
      }
    }

    for (const [codeId, testIds] of codeTestDirect) {
      for (const testId of testIds) {
        ensureTestExists(testId, codeId);
        if (!testCodeDirect.get(testId)?.has(codeId)) {
          registerConflict(
            'code',
            codeId,
            'test',
            testId,
            `Kod ${codeId} test ${testId} tarafından doğrulanmıyor.`,
            'high',
          );
        }
      }
    }

    for (const [testId, codeIds] of testCodeDirect) {
      for (const codeId of codeIds) {
        ensureCodeExists(codeId, 'test', testId);
        if (!codeTestDirect.get(codeId)?.has(testId)) {
          registerConflict(
            'test',
            testId,
            'code',
            codeId,
            `Test ${testId} kod ${codeId} tarafından referans edilmiyor.`,
            'high',
          );
        }
      }
    }

    const totalRequirements = this.model.requirements.length;
    const withGaps = requirementGaps.length;
    const summary: TraceabilityGapSummary = {
      totalRequirements,
      withGaps,
      complete: Math.max(0, totalRequirements - withGaps),
      highPriorityRequirements: requirementGaps
        .filter((gap) => gap.severity === 'high')
        .map((gap) => gap.requirementId)
        .sort((a, b) => a.localeCompare(b)),
    };

    return { requirementGaps, orphans, conflicts, summary };
  }
}

const MILLISECONDS_PER_DAY = 24 * 60 * 60 * 1000;

export type StaleEvidenceReason = 'beforeSnapshot' | 'exceedsMaxAge';

export interface StaleEvidenceFinding {
  objectiveId: string;
  artifactType: ObjectiveArtifactType;
  latestEvidenceTimestamp: string;
  reasons: StaleEvidenceReason[];
  ageDays?: number;
  maxAgeDays?: number;
  snapshotTimestamp?: string;
}

export interface StaleEvidenceOverrides {
  objectives?: Record<string, number | null>;
  artifacts?: Partial<Record<ObjectiveArtifactType, number | null>>;
}

export interface StaleEvidenceOptions {
  snapshotTimestamp?: string;
  analysisTimestamp?: string;
  maxAgeDays?: number | null;
  overrides?: StaleEvidenceOverrides;
}

const normalizeThreshold = (value: number | null | undefined): number | undefined =>
  value === null || value === undefined ? undefined : value;

const resolveAgeThreshold = (
  objectiveId: string,
  artifactType: ObjectiveArtifactType,
  options: StaleEvidenceOptions,
): number | undefined => {
  const objectiveOverride = normalizeThreshold(options.overrides?.objectives?.[objectiveId]);
  if (objectiveOverride !== undefined) {
    return objectiveOverride;
  }
  const artifactOverride = normalizeThreshold(options.overrides?.artifacts?.[artifactType]);
  if (artifactOverride !== undefined) {
    return artifactOverride;
  }
  return normalizeThreshold(options.maxAgeDays);
};

const computeAgeDays = (analysisTime: number, timestamp: number): number | undefined => {
  if (!Number.isFinite(analysisTime)) {
    return undefined;
  }
  const delta = analysisTime - timestamp;
  if (delta <= 0) {
    return 0;
  }
  return Math.floor(delta / MILLISECONDS_PER_DAY);
};

const compareFindings = (left: StaleEvidenceFinding, right: StaleEvidenceFinding): number => {
  const idDiff = left.objectiveId.localeCompare(right.objectiveId);
  if (idDiff !== 0) {
    return idDiff;
  }
  return left.artifactType.localeCompare(right.artifactType);
};

export const detectStaleEvidence = (
  objectives: Objective[],
  evidenceIndex: EvidenceIndex,
  options: StaleEvidenceOptions = {},
): StaleEvidenceFinding[] => {
  const snapshotTime = options.snapshotTimestamp ? Date.parse(options.snapshotTimestamp) : undefined;
  const analysisTime = options.analysisTimestamp
    ? Date.parse(options.analysisTimestamp)
    : Date.now();
  const findings: StaleEvidenceFinding[] = [];

  objectives.forEach((objective) => {
    objective.artifacts.forEach((artifactType) => {
      const evidenceItems = evidenceIndex[artifactType] ?? [];
      if (evidenceItems.length === 0) {
        return;
      }

      let latestTimestamp = Number.NEGATIVE_INFINITY;
      evidenceItems.forEach((item) => {
        const parsed = Date.parse(item.timestamp);
        if (Number.isFinite(parsed) && parsed > latestTimestamp) {
          latestTimestamp = parsed;
        }
      });

      if (!Number.isFinite(latestTimestamp)) {
        return;
      }

      const reasons: StaleEvidenceReason[] = [];
      if (snapshotTime !== undefined && latestTimestamp < snapshotTime) {
        reasons.push('beforeSnapshot');
      }

      const maxAgeDays = resolveAgeThreshold(objective.id, artifactType, options);
      let ageDays: number | undefined;
      if (maxAgeDays !== undefined) {
        ageDays = computeAgeDays(analysisTime, latestTimestamp);
        if (ageDays !== undefined && ageDays > maxAgeDays) {
          reasons.push('exceedsMaxAge');
        }
      } else if (Number.isFinite(analysisTime)) {
        ageDays = computeAgeDays(analysisTime, latestTimestamp);
      }

      if (reasons.length === 0) {
        return;
      }

      findings.push({
        objectiveId: objective.id,
        artifactType,
        latestEvidenceTimestamp: new Date(latestTimestamp).toISOString(),
        reasons,
        ageDays,
        maxAgeDays,
        snapshotTimestamp: options.snapshotTimestamp,
      });
    });
  });

  return findings.sort(compareFindings);
};
