import {
  CoverageMetric,
  CoverageReport,
  FileCoverageSummary,
  TestResult,
  CoverageSummary as StructuralCoverageSummary,
} from '@soipack/adapters';
import {
  CertificationLevel,
  Evidence,
  Objective,
  ObjectiveArtifactType,
  Requirement,
  TraceLink,
} from '@soipack/core';

export type TraceNodeType = 'requirement' | 'test' | 'code';

export interface CodePath {
  path: string;
  coverage?: FileCoverageSummary;
}

export type CoverageStatus = 'covered' | 'partial' | 'missing';

export interface RequirementCoverageStatus {
  requirement: Requirement;
  status: CoverageStatus;
  coverage?: {
    statements?: CoverageMetric;
    branches?: CoverageMetric;
    functions?: CoverageMetric;
  };
  codePaths: CodePath[];
}

export type EvidenceIndex = Partial<Record<ObjectiveArtifactType, Evidence[]>>;

export interface ImportBundle {
  requirements: Requirement[];
  objectives: Objective[];
  testResults: TestResult[];
  coverage?: CoverageReport;
  structuralCoverage?: StructuralCoverageSummary;
  evidenceIndex: EvidenceIndex;
  traceLinks?: TraceLink[];
  testToCodeMap?: Record<string, string[]>;
  generatedAt?: string;
  targetLevel?: CertificationLevel;
}

interface InternalNodeBase {
  key: string;
  id: string;
  links: Set<string>;
}

interface RequirementNode extends InternalNodeBase {
  type: 'requirement';
  data: Requirement;
}

interface TestNode extends InternalNodeBase {
  type: 'test';
  data: TestResult;
}

interface CodeNode extends InternalNodeBase {
  type: 'code';
  data: CodePath;
}

type InternalNode = RequirementNode | TestNode | CodeNode;

interface TraceGraphNodeBase {
  key: string;
  id: string;
  links: string[];
}

export type TraceGraphNode =
  | (TraceGraphNodeBase & { type: 'requirement'; data: Requirement })
  | (TraceGraphNodeBase & { type: 'test'; data: TestResult })
  | (TraceGraphNodeBase & { type: 'code'; data: CodePath });

export interface TraceGraph {
  nodes: TraceGraphNode[];
}

export interface RequirementTrace {
  requirement: Requirement;
  tests: TestResult[];
  code: CodePath[];
}

const createNodeKey = (type: TraceNodeType, id: string): string => `${type}:${id}`;

const normalizePath = (value: string): string => value.replace(/\\/g, '/');

const isRequirementNode = (node: InternalNode): node is RequirementNode =>
  node.type === 'requirement';
const isTestNode = (node: InternalNode): node is TestNode => node.type === 'test';
const isCodeNode = (node: InternalNode): node is CodeNode => node.type === 'code';

export class TraceEngine {
  private readonly nodes = new Map<string, InternalNode>();
  private readonly requirementIds = new Set<string>();
  private readonly testIds = new Set<string>();
  private readonly testToRequirements = new Map<string, Set<string>>();
  private readonly requirementToCode = new Map<string, Set<string>>();
  private readonly coverageByFile = new Map<string, FileCoverageSummary>();

  constructor(private readonly bundle: ImportBundle) {
    this.requirementIds = new Set(bundle.requirements.map((requirement) => requirement.id));
    this.testIds = new Set(bundle.testResults.map((result) => result.testId));
    this.indexCoverage(bundle.coverage);
    this.indexTraceLinks(bundle.traceLinks ?? []);
    this.buildRequirementNodes(bundle.requirements);
    this.buildTestNodes(bundle.testResults, bundle.testToCodeMap ?? {});
    this.linkManualCodeNodes();
  }

  private aggregateCoverageMetrics(codePaths: CodePath[]): {
    statements?: CoverageMetric;
    branches?: CoverageMetric;
    functions?: CoverageMetric;
  } {
    const totals = {
      statements: { covered: 0, total: 0 },
      branches: { covered: 0, total: 0 },
      functions: { covered: 0, total: 0 },
    };

    codePaths.forEach((code) => {
      const coverage = code.coverage;
      if (!coverage) {
        return;
      }
      if (coverage.statements) {
        totals.statements.covered += coverage.statements.covered;
        totals.statements.total += coverage.statements.total;
      }
      if (coverage.branches) {
        totals.branches.covered += coverage.branches.covered;
        totals.branches.total += coverage.branches.total;
      }
      if (coverage.functions) {
        totals.functions.covered += coverage.functions.covered;
        totals.functions.total += coverage.functions.total;
      }
    });

    const finalize = ({
      covered,
      total,
    }: {
      covered: number;
      total: number;
    }): CoverageMetric | undefined => {
      if (total === 0) {
        return undefined;
      }
      return {
        covered,
        total,
        percentage: Number(((covered / total) * 100).toFixed(2)),
      };
    };

    return {
      statements: finalize(totals.statements),
      branches: finalize(totals.branches),
      functions: finalize(totals.functions),
    };
  }

  private determineCoverageStatus(
    codePaths: CodePath[],
    coverage: ReturnType<TraceEngine['aggregateCoverageMetrics']>,
  ): CoverageStatus {
    if (codePaths.length === 0) {
      return 'missing';
    }
    const statements = coverage.statements;
    if (!statements || statements.total === 0) {
      return 'missing';
    }
    if (statements.covered >= statements.total) {
      return 'covered';
    }
    return 'partial';
  }

  private indexCoverage(summary?: CoverageReport): void {
    if (!summary) {
      return;
    }

    summary.files.forEach((fileSummary) => {
      const normalized = normalizePath(fileSummary.file);
      this.coverageByFile.set(normalized, fileSummary);
      this.coverageByFile.set(fileSummary.file, fileSummary);
    });
  }

  private indexTraceLinks(links: TraceLink[]): void {
    const processed = new Set<string>();
    links.forEach((link) => {
      const linkKey = `${link.from}::${link.to}::${link.type}`;
      if (processed.has(linkKey)) {
        return;
      }
      processed.add(linkKey);

      const fromIsRequirement = this.requirementIds.has(link.from);
      const toIsRequirement = this.requirementIds.has(link.to);
      const fromIsTest = this.testIds.has(link.from);
      const toIsTest = this.testIds.has(link.to);

      if (fromIsRequirement && toIsTest) {
        this.ensureTestRequirementLink(link.to, link.from);
      } else if (toIsRequirement && fromIsTest) {
        this.ensureTestRequirementLink(link.from, link.to);
      }

      if (link.type === 'implements') {
        if (fromIsRequirement && !toIsRequirement && !toIsTest) {
          this.ensureRequirementCodeLink(link.from, link.to);
        } else if (toIsRequirement && !fromIsRequirement && !fromIsTest) {
          this.ensureRequirementCodeLink(link.to, link.from);
        }
      }
    });
  }

  private ensureTestRequirementLink(testId: string, requirementId: string): void {
    const existing = this.testToRequirements.get(testId) ?? new Set<string>();
    existing.add(requirementId);
    this.testToRequirements.set(testId, existing);
  }

  private ensureRequirementCodeLink(requirementId: string, rawPath: string): void {
    const normalizedPath = normalizePath(rawPath.trim());
    if (!normalizedPath) {
      return;
    }
    const existing = this.requirementToCode.get(requirementId) ?? new Set<string>();
    existing.add(normalizedPath);
    this.requirementToCode.set(requirementId, existing);
  }

  private linkManualCodeNodes(): void {
    this.requirementToCode.forEach((codePaths, requirementId) => {
      const requirementKey = createNodeKey('requirement', requirementId);
      const requirementNode = this.nodes.get(requirementKey);
      if (!requirementNode || !isRequirementNode(requirementNode)) {
        return;
      }

      codePaths.forEach((codePath) => {
        const normalized = normalizePath(codePath);
        const coverage = this.coverageByFile.get(normalized) ?? this.coverageByFile.get(codePath);
        const codeKey = createNodeKey('code', normalized);
        const existing = this.nodes.get(codeKey);
        if (existing && isCodeNode(existing)) {
          this.linkNodes(requirementKey, codeKey);
          return;
        }

        const codeNode: CodeNode = {
          key: codeKey,
          id: normalized,
          type: 'code',
          data: {
            path: normalized,
            coverage,
          },
          links: new Set(),
        };

        this.nodes.set(codeKey, codeNode);
        this.linkNodes(requirementKey, codeKey);
      });
    });
  }

  private buildRequirementNodes(requirements: Requirement[]): void {
    requirements.forEach((requirement) => {
      const key = createNodeKey('requirement', requirement.id);
      this.nodes.set(key, {
        key,
        id: requirement.id,
        type: 'requirement',
        data: requirement,
        links: new Set(),
      });
    });
  }

  private buildTestNodes(testResults: TestResult[], testToCodeMap: Record<string, string[]>): void {
    testResults.forEach((test) => {
      const key = createNodeKey('test', test.testId);
      const node: TestNode = {
        key,
        id: test.testId,
        type: 'test',
        data: test,
        links: new Set(),
      };

      this.nodes.set(key, node);

      const requirementRefs = new Set<string>(test.requirementsRefs ?? []);
      const tracedRequirements = this.testToRequirements.get(test.testId);
      tracedRequirements?.forEach((requirementId) => requirementRefs.add(requirementId));

      requirementRefs.forEach((requirementId) => {
        const requirementKey = createNodeKey('requirement', requirementId);
        const requirementNode = this.nodes.get(requirementKey);
        if (requirementNode && isRequirementNode(requirementNode)) {
          this.linkNodes(node.key, requirementNode.key);
        }
      });

      const codePaths = testToCodeMap[test.testId] ?? [];
      codePaths.forEach((path) => {
        const normalized = normalizePath(path);
        const coverage = this.coverageByFile.get(normalized) ?? this.coverageByFile.get(path);
        const codeKey = createNodeKey('code', normalized);
        const existing = this.nodes.get(codeKey);
        if (existing && isCodeNode(existing)) {
          this.linkNodes(node.key, existing.key);
          return;
        }

        const codeNode: CodeNode = {
          key: codeKey,
          id: normalized,
          type: 'code',
          data: {
            path: normalized,
            coverage,
          },
          links: new Set(),
        };

        this.nodes.set(codeKey, codeNode);
        this.linkNodes(node.key, codeNode.key);
      });
    });
  }

  private linkNodes(sourceKey: string, targetKey: string): void {
    if (sourceKey === targetKey) {
      return;
    }

    const source = this.nodes.get(sourceKey);
    const target = this.nodes.get(targetKey);
    if (!source || !target) {
      return;
    }

    source.links.add(targetKey);
    target.links.add(sourceKey);
  }

  public getGraph(): TraceGraph {
    const nodes: TraceGraphNode[] = [];
    this.nodes.forEach((node) => {
      const links = Array.from(node.links.values());
      if (isRequirementNode(node)) {
        nodes.push({
          key: node.key,
          id: node.id,
          type: 'requirement',
          data: node.data,
          links,
        });
      } else if (isTestNode(node)) {
        nodes.push({
          key: node.key,
          id: node.id,
          type: 'test',
          data: node.data,
          links,
        });
      } else if (isCodeNode(node)) {
        nodes.push({
          key: node.key,
          id: node.id,
          type: 'code',
          data: node.data,
          links,
        });
      }
    });

    return { nodes };
  }

  public getRequirementTrace(requirementId: string): RequirementTrace {
    const requirementKey = createNodeKey('requirement', requirementId);
    const requirementNode = this.nodes.get(requirementKey);

    if (!requirementNode || !isRequirementNode(requirementNode)) {
      throw new Error(`Requirement ${requirementId} not found in trace graph.`);
    }

    const tests: TestResult[] = [];
    const code = new Map<string, CodePath>();

    requirementNode.links.forEach((neighborKey) => {
      const neighbor = this.nodes.get(neighborKey);
      if (!neighbor) {
        return;
      }
      if (isTestNode(neighbor)) {
        tests.push(neighbor.data);
        neighbor.links.forEach((codeKey) => {
          const codeNode = this.nodes.get(codeKey);
          if (!codeNode || !isCodeNode(codeNode)) {
            return;
          }

          code.set(codeKey, codeNode.data);
        });
        return;
      }

      if (isCodeNode(neighbor)) {
        code.set(neighborKey, neighbor.data);
      }
    });

    return {
      requirement: requirementNode.data,
      tests,
      code: Array.from(code.values()),
    };
  }

  public getRequirementCoverage(): RequirementCoverageStatus[] {
    return this.bundle.requirements.map((requirement) => {
      const trace = this.getRequirementTrace(requirement.id);
      const coverage = this.aggregateCoverageMetrics(trace.code);
      const status = this.determineCoverageStatus(trace.code, coverage);

      return {
        requirement,
        status,
        coverage,
        codePaths: trace.code,
      };
    });
  }
}

export type ObjectiveCoverageStatus = 'covered' | 'partial' | 'missing';

export interface ObjectiveCoverage {
  objectiveId: string;
  status: ObjectiveCoverageStatus;
  evidenceRefs: string[];
  satisfiedArtifacts: ObjectiveArtifactType[];
  missingArtifacts: ObjectiveArtifactType[];
}

const coverageArtifactMetrics: Partial<Record<ObjectiveArtifactType, 'stmt' | 'dec' | 'mcdc'>> = {
  coverage_stmt: 'stmt',
  coverage_dec: 'dec',
  coverage_mcdc: 'mcdc',
};

export class ObjectiveMapper {
  private readonly structuralCoverage?: StructuralCoverageSummary;
  private readonly coverageTotals: Record<'stmt' | 'dec' | 'mcdc', { covered: number; total: number }>;

  constructor(
    private readonly objectives: Objective[],
    private readonly evidenceIndex: EvidenceIndex,
    options: { structuralCoverage?: StructuralCoverageSummary; targetLevel?: CertificationLevel } = {},
  ) {
    this.structuralCoverage = options.structuralCoverage;
    this.coverageTotals = this.computeCoverageTotals(this.structuralCoverage);
  }

  public mapObjectives(): ObjectiveCoverage[] {
    return this.objectives.map((objective) => this.evaluateObjective(objective));
  }

  private evaluateObjective(objective: Objective): ObjectiveCoverage {
    const satisfiedArtifacts: ObjectiveArtifactType[] = [];
    const missingArtifacts: ObjectiveArtifactType[] = [];
    const evidenceRefs: string[] = [];
    let hasPartialCoverage = false;

    objective.artifacts.forEach((artifactType) => {
      const evidenceItems = this.evidenceIndex[artifactType] ?? [];
      if (coverageArtifactMetrics[artifactType]) {
        const coverageStatus = this.evaluateCoverageArtifact(artifactType);
        if (evidenceItems.length === 0) {
          missingArtifacts.push(artifactType);
        } else if (coverageStatus === 'covered') {
          satisfiedArtifacts.push(artifactType);
        } else if (coverageStatus === 'partial') {
          satisfiedArtifacts.push(artifactType);
          hasPartialCoverage = true;
          missingArtifacts.push(artifactType);
        } else {
          missingArtifacts.push(artifactType);
        }
        evidenceItems.forEach((evidence) => {
          evidenceRefs.push(this.createEvidenceRef(artifactType, evidence));
        });
        return;
      }

      if (evidenceItems.length > 0) {
        satisfiedArtifacts.push(artifactType);
        evidenceItems.forEach((evidence) => {
          evidenceRefs.push(this.createEvidenceRef(artifactType, evidence));
        });
      } else {
        missingArtifacts.push(artifactType);
      }
    });

    let status: ObjectiveCoverageStatus;
    if (missingArtifacts.length === 0) {
      status = hasPartialCoverage ? 'partial' : 'covered';
    } else if (satisfiedArtifacts.length === 0) {
      status = 'missing';
    } else {
      status = 'partial';
    }

    return {
      objectiveId: objective.id,
      status,
      evidenceRefs,
      satisfiedArtifacts,
      missingArtifacts,
    };
  }

  private computeCoverageTotals(
    summary?: StructuralCoverageSummary,
  ): Record<'stmt' | 'dec' | 'mcdc', { covered: number; total: number }> {
    const totals = {
      stmt: { covered: 0, total: 0 },
      dec: { covered: 0, total: 0 },
      mcdc: { covered: 0, total: 0 },
    };

    if (!summary) {
      return totals;
    }

    summary.files.forEach((file) => {
      totals.stmt.covered += file.stmt.covered;
      totals.stmt.total += file.stmt.total;
      if (file.dec) {
        totals.dec.covered += file.dec.covered;
        totals.dec.total += file.dec.total;
      }
      if (file.mcdc) {
        totals.mcdc.covered += file.mcdc.covered;
        totals.mcdc.total += file.mcdc.total;
      }
    });

    return totals;
  }

  private evaluateCoverageArtifact(artifact: ObjectiveArtifactType): 'missing' | 'partial' | 'covered' {
    const metric = coverageArtifactMetrics[artifact];
    if (!metric) {
      return 'missing';
    }
    const totals = this.coverageTotals[metric];
    if (!totals || totals.total === 0) {
      return 'missing';
    }
    if (totals.covered >= totals.total) {
      return 'covered';
    }
    return 'partial';
  }

  private createEvidenceRef(type: ObjectiveArtifactType, evidence: Evidence): string {
    return `${type}:${evidence.path}`;
  }
}

export interface GapItem {
  objectiveId: string;
  missingArtifacts: ObjectiveArtifactType[];
}

export interface GapAnalysis {
  plans: GapItem[];
  standards: GapItem[];
  reviews: GapItem[];
  analysis: GapItem[];
  tests: GapItem[];
  coverage: GapItem[];
  trace: GapItem[];
  configuration: GapItem[];
  quality: GapItem[];
  issues: GapItem[];
  conformity: GapItem[];
}

const artifactCategoryMap: Record<ObjectiveArtifactType, keyof GapAnalysis> = {
  plan: 'plans',
  standard: 'standards',
  review: 'reviews',
  analysis: 'analysis',
  test: 'tests',
  coverage_stmt: 'coverage',
  coverage_dec: 'coverage',
  coverage_mcdc: 'coverage',
  trace: 'trace',
  cm_record: 'configuration',
  qa_record: 'quality',
  problem_report: 'issues',
  conformity: 'conformity',
};

export const buildGapAnalysis = (objectiveCoverage: ObjectiveCoverage[]): GapAnalysis => {
  const categoryBuckets: Record<keyof GapAnalysis, Map<string, Set<ObjectiveArtifactType>>> = {
    plans: new Map(),
    standards: new Map(),
    reviews: new Map(),
    analysis: new Map(),
    tests: new Map(),
    coverage: new Map(),
    trace: new Map(),
    configuration: new Map(),
    quality: new Map(),
    issues: new Map(),
    conformity: new Map(),
  };

  objectiveCoverage.forEach((coverage) => {
    coverage.missingArtifacts.forEach((artifact) => {
      const category = artifactCategoryMap[artifact];
      const bucket = categoryBuckets[category];
      const entry = bucket.get(coverage.objectiveId) ?? new Set<ObjectiveArtifactType>();
      entry.add(artifact);
      bucket.set(coverage.objectiveId, entry);
    });
  });

  const toGapItems = (bucket: Map<string, Set<ObjectiveArtifactType>>): GapItem[] =>
    Array.from(bucket.entries()).map(([objectiveId, artifacts]) => ({
      objectiveId,
      missingArtifacts: Array.from(artifacts.values()),
    }));

  return {
    plans: toGapItems(categoryBuckets.plans),
    standards: toGapItems(categoryBuckets.standards),
    reviews: toGapItems(categoryBuckets.reviews),
    analysis: toGapItems(categoryBuckets.analysis),
    tests: toGapItems(categoryBuckets.tests),
    coverage: toGapItems(categoryBuckets.coverage),
    trace: toGapItems(categoryBuckets.trace),
    configuration: toGapItems(categoryBuckets.configuration),
    quality: toGapItems(categoryBuckets.quality),
    issues: toGapItems(categoryBuckets.issues),
    conformity: toGapItems(categoryBuckets.conformity),
  };
};

export interface ObjectiveStatistics {
  total: number;
  covered: number;
  partial: number;
  missing: number;
}

export interface TestStatistics {
  total: number;
  passed: number;
  failed: number;
  skipped: number;
}

export interface ComplianceStatistics {
  objectives: ObjectiveStatistics;
  requirements: { total: number };
  tests: TestStatistics;
  codePaths: { total: number };
}

export interface ComplianceSnapshot {
  generatedAt: string;
  objectives: ObjectiveCoverage[];
  stats: ComplianceStatistics;
  gaps: GapAnalysis;
  traceGraph: TraceGraph;
  requirementCoverage: RequirementCoverageStatus[];
}

const summarizeObjectives = (coverage: ObjectiveCoverage[]): ObjectiveStatistics => {
  return coverage.reduce(
    (acc, item) => {
      acc.total += 1;
      acc[item.status] += 1;
      return acc;
    },
    { total: 0, covered: 0, partial: 0, missing: 0 },
  );
};

const summarizeTests = (tests: TestResult[]): TestStatistics => {
  return tests.reduce(
    (acc, test) => {
      acc.total += 1;
      if (test.status === 'passed') {
        acc.passed += 1;
      } else if (test.status === 'failed') {
        acc.failed += 1;
      } else {
        acc.skipped += 1;
      }
      return acc;
    },
    { total: 0, passed: 0, failed: 0, skipped: 0 },
  );
};

export const generateComplianceSnapshot = (bundle: ImportBundle): ComplianceSnapshot => {
  const engine = new TraceEngine(bundle);
  const mapper = new ObjectiveMapper(bundle.objectives, bundle.evidenceIndex, {
    structuralCoverage: bundle.structuralCoverage,
    targetLevel: bundle.targetLevel,
  });
  const objectiveCoverage = mapper.mapObjectives();
  const traceGraph = engine.getGraph();
  const requirementCoverage = engine.getRequirementCoverage();
  const objectiveStats = summarizeObjectives(objectiveCoverage);
  const testStats = summarizeTests(bundle.testResults);
  const gapAnalysis = buildGapAnalysis(objectiveCoverage);
  const codePathCount = traceGraph.nodes.filter((node) => node.type === 'code').length;

  return {
    generatedAt: bundle.generatedAt ?? new Date().toISOString(),
    objectives: objectiveCoverage,
    stats: {
      objectives: objectiveStats,
      requirements: { total: bundle.requirements.length },
      tests: testStats,
      codePaths: { total: codePathCount },
    },
    gaps: gapAnalysis,
    traceGraph,
    requirementCoverage,
  };
};
