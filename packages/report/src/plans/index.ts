import type {
  CertificationLevel,
  Objective,
  ObjectiveArtifactType,
} from '@soipack/core';
import type { ComplianceSnapshot } from '@soipack/engine';
import {
  AlignmentType,
  Document,
  HeadingLevel,
  Packer,
  Paragraph,
  Table,
  TableCell,
  TableRow,
  TextRun,
  WidthType,
} from 'docx';
import nunjucks from 'nunjucks';

import packageInfo from '../../package.json';

import { basePlanTemplate, planTemplateDefinitions } from './templates';
import type { PlanTemplateDefinition, PlanTemplateId } from './types';

type ParagraphAlignment = (typeof AlignmentType)[keyof typeof AlignmentType];

const templateEnv = new nunjucks.Environment(undefined, {
  autoescape: true,
  trimBlocks: true,
  lstripBlocks: true,
});

const statusLabels = {
  covered: 'Covered',
  partial: 'Partially Covered',
  missing: 'Missing',
} as const;

const statusClasses = {
  covered: 'status-covered',
  partial: 'status-partial',
  missing: 'status-missing',
} as const;

const artifactLabels: Record<ObjectiveArtifactType, string> = {
  plan: 'Plans',
  standard: 'Standards',
  review: 'Reviews',
  analysis: 'Analyses',
  test: 'Test Evidence',
  coverage_stmt: 'Statement Coverage',
  coverage_dec: 'Decision Coverage',
  coverage_mcdc: 'MC/DC Coverage',
  trace: 'Traceability',
  cm_record: 'Configuration Records',
  qa_record: 'Quality Assurance Records',
  problem_report: 'Problem Reports',
  conformity: 'Conformity Review',
};

const paragraph = (...sentences: string[]): string => {
  const text = sentences.join(' ').replace(/\s+/g, ' ').trim();
  return `<p>${text}</p>`;
};

interface DefaultContentContext {
  projectLabel: string;
  levelNarrative: string;
  requirementTotal: number;
  testTotal: number;
  passedTests: number;
  failedTests: number;
  skippedTests: number;
  coveragePercent: number;
  coveredCount: number;
  partialCount: number;
  missingCount: number;
  objectiveTotal: number;
  codePaths: number;
  generatedAt: string;
}

interface DefaultPlanContent {
  overview: string;
  sections: Record<string, string>;
}

interface PlanObjectiveRow {
  id: string;
  name: string;
  description: string;
  table?: string;
  status: keyof typeof statusLabels;
  statusLabel: string;
  statusClass: string;
  satisfiedArtifacts: string[];
  missingArtifacts: string[];
  evidenceRefs: string[];
}

const buildDefaultContent = (
  templateId: PlanTemplateId,
  ctx: DefaultContentContext,
): DefaultPlanContent => {
  const outstandingCount = ctx.partialCount + ctx.missingCount;

  switch (templateId) {
    case 'psac':
      return {
        overview: paragraph(
          `The Plan for Software Aspects of Certification (PSAC) for ${ctx.projectLabel} establishes the activities, approvals, and evidence required to achieve ${ctx.levelNarrative} compliance with DO-178C.`,
          `As of ${ctx.generatedAt}, ${ctx.coveredCount} of ${ctx.objectiveTotal} objectives (${ctx.coveragePercent}%) are fully satisfied, supported by ${ctx.testTotal} verification cases that demonstrate the ${ctx.requirementTotal} tracked requirements.`,
        ),
        sections: {
          introduction: paragraph(
            `${ctx.projectLabel} targets ${ctx.levelNarrative} certification.`,
            'The applicant coordinates with designated engineering representatives and the certification authority to review plans, track issue resolutions, and approve baseline data for each life-cycle phase.',
          ),
          softwareLifecycle: paragraph(
            'The software life cycle follows a requirements-driven approach covering planning, development, verification, and configuration management.',
            `${ctx.requirementTotal} high-level requirements are baselined with traceability to design data and ${ctx.testTotal} verification cases to demonstrate completion.`,
          ),
          developmentEnvironment: paragraph(
            'Development activities leverage configuration-controlled repositories, code generation, static analysis, and automated build services.',
            `${ctx.codePaths} controlled code elements are maintained with peer review records and tool qualification evidence where required.`,
          ),
          complianceStrategy: paragraph(
            'Each DO-178C objective is mapped to specific plans, analyses, tests, and configuration data.',
            `${ctx.coveragePercent}% of objectives are fully covered, with ${ctx.partialCount} partial and ${ctx.missingCount} missing items tracked in the compliance gap log until closure.`,
          ),
          schedule: paragraph(
            'Certification data is generated incrementally with continuous authority engagement.',
            `Remaining findings (${outstandingCount}) are scheduled for targeted reviews, regression testing, and approvals prior to final certification submission.`,
          ),
        },
      };
    case 'sdp':
      return {
        overview: paragraph(
          `The Software Development Plan (SDP) for ${ctx.projectLabel} defines the engineering processes, methods, and resources that guide development towards ${ctx.levelNarrative} compliance.`,
          `${ctx.requirementTotal} functional requirements and ${ctx.testTotal} verification cases provide the baseline managed under configuration control as of ${ctx.generatedAt}.`,
        ),
        sections: {
          introduction: paragraph(
            `${ctx.projectLabel} is developed under a staged life cycle aligned with DO-178C guidance.`,
            'Planning artefacts establish objectives for requirements, architecture, implementation, verification, and certification coordination.',
          ),
          organization: paragraph(
            'The project organization assigns system, software, verification, and quality leads with defined independence.',
            'Suppliers and partners integrate into the same configuration and reporting processes to maintain visibility of deliverables.',
          ),
          developmentStandards: paragraph(
            'Development adheres to approved standards covering requirements notation, modelling, coding guidelines, and peer review checklists.',
            'Deviation handling and tool qualification approaches are documented to satisfy the applicable DO-178C objectives.',
          ),
          infrastructure: paragraph(
            'Engineering infrastructure includes requirements management, modelling, version control, build automation, and verification dashboards.',
            `${ctx.codePaths} software components are built and tested using reproducible toolchains with continuous integration feedback.`,
          ),
          configurationManagement: paragraph(
            'Configuration management processes align with the SCMP to baseline plans, requirements, code, and verification evidence.',
            'Interfaces define how change requests, releases, and audits are coordinated across development and verification teams.',
          ),
        },
      };
    case 'svp':
      return {
        overview: paragraph(
          `The Software Verification Plan (SVP) for ${ctx.projectLabel} captures the verification scope, independence, and coverage objectives needed for ${ctx.levelNarrative} certification.`,
          `Current data shows ${ctx.coveragePercent}% objective coverage with ${ctx.testTotal} verification cases executing against the ${ctx.requirementTotal} baseline requirements.`,
        ),
        sections: {
          verificationScope: paragraph(
            'Verification encompasses reviews, analyses, and testing across all life-cycle phases.',
            `${ctx.testTotal} cases cover functionality, interface behaviour, and robustness with independence applied according to DO-178C.`,
          ),
          reviewsAndAnalysis: paragraph(
            'Structured reviews confirm traceability and correctness of requirements, design, code, and test artefacts.',
            'Static analyses and walkthroughs provide supplemental evidence to justify coverage gaps and anomalous conditions.',
          ),
          testingStrategy: paragraph(
            'Dynamic testing includes requirements-based, interface, and regression campaigns.',
            `${ctx.passedTests} tests have passed, ${ctx.failedTests} have outstanding findings, and ${ctx.skippedTests} are awaiting data or dependencies.`,
          ),
          coverageAssessment: paragraph(
            'Structural coverage and requirements completeness are monitored continuously.',
            `${ctx.coveragePercent}% of objectives are satisfied; remaining partial (${ctx.partialCount}) and missing (${ctx.missingCount}) objectives drive targeted verification tasks.`,
          ),
          anomalyResolution: paragraph(
            'Problem reports, change requests, and discrepancy tracking ensure anomalies are recorded and dispositioned.',
            `Outstanding items (${outstandingCount}) are assessed for safety impact and resolved before final qualification.`,
          ),
        },
      };
    case 'scmp':
      return {
        overview: paragraph(
          `The Software Configuration Management Plan (SCMP) for ${ctx.projectLabel} defines how configuration items, baselines, and changes are controlled throughout the programme.`,
          `${ctx.codePaths} controlled code elements and ${ctx.requirementTotal} requirements are maintained under configuration status accounting with audits tied to ${ctx.levelNarrative} objectives.`,
        ),
        sections: {
          introduction: paragraph(
            'Configuration management ensures integrity of plans, requirements, code, tools, and generated data.',
            'The CM organisation coordinates with development and verification leads to maintain authoritative baselines.',
          ),
          responsibilities: paragraph(
            'Roles define who raises, evaluates, approves, and implements change requests.',
            'Independence between development and verification is maintained while sharing transparent status accounting.',
          ),
          baselines: paragraph(
            'Baselines capture planning data, requirements, design artefacts, source code, test procedures, and results.',
            `Each release identifies the ${ctx.requirementTotal} approved requirements and associated evidence ready for certification review.`,
          ),
          changeControl: paragraph(
            'Change control records include impact analysis, trace updates, and verification evidence updates.',
            `Open findings (${outstandingCount}) remain under CM tracking until all objectives are marked complete.`,
          ),
          audits: paragraph(
            'Configuration audits verify repository integrity, traceability, and documentation completeness before major milestones.',
            `Results feed certification data packages generated on ${ctx.generatedAt}.`,
          ),
        },
      };
    case 'sqap':
      return {
        overview: paragraph(
          `The Software Quality Assurance Plan (SQAP) for ${ctx.projectLabel} outlines independent oversight ensuring processes satisfy ${ctx.levelNarrative} objectives.`,
          `Quality assurance monitors ${ctx.requirementTotal} requirements, ${ctx.testTotal} verification artefacts, and the ${ctx.coveragePercent}% objective coverage achieved to date.`,
        ),
        sections: {
          qualityPolicy: paragraph(
            'Quality assurance policies enforce compliance with approved plans, standards, and certification commitments.',
            'Audit findings are reported to management and authorities with authority to stop non-conforming activities.',
          ),
          processAssurance: paragraph(
            'QA reviews confirm processes are executed, documented, and independently assessed throughout each phase.',
            'Checklists cover planning, development, verification, configuration management, and problem reporting.',
          ),
          audits: paragraph(
            'Process audits and product inspections evaluate adherence to DO-178C objectives and internal standards.',
            `Sampling focuses on areas with partial (${ctx.partialCount}) or missing (${ctx.missingCount}) objective coverage.`,
          ),
          metrics: paragraph(
            'Metrics track requirement maturity, verification progress, anomaly trends, and closure rates.',
            `Dashboards highlight ${ctx.coveragePercent}% objective coverage and ${ctx.passedTests}/${ctx.testTotal} passing tests.`,
          ),
          records: paragraph(
            'QA records include plans, checklists, audit reports, meeting minutes, and corrective actions.',
            `Records are archived to support certification submissions planned after ${ctx.generatedAt}.`,
          ),
        },
      };
    default:
      return { overview: paragraph('No content available.'), sections: {} };
  }
};

const toArtifactLabel = (artifact: ObjectiveArtifactType): string =>
  artifactLabels[artifact] ?? artifact.replace(/_/g, ' ');

const htmlToPlainText = (html: string): string =>
  html
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/p>/gi, '\n\n')
    .replace(/<li>\s*/gi, '\n• ')
    .replace(/<\/li>/gi, '')
    .replace(/&nbsp;/gi, ' ')
    .replace(/<[^>]+>/g, '')
    .replace(/\r?\n\s+/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();

const paragraphsFromPlainText = (text: string): Paragraph[] =>
  text
    .split(/\n+/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .map((line) =>
      line.startsWith('• ')
        ? new Paragraph({ text: line.replace(/^•\s*/, ''), bullet: { level: 0 } })
        : new Paragraph({ text: line }),
    );

const paragraphsFromHtml = (html: string): Paragraph[] => paragraphsFromPlainText(htmlToPlainText(html));

const createHeaderCell = (text: string): TableCell =>
  new TableCell({
    children: [
      new Paragraph({
        alignment: AlignmentType.CENTER,
        children: [new TextRun({ text, bold: true })],
      }),
    ],
  });

const createBodyCell = (
  value: string | string[],
  options: { alignment?: ParagraphAlignment } = {},
): TableCell => {
  const alignment = options.alignment ?? AlignmentType.LEFT;
  const lines = Array.isArray(value) ? value : [value];
  const normalized = lines
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  const paragraphs =
    normalized.length > 0
      ? normalized.map((line) => new Paragraph({ text: line, alignment }))
      : [new Paragraph({ text: '—', alignment })];

  return new TableCell({ children: paragraphs });
};

const toProjectLabel = (project?: { name?: string; version?: string }): string => {
  if (!project?.name && !project?.version) {
    return 'Unnamed Project';
  }
  if (project?.name && project?.version) {
    return `${project.name} v${project.version}`;
  }
  if (project?.name) {
    return project.name;
  }
  if (project?.version) {
    return `v${project.version}`;
  }
  return 'Unnamed Project';
};

const computeTableSummary = (
  objectives: Array<{
    table?: string;
    status: keyof typeof statusLabels;
  }>,
): Array<{ table: string; total: number; covered: number; partial: number; missing: number }> => {
  const aggregates = new Map<string, { table: string; total: number; covered: number; partial: number; missing: number }>();

  objectives.forEach((objective) => {
    const table = objective.table ?? 'Unspecified';
    const existing = aggregates.get(table) ?? { table, total: 0, covered: 0, partial: 0, missing: 0 };
    existing.total += 1;
    existing[objective.status] += 1;
    aggregates.set(table, existing);
  });

  const summary = Array.from(aggregates.values()).sort((a, b) => a.table.localeCompare(b.table));

  if (summary.length === 0) {
    return [{ table: 'Unspecified', total: 0, covered: 0, partial: 0, missing: 0 }];
  }

  return summary;
};

const buildDocxDocument = async (context: {
  definition: PlanTemplateDefinition;
  projectLabel: string;
  levelLabel: string;
  manifestId?: string;
  generatedAt: string;
  coverageSummary: PlanRenderResult['coverageSummary'];
  stats: ComplianceSnapshot['stats'];
  sections: Record<string, string>;
  tableSummary: Array<{ table: string; total: number; covered: number; partial: number; missing: number }>;
  objectives: PlanObjectiveRow[];
  openObjectives: PlanObjectiveRow[];
  openSummary: string;
  additionalNotes?: string;
}): Promise<Buffer> => {
  const children: Array<Paragraph | Table> = [];

  children.push(new Paragraph({ text: context.definition.title, heading: HeadingLevel.TITLE }));
  children.push(new Paragraph({ text: context.definition.purpose }));
  children.push(new Paragraph({ text: `Project: ${context.projectLabel}` }));
  children.push(new Paragraph({ text: `Certification Level: ${context.levelLabel}` }));
  children.push(new Paragraph({ text: `Manifest ID: ${context.manifestId ?? 'Pending'}` }));
  children.push(new Paragraph({ text: `Generated: ${context.generatedAt}` }));
  children.push(new Paragraph({ text: '' }));

  children.push(new Paragraph({ text: 'Summary', heading: HeadingLevel.HEADING_2 }));
  children.push(new Paragraph({ text: context.coverageSummary.text }));
  children.push(
    new Paragraph({
      text: `Verification Tests: ${context.stats.tests.total} total · ${context.stats.tests.passed} passed · ${context.stats.tests.failed} failed · ${context.stats.tests.skipped} skipped`,
    }),
  );
  children.push(
    new Paragraph({
      text: `Tracked Requirements: ${context.stats.requirements.total}`,
    }),
  );
  children.push(new Paragraph({ text: `Code Elements: ${context.stats.codePaths.total}` }));

  context.definition.sections.forEach((section) => {
    children.push(new Paragraph({ text: section.title, heading: HeadingLevel.HEADING_2 }));
    const sectionParagraphs = paragraphsFromHtml(context.sections[section.id] ?? '');
    if (sectionParagraphs.length > 0) {
      children.push(...sectionParagraphs);
    } else {
      children.push(new Paragraph({ text: 'Content pending definition.' }));
    }
  });

  children.push(new Paragraph({ text: 'Objective Coverage Summary', heading: HeadingLevel.HEADING_2 }));

  const coverageTable = new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: [
      new TableRow({
        tableHeader: true,
        children: ['Objective Table', 'Total', 'Covered', 'Partial', 'Missing'].map((header) =>
          createHeaderCell(header),
        ),
      }),
      ...context.tableSummary.map((row) =>
        new TableRow({
          children: [
            createBodyCell(row.table),
            createBodyCell(String(row.total), { alignment: AlignmentType.CENTER }),
            createBodyCell(String(row.covered), { alignment: AlignmentType.CENTER }),
            createBodyCell(String(row.partial), { alignment: AlignmentType.CENTER }),
            createBodyCell(String(row.missing), { alignment: AlignmentType.CENTER }),
          ],
        }),
      ),
    ],
  });
  children.push(coverageTable);

  children.push(new Paragraph({ text: 'Detailed Objective Mapping', heading: HeadingLevel.HEADING_2 }));

  const objectiveTable = new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: [
      new TableRow({
        tableHeader: true,
        children: ['Objective', 'Table', 'Description', 'Status', 'Evidence & Gaps'].map((header) =>
          createHeaderCell(header),
        ),
      }),
      ...context.objectives.map((objective) => {
        const evidenceParts: string[] = [];
        if (objective.satisfiedArtifacts.length > 0) {
          evidenceParts.push(`Available: ${objective.satisfiedArtifacts.join(', ')}`);
        }
        if (objective.missingArtifacts.length > 0) {
          evidenceParts.push(`Gaps: ${objective.missingArtifacts.join(', ')}`);
        }
        if (objective.evidenceRefs.length > 0) {
          evidenceParts.push(`Refs: ${objective.evidenceRefs.join(', ')}`);
        }

        const descriptionParagraphs = [
          new Paragraph({ children: [new TextRun({ text: objective.name, bold: true })] }),
          ...(objective.description ? [new Paragraph({ text: objective.description })] : []),
        ];

        return new TableRow({
          children: [
            createBodyCell(objective.id),
            createBodyCell(objective.table ?? '—', { alignment: AlignmentType.CENTER }),
            new TableCell({ children: descriptionParagraphs }),
            createBodyCell(objective.statusLabel, { alignment: AlignmentType.CENTER }),
            createBodyCell(evidenceParts.length > 0 ? evidenceParts : ['—']),
          ],
        });
      }),
    ],
  });
  children.push(objectiveTable);

  if (context.openObjectives.length > 0) {
    children.push(new Paragraph({ text: 'Open Compliance Items', heading: HeadingLevel.HEADING_2 }));
    children.push(new Paragraph({ text: context.openSummary }));
    context.openObjectives.forEach((objective) => {
      children.push(
        new Paragraph({
          text: `${objective.id} — ${objective.name} (${objective.statusLabel})`,
          bullet: { level: 0 },
        }),
      );
    });
  }

  if (context.additionalNotes) {
    children.push(new Paragraph({ text: 'Notes', heading: HeadingLevel.HEADING_2 }));
    children.push(...paragraphsFromHtml(context.additionalNotes));
  }

  children.push(
    new Paragraph({
      text: `Generated by SOIPack ${packageInfo.version} on ${context.generatedAt} for ${context.projectLabel}.`,
    }),
  );

  const doc = new Document({
    sections: [
      {
        properties: {},
        children,
      },
    ],
  });

  return Packer.toBuffer(doc);
};

export interface PlanRenderOptions {
  snapshot: ComplianceSnapshot;
  objectivesMetadata?: Objective[];
  manifestId?: string;
  project?: { name?: string; version?: string };
  level?: CertificationLevel;
  generatedAt?: string;
  overview?: string;
  sections?: Record<string, string>;
  additionalNotes?: string;
}

export interface PlanRenderResult {
  id: PlanTemplateId;
  title: string;
  html: string;
  docx: Buffer;
  overview: string;
  sections: Record<string, string>;
  coverageSummary: {
    total: number;
    coveredCount: number;
    partialCount: number;
    missingCount: number;
    coveragePercent: number;
    text: string;
  };
}

export interface PlanOverrideConfig {
  overview?: string;
  sections?: Record<string, string>;
  additionalNotes?: string;
}

export type PlanSectionOverrides = Partial<Record<PlanTemplateId, PlanOverrideConfig>>;

export const planTemplateSections: Record<PlanTemplateId, string[]> = Object.fromEntries(
  Object.entries(planTemplateDefinitions).map(([id, definition]) => [
    id,
    definition.sections.map((section) => section.id),
  ]),
) as Record<PlanTemplateId, string[]>;

export const planTemplateTitles: Record<PlanTemplateId, string> = Object.fromEntries(
  Object.entries(planTemplateDefinitions).map(([id, definition]) => [id, definition.title]),
) as Record<PlanTemplateId, string>;

const buildPlanContext = (
  definition: PlanTemplateDefinition,
  templateId: PlanTemplateId,
  options: PlanRenderOptions,
): {
  html: string;
  sections: Record<string, string>;
  overview: string;
  coverageSummary: PlanRenderResult['coverageSummary'];
  tableSummary: Array<{ table: string; total: number; covered: number; partial: number; missing: number }>;
  objectives: PlanObjectiveRow[];
  openObjectives: PlanObjectiveRow[];
  openSummary: string;
  projectLabel: string;
  levelLabel: string;
  generatedAt: string;
} => {
  const snapshot = options.snapshot;
  const metadataMap = new Map(
    (options.objectivesMetadata ?? []).map((objective) => [objective.id, objective]),
  );
  const projectLabel = toProjectLabel(options.project);
  const levelValue = options.level;
  const levelLabel = levelValue ? `Level ${levelValue}` : 'Not Specified';
  const levelNarrative = levelValue ? `Level ${levelValue}` : 'the applicable certification level';
  const generatedAt = options.generatedAt ?? snapshot.generatedAt ?? new Date().toISOString();

  const coverageStats = snapshot.stats.objectives;
  const coveragePercent = coverageStats.total > 0
    ? Math.round((coverageStats.covered / coverageStats.total) * 100)
    : 0;

  const coverageSummary = {
    total: coverageStats.total,
    coveredCount: coverageStats.covered,
    partialCount: coverageStats.partial,
    missingCount: coverageStats.missing,
    coveragePercent,
    text: `Objective coverage stands at ${coveragePercent}% (${coverageStats.covered}/${coverageStats.total} covered, ${coverageStats.partial} partial, ${coverageStats.missing} missing).`,
  };

  const defaultContent = buildDefaultContent(templateId, {
    projectLabel,
    levelNarrative,
    requirementTotal: snapshot.stats.requirements.total,
    testTotal: snapshot.stats.tests.total,
    passedTests: snapshot.stats.tests.passed,
    failedTests: snapshot.stats.tests.failed,
    skippedTests: snapshot.stats.tests.skipped,
    coveragePercent,
    coveredCount: coverageStats.covered,
    partialCount: coverageStats.partial,
    missingCount: coverageStats.missing,
    objectiveTotal: coverageStats.total,
    codePaths: snapshot.stats.codePaths.total,
    generatedAt,
  });

  const sections: Record<string, string> = {};
  definition.sections.forEach((section) => {
    const override = options.sections?.[section.id];
    const fallback = defaultContent.sections[section.id] ?? paragraph('Section content pending definition.');
    sections[section.id] = override ?? fallback;
  });

  const overview = options.overview ?? defaultContent.overview;

  const objectives: PlanObjectiveRow[] = snapshot.objectives
    .map((objective) => {
      const metadata = metadataMap.get(objective.objectiveId);
      const status = objective.status;
      return {
        id: objective.objectiveId,
        name: metadata?.name ?? objective.objectiveId,
        description: metadata?.desc ?? 'No description available.',
        table: metadata?.table,
        status,
        statusLabel: statusLabels[status],
        statusClass: statusClasses[status],
        satisfiedArtifacts: objective.satisfiedArtifacts.map(toArtifactLabel),
        missingArtifacts: objective.missingArtifacts.map(toArtifactLabel),
        evidenceRefs: objective.evidenceRefs,
      };
    })
    .sort((a, b) => a.id.localeCompare(b.id, 'en'));

  const tableSummary = computeTableSummary(objectives);
  const openObjectives = objectives.filter((objective) => objective.status !== 'covered');
  const openSummary = openObjectives.length
    ? `There are ${openObjectives.length} open objectives consisting of ${coverageStats.partial} partial and ${coverageStats.missing} missing items.`
    : 'All mapped objectives are currently marked as covered.';

  const html = templateEnv.renderString(basePlanTemplate, {
    planDefinition: definition,
    projectLabel,
    levelLabel,
    manifestId: options.manifestId,
    generatedAt,
    overview,
    sections,
    sectionDefinitions: definition.sections,
    coverageSummary,
    stats: snapshot.stats,
    tableSummary,
    objectiveRows: objectives,
    openObjectives,
    openSummary,
    additionalNotes: options.additionalNotes,
    packageVersion: packageInfo.version,
  });

  return {
    html,
    sections,
    overview,
    coverageSummary,
    tableSummary,
    objectives,
    openObjectives,
    openSummary,
    projectLabel,
    levelLabel,
    generatedAt,
  };
};

export const renderPlanDocument = async (
  templateId: PlanTemplateId,
  options: PlanRenderOptions,
): Promise<PlanRenderResult> => {
  const definition = planTemplateDefinitions[templateId];
  if (!definition) {
    throw new Error(`Unknown plan template: ${templateId}`);
  }

  const {
    html,
    sections,
    overview,
    coverageSummary,
    tableSummary,
    objectives,
    openObjectives,
    openSummary,
    projectLabel,
    levelLabel,
    generatedAt,
  } = buildPlanContext(
    definition,
    templateId,
    options,
  );

  const planDocx = await buildDocxDocument({
    definition,
    projectLabel,
    levelLabel,
    manifestId: options.manifestId,
    generatedAt,
    coverageSummary,
    stats: options.snapshot.stats,
    sections,
    tableSummary,
    objectives,
    openObjectives,
    openSummary,
    additionalNotes: options.additionalNotes,
  });

  return {
    id: templateId,
    title: definition.title,
    html,
    docx: planDocx,
    overview,
    sections,
    coverageSummary,
  };
};

export type { PlanTemplateId } from './types';
