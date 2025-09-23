import fs from 'fs';
import path from 'path';

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
import Handlebars from 'handlebars';
import type { HelperOptions } from 'handlebars';
import PdfPrinter from 'pdfmake';
import type { Content, TDocumentDefinitions } from 'pdfmake/interfaces';

import packageInfo from '../../package.json';

import { planTemplateDefinitions } from './templates';
import type { PlanTemplateDefinition, PlanTemplateId } from './types';

type ParagraphAlignment = (typeof AlignmentType)[keyof typeof AlignmentType];

const planTemplatesDir = path.resolve(__dirname, '..', '..', 'templates', 'plans');

const planHandlebars = Handlebars.create();

planHandlebars.registerHelper('paragraph', function paragraphHelper(
  ...args: unknown[]
) {
  const options = args.pop() as HelperOptions;
  void options;
  const text = args
    .map((value) => {
      if (value === undefined || value === null) {
        return '';
      }
      if (typeof value === 'string') {
        return value;
      }
      return String(value);
    })
    .join('');

  return new Handlebars.SafeString(paragraph(text));
});

planHandlebars.registerHelper('join', (items: unknown, separator: string) => {
  if (!Array.isArray(items)) {
    return '';
  }

  const normalizedSeparator = typeof separator === 'string' ? separator : ', ';
  const parts = items
    .map((item) => {
      if (item === undefined || item === null) {
        return '';
      }
      const value = String(item).trim();
      return value;
    })
    .filter((value) => value.length > 0);

  return parts.join(normalizedSeparator);
});

const pdfFonts = {
  Helvetica: {
    normal: 'Helvetica',
    bold: 'Helvetica-Bold',
    italics: 'Helvetica-Oblique',
    bolditalics: 'Helvetica-BoldOblique',
  },
};

const pdfPrinter = new PdfPrinter(pdfFonts);

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
  outstandingCount: number;
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

interface PlanHtmlTemplateContext {
  planDefinition: PlanTemplateDefinition;
  projectLabel: string;
  levelLabel: string;
  manifestId?: string;
  generatedAt: string;
  overview: string;
  sections: Record<string, string>;
  sectionDefinitions: PlanTemplateDefinition['sections'];
  coverageSummary: PlanRenderResult['coverageSummary'];
  stats: ComplianceSnapshot['stats'];
  tableSummary: Array<{ table: string; total: number; covered: number; partial: number; missing: number }>;
  objectiveRows: PlanObjectiveRow[];
  openObjectives: PlanObjectiveRow[];
  openSummary: string;
  additionalNotes?: string;
  packageVersion: string;
}

type PlanContentTemplate = Handlebars.TemplateDelegate<DefaultContentContext>;
type PlanHtmlTemplate = Handlebars.TemplateDelegate<PlanHtmlTemplateContext>;

const planContentTemplates: Partial<Record<PlanTemplateId, PlanContentTemplate>> = {};
let cachedPlanHtmlTemplate: PlanHtmlTemplate | undefined;

const getPlanHtmlTemplate = (): PlanHtmlTemplate => {
  if (!cachedPlanHtmlTemplate) {
    const templatePath = path.join(planTemplatesDir, 'base.hbs');
    const source = fs.readFileSync(templatePath, 'utf8');
    cachedPlanHtmlTemplate = planHandlebars.compile<PlanHtmlTemplateContext>(source);
  }
  return cachedPlanHtmlTemplate;
};

const getPlanContentTemplate = (templateId: PlanTemplateId): PlanContentTemplate => {
  const cached = planContentTemplates[templateId];
  if (cached) {
    return cached;
  }

  const templatePath = path.join(planTemplatesDir, `${templateId}.hbs`);
  if (!fs.existsSync(templatePath)) {
    throw new Error(`Plan template '${templateId}' could not be found at ${templatePath}`);
  }

  const source = fs.readFileSync(templatePath, 'utf8');
  const compiled = planHandlebars.compile<DefaultContentContext>(source);
  planContentTemplates[templateId] = compiled;
  return compiled;
};

const parsePlanTemplateOutput = (rendered: string): DefaultPlanContent => {
  const lines = rendered.split(/\r?\n/);
  let currentSection: string | null = null;
  let overview = '';
  const sections: Record<string, string> = {};
  const buffer: string[] = [];

  const flush = () => {
    if (!currentSection) {
      return;
    }

    const content = buffer.join('\n').trim();
    buffer.length = 0;

    if (content.length === 0) {
      return;
    }

    if (currentSection === 'overview') {
      overview = content;
    } else {
      sections[currentSection] = content;
    }
  };

  const markerPattern = /^@@(overview|section)(?:\s+([\w-]+))?$/i;

  for (const rawLine of lines) {
    const line = rawLine.trimEnd();
    const markerMatch = line.trim().match(markerPattern);
    if (markerMatch) {
      flush();
      const markerType = markerMatch[1];
      if (markerType.toLowerCase() === 'overview') {
        currentSection = 'overview';
      } else {
        const sectionId = markerMatch[2];
        if (!sectionId) {
          throw new Error('Section marker missing identifier.');
        }
        currentSection = sectionId;
      }
      continue;
    }

    if (!currentSection) {
      if (line.trim().length === 0) {
        continue;
      }
      throw new Error('Unexpected content before first section marker in plan template.');
    }

    buffer.push(line);
  }

  flush();

  if (!overview) {
    throw new Error('Plan template did not produce an overview section.');
  }

  return { overview, sections };
};

const createPdfBuffer = (docDefinition: TDocumentDefinitions): Promise<Buffer> =>
  new Promise((resolve, reject) => {
    const doc = pdfPrinter.createPdfKitDocument(docDefinition);
    const chunks: Buffer[] = [];

    doc.on('data', (chunk: Buffer) => {
      chunks.push(chunk);
    });
    doc.on('end', () => {
      resolve(Buffer.concat(chunks));
    });
    doc.on('error', (error: Error) => {
      reject(error);
    });

    doc.end();
  });

const buildDefaultContent = (
  templateId: PlanTemplateId,
  ctx: DefaultContentContext,
): DefaultPlanContent => {
  try {
    const template = getPlanContentTemplate(templateId);
    const rendered = template(ctx);
    return parsePlanTemplateOutput(rendered);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to render plan template '${templateId}': ${message}`);
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

const plainTextToPdfContent = (text: string): Content[] => {
  const lines = text
    .split(/\n+/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  const content: Content[] = [];
  let bullets: string[] = [];

  const flushBullets = () => {
    if (bullets.length > 0) {
      content.push({ ul: [...bullets], margin: [0, 0, 0, 6] });
      bullets = [];
    }
  };

  lines.forEach((line) => {
    if (line.startsWith('• ')) {
      bullets.push(line.replace(/^•\s*/, ''));
      return;
    }

    flushBullets();
    content.push({ text: line, margin: [0, 0, 0, 6] });
  });

  flushBullets();

  return content;
};

const htmlToPdfContent = (html: string): Content[] => plainTextToPdfContent(htmlToPlainText(html));

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

const buildPlanPdfDefinition = (
  definition: PlanTemplateDefinition,
  context: {
    overview: string;
    sections: Record<string, string>;
    coverageSummary: PlanRenderResult['coverageSummary'];
    tableSummary: Array<{ table: string; total: number; covered: number; partial: number; missing: number }>;
    objectives: PlanObjectiveRow[];
    openObjectives: PlanObjectiveRow[];
    openSummary: string;
    projectLabel: string;
    levelLabel: string;
    generatedAt: string;
  },
  stats: ComplianceSnapshot['stats'],
  manifestId?: string,
  additionalNotes?: string,
): TDocumentDefinitions => {
  const content: Content[] = [
    { text: definition.title, style: 'title' },
    { text: definition.purpose, style: 'subtitle' },
    { text: `Project: ${context.projectLabel}`, style: 'meta' },
    { text: `Certification Level: ${context.levelLabel}`, style: 'meta' },
    { text: `Manifest ID: ${manifestId ?? 'Pending'}`, style: 'meta' },
    { text: `Generated: ${context.generatedAt}`, style: 'meta', margin: [0, 0, 0, 12] },
  ];

  const metricsTable: Content = {
    table: {
      widths: ['*', '*'],
      body: [
        ['Objective Coverage', `${context.coverageSummary.coveredCount}/${context.coverageSummary.total} (${context.coverageSummary.coveragePercent}%)`],
        [
          'Verification Tests',
          `${stats.tests.total} total · ${stats.tests.passed} passed · ${stats.tests.failed} failed · ${stats.tests.skipped} skipped`,
        ],
        ['Tracked Requirements', `${stats.requirements.total}`],
        ['Code Elements', `${stats.codePaths.total}`],
      ].map(([label, value]) => [
        { text: label, style: 'metricLabel' },
        { text: value, style: 'metricValue' },
      ]),
    },
    layout: 'lightHorizontalLines',
    margin: [0, 0, 0, 16],
  };

  content.push(metricsTable);
  content.push({ text: 'Purpose & Overview', style: 'heading' });

  const overviewContent = htmlToPdfContent(context.overview);
  if (overviewContent.length > 0) {
    content.push(...overviewContent);
  } else {
    content.push({ text: 'Content pending definition.', margin: [0, 0, 0, 6] });
  }

  definition.sections.forEach((section) => {
    content.push({ text: section.title, style: 'heading' });
    const html = context.sections[section.id] ?? '';
    const sectionContent = htmlToPdfContent(html);
    if (sectionContent.length > 0) {
      content.push(...sectionContent);
    } else {
      content.push({ text: 'Content pending definition.', margin: [0, 0, 0, 6] });
    }
  });

  content.push({ text: 'Objective Coverage Summary', style: 'heading' });
  content.push({ text: context.coverageSummary.text, margin: [0, 0, 0, 8] });

  const coverageTable: Content = {
    table: {
      headerRows: 1,
      widths: ['*', 'auto', 'auto', 'auto', 'auto'],
      body: [
        [
          { text: 'Objective Table', style: 'tableHeader' },
          { text: 'Total', style: 'tableHeader', alignment: 'center' },
          { text: 'Covered', style: 'tableHeader', alignment: 'center' },
          { text: 'Partial', style: 'tableHeader', alignment: 'center' },
          { text: 'Missing', style: 'tableHeader', alignment: 'center' },
        ],
        ...context.tableSummary.map((row) => [
          { text: row.table, style: 'tableCell' },
          { text: String(row.total), style: 'tableCell', alignment: 'center' },
          { text: String(row.covered), style: 'tableCell', alignment: 'center' },
          { text: String(row.partial), style: 'tableCell', alignment: 'center' },
          { text: String(row.missing), style: 'tableCell', alignment: 'center' },
        ]),
      ],
    },
    layout: 'lightHorizontalLines',
    margin: [0, 8, 0, 16],
  };

  content.push(coverageTable);
  content.push({ text: 'Detailed Objective Mapping', style: 'heading' });

  const objectiveTable: Content = {
    table: {
      headerRows: 1,
      widths: ['auto', 'auto', '*', 'auto', '*'],
      body: [
        [
          { text: 'Objective', style: 'tableHeader' },
          { text: 'Table', style: 'tableHeader', alignment: 'center' },
          { text: 'Description', style: 'tableHeader' },
          { text: 'Status', style: 'tableHeader', alignment: 'center' },
          { text: 'Evidence & Gaps', style: 'tableHeader' },
        ],
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

          const descriptionStack: Content[] = [
            { text: objective.name, bold: true },
          ];
          if (objective.description) {
            descriptionStack.push({ text: objective.description, style: 'small' });
          }

          return [
            { text: objective.id, style: 'tableCell' },
            { text: objective.table ?? '—', style: 'tableCell', alignment: 'center' },
            { stack: descriptionStack, style: 'tableCell' },
            { text: objective.statusLabel, style: 'tableCell', alignment: 'center' },
            {
              text: evidenceParts.length > 0 ? evidenceParts.join('\n') : '—',
              style: 'tableCell',
            },
          ];
        }),
      ],
    },
    layout: 'lightHorizontalLines',
    margin: [0, 8, 0, 16],
  };

  content.push(objectiveTable);

  if (context.openObjectives.length > 0) {
    content.push({ text: 'Open Compliance Items', style: 'heading' });
    content.push({ text: context.openSummary, margin: [0, 0, 0, 8] });
    content.push({
      ul: context.openObjectives.map(
        (objective) => `${objective.id} — ${objective.name} (${objective.statusLabel})`,
      ),
      margin: [0, 0, 0, 12],
    });
  }

  if (additionalNotes) {
    content.push({ text: 'Notes', style: 'heading' });
    const notesContent = htmlToPdfContent(additionalNotes);
    if (notesContent.length > 0) {
      content.push(...notesContent);
    }
  }

  content.push({
    text: `Generated by SOIPack ${packageInfo.version} on ${context.generatedAt} for ${context.projectLabel}.`,
    style: 'footer',
  });

  return {
    info: {
      title: `${definition.title} - ${context.projectLabel}`,
      author: 'SOIPack',
      subject: definition.purpose,
      creator: 'SOIPack',
    },
    content,
    styles: {
      title: { fontSize: 18, bold: true, color: '#0a5c9b', margin: [0, 0, 0, 4] },
      subtitle: { fontSize: 11, color: '#3e5974', margin: [0, 0, 0, 12] },
      heading: { fontSize: 14, bold: true, color: '#0a5c9b', margin: [0, 16, 0, 8] },
      meta: { fontSize: 9, color: '#475569' },
      metricLabel: { fontSize: 9, bold: true, color: '#3b5773' },
      metricValue: { fontSize: 9, color: '#0f172a' },
      tableHeader: { fontSize: 9, bold: true, color: '#3b5773' },
      tableCell: { fontSize: 9, color: '#1f2937' },
      small: { fontSize: 8, color: '#64748b' },
      footer: { fontSize: 9, color: '#64748b', margin: [0, 24, 0, 0] },
    },
    defaultStyle: {
      font: 'Helvetica',
      fontSize: 10,
      lineHeight: 1.3,
    },
    pageMargins: [40, 60, 40, 60],
  };
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

  const outstandingCount = coverageStats.partial + coverageStats.missing;

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
    outstandingCount,
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

  const html = getPlanHtmlTemplate()({
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

export const renderPlanPdf = async (
  templateId: PlanTemplateId,
  options: PlanRenderOptions,
): Promise<Buffer> => {
  const definition = planTemplateDefinitions[templateId];
  if (!definition) {
    throw new Error(`Unknown plan template: ${templateId}`);
  }

  const context = buildPlanContext(
    definition,
    templateId,
    options,
  );

  const docDefinition = buildPlanPdfDefinition(
    definition,
    {
      overview: context.overview,
      sections: context.sections,
      coverageSummary: context.coverageSummary,
      tableSummary: context.tableSummary,
      objectives: context.objectives,
      openObjectives: context.openObjectives,
      openSummary: context.openSummary,
      projectLabel: context.projectLabel,
      levelLabel: context.levelLabel,
      generatedAt: context.generatedAt,
    },
    options.snapshot.stats,
    options.manifestId,
    options.additionalNotes,
  );

  return createPdfBuffer(docDefinition);
};

export type { PlanTemplateId } from './types';
