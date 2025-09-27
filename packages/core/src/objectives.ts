import { z, ZodIssueCode, type ZodType } from 'zod';

import rawCatalog from '../../../data/objectives/do178c_objectives.min.json';

export const objectiveTables = ['A-3', 'A-4', 'A-5', 'A-6', 'A-7'] as const;
export type ObjectiveTable = (typeof objectiveTables)[number];

export const objectiveArtifactTypes = [
  'plan',
  'standard',
  'review',
  'analysis',
  'test',
  'coverage_stmt',
  'coverage_dec',
  'coverage_mcdc',
  'trace',
  'cm_record',
  'qa_record',
  'problem_report',
  'conformity',
] as const;
export type ObjectiveArtifactType = (typeof objectiveArtifactTypes)[number];

export const certificationLevels = ['A', 'B', 'C', 'D', 'E'] as const;
export type CertificationLevel = (typeof certificationLevels)[number];

export interface LevelApplicability {
  A: boolean;
  B: boolean;
  C: boolean;
  D: boolean;
  E: boolean;
}

export const objectiveIndependenceLevels = ['none', 'recommended', 'required'] as const;
export type ObjectiveIndependenceLevel = (typeof objectiveIndependenceLevels)[number];

export const soiStages = ['SOI-1', 'SOI-2', 'SOI-3', 'SOI-4'] as const;
export type SoiStage = (typeof soiStages)[number];

export interface Objective {
  id: string;
  table: ObjectiveTable;
  stage: SoiStage;
  name: string;
  desc: string;
  artifacts: ObjectiveArtifactType[];
  levels: LevelApplicability;
  independence: ObjectiveIndependenceLevel;
}

export const levelApplicabilitySchema = z
  .object({
    A: z.boolean(),
    B: z.boolean(),
    C: z.boolean(),
    D: z.boolean(),
    E: z.boolean(),
  })
  .refine((value) => certificationLevels.some((level) => (value as LevelApplicability)[level]), {
    message: 'At least one certification level must apply to an objective.',
  }) as unknown as ZodType<LevelApplicability>;

export const objectiveSchema = z.object({
  id: z
    .string()
    .regex(/^A-[3-7]-\d{2}$/u, 'Objective id must follow the pattern A-<Table>-<Number>.'),
  table: z.enum(objectiveTables),
  stage: z.enum(soiStages),
  name: z.string().min(3, 'Objective name should provide a concise title.'),
  desc: z.string().min(10, 'Objective description should provide a concise summary.'),
  artifacts: z
    .array(z.enum(objectiveArtifactTypes))
    .min(1, 'At least one artifact type is expected for each objective.')
    .superRefine((items, ctx) => {
      const typedItems = items as ObjectiveArtifactType[];
      if (new Set(typedItems).size !== typedItems.length) {
        ctx.addIssue({
          code: ZodIssueCode.custom,
          message: 'Artifact types must be unique per objective.',
        });
      }
    }),
  levels: levelApplicabilitySchema,
  independence: z.enum(objectiveIndependenceLevels),
}) as unknown as ZodType<Objective>;

export const objectiveListSchema = z.array(objectiveSchema);

export type ObjectiveCatalogEntry = Objective;

const parsedCatalog = objectiveListSchema.parse(rawCatalog) as ObjectiveCatalogEntry[];

export const objectiveCatalog: ObjectiveCatalogEntry[] = parsedCatalog;

export const objectiveCatalogById = new Map<string, ObjectiveCatalogEntry>(
  parsedCatalog.map((objective) => [objective.id, objective as ObjectiveCatalogEntry]),
);

export const getObjectivesByTable = (table: ObjectiveTable): ObjectiveCatalogEntry[] =>
  parsedCatalog.filter((objective) => objective.table === table);

export const getObjectivesForLevel = (
  level: CertificationLevel,
  options: { includeNotApplicable?: boolean } = {},
): ObjectiveCatalogEntry[] => {
  const { includeNotApplicable = false } = options;
  if (includeNotApplicable) {
    return [...parsedCatalog];
  }
  return parsedCatalog.filter((objective) => objective.levels[level]);
};

export const getApplicableTablesForLevel = (level: CertificationLevel): ObjectiveTable[] => {
  const tables = new Set<ObjectiveTable>();
  parsedCatalog.forEach((objective) => {
    if (objective.levels[level]) {
      tables.add(objective.table);
    }
  });
  return Array.from(tables);
};
