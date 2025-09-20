import { z } from 'zod';

export type RequirementStatus = 'draft' | 'approved' | 'implemented' | 'verified';

export interface Requirement {
  id: string;
  title: string;
  description?: string;
  status: RequirementStatus;
  tags: string[];
}

export interface TestCase {
  id: string;
  requirementId: string;
  name: string;
  status: 'pending' | 'passed' | 'failed';
}

export const createRequirement = (
  id: string,
  title: string,
  options: Partial<Pick<Requirement, 'description' | 'status' | 'tags'>> = {},
): Requirement => ({
  id,
  title,
  description: options.description,
  status: options.status ?? 'draft',
  tags: options.tags ?? [],
});

export const normalizeTag = (tag: string): string => tag.trim().toLowerCase();

export const objectiveAreas = ['Plans', 'Standards', 'Reviews', 'Verification', 'Coverage'] as const;
export type ObjectiveArea = (typeof objectiveAreas)[number];

export const objectiveArtifactTypes = [
  'psac',
  'sdp',
  'svr',
  'testResults',
  'coverage',
  'traceability',
  'analysisReport',
  'configurationIndex',
  'git',
  'other',
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

export interface Objective {
  id: string;
  area: ObjectiveArea;
  description: string;
  artifacts: ObjectiveArtifactType[];
  level: LevelApplicability;
}

export const levelApplicabilitySchema: z.ZodType<LevelApplicability> = z
  .object({
    A: z.boolean(),
    B: z.boolean(),
    C: z.boolean(),
    D: z.boolean(),
    E: z.boolean(),
  })
  .refine((value) => certificationLevels.some((level) => value[level]), {
    message: 'At least one certification level must apply to an objective.',
  });

export const objectiveSchema: z.ZodType<Objective> = z.object({
  id: z
    .string()
    .regex(/^[A-E]-\d+-Obj\d+$/, 'Objective id must follow the pattern <Level>-<Area>-Obj<Number>.'),
  area: z.enum(objectiveAreas),
  description: z.string().min(10, 'Objective description should provide a concise summary.'),
  artifacts: z
    .array(z.enum(objectiveArtifactTypes))
    .min(1, 'At least one artifact type is expected for each objective.')
    .superRefine((items, ctx) => {
      if (new Set(items).size !== items.length) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'Artifact types must be unique per objective.',
        });
      }
    }),
  level: levelApplicabilitySchema,
});

export const objectiveListSchema = z.array(objectiveSchema);

export const evidenceSources = [
  'jiraCsv',
  'reqif',
  'junit',
  'lcov',
  'cobertura',
  'git',
  'staticAnalysis',
  'other',
] as const;
export type EvidenceSource = (typeof evidenceSources)[number];

export interface Evidence {
  source: EvidenceSource;
  path: string;
  summary: string;
  hash?: string;
  timestamp: string;
}

export const evidenceSchema: z.ZodType<Evidence> = z.object({
  source: z.enum(evidenceSources),
  path: z.string().min(1, 'Evidence path must be provided.'),
  summary: z.string().min(1, 'Evidence summary must be provided.'),
  hash: z
    .string()
    .regex(/^[a-f0-9]{8,}$/i, 'Evidence hash should be a hexadecimal digest.')
    .optional(),
  timestamp: z.string().datetime({ offset: true }),
});

export const traceLinkTypes = ['satisfies', 'verifies', 'implements'] as const;
export type TraceLinkType = (typeof traceLinkTypes)[number];

export interface TraceLink {
  from: string;
  to: string;
  type: TraceLinkType;
}

export const traceLinkSchema: z.ZodType<TraceLink> = z.object({
  from: z.string().min(1, 'Trace link source identifier is required.'),
  to: z.string().min(1, 'Trace link target identifier is required.'),
  type: z.enum(traceLinkTypes),
});

export interface ManifestFileEntry {
  path: string;
  sha256: string;
}

export interface Manifest {
  files: ManifestFileEntry[];
  createdAt: string;
  toolVersion: string;
}
