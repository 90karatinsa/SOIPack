import { z, type RefinementCtx, type ZodType, ZodIssueCode } from 'zod';

export type RequirementStatus = 'draft' | 'approved' | 'implemented' | 'verified';

export interface Requirement {
  id: string;
  title: string;
  description?: string;
  status: RequirementStatus;
  tags: string[];
}

export const requirementStatuses = ['draft', 'approved', 'implemented', 'verified'] as const;

export const requirementSchema: ZodType<Requirement> = z.object({
  id: z.string().min(1, 'Requirement identifier is required.'),
  title: z.string().min(1, 'Requirement title is required.'),
  description: z.string().optional(),
  status: z.enum(requirementStatuses),
  tags: z.array(z.string()),
});

export type DesignStatus = 'draft' | 'allocated' | 'implemented' | 'verified';

export const designStatuses = ['draft', 'allocated', 'implemented', 'verified'] as const;

const createUniqueNormalizedTags = (tags: string[]): string[] => {
  const normalized = tags
    .map((tag) => normalizeTag(tag))
    .filter((tag) => tag.length > 0);
  return Array.from(new Set(normalized));
};

const createReferenceArraySchema = (label: string) =>
  z
    .array(z.string())
    .default([])
    .transform((values: string[], ctx: RefinementCtx) => {
      const trimmed = values.map((value) => value.trim());
      const seen = new Set<string>();
      trimmed.forEach((value, index) => {
        if (!value) {
          ctx.addIssue({
            code: ZodIssueCode.custom,
            message: `${label} reference cannot be blank.`,
            path: [index],
          });
          return;
        }
        if (seen.has(value)) {
          ctx.addIssue({
            code: ZodIssueCode.custom,
            message: `${label} reference ${value} is duplicated.`,
            path: [index],
          });
          return;
        }
        seen.add(value);
      });
      return trimmed;
    });

export interface DesignRecord {
  id: string;
  title: string;
  description?: string;
  status: DesignStatus;
  tags: string[];
  requirementRefs: string[];
  codeRefs: string[];
}

export const designRecordSchema = z.object({
  id: z.string().min(1, 'Design identifier is required.'),
  title: z.string().min(1, 'Design title is required.'),
  description: z.string().optional(),
  status: z.enum(designStatuses),
  tags: z
    .array(z.string())
    .default([])
    .transform((values: string[]) => createUniqueNormalizedTags(values)),
  requirementRefs: createReferenceArraySchema('Requirement'),
  codeRefs: createReferenceArraySchema('Code'),
});

export const createDesignRecord = (
  id: string,
  title: string,
  options: Partial<
    Pick<DesignRecord, 'description' | 'status' | 'tags' | 'requirementRefs' | 'codeRefs'>
  > = {},
): DesignRecord =>
  designRecordSchema.parse({
    id,
    title,
    description: options.description,
    status: options.status ?? 'draft',
    tags: options.tags ?? [],
    requirementRefs: options.requirementRefs ?? [],
    codeRefs: options.codeRefs ?? [],
  }) as DesignRecord;

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

export * from './objectives';
export * from './i18n';
export * from './ledger';

export const evidenceSources = [
  'jiraCsv',
  'reqif',
  'junit',
  'lcov',
  'cobertura',
  'git',
  'doorsClassic',
  'polarion',
  'jenkins',
  'polyspace',
  'ldra',
  'vectorcast',
  'simulink',
  'doorsNext',
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
  snapshotId: string;
  independent?: boolean;
}

export const evidenceSchema: ZodType<Evidence> = z.object({
  source: z.enum(evidenceSources),
  path: z.string().min(1, 'Evidence path must be provided.'),
  summary: z.string().min(1, 'Evidence summary must be provided.'),
  hash: z
    .string()
    .regex(/^[a-f0-9]{8,}$/i, 'Evidence hash should be a hexadecimal digest.')
    .optional(),
  timestamp: z.string().datetime({ offset: true }),
  snapshotId: z
    .string()
    .regex(/^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{7,}$/i, 'Evidence snapshotId must look like 20240101T000000Z-deadbeef.'),
  independent: z.boolean().optional(),
});

export const traceLinkTypes = ['satisfies', 'verifies', 'implements'] as const;
export type TraceLinkType = (typeof traceLinkTypes)[number];

export interface TraceLink {
  from: string;
  to: string;
  type: TraceLinkType;
}

export const traceLinkSchema: ZodType<TraceLink> = z.object({
  from: z.string().min(1, 'Trace link source identifier is required.'),
  to: z.string().min(1, 'Trace link target identifier is required.'),
  type: z.enum(traceLinkTypes),
});

export interface ManifestMerkleProof {
  algorithm: 'ledger-merkle-v1';
  merkleRoot: string;
  proof: string;
}

export interface ManifestMerkleSummary {
  algorithm: 'ledger-merkle-v1';
  root: string;
  manifestDigest: string;
  snapshotId: string;
}

export interface ManifestFileEntry {
  path: string;
  sha256: string;
  proof?: ManifestMerkleProof;
}

export interface Manifest {
  files: ManifestFileEntry[];
  createdAt: string;
  toolVersion: string;
  merkle?: ManifestMerkleSummary;
}

export * from './versioning';
