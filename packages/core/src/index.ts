import { z } from 'zod';

export type RequirementStatus = 'draft' | 'approved' | 'implemented' | 'verified';

export interface Requirement {
  id: string;
  title: string;
  description?: string;
  status: RequirementStatus;
  tags: string[];
}

export const requirementStatuses = ['draft', 'approved', 'implemented', 'verified'] as const;

export const requirementSchema: z.ZodType<Requirement> = z.object({
  id: z.string().min(1, 'Requirement identifier is required.'),
  title: z.string().min(1, 'Requirement title is required.'),
  description: z.string().optional(),
  status: z.enum(requirementStatuses),
  tags: z.array(z.string()),
});

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
  'polarion',
  'jenkins',
  'polyspace',
  'ldra',
  'vectorcast',
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

export const evidenceSchema: z.ZodType<Evidence> = z.object({
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

export const traceLinkSchema: z.ZodType<TraceLink> = z.object({
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
