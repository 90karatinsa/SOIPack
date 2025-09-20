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
