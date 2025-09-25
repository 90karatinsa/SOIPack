import { createHash, randomUUID } from 'crypto';

import type { DatabaseManager } from './database';

export type ReviewStatus = 'draft' | 'pending' | 'approved' | 'rejected';

export type ReviewApproverStatus = 'pending' | 'approved' | 'rejected';

export type ReviewTargetKind = 'analyze' | 'report' | 'pack';

export interface ReviewTarget {
  kind: ReviewTargetKind;
  reference?: string | null;
}

export interface ReviewApprover {
  userId: string;
  status: ReviewApproverStatus;
  decidedAt?: Date | null;
  note?: string | null;
}

export interface ReviewRequiredArtifact {
  id: string;
  label: string;
  description?: string | null;
  provided: boolean;
  providedBy?: string | null;
  providedAt?: Date | null;
}

export interface ReviewChangeRequest {
  id: string;
  authorId: string;
  reason: string;
  createdAt: Date;
}

export interface Review {
  id: string;
  tenantId: string;
  status: ReviewStatus;
  target: ReviewTarget;
  approvers: ReviewApprover[];
  requiredArtifacts: ReviewRequiredArtifact[];
  changeRequests: ReviewChangeRequest[];
  hash: string;
  notes?: string | null;
  reviewer?: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface CreateReviewInput {
  tenantId: string;
  authorId: string;
  target: ReviewTarget;
  approvers?: string[];
  requiredArtifacts?: Array<{ id?: string; label: string; description?: string | null }>;
  notes?: string | null;
}

export interface UpdateReviewConfigurationInput {
  tenantId: string;
  reviewId: string;
  expectedHash: string;
  target?: ReviewTarget;
  approvers?: string[];
  requiredArtifacts?: Array<{ id?: string; label: string; description?: string | null }>;
  notes?: string | null;
}

export interface SubmitReviewInput {
  tenantId: string;
  reviewId: string;
  expectedHash: string;
  actorId: string;
}

export interface ApproveReviewInput {
  tenantId: string;
  reviewId: string;
  expectedHash: string;
  approverId: string;
  note?: string | null;
}

export interface RejectReviewInput {
  tenantId: string;
  reviewId: string;
  expectedHash: string;
  approverId: string;
  reason: string;
}

export class ReviewNotFoundError extends Error {
  constructor(message = 'Review not found.') {
    super(message);
    this.name = 'ReviewNotFoundError';
  }
}

export class ReviewConflictError extends Error {
  constructor(message = 'Review has been modified by another process.') {
    super(message);
    this.name = 'ReviewConflictError';
  }
}

export class ReviewTransitionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ReviewTransitionError';
  }
}

export class ReviewPermissionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ReviewPermissionError';
  }
}

interface StoredReviewMetadata {
  lockHash: string;
  target: ReviewTarget;
  approvers: Array<{
    userId: string;
    status: ReviewApproverStatus;
    decidedAt?: string | null;
    note?: string | null;
  }>;
  requiredArtifacts: Array<{
    id: string;
    label: string;
    description?: string | null;
    provided: boolean;
    providedBy?: string | null;
    providedAt?: string | null;
  }>;
  changeRequests: Array<{
    id: string;
    authorId: string;
    reason: string;
    createdAt: string;
  }>;
}

interface ReviewRow {
  id: string;
  tenant_id: string;
  job_id?: string | null;
  reviewer?: string | null;
  decision: ReviewStatus;
  notes?: string | null;
  metadata: unknown;
  created_at: unknown;
  updated_at: unknown;
}

const REVIEW_TABLE_COLUMNS =
  'id, tenant_id, job_id, reviewer, decision, notes, metadata, created_at, updated_at';

const toDate = (value: unknown): Date => {
  if (value instanceof Date) {
    return value;
  }
  if (typeof value === 'string' || typeof value === 'number') {
    const parsed = new Date(value);
    if (!Number.isNaN(parsed.getTime())) {
      return parsed;
    }
  }
  return new Date(0);
};

const isValidTargetKind = (value: string): value is ReviewTargetKind =>
  value === 'analyze' || value === 'report' || value === 'pack';

const normalizeTarget = (target: ReviewTarget | undefined): ReviewTarget => {
  if (!target || !isValidTargetKind(target.kind)) {
    return { kind: 'analyze', reference: null };
  }
  return {
    kind: target.kind,
    reference: target.reference ?? null,
  };
};

const buildLockHash = (metadata: Omit<StoredReviewMetadata, 'lockHash'>): string => {
  const serialized = JSON.stringify(metadata);
  return createHash('sha256').update(serialized).digest('hex');
};

const buildApprovers = (approvers: string[] | undefined): StoredReviewMetadata['approvers'] =>
  (approvers ?? []).map((userId) => ({ userId, status: 'pending' as ReviewApproverStatus }));

const buildRequiredArtifacts = (
  artifacts: UpdateReviewConfigurationInput['requiredArtifacts'] | CreateReviewInput['requiredArtifacts'],
): StoredReviewMetadata['requiredArtifacts'] =>
  (artifacts ?? []).map((artifact) => ({
    id: artifact.id ?? randomUUID(),
    label: artifact.label,
    description: artifact.description ?? null,
    provided: false,
    providedBy: null,
    providedAt: null,
  }));

export class ReviewStore {
  constructor(private readonly database: DatabaseManager) {}

  private get pool() {
    return this.database.getPool();
  }

  private parseMetadata(value: unknown): StoredReviewMetadata {
    if (!value || typeof value !== 'object') {
      return {
        lockHash: buildLockHash({
          target: { kind: 'analyze', reference: null },
          approvers: [],
          requiredArtifacts: [],
          changeRequests: [],
        }),
        target: { kind: 'analyze', reference: null },
        approvers: [],
        requiredArtifacts: [],
        changeRequests: [],
      };
    }
    const metadata = value as Partial<StoredReviewMetadata>;
    const target = normalizeTarget(metadata.target);
    const approvers = Array.isArray(metadata.approvers)
      ? metadata.approvers.map((approver) => ({
          userId: approver.userId,
          status: approver.status ?? 'pending',
          decidedAt: approver.decidedAt ?? null,
          note: approver.note ?? null,
        }))
      : [];
    const requiredArtifacts = Array.isArray(metadata.requiredArtifacts)
      ? metadata.requiredArtifacts.map((artifact) => ({
          id: artifact.id ?? randomUUID(),
          label: artifact.label ?? 'artifact',
          description: artifact.description ?? null,
          provided: artifact.provided ?? false,
          providedBy: artifact.providedBy ?? null,
          providedAt: artifact.providedAt ?? null,
        }))
      : [];
    const changeRequests = Array.isArray(metadata.changeRequests)
      ? metadata.changeRequests.map((entry) => ({
          id: entry.id ?? randomUUID(),
          authorId: entry.authorId ?? 'unknown',
          reason: entry.reason ?? '',
          createdAt: entry.createdAt ?? new Date().toISOString(),
        }))
      : [];
    const lockHash = metadata.lockHash ?? buildLockHash({
      target,
      approvers,
      requiredArtifacts,
      changeRequests,
    });
    return {
      lockHash,
      target,
      approvers,
      requiredArtifacts,
      changeRequests,
    };
  }

  private mapRow(row: ReviewRow): Review {
    const metadata = this.parseMetadata(row.metadata);
    return {
      id: row.id,
      tenantId: row.tenant_id,
      status: row.decision,
      target: metadata.target,
      approvers: metadata.approvers.map((approver) => ({
        userId: approver.userId,
        status: approver.status,
        decidedAt: approver.decidedAt ? toDate(approver.decidedAt) : null,
        note: approver.note ?? null,
      })),
      requiredArtifacts: metadata.requiredArtifacts.map((artifact) => ({
        id: artifact.id,
        label: artifact.label,
        description: artifact.description ?? null,
        provided: artifact.provided ?? false,
        providedBy: artifact.providedBy ?? null,
        providedAt: artifact.providedAt ? toDate(artifact.providedAt) : null,
      })),
      changeRequests: metadata.changeRequests.map((entry) => ({
        id: entry.id,
        authorId: entry.authorId,
        reason: entry.reason,
        createdAt: toDate(entry.createdAt),
      })),
      hash: metadata.lockHash,
      notes: row.notes ?? null,
      reviewer: row.reviewer ?? null,
      createdAt: toDate(row.created_at),
      updatedAt: toDate(row.updated_at),
    };
  }

  private async selectReview(tenantId: string, reviewId: string): Promise<ReviewRow | undefined> {
    const { rows } = await this.pool.query(
      `SELECT ${REVIEW_TABLE_COLUMNS} FROM reviews WHERE tenant_id = $1 AND id = $2 LIMIT 1`,
      [tenantId, reviewId],
    );
    const row = rows[0] as ReviewRow | undefined;
    return row;
  }

  public async getReview(tenantId: string, reviewId: string): Promise<Review | undefined> {
    const row = await this.selectReview(tenantId, reviewId);
    if (!row) {
      return undefined;
    }
    return this.mapRow(row);
  }

  public async createReview(input: CreateReviewInput): Promise<Review> {
    if (input.target && !isValidTargetKind(input.target.kind)) {
      throw new ReviewTransitionError('Unsupported review target.');
    }
    const id = randomUUID();
    const now = new Date().toISOString();
    const target = normalizeTarget(input.target);
    const metadataBase: Omit<StoredReviewMetadata, 'lockHash'> = {
      target,
      approvers: buildApprovers(input.approvers),
      requiredArtifacts: buildRequiredArtifacts(input.requiredArtifacts),
      changeRequests: [],
    };
    const lockHash = buildLockHash(metadataBase);
    const metadata: StoredReviewMetadata = { ...metadataBase, lockHash };

    const { rows } = await this.pool.query(
      `INSERT INTO reviews (id, tenant_id, job_id, reviewer, decision, notes, metadata, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $8)
       RETURNING ${REVIEW_TABLE_COLUMNS}`,
      [
        id,
        input.tenantId,
        target.reference ?? null,
        input.authorId,
        'draft',
        input.notes ?? null,
        JSON.stringify(metadata),
        now,
      ],
    );
    const row = rows[0] as ReviewRow | undefined;
    if (!row) {
      throw new ReviewNotFoundError('Review could not be created.');
    }
    return this.mapRow(row);
  }

  private async applyUpdate(
    tenantId: string,
    reviewId: string,
    expectedHash: string,
    updater: (current: { row: ReviewRow; metadata: StoredReviewMetadata }) => {
      reviewer?: string | null;
      status?: ReviewStatus;
      notes?: string | null;
      metadata: StoredReviewMetadata;
    },
  ): Promise<Review> {
    const row = await this.selectReview(tenantId, reviewId);
    if (!row) {
      throw new ReviewNotFoundError();
    }
    const metadata = this.parseMetadata(row.metadata);
    if (metadata.lockHash !== expectedHash) {
      throw new ReviewConflictError();
    }

    const result = updater({ row, metadata });
    const nextMetadata = result.metadata;
    const now = new Date().toISOString();

    const { rows } = await this.pool.query(
      `UPDATE reviews
         SET reviewer = $3,
             decision = $4,
             notes = $5,
             metadata = $6::jsonb,
             updated_at = $7
       WHERE tenant_id = $1
         AND id = $2
         AND metadata->>'lockHash' = $8
       RETURNING ${REVIEW_TABLE_COLUMNS}`,
      [
        tenantId,
        reviewId,
        result.reviewer ?? row.reviewer ?? null,
        result.status ?? row.decision,
        result.notes ?? row.notes ?? null,
        JSON.stringify(nextMetadata),
        now,
        expectedHash,
      ],
    );
    const updated = rows[0] as ReviewRow | undefined;
    if (!updated) {
      throw new ReviewConflictError();
    }
    return this.mapRow(updated);
  }

  public async updateConfiguration(input: UpdateReviewConfigurationInput): Promise<Review> {
    if (input.target && !isValidTargetKind(input.target.kind)) {
      throw new ReviewTransitionError('Unsupported review target.');
    }
    return this.applyUpdate(input.tenantId, input.reviewId, input.expectedHash, ({ row, metadata }) => {
      if (row.decision !== 'draft' && row.decision !== 'rejected') {
        throw new ReviewTransitionError('Only draft or rejected reviews can be edited.');
      }
      const target = normalizeTarget(input.target ?? metadata.target);
      const approvers = buildApprovers(input.approvers ?? metadata.approvers.map((approver) => approver.userId));
      const requiredArtifacts = buildRequiredArtifacts(
        input.requiredArtifacts ?? metadata.requiredArtifacts.map((artifact) => ({
          id: artifact.id,
          label: artifact.label,
          description: artifact.description ?? null,
        })),
      );
      const changeRequests = metadata.changeRequests;
      const base: Omit<StoredReviewMetadata, 'lockHash'> = {
        target,
        approvers,
        requiredArtifacts,
        changeRequests,
      };
      const lockHash = buildLockHash(base);
      return {
        reviewer: row.reviewer,
        status: row.decision,
        notes: input.notes ?? row.notes ?? null,
        metadata: { ...base, lockHash },
      };
    });
  }

  public async submitReview(input: SubmitReviewInput): Promise<Review> {
    return this.applyUpdate(input.tenantId, input.reviewId, input.expectedHash, ({ row, metadata }) => {
      if (row.decision !== 'draft' && row.decision !== 'rejected') {
        throw new ReviewTransitionError('Review can only be submitted from draft or rejected state.');
      }
      const approvers = metadata.approvers.map((approver) => ({
        userId: approver.userId,
        status: 'pending' as ReviewApproverStatus,
        decidedAt: null,
        note: null,
      }));
      const base: Omit<StoredReviewMetadata, 'lockHash'> = {
        target: metadata.target,
        approvers,
        requiredArtifacts: metadata.requiredArtifacts,
        changeRequests: metadata.changeRequests,
      };
      const lockHash = buildLockHash(base);
      return {
        reviewer: input.actorId,
        status: 'pending',
        notes: row.notes ?? null,
        metadata: { ...base, lockHash },
      };
    });
  }

  public async approveReview(input: ApproveReviewInput): Promise<Review> {
    return this.applyUpdate(input.tenantId, input.reviewId, input.expectedHash, ({ row, metadata }) => {
      if (row.decision !== 'pending') {
        throw new ReviewTransitionError('Only pending reviews can be approved.');
      }
      const approver = metadata.approvers.find((entry) => entry.userId === input.approverId);
      if (!approver) {
        throw new ReviewPermissionError('Approver is not assigned to this review.');
      }
      const updatedApprovers = metadata.approvers.map((entry) => {
        if (entry.userId !== input.approverId) {
          return entry;
        }
        return {
          userId: entry.userId,
          status: 'approved' as ReviewApproverStatus,
          decidedAt: new Date().toISOString(),
          note: input.note ?? null,
        };
      });
      const allApproved = updatedApprovers.every((entry) => entry.status === 'approved');
      const base: Omit<StoredReviewMetadata, 'lockHash'> = {
        target: metadata.target,
        approvers: updatedApprovers,
        requiredArtifacts: metadata.requiredArtifacts,
        changeRequests: metadata.changeRequests,
      };
      const lockHash = buildLockHash(base);
      return {
        reviewer: input.approverId,
        status: allApproved ? 'approved' : 'pending',
        notes: row.notes ?? null,
        metadata: { ...base, lockHash },
      };
    });
  }

  public async rejectReview(input: RejectReviewInput): Promise<Review> {
    return this.applyUpdate(input.tenantId, input.reviewId, input.expectedHash, ({ row, metadata }) => {
      if (row.decision !== 'pending') {
        throw new ReviewTransitionError('Only pending reviews can be rejected.');
      }
      const approver = metadata.approvers.find((entry) => entry.userId === input.approverId);
      if (!approver) {
        throw new ReviewPermissionError('Approver is not assigned to this review.');
      }
      const updatedApprovers = metadata.approvers.map((entry) => {
        if (entry.userId !== input.approverId) {
          return entry;
        }
        return {
          userId: entry.userId,
          status: 'rejected' as ReviewApproverStatus,
          decidedAt: new Date().toISOString(),
          note: input.reason,
        };
      });
      const changeRequests = [
        ...metadata.changeRequests,
        {
          id: randomUUID(),
          authorId: input.approverId,
          reason: input.reason,
          createdAt: new Date().toISOString(),
        },
      ];
      const base: Omit<StoredReviewMetadata, 'lockHash'> = {
        target: metadata.target,
        approvers: updatedApprovers,
        requiredArtifacts: metadata.requiredArtifacts,
        changeRequests,
      };
      const lockHash = buildLockHash(base);
      return {
        reviewer: input.approverId,
        status: 'rejected',
        notes: row.notes ?? null,
        metadata: { ...base, lockHash },
      };
    });
  }
}

export const __testHooks = {
  buildLockHash,
};
