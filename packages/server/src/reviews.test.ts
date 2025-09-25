import { newDb } from 'pg-mem';

import { DatabaseManager } from './database';
import {
  ReviewStore,
  ReviewConflictError,
  ReviewPermissionError,
  ReviewTransitionError,
  type Review,
} from './reviews';

describe('ReviewStore', () => {
  let manager: DatabaseManager;
  let store: ReviewStore;

  beforeEach(async () => {
    const mem = newDb();
    const { Pool } = mem.adapters.createPg();
    manager = new DatabaseManager('pg-mem', () => new Pool());
    await manager.initialize();
    store = new ReviewStore(manager);
  });

  afterEach(async () => {
    await manager.close();
  });

  const expectHash = (review: Review) => {
    expect(review.hash).toMatch(/^[a-f0-9]{64}$/u);
  };

  it('creates reviews with approver assignments and required artifacts', async () => {
    const review = await store.createReview({
      tenantId: 'tenant-a',
      authorId: 'author-1',
      target: { kind: 'analyze', reference: 'import-1234' },
      approvers: ['qa-1', 'qa-2'],
      requiredArtifacts: [
        { id: 'artifact-a', label: 'Traceability Matrix', description: 'Updated trace links' },
        { label: 'Checklist' },
      ],
      notes: 'Initial review draft',
    });

    expect(review.status).toBe('draft');
    expect(review.tenantId).toBe('tenant-a');
    expect(review.target).toEqual({ kind: 'analyze', reference: 'import-1234' });
    expect(review.approvers).toHaveLength(2);
    expect(review.approvers.every((approver) => approver.status === 'pending')).toBe(true);
    expect(review.requiredArtifacts).toHaveLength(2);
    expect(review.requiredArtifacts.every((artifact) => artifact.provided === false)).toBe(true);
    expectHash(review);

    const configured = await store.updateConfiguration({
      tenantId: 'tenant-a',
      reviewId: review.id,
      expectedHash: review.hash,
      approvers: ['qa-2'],
      requiredArtifacts: [{ id: 'artifact-b', label: 'QA Checklist' }],
      notes: 'Trimmed approvers',
    });

    expect(configured.approvers).toHaveLength(1);
    expect(configured.approvers[0].userId).toBe('qa-2');
    expect(configured.requiredArtifacts).toHaveLength(1);
    expect(configured.requiredArtifacts[0].label).toBe('QA Checklist');
    expect(configured.notes).toBe('Trimmed approvers');
    expectHash(configured);
  });

  it('enforces optimistic concurrency via hash locks', async () => {
    const review = await store.createReview({
      tenantId: 'tenant-a',
      authorId: 'author-1',
      target: { kind: 'report', reference: 'analysis-1' },
      approvers: ['qa-1'],
    });

    await expect(
      store.submitReview({ tenantId: 'tenant-a', reviewId: review.id, expectedHash: 'deadbeef', actorId: 'qa-1' }),
    ).rejects.toBeInstanceOf(ReviewConflictError);

    const submitted = await store.submitReview({
      tenantId: 'tenant-a',
      reviewId: review.id,
      expectedHash: review.hash,
      actorId: 'qa-1',
    });
    expect(submitted.status).toBe('pending');
    expectHash(submitted);
  });

  it('requires assigned approvers for approvals and finalizes when all approve', async () => {
    const review = await store.createReview({
      tenantId: 'tenant-a',
      authorId: 'author-1',
      target: { kind: 'pack', reference: 'report-99' },
      approvers: ['qa-1', 'qa-2'],
    });

    const submitted = await store.submitReview({
      tenantId: 'tenant-a',
      reviewId: review.id,
      expectedHash: review.hash,
      actorId: 'author-1',
    });

    await expect(
      store.approveReview({
        tenantId: 'tenant-a',
        reviewId: review.id,
        expectedHash: submitted.hash,
        approverId: 'intruder',
      }),
    ).rejects.toBeInstanceOf(ReviewPermissionError);

    const partial = await store.approveReview({
      tenantId: 'tenant-a',
      reviewId: review.id,
      expectedHash: submitted.hash,
      approverId: 'qa-1',
      note: 'Looks good to me',
    });

    expect(partial.status).toBe('pending');
    const second = await store.approveReview({
      tenantId: 'tenant-a',
      reviewId: review.id,
      expectedHash: partial.hash,
      approverId: 'qa-2',
    });

    expect(second.status).toBe('approved');
    expect(second.approvers.every((approver) => approver.status === 'approved')).toBe(true);
  });

  it('records change requests on rejection and allows resubmission', async () => {
    const review = await store.createReview({
      tenantId: 'tenant-a',
      authorId: 'author-1',
      target: { kind: 'analyze', reference: 'import-42' },
      approvers: ['qa-1'],
    });

    const submitted = await store.submitReview({
      tenantId: 'tenant-a',
      reviewId: review.id,
      expectedHash: review.hash,
      actorId: 'author-1',
    });

    const rejected = await store.rejectReview({
      tenantId: 'tenant-a',
      reviewId: review.id,
      expectedHash: submitted.hash,
      approverId: 'qa-1',
      reason: 'Need updated trace matrix',
    });

    expect(rejected.status).toBe('rejected');
    expect(rejected.changeRequests).toHaveLength(1);
    expect(rejected.changeRequests[0].reason).toMatch(/trace matrix/);
    expect(rejected.approvers[0].status).toBe('rejected');

    const resubmitted = await store.submitReview({
      tenantId: 'tenant-a',
      reviewId: review.id,
      expectedHash: rejected.hash,
      actorId: 'author-1',
    });

    expect(resubmitted.status).toBe('pending');
    expect(resubmitted.approvers[0].status).toBe('pending');
  });

  it('rejects invalid target kinds', async () => {
    await expect(
      store.createReview({
        tenantId: 'tenant-a',
        authorId: 'author-1',
        // @ts-expect-error intentional invalid kind for runtime validation
        target: { kind: 'invalid', reference: 'x' },
      }),
    ).rejects.toBeInstanceOf(ReviewTransitionError);
  });
});
