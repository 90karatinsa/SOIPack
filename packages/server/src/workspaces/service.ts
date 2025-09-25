import { createHash, createPublicKey, randomUUID, verify } from 'crypto';

import { evidenceSchema, requirementSchema, traceLinkSchema } from '@soipack/core';
import { ZodError, z } from 'zod';

import type { DatabaseManager } from '../database';

export const workspaceDocumentSchemas = {
  requirements: z.array(requirementSchema),
  traceLinks: z.array(traceLinkSchema),
  evidence: z.array(evidenceSchema),
} as const;

export type WorkspaceDocumentKind = keyof typeof workspaceDocumentSchemas;

export type WorkspaceSignoffStatus = 'pending' | 'approved';

export interface WorkspaceRevision {
  id: string;
  documentId: string;
  tenantId: string;
  workspaceId: string;
  revision: number;
  hash: string;
  content: unknown;
  authorId: string;
  createdAt: Date;
}

export interface WorkspaceDocument {
  id: string;
  tenantId: string;
  workspaceId: string;
  kind: WorkspaceDocumentKind;
  title: string;
  latestRevision: WorkspaceRevision;
  createdAt: Date;
  updatedAt: Date;
}

export interface WorkspaceComment {
  id: string;
  documentId: string;
  revisionId: string;
  tenantId: string;
  workspaceId: string;
  authorId: string;
  body: string;
  createdAt: Date;
}

export interface WorkspaceDocumentActivityOptions {
  cursor?: string | null;
  limit?: number;
}

export interface WorkspaceDocumentActivityResult {
  comments: WorkspaceComment[];
  signoffs: WorkspaceSignoff[];
  nextCursor: string | null;
}

export interface WorkspaceDocumentThread extends WorkspaceDocumentActivityResult {
  document: WorkspaceDocument;
}

export interface WorkspaceSignoff {
  id: string;
  documentId: string;
  revisionId: string;
  tenantId: string;
  workspaceId: string;
  revisionHash: string;
  status: WorkspaceSignoffStatus;
  requestedBy: string;
  requestedFor: string;
  signerId?: string | null;
  signerPublicKey?: string | null;
  signature?: string | null;
  signedAt?: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface SaveWorkspaceDocumentInput {
  tenantId: string;
  workspaceId: string;
  documentId: string;
  kind: WorkspaceDocumentKind;
  title: string;
  authorId: string;
  content: unknown;
  expectedHash?: string | null;
}

export interface AddWorkspaceCommentInput {
  tenantId: string;
  workspaceId: string;
  documentId: string;
  authorId: string;
  body: string;
  revisionId?: string;
  revisionHash?: string;
}

export interface RequestWorkspaceSignoffInput {
  tenantId: string;
  workspaceId: string;
  documentId: string;
  revisionHash: string;
  requestedBy: string;
  requestedFor: string;
}

export interface ApproveWorkspaceSignoffInput {
  tenantId: string;
  workspaceId: string;
  signoffId: string;
  actorId: string;
  expectedRevisionHash: string;
  publicKey: string;
  signature: string;
  signedAt: string;
  allowBypass?: boolean;
}

export class WorkspaceDocumentNotFoundError extends Error {
  constructor(message = 'Workspace document not found.') {
    super(message);
    this.name = 'WorkspaceDocumentNotFoundError';
  }
}

export class WorkspaceRevisionNotFoundError extends Error {
  constructor(message = 'Workspace document revision not found.') {
    super(message);
    this.name = 'WorkspaceRevisionNotFoundError';
  }
}

export class WorkspaceDocumentConflictError extends Error {
  constructor(message = 'Workspace document has been modified by another process.') {
    super(message);
    this.name = 'WorkspaceDocumentConflictError';
  }
}

export class WorkspaceDocumentValidationError extends Error {
  constructor(public readonly issues: ZodError['issues']) {
    super('Workspace document content is invalid.');
    this.name = 'WorkspaceDocumentValidationError';
  }
}

export class WorkspaceSignoffNotFoundError extends Error {
  constructor(message = 'Workspace signoff request not found.') {
    super(message);
    this.name = 'WorkspaceSignoffNotFoundError';
  }
}

export class WorkspaceSignoffPermissionError extends Error {
  constructor(message = 'You are not allowed to complete this signoff.') {
    super(message);
    this.name = 'WorkspaceSignoffPermissionError';
  }
}

export class WorkspaceSignoffVerificationError extends Error {
  constructor(message = 'Signoff signature verification failed.') {
    super(message);
    this.name = 'WorkspaceSignoffVerificationError';
  }
}

export class WorkspaceSignoffConflictError extends Error {
  constructor(message = 'Workspace signoff state is stale.') {
    super(message);
    this.name = 'WorkspaceSignoffConflictError';
  }
}

interface WorkspaceDocumentRow {
  id: string;
  tenant_id: string;
  workspace_id: string;
  kind: WorkspaceDocumentKind;
  title: string;
  latest_revision_id?: string | null;
  latest_revision_hash?: string | null;
  created_at: unknown;
  updated_at: unknown;
}

interface WorkspaceRevisionRow {
  id: string;
  document_id: string;
  tenant_id: string;
  workspace_id: string;
  revision: number;
  hash: string;
  content: unknown;
  author_id: string;
  created_at: unknown;
}

interface WorkspaceCommentRow {
  id: string;
  document_id: string;
  revision_id: string;
  tenant_id: string;
  workspace_id: string;
  author_id: string;
  body: string;
  created_at: unknown;
}

interface WorkspaceSignoffRow {
  id: string;
  document_id: string;
  revision_id: string;
  tenant_id: string;
  workspace_id: string;
  revision_hash: string;
  status: WorkspaceSignoffStatus;
  requested_by: string;
  requested_for: string;
  signer_id?: string | null;
  signer_public_key?: string | null;
  signature?: string | null;
  signed_at?: unknown;
  created_at: unknown;
  updated_at: unknown;
}

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

const computeHash = (value: unknown): string => {
  const serialized = JSON.stringify(value);
  return createHash('sha256').update(serialized).digest('hex');
};

const parseContent = (kind: WorkspaceDocumentKind, content: unknown): unknown => {
  const schema = workspaceDocumentSchemas[kind];
  try {
    return schema.parse(content);
  } catch (error) {
    if (error instanceof ZodError) {
      throw new WorkspaceDocumentValidationError((error as ZodError).issues);
    }
    throw error;
  }
};

const buildSignoffMessage = (params: {
  tenantId: string;
  workspaceId: string;
  documentId: string;
  revisionHash: string;
  signedAt: string;
}): Buffer => {
  const payload = `${params.tenantId}:${params.workspaceId}:${params.documentId}:${params.revisionHash}:${params.signedAt}`;
  return Buffer.from(payload, 'utf8');
};

const decodeBase64 = (value: string, field: string): Buffer => {
  try {
    return Buffer.from(value, 'base64');
  } catch {
    throw new WorkspaceSignoffVerificationError(`${field} must be valid base64.`);
  }
};

const decodeEd25519PublicKey = (value: string): Buffer => {
  const raw = decodeBase64(value, 'publicKey');
  if (raw.byteLength !== 32) {
    throw new WorkspaceSignoffVerificationError('publicKey must be a 32-byte Ed25519 key.');
  }
  const prefix = Buffer.from('302a300506032b6570032100', 'hex');
  return Buffer.concat([prefix, raw]);
};

const decodeEd25519Signature = (value: string): Buffer => {
  const signature = decodeBase64(value, 'signature');
  if (signature.byteLength !== 64) {
    throw new WorkspaceSignoffVerificationError('signature must be a 64-byte Ed25519 signature.');
  }
  return signature;
};

const DEFAULT_COMMENT_PAGE_SIZE = 20;

interface CommentCursor {
  createdAt: string;
  id: string;
}

const encodeCommentCursor = (row: WorkspaceCommentRow): string => {
  const payload: CommentCursor = {
    createdAt: toDate(row.created_at).toISOString(),
    id: row.id,
  };
  return Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
};

const parseCommentCursor = (cursor?: string | null): CommentCursor | null => {
  if (!cursor) {
    return null;
  }
  try {
    const decoded = Buffer.from(cursor, 'base64url').toString('utf8');
    const payload = JSON.parse(decoded) as { createdAt?: unknown; id?: unknown };
    if (typeof payload.createdAt !== 'string' || typeof payload.id !== 'string') {
      return null;
    }
    const timestamp = new Date(payload.createdAt);
    if (Number.isNaN(timestamp.getTime())) {
      return null;
    }
    return { createdAt: timestamp.toISOString(), id: payload.id };
  } catch {
    return null;
  }
};

export class WorkspaceService {
  constructor(private readonly database: DatabaseManager) {}

  private get pool() {
    return this.database.getPool();
  }

  private mapDocumentRow(row: WorkspaceDocumentRow, revision: WorkspaceRevision): WorkspaceDocument {
    return {
      id: row.id,
      tenantId: row.tenant_id,
      workspaceId: row.workspace_id,
      kind: row.kind,
      title: row.title,
      latestRevision: revision,
      createdAt: toDate(row.created_at),
      updatedAt: toDate(row.updated_at),
    };
  }

  private mapRevisionRow(row: WorkspaceRevisionRow): WorkspaceRevision {
    return {
      id: row.id,
      documentId: row.document_id,
      tenantId: row.tenant_id,
      workspaceId: row.workspace_id,
      revision: row.revision,
      hash: row.hash,
      content: row.content,
      authorId: row.author_id,
      createdAt: toDate(row.created_at),
    };
  }

  private mapCommentRow(row: WorkspaceCommentRow): WorkspaceComment {
    return {
      id: row.id,
      documentId: row.document_id,
      revisionId: row.revision_id,
      tenantId: row.tenant_id,
      workspaceId: row.workspace_id,
      authorId: row.author_id,
      body: row.body,
      createdAt: toDate(row.created_at),
    };
  }

  private mapSignoffRow(row: WorkspaceSignoffRow): WorkspaceSignoff {
    return {
      id: row.id,
      documentId: row.document_id,
      revisionId: row.revision_id,
      tenantId: row.tenant_id,
      workspaceId: row.workspace_id,
      revisionHash: row.revision_hash,
      status: row.status,
      requestedBy: row.requested_by,
      requestedFor: row.requested_for,
      signerId: row.signer_id ?? null,
      signerPublicKey: row.signer_public_key ?? null,
      signature: row.signature ?? null,
      signedAt: row.signed_at ? toDate(row.signed_at) : null,
      createdAt: toDate(row.created_at),
      updatedAt: toDate(row.updated_at),
    };
  }

  private async selectDocument(
    tenantId: string,
    workspaceId: string,
    documentId: string,
  ): Promise<WorkspaceDocumentRow | undefined> {
    const { rows } = await this.pool.query(
      `SELECT id, tenant_id, workspace_id, kind, title, latest_revision_id, latest_revision_hash, created_at, updated_at
         FROM workspace_documents
        WHERE tenant_id = $1 AND workspace_id = $2 AND id = $3
        LIMIT 1`,
      [tenantId, workspaceId, documentId],
    );
    return rows[0] as WorkspaceDocumentRow | undefined;
  }

  private async selectRevisionById(
    tenantId: string,
    workspaceId: string,
    revisionId: string,
  ): Promise<WorkspaceRevisionRow | undefined> {
    const { rows } = await this.pool.query(
      `SELECT id, document_id, tenant_id, workspace_id, revision, hash, content, author_id, created_at
         FROM workspace_document_revisions
        WHERE tenant_id = $1 AND workspace_id = $2 AND id = $3
        LIMIT 1`,
      [tenantId, workspaceId, revisionId],
    );
    return rows[0] as WorkspaceRevisionRow | undefined;
  }

  private async selectRevisionByHash(
    tenantId: string,
    workspaceId: string,
    documentId: string,
    revisionHash: string,
  ): Promise<WorkspaceRevisionRow | undefined> {
    const { rows } = await this.pool.query(
      `SELECT id, document_id, tenant_id, workspace_id, revision, hash, content, author_id, created_at
         FROM workspace_document_revisions
        WHERE tenant_id = $1 AND workspace_id = $2 AND document_id = $3 AND hash = $4
        LIMIT 1`,
      [tenantId, workspaceId, documentId, revisionHash],
    );
    return rows[0] as WorkspaceRevisionRow | undefined;
  }

  private async persistRevision(
    input: Omit<WorkspaceRevisionRow, 'created_at'> & { created_at: string },
  ): Promise<void> {
    await this.pool.query(
      `INSERT INTO workspace_document_revisions (id, document_id, tenant_id, workspace_id, revision, hash, content, author_id, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9)`,
      [
        input.id,
        input.document_id,
        input.tenant_id,
        input.workspace_id,
        input.revision,
        input.hash,
        input.content,
        input.author_id,
        input.created_at,
      ],
    );
  }

  private async persistDocument(row: WorkspaceDocumentRow & { created_at: string; updated_at: string }): Promise<void> {
    await this.pool.query(
      `INSERT INTO workspace_documents (id, tenant_id, workspace_id, kind, title, latest_revision_id, latest_revision_hash, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        row.id,
        row.tenant_id,
        row.workspace_id,
        row.kind,
        row.title,
        row.latest_revision_id ?? null,
        row.latest_revision_hash ?? null,
        row.created_at,
        row.updated_at,
      ],
    );
  }

  private async updateDocument(row: WorkspaceDocumentRow & { updated_at: string }): Promise<void> {
    await this.pool.query(
      `UPDATE workspace_documents
          SET title = $4,
              latest_revision_id = $5,
              latest_revision_hash = $6,
              updated_at = $7
        WHERE tenant_id = $1 AND workspace_id = $2 AND id = $3`,
      [
        row.tenant_id,
        row.workspace_id,
        row.id,
        row.title,
        row.latest_revision_id ?? null,
        row.latest_revision_hash ?? null,
        row.updated_at,
      ],
    );
  }

  private async selectSignoff(
    tenantId: string,
    workspaceId: string,
    signoffId: string,
  ): Promise<WorkspaceSignoffRow | undefined> {
    const { rows } = await this.pool.query(
      `SELECT id, document_id, revision_id, tenant_id, workspace_id, revision_hash, status, requested_by, requested_for,
              signer_id, signer_public_key, signature, signed_at, created_at, updated_at
         FROM workspace_signoffs
        WHERE tenant_id = $1 AND workspace_id = $2 AND id = $3
        LIMIT 1`,
      [tenantId, workspaceId, signoffId],
    );
    return rows[0] as WorkspaceSignoffRow | undefined;
  }

  public async getDocument(
    tenantId: string,
    workspaceId: string,
    documentId: string,
  ): Promise<WorkspaceDocument | undefined> {
    const documentRow = await this.selectDocument(tenantId, workspaceId, documentId);
    if (!documentRow || !documentRow.latest_revision_id) {
      return undefined;
    }
    const revisionRow = await this.selectRevisionById(tenantId, workspaceId, documentRow.latest_revision_id);
    if (!revisionRow) {
      return undefined;
    }
    return this.mapDocumentRow(documentRow, this.mapRevisionRow(revisionRow));
  }

  public async listDocumentActivity(
    tenantId: string,
    workspaceId: string,
    documentId: string,
    options: WorkspaceDocumentActivityOptions = {},
  ): Promise<WorkspaceDocumentActivityResult> {
    const rawLimit = options.limit ?? DEFAULT_COMMENT_PAGE_SIZE;
    const limit = Number.isFinite(rawLimit)
      ? Math.min(Math.max(Math.trunc(rawLimit), 1), 100)
      : DEFAULT_COMMENT_PAGE_SIZE;
    const cursor = parseCommentCursor(options.cursor);
    const parameters: unknown[] = [tenantId, workspaceId, documentId];
    let cursorClause = '';
    if (cursor) {
      parameters.push(cursor.createdAt);
      const createdAtIndex = parameters.length;
      parameters.push(cursor.id);
      const idIndex = parameters.length;
      cursorClause = ` AND (created_at > $${createdAtIndex} OR (created_at = $${createdAtIndex} AND id > $${idIndex}))`;
    }
    parameters.push(limit + 1);
    const limitIndex = parameters.length;

    const { rows: commentRowsRaw } = await this.pool.query(
      `SELECT id, document_id, revision_id, tenant_id, workspace_id, author_id, body, created_at
         FROM workspace_document_comments
        WHERE tenant_id = $1 AND workspace_id = $2 AND document_id = $3${cursorClause}
        ORDER BY created_at ASC, id ASC
        LIMIT $${limitIndex}`,
      parameters,
    );

    const commentRows = commentRowsRaw as WorkspaceCommentRow[];
    let nextCursor: string | null = null;
    if (commentRows.length > limit) {
      commentRows.splice(limit);
      const lastRow = commentRows[commentRows.length - 1];
      if (lastRow) {
        nextCursor = encodeCommentCursor(lastRow);
      }
    }
    const comments = commentRows.map((row) => this.mapCommentRow(row));

    const { rows: signoffRowsRaw } = await this.pool.query(
      `SELECT id, document_id, revision_id, tenant_id, workspace_id, revision_hash, status, requested_by, requested_for,
              signer_id, signer_public_key, signature, signed_at, created_at, updated_at
         FROM workspace_signoffs
        WHERE tenant_id = $1 AND workspace_id = $2 AND document_id = $3
        ORDER BY created_at ASC, id ASC`,
      [tenantId, workspaceId, documentId],
    );
    const signoffs = (signoffRowsRaw as WorkspaceSignoffRow[]).map((row) => this.mapSignoffRow(row));

    return { comments, signoffs, nextCursor };
  }

  public async getDocumentThread(
    tenantId: string,
    workspaceId: string,
    documentId: string,
    options: WorkspaceDocumentActivityOptions = {},
  ): Promise<WorkspaceDocumentThread | undefined> {
    const document = await this.getDocument(tenantId, workspaceId, documentId);
    if (!document) {
      return undefined;
    }
    const activity = await this.listDocumentActivity(tenantId, workspaceId, documentId, options);
    return {
      document,
      comments: activity.comments,
      signoffs: activity.signoffs,
      nextCursor: activity.nextCursor,
    };
  }

  public async saveRevision(input: SaveWorkspaceDocumentInput): Promise<WorkspaceDocument> {
    const content = parseContent(input.kind, input.content);
    const documentId = input.documentId;
    const existing = await this.selectDocument(input.tenantId, input.workspaceId, documentId);
    const now = new Date().toISOString();

    if (existing) {
      if (existing.kind !== input.kind) {
        throw new WorkspaceDocumentConflictError('Workspace document type cannot be changed.');
      }
      if (existing.latest_revision_hash) {
        if (!input.expectedHash) {
          throw new WorkspaceDocumentConflictError('expectedHash is required for concurrent updates.');
        }
        if (existing.latest_revision_hash !== input.expectedHash) {
          throw new WorkspaceDocumentConflictError();
        }
      }
    }

    let nextRevisionNumber = 1;
    if (existing && existing.latest_revision_id) {
      const latestRevision = await this.selectRevisionById(
        input.tenantId,
        input.workspaceId,
        existing.latest_revision_id,
      );
      if (!latestRevision) {
        throw new WorkspaceRevisionNotFoundError();
      }
      nextRevisionNumber = latestRevision.revision + 1;
    }

    const revisionId = randomUUID();
    const revisionHash = computeHash({
      kind: input.kind,
      content,
      revision: nextRevisionNumber,
      author: input.authorId,
    });

    const revisionRow: Omit<WorkspaceRevisionRow, 'created_at'> & { created_at: string } = {
      id: revisionId,
      document_id: documentId,
      tenant_id: input.tenantId,
      workspace_id: input.workspaceId,
      revision: nextRevisionNumber,
      hash: revisionHash,
      content: JSON.stringify(content),
      author_id: input.authorId,
      created_at: now,
    };

    await this.persistRevision(revisionRow);

    if (!existing) {
      const documentRow: WorkspaceDocumentRow & { created_at: string; updated_at: string } = {
        id: documentId,
        tenant_id: input.tenantId,
        workspace_id: input.workspaceId,
        kind: input.kind,
        title: input.title,
        latest_revision_id: revisionId,
        latest_revision_hash: revisionHash,
        created_at: now,
        updated_at: now,
      };
      await this.persistDocument(documentRow);
    } else {
      await this.updateDocument({
        ...existing,
        title: input.title,
        latest_revision_id: revisionId,
        latest_revision_hash: revisionHash,
        updated_at: now,
      });
    }

    const document = await this.getDocument(input.tenantId, input.workspaceId, documentId);
    if (!document) {
      throw new WorkspaceDocumentNotFoundError();
    }
    return document;
  }

  public async addComment(input: AddWorkspaceCommentInput): Promise<WorkspaceComment> {
    const document = await this.selectDocument(input.tenantId, input.workspaceId, input.documentId);
    if (!document) {
      throw new WorkspaceDocumentNotFoundError();
    }

    let revision: WorkspaceRevisionRow | undefined;
    if (input.revisionId) {
      revision = await this.selectRevisionById(input.tenantId, input.workspaceId, input.revisionId);
    } else if (input.revisionHash) {
      revision = await this.selectRevisionByHash(
        input.tenantId,
        input.workspaceId,
        input.documentId,
        input.revisionHash,
      );
    } else if (document.latest_revision_id) {
      revision = await this.selectRevisionById(input.tenantId, input.workspaceId, document.latest_revision_id);
    }

    if (!revision) {
      throw new WorkspaceRevisionNotFoundError();
    }

    if (input.revisionHash && revision.hash !== input.revisionHash) {
      throw new WorkspaceDocumentConflictError();
    }

    const commentId = randomUUID();
    const now = new Date().toISOString();

    await this.pool.query(
      `INSERT INTO workspace_document_comments (id, document_id, revision_id, tenant_id, workspace_id, author_id, body, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        commentId,
        input.documentId,
        revision.id,
        input.tenantId,
        input.workspaceId,
        input.authorId,
        input.body,
        now,
      ],
    );

    return this.mapCommentRow({
      id: commentId,
      document_id: input.documentId,
      revision_id: revision.id,
      tenant_id: input.tenantId,
      workspace_id: input.workspaceId,
      author_id: input.authorId,
      body: input.body,
      created_at: now,
    });
  }

  public async requestSignoff(input: RequestWorkspaceSignoffInput): Promise<WorkspaceSignoff> {
    const document = await this.selectDocument(input.tenantId, input.workspaceId, input.documentId);
    if (!document) {
      throw new WorkspaceDocumentNotFoundError();
    }

    const revision = await this.selectRevisionByHash(
      input.tenantId,
      input.workspaceId,
      input.documentId,
      input.revisionHash,
    );

    if (!revision) {
      throw new WorkspaceRevisionNotFoundError();
    }

    const signoffId = randomUUID();
    const now = new Date().toISOString();

    await this.pool.query(
      `INSERT INTO workspace_signoffs (id, document_id, revision_id, tenant_id, workspace_id, revision_hash, status, requested_by, requested_for, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10)`,
      [
        signoffId,
        input.documentId,
        revision.id,
        input.tenantId,
        input.workspaceId,
        input.revisionHash,
        'pending',
        input.requestedBy,
        input.requestedFor,
        now,
      ],
    );

    return this.mapSignoffRow({
      id: signoffId,
      document_id: input.documentId,
      revision_id: revision.id,
      tenant_id: input.tenantId,
      workspace_id: input.workspaceId,
      revision_hash: input.revisionHash,
      status: 'pending',
      requested_by: input.requestedBy,
      requested_for: input.requestedFor,
      created_at: now,
      updated_at: now,
    });
  }

  public async approveSignoff(input: ApproveWorkspaceSignoffInput): Promise<WorkspaceSignoff> {
    const signoff = await this.selectSignoff(input.tenantId, input.workspaceId, input.signoffId);
    if (!signoff) {
      throw new WorkspaceSignoffNotFoundError();
    }

    if (signoff.status !== 'pending') {
      throw new WorkspaceSignoffConflictError();
    }

    if (signoff.revision_hash !== input.expectedRevisionHash) {
      throw new WorkspaceSignoffConflictError('Revision hash no longer matches the pending signoff.');
    }

    if (!input.allowBypass && signoff.requested_for !== input.actorId) {
      throw new WorkspaceSignoffPermissionError();
    }

    const revision = await this.selectRevisionById(
      input.tenantId,
      input.workspaceId,
      signoff.revision_id,
    );
    if (!revision) {
      throw new WorkspaceRevisionNotFoundError();
    }

    const signedAt = new Date(input.signedAt);
    if (Number.isNaN(signedAt.getTime())) {
      throw new WorkspaceSignoffVerificationError('signedAt must be a valid ISO-8601 timestamp.');
    }

    const message = buildSignoffMessage({
      tenantId: input.tenantId,
      workspaceId: input.workspaceId,
      documentId: signoff.document_id,
      revisionHash: signoff.revision_hash,
      signedAt: signedAt.toISOString(),
    });

    const publicKeyDer = decodeEd25519PublicKey(input.publicKey);
    const signature = decodeEd25519Signature(input.signature);
    const keyObject = createPublicKey({ key: publicKeyDer, format: 'der', type: 'spki' });

    const verified = verify(null, message, keyObject, signature);
    if (!verified) {
      throw new WorkspaceSignoffVerificationError();
    }

    const now = new Date().toISOString();

    await this.pool.query(
      `UPDATE workspace_signoffs
          SET status = $4,
              signer_id = $5,
              signer_public_key = $6,
              signature = $7,
              signed_at = $8,
              updated_at = $9
        WHERE tenant_id = $1 AND workspace_id = $2 AND id = $3 AND status = 'pending'`,
      [
        input.tenantId,
        input.workspaceId,
        input.signoffId,
        'approved',
        input.actorId,
        input.publicKey,
        input.signature,
        signedAt.toISOString(),
        now,
      ],
    );

    const updated = await this.selectSignoff(input.tenantId, input.workspaceId, input.signoffId);
    if (!updated) {
      throw new WorkspaceSignoffNotFoundError();
    }
    return this.mapSignoffRow(updated);
  }
}
