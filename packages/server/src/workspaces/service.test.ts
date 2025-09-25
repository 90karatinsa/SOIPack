import { generateKeyPairSync, randomBytes, sign as signMessage } from 'crypto';

import { newDb } from 'pg-mem';

import { DatabaseManager } from '../database';

import {
  WorkspaceService,
  WorkspaceDocumentConflictError,
  WorkspaceDocumentValidationError,
  WorkspaceRevisionNotFoundError,
  WorkspaceSignoffVerificationError,
} from './service';

describe('WorkspaceService', () => {
  let manager: DatabaseManager;
  let service: WorkspaceService;

  beforeEach(async () => {
    const mem = newDb();
    const { Pool } = mem.adapters.createPg();
    manager = new DatabaseManager('pg-mem', () => new Pool());
    await manager.initialize();
    service = new WorkspaceService(manager);
  });

  afterEach(async () => {
    await manager.close();
  });

  const baseInput = {
    tenantId: 'tenant-a',
    workspaceId: 'ws-1',
    documentId: 'requirements',
    kind: 'requirements' as const,
    title: 'System Requirements',
    authorId: 'author-1',
    content: [
      {
        id: 'REQ-1',
        title: 'The system shall boot.',
        status: 'draft',
        tags: ['system'],
      },
    ],
  };

  it('enforces optimistic concurrency when saving revisions', async () => {
    const created = await service.saveRevision(baseInput);
    expect(created.latestRevision.revision).toBe(1);

    await expect(
      service.saveRevision({
        ...baseInput,
        title: 'Updated title',
        expectedHash: 'deadbeef',
        content: baseInput.content,
      }),
    ).rejects.toBeInstanceOf(WorkspaceDocumentConflictError);

    const updated = await service.saveRevision({
      ...baseInput,
      title: 'Updated title',
      expectedHash: created.latestRevision.hash,
      content: [
        {
          id: 'REQ-1',
          title: 'The system shall boot quickly.',
          status: 'approved',
          tags: ['system'],
        },
      ],
    });

    expect(updated.latestRevision.revision).toBe(2);
    expect(updated.latestRevision.hash).not.toBe(created.latestRevision.hash);
  });

  it('validates requirement payloads using @soipack/core schemas', async () => {
    await expect(
      service.saveRevision({
        ...baseInput,
        content: [
          {
            id: '',
            title: 'Missing identifier should fail',
            status: 'draft',
            tags: [],
          },
        ],
      }),
    ).rejects.toBeInstanceOf(WorkspaceDocumentValidationError);
  });

  it('rejects invalid Ed25519 signatures during signoff approval', async () => {
    const document = await service.saveRevision(baseInput);
    const signoff = await service.requestSignoff({
      tenantId: baseInput.tenantId,
      workspaceId: baseInput.workspaceId,
      documentId: baseInput.documentId,
      revisionHash: document.latestRevision.hash,
      requestedBy: 'maintainer-1',
      requestedFor: 'approver-1',
    });

    await expect(
      service.approveSignoff({
        tenantId: baseInput.tenantId,
        workspaceId: baseInput.workspaceId,
        signoffId: signoff.id,
        actorId: 'approver-1',
        expectedRevisionHash: document.latestRevision.hash,
        publicKey: randomBytes(32).toString('base64'),
        signature: randomBytes(64).toString('base64'),
        signedAt: new Date().toISOString(),
      }),
    ).rejects.toBeInstanceOf(WorkspaceSignoffVerificationError);
  });

  it('approves valid signoffs and records signature metadata', async () => {
    const document = await service.saveRevision(baseInput);
    const signoff = await service.requestSignoff({
      tenantId: baseInput.tenantId,
      workspaceId: baseInput.workspaceId,
      documentId: baseInput.documentId,
      revisionHash: document.latestRevision.hash,
      requestedBy: 'maintainer-1',
      requestedFor: 'approver-1',
    });

    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const signedAt = new Date().toISOString();

    const payload = Buffer.from(
      `${baseInput.tenantId}:${baseInput.workspaceId}:${baseInput.documentId}:${document.latestRevision.hash}:${signedAt}`,
      'utf8',
    );
    const signature = signMessage(null, payload, privateKey);
    const exported = publicKey.export({ format: 'der', type: 'spki' }) as Buffer;
    const rawPublicKey = exported.slice(exported.length - 32);

    const approved = await service.approveSignoff({
      tenantId: baseInput.tenantId,
      workspaceId: baseInput.workspaceId,
      signoffId: signoff.id,
      actorId: 'approver-1',
      expectedRevisionHash: document.latestRevision.hash,
      publicKey: rawPublicKey.toString('base64'),
      signature: signature.toString('base64'),
      signedAt,
    });

    expect(approved.status).toBe('approved');
    expect(approved.signerId).toBe('approver-1');
    expect(approved.signature).toBe(signature.toString('base64'));
    expect(approved.signerPublicKey).toBe(rawPublicKey.toString('base64'));
  });

  it('ensures comments target an existing revision', async () => {
    await service.saveRevision(baseInput);
    await expect(
      service.addComment({
        tenantId: baseInput.tenantId,
        workspaceId: baseInput.workspaceId,
        documentId: baseInput.documentId,
        authorId: 'commenter',
        body: 'Looks good to me',
        revisionId: randomBytes(16).toString('hex'),
      }),
    ).rejects.toBeInstanceOf(WorkspaceRevisionNotFoundError);
  });

  it('returns document threads with empty activity lists for new documents', async () => {
    const document = await service.saveRevision(baseInput);

    const thread = await service.getDocumentThread(
      baseInput.tenantId,
      baseInput.workspaceId,
      baseInput.documentId,
    );

    expect(thread).toBeDefined();
    expect(thread?.document.latestRevision.id).toBe(document.latestRevision.id);
    expect(thread?.comments).toEqual([]);
    expect(thread?.signoffs).toEqual([]);
    expect(thread?.nextCursor).toBeNull();
  });

  it('paginates document comments in chronological order', async () => {
    const document = await service.saveRevision(baseInput);

    const commentBodies = ['First comment', 'Second comment', 'Third comment'];
    for (const body of commentBodies) {
      await service.addComment({
        tenantId: baseInput.tenantId,
        workspaceId: baseInput.workspaceId,
        documentId: baseInput.documentId,
        authorId: 'commenter',
        body,
        revisionId: document.latestRevision.id,
      });
    }

    const firstPage = await service.getDocumentThread(
      baseInput.tenantId,
      baseInput.workspaceId,
      baseInput.documentId,
      { limit: 2 },
    );

    expect(firstPage).toBeDefined();
    expect(firstPage?.comments.map((entry) => entry.body)).toEqual(['First comment', 'Second comment']);
    expect(firstPage?.nextCursor).toBeTruthy();

    const secondPage = await service.listDocumentActivity(
      baseInput.tenantId,
      baseInput.workspaceId,
      baseInput.documentId,
      { limit: 2, cursor: firstPage?.nextCursor ?? undefined },
    );

    expect(secondPage.comments.map((entry) => entry.body)).toEqual(['Third comment']);
    expect(secondPage.nextCursor).toBeNull();
    expect(secondPage.signoffs).toEqual([]);
  });

  it('returns signoff history with mixed approval states', async () => {
    const document = await service.saveRevision(baseInput);

    await service.requestSignoff({
      tenantId: baseInput.tenantId,
      workspaceId: baseInput.workspaceId,
      documentId: baseInput.documentId,
      revisionHash: document.latestRevision.hash,
      requestedBy: 'maintainer-1',
      requestedFor: 'approver-1',
    });

    const secondSignoff = await service.requestSignoff({
      tenantId: baseInput.tenantId,
      workspaceId: baseInput.workspaceId,
      documentId: baseInput.documentId,
      revisionHash: document.latestRevision.hash,
      requestedBy: 'maintainer-1',
      requestedFor: 'approver-2',
    });

    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const signedAt = new Date().toISOString();
    const payload = Buffer.from(
      `${baseInput.tenantId}:${baseInput.workspaceId}:${baseInput.documentId}:${document.latestRevision.hash}:${signedAt}`,
      'utf8',
    );
    const signature = signMessage(null, payload, privateKey);
    const exported = publicKey.export({ format: 'der', type: 'spki' }) as Buffer;
    const rawPublicKey = exported.slice(exported.length - 32);

    await service.approveSignoff({
      tenantId: baseInput.tenantId,
      workspaceId: baseInput.workspaceId,
      signoffId: secondSignoff.id,
      actorId: 'approver-2',
      expectedRevisionHash: document.latestRevision.hash,
      publicKey: rawPublicKey.toString('base64'),
      signature: signature.toString('base64'),
      signedAt,
    });

    const thread = await service.getDocumentThread(
      baseInput.tenantId,
      baseInput.workspaceId,
      baseInput.documentId,
    );

    expect(thread).toBeDefined();
    expect(thread?.signoffs.map((entry) => entry.status)).toEqual(['pending', 'approved']);
    const approved = thread?.signoffs.find((entry) => entry.status === 'approved');
    expect(approved?.signerId).toBe('approver-2');
    expect(approved?.signature).toBe(signature.toString('base64'));
  });
});
