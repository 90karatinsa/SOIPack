import { Alert, Badge, Button, Input, PageHeader, Skeleton, Textarea } from '@bora/ui-kit';
import { type FormEvent, useCallback, useEffect, useMemo, useState } from 'react';

import {
  ApiError,
  createWorkspaceComment,
  getWorkspaceDocumentThread,
  requestWorkspaceSignoff,
  updateWorkspaceDocument,
  type WorkspaceComment,
  type WorkspaceDocument,
  type WorkspaceDocumentThread,
  type WorkspaceSignoff,
} from '../services/api';

const requirementStatuses = ['draft', 'approved', 'implemented', 'verified'] as const;
type RequirementStatus = (typeof requirementStatuses)[number];

export type RequirementRecord = {
  id: string;
  title: string;
  description: string;
  status: RequirementStatus;
  tags: string[];
};

type RequirementsEditorPageProps = {
  token?: string;
  license?: string;
  workspaceId: string;
  documentId: string;
  initialThread?: WorkspaceDocumentThread<RequirementRecord[]> | null;
};

const toLowerHash = (hash?: string | null): string => (hash ?? '').toLowerCase();

const normalizeRequirement = (value: unknown): RequirementRecord => {
  if (!value || typeof value !== 'object') {
    return { id: '', title: '', description: '', status: 'draft', tags: [] };
  }
  const candidate = value as Partial<RequirementRecord> & { tags?: unknown; status?: unknown };
  const status = requirementStatuses.includes(candidate.status as RequirementStatus)
    ? (candidate.status as RequirementStatus)
    : 'draft';
  const tags = Array.isArray(candidate.tags)
    ? (candidate.tags as unknown[])
        .map((tag) => (typeof tag === 'string' ? tag.trim() : String(tag)))
        .filter((tag) => tag.length > 0)
    : [];
  return {
    id: typeof candidate.id === 'string' ? candidate.id : '',
    title: typeof candidate.title === 'string' ? candidate.title : '',
    description: typeof candidate.description === 'string' ? candidate.description : '',
    status,
    tags,
  };
};

const normalizeRequirements = (value: unknown): RequirementRecord[] => {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((entry) => normalizeRequirement(entry));
};

const serializeTags = (tags: string[]): string => tags.join(', ');

const parseTags = (value: string): string[] =>
  value
    .split(',')
    .map((tag) => tag.trim())
    .filter((tag) => tag.length > 0);

export default function RequirementsEditorPage({
  token = '',
  license = '',
  workspaceId,
  documentId,
  initialThread = null,
}: RequirementsEditorPageProps) {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [document, setDocument] = useState<WorkspaceDocument<RequirementRecord[]> | null>(null);
  const [requirements, setRequirements] = useState<RequirementRecord[]>([]);
  const [comments, setComments] = useState<WorkspaceComment[]>([]);
  const [signoffs, setSignoffs] = useState<WorkspaceSignoff[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [commentDraft, setCommentDraft] = useState('');
  const [commentError, setCommentError] = useState<string | null>(null);
  const [isPostingComment, setIsPostingComment] = useState(false);
  const [showSignoffModal, setShowSignoffModal] = useState(false);
  const [signoffTarget, setSignoffTarget] = useState('');
  const [signoffError, setSignoffError] = useState<string | null>(null);
  const [isRequestingSignoff, setIsRequestingSignoff] = useState(false);

  const trimmedToken = token.trim();
  const trimmedLicense = license.trim();

  const hydrateThread = useCallback(
    (thread: WorkspaceDocumentThread<RequirementRecord[]>) => {
      const normalizedContent = normalizeRequirements(thread.document.revision.content);
      const normalizedDocument: WorkspaceDocument<RequirementRecord[]> = {
        ...thread.document,
        revision: {
          ...thread.document.revision,
          hash: toLowerHash(thread.document.revision?.hash),
          content: normalizedContent,
        },
      };
      setDocument(normalizedDocument);
      setRequirements(normalizedContent);
      setComments(thread.comments);
      setSignoffs(thread.signoffs.map((entry) => ({ ...entry, revisionHash: toLowerHash(entry.revisionHash) })));
      setNextCursor(thread.nextCursor);
      setLoading(false);
      setError(null);
    },
    [],
  );

  useEffect(() => {
    if (initialThread) {
      hydrateThread(initialThread);
    }
  }, [hydrateThread, initialThread]);

  useEffect(() => {
    if (!trimmedToken || !trimmedLicense) {
      setLoading(false);
      setError('Token ve lisans gereklidir.');
      setDocument(null);
      setRequirements([]);
      setComments([]);
      setSignoffs([]);
      setNextCursor(null);
      return;
    }

    if (initialThread && document) {
      const expectedHash = toLowerHash(initialThread.document.revision?.hash);
      if (document.revision.hash === expectedHash) {
        return;
      }
    } else if (initialThread && !document) {
      return;
    }

    const controller = new AbortController();
    setLoading(true);
    setError(null);

    getWorkspaceDocumentThread<RequirementRecord[]>({
      token: trimmedToken,
      license: trimmedLicense,
      workspaceId,
      documentId,
      signal: controller.signal,
    })
      .then((thread) => {
        if (controller.signal.aborted) {
          return;
        }
        hydrateThread(thread);
      })
      .catch((err) => {
        if (controller.signal.aborted) {
          return;
        }
        setError(err instanceof ApiError ? err.message : 'Belge yüklenemedi.');
        setLoading(false);
      });

    return () => {
      controller.abort();
    };
  }, [trimmedToken, trimmedLicense, workspaceId, documentId, initialThread, document, hydrateThread]);

  const handleRequirementChange = (
    index: number,
    field: keyof RequirementRecord,
    value: string | RequirementStatus,
  ) => {
    setRequirements((previous) => {
      const next = [...previous];
      const current = { ...next[index] };
      if (field === 'tags') {
        current.tags = parseTags(value as string);
      } else if (field === 'status') {
        current.status = value as RequirementStatus;
      } else if (field === 'description') {
        current.description = value as string;
      } else if (field === 'id') {
        current.id = value as string;
      } else if (field === 'title') {
        current.title = value as string;
      }
      next[index] = current;
      return next;
    });
  };

  const handleAddRequirement = () => {
    setRequirements((previous) => [
      ...previous,
      { id: '', title: '', description: '', status: 'draft', tags: [] },
    ]);
  };

  const handleSave = async () => {
    if (!document || !trimmedToken || !trimmedLicense) {
      return;
    }
    setIsSaving(true);
    setSaveError(null);
    try {
      const payloadContent = requirements.map((record) => ({
        id: record.id.trim(),
        title: record.title.trim(),
        description: record.description.trim(),
        status: record.status,
        tags: record.tags.map((tag) => tag.trim()).filter((tag) => tag.length > 0),
      }));
      const response = await updateWorkspaceDocument<RequirementRecord[]>({
        token: trimmedToken,
        license: trimmedLicense,
        workspaceId,
        documentId,
        expectedHash: document.revision.hash,
        title: document.title,
        content: payloadContent,
      });
      const normalizedContent = normalizeRequirements(response.document.revision.content);
      const normalizedDocument: WorkspaceDocument<RequirementRecord[]> = {
        ...response.document,
        revision: {
          ...response.document.revision,
          hash: toLowerHash(response.document.revision?.hash),
          content: normalizedContent,
        },
      };
      setDocument(normalizedDocument);
      setRequirements(normalizedContent);
    } catch (err) {
      setSaveError(err instanceof ApiError ? err.message : 'Belge kaydedilemedi.');
    } finally {
      setIsSaving(false);
    }
  };

  const handleSubmitComment = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!document || !trimmedToken || !trimmedLicense) {
      return;
    }
    const trimmed = commentDraft.trim();
    if (!trimmed) {
      setCommentError('Yorum metni gereklidir.');
      return;
    }

    setIsPostingComment(true);
    setCommentError(null);
    try {
      const response = await createWorkspaceComment({
        token: trimmedToken,
        license: trimmedLicense,
        workspaceId,
        documentId,
        revisionId: document.revision.id,
        body: trimmed,
      });
      setComments((previous) => [...previous, response.comment]);
      setCommentDraft('');
    } catch (err) {
      setCommentError(err instanceof ApiError ? err.message : 'Yorum eklenemedi.');
    } finally {
      setIsPostingComment(false);
    }
  };

  const handleSignoffSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!document || !trimmedToken || !trimmedLicense) {
      return;
    }
    const target = signoffTarget.trim();
    if (!target) {
      setSignoffError('İmza isteği için hedef gereklidir.');
      return;
    }

    setIsRequestingSignoff(true);
    setSignoffError(null);
    try {
      const response = await requestWorkspaceSignoff({
        token: trimmedToken,
        license: trimmedLicense,
        workspaceId,
        documentId,
        revisionId: document.revision.id,
        requestedFor: target,
      });
      setSignoffs((previous) => [...previous, response.signoff]);
      setShowSignoffModal(false);
      setSignoffTarget('');
    } catch (err) {
      setSignoffError(err instanceof ApiError ? err.message : 'İmza isteği gönderilemedi.');
    } finally {
      setIsRequestingSignoff(false);
    }
  };

  const revisionSummary = useMemo(() => {
    if (!document) {
      return '';
    }
    return `Revision ${document.revision.number} • Last updated ${new Date(
      document.revision.createdAt,
    ).toLocaleString()}`;
  }, [document]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Requirements editor"
        description="Manage requirements, collect feedback and request signoffs without leaving the browser."
        breadcrumb={[{ label: 'Workspaces', href: '/workspaces' }, { label: 'Requirements editor' }]}
        actions={
          <Button onClick={() => setShowSignoffModal(true)} disabled={!document}>
            Request signoff
          </Button>
        }
      />

      {loading ? (
        <Skeleton className="h-64 w-full" data-testid="requirements-loading" />
      ) : error ? (
        <Alert title="Belge yüklenemedi" description={error} variant="error" />
      ) : !document ? (
        <Alert title="Belge bulunamadı" description="Çalışma alanı belgesi okunamadı." variant="warning" />
      ) : (
        <div className="grid gap-6 lg:grid-cols-[2fr_1fr]" data-testid="requirements-editor">
          <div className="space-y-4">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h2 className="text-lg font-semibold text-white">{document.title}</h2>
                <p className="text-sm text-slate-300">{revisionSummary}</p>
                <p className="text-xs text-slate-400" data-testid="revision-hash">
                  Hash: {document.revision.hash}
                </p>
              </div>
              <div className="flex gap-2">
                <Button type="button" variant="secondary" onClick={handleAddRequirement}>
                  Add requirement
                </Button>
                <Button type="button" onClick={handleSave} disabled={isSaving}>
                  {isSaving ? 'Saving…' : 'Save changes'}
                </Button>
              </div>
            </div>

            {saveError && <Alert title="Kaydetme hatası" description={saveError} variant="error" />}

            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-slate-700" data-testid="requirements-grid">
                <thead>
                  <tr className="text-left text-xs uppercase tracking-wide text-slate-400">
                    <th className="px-3 py-2">ID</th>
                    <th className="px-3 py-2">Title</th>
                    <th className="px-3 py-2">Description</th>
                    <th className="px-3 py-2">Status</th>
                    <th className="px-3 py-2">Tags</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {requirements.map((requirement, index) => {
                    const idField = `requirement-${index}-id`;
                    const titleField = `requirement-${index}-title`;
                    const descriptionField = `requirement-${index}-description`;
                    const statusField = `requirement-${index}-status`;
                    const tagsField = `requirement-${index}-tags`;
                    return (
                      <tr key={index} className="align-top text-sm text-slate-100">
                        <td className="px-3 py-2">
                          <label className="block text-xs text-slate-400" htmlFor={idField}>
                            Requirement ID {index + 1}
                          </label>
                          <Input
                            id={idField}
                            value={requirement.id}
                            onChange={(event) => handleRequirementChange(index, 'id', event.target.value)}
                          />
                        </td>
                        <td className="px-3 py-2">
                          <label className="block text-xs text-slate-400" htmlFor={titleField}>
                            Title {index + 1}
                          </label>
                          <Input
                            id={titleField}
                            value={requirement.title}
                            onChange={(event) => handleRequirementChange(index, 'title', event.target.value)}
                          />
                        </td>
                        <td className="px-3 py-2">
                          <label className="block text-xs text-slate-400" htmlFor={descriptionField}>
                            Description {index + 1}
                          </label>
                          <Textarea
                            id={descriptionField}
                            rows={3}
                            value={requirement.description}
                            onChange={(event) => handleRequirementChange(index, 'description', event.target.value)}
                          />
                        </td>
                        <td className="px-3 py-2">
                          <label className="block text-xs text-slate-400" htmlFor={statusField}>
                            Status {index + 1}
                          </label>
                          <select
                            id={statusField}
                            className="mt-1 w-full rounded border border-slate-700 bg-slate-900 p-2 text-sm"
                            value={requirement.status}
                            onChange={(event) => handleRequirementChange(index, 'status', event.target.value as RequirementStatus)}
                          >
                            {requirementStatuses.map((status) => (
                              <option key={status} value={status}>
                                {status}
                              </option>
                            ))}
                          </select>
                        </td>
                        <td className="px-3 py-2">
                          <label className="block text-xs text-slate-400" htmlFor={tagsField}>
                            Tags {index + 1}
                          </label>
                          <Input
                            id={tagsField}
                            value={serializeTags(requirement.tags)}
                            placeholder="comma,separated,tags"
                            onChange={(event) => handleRequirementChange(index, 'tags', event.target.value)}
                          />
                        </td>
                      </tr>
                    );
                  })}
                  {requirements.length === 0 && (
                    <tr>
                      <td colSpan={5} className="px-3 py-6 text-center text-sm text-slate-400">
                        No requirements defined yet. Use “Add requirement” to start authoring.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          <aside className="space-y-6">
            <section className="space-y-3">
              <h3 className="text-sm font-semibold uppercase tracking-wide text-slate-300">Comments</h3>
              <div className="space-y-3" data-testid="comment-list">
                {comments.length === 0 ? (
                  <p className="text-sm text-slate-400">Henüz yorum eklenmemiş.</p>
                ) : (
                  comments.map((comment) => (
                    <div key={comment.id} className="rounded border border-slate-800 bg-slate-900 p-3">
                      <p className="text-xs text-slate-400">
                        {comment.authorId} • {new Date(comment.createdAt).toLocaleString()}
                      </p>
                      <p className="mt-2 text-sm text-slate-100">{comment.body}</p>
                    </div>
                  ))
                )}
              </div>
              <form className="space-y-2" onSubmit={handleSubmitComment}>
                <label className="block text-xs uppercase tracking-wide text-slate-400" htmlFor="new-comment">
                  Add comment
                </label>
                <Textarea
                  id="new-comment"
                  rows={3}
                  value={commentDraft}
                  onChange={(event) => setCommentDraft(event.target.value)}
                />
                {commentError && <p className="text-sm text-red-400">{commentError}</p>}
                <Button type="submit" disabled={isPostingComment}>
                  {isPostingComment ? 'Posting…' : 'Post comment'}
                </Button>
              </form>
            </section>

            <section className="space-y-3" data-testid="signoff-list">
              <h3 className="text-sm font-semibold uppercase tracking-wide text-slate-300">Signoffs</h3>
              {signoffs.length === 0 ? (
                <p className="text-sm text-slate-400">İmza isteği bulunmuyor.</p>
              ) : (
                <ul className="space-y-3">
                  {signoffs.map((signoff) => (
                    <li key={signoff.id} className="rounded border border-slate-800 bg-slate-900 p-3">
                      <div className="flex items-center justify-between">
                        <p className="text-sm text-slate-100">{signoff.requestedFor}</p>
                        <Badge variant={signoff.status === 'approved' ? 'success' : 'warning'}>{signoff.status}</Badge>
                      </div>
                      <p className="mt-1 text-xs text-slate-400">
                        Requested by {signoff.requestedBy} • {new Date(signoff.createdAt).toLocaleString()}
                      </p>
                      <p className="mt-1 text-xs text-slate-500">Revision hash: {signoff.revisionHash}</p>
                    </li>
                  ))}
                </ul>
              )}
              {nextCursor && (
                <p className="text-xs text-slate-500">Daha fazla yorum için sunucudan `nextCursor` ile devam edin.</p>
              )}
            </section>
          </aside>
        </div>
      )}

      {showSignoffModal && (
        <div
          role="dialog"
          aria-modal="true"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
        >
          <div className="w-full max-w-md space-y-4 rounded border border-slate-700 bg-slate-900 p-6">
            <h2 className="text-lg font-semibold text-white">Request signoff</h2>
            <p className="text-sm text-slate-300">
              Send a signoff request for the current revision ({document?.revision.hash}).
            </p>
            <form className="space-y-3" onSubmit={handleSignoffSubmit}>
              <label className="block text-xs uppercase tracking-wide text-slate-400" htmlFor="signoff-target">
                Requested for
              </label>
              <Input
                id="signoff-target"
                value={signoffTarget}
                onChange={(event) => setSignoffTarget(event.target.value)}
              />
              {signoffError && <p className="text-sm text-red-400">{signoffError}</p>}
              <div className="flex justify-end gap-2">
                <Button type="button" variant="secondary" onClick={() => setShowSignoffModal(false)}>
                  Cancel
                </Button>
                <Button type="submit" disabled={isRequestingSignoff}>
                  {isRequestingSignoff ? 'Sending…' : 'Send request'}
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
