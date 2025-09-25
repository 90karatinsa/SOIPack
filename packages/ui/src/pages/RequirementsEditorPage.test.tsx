import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import React from 'react';

import RequirementsEditorPage, { type RequirementRecord } from './RequirementsEditorPage';
import {
  createWorkspaceComment,
  getWorkspaceDocumentThread,
  requestWorkspaceSignoff,
  updateWorkspaceDocument,
  type WorkspaceComment,
  type WorkspaceDocument,
  type WorkspaceSignoff,
} from '../services/api';

jest.mock('../services/api', () => {
  const actual = jest.requireActual('../services/api');
  return {
    ...actual,
    getWorkspaceDocumentThread: jest.fn(),
    updateWorkspaceDocument: jest.fn(),
    createWorkspaceComment: jest.fn(),
    requestWorkspaceSignoff: jest.fn(),
  };
});

describe('RequirementsEditorPage', () => {
  const mockGetThread = getWorkspaceDocumentThread as jest.MockedFunction<typeof getWorkspaceDocumentThread>;
  const mockUpdateDocument = updateWorkspaceDocument as jest.MockedFunction<typeof updateWorkspaceDocument>;
  const mockCreateComment = createWorkspaceComment as jest.MockedFunction<typeof createWorkspaceComment>;
  const mockRequestSignoff = requestWorkspaceSignoff as jest.MockedFunction<typeof requestWorkspaceSignoff>;

  const baseDocument: WorkspaceDocument<RequirementRecord[]> = {
    id: 'requirements',
    tenantId: 'tenant-1',
    workspaceId: 'ws-1',
    kind: 'requirements',
    title: 'Flight Controls',
    createdAt: '2024-03-01T00:00:00.000Z',
    updatedAt: '2024-03-01T00:00:00.000Z',
    revision: {
      id: 'rev-1',
      number: 1,
      hash: 'abc123',
      authorId: 'alice',
      createdAt: '2024-03-01T00:00:00.000Z',
      content: [
        {
          id: 'REQ-1',
          title: 'Autopilot shall disengage on manual override.',
          description: 'Ensure manual override has priority.',
          status: 'draft',
          tags: ['safety'],
        },
      ],
    },
  };

  const baseComments: WorkspaceComment[] = [
    {
      id: 'comment-1',
      documentId: 'requirements',
      revisionId: 'rev-1',
      tenantId: 'tenant-1',
      workspaceId: 'ws-1',
      authorId: 'qa-lead',
      body: 'Please attach verification evidence.',
      createdAt: '2024-03-01T10:00:00.000Z',
    },
  ];

  const baseSignoffs: WorkspaceSignoff[] = [
    {
      id: 'signoff-1',
      documentId: 'requirements',
      revisionId: 'rev-1',
      tenantId: 'tenant-1',
      workspaceId: 'ws-1',
      revisionHash: 'abc123',
      status: 'pending',
      requestedBy: 'alice',
      requestedFor: 'qa',
      createdAt: '2024-03-02T08:00:00.000Z',
      updatedAt: '2024-03-02T08:00:00.000Z',
      approvedAt: null,
      rejectedAt: null,
    },
  ];

  const renderPage = () =>
    render(
      <RequirementsEditorPage
        token="token"
        license="license"
        workspaceId="ws-1"
        documentId="requirements"
      />,
    );

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders requirements, comments and signoffs from the thread', async () => {
    mockGetThread.mockResolvedValue({
      document: baseDocument,
      comments: baseComments,
      signoffs: baseSignoffs,
      nextCursor: null,
    } as unknown as Awaited<ReturnType<typeof getWorkspaceDocumentThread>>);

    renderPage();

    await waitFor(() => {
      expect(screen.getByTestId('requirements-grid')).toBeInTheDocument();
    });

    expect(screen.getByLabelText('Requirement ID 1')).toHaveValue('REQ-1');
    expect(screen.getByLabelText('Title 1')).toHaveValue('Autopilot shall disengage on manual override.');
    expect(screen.getByText(/verification evidence/i)).toBeInTheDocument();
    expect(screen.getByText(/Requested by alice/i)).toBeInTheDocument();
  });

  it('saves changes with expected hash and updates the revision summary', async () => {
    mockGetThread.mockResolvedValue({
      document: baseDocument,
      comments: baseComments,
      signoffs: baseSignoffs,
      nextCursor: null,
    } as unknown as Awaited<ReturnType<typeof getWorkspaceDocumentThread>>);

    mockUpdateDocument.mockResolvedValue({
      document: {
        ...baseDocument,
        revision: {
          ...baseDocument.revision,
          hash: 'def456',
          number: 2,
          content: [
            {
              id: 'REQ-1',
              title: 'Updated title',
              description: 'Ensure manual override has priority.',
              status: 'approved',
              tags: ['safety'],
            },
          ],
        },
      },
    } as unknown as Awaited<ReturnType<typeof updateWorkspaceDocument>>);

    renderPage();

    await waitFor(() => {
      expect(screen.getByTestId('requirements-grid')).toBeInTheDocument();
    });

    const titleInput = screen.getByLabelText('Title 1');
    fireEvent.change(titleInput, { target: { value: 'Updated title' } });

    fireEvent.click(screen.getByRole('button', { name: /save changes/i }));

    await waitFor(() => {
      expect(mockUpdateDocument).toHaveBeenCalled();
    });

    const updateCall = mockUpdateDocument.mock.calls[0]?.[0] as
      | undefined
      | {
          expectedHash?: string;
          content?: Array<{ title?: string }>;
        };
    expect(updateCall?.expectedHash).toBe('abc123');
    expect(updateCall?.content?.[0]?.title).toBe('Updated title');

    await waitFor(() => {
      expect(screen.getByTestId('revision-hash')).toHaveTextContent('def456');
    });
  });

  it('allows posting comments and requesting signoffs', async () => {
    mockGetThread.mockResolvedValue({
      document: baseDocument,
      comments: [],
      signoffs: [],
      nextCursor: null,
    } as unknown as Awaited<ReturnType<typeof getWorkspaceDocumentThread>>);

    mockCreateComment.mockResolvedValue({
      comment: {
        id: 'comment-2',
        documentId: 'requirements',
        revisionId: 'rev-1',
        tenantId: 'tenant-1',
        workspaceId: 'ws-1',
        authorId: 'alice',
        body: 'Looks great!',
        createdAt: '2024-03-01T12:00:00.000Z',
      },
    } as Awaited<ReturnType<typeof createWorkspaceComment>>);

    mockRequestSignoff.mockResolvedValue({
      signoff: {
        ...baseSignoffs[0],
        id: 'signoff-2',
        requestedFor: 'der',
        revisionHash: 'abc123',
      },
    } as Awaited<ReturnType<typeof requestWorkspaceSignoff>>);

    renderPage();

    await waitFor(() => {
      expect(screen.getByTestId('requirements-grid')).toBeInTheDocument();
    });

    fireEvent.change(screen.getByLabelText('Add comment'), { target: { value: 'Looks great!' } });
    fireEvent.click(screen.getByRole('button', { name: /post comment/i }));

    await waitFor(() => {
      expect(mockCreateComment).toHaveBeenCalled();
    });

    await waitFor(() => {
      expect(screen.getByText('Looks great!')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /request signoff/i }));

    const targetInput = await screen.findByLabelText('Requested for');
    fireEvent.change(targetInput, { target: { value: 'der' } });
    fireEvent.click(screen.getByRole('button', { name: /send request/i }));

    await waitFor(() => {
      expect(mockRequestSignoff).toHaveBeenCalledWith(
        expect.objectContaining({
          documentId: 'requirements',
          requestedFor: 'der',
          revisionId: 'rev-1',
        }),
      );
    });

    await waitFor(() => {
      expect(screen.getByText('der')).toBeInTheDocument();
    });

    await waitFor(() => {
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });
  });
});
