import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { ComponentProps } from 'react';

import { I18nProvider } from '../providers/I18nProvider';
import LogsPage from './LogsPage';
import { listAuditLogs } from '../services/api';

jest.mock('../services/api', () => {
  const actual = jest.requireActual('../services/api');
  return {
    ...actual,
    listAuditLogs: jest.fn(),
  };
});

describe('LogsPage', () => {
  const mockListAuditLogs = listAuditLogs as jest.MockedFunction<typeof listAuditLogs>;
  const observers: Array<{
    observe: jest.Mock;
    unobserve: jest.Mock;
    disconnect: jest.Mock;
    trigger: (isIntersecting?: boolean) => void;
  }> = [];

  const installObserver = () => {
    observers.length = 0;
    (global as unknown as { IntersectionObserver: unknown }).IntersectionObserver = jest.fn(
      (callback: IntersectionObserverCallback) => {
        const instance: {
          observe: jest.Mock;
          unobserve: jest.Mock;
          disconnect: jest.Mock;
          trigger: (isIntersecting?: boolean) => void;
          element?: Element;
        } = {
          observe: jest.fn((element: Element) => {
            instance.element = element;
          }),
          unobserve: jest.fn(),
          disconnect: jest.fn(),
          trigger: (isIntersecting = true) => {
            const target = instance.element ?? document.createElement('div');
            const entry = {
              isIntersecting,
              intersectionRatio: isIntersecting ? 1 : 0,
              target,
              boundingClientRect: target.getBoundingClientRect(),
              intersectionRect: target.getBoundingClientRect(),
              rootBounds: null,
              time: 0,
            } as IntersectionObserverEntry;
            callback([entry], instance as unknown as IntersectionObserver);
          },
        };
        observers.push(instance);
        return instance as unknown as IntersectionObserver;
      },
    );
  };

  const renderLogs = (props?: Partial<ComponentProps<typeof LogsPage>>) =>
    render(
      <I18nProvider>
        <LogsPage token="demo-token" license="demo-license" {...props} />
      </I18nProvider>,
    );

  beforeEach(() => {
    jest.clearAllMocks();
    installObserver();
    mockListAuditLogs.mockImplementation(() =>
      Promise.resolve({ items: [], hasMore: false, nextOffset: null }),
    );
  });

  it('fetches audit logs and refetches when filters change', async () => {
    const now = new Date().toISOString();
    mockListAuditLogs
      .mockImplementationOnce(() =>
        Promise.resolve({
          items: [
            { id: 'log-1', tenantId: 'tenant-1', actor: 'alice', action: 'login', createdAt: now },
          ],
          hasMore: true,
          nextOffset: 25,
        }),
      )
      .mockImplementationOnce(() =>
        Promise.resolve({
          items: [
            { id: 'log-2', tenantId: 'tenant-2', actor: 'bob', action: 'update', createdAt: now },
          ],
          hasMore: true,
          nextOffset: 50,
        }),
      )
      .mockImplementationOnce(() =>
        Promise.resolve({
          items: [
            { id: 'log-3', tenantId: 'tenant-2', actor: 'bob', action: 'approve', createdAt: now },
          ],
          hasMore: false,
          nextOffset: null,
        }),
      );

    renderLogs();

    await waitFor(() => {
      expect(screen.getByText('alice')).toBeInTheDocument();
    });

    expect(mockListAuditLogs).toHaveBeenCalledWith(
      expect.objectContaining({
        token: 'demo-token',
        license: 'demo-license',
        tenantId: undefined,
        actor: undefined,
        offset: 0,
      }),
    );

    const tenantInput = screen.getByLabelText(/Kiracı filtresi/i);
    fireEvent.change(tenantInput, { target: { value: 'tenant-2' } });

    await waitFor(() => {
      expect(mockListAuditLogs).toHaveBeenCalledTimes(2);
    });

    expect(mockListAuditLogs.mock.calls[1][0]).toEqual(
      expect.objectContaining({ tenantId: 'tenant-2', actor: undefined }),
    );

    const sentinel = await screen.findByTestId('logs-sentinel');
    const observer = observers.find((entry) => entry.observe.mock.calls.some(([element]) => element === sentinel));
    expect(observer).toBeDefined();
    await waitFor(() => {
      expect(observer?.observe).toHaveBeenCalledWith(sentinel);
    });
    await act(async () => {
      observer?.trigger();
    });

    await waitFor(() => {
      expect(mockListAuditLogs).toHaveBeenCalledTimes(3);
    });
    await waitFor(() => {
      expect(screen.getAllByText('bob')).toHaveLength(2);
    });
  });

  it('invokes export callback with the active filters', async () => {
    const onExport = jest.fn();
    renderLogs({ onExport });

    await waitFor(() => {
      expect(mockListAuditLogs).toHaveBeenCalledTimes(1);
    });

    const actorInput = screen.getByLabelText(/Kullanıcı filtresi/i);
    fireEvent.change(actorInput, { target: { value: 'auditor ' } });

    await waitFor(() => {
      expect(mockListAuditLogs).toHaveBeenCalledTimes(2);
    });

    const tenantInput = screen.getByLabelText(/Kiracı filtresi/i);
    fireEvent.change(tenantInput, { target: { value: 'tenant-ops' } });

    await waitFor(() => {
      expect(mockListAuditLogs).toHaveBeenCalledTimes(3);
    });

    const exportButton = await screen.findByRole('button', { name: /CSV/i });
    fireEvent.click(exportButton);

    expect(onExport).toHaveBeenCalledWith({ tenantId: 'tenant-ops', actor: 'auditor' });
    expect(onExport).toHaveBeenCalledTimes(1);
  });
});
