import { Alert, Button, EmptyState, Input, PageHeader, Skeleton, Table, Toolbar } from '@bora/ui-kit';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import { useT } from '../providers/I18nProvider';
import { RoleGate } from '../providers/RbacProvider';
import { ApiError, listAuditLogs, type AuditLogEntry } from '../services/api';

type LogsPageProps = {
  token?: string;
  license?: string;
  onExport?: (filters: { tenantId?: string; actor?: string }) => void;
  pageSize?: number;
};

interface LogsState {
  loading: boolean;
  error: string | null;
  items: AuditLogEntry[];
  hasMore: boolean;
  nextOffset: number | null;
}

const PAGE_SIZE_DEFAULT = 25;

export default function LogsPage({
  token = '',
  license = '',
  onExport,
  pageSize = PAGE_SIZE_DEFAULT,
}: LogsPageProps) {
  const t = useT();
  const [filters, setFilters] = useState<{ tenantId: string; actor: string }>({ tenantId: '', actor: '' });
  const [state, setState] = useState<LogsState>({
    loading: false,
    error: null,
    items: [],
    hasMore: false,
    nextOffset: null,
  });
  const [isAppending, setIsAppending] = useState(false);
  const sentinelRef = useRef<HTMLDivElement | null>(null);
  const appendGuardRef = useRef(false);
  const filterSignatureRef = useRef('');

  const trimmedToken = token.trim();
  const trimmedLicense = license.trim();
  const tenantFilter = filters.tenantId.trim();
  const actorFilter = filters.actor.trim();
  const filterSignature = `${tenantFilter}::${actorFilter}`;

  useEffect(() => {
    if (!trimmedToken || !trimmedLicense) {
      filterSignatureRef.current = filterSignature;
      appendGuardRef.current = false;
      setIsAppending(false);
      setState({
        loading: false,
        error: t('logs.credentialsRequired'),
        items: [],
        hasMore: false,
        nextOffset: null,
      });
      return;
    }

    filterSignatureRef.current = filterSignature;
    appendGuardRef.current = false;
    setIsAppending(false);

    const controller = new AbortController();
    setState((previous) => ({ ...previous, loading: true, error: null, items: [] }));

    listAuditLogs({
      token: trimmedToken,
      license: trimmedLicense,
      tenantId: tenantFilter || undefined,
      actor: actorFilter || undefined,
      order: 'desc',
      limit: pageSize,
      offset: 0,
      signal: controller.signal,
    })
      .then((response) => {
        setState({
          loading: false,
          error: null,
          items: response.items,
          hasMore: response.hasMore,
          nextOffset: response.nextOffset,
        });
      })
      .catch((error) => {
        if (controller.signal.aborted) {
          return;
        }
        const message = error instanceof ApiError ? error.message : t('logs.error');
        setState({ loading: false, error: message, items: [], hasMore: false, nextOffset: null });
      });

    return () => {
      controller.abort();
    };
  }, [
    trimmedToken,
    trimmedLicense,
    tenantFilter,
    actorFilter,
    pageSize,
    t,
    filterSignature,
  ]);

  const loadMore = useCallback(() => {
    if (appendGuardRef.current) {
      return;
    }
    if (!trimmedToken || !trimmedLicense) {
      return;
    }
    if (!state.hasMore || state.nextOffset === null) {
      return;
    }

    appendGuardRef.current = true;
    setIsAppending(true);

    const requestSignature = filterSignature;

    listAuditLogs({
      token: trimmedToken,
      license: trimmedLicense,
      tenantId: tenantFilter || undefined,
      actor: actorFilter || undefined,
      order: 'desc',
      limit: pageSize,
      offset: state.nextOffset,
    })
      .then((response) => {
        if (filterSignatureRef.current !== requestSignature) {
          return;
        }
        setState((previous) => ({
          loading: previous.loading,
          error: null,
          items: [...previous.items, ...response.items],
          hasMore: response.hasMore,
          nextOffset: response.nextOffset,
        }));
      })
      .catch((error) => {
        const message = error instanceof ApiError ? error.message : t('logs.error');
        setState((previous) => ({
          ...previous,
          error: message,
        }));
      })
      .finally(() => {
        appendGuardRef.current = false;
        setIsAppending(false);
      });
  }, [
    actorFilter,
    filterSignature,
    pageSize,
    state.hasMore,
    state.nextOffset,
    tenantFilter,
    t,
    trimmedLicense,
    trimmedToken,
  ]);

  useEffect(() => {
    const sentinel = sentinelRef.current;
    if (!sentinel) {
      return;
    }
    if (!state.hasMore) {
      return;
    }

    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          loadMore();
        }
      });
    }, { rootMargin: '200px' });

    observer.observe(sentinel);

    return () => {
      observer.disconnect();
    };
  }, [loadMore, state.hasMore]);

  const rows = useMemo(
    () =>
      state.items.map((entry) => ({
        id: entry.id,
        actor: entry.actor,
        tenantId: entry.tenantId,
        action: entry.action,
        target: entry.target ?? '-',
        createdAt: new Date(entry.createdAt).toLocaleString(),
      })),
    [state.items],
  );

  const handleExport = () => {
    const exportFilters = {
      tenantId: tenantFilter || undefined,
      actor: actorFilter || undefined,
    };

    if (onExport) {
      onExport(exportFilters);
      return;
    }

    if (typeof document === 'undefined') {
      return;
    }

    const header = 'id,tenantId,actor,action,target,createdAt\n';
    const rowsAsString = state.items
      .map((entry) =>
        [entry.id, entry.tenantId, entry.actor, entry.action, entry.target ?? '', entry.createdAt]
          .map((value) => {
            const text = value ?? '';
            return `"${String(text).replace(/"/g, '""')}"`;
          })
          .join(','),
      )
      .join('\n');

    const blob = new Blob([header + rowsAsString], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'audit-logs.csv';
    anchor.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-8">
      <PageHeader
        title={t('logs.title')}
        description={t('logs.description')}
        breadcrumb={[{ label: t('dashboard.title'), href: '/' }, { label: t('logs.title') }]}
        actions={
          <RoleGate role={['admin', 'operator']}>
            <Button onClick={handleExport} variant="secondary" size="sm">
              {t('logs.exportCsv')}
            </Button>
          </RoleGate>
        }
      />

      <Toolbar>
        <Input
          value={filters.tenantId}
          onChange={(event) => setFilters((previous) => ({ ...previous, tenantId: event.target.value }))}
          placeholder={t('logs.filter.tenant')}
          aria-label={t('logs.filter.tenant')}
        />
        <Input
          value={filters.actor}
          onChange={(event) => setFilters((previous) => ({ ...previous, actor: event.target.value }))}
          placeholder={t('logs.filter.actor')}
          aria-label={t('logs.filter.actor')}
        />
      </Toolbar>

      {state.loading ? (
        <div data-testid="logs-loading" className="space-y-2">
          {Array.from({ length: 5 }).map((_, index) => (
            <Skeleton key={index} className="h-12 w-full" />
          ))}
        </div>
      ) : state.error ? (
        <Alert title={t('logs.errorTitle')} description={state.error} variant="error" />
      ) : rows.length === 0 ? (
        <EmptyState title={t('logs.empty')} description="" />
      ) : (
        <div className="space-y-4">
          <Table
            columns={[
              { key: 'createdAt', title: t('logs.table.timestamp') },
              { key: 'actor', title: t('logs.table.actor') },
              { key: 'tenantId', title: t('logs.table.tenant') },
              { key: 'action', title: t('logs.table.action') },
              { key: 'target', title: t('logs.table.target') },
            ]}
            rows={rows}
          />
          <div ref={sentinelRef} data-testid="logs-sentinel" className="h-2 w-full" />
          {isAppending && (
            <div data-testid="logs-appending" className="space-y-2">
              <Skeleton className="h-12 w-full" />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
