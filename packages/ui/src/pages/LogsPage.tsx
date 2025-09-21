import { Button, EmptyState, Input, PageHeader, Pagination, Select, Table, Toolbar } from '@bora/ui-kit';
import type { AuditLogEntry } from '@soipack/ui-mocks';
import { useEffect, useMemo, useState } from 'react';

import { useAuditTrail } from '../providers/AuditTrailProvider';
import { useT } from '../providers/I18nProvider';
import { RoleGate } from '../providers/RbacProvider';
import { fetchLogs } from '../services/mockService';

const severityOptions = [
  { value: 'all', label: 'Tümü' },
  { value: 'info', label: 'Bilgi' },
  { value: 'warning', label: 'Uyarı' },
  { value: 'danger', label: 'Kritik' }
];

export default function LogsPage() {
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('all');
  const [page, setPage] = useState(1);
  const pageSize = 8;
  const t = useT();
  const { logEvent } = useAuditTrail();

  useEffect(() => {
    void fetchLogs().then(setLogs);
  }, []);

  const filtered = useMemo(() => {
    return logs
      .filter((entry) =>
        severity === 'all' ? true : entry.severity === severity
      )
      .filter((entry) =>
        [entry.actor, entry.role, entry.action, entry.correlationId]
          .join(' ')
          .toLowerCase()
          .includes(query.toLowerCase())
      );
  }, [logs, query, severity]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const visible = filtered.slice((page - 1) * pageSize, page * pageSize);

  const handleExport = () => {
    const header = 'actor,role,action,severity,createdAt,correlationId\n';
    const rows = filtered
      .map((entry) =>
        [entry.actor, entry.role, entry.action, entry.severity, entry.createdAt, entry.correlationId]
          .map((value) => `"${value.replace(/"/g, '""')}"`)
          .join(',')
      )
      .join('\n');
    const blob = new Blob([header + rows], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'audit-logs.csv';
    anchor.click();
    URL.revokeObjectURL(url);
    logEvent('Denetim kayıtları CSV dışa aktarıldı');
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
          placeholder="Ara"
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
            setPage(1);
          }}
          aria-label="Kayıt filtrele"
        />
        <Select
          value={severity}
          onValueChange={(value) => {
            setSeverity(value);
            setPage(1);
          }}
          options={severityOptions}
        />
        <Pagination page={page} totalPages={totalPages} onPageChange={setPage} />
      </Toolbar>

      {visible.length === 0 ? (
        <EmptyState title={t('logs.empty')} description="" />
      ) : (
        <Table
          columns={[
            { key: 'actor', title: 'Kullanıcı' },
            { key: 'role', title: 'Rol' },
            { key: 'action', title: 'Eylem' },
            { key: 'severity', title: 'Seviye' },
            { key: 'createdAt', title: 'Zaman' },
            { key: 'correlationId', title: 'Correlation' }
          ]}
          rows={visible.map((entry) => ({
            actor: entry.actor,
            role: entry.role,
            action: entry.action,
            severity: entry.severity,
            createdAt: new Date(entry.createdAt).toLocaleString(),
            correlationId: entry.correlationId
          }))}
        />
      )}
    </div>
  );
}
