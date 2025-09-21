import { Alert, Badge, Card, EmptyState, PageHeader, Skeleton, Table } from '@bora/ui-kit';
import type { AuditLogEntry } from '@soipack/ui-mocks';
import { useEffect, useMemo, useState } from 'react';

import { useAuditTrail } from '../providers/AuditTrailProvider';
import { useT } from '../providers/I18nProvider';
import { fetchDashboard, fetchLogs, type DashboardPayload } from '../services/mockService';

export default function DashboardPage() {
  const [dashboard, setDashboard] = useState<DashboardPayload | null>(null);
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const { events } = useAuditTrail();
  const t = useT();

  useEffect(() => {
    async function load() {
      setLoading(true);
      const [dashboardData, logData] = await Promise.all([fetchDashboard(), fetchLogs()]);
      setDashboard(dashboardData);
      setLogs(logData);
      setLoading(false);
    }
    void load();
  }, []);

  const recentActivity = useMemo(() => {
    const synthetic = events.map((event) => ({
      id: event.id,
      correlationId: event.correlationId,
      actor: event.actor,
      role: event.role as AuditLogEntry['role'],
      action: event.action,
      severity: 'info' as AuditLogEntry['severity'],
      createdAt: event.timestamp
    }));
    return [...synthetic, ...logs].slice(0, 6);
  }, [events, logs]);

  return (
    <div className="space-y-8">
      <PageHeader
        title={t('dashboard.title')}
        description={t('dashboard.description')}
        breadcrumb={[{ label: t('dashboard.title') }]}
      />

      {loading && (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          {Array.from({ length: 4 }).map((_, index) => (
            <Skeleton key={index} className="h-36 w-full" />
          ))}
        </div>
      )}

      {!loading && dashboard && (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          {dashboard.metrics.map((metric) => (
            <Card key={metric.id} title={metric.label} description={`${metric.value}${metric.unit ?? ''}`}>
              <div className="flex items-end justify-between text-xs text-[color:var(--fg-muted)]">
                <span>{metric.trend === 'up' ? '▲' : metric.trend === 'down' ? '▼' : '–'}</span>
                <span>{metric.delta.toFixed(2)}</span>
              </div>
            </Card>
          ))}
        </div>
      )}

      {!loading && dashboard?.notices.length ? (
        <div className="grid gap-3">
          {dashboard.notices.map((notice) => (
            <Alert
              key={notice.id}
              title={t('dashboard.notices')}
              description={notice.message}
              variant={notice.scope === 'internal' ? 'warning' : 'info'}
            />
          ))}
        </div>
      ) : null}

      <section className="space-y-4">
        <header className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">{t('dashboard.auditFeed')}</h2>
          {dashboard?.health && (
            <Badge variant="outline">
              {t('dashboard.health')}: {t(`status.${dashboard.health.status.toLowerCase()}`)}
            </Badge>
          )}
        </header>
        {recentActivity.length === 0 ? (
          <EmptyState title={t('logs.empty')} description="" />
        ) : (
          <Table
            columns={[
              { key: 'actor', title: 'Kullanıcı' },
              { key: 'role', title: 'Rol' },
              { key: 'action', title: 'Eylem' },
              { key: 'createdAt', title: 'Zaman' }
            ]}
            rows={recentActivity.map((item) => ({
              actor: item.actor,
              role: item.role,
              action: item.action,
              createdAt: new Date(item.createdAt).toLocaleString()
            }))}
          />
        )}
      </section>
    </div>
  );
}
