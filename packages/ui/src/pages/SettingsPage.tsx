import {
  Alert,
  Badge,
  Button,
  Card,
  Form,
  FormField,
  Input,
  PageHeader,
  Skeleton,
  Tabs,
  Textarea,
  useToast,
} from '@bora/ui-kit';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { useForm } from 'react-hook-form';

import { useAuditTrail } from '../providers/AuditTrailProvider';
import { useT } from '../providers/I18nProvider';
import { RoleGate } from '../providers/RbacProvider';
import {
  ApiError,
  getAdminSecurity,
  getLicense,
  getServiceMetadata,
  putAdminSecurity,
  type AdminSecuritySettings,
  type LicenseMetadata,
  type SecurityRule,
  type ServiceMetadata,
} from '../services/api';

interface SecurityFormValues {
  revision: string;
  incidentContact: {
    name: string;
    email: string;
    phone: string;
  };
  retention: {
    uploadsDays: string;
    analysesDays: string;
    reportsDays: string;
    packagesDays: string;
  };
  maintenance: {
    dayOfWeek: string;
    startTime: string;
    durationMinutes: string;
    timezone: string;
  };
}

interface SecurityRuleSnapshot {
  incidentContact: { name: string; email: string; phone: string | null };
  retention: {
    uploadsDays: number | null;
    analysesDays: number | null;
    reportsDays: number | null;
    packagesDays: number | null;
  };
  maintenance: { dayOfWeek: string; startTime: string; durationMinutes: number | null; timezone: string };
}

const RETENTION_LABELS: Record<keyof SecurityRuleSnapshot['retention'], string> = {
  uploadsDays: 'Yüklemeler',
  analysesDays: 'Analizler',
  reportsDays: 'Raporlar',
  packagesDays: 'Paketler',
};

const DAY_LABELS: Record<string, string> = {
  monday: 'Pazartesi',
  tuesday: 'Salı',
  wednesday: 'Çarşamba',
  thursday: 'Perşembe',
  friday: 'Cuma',
  saturday: 'Cumartesi',
  sunday: 'Pazar',
};

const createSecurityRuleSnapshot = (): SecurityRuleSnapshot => ({
  incidentContact: { name: '', email: '', phone: null },
  retention: { uploadsDays: null, analysesDays: null, reportsDays: null, packagesDays: null },
  maintenance: { dayOfWeek: '', startTime: '', durationMinutes: null, timezone: '' },
});

const deriveSecuritySnapshot = (rules: SecurityRule[] | undefined): SecurityRuleSnapshot => {
  const snapshot = createSecurityRuleSnapshot();
  for (const rule of rules ?? []) {
    switch (rule.type) {
      case 'incidentContact':
        snapshot.incidentContact = {
          name: rule.config.name ?? '',
          email: rule.config.email ?? '',
          phone: rule.config.phone ?? null,
        };
        break;
      case 'retention':
        snapshot.retention = {
          uploadsDays: rule.config.uploadsDays ?? null,
          analysesDays: rule.config.analysesDays ?? null,
          reportsDays: rule.config.reportsDays ?? null,
          packagesDays: rule.config.packagesDays ?? null,
        };
        break;
      case 'maintenance':
        snapshot.maintenance = {
          dayOfWeek: rule.config.dayOfWeek ?? '',
          startTime: rule.config.startTime ?? '',
          durationMinutes: rule.config.durationMinutes ?? null,
          timezone: rule.config.timezone ?? '',
        };
        break;
      default:
        break;
    }
  }
  return snapshot;
};

const toSecurityFormValues = (
  settings: AdminSecuritySettings | null,
  fallbackTimezone: string,
): SecurityFormValues => {
  const snapshot = deriveSecuritySnapshot(settings?.rules);
  return {
    revision: settings?.revision ?? '',
    incidentContact: {
      name: snapshot.incidentContact.name,
      email: snapshot.incidentContact.email,
      phone: snapshot.incidentContact.phone ?? '',
    },
    retention: {
      uploadsDays: snapshot.retention.uploadsDays !== null ? String(snapshot.retention.uploadsDays) : '',
      analysesDays: snapshot.retention.analysesDays !== null ? String(snapshot.retention.analysesDays) : '',
      reportsDays: snapshot.retention.reportsDays !== null ? String(snapshot.retention.reportsDays) : '',
      packagesDays: snapshot.retention.packagesDays !== null ? String(snapshot.retention.packagesDays) : '',
    },
    maintenance: {
      dayOfWeek: snapshot.maintenance.dayOfWeek,
      startTime: snapshot.maintenance.startTime,
      durationMinutes:
        snapshot.maintenance.durationMinutes !== null ? String(snapshot.maintenance.durationMinutes) : '',
      timezone: snapshot.maintenance.timezone || fallbackTimezone,
    },
  } satisfies SecurityFormValues;
};

const parseInteger = (value: string): number | null => {
  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }
  const parsed = Number.parseInt(trimmed, 10);
  if (!Number.isFinite(parsed)) {
    return null;
  }
  return parsed;
};

const toSecurityRulesPayload = (values: SecurityFormValues): SecurityRule[] => {
  const name = values.incidentContact.name.trim();
  const email = values.incidentContact.email.trim();
  const phone = values.incidentContact.phone.trim();
  const incidentContact: SecurityRule = {
    type: 'incidentContact',
    config: {
      name,
      email,
      ...(phone ? { phone } : {}),
    },
  };

  const uploadsDays = parseInteger(values.retention.uploadsDays);
  const analysesDays = parseInteger(values.retention.analysesDays);
  const reportsDays = parseInteger(values.retention.reportsDays);
  const packagesDays = parseInteger(values.retention.packagesDays);
  const retention: SecurityRule = {
    type: 'retention',
    config: {
      ...(uploadsDays !== null ? { uploadsDays } : {}),
      ...(analysesDays !== null ? { analysesDays } : {}),
      ...(reportsDays !== null ? { reportsDays } : {}),
      ...(packagesDays !== null ? { packagesDays } : {}),
    },
  };

  const durationMinutes = parseInteger(values.maintenance.durationMinutes);
  const maintenance: SecurityRule = {
    type: 'maintenance',
    config: {
      dayOfWeek: values.maintenance.dayOfWeek.trim().toLowerCase(),
      startTime: values.maintenance.startTime.trim(),
      durationMinutes: durationMinutes ?? null,
      timezone: values.maintenance.timezone.trim(),
    },
  };

  return [incidentContact, retention, maintenance];
};

const formatDayOfWeek = (value: string): string => {
  const normalized = value.trim().toLowerCase();
  if (!normalized) {
    return '—';
  }
  return DAY_LABELS[normalized] ?? value;
};

const formatRetentionValue = (value: number | null): string => {
  if (value === null || Number.isNaN(value)) {
    return '—';
  }
  return `${value} gün`;
};

const formatDurationMinutes = (value: number | null): string => {
  if (value === null || Number.isNaN(value)) {
    return '—';
  }
  return `${value} dk`;
};

type SettingsPageProps = {
  token?: string;
  license?: string;
};

export default function SettingsPage({ token = '', license = '' }: SettingsPageProps) {
  const t = useT();
  const { notify } = useToast();
  const { logEvent } = useAuditTrail();
  const [activeTab, setActiveTab] = useState('general');
  const [serviceState, setServiceState] = useState<{
    loading: boolean;
    error: string | null;
    metadata: ServiceMetadata | null;
  }>({ loading: false, error: null, metadata: null });
  const [licenseState, setLicenseState] = useState<{
    loading: boolean;
    error: string | null;
    metadata: LicenseMetadata | null;
  }>({ loading: false, error: null, metadata: null });
  const [securityState, setSecurityState] = useState<{
    loading: boolean;
    error: string | null;
    settings: AdminSecuritySettings | null;
    etag: string | null;
    lastModified: string | null;
    notFound: boolean;
  }>({ loading: false, error: null, settings: null, etag: null, lastModified: null, notFound: false });
  const [isSaving, setIsSaving] = useState(false);
  const environment = import.meta.env.VITE_ENVIRONMENT ?? 'DEV';
  const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const form = useForm<SecurityFormValues>({
    defaultValues: toSecurityFormValues(null, timezone),
  });

  const trimmedToken = token.trim();
  const trimmedLicense = license.trim();

  const loadSecuritySettings = useCallback(
    async ({ signal }: { signal?: AbortSignal } = {}) => {
      if (!trimmedToken || !trimmedLicense) {
        return;
      }

      setSecurityState((previous) => ({ ...previous, loading: true, error: null, notFound: false }));
      try {
        const response = await getAdminSecurity({
          token: trimmedToken,
          license: trimmedLicense,
          signal,
        });
        if (signal?.aborted) {
          return;
        }
        const settings = response.settings;
        setSecurityState({
          loading: false,
          error: null,
          settings,
          etag: response.etag,
          lastModified: response.lastModified,
          notFound: settings === null,
        });
        form.reset(toSecurityFormValues(settings, timezone));
      } catch (error) {
        if (signal?.aborted) {
          return;
        }
        const message = error instanceof ApiError ? error.message : 'Güvenlik ayarları yüklenemedi.';
        setSecurityState({
          loading: false,
          error: message,
          settings: null,
          etag: null,
          lastModified: null,
          notFound: false,
        });
        form.reset(toSecurityFormValues(null, timezone));
      }
    },
    [form, timezone, trimmedLicense, trimmedToken],
  );

  useEffect(() => {
    const credentialsRequired = !trimmedToken || !trimmedLicense;
    if (credentialsRequired) {
      const message = t('dashboard.credentialsRequired');
      setServiceState({ loading: false, error: message, metadata: null });
      setLicenseState({ loading: false, error: message, metadata: null });
      setSecurityState({
        loading: false,
        error: message,
        settings: null,
        etag: null,
        lastModified: null,
        notFound: false,
      });
      form.reset(toSecurityFormValues(null, timezone));
      return;
    }

    const serviceController = new AbortController();
    const licenseController = new AbortController();
    const securityController = new AbortController();

    setServiceState({ loading: true, error: null, metadata: null });
    setLicenseState({ loading: true, error: null, metadata: null });

    getServiceMetadata({
      token: trimmedToken,
      license: trimmedLicense,
      signal: serviceController.signal,
    })
      .then((metadata) => {
        if (!serviceController.signal.aborted) {
          setServiceState({ loading: false, error: null, metadata });
        }
      })
      .catch((error) => {
        if (serviceController.signal.aborted) {
          return;
        }
        const message =
          error instanceof ApiError ? error.message : 'Servis metadatası alınırken bir hata oluştu.';
        setServiceState({ loading: false, error: message, metadata: null });
      });

    getLicense({
      token: trimmedToken,
      license: trimmedLicense,
      signal: licenseController.signal,
    })
      .then((metadata) => {
        if (!licenseController.signal.aborted) {
          setLicenseState({ loading: false, error: null, metadata });
        }
      })
      .catch((error) => {
        if (licenseController.signal.aborted) {
          return;
        }
        const message = error instanceof ApiError ? error.message : 'Lisans bilgisi alınamadı.';
        setLicenseState({ loading: false, error: message, metadata: null });
      });

    void loadSecuritySettings({ signal: securityController.signal });

    return () => {
      serviceController.abort();
      licenseController.abort();
      securityController.abort();
    };
  }, [form, t, timezone, trimmedLicense, trimmedToken, loadSecuritySettings]);

  const securitySnapshot = useMemo(
    () => deriveSecuritySnapshot(securityState.settings?.rules),
    [securityState.settings],
  );

  const handleSubmit = async (values: SecurityFormValues) => {
    if (!trimmedToken || !trimmedLicense) {
      notify({
        title: 'Failure',
        description: 'Kimlik doğrulama bilgileri olmadan güvenlik ayarları kaydedilemez.',
      });
      return;
    }

    setIsSaving(true);
    const ifMatch = securityState.etag ?? '*';
    const revision = values.revision.trim();
    const rules = toSecurityRulesPayload(values);

    try {
      const result = await putAdminSecurity(
        { rules, revision },
        { token: trimmedToken, license: trimmedLicense, ifMatch },
      );

      setSecurityState({
        loading: false,
        error: null,
        settings: result.settings,
        etag: result.etag,
        lastModified: result.lastModified,
        notFound: false,
      });
      form.reset(toSecurityFormValues(result.settings, timezone));

      notify({
        title: 'Success',
        description: `Revizyon ${result.settings.revision || '—'} kaydedildi.`,
      });
      logEvent('Güvenlik ayarları güncellendi');
    } catch (error) {
      if (error instanceof ApiError) {
        if (error.status === 409 || error.status === 412) {
          const details =
            error.details && typeof error.details === 'object' && error.details !== null
              ? (error.details as { currentRevision?: unknown })
              : null;
          const currentRevision =
            details && typeof details.currentRevision === 'string' ? details.currentRevision : null;
          notify({
            title: 'Failure',
            description:
              (error.message || 'Güvenlik ayarları başka biri tarafından güncellendi.') +
              (currentRevision ? ` En güncel revizyon ${currentRevision}.` : '') +
              ' En son veriler yükleniyor.',
          });
          await loadSecuritySettings();
          return;
        }

        if (error.status === 400) {
          notify({
            title: 'Failure',
            description: error.message || 'Gönderilen güvenlik ayarları doğrulamadan geçmedi.',
          });
          return;
        }

        if (error.status === 403) {
          notify({
            title: 'Failure',
            description: error.message || 'Bu işlemi gerçekleştirmek için yetkiniz yok.',
          });
          return;
        }

        if (error.status >= 500) {
          notify({
            title: 'Failure',
            description: error.message || 'Sunucu hatası nedeniyle güvenlik ayarları kaydedilemedi.',
          });
          return;
        }
      }

      const fallbackMessage =
        error instanceof Error ? error.message : 'Güvenlik ayarları kaydedilemedi. Lütfen tekrar deneyin.';
      notify({ title: 'Failure', description: fallbackMessage });
    } finally {
      setIsSaving(false);
    }
  };

  const renderPackJob = () => {
    if (serviceState.loading) {
      return <Skeleton className="h-16 w-full" />;
    }
    if (serviceState.error) {
      return <Alert variant="error" title="Paket" description={serviceState.error} />;
    }
    if (!serviceState.metadata?.packJob) {
      return <p className="text-sm text-[color:var(--fg-muted)]">Henüz paketleme işi bulunmuyor.</p>;
    }
    const { id, createdAt } = serviceState.metadata.packJob;
    return (
      <div className="space-y-1 text-sm text-[color:var(--fg-default)]">
        <div>
          <span className="font-medium text-[color:var(--fg-muted)]">Kimlik:</span>{' '}
          <code className="text-xs">{id}</code>
        </div>
        <div>
          <span className="font-medium text-[color:var(--fg-muted)]">Oluşturulma:</span>{' '}
          {createdAt ? new Date(createdAt).toLocaleString() : '—'}
        </div>
      </div>
    );
  };

  const renderSbomDetails = () => {
    if (serviceState.loading) {
      return <Skeleton className="h-20 w-full" />;
    }
    if (serviceState.error) {
      return <Alert variant="error" title="SBOM" description={serviceState.error} />;
    }
    const sbom = serviceState.metadata?.sbom;
    if (!sbom) {
      return <p className="text-sm text-[color:var(--fg-muted)]">SBOM artefaktı bulunamadı.</p>;
    }
    const verificationVariant = sbom.verified === true ? 'success' : sbom.verified === false ? 'warning' : 'neutral';
    const verificationLabel = sbom.verified === true ? 'Doğrulandı' : sbom.verified === false ? 'Doğrulanamadı' : 'Doğrulama bekleniyor';
    return (
      <div className="space-y-3 text-sm text-[color:var(--fg-default)]">
        <div>
          <span className="font-medium text-[color:var(--fg-muted)]">URL:</span>{' '}
          {sbom.url ? (
            <a
              href={sbom.url}
              target="_blank"
              rel="noreferrer"
              className="text-[color:var(--fg-accent)] underline"
            >
              {sbom.url}
            </a>
          ) : (
            '—'
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-medium text-[color:var(--fg-muted)]">SHA-256:</span>
          <code className="rounded bg-black/40 px-2 py-1 text-xs">
            {sbom.sha256 ?? 'Belirtilmedi'}
          </code>
          <Badge variant={verificationVariant}>{verificationLabel}</Badge>
        </div>
      </div>
    );
  };

  const renderAttestationDetails = () => {
    if (serviceState.loading) {
      return <Skeleton className="h-16 w-full" />;
    }
    if (serviceState.error) {
      return <Alert variant="error" title="Attestasyon" description={serviceState.error} />;
    }
    const attestation = serviceState.metadata?.attestation;
    if (!attestation) {
      return <p className="text-sm text-[color:var(--fg-muted)]">Attestasyon sinyali sağlanmadı.</p>;
    }
    const hasSignals = Object.keys(attestation.signals ?? {}).length > 0;
    return (
      <div className="space-y-3 text-sm text-[color:var(--fg-default)]">
        <Badge variant={attestation.present ? 'success' : 'warning'}>
          {attestation.present ? 'Doğrulama mevcut' : 'Doğrulama bulunamadı'}
        </Badge>
        {hasSignals ? (
          <dl className="space-y-1">
            {Object.entries(attestation.signals).map(([key, value]) => (
              <div key={key} className="flex flex-wrap justify-between gap-2">
                <dt className="font-medium text-[color:var(--fg-muted)]">{key}</dt>
                <dd className="truncate text-[color:var(--fg-default)]">{String(value)}</dd>
              </div>
            ))}
          </dl>
        ) : (
          <p className="text-sm text-[color:var(--fg-muted)]">Ek sinyal paylaşılmadı.</p>
        )}
      </div>
    );
  };

  const isSubmitDisabled = securityState.loading || !trimmedToken || !trimmedLicense || isSaving;

  return (
    <div className="space-y-8">
      <PageHeader
        title={t('settings.title')}
        description={t('settings.description')}
        breadcrumb={[{ label: t('dashboard.title'), href: '/' }, { label: t('settings.title') }]}
      />

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <Tabs.List>
          <Tabs.Trigger value="general">{t('settings.tab.general')}</Tabs.Trigger>
          <Tabs.Trigger value="security">{t('settings.tab.security')}</Tabs.Trigger>
          <Tabs.Trigger value="license">{t('settings.tab.license')}</Tabs.Trigger>
          <Tabs.Trigger value="updates">{t('settings.tab.updates')}</Tabs.Trigger>
        </Tabs.List>

        <Tabs.Content value="general">
          <div className="grid gap-4 md:grid-cols-2">
            <Card title={t('settings.environment')} description={environment}>
              <p className="text-sm text-[color:var(--fg-muted)]">{t('audit.banner')}</p>
            </Card>
            <Card title="Son paketleme işi">{renderPackJob()}</Card>
          </div>
        </Tabs.Content>

        <Tabs.Content value="security">
          <RoleGate role={['admin', 'operator']}>
            <div className="space-y-6">
              {securityState.loading ? (
                <Skeleton className="h-28 w-full" />
              ) : securityState.error ? (
                <Alert variant="error" title="Güvenlik" description={securityState.error} />
              ) : securityState.notFound ? (
                <Alert
                  variant="info"
                  title="Güvenlik"
                  description="Henüz kayıtlı bir güvenlik yapılandırması bulunmuyor."
                />
              ) : securityState.settings ? (
                <Card title="Güncel güvenlik kuralları">
                  <div className="space-y-3 text-sm text-[color:var(--fg-default)]">
                    <div>
                      <span className="font-medium text-[color:var(--fg-muted)]">Revizyon:</span>{' '}
                      <code className="text-xs">{securityState.settings.revision || '—'}</code>
                    </div>
                    <div>
                      <span className="font-medium text-[color:var(--fg-muted)]">Olay irtibatı:</span>{' '}
                      {securitySnapshot.incidentContact.name || securitySnapshot.incidentContact.email ? (
                        <span>
                          {securitySnapshot.incidentContact.name || '—'} (
                          {securitySnapshot.incidentContact.email || '—'})
                        </span>
                      ) : (
                        '—'
                      )}
                    </div>
                    <div>
                      <span className="font-medium text-[color:var(--fg-muted)]">Telefon:</span>{' '}
                      {securitySnapshot.incidentContact.phone ?? '—'}
                    </div>
                    <div className="space-y-1">
                      <span className="font-medium text-[color:var(--fg-muted)]">Saklama pencereleri:</span>
                      <ul className="list-inside list-disc">
                        {(Object.entries(RETENTION_LABELS) as Array<
                          [keyof SecurityRuleSnapshot['retention'], string]
                        >).map(([key, label]) => (
                          <li key={key} className="text-[color:var(--fg-default)]">
                            {label}: {formatRetentionValue(securitySnapshot.retention[key])}
                          </li>
                        ))}
                      </ul>
                    </div>
                    <div>
                      <span className="font-medium text-[color:var(--fg-muted)]">Bakım penceresi:</span>{' '}
                      {securitySnapshot.maintenance.dayOfWeek || securitySnapshot.maintenance.startTime ? (
                        <span>
                          {formatDayOfWeek(securitySnapshot.maintenance.dayOfWeek)}{' '}
                          {securitySnapshot.maintenance.startTime || ''} •{' '}
                          {formatDurationMinutes(securitySnapshot.maintenance.durationMinutes)} •{' '}
                          {securitySnapshot.maintenance.timezone || '—'}
                        </span>
                      ) : (
                        '—'
                      )}
                    </div>
                  </div>
                </Card>
              ) : null}

              <Form form={form} onSubmit={handleSubmit}>
                <div className="grid gap-4 md:grid-cols-2">
                  <FormField
                    control={form.control}
                    name="incidentContact.name"
                    label="Olay irtibatı adı"
                    input={({ name, value, onChange, id, error }) => (
                      <Input
                        id={id}
                        name={name}
                        value={(value as string) ?? ''}
                        onChange={onChange}
                        required
                        invalid={error}
                      />
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="incidentContact.email"
                    label="Olay irtibatı e-posta"
                    input={({ name, value, onChange, id, error }) => (
                      <Input
                        id={id}
                        name={name}
                        type="email"
                        value={(value as string) ?? ''}
                        onChange={onChange}
                        required
                        invalid={error}
                      />
                    )}
                  />
                </div>
                <FormField
                  control={form.control}
                  name="incidentContact.phone"
                  label="Telefon"
                  input={({ name, value, onChange, id, error }) => (
                    <Input
                      id={id}
                      name={name}
                      value={(value as string) ?? ''}
                      onChange={onChange}
                      placeholder="+90 555 000 0000"
                      invalid={error}
                    />
                  )}
                />

                <div className="grid gap-4 md:grid-cols-2">
                  <FormField
                    control={form.control}
                    name="retention.uploadsDays"
                    label="Yüklemeler (gün)"
                    input={({ name, value, onChange, id, error }) => (
                      <Input
                        id={id}
                        name={name}
                        type="number"
                        min={1}
                        max={3650}
                        value={(value as string) ?? ''}
                        onChange={onChange}
                        placeholder="30"
                        invalid={error}
                      />
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="retention.analysesDays"
                    label="Analizler (gün)"
                    input={({ name, value, onChange, id, error }) => (
                      <Input
                        id={id}
                        name={name}
                        type="number"
                        min={1}
                        max={3650}
                        value={(value as string) ?? ''}
                        onChange={onChange}
                        placeholder="90"
                        invalid={error}
                      />
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="retention.reportsDays"
                    label="Raporlar (gün)"
                    input={({ name, value, onChange, id, error }) => (
                      <Input
                        id={id}
                        name={name}
                        type="number"
                        min={1}
                        max={3650}
                        value={(value as string) ?? ''}
                        onChange={onChange}
                        placeholder="180"
                        invalid={error}
                      />
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="retention.packagesDays"
                    label="Paketler (gün)"
                    input={({ name, value, onChange, id, error }) => (
                      <Input
                        id={id}
                        name={name}
                        type="number"
                        min={1}
                        max={3650}
                        value={(value as string) ?? ''}
                        onChange={onChange}
                        placeholder="365"
                        invalid={error}
                      />
                    )}
                  />
                </div>

                <div className="grid gap-4 md:grid-cols-2">
                  <FormField
                    control={form.control}
                    name="maintenance.dayOfWeek"
                    label="Bakım günü"
                    input={({ name, value, onChange, id, error }) => (
                      <Input
                        id={id}
                        name={name}
                        value={(value as string) ?? ''}
                        onChange={onChange}
                        placeholder="monday"
                        invalid={error}
                      />
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="maintenance.startTime"
                    label="Başlangıç saati"
                    input={({ name, value, onChange, id, error }) => (
                      <Input
                        id={id}
                        name={name}
                        type="time"
                        value={(value as string) ?? ''}
                        onChange={onChange}
                        invalid={error}
                      />
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="maintenance.durationMinutes"
                    label="Süre (dakika)"
                    input={({ name, value, onChange, id, error }) => (
                      <Input
                        id={id}
                        name={name}
                        type="number"
                        min={15}
                        max={1440}
                        step={15}
                        value={(value as string) ?? ''}
                        onChange={onChange}
                        placeholder="60"
                        invalid={error}
                      />
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="maintenance.timezone"
                    label="Saat dilimi"
                    input={({ name, value, onChange, id, error }) => (
                      <Input
                        id={id}
                        name={name}
                        value={(value as string) ?? ''}
                        onChange={onChange}
                        placeholder="Europe/Istanbul"
                        invalid={error}
                      />
                    )}
                  />
                </div>

                <div className="flex justify-end">
                  <Button type="submit" variant="primary" disabled={isSubmitDisabled}>
                    {isSaving ? 'Kaydediliyor…' : t('wizard.sign.cta')}
                  </Button>
                </div>
              </Form>
            </div>
          </RoleGate>
        </Tabs.Content>

        <Tabs.Content value="license">
          <div className="space-y-6">
            {licenseState.loading ? (
              <Skeleton className="h-32 w-full" />
            ) : licenseState.error ? (
              <Alert variant="error" title="Lisans" description={licenseState.error} />
            ) : licenseState.metadata ? (
              <div className="grid gap-4 md:grid-cols-2">
                <Card title="Fingerprint">
                  <code className="break-all text-xs text-[color:var(--fg-default)]">
                    {licenseState.metadata.fingerprint || '—'}
                  </code>
                </Card>
                <Card title="Bitiş">
                  <p className="text-sm text-[color:var(--fg-default)]">
                    {licenseState.metadata.expiresAt
                      ? new Date(licenseState.metadata.expiresAt).toLocaleString()
                      : 'Süre sonu tanımlı değil'}
                  </p>
                </Card>
                <Card title="Tenant">
                  <p className="text-sm text-[color:var(--fg-default)]">
                    {licenseState.metadata.tenantId || '—'}
                  </p>
                </Card>
                <Card title="Geçerlilik">
                  <Badge variant={licenseState.metadata.valid ? 'success' : 'danger'}>
                    {licenseState.metadata.valid ? 'Geçerli' : 'Geçersiz'}
                  </Badge>
                </Card>
              </div>
            ) : (
              <Alert variant="info" title="Lisans" description="Lisans verisi bulunamadı." />
            )}

            <div className="grid gap-4 md:grid-cols-2">
              <Card title="SBOM ayrıntıları">{renderSbomDetails()}</Card>
              <Card title="Attestasyon">{renderAttestationDetails()}</Card>
            </div>
          </div>
        </Tabs.Content>

        <Tabs.Content value="updates">
          <Card title={t('settings.updatePolicy')}>
            <Textarea rows={4} defaultValue="Yama penceresi her Çarşamba 02:00-04:00 arası uygulanır." />
            <div className="mt-4 flex justify-end">
              <RoleGate role="admin">
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => logEvent('Güncelleme politikası güncellendi')}
                >
                  {t('wizard.deploy.cta')}
                </Button>
              </RoleGate>
            </div>
          </Card>
        </Tabs.Content>
      </Tabs>
    </div>
  );
}
