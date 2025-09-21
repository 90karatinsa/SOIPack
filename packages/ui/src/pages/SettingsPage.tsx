import {
  Alert,
  Button,
  Card,
  DateTimePicker,
  Form,
  FormField,
  Input,
  PageHeader,
  Tabs,
  Textarea,
  useToast
} from '@bora/ui-kit';
import type { LicenseInfo } from '@soipack/ui-mocks';
import { useEffect, useState } from 'react';
import { useForm } from 'react-hook-form';

import { useAuditTrail } from '../providers/AuditTrailProvider';
import { useT } from '../providers/I18nProvider';
import { RoleGate } from '../providers/RbacProvider';
import { fetchDashboard, fetchLicense } from '../services/mockService';

interface SecurityFormValues {
  incidentEmail: string;
  retentionDays: number;
  maintenance: { iso: string; tz: string };
  maintenanceNotes: string;
}

export default function SettingsPage() {
  const t = useT();
  const { notify } = useToast();
  const { logEvent } = useAuditTrail();
  const [activeTab, setActiveTab] = useState('general');
  const [license, setLicense] = useState<LicenseInfo | null>(null);
  const [healthStatus, setHealthStatus] = useState('UP');
  const environment = import.meta.env.VITE_ENVIRONMENT ?? 'DEV';

  const form = useForm<SecurityFormValues>({
    defaultValues: {
      incidentEmail: 'soc@bora.def',
      retentionDays: 90,
      maintenance: { iso: new Date().toISOString(), tz: Intl.DateTimeFormat().resolvedOptions().timeZone },
      maintenanceNotes: ''
    }
  });

  useEffect(() => {
    void fetchLicense().then(setLicense);
    void fetchDashboard().then((data) => setHealthStatus(data.health.status));
  }, []);

  const handleSubmit = (values: SecurityFormValues) => {
    logEvent('Güvenlik ayarları güncellendi');
    notify({ title: t('notifications.success'), description: `${values.retentionDays} gün saklama` });
  };

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
            <Card title={t('dashboard.health')} description={t(`status.${healthStatus.toLowerCase()}`)} />
          </div>
        </Tabs.Content>

        <Tabs.Content value="security">
          <RoleGate role={['admin', 'operator']}>
            <Form form={form} onSubmit={handleSubmit}>
              <FormField
                control={form.control}
                name="incidentEmail"
                label="Olay e-posta"
                input={({ name, onChange, value, id, error }) => (
                  <Input
                    id={id}
                    name={name}
                    value={value as string}
                    onChange={onChange}
                    type="email"
                    required
                    invalid={error}
                  />
                )}
              />
              <FormField
                control={form.control}
                name="retentionDays"
                label="Saklama (gün)"
                input={({ name, onChange, value, id, error }) => (
                  <Input
                    id={id}
                    name={name}
                    value={String(value ?? '')}
                    onChange={(event) => onChange(Number(event.target.value))}
                    type="number"
                    min={30}
                    max={365}
                    invalid={error}
                  />
                )}
              />
              <FormField
                control={form.control}
                name="maintenance"
                label="Bakım penceresi"
                input={({ value, onChange }) => (
                  <DateTimePicker value={value as SecurityFormValues['maintenance']} onChange={onChange} />
                )}
              />
              <RoleGate role="admin">
                <FormField
                  control={form.control}
                  name="maintenanceNotes"
                  label="Notlar"
                  input={({ name, value, onChange, id, error }) => (
                    <Textarea
                      id={id}
                      name={name}
                      value={value as string}
                      onChange={onChange}
                      rows={3}
                      placeholder="Planlanan bakım adımları"
                      invalid={error}
                    />
                  )}
                />
              </RoleGate>
              <div className="flex justify-end">
                <Button type="submit" variant="primary">
                  {t('wizard.sign.cta')}
                </Button>
              </div>
            </Form>
          </RoleGate>
        </Tabs.Content>

        <Tabs.Content value="license">
          {license ? (
            <div className="grid gap-4 md:grid-cols-2">
              <Card title={t('settings.licenseSerial')} description={license.serial} />
              <Card title={t('settings.licenseExpiry')} description={new Date(license.expiresAt).toLocaleDateString()} />
              <Card title={t('settings.features')}>
                <ul className="space-y-2 text-sm text-[color:var(--fg-default)]">
                  {license.features.map((feature) => (
                    <li key={feature}>{feature}</li>
                  ))}
                </ul>
              </Card>
            </div>
          ) : (
            <Alert title="Lisans" description="Veri yükleniyor" variant="info" />
          )}
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
