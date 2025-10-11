import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import SettingsPage from './SettingsPage';
import { I18nProvider } from '../providers/I18nProvider';
import { RbacProvider } from '../providers/RbacProvider';
import {
  ApiError,
  getAdminSecurity,
  getLicense,
  getServiceMetadata,
  putAdminSecurity,
  type AdminSecuritySettings,
  type LicenseMetadata,
  type ServiceMetadata,
} from '../services/api';

const notifyMock = jest.fn();
const logEventMock = jest.fn();

jest.mock('../providers/AuditTrailProvider', () => ({
  useAuditTrail: () => ({ logEvent: logEventMock }),
}), { virtual: true });

jest.mock('../services/api', () => {
  const actual = jest.requireActual('../services/api');
  return {
    ...actual,
    getServiceMetadata: jest.fn(),
    getLicense: jest.fn(),
    getAdminSecurity: jest.fn(),
    putAdminSecurity: jest.fn(),
  };
});

jest.mock('@bora/ui-kit', () => {
  const actual = jest.requireActual('@bora/ui-kit');
  return {
    ...actual,
    useToast: () => ({ notify: notifyMock }),
  };
});

const mockGetServiceMetadata = getServiceMetadata as jest.MockedFunction<typeof getServiceMetadata>;
const mockGetLicense = getLicense as jest.MockedFunction<typeof getLicense>;
const mockGetAdminSecurity = getAdminSecurity as jest.MockedFunction<typeof getAdminSecurity>;
const mockPutAdminSecurity = putAdminSecurity as jest.MockedFunction<typeof putAdminSecurity>;

const renderSettings = () =>
  render(
    <I18nProvider>
      <RbacProvider roles={['admin', 'operator']}>
        <SettingsPage token="demo-token" license="demo-license" />
      </RbacProvider>
    </I18nProvider>,
  );

const baseServiceMetadata: ServiceMetadata = {
  sbom: {
    url: 'https://cdn.example.com/artifacts/sbom.spdx.json',
    sha256: 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789',
    verified: true,
  },
  attestation: {
    present: true,
    signals: { provenance: 'in-toto', integrity: 'verified' },
  },
  packJob: {
    id: 'pack-job-42',
    createdAt: '2024-03-01T10:00:00.000Z',
  },
};

const baseLicense: LicenseMetadata = {
  fingerprint: 'license-fp-123',
  expiresAt: '2025-01-15T00:00:00.000Z',
  tenantId: 'tenant-main',
  valid: true,
};

type SecurityRuleOverride = Partial<AdminSecuritySettings['rules'][number]>;

const buildSecuritySettings = (
  revision: string,
  overrides: SecurityRuleOverride[] = [],
): AdminSecuritySettings => {
  const baseRules: AdminSecuritySettings['rules'] = [
    {
      type: 'incidentContact',
      config: { name: 'Alice Example', email: 'alice@example.com', phone: '+90 555 000 0000' },
    },
    {
      type: 'retention',
      config: { uploadsDays: 30, analysesDays: 60, reportsDays: 90, packagesDays: 120 },
    },
    {
      type: 'maintenance',
      config: { dayOfWeek: 'monday', startTime: '09:00', durationMinutes: 60, timezone: 'Europe/Istanbul' },
    },
  ];

  const rules = baseRules.map((rule, index) => {
    const override = overrides[index];
    if (!override) {
      return rule;
    }
    const nextConfig = {
      ...(rule as { config: Record<string, unknown> }).config,
      ...(override.config as Record<string, unknown> | undefined),
    };
    return { ...rule, ...override, config: nextConfig } as AdminSecuritySettings['rules'][number];
  });

  return { rules, revision };
};

beforeEach(() => {
  jest.clearAllMocks();
  notifyMock.mockReset();
  logEventMock.mockReset();
});

describe('SettingsPage', () => {
  it('renders metadata, license details, and security rules when load succeeds', async () => {
    mockGetServiceMetadata.mockResolvedValue(baseServiceMetadata);
    mockGetLicense.mockResolvedValue(baseLicense);
    mockGetAdminSecurity.mockResolvedValue({
      settings: buildSecuritySettings('rev-1'),
      etag: '"rev-1"',
      lastModified: 'Wed, 01 Mar 2024 10:00:00 GMT',
    });

    renderSettings();

    await waitFor(() => {
      expect(mockGetAdminSecurity).toHaveBeenCalled();
    });

    expect(screen.getByText('pack-job-42')).toBeInTheDocument();
    expect(screen.getByText('https://cdn.example.com/artifacts/sbom.spdx.json')).toHaveAttribute(
      'href',
      'https://cdn.example.com/artifacts/sbom.spdx.json',
    );
    expect(screen.getByText(baseServiceMetadata.sbom!.sha256!)).toBeInTheDocument();
    expect(screen.getByText('Doğrulandı')).toBeInTheDocument();
    expect(screen.getByText('license-fp-123')).toBeInTheDocument();
    expect(screen.getByText('tenant-main')).toBeInTheDocument();
    expect(screen.getByText('Güncel güvenlik kuralları')).toBeInTheDocument();
    expect(screen.getByText('rev-1')).toBeInTheDocument();

    expect(await screen.findByDisplayValue('Alice Example')).toHaveAttribute('name', 'incidentContact.name');
    expect(screen.getByDisplayValue('alice@example.com')).toHaveAttribute('name', 'incidentContact.email');
    expect(screen.getByDisplayValue('30')).toHaveAttribute('name', 'retention.uploadsDays');
    expect(screen.getByDisplayValue('09:00')).toHaveAttribute('name', 'maintenance.startTime');
    expect(screen.getByDisplayValue('Europe/Istanbul')).toHaveAttribute('name', 'maintenance.timezone');
  });

  it('surfaces error states when metadata or security settings fail to load', async () => {
    mockGetServiceMetadata.mockRejectedValue(new ApiError(500, 'Service down'));
    mockGetLicense.mockResolvedValue(baseLicense);
    mockGetAdminSecurity.mockRejectedValue(new ApiError(500, 'Security kaput'));

    renderSettings();

    expect(await screen.findByText('Service down')).toBeInTheDocument();
    expect(screen.getAllByTestId('alert')).not.toHaveLength(0);
    expect(screen.getByText('Security kaput')).toBeInTheDocument();
  });

  it('submits security settings successfully and shows a success toast', async () => {
    mockGetServiceMetadata.mockResolvedValue(baseServiceMetadata);
    mockGetLicense.mockResolvedValue(baseLicense);
    mockGetAdminSecurity.mockResolvedValue({
      settings: buildSecuritySettings('rev-7'),
      etag: '"rev-7"',
      lastModified: 'Wed, 01 Mar 2024 10:00:00 GMT',
    });

    mockPutAdminSecurity.mockResolvedValue({
      settings: buildSecuritySettings('rev-8', [
        { config: { name: 'Bob Example' } },
        undefined,
        { config: { durationMinutes: 90 } },
      ]),
      etag: '"rev-8"',
      lastModified: 'Wed, 01 Mar 2024 11:00:00 GMT',
    });

    const user = userEvent.setup();
    renderSettings();

    await waitFor(() => {
      expect(mockGetAdminSecurity).toHaveBeenCalled();
    });

    const nameInput = await screen.findByDisplayValue('Alice Example');
    await user.clear(nameInput);
    await user.type(nameInput, 'Bob Example');

    const submitButton = screen.getByRole('button', { name: 'Save Settings' });
    await user.click(submitButton);

    await waitFor(() => {
      expect(mockPutAdminSecurity).toHaveBeenCalledWith(
        expect.objectContaining({ rules: expect.any(Array) }),
        expect.objectContaining({ ifMatch: '"rev-7"' }),
      );
    });

    await waitFor(() => {
      expect(notifyMock).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Success', description: 'Revizyon rev-8 kaydedildi.' }),
      );
    });

    expect(logEventMock).toHaveBeenCalledWith('Güvenlik ayarları güncellendi');
    expect(screen.getByText('rev-8')).toBeInTheDocument();
    expect(screen.getByDisplayValue('Bob Example')).toBeInTheDocument();
  });

  it('reloads settings after a revision conflict and succeeds on retry', async () => {
    mockGetServiceMetadata.mockResolvedValue(baseServiceMetadata);
    mockGetLicense.mockResolvedValue(baseLicense);
    mockGetAdminSecurity
      .mockResolvedValueOnce({
        settings: buildSecuritySettings('rev-1'),
        etag: '"rev-1"',
        lastModified: 'Wed, 01 Mar 2024 10:00:00 GMT',
      })
      .mockResolvedValueOnce({
        settings: buildSecuritySettings('rev-2', [
          { config: { name: 'Carol Example' } },
          undefined,
          undefined,
        ]),
        etag: '"rev-2"',
        lastModified: 'Wed, 01 Mar 2024 11:00:00 GMT',
      });

    mockPutAdminSecurity
      .mockRejectedValueOnce(new ApiError(409, 'Revision conflict', undefined, { currentRevision: 'rev-2' }))
      .mockResolvedValueOnce({
        settings: buildSecuritySettings('rev-3', [
          { config: { name: 'Carol Example' } },
          undefined,
          undefined,
        ]),
        etag: '"rev-3"',
        lastModified: 'Wed, 01 Mar 2024 12:00:00 GMT',
      });

    const user = userEvent.setup();
    renderSettings();

    await waitFor(() => {
      expect(mockGetAdminSecurity).toHaveBeenCalledTimes(1);
    });

    const nameInput = await screen.findByDisplayValue('Alice Example');
    await user.clear(nameInput);
    await user.type(nameInput, 'Carol Example');

    const submitButton = screen.getByRole('button', { name: 'Save Settings' });
    await user.click(submitButton);

    await waitFor(() => {
      expect(mockPutAdminSecurity).toHaveBeenCalledTimes(1);
    });

    await waitFor(() => {
      expect(notifyMock).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'Failure',
          description: expect.stringContaining('En son veriler yükleniyor.'),
        }),
      );
    });

    await waitFor(() => {
      expect(mockGetAdminSecurity).toHaveBeenCalledTimes(2);
    });

    expect(screen.getByDisplayValue('Carol Example')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Save Settings' }));

    await waitFor(() => {
      expect(mockPutAdminSecurity).toHaveBeenCalledTimes(2);
    });

    await waitFor(() => {
      expect(notifyMock).toHaveBeenCalledWith(
        expect.objectContaining({ description: 'Revizyon rev-3 kaydedildi.' }),
      );
    });

    expect(screen.getByText('rev-3')).toBeInTheDocument();
  });

  it.each([
    { status: 400, error: new ApiError(400, ''), expected: 'Gönderilen güvenlik ayarları doğrulamadan geçmedi.' },
    { status: 403, error: new ApiError(403, ''), expected: 'Bu işlemi gerçekleştirmek için yetkiniz yok.' },
    { status: 500, error: new ApiError(500, 'Server exploded'), expected: 'Server exploded' },
  ])('shows a failure toast when saving fails with status $status', async ({ error, expected }) => {
    mockGetServiceMetadata.mockResolvedValue(baseServiceMetadata);
    mockGetLicense.mockResolvedValue(baseLicense);
    mockGetAdminSecurity.mockResolvedValue({
      settings: buildSecuritySettings('rev-9'),
      etag: '"rev-9"',
      lastModified: 'Wed, 01 Mar 2024 10:00:00 GMT',
    });

    mockPutAdminSecurity.mockRejectedValueOnce(error);

    const user = userEvent.setup();
    renderSettings();

    await waitFor(() => {
      expect(mockGetAdminSecurity).toHaveBeenCalled();
    });

    await user.click(screen.getByRole('button', { name: 'Save Settings' }));

    await waitFor(() => {
      expect(notifyMock).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failure', description: expect.stringContaining(expected) }),
      );
    });
  });
});
