import { Alert, Button, Input, PageHeader } from '@bora/ui-kit';
import { type FormEvent, useEffect, useMemo, useState } from 'react';

import {
  ApiError,
  createAdminUser,
  deleteAdminUser,
  listAdminRoles,
  listAdminUsers,
  updateAdminUser,
  type AdminRole,
  type AdminUser,
} from '../services/api';

interface AdminUsersPageProps {
  token?: string;
  license?: string;
}

interface AdminUserFormState {
  email: string;
  displayName: string;
  roles: string[];
}

const emptyForm: AdminUserFormState = { email: '', displayName: '', roles: [] };

export default function AdminUsersPage({ token = '', license = '' }: AdminUsersPageProps) {
  const trimmedToken = token.trim();
  const trimmedLicense = license.trim();
  const credentials = useMemo(() => ({ token: trimmedToken, license: trimmedLicense }), [trimmedToken, trimmedLicense]);

  const [roles, setRoles] = useState<AdminRole[]>([]);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [dialogMode, setDialogMode] = useState<'create' | 'edit' | null>(null);
  const [form, setForm] = useState<AdminUserFormState>(emptyForm);
  const [editingUserId, setEditingUserId] = useState<string | null>(null);
  const [secretNotice, setSecretNotice] = useState<{ type: 'success' | 'warning'; message: string } | null>(null);

  useEffect(() => {
    if (!trimmedToken || !trimmedLicense) {
      setRoles([]);
      setUsers([]);
      return;
    }

    const controller = new AbortController();
    setLoading(true);
    setError(null);

    const auth = { token: trimmedToken, license: trimmedLicense, signal: controller.signal } as const;

    Promise.all([listAdminRoles(auth), listAdminUsers(auth)])
      .then(([roleResponse, userResponse]) => {
        setRoles(roleResponse.roles);
        setUsers(userResponse.users);
      })
      .catch((err) => {
        if (!controller.signal.aborted) {
          setError(err instanceof ApiError ? err.message : 'Yönetici kullanıcıları yüklenemedi.');
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setLoading(false);
        }
      });

    return () => {
      controller.abort();
    };
  }, [trimmedToken, trimmedLicense]);

  const resetDialog = () => {
    setDialogMode(null);
    setForm(emptyForm);
    setEditingUserId(null);
    setSubmitError(null);
  };

  const handleOpenCreate = () => {
    setSecretNotice(null);
    setDialogMode('create');
    setForm(emptyForm);
    setEditingUserId(null);
  };

  const handleOpenEdit = (user: AdminUser) => {
    setSecretNotice(null);
    setDialogMode('edit');
    setEditingUserId(user.id);
    setForm({
      email: user.email,
      displayName: user.displayName ?? '',
      roles: user.roles ?? [],
    });
  };

  const handleFormChange = (field: keyof AdminUserFormState, value: string | string[]) => {
    setForm((previous) => ({
      ...previous,
      [field]: value,
    }));
  };

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!dialogMode || !trimmedToken || !trimmedLicense) {
      return;
    }
    setSubmitError(null);

    const payload = {
      token: credentials.token,
      license: credentials.license,
      email: form.email.trim(),
      roles: form.roles,
      displayName: form.displayName.trim() || null,
    } as const;

    try {
      if (dialogMode === 'create') {
        const response = await createAdminUser(payload);
        setUsers((prev) => [...prev.filter((user) => user.id !== response.user.id), response.user]);
        if (response.secret) {
          setSecretNotice({ type: 'success', message: `Yeni kullanıcı parolası: ${response.secret}` });
        }
      } else if (dialogMode === 'edit' && editingUserId) {
        const response = await updateAdminUser({ ...payload, userId: editingUserId });
        setUsers((prev) => prev.map((user) => (user.id === response.user.id ? response.user : user)));
        if (response.secret) {
          setSecretNotice({ type: 'success', message: `Yeni oturum sırrı: ${response.secret}` });
        }
      }
      resetDialog();
    } catch (err) {
      setSubmitError(err instanceof ApiError ? err.message : 'Kullanıcı kaydedilemedi.');
    }
  };

  const handleRotateSecret = async (user: AdminUser) => {
    if (!trimmedToken || !trimmedLicense) {
      return;
    }
    setSecretNotice(null);
    try {
      const response = await updateAdminUser({
        token: credentials.token,
        license: credentials.license,
        userId: user.id,
        email: user.email,
        roles: user.roles ?? [],
        rotateSecret: true,
      });
      setUsers((prev) => prev.map((entry) => (entry.id === response.user.id ? response.user : entry)));
      if (response.secret) {
        setSecretNotice({ type: 'success', message: `Yeni oturum sırrı: ${response.secret}` });
      }
    } catch (err) {
      setSecretNotice({
        type: 'warning',
        message: err instanceof ApiError ? err.message : 'Sır yeniden oluşturulamadı.',
      });
    }
  };

  const handleDelete = async (user: AdminUser) => {
    if (!trimmedToken || !trimmedLicense) {
      return;
    }
    await deleteAdminUser({ token: credentials.token, license: credentials.license, userId: user.id });
    setUsers((prev) => prev.filter((entry) => entry.id !== user.id));
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="RBAC Kullanıcı Yönetimi"
        description="Yönetici rollerini ve güvenlik bilgilerini güncelleyin."
        breadcrumb={[
          { label: 'Dashboard', href: '/' },
          { label: 'RBAC', href: '/admin' },
          { label: 'Kullanıcılar' },
        ]}
      />

      {error && <Alert variant="destructive" title="Yükleme başarısız" description={error} />}
      {secretNotice?.type === 'success' && (
        <Alert title="Güncelleme tamamlandı" description={secretNotice.message} />
      )}
      {secretNotice?.type === 'warning' && (
        <Alert variant="warning" title="Uyarı" description={secretNotice.message} />
      )}

      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-white">Kullanıcılar</h2>
        <Button onClick={handleOpenCreate} disabled={loading}>Yeni Kullanıcı</Button>
      </div>

      {loading ? (
        <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-6 text-center text-slate-300">Veriler yükleniyor…</div>
      ) : (
        <div className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-950/60">
          <table className="min-w-full divide-y divide-slate-800 text-left text-sm text-slate-200" data-testid="admin-users-table">
            <thead className="bg-slate-900/70 text-xs uppercase tracking-wide text-slate-400">
              <tr>
                <th className="px-4 py-3">E-posta</th>
                <th className="px-4 py-3">Görünen Ad</th>
                <th className="px-4 py-3">Roller</th>
                <th className="px-4 py-3">Durum</th>
                <th className="px-4 py-3 text-right">İşlemler</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {users.map((user) => (
                <tr key={user.id}>
                  <td className="px-4 py-3 font-mono text-slate-100">{user.email}</td>
                  <td className="px-4 py-3">{user.displayName ?? '—'}</td>
                  <td className="px-4 py-3">{(user.roles ?? []).join(', ') || '—'}</td>
                  <td className="px-4 py-3 capitalize">{user.status ?? 'unknown'}</td>
                  <td className="px-4 py-3 text-right space-x-2">
                    <Button size="sm" variant="ghost" onClick={() => handleOpenEdit(user)}>
                      Düzenle
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => handleRotateSecret(user)}>
                      Sır Sıfırla
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => handleDelete(user)}>
                      Sil
                    </Button>
                  </td>
                </tr>
              ))}
              {users.length === 0 && (
                <tr>
                  <td className="px-4 py-5 text-center text-slate-500" colSpan={5}>
                    Henüz tanımlı kullanıcı yok.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {dialogMode && (
        <div role="dialog" aria-modal="true" className="rounded-3xl border border-slate-800 bg-slate-900/90 p-6 shadow-xl">
          <h3 className="text-lg font-semibold text-white">
            {dialogMode === 'create' ? 'Yeni Kullanıcı Oluştur' : 'Kullanıcıyı Düzenle'}
          </h3>
          <form className="mt-4 space-y-4" onSubmit={handleSubmit}>
            <label className="block text-sm text-slate-300">
              <span className="mb-1 block font-medium">E-posta</span>
              <Input
                value={form.email}
                onChange={(event) => handleFormChange('email', event.target.value)}
                required
                type="email"
              />
            </label>
            <label className="block text-sm text-slate-300">
              <span className="mb-1 block font-medium">Görünen ad</span>
              <Input value={form.displayName} onChange={(event) => handleFormChange('displayName', event.target.value)} />
            </label>
            <label className="block text-sm text-slate-300">
              <span className="mb-1 block font-medium">Roller</span>
              <select
                multiple
                className="w-full rounded-xl border border-slate-700 bg-slate-950/70 p-2"
                value={form.roles}
                onChange={(event) => {
                  const selected = Array.from(event.target.selectedOptions).map((option) => option.value);
                  handleFormChange('roles', selected);
                }}
              >
                {roles.map((role) => (
                  <option key={role.name} value={role.name}>
                    {role.name}
                  </option>
                ))}
              </select>
            </label>

            {submitError && <Alert variant="destructive" title="Kaydedilemedi" description={submitError} />}

            <div className="flex items-center justify-end gap-2">
              <Button type="button" variant="ghost" onClick={resetDialog}>
                Vazgeç
              </Button>
              <Button type="submit">Kaydet</Button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
