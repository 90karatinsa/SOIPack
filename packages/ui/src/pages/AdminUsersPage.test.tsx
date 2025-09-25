import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import AdminUsersPage from './AdminUsersPage';
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

jest.mock('../services/api', () => {
  const actual = jest.requireActual('../services/api');
  return {
    ...actual,
    listAdminRoles: jest.fn(),
    listAdminUsers: jest.fn(),
    createAdminUser: jest.fn(),
    updateAdminUser: jest.fn(),
    deleteAdminUser: jest.fn(),
  };
});

describe('AdminUsersPage', () => {
  const mockListRoles = listAdminRoles as jest.MockedFunction<typeof listAdminRoles>;
  const mockListUsers = listAdminUsers as jest.MockedFunction<typeof listAdminUsers>;
  const mockCreateUser = createAdminUser as jest.MockedFunction<typeof createAdminUser>;
  const mockUpdateUser = updateAdminUser as jest.MockedFunction<typeof updateAdminUser>;
  const mockDeleteUser = deleteAdminUser as jest.MockedFunction<typeof deleteAdminUser>;

  const baseRoles: AdminRole[] = [
    { name: 'admin', permissions: [], description: 'Tam yetki' },
    { name: 'operator', permissions: [], description: 'Güncelleme yetkisi' },
  ];

  const baseUsers: AdminUser[] = [
    {
      id: 'user-1',
      email: 'alice@example.com',
      displayName: 'Alice',
      roles: ['admin'],
      status: 'active',
    },
  ];

  beforeEach(() => {
    jest.clearAllMocks();
    mockListRoles.mockResolvedValue({ roles: baseRoles });
    mockListUsers.mockResolvedValue({ users: baseUsers });
  });

  it('renders users and supports create, edit and secret reset flows', async () => {
    mockCreateUser.mockResolvedValue({
      user: {
        id: 'user-2',
        email: 'bob@example.com',
        displayName: 'Bob',
        roles: ['operator'],
        status: 'invited',
      },
      secret: 'temporary-secret',
    });

    mockUpdateUser.mockResolvedValue({
      user: {
        ...baseUsers[0],
        displayName: 'Alice Updated',
        roles: ['operator'],
      },
    });

    mockDeleteUser.mockResolvedValue(undefined);

    render(<AdminUsersPage token="token" license="license" />);

    await waitFor(() => {
      expect(screen.getByText('alice@example.com')).toBeInTheDocument();
    });

    const table = screen.getByTestId('admin-users-table');
    expect(table).toBeInTheDocument();
    expect(table.textContent).toContain('Alice');

    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Yeni Kullanıcı' }));

    const emailInput = await screen.findByLabelText('E-posta');
    await user.type(emailInput, 'bob@example.com');
    const displayNameInput = screen.getByLabelText('Görünen ad');
    await user.type(displayNameInput, 'Bob');

    const roleSelect = screen.getByLabelText('Roller');
    await user.selectOptions(roleSelect, ['operator']);

    await user.click(screen.getByRole('button', { name: 'Kaydet' }));

    await waitFor(() => {
      expect(mockCreateUser).toHaveBeenCalledWith(
        expect.objectContaining({ email: 'bob@example.com', roles: ['operator'] }),
      );
    });

    await waitFor(() => {
      expect(screen.getByText('temporary-secret')).toBeInTheDocument();
      expect(screen.getByText('bob@example.com')).toBeInTheDocument();
    });

    const editButtons = screen.getAllByRole('button', { name: /Düzenle/ });
    await user.click(editButtons[0]);

    const updatedDisplayName = screen.getByLabelText('Görünen ad');
    fireEvent.change(updatedDisplayName, { target: { value: 'Alice Updated' } });
    const updatedRoles = screen.getByLabelText('Roller');
    await user.selectOptions(updatedRoles, ['operator']);

    mockUpdateUser.mockResolvedValueOnce({
      user: {
        ...baseUsers[0],
        displayName: 'Alice Updated',
        roles: ['operator'],
      },
    });

    await user.click(screen.getByRole('button', { name: 'Kaydet' }));

    await waitFor(() => {
      expect(mockUpdateUser).toHaveBeenCalledWith(
        expect.objectContaining({ userId: 'user-1', roles: ['operator'] }),
      );
    });

    await waitFor(() => {
      expect(screen.getAllByText('Alice Updated').length).toBeGreaterThan(0);
    });

    mockUpdateUser.mockResolvedValueOnce({
      user: {
        ...baseUsers[0],
        roles: ['admin'],
      },
      secret: 'rotated-secret',
    });

    await user.click(screen.getByRole('button', { name: 'Sır Sıfırla' }));

    await waitFor(() => {
      expect(mockUpdateUser).toHaveBeenCalledWith(
        expect.objectContaining({ userId: 'user-1', rotateSecret: true }),
      );
    });

    await waitFor(() => {
      expect(screen.getByText('rotated-secret')).toBeInTheDocument();
    });

    await user.click(screen.getByRole('button', { name: 'Sil' }));
    await waitFor(() => {
      expect(mockDeleteUser).toHaveBeenCalledWith(
        expect.objectContaining({ userId: 'user-1' }),
      );
    });
  });

  it('surfaces validation errors from the server', async () => {
    mockCreateUser.mockRejectedValue(new ApiError(422, 'ROLE_REQUIRED'));

    render(<AdminUsersPage token="token" license="license" />);

    await waitFor(() => {
      expect(screen.getByText('alice@example.com')).toBeInTheDocument();
    });

    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Yeni Kullanıcı' }));
    await user.type(await screen.findByLabelText('E-posta'), 'bob@example.com');
    await user.click(screen.getByRole('button', { name: 'Kaydet' }));

    await waitFor(() => {
      expect(screen.getByText('ROLE_REQUIRED')).toBeInTheDocument();
    });
  });
});
