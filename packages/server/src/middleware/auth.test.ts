import { createHash } from 'crypto';

import type { Request, Response } from 'express';

import {
  ApiKeyAuthorizer,
  ApiKeyDefinition,
  createApiKeyAuthorizer,
  createJwtPrincipalResolver,
  JwtUserLoader,
  JwtUserRecord,
  parseApiKeyList,
  UserRole,
} from './auth';
import { HttpError } from '../errors';

describe('ApiKeyAuthorizer', () => {
  const permissionMap: Partial<Record<UserRole, string[]>> = {
    admin: ['system:manage'],
    maintainer: ['jobs:write'],
    operator: ['jobs:execute'],
    reader: ['jobs:read'],
  };

  const createAuthorizer = (definitions: ApiKeyDefinition[] = []): ApiKeyAuthorizer =>
    new ApiKeyAuthorizer(definitions, { permissionMap });

  const createRequest = (key: string): Request =>
    ({
      get: jest.fn().mockReturnValue(key),
      path: '/jobs',
    } as unknown as Request);

  it('supports runtime API key registration and revocation', () => {
    const authorizer = createAuthorizer();
    const registered = authorizer.register({
      key: 'runtime-secret',
      roles: ['maintainer'],
      tenantId: 'tenant-a',
    });

    expect(registered.permissions).toEqual(['jobs:write']);
    expect(authorizer.authenticate('runtime-secret')).toMatchObject({
      tenantId: 'tenant-a',
      permissions: ['jobs:write'],
    });

    const fingerprint = registered.tokenHash;
    expect(authorizer.revoke(fingerprint)).toBe(true);
    expect(authorizer.authenticate('runtime-secret')).toBeUndefined();
  });

  it('enforces tenant scope and permissions during middleware execution', () => {
    const authorizer = createAuthorizer();
    authorizer.register({
      key: 'tenant-key',
      roles: ['maintainer'],
      tenantId: 'tenant-a',
    });

    const req = createRequest('tenant-key');
    const res = {} as Response;
    const next = jest.fn();

    authorizer.require({ tenant: 'tenant-a', permissions: ['jobs:write'] })(req, res, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(next.mock.calls[0]).toHaveLength(0);

    const errorNext = jest.fn();
    const wrongTenantReq = createRequest('tenant-key');
    authorizer.require({ tenant: 'tenant-b' })(wrongTenantReq, res, errorNext);
    expect(errorNext).toHaveBeenCalledWith(expect.any(HttpError));
    const tenantError = errorNext.mock.calls[0][0] as HttpError;
    expect(tenantError.statusCode).toBe(403);
    expect(tenantError.code).toBe('TENANT_MISMATCH');

    const permissionNext = jest.fn();
    const missingPermissionReq = createRequest('tenant-key');
    authorizer.require({ permissions: ['system:manage'] })(missingPermissionReq, res, permissionNext);
    expect(permissionNext).toHaveBeenCalledWith(expect.any(HttpError));
    const permissionError = permissionNext.mock.calls[0][0] as HttpError;
    expect(permissionError.statusCode).toBe(403);
    expect(permissionError.code).toBe('INSUFFICIENT_PERMISSION');
  });

  it('rejects expired API keys', () => {
    const authorizer = createAuthorizer();
    authorizer.register({
      key: 'expired-key',
      roles: ['reader'],
      tenantId: 'tenant-a',
      expiresAt: Date.now() - 1,
    });

    expect(authorizer.authenticate('expired-key')).toBeUndefined();
  });

  it('parses operator roles from CSV definitions', () => {
    const definitions = parseApiKeyList('operator-key:operator');

    expect(definitions).toHaveLength(1);
    expect(definitions[0]?.roles).toEqual(['operator']);
  });

  it('filters unknown roles from CSV definitions', () => {
    const definitions = parseApiKeyList('unknown-key:superuser');

    expect(definitions).toHaveLength(1);
    expect(definitions[0]?.roles).toEqual(['reader']);
  });

  it('produces operator principals from CSV configuration', () => {
    const authorizer = createApiKeyAuthorizer('operator-auth:operator');

    const principal = authorizer.authenticate('operator-auth');

    expect(principal?.roles).toEqual(['operator']);
  });

  it('omits unknown roles from CSV configuration', () => {
    const authorizer = createApiKeyAuthorizer('fallback-auth:superuser');

    const principal = authorizer.authenticate('fallback-auth');

    expect(principal?.roles).toEqual(['reader']);
  });
});

describe('createJwtPrincipalResolver', () => {
  const token = 'jwt-token';
  const context = { token, tenantId: 'tenant-a', subject: 'user-1' };
  const clock = () => new Date('2024-01-01T00:00:00Z');

  const createLoader = () => {
    const loadUser = jest.fn<Promise<JwtUserRecord | null>, [string, string]>();
    const loadRoles = jest.fn<Promise<UserRole[]>, [string, string]>();
    const loader: JwtUserLoader = {
      loadUser: async (tenantId, subject) => loadUser(tenantId, subject),
      loadRoles: async (tenantId, userId) => loadRoles(tenantId, userId),
    };
    return { loader, loadUser, loadRoles };
  };

  it('throws unauthorized when the user record cannot be located', async () => {
    const { loader, loadUser, loadRoles } = createLoader();
    loadUser.mockResolvedValue(null);
    const resolver = createJwtPrincipalResolver(loader, { clock });

    await expect(resolver(context)).rejects.toMatchObject({ statusCode: 401, code: 'USER_NOT_FOUND' });
    expect(loadRoles).not.toHaveBeenCalled();
  });

  it('rejects expired user sessions', async () => {
    const { loader, loadUser, loadRoles } = createLoader();
    loadUser.mockResolvedValue({
      id: 'user-1',
      tenantId: 'tenant-a',
      expiresAt: new Date('2023-12-31T23:59:00Z'),
      active: true,
    });
    loadRoles.mockResolvedValue(['reader']);

    const resolver = createJwtPrincipalResolver(loader, { clock });
    await expect(resolver(context)).rejects.toMatchObject({ statusCode: 401, code: 'TOKEN_EXPIRED' });
    expect(loadRoles).not.toHaveBeenCalled();
  });

  it('returns principal details with mapped permissions when the session is valid', async () => {
    const { loader, loadUser, loadRoles } = createLoader();
    loadUser.mockResolvedValue({
      id: 'user-1',
      tenantId: 'tenant-a',
      displayName: 'Alice',
      expiresAt: new Date('2024-01-01T00:01:00Z'),
      active: true,
    });
    loadRoles.mockResolvedValue(['admin', 'reader']);

    const resolver = createJwtPrincipalResolver(loader, {
      clock,
      permissionMap: { admin: ['system:manage'], reader: ['jobs:read'] },
    });
    const principal = await resolver(context);

    expect(principal.tenantId).toBe('tenant-a');
    expect(principal.userId).toBe('user-1');
    expect(principal.roles).toEqual(['admin', 'reader']);
    expect(principal.permissions).toEqual(['jobs:read', 'system:manage']);
    expect(principal.label).toBe('Alice');
    expect(principal.preview.length).toBeGreaterThan(0);

    const expectedHash = createHash('sha256').update(token, 'utf8').digest('hex');
    expect(principal.tokenHash).toBe(expectedHash);
  });
});
