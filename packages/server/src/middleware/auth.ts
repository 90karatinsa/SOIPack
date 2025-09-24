import { createHash } from 'crypto';

import type { NextFunction, Request, Response } from 'express';

import { HttpError } from '../errors';

export type UserRole = 'admin' | 'maintainer' | 'reader';

export interface ApiPrincipal {
  tokenHash: string;
  label?: string;
  roles: UserRole[];
  preview: string;
  tenantId?: string;
  permissions: string[];
  expiresAt?: Date | null;
  userId?: string;
}

interface ApiKeyRecord {
  fingerprint: string;
  label?: string;
  roles: Set<UserRole>;
  preview: string;
  tenantId?: string;
  permissions: Set<string>;
  expiresAt?: Date | null;
}

export interface ApiKeyDefinition {
  key: string;
  label?: string;
  roles: UserRole[];
  tenantId?: string;
  permissions?: string[];
  expiresAt?: Date | string | number | null;
}

const PRINCIPAL_SYMBOL = Symbol('soipack:api-principal');

const DEFAULT_ROLE: UserRole = 'reader';

const ROLE_MAP: Record<string, UserRole> = {
  admin: 'admin',
  maintainer: 'maintainer',
  reader: 'reader',
};

const normalizeList = (value: string | undefined): string[] =>
  (value ?? '')
    .split(/[,|+]/u)
    .map((entry) => entry.trim().toLowerCase())
    .filter((entry) => entry.length > 0);

const toPreview = (value: string): string => {
  const trimmed = value.trim();
  if (trimmed.length <= 8) {
    return trimmed;
  }
  const prefix = trimmed.slice(0, 4);
  const suffix = trimmed.slice(-4);
  return `${prefix}…${suffix}`;
};

const computeFingerprint = (value: string): string =>
  createHash('sha256').update(value, 'utf8').digest('hex');

const normalizePermissions = (permissions: string[] | undefined): string[] => {
  if (!permissions) {
    return [];
  }
  const unique = new Set<string>();
  permissions.forEach((permission) => {
    const trimmed = permission.trim();
    if (trimmed.length > 0) {
      unique.add(trimmed);
    }
  });
  return [...unique];
};

const toDateOrNull = (value: Date | string | number | null | undefined): Date | null | undefined => {
  if (value === undefined) {
    return undefined;
  }
  if (value === null) {
    return null;
  }
  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? undefined : value;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      return undefined;
    }
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? undefined : parsed;
  }
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed;
};

type PermissionMap = Partial<Record<UserRole, string[]>>;

const normalizePermissionMap = (map: PermissionMap | undefined): Map<UserRole, Set<string>> => {
  const result = new Map<UserRole, Set<string>>();
  if (!map) {
    return result;
  }
  (Object.keys(map) as UserRole[]).forEach((role) => {
    const permissions = map[role];
    if (permissions && permissions.length > 0) {
      result.set(role, new Set(normalizePermissions(permissions)));
    }
  });
  return result;
};

const parseDefinition = (raw: string): ApiKeyDefinition | null => {
  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    return null;
  }

  const [rawKeyPart, rawRolesPart] = trimmed.split(':', 2);
  if (!rawKeyPart) {
    return null;
  }

  const equalsIndex = rawKeyPart.indexOf('=');
  let label: string | undefined;
  let keyToken = rawKeyPart;
  if (equalsIndex >= 0) {
    label = rawKeyPart.slice(0, equalsIndex).trim();
    keyToken = rawKeyPart.slice(equalsIndex + 1);
  }

  const key = keyToken.trim();
  if (!key) {
    return null;
  }

  const rolesRaw = normalizeList(rawRolesPart);
  const roles = rolesRaw
    .map((role) => ROLE_MAP[role])
    .filter((role): role is UserRole => role !== undefined);

  return {
    key,
    label: label && label.length > 0 ? label : undefined,
    roles: roles.length > 0 ? roles : [DEFAULT_ROLE],
  };
};

export const parseApiKeyList = (csv: string | undefined): ApiKeyDefinition[] => {
  if (!csv) {
    return [];
  }

  return csv
    .split(',')
    .map((entry) => parseDefinition(entry))
    .filter((definition): definition is ApiKeyDefinition => definition !== null);
};

interface ApiKeyAuthorizerOptions {
  headerName?: string;
  excludedPaths?: Array<RegExp | string>;
  permissionMap?: PermissionMap;
}

const matchesExclusion = (path: string, patterns: Array<RegExp | string>): boolean =>
  patterns.some((pattern) =>
    pattern instanceof RegExp ? pattern.test(path) : path === pattern,
  );

export class ApiKeyAuthorizer {
  private readonly records = new Map<string, ApiKeyRecord>();

  private readonly headerName: string;

  private readonly excluded: Array<RegExp | string>;

  private readonly permissionMap: Map<UserRole, Set<string>>;

  constructor(definitions: ApiKeyDefinition[], options?: ApiKeyAuthorizerOptions) {
    this.headerName = options?.headerName ?? 'x-api-key';
    const defaultExcluded: Array<RegExp | string> = [/^\/health$/];
    this.excluded = options?.excludedPaths
      ? [...options.excludedPaths, ...defaultExcluded]
      : defaultExcluded;
    this.permissionMap = normalizePermissionMap(options?.permissionMap);

    definitions.forEach((definition) => {
      const record = this.createRecord(definition);
      this.records.set(record.fingerprint, record);
    });
  }

  public isEnabled(): boolean {
    return this.records.size > 0;
  }

  private computePermissions(roles: Set<UserRole>, extra: string[] = []): Set<string> {
    const permissions = new Set<string>();
    normalizePermissions(extra).forEach((permission) => permissions.add(permission));
    roles.forEach((role) => {
      const mapped = this.permissionMap.get(role);
      if (mapped) {
        mapped.forEach((permission) => permissions.add(permission));
      }
    });
    return permissions;
  }

  private createRecord(definition: ApiKeyDefinition): ApiKeyRecord {
    const fingerprint = computeFingerprint(definition.key);
    const preview = toPreview(definition.key);
    const roles = new Set<UserRole>(definition.roles);
    if (roles.size === 0) {
      roles.add(DEFAULT_ROLE);
    }
    const expiresAt = toDateOrNull(definition.expiresAt);
    const permissions = this.computePermissions(roles, definition.permissions);
    return {
      fingerprint,
      label: definition.label,
      roles,
      preview,
      tenantId: definition.tenantId,
      permissions,
      expiresAt,
    };
  }

  private toPrincipal(record: ApiKeyRecord): ApiPrincipal {
    const permissions = Array.from(record.permissions).sort();
    return {
      tokenHash: record.fingerprint,
      label: record.label,
      roles: Array.from(record.roles),
      preview: record.preview,
      tenantId: record.tenantId,
      permissions,
      expiresAt: record.expiresAt ?? undefined,
    };
  }

  private resolveFingerprint(keyOrFingerprint: string): string {
    const normalized = keyOrFingerprint.trim();
    if (/^[a-f0-9]{64}$/iu.test(normalized)) {
      return normalized.toLowerCase();
    }
    return computeFingerprint(normalized);
  }

  private lookup(key: string): ApiKeyRecord | undefined {
    const fingerprint = this.resolveFingerprint(key);
    return this.records.get(fingerprint);
  }

  private isExpired(record: ApiKeyRecord): boolean {
    if (!record.expiresAt) {
      return false;
    }
    return record.expiresAt.getTime() <= Date.now();
  }

  private extractKey(req: Request): string | undefined {
    const headerValue = req.get(this.headerName);
    if (headerValue && headerValue.trim().length > 0) {
      return headerValue.trim();
    }
    return undefined;
  }

  public authenticate(key: string): ApiPrincipal | undefined {
    const record = this.lookup(key);
    if (!record || this.isExpired(record)) {
      return undefined;
    }

    return this.toPrincipal(record);
  }

  public register(definition: ApiKeyDefinition): ApiPrincipal {
    const record = this.createRecord(definition);
    this.records.set(record.fingerprint, record);
    return this.toPrincipal(record);
  }

  public revoke(keyOrFingerprint: string): boolean {
    const fingerprint = this.resolveFingerprint(keyOrFingerprint);
    return this.records.delete(fingerprint);
  }

  public setPrincipal(req: Request, principal: ApiPrincipal): void {
    Reflect.set(req, PRINCIPAL_SYMBOL, principal);
  }

  public getPrincipal(req: Request): ApiPrincipal | undefined {
    return Reflect.get(req, PRINCIPAL_SYMBOL) as ApiPrincipal | undefined;
  }

  public require(
    requirements: UserRole[] | ApiKeyRequirement = [],
  ): (req: Request, res: Response, next: NextFunction) => void {
    const normalized = this.normalizeRequirements(requirements);
    return (req, _res, next) => {
      if (!this.isEnabled()) {
        next();
        return;
      }

      if (matchesExclusion(req.path, this.excluded)) {
        next();
        return;
      }

      const rawKey = this.extractKey(req);
      if (!rawKey) {
        next(new HttpError(401, 'UNAUTHORIZED', 'API anahtarı zorunludur.'));
        return;
      }

      const principal = this.authenticate(rawKey);
      if (!principal) {
        next(new HttpError(401, 'UNAUTHORIZED', 'API anahtarı doğrulanamadı.'));
        return;
      }

      this.setPrincipal(req, principal);

      if (normalized.roles.length > 0) {
        const allowed = normalized.roles.some((role) => principal.roles.includes(role));
        if (!allowed) {
          next(
            new HttpError(
              403,
              'FORBIDDEN',
              'Bu kaynak için gerekli role sahip değilsiniz.',
              { requiredRoles: normalized.roles },
            ),
          );
          return;
        }
      }

      if (normalized.tenant) {
        const expectedTenant =
          typeof normalized.tenant === 'function' ? normalized.tenant(req, principal) : normalized.tenant;
        if (expectedTenant && principal.tenantId && principal.tenantId !== expectedTenant) {
          next(
            new HttpError(
              403,
              'TENANT_MISMATCH',
              'Bu API anahtarı istenen tenant kapsamında yetkili değil.',
              { expectedTenant, actualTenant: principal.tenantId },
            ),
          );
          return;
        }
        if (expectedTenant && !principal.tenantId) {
          next(
            new HttpError(
              403,
              'TENANT_REQUIRED',
              'Bu işlem için tenant kapsamı zorunludur.',
              { expectedTenant },
            ),
          );
          return;
        }
      }

      if (normalized.permissions.length > 0) {
        const permissionSet = new Set(principal.permissions);
        const missing = normalized.permissions.filter((permission) => !permissionSet.has(permission));
        if (missing.length > 0) {
          next(
            new HttpError(
              403,
              'INSUFFICIENT_PERMISSION',
              'Bu kaynak için gerekli izinlere sahip değilsiniz.',
              { requiredPermissions: missing },
            ),
          );
          return;
        }
      }

      next();
    };
  }

  private normalizeRequirements(input: UserRole[] | ApiKeyRequirement): ApiKeyRequirementNormalized {
    if (Array.isArray(input)) {
      return { roles: input, permissions: [], tenant: undefined };
    }
    return {
      roles: input.roles ?? [],
      tenant: input.tenant,
      permissions: normalizePermissions(input.permissions),
    };
  }
}

export interface ApiKeyRequirement {
  roles?: UserRole[];
  tenant?: string | ((req: Request, principal: ApiPrincipal) => string | undefined);
  permissions?: string[];
}

interface ApiKeyRequirementNormalized {
  roles: UserRole[];
  tenant?: string | ((req: Request, principal: ApiPrincipal) => string | undefined);
  permissions: string[];
}

export const createApiKeyAuthorizer = (
  csv: string | undefined = process.env.SOIPACK_API_KEYS,
  options?: ApiKeyAuthorizerOptions,
): ApiKeyAuthorizer => {
  const definitions = parseApiKeyList(csv);
  return new ApiKeyAuthorizer(definitions, options);
};

export const getApiPrincipal = (req: Request): ApiPrincipal | undefined =>
  Reflect.get(req, PRINCIPAL_SYMBOL) as ApiPrincipal | undefined;

export interface JwtUserRecord {
  id: string;
  tenantId: string;
  displayName?: string | null;
  expiresAt?: Date | string | number | null;
  active?: boolean;
}

export interface JwtUserLoader {
  loadUser: (tenantId: string, subject: string) => Promise<JwtUserRecord | null | undefined>;
  loadRoles: (tenantId: string, userId: string) => Promise<UserRole[]>;
}

export interface JwtPrincipalContext {
  token: string;
  tenantId: string;
  subject: string;
}

export interface JwtPrincipalResolverOptions {
  permissionMap?: PermissionMap;
  clock?: () => Date;
}

export const createJwtPrincipalResolver = (
  loader: JwtUserLoader,
  options?: JwtPrincipalResolverOptions,
) => {
  const permissionMap = normalizePermissionMap(options?.permissionMap);
  const clock = options?.clock ?? (() => new Date());

  const computeJwtPermissions = (roles: UserRole[]): string[] => {
    const permissions = new Set<string>();
    roles.forEach((role) => {
      const mapped = permissionMap.get(role);
      if (mapped) {
        mapped.forEach((permission) => permissions.add(permission));
      }
    });
    return [...permissions].sort();
  };

  return async (context: JwtPrincipalContext): Promise<ApiPrincipal> => {
    const user = await loader.loadUser(context.tenantId, context.subject);
    if (!user) {
      throw new HttpError(401, 'USER_NOT_FOUND', 'Kullanıcı kaydı bulunamadı.');
    }

    if (user.active === false) {
      throw new HttpError(403, 'USER_DISABLED', 'Kullanıcı devre dışı bırakılmış.');
    }

    const expiresAt = toDateOrNull(user.expiresAt ?? undefined);
    if (expiresAt && expiresAt.getTime() <= clock().getTime()) {
      throw new HttpError(401, 'TOKEN_EXPIRED', 'Kullanıcı kimlik doğrulama süresi dolmuş.');
    }

    const roles = await loader.loadRoles(context.tenantId, user.id);
    const uniqueRoles = roles.length > 0 ? Array.from(new Set<UserRole>(roles)) : [DEFAULT_ROLE];
    const permissions = computeJwtPermissions(uniqueRoles);

    return {
      tokenHash: computeFingerprint(context.token),
      label: user.displayName ?? undefined,
      roles: uniqueRoles,
      preview: toPreview(context.token),
      tenantId: user.tenantId,
      permissions,
      expiresAt: expiresAt ?? undefined,
      userId: user.id,
    };
  };
};
