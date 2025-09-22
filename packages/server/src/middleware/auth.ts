import { createHash } from 'crypto';

import type { NextFunction, Request, Response } from 'express';

import { HttpError } from '../errors';

export type UserRole = 'admin' | 'maintainer' | 'reader';

export interface ApiPrincipal {
  tokenHash: string;
  label?: string;
  roles: UserRole[];
  preview: string;
}

interface ApiKeyRecord {
  fingerprint: string;
  label?: string;
  roles: Set<UserRole>;
  preview: string;
}

export interface ApiKeyDefinition {
  key: string;
  label?: string;
  roles: UserRole[];
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
}

const matchesExclusion = (path: string, patterns: Array<RegExp | string>): boolean =>
  patterns.some((pattern) =>
    pattern instanceof RegExp ? pattern.test(path) : path === pattern,
  );

export class ApiKeyAuthorizer {
  private readonly records = new Map<string, ApiKeyRecord>();

  private readonly headerName: string;

  private readonly excluded: Array<RegExp | string>;

  constructor(definitions: ApiKeyDefinition[], options?: ApiKeyAuthorizerOptions) {
    this.headerName = options?.headerName ?? 'x-api-key';
    const defaultExcluded: Array<RegExp | string> = [/^\/health$/];
    this.excluded = options?.excludedPaths
      ? [...options.excludedPaths, ...defaultExcluded]
      : defaultExcluded;

    definitions.forEach((definition) => {
      const fingerprint = computeFingerprint(definition.key);
      const preview = toPreview(definition.key);
      const roles = new Set<UserRole>(definition.roles);
      this.records.set(fingerprint, { fingerprint, label: definition.label, roles, preview });
    });
  }

  public isEnabled(): boolean {
    return this.records.size > 0;
  }

  private lookup(key: string): ApiKeyRecord | undefined {
    const fingerprint = computeFingerprint(key);
    return this.records.get(fingerprint);
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
    if (!record) {
      return undefined;
    }

    return {
      tokenHash: record.fingerprint,
      label: record.label,
      roles: Array.from(record.roles),
      preview: record.preview,
    };
  }

  public setPrincipal(req: Request, principal: ApiPrincipal): void {
    Reflect.set(req, PRINCIPAL_SYMBOL, principal);
  }

  public getPrincipal(req: Request): ApiPrincipal | undefined {
    return Reflect.get(req, PRINCIPAL_SYMBOL) as ApiPrincipal | undefined;
  }

  public require(roles: UserRole[] = []): (req: Request, res: Response, next: NextFunction) => void {
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

      if (roles.length > 0) {
        const allowed = roles.some((role) => principal.roles.includes(role));
        if (!allowed) {
          next(
            new HttpError(
              403,
              'FORBIDDEN',
              'Bu kaynak için gerekli role sahip değilsiniz.',
              { requiredRoles: roles },
            ),
          );
          return;
        }
      }

      next();
    };
  }
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
