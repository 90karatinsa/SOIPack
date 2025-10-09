import { createHash } from 'crypto';

import { z, ZodError } from 'zod';

import { HttpError } from './errors';

const SECRET_REDACTION_KEYS = new Set(
  [
    'password',
    'token',
    'apiToken',
    'clientSecret',
    'authorization',
    'secret',
    'privateKey',
    'personalAccessToken',
  ].map((key) => key.toLowerCase()),
);

const redactSecrets = <T>(input: T): T => {
  if (Array.isArray(input)) {
    return input.map((entry) => redactSecrets(entry)) as unknown as T;
  }

  if (!input || typeof input !== 'object') {
    return input;
  }

  if (input instanceof Date || input instanceof RegExp || input instanceof URL) {
    return input;
  }

  if (Buffer.isBuffer(input)) {
    return input;
  }

  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
    if (SECRET_REDACTION_KEYS.has(key.toLowerCase())) {
      result[key] = 'REDACTED';
      continue;
    }
    result[key] = redactSecrets(value);
  }

  return result as unknown as T;
};

const stripSecrets = <T>(input: T): T => {
  if (Array.isArray(input)) {
    return input.map((entry) => stripSecrets(entry)) as unknown as T;
  }

  if (!input || typeof input !== 'object') {
    return input;
  }

  if (input instanceof Date || input instanceof RegExp || input instanceof URL) {
    return input;
  }

  if (Buffer.isBuffer(input)) {
    return input;
  }

  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
    if (SECRET_REDACTION_KEYS.has(key.toLowerCase())) {
      continue;
    }
    result[key] = stripSecrets(value);
  }

  return result as unknown as T;
};

const toStableJson = (value: unknown): string => {
  const normalize = (input: unknown): unknown => {
    if (Array.isArray(input)) {
      return input.map((item) => normalize(item));
    }
    if (input && typeof input === 'object') {
      return Object.keys(input as Record<string, unknown>)
        .sort()
        .reduce<Record<string, unknown>>((acc, key) => {
          acc[key] = normalize((input as Record<string, unknown>)[key]);
          return acc;
        }, {});
    }
    return input;
  };

  return JSON.stringify(normalize(value));
};

const createRequiredString = (field: string): z.ZodString =>
  z
    .string({ required_error: `${field} alanı zorunludur.` })
    .trim()
    .min(1, `${field} alanı zorunludur.`);

const createOptionalString = (field: string): z.ZodString =>
  z
    .string()
    .trim()
    .min(1, `${field} alanı boş bırakılamaz.`);

const isValidUrl = (value: string): boolean => {
  try {
    // eslint-disable-next-line no-new
    new URL(value);
    return true;
  } catch {
    return false;
  }
};

const normalizeUrlString = (value: string): string => {
  const url = new URL(value);
  url.hash = '';
  url.searchParams.sort();
  return url.toString();
};

const createRequiredUrlString = (field: string): z.ZodEffects<z.ZodString, string, string> =>
  createRequiredString(field)
    .refine((value) => isValidUrl(value), `${field} alanı geçerli bir URL olmalıdır.`)
    .transform((value) => normalizeUrlString(value));

const createOptionalUrlString = (field: string): z.ZodEffects<z.ZodString, string, string> =>
  createOptionalString(field)
    .refine((value) => isValidUrl(value), `${field} alanı geçerli bir URL olmalıdır.`)
    .transform((value) => normalizeUrlString(value));

const createOptionalPositiveInteger = (
  field: string,
  { allowZero = false }: { allowZero?: boolean } = {},
): z.ZodOptional<z.ZodNumber> =>
  z
    .preprocess((value) => {
      if (value === undefined) {
        return undefined;
      }
      if (value === null) {
        return null;
      }
      if (typeof value === 'string') {
        const trimmed = value.trim();
        if (!trimmed) {
          return undefined;
        }
        const parsed = Number(trimmed);
        if (!Number.isFinite(parsed)) {
          return NaN;
        }
        return parsed;
      }
      return value;
    },
    z
      .number({ invalid_type_error: `${field} alanı sayı olmalıdır.` })
      .int(`${field} alanı tam sayı olmalıdır.`)
      .refine((value) => (allowZero ? value >= 0 : value > 0), `${field} alanı pozitif olmalıdır.`))
    .optional();

const polarionConnectorOptionsSchema = z.object({
    baseUrl: createRequiredUrlString('baseUrl'),
    projectId: createOptionalString('projectId').optional(),
    project: createOptionalString('project').optional(),
    username: createRequiredString('username'),
    password: createOptionalString('password').optional(),
    token: createOptionalString('token').optional(),
  }).superRefine((value, ctx) => {
    if (!value.projectId && !value.project) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'projectId veya project alanı zorunludur.',
        path: ['projectId'],
      });
    }
    if (!value.password && !value.token) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'password veya token alanlarından biri sağlanmalıdır.',
        path: ['password'],
      });
    }
  });

const jenkinsConnectorOptionsSchema = z.object({
    baseUrl: createRequiredUrlString('baseUrl'),
    job: createRequiredString('job'),
    username: createRequiredString('username'),
    apiToken: createOptionalString('apiToken').optional(),
    token: createOptionalString('token').optional(),
    password: createOptionalString('password').optional(),
  }).superRefine((value, ctx) => {
    if (!value.apiToken && !value.token) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'apiToken veya token alanı sağlanmalıdır.',
        path: ['apiToken'],
      });
    }
  });

const doorsNextOAuthSchema = z.object({
    tokenUrl: createRequiredUrlString('oauth.tokenUrl'),
    clientId: createRequiredString('oauth.clientId'),
    clientSecret: createRequiredString('oauth.clientSecret'),
    scope: createOptionalString('oauth.scope').optional(),
  });

const doorsNextConnectorOptionsSchema = z.object({
    baseUrl: createRequiredUrlString('baseUrl'),
    project: createOptionalString('project').optional(),
    projectArea: createOptionalString('projectArea').optional(),
    username: createOptionalString('username').optional(),
    password: createOptionalString('password').optional(),
    accessToken: createOptionalString('accessToken').optional(),
    oauth: doorsNextOAuthSchema.optional(),
  }).superRefine((value, ctx) => {
    if (!value.project && !value.projectArea) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'project veya projectArea alanı zorunludur.',
        path: ['project'],
      });
    }

    const hasUsername = Boolean(value.username);
    const hasPassword = Boolean(value.password);
    if (hasUsername !== hasPassword) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'username ve password alanları birlikte sağlanmalıdır.',
        path: hasUsername ? ['password'] : ['username'],
      });
    }

    const hasAccessToken = Boolean(value.accessToken);
    const hasOauth = Boolean(value.oauth);
    const hasBasicAuth = hasUsername && hasPassword;

    if (!hasBasicAuth && !hasAccessToken && !hasOauth) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'username/password, accessToken veya oauth bilgileri sağlanmalıdır.',
        path: ['username'],
      });
    }
  });

const jamaConnectorOptionsSchema = z.object({
    baseUrl: createRequiredUrlString('baseUrl'),
    project: createOptionalString('project').optional(),
    projectId: createOptionalString('projectId').optional(),
    clientId: createOptionalString('clientId').optional(),
    clientSecret: createOptionalString('clientSecret').optional(),
    apiToken: createOptionalString('apiToken').optional(),
  }).superRefine((value, ctx) => {
    const hasClientId = Boolean(value.clientId);
    const hasClientSecret = Boolean(value.clientSecret);
    if (hasClientId !== hasClientSecret) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'clientId ve clientSecret alanları birlikte sağlanmalıdır.',
        path: hasClientId ? ['clientSecret'] : ['clientId'],
      });
    }

    const hasToken = Boolean(value.apiToken);
    const hasClientCredentials = hasClientId && hasClientSecret;

    if (!hasToken && !hasClientCredentials) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'apiToken ya da clientId/clientSecret bilgileri sağlanmalıdır.',
        path: ['apiToken'],
      });
    }
  });

const jiraCloudConnectorOptionsSchema = z.object({
    site: createRequiredString('site'),
    email: createRequiredString('email'),
    apiToken: createRequiredString('apiToken'),
    projectKey: createRequiredString('projectKey'),
    baseUrl: createOptionalUrlString('baseUrl').optional(),
  });

const azureDevOpsConnectorOptionsSchema = z.object({
    baseUrl: createRequiredUrlString('baseUrl'),
    organization: createRequiredString('organization'),
    project: createRequiredString('project'),
    personalAccessToken: createRequiredString('personalAccessToken'),
    requirementsEndpoint: createOptionalUrlString('requirementsEndpoint').optional(),
    testsEndpoint: createOptionalUrlString('testsEndpoint').optional(),
    buildsEndpoint: createOptionalUrlString('buildsEndpoint').optional(),
    attachmentsEndpoint: createOptionalUrlString('attachmentsEndpoint').optional(),
    timeoutMs: createOptionalPositiveInteger('timeoutMs'),
    pageSize: createOptionalPositiveInteger('pageSize'),
    maxPages: createOptionalPositiveInteger('maxPages'),
    apiVersion: createOptionalString('apiVersion').optional(),
    rateLimitDelaysMs: z
      .preprocess((value) => {
        if (value === undefined || value === null) {
          return undefined;
        }
        if (Array.isArray(value)) {
          return value;
        }
        return [value];
      },
      z
        .array(
          z
            .preprocess((entry) => {
              if (typeof entry === 'string') {
                const trimmed = entry.trim();
                if (!trimmed) {
                  return NaN;
                }
                const parsed = Number(trimmed);
                if (!Number.isFinite(parsed)) {
                  return NaN;
                }
                return parsed;
              }
              return entry;
            },
            z
              .number({ invalid_type_error: 'rateLimitDelaysMs değerleri sayı olmalıdır.' })
              .int('rateLimitDelaysMs değerleri tam sayı olmalıdır.')
              .min(0, 'rateLimitDelaysMs değerleri negatif olamaz.'),
          ),
        )
        .min(1, 'rateLimitDelaysMs en az bir değer içermelidir.'))
      .optional(),
    maxAttachmentBytes: createOptionalPositiveInteger('maxAttachmentBytes'),
    requirementsQuery: createOptionalString('requirementsQuery').optional(),
    testOutcomeFilter: createOptionalString('testOutcomeFilter').optional(),
    testPlanId: createOptionalString('testPlanId').optional(),
    testSuiteId: createOptionalString('testSuiteId').optional(),
    testRunId: createOptionalString('testRunId').optional(),
    buildDefinitionId: createOptionalString('buildDefinitionId').optional(),
  });

const connectorOptionSchemas = {
  polarion: polarionConnectorOptionsSchema,
  jenkins: jenkinsConnectorOptionsSchema,
  doorsNext: doorsNextConnectorOptionsSchema,
  jama: jamaConnectorOptionsSchema,
  jiraCloud: jiraCloudConnectorOptionsSchema,
  azureDevOps: azureDevOpsConnectorOptionsSchema,
} as const;

type ConnectorType = keyof typeof connectorOptionSchemas;

type ConnectorOptionsMap = {
  [K in ConnectorType]: z.infer<(typeof connectorOptionSchemas)[K]>;
};

type ConnectorConfig = {
  [K in ConnectorType]: { type: K; options: ConnectorOptionsMap[K]; fingerprint: string };
}[ConnectorType];

type ConnectorMetadata = {
  [K in ConnectorType]: { type: K; metadata: ConnectorOptionsMap[K] };
}[ConnectorType];

const normalizeConnectorValue = (value: unknown): unknown => {
  if (Array.isArray(value)) {
    if (value.length === 0) {
      throw new HttpError(400, 'INVALID_CONNECTOR_REQUEST', 'connector alanı boş olamaz.');
    }
    return normalizeConnectorValue(value[0]);
  }

  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) {
      throw new HttpError(400, 'INVALID_CONNECTOR_REQUEST', 'connector alanı boş olamaz.');
    }
    try {
      return JSON.parse(trimmed);
    } catch (error) {
      throw new HttpError(400, 'INVALID_CONNECTOR_REQUEST', 'connector alanı geçerli JSON içermelidir.');
    }
  }

  if (!value || typeof value !== 'object') {
    throw new HttpError(400, 'INVALID_CONNECTOR_REQUEST', 'connector alanı geçerli JSON içermelidir.');
  }

  return value;
};

const parseConnectorPayload = (value: unknown): ConnectorConfig => {
  const normalized = normalizeConnectorValue(value);
  const container = normalized as Record<string, unknown>;

  const rawType = container.type;
  if (typeof rawType !== 'string') {
    throw new HttpError(400, 'INVALID_CONNECTOR_REQUEST', 'type alanı zorunludur.');
  }

  const normalizedType = rawType.trim();
  if (normalizedType.length === 0) {
    throw new HttpError(400, 'INVALID_CONNECTOR_REQUEST', 'type alanı zorunludur.');
  }

  const type = normalizedType as ConnectorType;
  const schema = connectorOptionSchemas[type];
  if (!schema) {
    throw new HttpError(400, 'INVALID_CONNECTOR_REQUEST', 'Desteklenmeyen bağlayıcı türü.');
  }

  if (!Object.prototype.hasOwnProperty.call(container, 'options')) {
    throw new HttpError(400, 'INVALID_CONNECTOR_REQUEST', 'options alanı zorunludur.');
  }

  try {
    const options = schema.parse(container.options);
    const fingerprint = computeConnectorFingerprint(options);

    return { type, options, fingerprint } as ConnectorConfig;
  } catch (error) {
    if (error instanceof ZodError) {
      throw new HttpError(
        400,
        'INVALID_CONNECTOR_REQUEST',
        'Bağlayıcı yapılandırması doğrulanamadı.',
        { issues: error.issues },
      );
    }
    throw error;
  }
};

const computeConnectorFingerprint = <K extends ConnectorType>(options: ConnectorOptionsMap[K]): string => {
  const normalized = toStableJson(stripSecrets(options));
  return createHash('sha256').update(normalized).digest('hex');
};

export {
  SECRET_REDACTION_KEYS,
  connectorOptionSchemas,
  computeConnectorFingerprint,
  parseConnectorPayload,
  redactSecrets,
  stripSecrets,
  toStableJson,
  type ConnectorConfig,
  type ConnectorMetadata,
  type ConnectorOptionsMap,
  type ConnectorType,
};
