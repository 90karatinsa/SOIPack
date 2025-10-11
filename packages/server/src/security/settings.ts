import { randomUUID } from 'crypto';
import path from 'path';

import { ZodError, z, type ZodTypeAny } from 'zod';

import { StorageProvider } from '../storage';

const isoDateSchema = z
  .string()
  .refine((value) => {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return false;
    }
    return date.toISOString() === value;
  }, 'Invalid ISO 8601 timestamp.');

const dayOfWeekSchema = z.enum([
  'monday',
  'tuesday',
  'wednesday',
  'thursday',
  'friday',
  'saturday',
  'sunday',
]);

const timeSchema = z
  .string()
  .regex(/^(?:[01]\d|2[0-3]):[0-5]\d$/, 'Start time must use HH:MM 24-hour format.');

const retentionWindowSchema = z
  .number({ invalid_type_error: 'Retention windows must be integers representing days.' })
  .refine((value) => Number.isInteger(value), 'Retention windows must be integers.')
  .refine((value) => value >= 1, 'Retention windows must be positive.')
  .refine((value) => value <= 3650, 'Retention windows cannot exceed 10 years.');

const trimmed = <T extends ZodTypeAny>(schema: T) =>
  z.preprocess((value) => (typeof value === 'string' ? value.trim() : value), schema);

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const incidentContactSchema = z.object({
  name: trimmed(z.string().min(1, 'Incident contact name is required.')),
  email: trimmed(
    z.string().refine((value) => EMAIL_REGEX.test(value), 'Incident contact email must be valid.'),
  ),
  phone: trimmed(z.string().min(1, 'Incident contact phone must not be empty.')).optional(),
});

const retentionPolicySchema = z
  .object({
    uploadsDays: retentionWindowSchema.optional(),
    analysesDays: retentionWindowSchema.optional(),
    reportsDays: retentionWindowSchema.optional(),
    packagesDays: retentionWindowSchema.optional(),
  })
  .refine((value) => Object.values(value).some((entry) => entry !== undefined), {
    message: 'Retention policy cannot be empty.',
  });

const maintenanceScheduleSchema = z.object({
  dayOfWeek: dayOfWeekSchema,
  startTime: timeSchema,
  durationMinutes: z
    .number({ invalid_type_error: 'Maintenance duration must be expressed in minutes.' })
    .refine((value) => Number.isInteger(value), 'Maintenance duration must be an integer in minutes.')
    .refine((value) => value >= 15, 'Maintenance windows must be at least 15 minutes.')
    .refine((value) => value <= 24 * 60, 'Maintenance windows cannot exceed 24 hours.'),
  timezone: trimmed(z.string().min(1, 'Maintenance timezone is required.')),
});

const securitySettingsSchema = z.object({
  incidentContact: incidentContactSchema,
  retention: retentionPolicySchema,
  maintenance: maintenanceScheduleSchema,
});

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const storedDocumentSchema = z.object({
  tenantId: trimmed(z.string().min(1, 'Tenant identifier is required.')),
  createdAt: isoDateSchema,
  revision: z.object({
    id: z.string().refine((value) => value.length > 0, 'Revision identifiers are required.'),
    number: z
      .number()
      .refine((value) => Number.isInteger(value), 'Revision numbers must be integers.')
      .refine((value) => value >= 1, 'Revision numbers start at 1.'),
    updatedAt: isoDateSchema,
  }),
  settings: securitySettingsSchema,
});

const parseSettingsInput = (input: SecuritySettingsInput): SecuritySettings => {
  try {
    return securitySettingsSchema.parse(input);
  } catch (error) {
    if (error instanceof ZodError) {
      throw new SecuritySettingsValidationError(error.errors);
    }
    throw error;
  }
};

const parseStoredDocument = (raw: unknown): SecuritySettingsRecord => {
  try {
    return storedDocumentSchema.parse(raw);
  } catch (error) {
    if (error instanceof ZodError) {
      throw new SecuritySettingsValidationError(error.errors);
    }
    throw error;
  }
};

export type SecuritySettingsInput = z.input<typeof securitySettingsSchema>;
export type SecuritySettings = z.output<typeof securitySettingsSchema>;

export interface SecuritySettingsRevision {
  id: string;
  number: number;
  updatedAt: string;
}

export interface SecuritySettingsRecord {
  tenantId: string;
  createdAt: string;
  revision: SecuritySettingsRevision;
  settings: SecuritySettings;
}

export interface SaveSecuritySettingsInput {
  tenantId: string;
  settings: SecuritySettingsInput;
  expectedRevision?: number | null;
}

export interface SecuritySettingsStoreOptions {
  directory?: string;
  clock?: () => Date;
  revisionIdFactory?: () => string;
}

export class SecuritySettingsValidationError extends Error {
  public readonly issues: z.ZodIssue[];

  constructor(issues: z.ZodIssue[]) {
    super('Security settings payload failed validation.');
    this.issues = issues;
  }
}

export class SecuritySettingsConflictError extends Error {
  constructor(message = 'Security settings were modified by another process.') {
    super(message);
  }
}

const DEFAULT_FILENAME = 'settings.json';
const TENANT_SEGMENT_PATTERN = /^[a-zA-Z0-9_.-]+$/;

const toIsoString = (date: Date): string => date.toISOString();

export class SecuritySettingsStore {
  private readonly storage: StorageProvider;

  private readonly baseDirectory: string;

  private readonly clock: () => Date;

  private readonly revisionIdFactory: () => string;

  constructor(storage: StorageProvider, options: SecuritySettingsStoreOptions = {}) {
    this.storage = storage;
    this.baseDirectory = options.directory ?? path.join(storage.directories.base, 'security');
    this.clock = options.clock ?? (() => new Date());
    this.revisionIdFactory = options.revisionIdFactory ?? (() => randomUUID());
  }

  public async get(tenantId: string): Promise<SecuritySettingsRecord | undefined> {
    const filePath = this.toTenantFilePath(tenantId);
    const exists = await this.storage.fileExists(filePath);
    if (!exists) {
      return undefined;
    }
    const raw = await this.storage.readJson<unknown>(filePath);
    return parseStoredDocument(raw);
  }

  public async save(input: SaveSecuritySettingsInput): Promise<SecuritySettingsRecord> {
    const tenantId = input.tenantId.trim();
    if (tenantId.length === 0) {
      throw new SecuritySettingsValidationError([
        { code: z.ZodIssueCode.custom, message: 'Tenant identifier is required.', path: ['tenantId'] },
      ]);
    }
    const normalizedTenantId = tenantId;

    const settings = parseSettingsInput(input.settings);
    const existing = await this.get(normalizedTenantId);

    if (!existing) {
      const now = toIsoString(this.clock());
      const record: SecuritySettingsRecord = {
        tenantId: normalizedTenantId,
        createdAt: now,
        revision: {
          id: this.revisionIdFactory(),
          number: 1,
          updatedAt: now,
        },
        settings,
      };
      await this.persist(normalizedTenantId, record);
      return record;
    }

    const expectedRevision = input.expectedRevision ?? undefined;
    if (expectedRevision === undefined) {
      throw new SecuritySettingsConflictError('expectedRevision is required when updating security settings.');
    }
    if (expectedRevision !== existing.revision.number) {
      throw new SecuritySettingsConflictError();
    }

    const now = toIsoString(this.clock());
    const record: SecuritySettingsRecord = {
      tenantId: normalizedTenantId,
      createdAt: existing.createdAt,
      revision: {
        id: this.revisionIdFactory(),
        number: existing.revision.number + 1,
        updatedAt: now,
      },
      settings,
    };
    await this.persist(normalizedTenantId, record);
    return record;
  }

  private async persist(tenantId: string, record: SecuritySettingsRecord): Promise<void> {
    const filePath = this.toTenantFilePath(tenantId);
    await this.storage.writeJson(filePath, record);
  }

  private toTenantFilePath(tenantId: string): string {
    const normalized = tenantId.trim();
    if (!TENANT_SEGMENT_PATTERN.test(normalized)) {
      throw new SecuritySettingsValidationError([
        { code: z.ZodIssueCode.custom, message: 'Tenant identifier contains invalid characters.', path: ['tenantId'] },
      ]);
    }
    return path.join(this.baseDirectory, normalized, DEFAULT_FILENAME);
  }
}
