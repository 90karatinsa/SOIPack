declare module 'zod' {
  export const ZodIssueCode: { custom: string };

  export interface RefinementCtx {
    addIssue: (...args: unknown[]) => void;
  }

  export type ZodType<T = unknown> = {
    parse(value: unknown): T;
    optional(): ZodType<T | undefined>;
    default(value: unknown): ZodType<T>;
    min(value: unknown, message?: string): ZodType<T>;
    regex(pattern: RegExp, message?: string): ZodType<T>;
    datetime(options?: unknown): ZodType<T>;
    refine(check: (value: T) => unknown, options?: unknown): ZodType<T>;
    superRefine(check: (value: T, ctx: RefinementCtx) => unknown): ZodType<T>;
    transform<R>(transformer: (value: T, ctx: RefinementCtx) => R): ZodType<R>;
  } & Record<string, unknown>;

  export const z: {
    object(shape: Record<string, ZodType>): ZodType<any>;
    array<T>(schema: ZodType<T>): ZodType<T[]>;
    enum(values: readonly string[]): ZodType<string>;
    string(): ZodType<string>;
    boolean(): ZodType<boolean>;
    literal<T>(value: T): ZodType<T>;
  } & Record<string, unknown>;

  export default z;
}
