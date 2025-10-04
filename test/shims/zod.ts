/* eslint-disable @typescript-eslint/no-explicit-any */

type Refinement<T> = (value: T) => void;

class ZodError extends Error {
  public issues: { message: string; path?: (string | number)[] }[];

  constructor(issues: { message: string; path?: (string | number)[] }[]) {
    super('Mock Zod validation error');
    this.name = 'ZodError';
    this.issues = issues;
  }
}

class MockSchema<T = any> {
  private parser: (value: any) => T;

  private refinements: Refinement<T>[];

  constructor(parser?: (value: any) => T, refinements?: Refinement<T>[]) {
    this.parser = parser ?? ((value) => value as T);
    this.refinements = refinements ? [...refinements] : [];
  }

  private cloneWith<U>(parser: (value: any) => U, refinements?: Refinement<U>[]): MockSchema<U> {
    return new MockSchema<U>(parser, refinements);
  }

  private withRefinement(refinement: Refinement<T>): MockSchema<T> {
    return new MockSchema<T>(this.parser, [...this.refinements, refinement]);
  }

  parse(value: any): T {
    const parsed = this.parser(value);
    this.refinements.forEach((refinement) => refinement(parsed));
    return parsed;
  }

  optional(): MockSchema<T | undefined> {
    const parser = (value: any) => {
      if (value === undefined || value === null) {
        return undefined;
      }
      return this.parser(value);
    };
    const refinements: Refinement<T | undefined>[] = this.refinements.map(
      (refinement) => (value: T | undefined) => {
        if (value !== undefined) {
          refinement(value as T);
        }
      },
    );
    return this.cloneWith<T | undefined>(parser, refinements);
  }

  trim(): MockSchema<T> {
    const parser = (value: any) => {
      const parsed = this.parser(value);
      if (typeof parsed === 'string') {
        return parsed.trim() as T;
      }
      return parsed;
    };
    return this.cloneWith<T>(parser, [...this.refinements]);
  }

  default(defaultValue?: T): MockSchema<T> {
    const parser = (value: any) => {
      if (value === undefined) {
        return defaultValue as T;
      }
      return this.parser(value);
    };
    return this.cloneWith<T>(parser, [...this.refinements]);
  }

  min(minValue: number, message?: string): MockSchema<T> {
    const refinement: Refinement<T> = (value) => {
      if (typeof value === 'number' && value < minValue) {
        throw new ZodError([
          { message: message ?? `Value must be greater than or equal to ${minValue}.`, path: [] },
        ]);
      }
      const length =
        typeof value === 'string' || Array.isArray(value)
          ? (value as { length: number }).length
          : undefined;
      if (typeof length === 'number' && length < minValue) {
        throw new ZodError([
          { message: message ?? `Value must contain at least ${minValue} items.`, path: [] },
        ]);
      }
    };
    return this.withRefinement(refinement);
  }

  regex(): MockSchema<T> {
    return this;
  }

  datetime(): MockSchema<T> {
    return this;
  }

  refine(): MockSchema<T> {
    return this;
  }

  superRefine(): MockSchema<T> {
    return this;
  }

  transform(fn: (value: T, ctx: { addIssue: (...args: any[]) => void }) => any): MockSchema<any> {
    return new MockSchema((value: any) => fn(this.parser(value), { addIssue: () => undefined }));
  }
}

const string = () => new MockSchema<string>((value) => (value != null ? String(value) : ''));
const boolean = () => new MockSchema<boolean>((value) => Boolean(value));

const enumFactory = (values: readonly string[]) =>
  new MockSchema<string>((value) => (values.includes(String(value)) ? String(value) : values[0]));

const array = <T>(schema: MockSchema<T>) =>
  new MockSchema<T[]>((value) => {
    if (!Array.isArray(value)) {
      return [];
    }
    return value.map((item) => schema.parse(item));
  });

const object = (shape: Record<string, MockSchema<any>>) =>
  new MockSchema<Record<string, any>>((value) => {
    if (!value || typeof value !== 'object') {
      return {};
    }
    const result: Record<string, any> = {};
    Object.keys(shape).forEach((key) => {
      result[key] = shape[key].parse((value as Record<string, any>)[key]);
    });
    return result;
  });

const literal = <T>(value: T) => new MockSchema<T>(() => value);

const z = {
  object,
  array,
  enum: enumFactory,
  string,
  boolean,
  literal,
};

type ZodIssueCode = string;

type ZodType<T = any> = MockSchema<T>;

type RefinementCtx = {
  addIssue: (...args: any[]) => void;
};

export { MockSchema, ZodError, z, ZodIssueCode, ZodType, RefinementCtx };
export default z;
