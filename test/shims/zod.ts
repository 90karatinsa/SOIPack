/* eslint-disable @typescript-eslint/no-explicit-any */

class MockSchema<T = any> {
  private parser: (value: any) => T;

  constructor(parser?: (value: any) => T) {
    this.parser = parser ?? ((value) => value as T);
  }

  parse(value: any): T {
    return this.parser(value);
  }

  optional(): MockSchema<T | undefined> {
    return this as unknown as MockSchema<T | undefined>;
  }

  default(): MockSchema<T> {
    return this;
  }

  min(): MockSchema<T> {
    return this;
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

export { MockSchema, z, ZodIssueCode, ZodType, RefinementCtx };
export default z;
