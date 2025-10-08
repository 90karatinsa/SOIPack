export type SaxesTagPlain = {
  name?: string;
  attributes?: Record<string, unknown>;
};

export class SaxesParser {
  public on(): this {
    return this;
  }

  public write(): this {
    return this;
  }

  public close(): this {
    return this;
  }
}
