declare module 'saxes' {
  export interface SaxesOptions {
    xmlns?: boolean;
  }

  export interface SaxesTagPlain {
    name: string;
    attributes: Record<string, unknown>;
  }

  export class SaxesParser {
    constructor(options?: SaxesOptions);
    on(event: 'error', handler: (error: unknown) => void): this;
    on(event: 'opentag', handler: (tag: SaxesTagPlain) => void): this;
    on(event: 'text', handler: (text: string) => void): this;
    on(event: 'closetag', handler: (tag: unknown) => void): this;
    on(event: 'end', handler: () => void): this;
    write(chunk: string): void;
    close(): void;
  }
}
