declare module 'fast-xml-parser' {
  export class XMLParser {
    constructor(options?: unknown);
    parse<T = unknown>(input: string): T;
  }
}
