declare module 'fast-xml-parser' {
  export class XMLParser {
    constructor(options?: unknown);
    parse(input: string): any;
  }
}
