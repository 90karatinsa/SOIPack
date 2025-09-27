declare module 'docx' {
  export class Document {
    constructor(options?: unknown);
  }

  export enum AlignmentType {
    LEFT,
    CENTER,
    RIGHT,
  }

  export enum HeadingLevel {
    TITLE,
    HEADING_1,
    HEADING_2,
    HEADING_3,
  }

  export enum WidthType {
    AUTO,
    PERCENTAGE,
  }

  export class TextRun {
    constructor(options?: unknown);
  }

  export class Paragraph {
    constructor(options?: unknown);
  }

  export class TableCell {
    constructor(options?: unknown);
  }

  export class TableRow {
    constructor(options?: unknown);
  }

  export class Table {
    constructor(options?: unknown);
  }

  export class Packer {
    static toBuffer(document: Document): Promise<Buffer>;
  }
}
