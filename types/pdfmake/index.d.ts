declare module 'pdfmake' {
  export default class PdfPrinter {
    constructor(fonts?: unknown);
    createPdfKitDocument(definition: unknown, options?: unknown): {
      end(): void;
      pipe(destination: unknown): void;
      on(event: string, listener: (...args: any[]) => void): void;
    };
  }
}
