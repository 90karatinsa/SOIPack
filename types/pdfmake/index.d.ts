/// <reference types="node" />

import type { TDocumentDefinitions } from 'pdfmake/interfaces';

export type PdfStream = {
  on(event: 'data', listener: (chunk: Buffer) => void): PdfStream;
  on(event: 'end', listener: () => void): PdfStream;
  on(event: 'error', listener: (error: Error) => void): PdfStream;
  end(): void;
};

declare class PdfPrinter {
  constructor(fonts?: Record<string, unknown>);
  createPdfKitDocument(docDefinition: TDocumentDefinitions, options?: Record<string, unknown>): PdfStream;
}

export default PdfPrinter;
