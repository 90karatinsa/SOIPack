class PdfPrinter {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  constructor(_fonts: unknown) {}

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  createPdfKitDocument(_definition: unknown): { on: () => void; end: () => void; pipe: () => void } {
    return {
      on: () => {},
      end: () => {},
      pipe: () => {},
    };
  }
}

const pdfmake = PdfPrinter;

export = pdfmake;
