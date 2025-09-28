import { Buffer } from 'node:buffer';

export interface PdfOptions {
  format?: string;
  printBackground?: boolean;
  displayHeaderFooter?: boolean;
  headerTemplate?: string;
  footerTemplate?: string;
  margin?: {
    top?: string;
    bottom?: string;
    left?: string;
    right?: string;
  };
}

class MockPage {
  private html = '';

  async setContent(content: string): Promise<void> {
    this.html = content;
  }

  async pdf(options: PdfOptions = {}): Promise<Buffer> {
    const metadata = JSON.stringify({ options });
    return Buffer.concat([
      Buffer.from('%PDF-FAKE\n', 'utf-8'),
      Buffer.from(this.html, 'utf-8'),
      Buffer.from('\n', 'utf-8'),
      Buffer.from(metadata, 'utf-8'),
    ]);
  }

  async close(): Promise<void> {
    // no-op for tests
  }
}

class MockBrowser {
  async newPage(): Promise<MockPage> {
    return new MockPage();
  }

  async close(): Promise<void> {
    // no-op for tests
  }
}

export interface LaunchOptions {
  headless?: boolean;
}

const playwright = {
  chromium: {
    async launch(_options?: LaunchOptions): Promise<MockBrowser> {
      return new MockBrowser();
    },
  },
};

export type Browser = MockBrowser;
export type Page = MockPage;

export default playwright;
