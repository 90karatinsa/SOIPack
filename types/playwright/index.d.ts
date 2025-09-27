declare module 'playwright' {
  export interface Page {
    goto(url: string, options?: unknown): Promise<void>;
    setContent(html: string, options?: unknown): Promise<void>;
    pdf(options?: unknown): Promise<Buffer>;
    close(): Promise<void>;
  }

  export interface Browser {
    newPage(): Promise<Page>;
    close(): Promise<void>;
  }

  export const chromium: {
    launch(options?: unknown): Promise<Browser>;
  };
}
