declare module 'html-validator' {
  export interface HtmlValidatorMessage {
    type: string;
    message?: string;
  }

  export interface HtmlValidatorResult {
    messages?: HtmlValidatorMessage[];
  }

  export interface HtmlValidatorOptions {
    data?: string;
    format?: 'json' | 'html' | 'text';
  }

  export default function htmlValidator(options: HtmlValidatorOptions): Promise<HtmlValidatorResult>;
}
