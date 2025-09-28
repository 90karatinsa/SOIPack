export interface HtmlValidatorOptions {
  readonly data?: string;
  readonly format?: string;
}

export interface HtmlValidatorResult {
  messages?: Array<{
    type?: string;
    message?: string;
    extract?: string;
    lastLine?: number;
    firstLine?: number;
  }>;
}

const validate = async (_options?: HtmlValidatorOptions): Promise<HtmlValidatorResult> => ({ messages: [] });

export default validate;
export { validate };
