declare module 'html-validator' {
  export interface ValidationMessage {
    type?: string;
    message?: string;
  }

  export interface ValidationResult {
    messages: ValidationMessage[];
  }

  export default function validate(options?: unknown): Promise<ValidationResult>;
}
