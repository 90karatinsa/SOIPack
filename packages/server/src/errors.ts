import { DEFAULT_LOCALE, translate } from '@soipack/core';

export interface HttpErrorOptions {
  messageKey?: string;
  messageParams?: Record<string, unknown>;
  locale?: string;
}

export class HttpError extends Error {
  public readonly statusCode: number;

  public readonly code: string;

  public readonly details?: unknown;

  public readonly messageKey?: string;

  public readonly messageParams?: Record<string, unknown>;

  constructor(
    statusCode: number,
    code: string,
    message: string,
    details?: unknown,
    options: HttpErrorOptions = {},
  ) {
    const locale = options.locale ?? DEFAULT_LOCALE;
    const resolvedMessage =
      options.messageKey !== undefined
        ? translate(options.messageKey, { locale, values: options.messageParams })
        : message;
    super(resolvedMessage);
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
    this.messageKey = options.messageKey;
    this.messageParams = options.messageParams;
  }
}

export const toHttpError = (
  error: unknown,
  fallback?: {
    code?: string;
    message?: string;
    statusCode?: number;
    messageKey?: string;
    messageParams?: Record<string, unknown>;
    details?: unknown;
  },
): HttpError => {
  if (error instanceof HttpError) {
    return error;
  }
  const message =
    (error && typeof error === 'object' && 'message' in error && typeof (error as { message: unknown }).message === 'string')
      ? (error as { message: string }).message
      : String(error);

  const statusCode = fallback?.statusCode ?? 500;
  const code = fallback?.code ?? 'UNEXPECTED_ERROR';
  const messageKey = fallback?.messageKey ?? 'errors.unexpected';
  const fallbackMessage =
    fallback?.message ?? translate(messageKey, { locale: DEFAULT_LOCALE, values: fallback?.messageParams });

  return new HttpError(statusCode, code, message || fallbackMessage, fallback?.details, {
    messageKey,
    messageParams: fallback?.messageParams,
  });
};
