export class HttpError extends Error {
  public readonly statusCode: number;

  public readonly code: string;

  public readonly details?: unknown;

  constructor(statusCode: number, code: string, message: string, details?: unknown) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
  }
}

export const toHttpError = (error: unknown, fallback?: { code?: string; message?: string; statusCode?: number }): HttpError => {
  if (error instanceof HttpError) {
    return error;
  }
  const message =
    (error && typeof error === 'object' && 'message' in error && typeof (error as { message: unknown }).message === 'string')
      ? (error as { message: string }).message
      : String(error);

  const statusCode = fallback?.statusCode ?? 500;
  const code = fallback?.code ?? 'UNEXPECTED_ERROR';
  const fallbackMessage = fallback?.message ?? 'Beklenmeyen bir hata oluştu.';

  return new HttpError(statusCode, code, message || fallbackMessage);
};
