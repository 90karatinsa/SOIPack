import http, { type IncomingHttpHeaders } from 'http';
import https from 'https';

export interface HttpRequestOptions {
  url: string | URL;
  method?: 'GET' | 'POST';
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
}

export class HttpError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly statusMessage: string,
    message?: string,
    public readonly headers?: IncomingHttpHeaders,
  ) {
    super(message ?? `HTTP ${statusCode} ${statusMessage}`);
    this.name = 'HttpError';
  }
}

const toUrl = (target: string | URL): URL => {
  if (target instanceof URL) {
    return target;
  }
  try {
    return new URL(target);
  } catch (error) {
    throw new Error(`Invalid URL: ${target}`);
  }
};

export const requestJson = async <T>(options: HttpRequestOptions): Promise<T> => {
  const url = toUrl(options.url);
  const client = url.protocol === 'https:' ? https : http;
  const method = options.method ?? 'GET';
  const headers = { Accept: 'application/json', ...(options.headers ?? {}) };

  return await new Promise<T>((resolve, reject) => {
    const request = client.request(
      url,
      {
        method,
        headers,
        timeout: options.timeoutMs ?? 15000,
      },
      (response) => {
        const { statusCode = 0, statusMessage = '' } = response;
        const chunks: Buffer[] = [];

        response.on('data', (chunk) => {
          chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
        });

        response.on('end', () => {
          const payload = Buffer.concat(chunks).toString('utf8');

          if (statusCode < 200 || statusCode >= 300) {
            reject(new HttpError(statusCode, statusMessage, payload || undefined, response.headers));
            return;
          }

          if (!payload) {
            resolve({} as T);
            return;
          }

          try {
            const parsed = JSON.parse(payload) as T;
            resolve(parsed);
          } catch (error) {
            reject(new Error(`Unable to parse JSON response from ${url.toString()}: ${(error as Error).message}`));
          }
        });
      },
    );

    request.on('error', (error) => {
      reject(error);
    });

    if (options.body) {
      request.write(options.body);
    }

    request.end();
  });
};
