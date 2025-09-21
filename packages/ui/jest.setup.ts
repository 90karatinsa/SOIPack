import '@testing-library/jest-dom';

if (!process.env.VITE_API_BASE_URL) {
  process.env.VITE_API_BASE_URL = 'http://localhost';
}

import { ReadableStream, TransformStream, WritableStream } from 'stream/web';
import { TextDecoder, TextEncoder } from 'util';

Object.assign(globalThis, { TextDecoder, TextEncoder, ReadableStream, TransformStream, WritableStream });

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { fetch, FormData, File, Headers, Request, Response } = require('undici');

Object.assign(globalThis, { fetch, FormData, File, Headers, Request, Response });
