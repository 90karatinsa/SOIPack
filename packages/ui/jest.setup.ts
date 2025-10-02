import '@testing-library/jest-dom';

if (!process.env.VITE_API_BASE_URL) {
  process.env.VITE_API_BASE_URL = 'http://localhost';
}

Object.defineProperty(window.navigator, 'language', {
  configurable: true,
  value: 'tr-TR',
});

Object.defineProperty(window.navigator, 'languages', {
  configurable: true,
  value: ['tr-TR', 'tr'],
});

import { ReadableStream, TransformStream, WritableStream } from 'stream/web';
import { TextDecoder, TextEncoder } from 'util';

Object.assign(globalThis, { TextDecoder, TextEncoder, ReadableStream, TransformStream, WritableStream });

Object.defineProperty(globalThis, 'performance', {
  configurable: true,
  value: {
    now: () => Date.now(),
    markResourceTiming: () => {},
  },
});

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { fetch, FormData, File, Headers, Request, Response } = require('undici');

Object.assign(globalThis, { fetch, FormData, File, Headers, Request, Response });

if (typeof globalThis.setImmediate === 'undefined') {
  globalThis.setImmediate = ((callback: (...args: unknown[]) => void, ...args: unknown[]) =>
    setTimeout(callback, 0, ...args)) as unknown as typeof setImmediate;
}

if (typeof globalThis.clearImmediate === 'undefined') {
  globalThis.clearImmediate = ((handle: ReturnType<typeof setTimeout>) => clearTimeout(handle)) as unknown as typeof clearImmediate;
}
