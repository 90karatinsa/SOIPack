import { buildAuthHeaders } from './api';

const IMPORT_META_OVERRIDE_KEY = '__SOIPACK_IMPORT_META_ENV__';

describe('buildAuthHeaders', () => {
  it('returns sanitized headers when token and license are provided', () => {
    const headers = buildAuthHeaders({ token: ' demo-token ', license: '  ZXhhbXBsZV9saWNlbnNl\n' });
    expect(headers.Authorization).toBe('Bearer demo-token');
    expect(headers['X-SOIPACK-License']).toBe('ZXhhbXBsZV9saWNlbnNl');
  });

  it('throws an error when the token is missing', () => {
    expect(() => buildAuthHeaders({ token: '   ', license: 'ZW1wdHk=' })).toThrow('Token gereklidir.');
  });

  it('throws an error when the license is missing', () => {
    expect(() => buildAuthHeaders({ token: 'valid', license: '   ' })).toThrow('Lisans gereklidir.');
  });
});

describe('resolveBaseUrl', () => {
  afterEach(() => {
    delete (globalThis as Record<string, unknown>)[IMPORT_META_OVERRIDE_KEY];
    delete process.env.VITE_API_BASE_URL;
    jest.resetModules();
  });

  it('prefers values from import.meta.env when available', async () => {
    (globalThis as Record<string, unknown>)[IMPORT_META_OVERRIDE_KEY] = {
      VITE_API_BASE_URL: 'https://import-meta.example/api/',
    };
    process.env.VITE_API_BASE_URL = 'https://process-env.example/base/';

    await jest.isolateModulesAsync(async () => {
      const module = await import('./api');
      expect(module.__test__.getConfiguredBaseUrl()).toBe('https://import-meta.example/api');
    });
  });

  it('falls back to process.env when import.meta.env is unavailable', async () => {
    process.env.VITE_API_BASE_URL = 'https://process-env.example/base/';

    await jest.isolateModulesAsync(async () => {
      const module = await import('./api');
      expect(module.__test__.getConfiguredBaseUrl()).toBe('https://process-env.example/base');
    });
  });

  it('returns an empty base URL when no overrides exist', async () => {
    await jest.isolateModulesAsync(async () => {
      const module = await import('./api');
      expect(module.__test__.getConfiguredBaseUrl()).toBe('');
      expect(module.__test__.resolveBaseUrl()).toBe('');
    });
  });
});
