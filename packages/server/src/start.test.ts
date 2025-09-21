import fs from 'fs';
import type { Server as HttpsServer } from 'https';
import os from 'os';
import path from 'path';

describe('resolveSigningKeyPath', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
    jest.restoreAllMocks();
  });

  const loadHelper = async () => {
    const module = await import('./start');
    return module.resolveSigningKeyPath;
  };

  it('exits when signing key path env is missing', async () => {
    delete process.env.SOIPACK_SIGNING_KEY_PATH;

    const exitSpy = jest
      .spyOn(process, 'exit')
      .mockImplementation(((code?: number) => {
        throw new Error(`process.exit: ${code ?? 0}`);
      }) as never);
    const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

    const resolveSigningKeyPath = await loadHelper();

    await expect(resolveSigningKeyPath()).rejects.toThrow('process.exit: 1');
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(errorSpy).toHaveBeenCalledWith('SOIPACK_SIGNING_KEY_PATH ortam değişkeni tanımlanmalıdır.');
  });

  it('exits when signing key path is unreadable', async () => {
    process.env.SOIPACK_SIGNING_KEY_PATH = 'non-existent.pem';

    const exitSpy = jest
      .spyOn(process, 'exit')
      .mockImplementation(((code?: number) => {
        throw new Error(`process.exit: ${code ?? 0}`);
      }) as never);
    const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

    const resolveSigningKeyPath = await loadHelper();

    await expect(resolveSigningKeyPath()).rejects.toThrow('process.exit: 1');
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining('SOIPACK_SIGNING_KEY_PATH ile belirtilen anahtar dosyasına erişilemiyor:'),
    );
  });

  it('returns resolved path when signing key is accessible', async () => {
    const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'soipack-start-test-'));
    const keyPath = path.join(tmpDir, 'signing.pem');
    await fs.promises.writeFile(keyPath, 'dummy');
    process.env.SOIPACK_SIGNING_KEY_PATH = keyPath;

    const exitSpy = jest
      .spyOn(process, 'exit')
      .mockImplementation(((code?: number) => {
        throw new Error(`process.exit: ${code ?? 0}`);
      }) as never);

    const resolveSigningKeyPath = await loadHelper();

    await expect(resolveSigningKeyPath()).resolves.toBe(path.resolve(keyPath));
    expect(exitSpy).not.toHaveBeenCalled();

    await fs.promises.rm(tmpDir, { recursive: true, force: true });
  });
});

describe('start', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
    jest.restoreAllMocks();
    jest.resetModules();
  });

  const prepareBaseEnv = async () => {
    const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'soipack-start-env-'));
    const signingKeyPath = path.join(tmpDir, 'signing.pem');
    const licenseKeyPath = path.join(tmpDir, 'license.pub');
    const tlsKeyPath = path.join(tmpDir, 'server.key');
    const tlsCertPath = path.join(tmpDir, 'server.crt');
    const jwksPath = path.join(tmpDir, 'jwks.json');

    await fs.promises.writeFile(signingKeyPath, 'signing-key');
    await fs.promises.writeFile(licenseKeyPath, 'license-key');
    await fs.promises.writeFile(tlsKeyPath, 'tls-key');
    await fs.promises.writeFile(tlsCertPath, 'tls-cert');
    await fs.promises.writeFile(
      jwksPath,
      JSON.stringify({ keys: [] }),
      'utf8',
    );

    process.env.SOIPACK_AUTH_ISSUER = 'https://auth.example.com/';
    process.env.SOIPACK_AUTH_AUDIENCE = 'soipack-api';
    process.env.SOIPACK_AUTH_JWKS_PATH = jwksPath;
    delete process.env.SOIPACK_AUTH_JWKS_URI;
    process.env.SOIPACK_AUTH_TENANT_CLAIM = 'tenant';
    process.env.SOIPACK_SIGNING_KEY_PATH = signingKeyPath;
    process.env.SOIPACK_LICENSE_PUBLIC_KEY_PATH = licenseKeyPath;
    process.env.SOIPACK_TLS_KEY_PATH = tlsKeyPath;
    process.env.SOIPACK_TLS_CERT_PATH = tlsCertPath;
    process.env.PORT = '3443';

    return { tmpDir, tlsKeyPath, tlsCertPath };
  };

  it('exits when TLS key is missing', async () => {
    const { tmpDir } = await prepareBaseEnv();
    delete process.env.SOIPACK_TLS_KEY_PATH;

    const exitSpy = jest
      .spyOn(process, 'exit')
      .mockImplementation(((code?: number) => {
        throw new Error(`process.exit: ${code ?? 0}`);
      }) as never);
    const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

    const { start } = await import('./start');
    await expect(start()).rejects.toThrow('process.exit: 1');
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(errorSpy).toHaveBeenCalledWith('SOIPACK_TLS_KEY_PATH ortam değişkeni tanımlanmalıdır.');

    await fs.promises.rm(tmpDir, { recursive: true, force: true });
  });

  it('starts HTTPS server with provided certificates', async () => {
    const { tmpDir } = await prepareBaseEnv();
    process.env.SOIPACK_TLS_CLIENT_CA_PATH = path.join(tmpDir, 'client-ca.pem');
    await fs.promises.writeFile(process.env.SOIPACK_TLS_CLIENT_CA_PATH, 'client-ca');
    process.env.SOIPACK_MAX_JSON_BODY_BYTES = '4096';
    process.env.SOIPACK_RATE_LIMIT_IP_WINDOW_MS = '1000';
    process.env.SOIPACK_RATE_LIMIT_IP_MAX_REQUESTS = '5';
    process.env.SOIPACK_RATE_LIMIT_TENANT_WINDOW_MS = '1000';
    process.env.SOIPACK_RATE_LIMIT_TENANT_MAX_REQUESTS = '3';
    process.env.SOIPACK_LICENSE_MAX_BYTES = '131072';
    process.env.SOIPACK_LICENSE_CACHE_MAX_ENTRIES = '10';
    process.env.SOIPACK_LICENSE_CACHE_MAX_AGE_MS = '60000';
    process.env.SOIPACK_HTTP_REQUEST_TIMEOUT_MS = '10000';
    process.env.SOIPACK_HTTP_HEADERS_TIMEOUT_MS = '5000';
    process.env.SOIPACK_HTTP_KEEP_ALIVE_TIMEOUT_MS = '2000';
    process.env.SOIPACK_MAX_QUEUED_JOBS_TOTAL = '9';
    process.env.SOIPACK_WORKER_CONCURRENCY = '3';
    process.env.SOIPACK_SHUTDOWN_TIMEOUT_MS = '15000';

    const mockApp = {};
    const listenSpy = jest.fn<void, [number, (() => void)?]>((_port, callback) => {
      callback?.();
    });
    const closeSpy = jest.fn<void, [(callback?: (error?: Error) => void) => void]>((callback) => {
      callback?.();
    });
    const mockHttpsServer: {
      listen: typeof listenSpy;
      close: typeof closeSpy;
      requestTimeout: number;
      headersTimeout: number;
      keepAliveTimeout: number;
    } = {
      listen: listenSpy,
      close: closeSpy,
      requestTimeout: 0,
      headersTimeout: 0,
      keepAliveTimeout: 0,
    };
    const createServerMock = jest.fn(() => mockApp);
    const createHttpsServerMock = jest.fn(() => mockHttpsServer);
    const lifecycleMock = {
      waitForIdle: jest.fn().mockResolvedValue(undefined),
      shutdown: jest.fn().mockResolvedValue(undefined),
      runTenantRetention: jest.fn(),
      runAllTenantRetention: jest.fn(),
      logger: {
        info: jest.fn(),
        error: jest.fn(),
        warn: jest.fn(),
      },
    };
    const getServerLifecycleMock = jest.fn(() => lifecycleMock);
    const registeredHandlers: Partial<Record<NodeJS.Signals, () => void>> = {};

    jest.doMock('./index', () => ({
      __esModule: true,
      createServer: createServerMock,
      createHttpsServer: createHttpsServerMock,
      getServerLifecycle: getServerLifecycleMock,
      JwtAuthConfig: {} as never,
      RateLimitConfig: {} as never,
      RetentionConfig: {} as never,
    }));

    jest.spyOn(process, 'on').mockImplementation(((event: NodeJS.Signals, handler: () => void) => {
      registeredHandlers[event] = handler;
      return process;
    }) as unknown as typeof process.on);

    const logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});

    const { start } = await import('./start');
    await start();

    expect(createServerMock).toHaveBeenCalledWith(
      expect.objectContaining({
        jsonBodyLimitBytes: 4096,
        rateLimit: {
          ip: { windowMs: 1000, max: 5 },
          tenant: { windowMs: 1000, max: 3 },
        },
        requireAdminClientCertificate: true,
        licenseLimits: {
          maxBytes: 131072,
          headerMaxBytes: Math.ceil((131072 * 4) / 3),
        },
        licenseCache: { maxEntries: 10, maxAgeMs: 60000 },
        maxQueuedJobsTotal: 9,
        workerConcurrency: 3,
      }),
    );
    expect(createHttpsServerMock).toHaveBeenCalledWith(
      mockApp,
      expect.objectContaining({
        key: 'tls-key',
        cert: 'tls-cert',
        clientCa: 'client-ca',
      }),
    );
    expect(getServerLifecycleMock).toHaveBeenCalledWith(mockApp);
    expect(mockHttpsServer.requestTimeout).toBe(10000);
    expect(mockHttpsServer.headersTimeout).toBe(5000);
    expect(mockHttpsServer.keepAliveTimeout).toBe(2000);
    expect(listenSpy).toHaveBeenCalledWith(3443, expect.any(Function));
    expect(logSpy).toHaveBeenCalledWith('SOIPack API HTTPS olarak 3443 portunda dinliyor.');
    expect(lifecycleMock.logger.info).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'server_listening',
        port: 3443,
        requestTimeoutMs: 10000,
        headersTimeoutMs: 5000,
        keepAliveTimeoutMs: 2000,
      }),
      'SOIPack API HTTPS dinleyicisi başlatıldı.',
    );
    expect(registeredHandlers).toHaveProperty('SIGTERM');
    expect(registeredHandlers).toHaveProperty('SIGINT');

    await fs.promises.rm(tmpDir, { recursive: true, force: true });
  });

  it('drains queues and exits cleanly on termination signals', async () => {
    const { tmpDir } = await prepareBaseEnv();

    const mockApp = {};
    const listenSpy = jest.fn<void, [number, (() => void)?]>((_port, callback) => {
      callback?.();
    });
    const closeSpy = jest.fn<void, [(callback?: (error?: Error) => void) => void]>((callback) => {
      callback?.();
    });
    const mockHttpsServer: Pick<HttpsServer, 'listen' | 'close'> & {
      requestTimeout: number;
      headersTimeout: number;
      keepAliveTimeout: number;
    } = {
      listen: listenSpy as unknown as HttpsServer['listen'],
      close: closeSpy as unknown as HttpsServer['close'],
      requestTimeout: 0,
      headersTimeout: 0,
      keepAliveTimeout: 0,
    };
    const createServerMock = jest.fn(() => mockApp);
    const createHttpsServerMock = jest.fn(() => mockHttpsServer);
    const lifecycleMock = {
      waitForIdle: jest.fn().mockResolvedValue(undefined),
      shutdown: jest.fn().mockResolvedValue(undefined),
      runTenantRetention: jest.fn(),
      runAllTenantRetention: jest.fn(),
      logger: {
        info: jest.fn(),
        error: jest.fn(),
        warn: jest.fn(),
      },
    };
    const getServerLifecycleMock = jest.fn(() => lifecycleMock);
    const registeredHandlers: Partial<Record<NodeJS.Signals, () => void>> = {};

    jest.doMock('./index', () => ({
      __esModule: true,
      createServer: createServerMock,
      createHttpsServer: createHttpsServerMock,
      getServerLifecycle: getServerLifecycleMock,
      JwtAuthConfig: {} as never,
      RateLimitConfig: {} as never,
      RetentionConfig: {} as never,
    }));

    jest.spyOn(process, 'on').mockImplementation(((event: NodeJS.Signals, handler: () => void) => {
      registeredHandlers[event] = handler;
      return process;
    }) as unknown as typeof process.on);

    const exitSpy = jest.spyOn(process, 'exit').mockImplementation(((code?: number) => {
      void code;
      return undefined as never;
    }) as never);

    const { start } = await import('./start');
    await start();

    const handler = registeredHandlers.SIGTERM;
    expect(handler).toBeDefined();
    handler?.();

    await new Promise((resolve) => setImmediate(resolve));

    expect(closeSpy).toHaveBeenCalledTimes(1);
    expect(lifecycleMock.waitForIdle).toHaveBeenCalledTimes(1);
    expect(lifecycleMock.shutdown).toHaveBeenCalledTimes(1);
    expect(lifecycleMock.logger.info).toHaveBeenCalledWith(
      { event: 'shutdown_signal', signal: 'SIGTERM' },
      'Kapatma sinyali alındı.',
    );
    expect(exitSpy).toHaveBeenCalledWith(0);

    await fs.promises.rm(tmpDir, { recursive: true, force: true });
  });
});
