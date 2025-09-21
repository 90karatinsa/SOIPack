import fs from 'fs';
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
