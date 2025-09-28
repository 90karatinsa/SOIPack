import { promises as fsPromises } from 'fs';
import os from 'os';
import path from 'path';

import { FileSystemStorage } from '../storage';

describe('FileSystemStorage.writeJson', () => {
  let baseDir: string;
  let storage: FileSystemStorage;

  beforeEach(async () => {
    baseDir = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'storage-test-'));
    storage = new FileSystemStorage(baseDir);
  });

  afterEach(async () => {
    jest.restoreAllMocks();
    await fsPromises.rm(baseDir, { recursive: true, force: true });
  });

  it('does not corrupt existing data when rename fails', async () => {
    const filePath = path.join(storage.directories.base, 'tenant.json');
    await fsPromises.writeFile(filePath, JSON.stringify({ existing: true }, null, 2));

    const renameSpy = jest
      .spyOn(fsPromises, 'rename')
      .mockRejectedValueOnce(new Error('rename failed'));

    await expect(storage.writeJson(filePath, { existing: false })).rejects.toThrow('rename failed');

    expect(renameSpy).toHaveBeenCalled();

    const persisted = JSON.parse(await fsPromises.readFile(filePath, 'utf8'));
    expect(persisted).toEqual({ existing: true });
  });

  it('persists new data when write succeeds', async () => {
    const filePath = path.join(storage.directories.base, 'tenant.json');

    const renameSpy = jest.spyOn(fsPromises, 'rename');

    await storage.writeJson(filePath, { updated: true });

    expect(renameSpy).toHaveBeenCalled();

    const persisted = JSON.parse(await fsPromises.readFile(filePath, 'utf8'));
    expect(persisted).toEqual({ updated: true });
  });
});
