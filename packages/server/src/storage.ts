import fs, { promises as fsPromises } from 'fs';
import path from 'path';

import { HttpError } from './errors';

const DIRECTORY_MODE = 0o750;
const FILE_MODE = 0o640;

const CURRENT_UID = typeof process.getuid === 'function' ? process.getuid() : undefined;
const CURRENT_GID = typeof process.getgid === 'function' ? process.getgid() : undefined;

const shouldIgnoreFsError = (error: unknown): boolean => {
  if (!error || typeof error !== 'object') {
    return false;
  }
  const code = (error as NodeJS.ErrnoException).code;
  return code === 'EPERM' || code === 'EINVAL' || code === 'ENOSYS';
};

const safeChmodSync = (target: string, mode: number): void => {
  try {
    fs.chmodSync(target, mode);
  } catch (error) {
    if (!shouldIgnoreFsError(error)) {
      throw error;
    }
  }
};

const safeChmod = async (target: string, mode: number): Promise<void> => {
  try {
    await fsPromises.chmod(target, mode);
  } catch (error) {
    if (!shouldIgnoreFsError(error)) {
      throw error;
    }
  }
};

const normalizeOwnershipSync = (target: string): void => {
  if (CURRENT_UID === undefined || CURRENT_GID === undefined) {
    return;
  }
  try {
    fs.chownSync(target, CURRENT_UID, CURRENT_GID);
  } catch (error) {
    if (!shouldIgnoreFsError(error)) {
      throw error;
    }
  }
};

const normalizeOwnership = async (target: string): Promise<void> => {
  if (CURRENT_UID === undefined || CURRENT_GID === undefined) {
    return;
  }
  try {
    await fsPromises.chown(target, CURRENT_UID, CURRENT_GID);
  } catch (error) {
    if (!shouldIgnoreFsError(error)) {
      throw error;
    }
  }
};

export interface PipelineDirectories {
  base: string;
  uploads: string;
  workspaces: string;
  analyses: string;
  reports: string;
  packages: string;
  ledgers: string;
}

export interface PersistableFile {
  originalname: string;
  path: string;
}

export type UploadedFileMap = Record<string, PersistableFile[]>;

const sanitizeFileName = (fileName: string, fallback: string): string => {
  const baseName = path.basename(fileName || fallback);
  const normalized = baseName.replace(/[^a-zA-Z0-9._-]/g, '_');
  return normalized || fallback;
};

export interface StorageProvider {
  readonly directories: PipelineDirectories;
  persistUploads(jobId: string, fileMap: UploadedFileMap): Promise<Record<string, string[]>>;
  ensureDirectory(target: string): Promise<void>;
  removeDirectory(target: string): Promise<void>;
  fileExists(target: string): Promise<boolean>;
  openReadStream(target: string): Promise<NodeJS.ReadableStream>;
  getFileInfo(target: string): Promise<{ size?: number } | undefined>;
  readJson<T>(filePath: string): Promise<T>;
  writeJson(filePath: string, data: unknown): Promise<void>;
  listSubdirectories(directory: string): Promise<string[]>;
  toRelativePath(target: string): string;
}

export class FileSystemStorage implements StorageProvider {
  public readonly directories: PipelineDirectories;

  constructor(baseDir: string) {
    const directories: PipelineDirectories = {
      base: baseDir,
      uploads: path.join(baseDir, 'uploads'),
      workspaces: path.join(baseDir, 'workspaces'),
      analyses: path.join(baseDir, 'analyses'),
      reports: path.join(baseDir, 'reports'),
      packages: path.join(baseDir, 'packages'),
      ledgers: path.join(baseDir, 'ledgers'),
    };

    this.directories = directories;
    Object.values(directories).forEach((directory) => {
      fs.mkdirSync(directory, { recursive: true, mode: DIRECTORY_MODE });
      safeChmodSync(directory, DIRECTORY_MODE);
      normalizeOwnershipSync(directory);
    });
  }

  public async persistUploads(
    jobId: string,
    fileMap: UploadedFileMap,
  ): Promise<Record<string, string[]>> {
    const entries = Object.entries(fileMap);
    const result: Record<string, string[]> = {};
    const jobUploadDir = path.join(this.directories.uploads, jobId);
    await this.ensureDirectory(jobUploadDir);

    for (const [field, files] of entries) {
      for (const [index, file] of files.entries()) {
        const targetDir = path.join(jobUploadDir, field);
        await this.ensureDirectory(targetDir);
        const safeName = sanitizeFileName(file.originalname, `${field}-${index}`);
        const targetPath = path.join(targetDir, safeName);
        await fsPromises.copyFile(file.path, targetPath);
        await safeChmod(targetPath, FILE_MODE);
        await normalizeOwnership(targetPath);
        await fsPromises.rm(file.path, { force: true });
        if (!result[field]) {
          result[field] = [];
        }
        result[field].push(targetPath);
      }
    }

    return result;
  }

  public async ensureDirectory(target: string): Promise<void> {
    await fsPromises.mkdir(target, { recursive: true, mode: DIRECTORY_MODE });
    await safeChmod(target, DIRECTORY_MODE);
    await normalizeOwnership(target);
  }

  public async removeDirectory(target: string): Promise<void> {
    await fsPromises.rm(target, { recursive: true, force: true });
  }

  public async fileExists(target: string): Promise<boolean> {
    try {
      await fsPromises.access(target, fs.constants.F_OK);
      return true;
    } catch {
      return false;
    }
  }

  public async openReadStream(target: string): Promise<NodeJS.ReadableStream> {
    return fs.createReadStream(target);
  }

  public async getFileInfo(target: string): Promise<{ size?: number } | undefined> {
    try {
      const stats = await fsPromises.stat(target);
      return { size: stats.size };
    } catch {
      return undefined;
    }
  }

  public async readJson<T>(filePath: string): Promise<T> {
    const content = await fsPromises.readFile(filePath, 'utf8');
    return JSON.parse(content) as T;
  }

  public async writeJson(filePath: string, data: unknown): Promise<void> {
    const serialized = `${JSON.stringify(data, null, 2)}\n`;
    await fsPromises.writeFile(filePath, serialized, 'utf8');
  }

  public async listSubdirectories(directory: string): Promise<string[]> {
    const entries = await fsPromises.readdir(directory, { withFileTypes: true });
    return entries.filter((entry) => entry.isDirectory()).map((entry) => entry.name);
  }

  public toRelativePath(target: string): string {
    const resolvedBase = path.resolve(this.directories.base);
    const resolvedTarget = path.resolve(target);
    const relative = path.relative(resolvedBase, resolvedTarget);
    if (relative.startsWith('..') || path.isAbsolute(relative)) {
      throw new HttpError(500, 'PATH_OUT_OF_ROOT', 'Dosya yolu sunucu depolama alanının dışında.');
    }
    return relative.split(path.sep).join('/');
  }
}
