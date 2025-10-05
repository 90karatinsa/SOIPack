import { createReadStream } from 'fs';
import { promises as fsPromises } from 'fs';
import path from 'path';
import { Readable } from 'stream';

import {
  DeleteObjectsCommand,
  GetObjectCommand,
  HeadObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  S3Client,
  type DeleteObjectsCommandInput,
  type PutObjectCommandInput,
} from '@aws-sdk/client-s3';

import { HttpError } from '../errors';
import type { StorageProvider, UploadedFileMap } from '../storage';

const sanitizeFileName = (fileName: string, fallback: string): string => {
  const baseName = path.basename(fileName || fallback);
  const normalized = baseName.replace(/[^a-zA-Z0-9._-]/g, '_');
  return normalized || fallback;
};

const normalizeSegment = (segment?: string): string => {
  if (!segment) {
    return '';
  }
  const replaced = segment.replace(/\\/g, '/');
  const trimmed = replaced.replace(/^\/+/, '').replace(/\/+$/, '');
  return trimmed;
};

const toDirectoryPrefix = (key: string): string => {
  if (!key) {
    return '';
  }
  return key.endsWith('/') ? key : `${key}/`;
};

const isNotFoundError = (error: unknown): boolean => {
  if (!error || typeof error !== 'object') {
    return false;
  }
  const status = (error as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode;
  if (status === 404) {
    return true;
  }
  const name = (error as { name?: string }).name;
  return name === 'NotFound' || name === 'NoSuchKey';
};

const streamToBuffer = async (body: NodeJS.ReadableStream | Uint8Array | string): Promise<Buffer> => {
  if (body instanceof Readable) {
    const chunks: Buffer[] = [];
    for await (const chunk of body) {
      chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : Buffer.from(chunk));
    }
    return Buffer.concat(chunks);
  }
  if (body instanceof Uint8Array) {
    return Buffer.from(body);
  }
  if (typeof body === 'string') {
    return Buffer.from(body);
  }
  throw new HttpError(500, 'S3_STREAM_ERROR', 'S3 akışı okunamadı.');
};

interface S3StorageOptions {
  bucket: string;
  prefix?: string;
  kmsKeyId?: string;
  client?: S3Client;
}

export class S3StorageProvider implements StorageProvider {
  public readonly directories;

  private readonly client: S3Client;

  private readonly bucket: string;

  private readonly basePrefix: string;

  private readonly encryptionOptions?: {
    ServerSideEncryption: 'aws:kms';
    SSEKMSKeyId: string;
  };

  constructor(options: S3StorageOptions) {
    this.bucket = options.bucket;
    this.client = options.client ?? new S3Client({});
    this.basePrefix = normalizeSegment(options.prefix);
    this.directories = {
      base: this.basePrefix,
      uploads: this.joinPath(this.basePrefix, 'uploads'),
      workspaces: this.joinPath(this.basePrefix, 'workspaces'),
      analyses: this.joinPath(this.basePrefix, 'analyses'),
      reports: this.joinPath(this.basePrefix, 'reports'),
      packages: this.joinPath(this.basePrefix, 'packages'),
      ledgers: this.joinPath(this.basePrefix, 'ledgers'),
    } as const;

    if (options.kmsKeyId) {
      this.encryptionOptions = {
        ServerSideEncryption: 'aws:kms',
        SSEKMSKeyId: options.kmsKeyId,
      };
    }
  }

  private joinPath(...segments: string[]): string {
    const parts: string[] = [];
    segments.forEach((segment, index) => {
      if (index === 0 && segment === '') {
        return;
      }
      const normalized = normalizeSegment(segment);
      if (normalized) {
        parts.push(...normalized.split('/'));
      }
    });
    return parts.join('/');
  }

  private toKey(target: string): string {
    const normalizedTarget = normalizeSegment(target);
    const base = this.basePrefix;
    if (!base) {
      return normalizedTarget;
    }
    if (normalizedTarget === base) {
      return normalizedTarget;
    }
    if (normalizedTarget.startsWith(`${base}/`)) {
      return normalizedTarget;
    }
    throw new HttpError(500, 'PATH_OUT_OF_ROOT', 'Dosya yolu sunucu depolama alanının dışında.');
  }

  private async deleteObjects(keys: string[]): Promise<void> {
    if (keys.length === 0) {
      return;
    }
    const input: DeleteObjectsCommandInput = {
      Bucket: this.bucket,
      Delete: {
        Objects: keys.map((Key) => ({ Key })),
        Quiet: true,
      },
    };
    await this.client.send(new DeleteObjectsCommand(input));
  }

  private buildPutObjectParams(
    key: string,
    body: NodeJS.ReadableStream | Buffer | string,
  ): PutObjectCommandInput {
    return {
      Bucket: this.bucket,
      Key: key,
      Body: body,
      ...(this.encryptionOptions ?? {}),
    };
  }

  public async persistUploads(
    jobId: string,
    fileMap: UploadedFileMap,
  ): Promise<Record<string, string[]>> {
    const entries = Object.entries(fileMap);
    const result: Record<string, string[]> = {};
    const jobUploadDir = this.joinPath(this.directories.uploads, jobId);

    for (const [field, files] of entries) {
      for (const [index, file] of files.entries()) {
        const targetDir = this.joinPath(jobUploadDir, field);
        const safeName = sanitizeFileName(file.originalname, `${field}-${index}`);
        const targetPath = this.joinPath(targetDir, safeName);
        const key = this.toKey(targetPath);
        const body = createReadStream(file.path);
        await this.client.send(new PutObjectCommand(this.buildPutObjectParams(key, body)));
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
    // S3 does not require explicit directory creation; validate path is within prefix.
    this.toKey(target);
  }

  public async removeDirectory(target: string): Promise<void> {
    const key = this.toKey(target);
    const prefix = toDirectoryPrefix(key);

    if (key) {
      await this.deleteObjects([key]);
    }

    let continuationToken: string | undefined;
    do {
      const response = await this.client.send(
        new ListObjectsV2Command({
          Bucket: this.bucket,
          Prefix: prefix,
          ContinuationToken: continuationToken,
        }),
      );
      const objects = (response.Contents ?? [])
        .map((item) => item.Key)
        .filter((value): value is string => Boolean(value));
      if (objects.length > 0) {
        await this.deleteObjects(objects);
      }
      continuationToken = response.IsTruncated ? response.NextContinuationToken : undefined;
    } while (continuationToken);
  }

  public async fileExists(target: string): Promise<boolean> {
    const key = this.toKey(target);
    if (!key) {
      const response = await this.client.send(
        new ListObjectsV2Command({ Bucket: this.bucket, MaxKeys: 1 }),
      );
      return (response.Contents?.length ?? 0) > 0;
    }
    try {
      await this.client.send(new HeadObjectCommand({ Bucket: this.bucket, Key: key }));
      return true;
    } catch (error) {
      if (!isNotFoundError(error)) {
        throw error;
      }
    }
    const response = await this.client.send(
      new ListObjectsV2Command({ Bucket: this.bucket, Prefix: toDirectoryPrefix(key), MaxKeys: 1 }),
    );
    return (response.Contents?.length ?? 0) > 0;
  }

  public async openReadStream(target: string): Promise<NodeJS.ReadableStream> {
    const key = this.toKey(target);
    const response = await this.client.send(new GetObjectCommand({ Bucket: this.bucket, Key: key }));
    const body = response.Body;
    if (!body) {
      throw new HttpError(500, 'S3_EMPTY_BODY', 'S3 nesnesi boş döndü.');
    }
    if (body instanceof Readable) {
      return body;
    }
    if (body instanceof Uint8Array || typeof body === 'string') {
      return Readable.from(body);
    }
    throw new HttpError(500, 'S3_STREAM_ERROR', 'S3 akışı okunamadı.');
  }

  public async getFileInfo(target: string): Promise<{ size?: number } | undefined> {
    const key = this.toKey(target);
    try {
      const response = await this.client.send(
        new HeadObjectCommand({ Bucket: this.bucket, Key: key }),
      );
      return { size: response.ContentLength ?? undefined };
    } catch (error) {
      if (isNotFoundError(error)) {
        return undefined;
      }
      throw error;
    }
  }

  public async readJson<T>(filePath: string): Promise<T> {
    const key = this.toKey(filePath);
    const response = await this.client.send(new GetObjectCommand({ Bucket: this.bucket, Key: key }));
    if (!response.Body) {
      throw new HttpError(500, 'S3_EMPTY_BODY', 'S3 nesnesi boş döndü.');
    }
    const buffer = await streamToBuffer(response.Body as NodeJS.ReadableStream | Uint8Array | string);
    return JSON.parse(buffer.toString('utf8')) as T;
  }

  public async writeJson(filePath: string, data: unknown): Promise<void> {
    const key = this.toKey(filePath);
    const serialized = `${JSON.stringify(data, null, 2)}\n`;
    await this.client.send(
      new PutObjectCommand(this.buildPutObjectParams(key, Buffer.from(serialized, 'utf8'))),
    );
  }

  public async listSubdirectories(directory: string): Promise<string[]> {
    const key = this.toKey(directory);
    const prefix = toDirectoryPrefix(key);
    const response = await this.client.send(
      new ListObjectsV2Command({
        Bucket: this.bucket,
        Prefix: prefix,
        Delimiter: '/',
      }),
    );
    const baseLength = prefix.length;
    const commonPrefixes = response.CommonPrefixes ?? [];
    return commonPrefixes
      .map((entry) => entry.Prefix)
      .filter((value): value is string => Boolean(value))
      .map((value) => value.slice(baseLength))
      .map((value) => value.replace(/\/+$/, ''))
      .filter((value) => value.length > 0);
  }

  public toRelativePath(target: string): string {
    const normalizedTarget = normalizeSegment(target);
    const base = this.basePrefix;
    if (!base) {
      return normalizedTarget;
    }
    if (normalizedTarget === base) {
      return '';
    }
    if (normalizedTarget.startsWith(`${base}/`)) {
      return normalizedTarget.slice(base.length + 1);
    }
    throw new HttpError(500, 'PATH_OUT_OF_ROOT', 'Dosya yolu sunucu depolama alanının dışında.');
  }
}

