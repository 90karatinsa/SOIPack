import { promises as fsPromises } from 'fs';
import os from 'os';
import path from 'path';
import { Readable } from 'stream';

import {
  DeleteObjectsCommand,
  GetObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';
import { mockClient } from 'aws-sdk-client-mock';

import { S3StorageProvider } from './s3';

const readBody = async (body: unknown): Promise<string> => {
  if (body instanceof Readable) {
    const chunks: Buffer[] = [];
    for await (const chunk of body) {
      chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : Buffer.from(chunk));
    }
    return Buffer.concat(chunks).toString('utf8');
  }
  if (body instanceof Uint8Array) {
    return Buffer.from(body).toString('utf8');
  }
  if (typeof body === 'string') {
    return body;
  }
  throw new Error('Unsupported body type');
};

describe('S3StorageProvider', () => {
  const s3Mock = mockClient(S3Client);
  let client: S3Client;

  beforeEach(() => {
    s3Mock.reset();
    client = new S3Client({ region: 'us-east-1' });
  });

  it('persistUploads uploads sanitized files and removes temporary sources', async () => {
    const tmpDir = await fsPromises.mkdtemp(path.join(os.tmpdir(), 's3-storage-'));
    const filePath = path.join(tmpDir, 'payload.bin');
    await fsPromises.writeFile(filePath, 'payload');

    s3Mock.on(PutObjectCommand).resolves({});

    const storage = new S3StorageProvider({
      bucket: 'test-bucket',
      prefix: 'tenant-data',
      kmsKeyId: 'kms-key-123',
      client,
    });

    const persisted = await storage.persistUploads('acme/job-1', {
      input: [
        {
          originalname: ' report.txt ',
          path: filePath,
        },
      ],
    });

    expect(persisted).toEqual({
      input: ['tenant-data/uploads/acme/job-1/input/_report.txt_'],
    });

    const putCalls = s3Mock.commandCalls(PutObjectCommand);
    expect(putCalls).toHaveLength(1);
    const putInput = putCalls[0].args[0].input;
    expect(putInput.Bucket).toBe('test-bucket');
    expect(putInput.Key).toBe('tenant-data/uploads/acme/job-1/input/_report.txt_');
    expect(putInput.ServerSideEncryption).toBe('aws:kms');
    expect(putInput.SSEKMSKeyId).toBe('kms-key-123');
    expect(await readBody(putInput.Body)).toBe('payload');

    await expect(fsPromises.access(filePath)).rejects.toThrow();
    await fsPromises.rm(tmpDir, { recursive: true, force: true });
  });

  it('writeJson and readJson round-trip data through S3', async () => {
    const storage = new S3StorageProvider({
      bucket: 'test-bucket',
      prefix: 'tenant-data',
      client,
    });

    const payload = { ok: true };
    const serialized = `${JSON.stringify(payload, null, 2)}\n`;

    s3Mock.on(PutObjectCommand).resolves({});
    s3Mock
      .on(GetObjectCommand)
      .resolves({ Body: Readable.from([serialized]) })
      .resolves({ Body: Readable.from([serialized]) });

    await storage.writeJson('tenant-data/ledgers/acme.json', payload);
    const written = s3Mock.commandCalls(PutObjectCommand)[0].args[0].input;
    expect(await readBody(written.Body)).toBe(serialized);

    const roundTripped = await storage.readJson<typeof payload>('tenant-data/ledgers/acme.json');
    expect(roundTripped).toEqual(payload);
  });

  it('listSubdirectories returns folder names beneath a prefix', async () => {
    const storage = new S3StorageProvider({
      bucket: 'test-bucket',
      prefix: 'tenant-data',
      client,
    });

    s3Mock.on(ListObjectsV2Command).resolves({
      CommonPrefixes: [
        { Prefix: 'tenant-data/uploads/acme/job-1/' },
        { Prefix: 'tenant-data/uploads/acme/job-2/' },
      ],
    });

    const subdirectories = await storage.listSubdirectories('tenant-data/uploads/acme');
    expect(subdirectories).toEqual(['job-1', 'job-2']);

    const listCall = s3Mock.commandCalls(ListObjectsV2Command)[0].args[0].input;
    expect(listCall.Prefix).toBe('tenant-data/uploads/acme/');
    expect(listCall.Delimiter).toBe('/');
  });

  it('removeDirectory deletes all matching objects across pages', async () => {
    const storage = new S3StorageProvider({
      bucket: 'test-bucket',
      prefix: 'tenant-data',
      client,
    });

    s3Mock
      .on(ListObjectsV2Command)
      .resolvesOnce({
        Contents: [
          { Key: 'tenant-data/uploads/acme/job-1/file-a' },
          { Key: 'tenant-data/uploads/acme/job-1/file-b' },
        ],
        IsTruncated: true,
        NextContinuationToken: 'next-token',
      })
      .resolvesOnce({
        Contents: [{ Key: 'tenant-data/uploads/acme/job-1/file-c' }],
        IsTruncated: false,
      });

    s3Mock.on(DeleteObjectsCommand).resolves({});

    await storage.removeDirectory('tenant-data/uploads/acme/job-1');

    const deleteCalls = s3Mock.commandCalls(DeleteObjectsCommand);
    expect(deleteCalls).toHaveLength(3);

    expect(deleteCalls[0].args[0].input.Delete?.Objects).toEqual([
      { Key: 'tenant-data/uploads/acme/job-1' },
    ]);

    expect(deleteCalls[1].args[0].input.Delete?.Objects).toEqual([
      { Key: 'tenant-data/uploads/acme/job-1/file-a' },
      { Key: 'tenant-data/uploads/acme/job-1/file-b' },
    ]);

    expect(deleteCalls[2].args[0].input.Delete?.Objects).toEqual([
      { Key: 'tenant-data/uploads/acme/job-1/file-c' },
    ]);
  });
});

