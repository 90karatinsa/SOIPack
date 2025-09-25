import path from 'path';
import { PassThrough, Readable } from 'stream';

import type { Entry, ZipFile } from 'yauzl';
import yauzl from 'yauzl';

import { parseReqifFromReadable, parseReqifStream } from './adapters/reqif';
import { ParseResult, ReqIFRequirement } from './types';

const MAX_REQIF_ARCHIVE_SIZE = 50 * 1024 * 1024;

const openZipFile = (location: string): Promise<ZipFile> =>
  new Promise((resolve, reject) => {
    yauzl.open(location, { lazyEntries: true }, (error: Error | null, zipfile?: ZipFile) => {
      if (error || !zipfile) {
        reject(new Error(`Unable to open ReqIF archive at ${location}: ${(error as Error)?.message ?? ''}`.trim()));
        return;
      }
      resolve(zipfile);
    });
  });

const findReqifEntry = (zipfile: ZipFile): Promise<Entry | undefined> =>
  new Promise((resolve, reject) => {
    const cleanup = (): void => {
      zipfile.removeListener('entry', handleEntry);
      zipfile.removeListener('end', handleEnd);
      zipfile.removeListener('error', handleError);
    };

    const handleEntry = (entry: Entry): void => {
      if (/\.reqif$/iu.test(entry.fileName) && !entry.fileName.endsWith('/')) {
        cleanup();
        resolve(entry);
        return;
      }
      zipfile.readEntry();
    };

    const handleEnd = (): void => {
      cleanup();
      resolve(undefined);
    };

    const handleError = (error: Error): void => {
      cleanup();
      reject(error);
    };

    zipfile.on('entry', handleEntry);
    zipfile.on('end', handleEnd);
    zipfile.on('error', handleError);
    zipfile.readEntry();
  });

const openEntryStream = (zipfile: ZipFile, entry: Entry): Promise<Readable> =>
  new Promise((resolve, reject) => {
    zipfile.openReadStream(entry, (error: Error | null, stream?: Readable) => {
      if (error || !stream) {
        reject(error ?? new Error(`Unable to read entry ${entry.fileName}`));
        return;
      }
      resolve(stream);
    });
  });

const parseReqifArchive = async (filePath: string): Promise<ParseResult<ReqIFRequirement[]>> => {
  const location = path.resolve(filePath);
  const zipfile = await openZipFile(location);
  try {
    const entry = await findReqifEntry(zipfile);
    if (!entry) {
      throw new Error(`ReqIF archive at ${location} does not contain a .reqif document.`);
    }
    if (entry.uncompressedSize > MAX_REQIF_ARCHIVE_SIZE) {
      throw new Error(
        `ReqIF archive entry ${entry.fileName} exceeds maximum allowed size of ${MAX_REQIF_ARCHIVE_SIZE} bytes.`,
      );
    }

    const stream = await openEntryStream(zipfile, entry);
    const guard = new PassThrough();
    let total = 0;

    stream.on('data', (chunk: Buffer | string) => {
      const size = Buffer.isBuffer(chunk) ? chunk.length : Buffer.byteLength(chunk);
      total += size;
      if (total > MAX_REQIF_ARCHIVE_SIZE) {
        stream.destroy(
          new Error(
            `ReqIF archive entry ${entry.fileName} exceeds maximum allowed size of ${MAX_REQIF_ARCHIVE_SIZE} bytes.`,
          ),
        );
      }
    });

    stream.on('error', (error) => {
      guard.destroy(error as Error);
    });

    stream.pipe(guard);
    const result = await parseReqifFromReadable(guard, `${location}::${entry.fileName}`);
    return result;
  } finally {
    zipfile.close();
  }
};

const isReqifArchive = (filePath: string): boolean => filePath.toLowerCase().endsWith('.reqifz');

export const importReqIF = async (filePath: string): Promise<ParseResult<ReqIFRequirement[]>> => {
  try {
    if (isReqifArchive(filePath)) {
      return await parseReqifArchive(filePath);
    }
    return await parseReqifStream(filePath);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { data: [], warnings: [message] };
  }
};
