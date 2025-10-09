import { EventEmitter } from 'events';
import { Readable } from 'stream';

export interface Entry {
  fileName: string;
  uncompressedSize: number;
}

export class ZipFile extends EventEmitter {
  readEntry(): void {
    this.emit('end');
  }

  openReadStream(_entry: Entry, callback: (error: Error | null, stream?: Readable) => void): void {
    callback(new Error('Mock ZipFile does not provide entry streams.'));
  }

  close(): void {
    this.removeAllListeners();
  }
}

export const open = (
  _path: string,
  _options: unknown,
  callback: (error: Error | null, zipfile?: ZipFile) => void,
): void => {
  callback(null, new ZipFile());
};

const yauzl = { open };

export default yauzl;
