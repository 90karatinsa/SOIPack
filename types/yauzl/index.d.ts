declare module 'yauzl' {
  import { EventEmitter } from 'events';
  import { Readable } from 'stream';

  export interface Entry {
    fileName: string;
    uncompressedSize: number;
  }

  export interface ZipFile extends EventEmitter {
    readEntry(): void;
    close(): void;
    on(event: 'entry', listener: (entry: Entry) => void): this;
    on(event: 'end', listener: () => void): this;
    on(event: 'error', listener: (error: Error) => void): this;
    openReadStream(entry: Entry, callback: (error: Error | null, stream?: Readable) => void): void;
  }

  export interface OpenOptions {
    lazyEntries?: boolean;
  }

  interface YauzlModule {
    open(path: string, options: OpenOptions, callback: (error: Error | null, zipfile?: ZipFile) => void): void;
  }

  const yauzl: YauzlModule;
  export default yauzl;
}
