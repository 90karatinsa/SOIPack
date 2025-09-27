declare module 'yazl' {
  import { Readable } from 'stream';

  export class ZipFile {
    outputStream: Readable;
    addFile(srcPath: string, metadataPath: string): void;
    addBuffer(buffer: Buffer, metadataPath: string): void;
    end(): void;
  }
}
