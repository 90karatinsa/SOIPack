import { PassThrough } from 'stream';

class MockZipFile {
  outputStream: PassThrough;

  constructor() {
    this.outputStream = new PassThrough();
  }

  addFile(): void {
    // no-op for tests
  }

  addBuffer(): void {
    // no-op for tests
  }

  end(): void {
    this.outputStream.end();
  }
}

export { MockZipFile as ZipFile };
