import { PassThrough } from 'stream';
import { readFileSync } from 'fs';

type ZipEntry = { path: string; data: Buffer };

class MockZipFile {
  outputStream: PassThrough;
  private readonly entries: ZipEntry[];

  constructor() {
    this.outputStream = new PassThrough();
    this.entries = [];
  }

  addFile(filePath: string, archivePath: string): void {
    const data = readFileSync(filePath);
    this.entries.push({ path: archivePath, data });
  }

  addBuffer(buffer: Buffer, archivePath: string): void {
    this.entries.push({ path: archivePath, data: Buffer.from(buffer) });
  }

  end(): void {
    const payload = this.entries.map((entry) => ({ path: entry.path, data: entry.data.toString('base64') }));
    this.outputStream.end(Buffer.from(JSON.stringify(payload), 'utf8'));
  }
}

export { MockZipFile as ZipFile };
