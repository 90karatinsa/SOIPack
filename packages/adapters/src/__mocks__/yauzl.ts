export type Entry = {
  fileName?: string;
};

export type ZipFile = {
  on: (...args: unknown[]) => void;
  openReadStream: (...args: unknown[]) => void;
  close: () => void;
};

export interface OpenOptions {
  lazyEntries?: boolean;
  autoClose?: boolean;
}

type Callback = (err: Error | null, zipfile?: ZipFile) => void;

const open = (_path: string, _options: OpenOptions, callback: Callback): void => {
  callback(new Error('yauzl stub is not implemented in tests.'));
};

const fromBuffer = (_buffer: unknown, _options: OpenOptions, callback: Callback): void => {
  callback(new Error('yauzl stub is not implemented in tests.'));
};

const yauzl = {
  open,
  fromBuffer,
};

export default yauzl;
