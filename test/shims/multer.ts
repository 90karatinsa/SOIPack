type FieldDescriptor = { name: string; maxCount?: number };

type MulterMiddleware = (...args: unknown[]) => void;

type MulterInstance = {
  fields: (_fields: FieldDescriptor[]) => MulterMiddleware;
};

type MulterFunction = ((config?: unknown) => MulterInstance) & {
  diskStorage: (_options: unknown) => Record<string, unknown>;
};

type MulterMockFile = {
  fieldname: string;
  originalname: string;
  encoding: string;
  mimetype: string;
  size: number;
  destination?: string;
  filename?: string;
  path: string;
  buffer?: Buffer;
};

type MulterMockFileMap = Record<string, MulterMockFile[]>;

let pendingFiles: MulterMockFileMap | undefined;

const setMockFiles = (files: MulterMockFileMap | undefined): void => {
  pendingFiles = files;
};

const createMulter: MulterFunction = ((_: unknown) => ({
  fields: () => (req: { files?: MulterMockFileMap }, _res: unknown, next: () => void) => {
    const files = pendingFiles;
    pendingFiles = undefined;
    req.files = files ?? {};
    next();
  },
})) as MulterFunction;

createMulter.diskStorage = (_options: unknown) => ({}) as Record<string, unknown>;
(createMulter as MulterFunction & { __setMockFiles?: typeof setMockFiles }).__setMockFiles = setMockFiles;

export const __setMockMulterFiles = setMockFiles;
export type { MulterMockFile, MulterMockFileMap };

export default createMulter;
