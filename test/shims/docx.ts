import { createRequire } from 'module';

const requireActual = createRequire(require.resolve('../../packages/report/package.json'));

const docx: any = requireActual('docx');

Object.defineProperty(docx, '__esModule', { value: true });
docx.default = docx;

export = docx;
