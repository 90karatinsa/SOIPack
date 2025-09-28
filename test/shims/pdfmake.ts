import { createRequire } from 'module';

const requireActual = createRequire(require.resolve('../../packages/report/package.json'));

const pdfmake: any = requireActual('pdfmake');

Object.defineProperty(pdfmake, '__esModule', { value: true });
pdfmake.default = pdfmake;

export = pdfmake;
