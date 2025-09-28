import { createRequire } from 'module';

const requireActual = createRequire(require.resolve('../../packages/report/package.json'));

const jszip: any = requireActual('jszip');

Object.defineProperty(jszip, '__esModule', { value: true });
jszip.default = jszip;

export = jszip;
