import { createRequire } from 'module';

const requireActual = createRequire(require.resolve('../../packages/report/package.json'));

const nunjucks: any = requireActual('nunjucks');

Object.defineProperty(nunjucks, '__esModule', { value: true });
nunjucks.default = nunjucks;

export = nunjucks;
