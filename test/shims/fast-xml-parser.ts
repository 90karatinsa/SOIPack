import { createRequire } from 'module';

const requireActual = createRequire(require.resolve('../../packages/adapters/package.json'));

const parser: any = requireActual('fast-xml-parser');

Object.defineProperty(parser, '__esModule', { value: true });
parser.default = parser;

export = parser;
