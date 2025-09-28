import { createRequire } from 'module';

const requireActual = createRequire(require.resolve('../../packages/packager/package.json'));

const forge: any = requireActual('node-forge');

Object.defineProperty(forge, '__esModule', { value: true });
forge.default = forge;

export = forge;
