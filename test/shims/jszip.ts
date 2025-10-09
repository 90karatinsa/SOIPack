import { createRequire } from 'module';
import { readdirSync } from 'node:fs';
import path from 'node:path';

const projectRequire = createRequire(require.resolve('../../package.json'));

const resolveFromPnpm = (moduleName: string): unknown => {
  const pnpmDir = path.resolve(__dirname, '../../node_modules/.pnpm');
  const entries = readdirSync(pnpmDir, { withFileTypes: true });
  const match = entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .find((entry) => entry.startsWith(`${moduleName}@`));
  if (!match) {
    throw new Error(`Unable to locate ${moduleName} in pnpm store`);
  }
  const modulePath = path.join(pnpmDir, match, 'node_modules', moduleName);
  return projectRequire(modulePath);
};

let jszip: any;

try {
  jszip = projectRequire('jszip');
} catch (error) {
  jszip = resolveFromPnpm('jszip');
}

Object.defineProperty(jszip, '__esModule', { value: true });
jszip.default = jszip;

export = jszip;
