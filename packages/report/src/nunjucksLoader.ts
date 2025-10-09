import { createRequire } from 'node:module';
import { readdirSync } from 'node:fs';
import path from 'node:path';

import type * as Nunjucks from 'nunjucks';

const projectRequire = createRequire(require.resolve('../../../package.json'));

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

let nunjucks: typeof Nunjucks;

try {
  nunjucks = projectRequire('nunjucks') as typeof Nunjucks;
} catch (error) {
  nunjucks = resolveFromPnpm('nunjucks') as typeof Nunjucks;
}

export default nunjucks;
