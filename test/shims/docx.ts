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

let docx: any;

try {
  docx = projectRequire('docx');
} catch (error) {
  docx = resolveFromPnpm('docx');
}

Object.defineProperty(docx, '__esModule', { value: true });
docx.default = docx;

if (!docx.HeadingLevel) {
  docx.HeadingLevel = {
    TITLE: 'TITLE',
    HEADING_1: 'HEADING_1',
    HEADING_2: 'HEADING_2',
    HEADING_3: 'HEADING_3',
    HEADING_4: 'HEADING_4',
    HEADING_5: 'HEADING_5',
    HEADING_6: 'HEADING_6',
  };
}

export = docx;
