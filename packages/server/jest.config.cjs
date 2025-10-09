const path = require('path');
const baseConfig = require('../../jest.preset.cjs');

const workspaceRoot = path.resolve(__dirname, '..', '..');
if (process.cwd() !== workspaceRoot) {
  process.chdir(workspaceRoot);
}

module.exports = {
  ...baseConfig,
  displayName: 'server',
  rootDir: workspaceRoot,
  roots: ['<rootDir>/packages/server/src'],
  testMatch: ['<rootDir>/packages/server/src/**/*.test.ts'],
  moduleNameMapper: {
    '^@soipack/([^/]+)(.*)$': '<rootDir>/packages/$1/src$2',
    '^zod$': '<rootDir>/test/shims/zod.ts',
    '^pg$': '<rootDir>/test/shims/pg.ts',
    '^pg-mem$': '<rootDir>/test/shims/pg-mem.ts',
    '^@aws-sdk/client-s3$': '<rootDir>/test/shims/aws-sdk-client-s3.ts',
    '^aws-sdk-client-mock$': '<rootDir>/test/shims/aws-sdk-client-mock.ts',
    '^express-rate-limit$': '<rootDir>/test/shims/express-rate-limit.ts',
    '^helmet$': '<rootDir>/test/shims/helmet.ts',
    '^pino$': '<rootDir>/test/shims/pino.ts',
    '^prom-client$': '<rootDir>/test/shims/prom-client.ts',
    '^multer$': '<rootDir>/test/shims/multer.ts',
    '^yaml$': '<rootDir>/test/shims/yaml.ts',
    '^yazl$': '<rootDir>/test/shims/yazl.ts',
    '^saxes$': '<rootDir>/test/shims/saxes.ts',
    '^node-forge$': '<rootDir>/test/shims/node-forge.ts',
    '^tweetnacl$': '<rootDir>/test/shims/tweetnacl.ts',
    '^yauzl$': '<rootDir>/test/shims/yauzl.ts',
    '^fast-xml-parser$': '<rootDir>/test/shims/fast-xml-parser.ts',
    '^nunjucks$': '<rootDir>/test/shims/nunjucks.js',
    '^@soipack/report/src/nunjucksLoader$': '<rootDir>/test/shims/nunjucks.js',
    '^pdfmake$': '<rootDir>/test/shims/pdfmake.ts',
    '^pdfmake/interfaces$': '<rootDir>/test/shims/pdfmake-interfaces.ts',
    '^docx$': '<rootDir>/test/shims/docx.ts',
    '^jszip$': '<rootDir>/test/shims/jszip.ts'
  },
  maxWorkers: 1,
  transform: {
    '^.+\\.(ts|tsx)$': [
      'ts-jest',
      { tsconfig: '<rootDir>/packages/server/tsconfig.test.json', diagnostics: false },
    ],
  }
};
