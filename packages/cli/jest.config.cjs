const baseConfig = require('../../jest.preset.cjs');

module.exports = {
  ...baseConfig,
  displayName: 'cli',
  rootDir: __dirname,
  testMatch: ['<rootDir>/src/**/*.test.ts'],
  moduleNameMapper: {
    '^@soipack/([^/]+)(.*)$': '<rootDir>/../$1/src$2',
    '^zod$': '<rootDir>/../../test/shims/zod.ts',
    '^tweetnacl$': '<rootDir>/../../test/shims/tweetnacl.ts',
    '^yauzl$': '<rootDir>/../../test/shims/yauzl.ts',
    '^jszip$': '<rootDir>/../../test/shims/jszip.ts',
    '^yazl$': '<rootDir>/../../test/shims/yazl.ts',
    '^pdfmake$': '<rootDir>/../../test/shims/pdfmake.ts',
    '^pdfmake/interfaces$': '<rootDir>/../../test/shims/pdfmake-interfaces.ts',
    '^node-forge$': '<rootDir>/../../test/shims/node-forge.ts',
    '^nunjucks$': '<rootDir>/../../test/shims/nunjucks.js',
    '^saxes$': '<rootDir>/../../test/shims/saxes.ts',
    '^fast-xml-parser$': '<rootDir>/../../test/shims/fast-xml-parser.ts',
    '^@soipack/report/src/nunjucksLoader$': '<rootDir>/../../test/shims/nunjucks.js',
    '^docx$': '<rootDir>/../../test/shims/docx.ts',
    '^yaml$': '<rootDir>/../../test/shims/yaml.ts',
    '^pino$': '<rootDir>/../../test/shims/pino.ts',
  },
  transform: {
    '^.+\\.(ts|tsx)$': [
      'ts-jest',
      { tsconfig: '<rootDir>/tsconfig.test.json', diagnostics: false }
    ]
  }
};
