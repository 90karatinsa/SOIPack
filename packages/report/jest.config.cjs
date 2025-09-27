const baseConfig = require('../../jest.preset.cjs');

module.exports = {
  ...baseConfig,
  displayName: 'report',
  rootDir: __dirname,
  testMatch: ['<rootDir>/src/**/*.test.ts'],
  moduleNameMapper: {
    '^@soipack/([^/]+)(.*)$': '<rootDir>/../$1/src$2',
    '^zod$': '<rootDir>/../../test/shims/zod.ts',
    '^jszip$': '<rootDir>/../../test/shims/jszip.ts',
    '^yazl$': '<rootDir>/../../test/shims/yazl.ts',
    '^playwright$': '<rootDir>/../../test/shims/playwright.ts',
    '^html-validator$': '<rootDir>/../../test/shims/html-validator.ts',
    '^node-forge$': '<rootDir>/../../test/shims/node-forge.ts',
    '^nunjucks$': '<rootDir>/../../test/shims/nunjucks.ts',
    '^docx$': '<rootDir>/../../test/shims/docx.ts',
    '^pdfmake$': '<rootDir>/../../test/shims/pdfmake.ts',
    '^pdfmake/interfaces$': '<rootDir>/../../test/shims/pdfmake-interfaces.ts',
    '^fast-xml-parser$': '<rootDir>/../../test/shims/fast-xml-parser.ts'
  },
  transform: {
    '^.+\\.(ts|tsx)$': ['ts-jest', { tsconfig: '<rootDir>/tsconfig.test.json' }]
  }
};
