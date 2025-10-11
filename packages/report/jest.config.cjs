const baseConfig = require('../../jest.preset.cjs');

module.exports = {
  ...baseConfig,
  displayName: 'report',
  rootDir: __dirname,
  testMatch: ['<rootDir>/src/**/*.test.ts'],
  moduleNameMapper: {
    '^@soipack/([^/]+)(.*)$': '<rootDir>/../$1/src$2',
    '^zod$': '<rootDir>/../../test/shims/zod.ts',
    '^yazl$': '<rootDir>/../../test/shims/yazl.ts',
    '^playwright$': '<rootDir>/../../test/shims/playwright.ts',
    '^html-validator$': '<rootDir>/../../test/shims/html-validator.ts',
    '^node-forge$': '<rootDir>/../../test/shims/node-forge.ts',
    '^fast-xml-parser$': '<rootDir>/../../test/shims/fast-xml-parser.ts',
    '^jszip$': '<rootDir>/node_modules/jszip/dist/jszip.js',
    '^docx$': '<rootDir>/node_modules/docx/build/index.cjs'
  },
  transform: {
    '^.+\\.(ts|tsx)$': ['ts-jest', { tsconfig: '<rootDir>/tsconfig.test.json' }]
  }
};
