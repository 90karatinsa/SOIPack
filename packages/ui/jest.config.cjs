const baseConfig = require('../../jest.preset.cjs');

module.exports = {
  ...baseConfig,
  displayName: 'ui',
  rootDir: __dirname,
  testEnvironment: 'jsdom',
  setupFilesAfterEnv: ['<rootDir>/jest.setup.ts'],
  testMatch: ['<rootDir>/src/**/*.test.ts?(x)'],
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1',
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
    '^fast-xml-parser$': '<rootDir>/../../test/shims/fast-xml-parser.ts',
    '^@bora/ui-kit$': '<rootDir>/src/testUtils/ui-kit.tsx'
  },
  transform: {
    '^.+\\.(ts|tsx)$': ['ts-jest', { tsconfig: '<rootDir>/tsconfig.test.json' }]
  }
};
