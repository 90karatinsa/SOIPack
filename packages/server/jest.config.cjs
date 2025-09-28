const baseConfig = require('../../jest.preset.cjs');

module.exports = {
  ...baseConfig,
  displayName: 'server',
  rootDir: __dirname,
  testMatch: ['<rootDir>/src/**/*.test.ts'],
  moduleNameMapper: {
    '^@soipack/([^/]+)(.*)$': '<rootDir>/../$1/src$2',
    '^zod$': '<rootDir>/../../test/shims/zod.ts',
    '^pg$': '<rootDir>/../../test/shims/pg.ts'
  },
  transform: {
    '^.+\\.(ts|tsx)$': ['ts-jest', { tsconfig: '<rootDir>/tsconfig.test.json' }]
  }
};
