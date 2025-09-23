const baseConfig = require('../../jest.preset.cjs');

module.exports = {
  ...baseConfig,
  displayName: 'report',
  rootDir: __dirname,
  testMatch: ['<rootDir>/src/**/*.test.ts'],
  moduleNameMapper: {
    '^@soipack/([^/]+)(.*)$': '<rootDir>/../$1/src$2',
    '^zod$': '<rootDir>/../core/node_modules/zod'
  },
  transform: {
    '^.+\\.(ts|tsx)$': ['ts-jest', { tsconfig: '<rootDir>/tsconfig.test.json' }]
  }
};
