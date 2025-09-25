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
    '^@bora/ui-kit$': '<rootDir>/src/testUtils/ui-kit.tsx'
  },
  transform: {
    '^.+\\.(ts|tsx)$': ['ts-jest', { tsconfig: '<rootDir>/tsconfig.test.json' }]
  }
};
