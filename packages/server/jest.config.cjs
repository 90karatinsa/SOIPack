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
    '^pg$': '<rootDir>/test/shims/pg.ts'
  },
  transform: {
    '^.+\\.(ts|tsx)$': [
      'ts-jest',
      { tsconfig: '<rootDir>/packages/server/tsconfig.test.json', diagnostics: false },
    ],
  }
};
