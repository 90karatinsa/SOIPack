module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  parserOptions: {
    project: null,
    tsconfigRootDir: __dirname,
    sourceType: 'module'
  },
  env: {
    es2022: true,
    node: true,
    jest: true
  },
  plugins: ['@typescript-eslint', 'import'],
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:import/recommended',
    'plugin:import/typescript',
    'prettier'
  ],
  rules: {
    'import/order': [
      'error',
      {
        'newlines-between': 'always',
        alphabetize: { order: 'asc', caseInsensitive: true }
      }
    ],
    'import/no-unresolved': 'off'
  },
  ignorePatterns: ['dist', 'node_modules']
};
