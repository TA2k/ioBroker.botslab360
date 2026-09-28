import js from '@eslint/js';
import globals from 'globals';

export default [
  {
    ignores: ['node_modules/**', 'admin/**', 'www/**', 'test/**/*.json', '.prettierrc.js', '.references/**'],
  },
  js.configs.recommended,
  {
    files: ['**/*.js'],
    languageOptions: {
      ecmaVersion: 2020,
      sourceType: 'commonjs',
      globals: {
        ...globals.node,
        ...globals.mocha,
        ...globals.es2020,
      },
    },
    rules: {
      indent: ['error', 2, { SwitchCase: 1 }],
      'no-console': 'off',
      'no-unused-vars': ['error', { ignoreRestSiblings: true, argsIgnorePattern: '^_' }],
      'no-var': 'error',
      'no-trailing-spaces': 'error',
      'prefer-const': 'error',
      quotes: ['error', 'single', { avoidEscape: true, allowTemplateLiterals: true }],
      semi: ['error', 'always'],
    },
  },
  {
    files: ['**/*.mjs'],
    languageOptions: {
      ecmaVersion: 2020,
      sourceType: 'module',
      globals: {
        ...globals.node,
      },
    },
    rules: {
      indent: ['error', 2, { SwitchCase: 1 }],
      'no-trailing-spaces': 'error',
      quotes: ['error', 'single', { avoidEscape: true, allowTemplateLiterals: true }],
      semi: ['error', 'always'],
    },
  },
];
