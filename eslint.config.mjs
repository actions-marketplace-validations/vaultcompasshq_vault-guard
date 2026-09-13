import js from '@eslint/js';
import tseslint from '@typescript-eslint/eslint-plugin';
import tsparser from '@typescript-eslint/parser';

export default [
  {
    ignores: [
      'node_modules/**',
      'bench/fixtures/**',
      'packages/mcp/scripts/**',
      'packages/**/dist/**',
      'packages/**/build/**',
      'packages/**/coverage/**',
      '**/*.test.ts',
      '**/*.spec.ts',
      '**/*.d.ts',
      '**/*.d.ts.map',
      '**/*.js.map',
      '**/jest.config.js',
      '**/jest.config.cjs',
    ],
  },
  js.configs.recommended,
  {
    files: ['packages/**/*.ts'],
    languageOptions: {
      parser: tsparser,
      parserOptions: {
        ecmaVersion: 2022,
        sourceType: 'module',
      },
      globals: {
        console: 'readonly',
        process: 'readonly',
        Buffer: 'readonly',
        __dirname: 'readonly',
        __filename: 'readonly',
        module: 'readonly',
        require: 'readonly',
        exports: 'readonly',
      },
    },
    plugins: {
      '@typescript-eslint': tseslint,
    },
    rules: {
      ...tseslint.configs.recommended.rules,
      '@typescript-eslint/no-unused-vars': 'error',
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/explicit-function-return-type': 'off',
      '@typescript-eslint/explicit-module-boundary-types': 'off',
      '@typescript-eslint/no-non-null-assertion': 'warn',
      'no-console': 'off',
      'no-undef': 'off',
    },
  },
  {
    files: ['scripts/**/*.cjs', 'bench/**/*.cjs'],
    languageOptions: {
      sourceType: 'script',
      globals: {
        __dirname: 'readonly',
        __filename: 'readonly',
        console: 'readonly',
        process: 'readonly',
        require: 'readonly',
        module: 'readonly',
        exports: 'writable',
        // The action-install dogfood harness runs HTTP servers and a timeout
        // around each spawned step, so it reaches for the globals a plain
        // script-transform never needed.
        Buffer: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        setInterval: 'readonly',
        clearInterval: 'readonly',
        URL: 'readonly',
      },
    },
  },
  {
    // scripts/lib/release-kind.mjs and scripts/classify-release-tag.mjs:
    // plain ESM tooling for .github/workflows/release.yml, run before
    // "pnpm install" so it has no build step ahead of it.
    files: ['scripts/**/*.mjs'],
    languageOptions: {
      sourceType: 'module',
      ecmaVersion: 2022,
      globals: {
        console: 'readonly',
        process: 'readonly',
      },
    },
  },
  {
    // The release-kind test suite, run under jest.release-kind.config.mjs
    // (see "test:release-kind" in package.json) rather than through any
    // package's own ts-jest config, so it needs jest's own globals added
    // explicitly here the way the TypeScript test files get them for free
    // from @types/jest.
    files: ['scripts/tests/**/*.test.mjs'],
    languageOptions: {
      globals: {
        describe: 'readonly',
        it: 'readonly',
        test: 'readonly',
        expect: 'readonly',
        beforeAll: 'readonly',
        beforeEach: 'readonly',
        afterAll: 'readonly',
        afterEach: 'readonly',
        jest: 'readonly',
      },
    },
  },
];
