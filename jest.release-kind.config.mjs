/**
 * A root-level Jest config for the release-tooling tests, kept separate
 * from every package's own jest.config.js (each of which is scoped to its
 * own src/__tests__ directory and ts-jest'd, run via "pnpm -r test").
 *
 * scripts/lib/release-kind.mjs and scripts/classify-release-tag.mjs are
 * plain ESM tooling that runs before "pnpm install" in
 * .github/workflows/release.yml, so their tests are .mjs files that
 * execute as native ES modules rather than through a TypeScript
 * transform -- no per-package config covers that shape, hence this one.
 *
 * NODE_OPTIONS=--experimental-vm-modules is required to run this (see the
 * "test:release-kind" script in package.json); Jest's own ESM support is
 * still experimental as of Jest 30.
 */
export default {
  testEnvironment: 'node',
  testMatch: ['<rootDir>/scripts/tests/**/*.test.mjs'],
};
