import { defineConfig } from 'vitest/config'
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    // Reporting only (item 4 of the post-0.2.0 additive pass) — no
    // `thresholds` are set here deliberately: a threshold that could fail
    // CI is explicitly out of scope for this pass (the task is "coverage
    // with a threshold in CI" from the gap survey, but the acceptance bar
    // for THIS change is narrower: `npm run test:coverage` runs and
    // reports, it must never turn a currently-green CI run red). Add
    // `coverage.thresholds` in a later, deliberate change if that's wanted.
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.test.ts'],
    },
  },
})
