import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // The Worker suite only. The GUI is a separate project with its own `@/` alias and jsdom
    // setup, run by `pnpm web:test` from web/vite.config.ts.
    include: ['tests/**/*.test.ts'],
  },
});
