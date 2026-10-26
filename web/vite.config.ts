import path from 'node:path';
import { fileURLToPath } from 'node:url';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

const rootDir = fileURLToPath(new URL('.', import.meta.url));

export default defineConfig({
  // The Worker serves this bundle under /web/, so every emitted URL is relative to that prefix.
  base: '/web/',
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(rootDir, 'src'),
      // The pages only import types from the vendored SDK; the runtime comes from the provider below.
      'auth-mini/sdk': path.resolve(rootDir, 'src/sdk'),
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: './src/test/setup.ts',
    server: {
      deps: { inline: ['auth-mini-react-components'] },
    },
  },
});
