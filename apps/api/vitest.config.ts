import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    globals: false,
    testTimeout: 30000,
  },
  server: {
    deps: {
      inline: ['@prisma/client'],
      noExternal: ['@prisma/client'],
    },
  },
});
