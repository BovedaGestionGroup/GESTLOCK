import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    globals: false,
  },
  server: {
    deps: {
      inline: ['@prisma/client'],
      noExternal: ['@prisma/client'],
    },
  },
});
