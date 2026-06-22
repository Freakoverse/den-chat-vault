import { defineConfig } from 'vite'

// The vault is served at the root of its own origin (e.g. https://vault.denchat.top/).
// Single tiny entry; no code-splitting needed — keep the trusted surface minimal.
export default defineConfig({
  base: '/',
  build: {
    target: 'es2020',
    rollupOptions: {
      output: { manualChunks: undefined },
    },
  },
})
