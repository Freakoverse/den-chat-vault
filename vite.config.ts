import { defineConfig } from 'vite'
import tailwindcss from '@tailwindcss/vite'

// The vault is served at the root of its own origin (e.g. https://vault.denchat.top/).
// Single tiny entry; no code-splitting needed — keep the trusted surface minimal.
// Tailwind is build-time only (static CSS, no runtime JS) so it adds no attack surface.
export default defineConfig({
  base: '/',
  plugins: [tailwindcss()],
  build: {
    target: 'es2020',
    rollupOptions: {
      output: { manualChunks: undefined },
    },
  },
})
