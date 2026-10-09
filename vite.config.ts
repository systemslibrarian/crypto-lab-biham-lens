import { defineConfig } from 'vite'

export default defineConfig({
  base: '/crypto-lab-biham-lens/',
  server: {
    port: 5173,
    open: true
  },
  build: {
    target: 'es2020',
    outDir: 'dist',
    sourcemap: true
  }
})
