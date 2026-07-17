// Standalone Vite config to preview the renderer UI in a browser (no Electron).
// Uses the dev API mock installed in main.tsx. Not used for production builds.
import { resolve } from 'path'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  root: resolve(__dirname, 'src/renderer'),
  plugins: [react()],
  resolve: {
    alias: {
      '@renderer': resolve(__dirname, 'src/renderer/src'),
      '@shared': resolve(__dirname, 'src/shared')
    }
  },
  server: {
    port: 5199,
    strictPort: true
  }
})
