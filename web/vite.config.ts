import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// The build goes to the API's wwwroot, so one process serves the SPA and the API (same origin: no CORS,
// and the SameSite=Strict refresh cookie works). In development Vite proxies the API.
export default defineConfig({
  plugins: [react()],
  build: { outDir: '../src/Auth.Api/wwwroot', emptyOutDir: true },
  server: {
    port: 5173,
    proxy: { '/api': 'http://localhost:8080', '/.well-known': 'http://localhost:8080' },
  },
})
