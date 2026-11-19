import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig, loadEnv } from 'vite'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), 'LUNISCAN_')
  const target = new URL(env.LUNISCAN_API_PROXY_TARGET || 'http://127.0.0.1:8000')
  if (!['http:', 'https:'].includes(target.protocol) || target.pathname !== '/' || target.search || target.hash ||
      target.username || target.password) {
    throw new Error('LUNISCAN_API_PROXY_TARGET must be an HTTP or HTTPS origin without a path, credentials, or query.')
  }
  const proxy = {
    '^/api(?:/|$)': { target: target.origin, changeOrigin: false },
  }
  const headers = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
  }

  return {
    plugins: [react(), tailwindcss()],
    server: { host: '127.0.0.1', cors: false, headers, proxy },
    preview: {
      host: '127.0.0.1', strictPort: true, cors: false, proxy,
      headers: {
        ...headers,
        'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
      },
    },
  }
})
