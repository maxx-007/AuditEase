import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    open: true,
    cors: true,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        secure: false,
        ws: true,
        rewrite: (path) => path.replace(/^\/api/, '/api'), // Keep /api prefix
        configure: (proxy, _options) => {
          proxy.on('error', (err, _req, _res) => {
            console.error('❌ Proxy error:', err);
          });
          proxy.on('proxyReq', (proxyReq, req, _res) => {
            console.log('🔄 Proxying:', req.method, req.url, '→', 'http://localhost:8000' + req.url);
          });
          proxy.on('proxyRes', (proxyRes, req, _res) => {
            console.log('✅ Proxy response:', proxyRes.statusCode, req.url);
          });
        },
      },
      '/collect': {
        target: 'http://localhost:8000/api',
        changeOrigin: true,
        secure: false,
      },
      '/status': {
        target: 'http://localhost:8000/api',
        changeOrigin: true,
        secure: false,
      },
      '/train': {
        target: 'http://localhost:8000/api',
        changeOrigin: true,
        secure: false,
      },
      '/audit': {
        target: 'http://localhost:8000/api',
        changeOrigin: true,
        secure: false,
      },
      '/reports': {
        target: 'http://localhost:8000/api',
        changeOrigin: true,
        secure: false,
      }
    }
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    minify: 'terser',
    chunkSizeWarningLimit: 1000,
  },
  optimizeDeps: {
    include: ['three']
  }
});