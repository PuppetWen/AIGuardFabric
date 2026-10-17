/// <reference types="vitest/config" />
import { fileURLToPath, URL } from 'node:url';

import react from '@vitejs/plugin-react';
import { defineConfig, loadEnv } from 'vite';

/**
 * Backend target for the dev-server proxy.
 *
 * `VITE_API_BASE_URL` wins, then `AIGUARD_BACKEND_URL` (used by docker-compose /
 * the Rust workspace), then the documented default `http://127.0.0.1:8080`.
 */
function resolveBackendTarget(mode: string): string {
  const env = loadEnv(mode, process.cwd(), '');
  return env.VITE_API_BASE_URL || env.AIGUARD_BACKEND_URL || 'http://127.0.0.1:8080';
}

export default defineConfig(({ mode }) => {
  const backend = resolveBackendTarget(mode);

  return {
    plugins: [react()],
    resolve: {
      alias: {
        '@': fileURLToPath(new URL('./src', import.meta.url)),
      },
    },
    server: {
      host: '127.0.0.1',
      port: 5173,
      strictPort: false,
      proxy: {
        '/v1/': { target: backend, changeOrigin: false },
        '/downloads/': { target: backend, changeOrigin: false },
        '/healthz': { target: backend, changeOrigin: false },
        '/api': {
          target: backend,
          changeOrigin: true,
          // The console degrades to demo data instead of exploding when the
          // Rust gateway is not running.
          configure: (proxy) => {
            proxy.on('error', () => {
              /* swallowed on purpose: see README "offline demo fallback" */
            });
          },
        },
        '/ws': {
          target: backend,
          changeOrigin: true,
          ws: true,
        },
      },
    },
    preview: {
      host: '127.0.0.1',
      port: 4173,
    },
    build: {
      outDir: 'dist',
      sourcemap: false,
      chunkSizeWarningLimit: 1600,
      rollupOptions: {
        output: {
          manualChunks: {
            react: ['react', 'react-dom', 'react-router-dom'],
            antd: ['antd', '@ant-design/icons'],
            charts: ['echarts', 'echarts-for-react'],
            graph: ['@antv/g6'],
            i18n: ['i18next', 'react-i18next'],
          },
        },
      },
    },
    test: {
      environment: 'jsdom',
      globals: true,
      setupFiles: ['./vitest.setup.ts'],
      include: ['src/**/*.test.{ts,tsx}'],
      css: false,
      restoreMocks: true,
    },
  };
});
