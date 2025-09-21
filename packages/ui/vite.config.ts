import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [react()],
  define: {
    __VITE_ENV__: 'import.meta.env'
  },
  server: {
    port: 5173,
    host: '0.0.0.0'
  }
});
