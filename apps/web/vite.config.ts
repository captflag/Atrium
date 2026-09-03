import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const SERVER_PORT = process.env["PORT"] ?? "8787";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      // Same-origin in development so cookie flags behave as they will in
      // production. The preview proxy gets its own origin later (SECURITY D3).
      "/api": {
        target: `http://127.0.0.1:${SERVER_PORT}`,
        changeOrigin: false,
      },
      // Realtime canvas gateway. changeOrigin stays false so the browser's
      // Origin header reaches the server, which checks it at upgrade.
      "/rt": {
        target: `http://127.0.0.1:${SERVER_PORT}`,
        ws: true,
        changeOrigin: false,
      },
    },
  },
  build: {
    sourcemap: true,
  },
});
