import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "../static/dist",
    emptyOutDir: true,
  },
  server: {
    host: "0.0.0.0",
    port: 5173,

    proxy: {
      "/api": {
        target: "http://pyapp:5000",
        changeOrigin: true,
      },
      "/download": {
        target: "http://pyapp:5000",
        changeOrigin: true,
      },
      "/view": {
        target: "http://pyapp:5000",
        changeOrigin: true,
      },
    },
  },
});