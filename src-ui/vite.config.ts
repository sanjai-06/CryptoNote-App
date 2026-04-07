import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

const host = process.env.TAURI_DEV_HOST;

export default defineConfig(async () => ({
  plugins: [react()],
  root: path.resolve(__dirname),
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host
      ? {
          protocol: "ws",
          host,
          port: 1421,
        }
      : undefined,
    watch: {
      ignored: ["**/src-tauri/**"],
    },
  },
  build: {
    outDir: "../dist",
    emptyOutDir: true,
  },
  envPrefix: ["VITE_", "TAURI_ENV_*"],
  define: {
    // Disable React devtools in production
    ...(process.env.NODE_ENV === "production" && {
      "window.__REACT_DEVTOOLS_GLOBAL_HOOK__": "({ isDisabled: true })",
    }),
  },
}));
