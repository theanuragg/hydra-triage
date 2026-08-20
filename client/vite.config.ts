import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev: `npm run dev` here (port 5174) proxies /api to webServer.ts (port
// 5173), so the React app and the pipeline server are two independent
// processes — the server has zero knowledge of Vite, the client has zero
// knowledge of how the scan runs. Prod: `npm run build` emits static
// files to dist/, which webServer.ts serves directly (see src/webServer.ts).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5174,
    proxy: {
      "/api": "http://127.0.0.1:5173",
    },
  },
  build: {
    outDir: "dist",
  },
});
