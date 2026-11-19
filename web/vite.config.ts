import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// During development, run "certower serve" on :8080 and "npm run dev".
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: { "/api": "http://localhost:8080" },
  },
  build: {
    outDir: "dist",
    emptyOutDir: false, // keep dist/.gitkeep for the Go embed
    sourcemap: false,
  },
});
