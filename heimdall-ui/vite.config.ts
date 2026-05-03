import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// React Compiler — auto-memoization for React 19+.
// https://react.dev/learn/react-compiler
const reactCompilerConfig = {
  // Target React 19.
  target: "19",
  // Annotate-only mode: false → compile every component.
  // Set to "annotation" if you want to opt-in per file with "use memo".
  compilationMode: "infer",
} as const;

export default defineConfig({
  plugins: [
    react({
      babel: {
        plugins: [["babel-plugin-react-compiler", reactCompilerConfig]],
      },
    }),
  ],

  server: {
    // Proxy /api/* to the running heimdall daemon during dev.
    proxy: {
      "/api": {
        target: "http://localhost:9999",
        changeOrigin: true,
        ws: true,
      },
    },
  },

  build: {
    target: "es2022",
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
    cssCodeSplit: false,
    rollupOptions: {
      output: {
        // Stable filenames (no content hash) so rust-embed picks them up
        // deterministically across builds. We deliberately accept worse
        // browser caching here — heimdall is on a single host, low traffic.
        entryFileNames: "assets/[name].js",
        chunkFileNames: "assets/[name]-[hash].js",
        assetFileNames: "assets/[name][extname]",
      },
    },
  },
});
