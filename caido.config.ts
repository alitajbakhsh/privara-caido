import { defineConfig } from "@caido-community/dev";

// Privara iOS kit for Caido. Built with
// `npx caido-dev build` (see build.sh) into dist/plugin_package.zip.
export default defineConfig({
  id: "privara-ios-kit",
  name: "Privara iOS kit",
  description: "Privara iOS Analysis inside Caido: API map to Replay and scope, request forging, findings.",
  version: "2026.11.13",
  author: {
    name: "TAJ APPS LLC",
    url: "https://tajapps.com",
  },
  plugins: [
    {
      kind: "backend",
      id: "backend",
      root: "packages/backend",
    },
    {
      kind: "frontend",
      id: "frontend",
      root: "packages/frontend",
      backend: {
        id: "backend",
      },
    },
  ],
});
