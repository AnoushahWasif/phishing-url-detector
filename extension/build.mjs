import { cpSync, rmSync } from "node:fs";

import { build } from "esbuild";

rmSync("dist", { recursive: true, force: true });
const common = { bundle: true, target: "chrome120", minify: false, sourcemap: false, logLevel: "info" };
// Content scripts can't be ES modules, so that one is an IIFE; the service worker is declared as a module.
await build({ ...common, entryPoints: ["src/background.ts"], outfile: "dist/background.js", format: "esm" });
await build({ ...common, entryPoints: ["src/content.ts"], outfile: "dist/content.js", format: "iife" });
cpSync("public", "dist", { recursive: true });
