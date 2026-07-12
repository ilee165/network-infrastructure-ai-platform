/**
 * Wave 5 / perf #5 bite gate: production build must emit ≥2 JS chunks so
 * route-level code-splitting cannot silently regress to a single bundle.
 *
 * Usage (from frontend/): node scripts/check-chunk-split.mjs
 * Expects vite to have written dist/assets/*.js (run `npm run build` first).
 */
import { readdirSync } from "node:fs";
import { join } from "node:path";

const assetsDir = join(process.cwd(), "dist", "assets");
let files;
try {
  files = readdirSync(assetsDir).filter((f) => f.endsWith(".js"));
} catch (err) {
  console.error(`check-chunk-split: cannot read ${assetsDir}: ${err}`);
  process.exit(1);
}

if (files.length < 2) {
  console.error(
    `check-chunk-split BITE: expected ≥2 JS chunks in dist/assets, found ${files.length}: ${files.join(", ") || "(none)"}`,
  );
  process.exit(1);
}

console.log(`check-chunk-split OK: ${files.length} JS chunks (${files.join(", ")})`);
