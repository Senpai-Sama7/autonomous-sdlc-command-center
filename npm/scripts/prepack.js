#!/usr/bin/env node
"use strict";

/**
 * prepack: bundle the Python sources into the npm package so that
 * `npx sdlc-mcp` is fully self-contained (no pip install required).
 *
 * Copies ../mcp/sdlc_*.py -> python/ inside this package directory.
 */

const fs = require("fs");
const path = require("path");

const pkgRoot = path.resolve(__dirname, "..");
const srcDir = path.resolve(pkgRoot, "..", "mcp");
const destDir = path.join(pkgRoot, "python");

if (!fs.existsSync(srcDir)) {
  console.error(`prepack: source directory not found: ${srcDir}`);
  process.exit(1);
}

fs.rmSync(destDir, { recursive: true, force: true });
fs.mkdirSync(destDir, { recursive: true });

const modules = fs.readdirSync(srcDir).filter((f) => /^sdlc_.*\.py$/.test(f));
if (modules.length === 0) {
  console.error(`prepack: no sdlc_*.py modules found in ${srcDir}`);
  process.exit(1);
}

for (const mod of modules) {
  fs.copyFileSync(path.join(srcDir, mod), path.join(destDir, mod));
}

// Record provenance for debugging.
const meta = {
  bundledAtUtc: new Date().toISOString(),
  modules: modules.sort(),
};
fs.writeFileSync(path.join(destDir, "bundle.json"), JSON.stringify(meta, null, 2) + "\n");

console.log(`prepack: bundled ${modules.length} Python modules -> ${path.relative(process.cwd(), destDir)}`);
