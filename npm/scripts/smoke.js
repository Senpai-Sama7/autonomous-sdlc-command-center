#!/usr/bin/env node
"use strict";

/**
 * smoke: verify the npm wrapper end-to-end without publishing.
 * 1. Ensures the Python sources are bundled (runs prepack if missing).
 * 2. Spawns `sdlc doctor` through the wrapper and expects a JSON result.
 * 3. Spawns `sdlc-mcp --version` and expects a version string.
 */

const { spawnSync } = require("child_process");
const path = require("path");

const pkgRoot = path.resolve(__dirname, "..");
const node = process.execPath;

function run(args, opts = {}) {
  return spawnSync(node, args, { encoding: "utf8", cwd: pkgRoot, ...opts });
}

let failures = 0;

function check(name, ok, detail) {
  const mark = ok ? "PASS" : "FAIL";
  console.log(`${mark}  ${name}${detail ? " — " + detail : ""}`);
  if (!ok) failures += 1;
}

// 1. Bundle present?
if (!require("fs").existsSync(path.join(pkgRoot, "python", "sdlc_mcp_server.py"))) {
  const pre = run([path.join(pkgRoot, "scripts", "prepack.js")]);
  check("prepack bundle", pre.status === 0, (pre.stderr || "").trim());
} else {
  check("prepack bundle", true, "already present");
}

// 2. CLI: sdlc doctor (doctor is an environment probe; it takes no --path)
const doctor = run([path.join(pkgRoot, "bin", "sdlc.js"), "doctor"]);
let doctorOk = false;
try {
  const parsed = JSON.parse(doctor.stdout);
  doctorOk = doctor.status === 0 && (parsed.status === "ok" || parsed.status === "warning");
} catch (_) {
  /* JSON parse failed */
}
check("sdlc doctor", doctorOk, doctorOk ? "JSON status ok" : (doctor.stderr || doctor.stdout || "").trim().slice(0, 120));

// 3. Server: sdlc-mcp --version
const ver = run([path.join(pkgRoot, "bin", "sdlc-mcp.js"), "--version"]);
check("sdlc-mcp --version", ver.status === 0 && /\d+\.\d+\.\d+/.test(ver.stdout + ver.stderr), (ver.stdout || ver.stderr || "").trim());

process.exit(failures ? 1 : 0);
