#!/usr/bin/env node
"use strict";

/**
 * sdlc — human-facing CLI entry point (doctor, risk, dashboard, write, ...).
 * All arguments are forwarded verbatim to sdlc_cli.py.
 */

const { spawn } = require("child_process");
const path = require("path");
const { resolveOrExit } = require("../lib/resolve");

const { srcDir, py } = resolveOrExit("sdlc_cli.py");

const child = spawn(py.cmd, [...py.args, path.join(srcDir, "sdlc_cli.py"), ...process.argv.slice(2)], {
  stdio: "inherit",
  env: process.env,
  windowsHide: true,
});

child.on("error", (err) => {
  process.stderr.write(`sdlc: failed to launch Python: ${err.message}\n`);
  process.exit(3);
});

child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code === null ? 1 : code);
});
