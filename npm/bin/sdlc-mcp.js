#!/usr/bin/env node
"use strict";

/**
 * sdlc-mcp — MCP server entry point (stdio default; --http / --http-streamable for HTTP).
 * All arguments are forwarded verbatim to sdlc_mcp_server.py.
 */

const { spawn } = require("child_process");
const path = require("path");
const { resolveOrExit } = require("../lib/resolve");

const { srcDir, py } = resolveOrExit("sdlc_mcp_server.py");

const child = spawn(py.cmd, [...py.args, path.join(srcDir, "sdlc_mcp_server.py"), ...process.argv.slice(2)], {
  stdio: "inherit",
  env: process.env,
  windowsHide: true,
});

child.on("error", (err) => {
  process.stderr.write(`sdlc-mcp: failed to launch Python: ${err.message}\n`);
  process.exit(3);
});

child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code === null ? 1 : code);
});
