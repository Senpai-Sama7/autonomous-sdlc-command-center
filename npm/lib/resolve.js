"use strict";

/**
 * Shared resolution logic for the sdlc-mcp npm wrapper.
 *
 * The actual MCP server is written in dependency-free Python (3.9+).
 * This wrapper locates the bundled Python sources and a suitable
 * Python interpreter, then spawns the requested entry point.
 */

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const PKG_ROOT = path.resolve(__dirname, "..");

/**
 * Locate the directory containing the Python modules.
 * Search order:
 *   1. SDLC_PYTHON_HOME environment variable (explicit override)
 *   2. <pkg>/python  (bundled at npm pack time)
 *   3. <pkg>/../mcp  (running from a repo checkout)
 */
function findPythonSources(entryPoint) {
  const candidates = [];
  if (process.env.SDLC_PYTHON_HOME) {
    candidates.push(process.env.SDLC_PYTHON_HOME);
  }
  candidates.push(path.join(PKG_ROOT, "python"));
  candidates.push(path.join(PKG_ROOT, "..", "mcp"));

  for (const dir of candidates) {
    try {
      if (fs.statSync(path.join(dir, entryPoint)).isFile()) {
        return dir;
      }
    } catch (_) {
      /* keep looking */
    }
  }
  return null;
}

/**
 * Candidate interpreter commands, in preference order.
 * On Windows the `py` launcher is the most reliable discovery mechanism.
 */
function interpreterCandidates() {
  if (process.env.SDLC_PYTHON) {
    return [process.env.SDLC_PYTHON];
  }
  return process.platform === "win32"
    ? ["python", "python3", "py"]
    : ["python3", "python"];
}

/**
 * Find a Python interpreter >= 3.9. Returns { cmd, args, version } or null.
 */
function findPython() {
  for (const cmd of interpreterCandidates()) {
    // `py` on Windows needs `-3` to select Python 3.
    const prefix = cmd === "py" ? ["-3"] : [];
    const probe = spawnSync(cmd, [...prefix, "-c", "import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}')"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      windowsHide: true,
    });
    if (probe.error || probe.status !== 0) continue;
    const match = /^(\d+)\.(\d+)/.exec((probe.stdout || "").trim());
    if (!match) continue;
    const major = Number(match[1]);
    const minor = Number(match[2]);
    if (major === 3 && minor >= 9) {
      return { cmd, args: prefix, version: `${major}.${minor}` };
    }
  }
  return null;
}

/**
 * Resolve everything needed to run an entry point, or print a
 * diagnostic and exit non-zero.
 */
function resolveOrExit(entryPoint) {
  const srcDir = findPythonSources(entryPoint);
  if (!srcDir) {
    process.stderr.write(
      `sdlc-mcp: cannot locate Python sources (${entryPoint}).\n` +
        `The npm package bundles them under python/ - try reinstalling,\n` +
        `or set SDLC_PYTHON_HOME to a directory containing the sdlc_*.py modules.\n`
    );
    process.exit(3);
  }
  const py = findPython();
  if (!py) {
    process.stderr.write(
      "sdlc-mcp: Python 3.9+ is required but no interpreter was found.\n" +
        "Install Python from https://www.python.org/downloads/ and ensure it is on PATH,\n" +
        "or set SDLC_PYTHON to the interpreter path.\n"
    );
    process.exit(3);
  }
  return { srcDir, py };
}

module.exports = { resolveOrExit, findPython, findPythonSources };
