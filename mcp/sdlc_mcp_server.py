"""Portable, tools-only MCP server for local SDLC diagnostics and gated writes.

Transports:
  - stdio (default): newline-delimited JSON-RPC, one message per line.
  - HTTP  (--http):  request/response JSON-RPC over localhost HTTP (dependency-free).

Cross-platform (Windows/Linux/macOS), Python 3.9+, no third-party packages.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any, Callable

from sdlc_core import InputError, VERSION, directory_tree, plugin_preflight, read_file_content, read_multiple_files, release_readiness, repo_snapshot
from sdlc_analyze import dependency_inventory, doctor, git_history, language_stats, risk_score, search_code, secret_scan
from sdlc_write import audit_log, list_changes, replace_in_file, rollback, write_file
try:
    from sdlc_extensions import code_metrics, sbom_lite
    HAS_EXTENSIONS = True
except ImportError:
    HAS_EXTENSIONS = False
    code_metrics = None
    sbom_lite = None


SERVER_INFO = {"name": "autonomous-sdlc-command-center", "version": VERSION}
INSTRUCTIONS = (
    "This server exposes local engineering diagnostics plus a safety-gated write engine. "
    "Read tools are side-effect free. Write tools (sdlc_write_file, sdlc_replace_in_file, sdlc_rollback) "
    "are dry-run by default, require confirm=true to mutate, stay inside the approved directory, "
    "back up before changing anything, and record a hash-chained audit log. "
    "Secret values are redacted from all outputs. Treat evidence as bounded, not proof of production safety."
)
SERVER_CAPABILITIES = {"tools": {"listChanged": False}}
SUPPORTED_PROTOCOL_VERSIONS = ["DRAFT-2026-v1", "2025-11-25", "2025-06-18"]
MAX_MESSAGE_BYTES = 1_048_576
RATE_LIMIT_CALLS = int(os.environ.get("SDLC_RATE_LIMIT_CALLS", "60"))
RATE_LIMIT_WINDOW_SECONDS = float(os.environ.get("SDLC_RATE_LIMIT_WINDOW_SECONDS", "60"))

_rate_limit_windows: dict[str, dict[str, Any]] = {}


def _check_rate_limit(tool_name: str) -> None:
    """Fixed-window per-tool rate limiter. Raises InputError when exceeded."""

    now = time.monotonic()
    window = _rate_limit_windows.get(tool_name)
    if window is None or (now - window["start"]) >= RATE_LIMIT_WINDOW_SECONDS:
        _rate_limit_windows[tool_name] = {"start": now, "count": 1}
        return
    window["count"] += 1
    if window["count"] > RATE_LIMIT_CALLS:
        raise InputError(
            f"rate limit exceeded for {tool_name}: {RATE_LIMIT_CALLS} calls per {RATE_LIMIT_WINDOW_SECONDS:.0f}s"
        )


def _object_schema(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "object", "properties": properties, "additionalProperties": False}
    if required:
        schema["required"] = required
    return schema


_PATH_PROPERTY = {"type": "string", "description": "Target directory. Filesystem roots are rejected; UNC/network paths require an explicit environment override."}
_FILE_PATH_PROPERTY = {"type": "string", "description": "File to act on, relative to the target directory (absolute paths contained by it are accepted)."}
_CONFIRM_PROPERTIES = {
    "confirm": {"type": "boolean", "default": False, "description": "Approval gate. Without confirm=true the call is a dry-run and changes nothing."},
    "dryRun": {"type": "boolean", "default": True, "description": "Explicit dry-run switch. Mutation only occurs when dryRun is false AND confirm is true."},
}
_READ_ONLY_ANNOTATIONS = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}
_WRITE_ANNOTATIONS = {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False}

TOOLS: list[dict[str, Any]] = [
    {
        "name": "sdlc_repo_snapshot",
        "title": "Repository Snapshot",
        "description": "Bounded, read-only inventory of repository structure, delivery signals, symlink/non-UTF-8 counts, and optional Git metadata.",
        "inputSchema": _object_schema(
            {
                "path": _PATH_PROPERTY,
                "maxFiles": {"type": "integer", "minimum": 1, "maximum": 2000, "default": 250},
                "includeGit": {"type": "boolean", "default": False},
            }
        ),
        "outputSchema": _object_schema({"scanRoot": {"type": "string"}, "fileCountSampled": {"type": "integer"}}),
        "annotations": _READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "sdlc_release_readiness",
        "title": "Release Readiness",
        "description": "Read-only local evidence for release readiness: inventory, documentation, Git state, and whitespace checks. Does not run tests or deploy.",
        "inputSchema": _object_schema(
            {
                "path": _PATH_PROPERTY,
                "maxFiles": {"type": "integer", "minimum": 1, "maximum": 2000, "default": 500},
            }
        ),
        "outputSchema": _object_schema({"status": {"type": "string"}, "checks": {"type": "array"}}),
        "annotations": _READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "sdlc_plugin_preflight",
        "title": "Plugin Preflight",
        "description": "Validate a plugin manifest, skill metadata, machine-readable skill contracts, and bundled command safety signatures.",
        "inputSchema": _object_schema(
            {"pluginPath": {"type": "string", "description": "Optional plugin root. Defaults to this plugin's root."}}
        ),
        "outputSchema": _object_schema({"status": {"type": "string"}, "summary": {"type": "object"}}),
        "annotations": _READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "sdlc_read_file",
        "title": "Read File",
        "description": "Bounded, symlink-safe UTF-8 file read with binary detection, truncation flags, and secret redaction (on by default).",
        "inputSchema": _object_schema(
            {
                "path": _PATH_PROPERTY,
                "filePath": _FILE_PATH_PROPERTY,
                "maxBytes": {"type": "integer", "minimum": 1, "maximum": 1048576, "default": 65536},
                "maxLines": {"type": "integer", "minimum": 1, "maximum": 100000, "default": 2000},
                "redactSecrets": {"type": "boolean", "default": True},
            },
            required=["filePath"],
        ),
        "outputSchema": _object_schema({"status": {"type": "string"}, "content": {"type": ["string", "null"]}}),
        "annotations": _READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "sdlc_read_files",
        "title": "Read Files (Batch)",
        "description": "Bounded batch read of up to 20 files. Each file gets the same safety treatment as sdlc_read_file.",
        "inputSchema": _object_schema(
            {
                "path": _PATH_PROPERTY,
                "filePaths": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 20, "description": "Files to read, relative to the target directory."},
                "maxBytes": {"type": "integer", "minimum": 1, "maximum": 1048576, "default": 65536},
                "maxLines": {"type": "integer", "minimum": 1, "maximum": 100000, "default": 2000},
                "redactSecrets": {"type": "boolean", "default": True},
            },
            required=["filePaths"],
        ),
        "outputSchema": _object_schema({"status": {"type": "string"}, "fileCount": {"type": "integer"}}),
        "annotations": _READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "sdlc_directory_tree",
        "title": "Directory Tree",
        "description": "Bounded recursive directory listing with depth and entry caps. Returns a flat array of {path, type, depth} entries.",
        "inputSchema": _object_schema(
            {
                "path": _PATH_PROPERTY,
                "maxDepth": {"type": "integer", "minimum": 1, "maximum": 10, "default": 4},
                "maxEntries": {"type": "integer", "minimum": 1, "maximum": 2000, "default": 500},
                "includeFiles": {"type": "boolean", "default": True},
                "includeDirs": {"type": "boolean", "default": True},
            }
        ),
        "outputSchema": _object_schema({"status": {"type": "string"}, "entryCount": {"type": "integer"}}),
        "annotations": _READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "sdlc_search_code",
        "title": "Search Code",
        "description": "Bounded regex search across repository text files with context lines and secret redaction.",
        "inputSchema": _object_schema(
            {
                "path": _PATH_PROPERTY,
                "pattern": {"type": "string", "minLength": 1, "maxLength": 500},
                "filePattern": {"type": "string", "maxLength": 500, "description": "Optional regex to filter relative file paths."},
                "maxResults": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50},
                "contextLines": {"type": "integer", "minimum": 0, "maximum": 10, "default": 1},
                "maxFiles": {"type": "integer", "minimum": 1, "maximum": 2000, "default": 1000},
                "maxFileBytes": {"type": "integer", "minimum": 1024, "maximum": 1048576, "default": 262144},
                "redactSecrets": {"type": "boolean", "default": True},
            },
            required=["pattern"],
        ),
        "outputSchema": _object_schema({"status": {"type": "string"}, "matchCount": {"type": "integer"}}),
        "annotations": _READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "sdlc_secret_scan",
        "title": "Secret Scan",
        "description": "Scan text files for secret signatures (tokens, keys, assignments). Findings are always redacted.",
        "inputSchema": _object_schema(
            {
                "path": _PATH_PROPERTY,
                "maxFiles": {"type": "integer", "minimum": 1, "maximum": 2000, "default": 1000},
                "maxFileBytes": {"type": "integer", "minimum": 1024, "maximum": 1048576},
                "maxFindings": {"type": "integer", "minimum": 1, "maximum": 5000, "default": 500},
            }
        ),
        "outputSchema": _object_schema({"status": {"type": "string"}, "findingCount": {"type": "integer"}}),
        "annotations": _READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "sdlc_language_stats",
        "title": "Language Statistics",
        "description": "Language breakdown by file count and bounded line counting, with primary-language detection.",
        "inputSchema": _object_schema(
            {
                "path": _PATH_PROPERTY,
                "maxFiles": {"type": "integer", "minimum": 1, "maximum": 2000, "default": 2000},
                "maxFileBytes": {"type": "integer", "minimum": 1024, "maximum": 4194304},
            }
        ),
        "outputSchema": _object_schema({"status": {"type": "string"}, "primaryLanguage": {"type": ["string", "null"]}}),
        "annotations": _READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "sdlc_dependency_inventory",
        "title": "Dependency Inventory",
        "description": "Best-effort offline dependency extraction from package.json, requirements.txt, pyproject.toml, go.mod, and Cargo.toml.",
        "inputSchema": _object_schema(
            {
                "path": _PATH_PROPERTY,
                "maxFiles": {"type": "integer", "minimum": 1, "maximum": 2000, "default": 500},
                "maxDependenciesPerManifest": {"type": "integer", "minimum": 1, "maximum": 2000, "default": 200},
            }
        ),
        "outputSchema": _object_schema({"status": {"type": "string"}, "totalDependencies": {"type": "integer"}}),
        "annotations": _READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "sdlc_git_history",
        "title": "Git History",
        "description": "Recent local commits, distinct authors, and churn hotspots. Never contacts remotes.",
        "inputSchema": _object_schema(
            {
                "path": _PATH_PROPERTY,
                "maxCommits": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
                "includeChurn": {"type": "boolean", "default": True},
            }
        ),
        "outputSchema": _object_schema({"status": {"type": "string"}, "commitCount": {"type": "integer"}}),
        "annotations": _READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "sdlc_risk_score",
        "title": "Composite Risk Score",
        "description": "Heuristic 0-100 delivery-risk score with letter grade and weighted evidence factors from read-only signals.",
        "inputSchema": _object_schema(
            {
                "path": _PATH_PROPERTY,
                "maxFiles": {"type": "integer", "minimum": 1, "maximum": 2000, "default": 500},
            }
        ),
        "outputSchema": _object_schema({"score": {"type": "integer"}, "grade": {"type": "string"}, "riskLevel": {"type": "string"}}),
        "annotations": _READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "sdlc_doctor",
        "title": "Environment Doctor",
        "description": "Probe runtime, platform, executables, capabilities, and plugin preflight status. Useful for harness-agnostic setup verification.",
        "inputSchema": _object_schema({}),
        "outputSchema": _object_schema({"status": {"type": "string"}, "coreVersion": {"type": "string"}}),
        "annotations": _READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "sdlc_list_changes",
        "title": "List Change Sets",
        "description": "List recorded, rollback-capable change sets created by the write engine.",
        "inputSchema": _object_schema({"path": _PATH_PROPERTY}),
        "outputSchema": _object_schema({"status": {"type": "string"}, "changeCount": {"type": "integer"}}),
        "annotations": _READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "sdlc_audit_log",
        "title": "Audit Log",
        "description": "Read the mutation audit log and verify its tamper-evident hash chain.",
        "inputSchema": _object_schema(
            {
                "path": _PATH_PROPERTY,
                "maxEntries": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 50},
            }
        ),
        "outputSchema": _object_schema({"status": {"type": "string"}, "chainValid": {"type": "boolean"}}),
        "annotations": _READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "sdlc_write_file",
        "title": "Write File (Gated)",
        "description": "Create/overwrite/append a UTF-8 text file. Dry-run unless confirm=true; backs up existing content; appends to the audit log; rollback via the returned changeId.",
        "inputSchema": _object_schema(
            {
                "path": _PATH_PROPERTY,
                "filePath": _FILE_PATH_PROPERTY,
                "content": {"type": "string", "description": "UTF-8 content (max 1 MiB)."},
                "mode": {"type": "string", "enum": ["create", "overwrite", "append"], "default": "overwrite"},
                "expectedSha256": {"type": "string", "description": "Optional optimistic-concurrency guard: current file SHA-256."},
                "allowSensitive": {"type": "boolean", "default": False, "description": "Required to touch .env/key/credential-style paths."},
                **_CONFIRM_PROPERTIES,
            },
            required=["filePath", "content"],
        ),
        "outputSchema": _object_schema({"status": {"type": "string"}, "changeId": {"type": "string"}}),
        "annotations": _WRITE_ANNOTATIONS,
    },
    {
        "name": "sdlc_replace_in_file",
        "title": "Replace In File (Gated)",
        "description": "Exact-string replacement with occurrence verification. Dry-run unless confirm=true; backs up and audits on apply.",
        "inputSchema": _object_schema(
            {
                "path": _PATH_PROPERTY,
                "filePath": _FILE_PATH_PROPERTY,
                "find": {"type": "string", "minLength": 1},
                "replace": {"type": "string", "default": ""},
                "expectedOccurrences": {"type": "integer", "minimum": 1, "maximum": 10000, "default": 1},
                "allowSensitive": {"type": "boolean", "default": False},
                **_CONFIRM_PROPERTIES,
            },
            required=["filePath", "find"],
        ),
        "outputSchema": _object_schema({"status": {"type": "string"}, "changeId": {"type": "string"}}),
        "annotations": _WRITE_ANNOTATIONS,
    },
    {
        "name": "sdlc_rollback",
        "title": "Rollback Change Set (Gated)",
        "description": "Restore files from a recorded change set (or delete files it created). Dry-run unless confirm=true; the rollback itself is audited.",
        "inputSchema": _object_schema(
            {
                "path": _PATH_PROPERTY,
                "changeId": {"type": "string", "description": "Identifier returned by a write operation."},
                **_CONFIRM_PROPERTIES,
            },
            required=["changeId"],
        ),
        "outputSchema": _object_schema({"status": {"type": "string"}, "plan": {"type": "array"}}),
        "annotations": _WRITE_ANNOTATIONS,
    },
    {
        "name": "sdlc_code_metrics",
        "title": "Code Metrics",
        "description": "Heuristic code health: TODO/FIXME counts, large files, long lines, empty files, branch-density hints, health score A-F. Offline, dependency-free.",
        "inputSchema": _object_schema(
            {
                "path": _PATH_PROPERTY,
                "maxFiles": {"type": "integer", "minimum": 1, "maximum": 2000, "default": 1000},
                "maxFileBytes": {"type": "integer", "minimum": 1024, "maximum": 1048576, "default": 262144},
            }
        ),
        "outputSchema": _object_schema({"status": {"type": "string"}, "healthScore": {"type": "integer"}}),
        "annotations": _READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "sdlc_sbom",
        "title": "SBOM Lite (CycloneDX)",
        "description": "Offline SBOM generation from manifests (package.json, requirements.txt, pyproject.toml, go.mod, Cargo.toml) into CycloneDX-like JSON. No network, no registry lookup.",
        "inputSchema": _object_schema(
            {
                "path": _PATH_PROPERTY,
                "maxFiles": {"type": "integer", "minimum": 1, "maximum": 2000, "default": 500},
            }
        ),
        "outputSchema": _object_schema({"status": {"type": "string"}, "componentCount": {"type": "integer"}}),
        "annotations": _READ_ONLY_ANNOTATIONS,
    },
]

TOOL_HANDLERS: dict[str, Callable[[dict[str, Any] | None], dict[str, Any]]] = {
    "sdlc_repo_snapshot": repo_snapshot,
    "sdlc_release_readiness": release_readiness,
    "sdlc_plugin_preflight": plugin_preflight,
    "sdlc_read_file": read_file_content,
    "sdlc_read_files": read_multiple_files,
    "sdlc_directory_tree": directory_tree,
    "sdlc_search_code": search_code,
    "sdlc_secret_scan": secret_scan,
    "sdlc_language_stats": language_stats,
    "sdlc_dependency_inventory": dependency_inventory,
    "sdlc_git_history": git_history,
    "sdlc_risk_score": risk_score,
    "sdlc_doctor": doctor,
    "sdlc_list_changes": list_changes,
    "sdlc_audit_log": audit_log,
    "sdlc_write_file": write_file,
    "sdlc_replace_in_file": replace_in_file,
    "sdlc_rollback": rollback,
}

# Conditionally add extended tools if module available
if HAS_EXTENSIONS:
    TOOL_HANDLERS["sdlc_code_metrics"] = code_metrics
    TOOL_HANDLERS["sdlc_sbom"] = sbom_lite


def _response(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _tool_result(result: dict[str, Any], is_error: bool = False) -> dict[str, Any]:
    serialized = json.dumps(result, separators=(",", ":"), ensure_ascii=False)
    payload: dict[str, Any] = {
        "resultType": "complete",
        "content": [{"type": "text", "text": serialized}],
        "structuredContent": result,
    }
    if is_error:
        payload["isError"] = True
    return payload


def _handle_request(message: dict[str, Any]) -> dict[str, Any] | None:
    if message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
        return _error(message.get("id"), -32600, "Invalid Request")

    method = message["method"]
    request_id = message.get("id")
    params = message.get("params", {})
    if params is None:
        params = {}
    if not isinstance(params, dict):
        return _error(request_id, -32602, "Invalid params")

    # Notifications intentionally receive no response.
    if request_id is None and method.startswith("notifications/"):
        return None

    if method == "server/discover":
        return _response(
            request_id,
            {
                "resultType": "complete",
                "supportedVersions": SUPPORTED_PROTOCOL_VERSIONS,
                "capabilities": SERVER_CAPABILITIES,
                "serverInfo": SERVER_INFO,
                "instructions": INSTRUCTIONS,
                "transports": ["stdio", "http"],
                "toolNames": sorted(TOOL_HANDLERS),
            },
        )
    if method == "initialize":
        requested_version = params.get("protocolVersion")
        accepted_version = requested_version if requested_version in SUPPORTED_PROTOCOL_VERSIONS else "2025-11-25"
        return _response(
            request_id,
            {
                "protocolVersion": accepted_version,
                "capabilities": SERVER_CAPABILITIES,
                "serverInfo": SERVER_INFO,
                "instructions": INSTRUCTIONS,
            },
        )
    if method == "ping":
        return _response(request_id, {})
    if method == "tools/list":
        return _response(request_id, {"tools": TOOLS})
    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(name, str) or not isinstance(arguments, dict):
            return _error(request_id, -32602, "Invalid params")
        handler = TOOL_HANDLERS.get(name)
        if handler is None:
            return _error(request_id, -32602, "Unknown tool")
        try:
            _check_rate_limit(name)
            return _response(request_id, _tool_result(handler(arguments)))
        except InputError as exc:
            return _response(request_id, _tool_result({"status": "error", "error": str(exc)}, is_error=True))
        except Exception:
            return _response(
                request_id,
                _tool_result(
                    {"status": "error", "error": "The local diagnostic did not complete. Check the path and local permissions."},
                    is_error=True,
                ),
            )
    return _error(request_id, -32601, "Method not found")


def _dispatch_payload(raw: bytes) -> dict[str, Any] | None:
    """Shared stdio/HTTP dispatch for one JSON-RPC payload."""

    if len(raw) > MAX_MESSAGE_BYTES:
        return _error(None, -32700, "Request exceeds the maximum message size")
    try:
        parsed = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _error(None, -32700, "Parse error")
    if isinstance(parsed, list):
        return _error(None, -32600, "Batch requests are not supported")
    if not isinstance(parsed, dict):
        return _error(None, -32600, "Invalid Request")
    return _handle_request(parsed)


def _run_stdio() -> int:
    for raw_line in sys.stdin:
        response = _dispatch_payload(raw_line.encode("utf-8", errors="replace")[: MAX_MESSAGE_BYTES + 1])
        if response is not None:
            sys.stdout.write(json.dumps(response, separators=(",", ":"), ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0


def create_http_server(host: str, port: int):
    """Build the localhost HTTP transport. Returns a ThreadingHTTPServer."""

    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class SdlcRequestHandler(BaseHTTPRequestHandler):
        server_version = f"sdlc-mcp/{VERSION}"
        protocol_version = "HTTP/1.1"

        def _send_json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:  # keep stdout JSON-clean
            sys.stderr.write("%s - %s\n" % (self.address_string(), format % args))

        def do_GET(self) -> None:
            path = self.path.split("?", 1)[0]
            if path == "/health":
                self._send_json(200, {"status": "ok", **SERVER_INFO})
            elif path == "/tools":
                self._send_json(200, {"tools": TOOLS})
            elif path in {"/", ""}:
                self._send_json(
                    200,
                    {
                        **dict(SERVER_INFO),
                        "instructions": INSTRUCTIONS,
                        "endpoints": {"POST /mcp": "JSON-RPC dispatch", "GET /health": "liveness", "GET /tools": "tool catalog"},
                        "supportedProtocolVersions": SUPPORTED_PROTOCOL_VERSIONS,
                    },
                )
            else:
                self._send_json(404, {"error": "not found"})

        def do_POST(self) -> None:
            path = self.path.split("?", 1)[0]
            if path not in {"/mcp", "/", ""}:
                self._send_json(404, {"error": "not found"})
                return
            length_header = self.headers.get("Content-Length")
            try:
                length = int(length_header) if length_header is not None else -1
            except ValueError:
                length = -1
            if length < 0 or length > MAX_MESSAGE_BYTES:
                self._send_json(413, _error(None, -32700, "Request exceeds the maximum message size"))
                return
            raw = self.rfile.read(length)
            response = _dispatch_payload(raw)
            if response is None:  # notification
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self._send_json(200, response)

    return ThreadingHTTPServer((host, port), SdlcRequestHandler)


def main() -> int:
    parser = argparse.ArgumentParser(description="autonomous-sdlc-command-center MCP server")
    parser.add_argument("--http", type=int, metavar="PORT", default=None, help="Serve JSON-RPC over localhost HTTP on PORT instead of stdio")
    parser.add_argument("--host", default="127.0.0.1", help="HTTP bind host (default 127.0.0.1)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARN", "ERROR"], default="INFO", help="Log verbosity for HTTP transport")
    args = parser.parse_args()

    if args.http is not None:
        if not 1 <= args.http <= 65535:
            parser.error("--http port must be between 1 and 65535")
        server = create_http_server(args.host, args.http)
        actual_host, actual_port = server.server_address[:2]
        sys.stderr.write(f"sdlc-mcp {VERSION} listening on http://{actual_host}:{actual_port} (POST /mcp, GET /health)\n")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
        return 0
    return _run_stdio()


if __name__ == "__main__":
    sys.exit(main())
