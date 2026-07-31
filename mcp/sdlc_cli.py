"""Dependency-free, cross-platform CLI for the SDLC core, intelligence, and write engine.

Exit codes: 0 = ok/pass, 1 = failing status (or --strict warning), 2 = input error, 3 = internal error.
Output: JSON by default; --format text for human summaries; --format sarif for secret-scan.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
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


def _add_path(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--path", default=".", help="Target directory (default: current directory)")


def _add_format(parser: argparse.ArgumentParser, sarif: bool = False) -> None:
    choices = ["json", "text"] + (["sarif"] if sarif else [])
    parser.add_argument("--format", choices=choices, default="json")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    parser.add_argument("--strict", action="store_true", help="Exit 1 on warning-status results as well")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sdlc", description=f"SDLC command center CLI (core {VERSION})")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output for debugging")
    sub = parser.add_subparsers(dest="command", required=False)

    p = sub.add_parser("snapshot", help="Bounded repository inventory")
    _add_path(p); p.add_argument("--max-files", type=int, default=250); p.add_argument("--include-git", action="store_true"); _add_format(p)

    p = sub.add_parser("release-readiness", help="Release-readiness evidence")
    _add_path(p); p.add_argument("--max-files", type=int, default=500); _add_format(p)

    p = sub.add_parser("plugin-preflight", help="Validate a plugin (manifest, skills, contracts, safety)")
    p.add_argument("--plugin-path", default=None); _add_format(p)

    p = sub.add_parser("read", help="Bounded file read with redaction")
    _add_path(p); p.add_argument("--file", required=True); p.add_argument("--max-bytes", type=int, default=65536)
    p.add_argument("--max-lines", type=int, default=2000); p.add_argument("--no-redact", action="store_true"); _add_format(p)

    p = sub.add_parser("read-batch", help="Batch-read up to 20 files")
    _add_path(p); p.add_argument("--file", action="append", required=True, dest="files", help="File to read (repeat for multiple)")
    p.add_argument("--max-bytes", type=int, default=65536); p.add_argument("--max-lines", type=int, default=2000)
    p.add_argument("--no-redact", action="store_true"); _add_format(p)

    p = sub.add_parser("tree", help="Bounded recursive directory listing")
    _add_path(p); p.add_argument("--max-depth", type=int, default=4); p.add_argument("--max-entries", type=int, default=500)
    p.add_argument("--files-only", action="store_true"); p.add_argument("--dirs-only", action="store_true"); _add_format(p)

    p = sub.add_parser("search", help="Regex search with context")
    _add_path(p); p.add_argument("--pattern", required=True); p.add_argument("--file-pattern", default=None)
    p.add_argument("--max-results", type=int, default=50); p.add_argument("--context-lines", type=int, default=1); _add_format(p)

    p = sub.add_parser("secret-scan", help="Redacted secret-signature scan")
    _add_path(p); p.add_argument("--max-files", type=int, default=1000); _add_format(p, sarif=True)

    p = sub.add_parser("languages", help="Language statistics")
    _add_path(p); _add_format(p)

    p = sub.add_parser("deps", help="Dependency inventory")
    _add_path(p); _add_format(p)

    p = sub.add_parser("git-history", help="Local git history and churn")
    _add_path(p); p.add_argument("--max-commits", type=int, default=20); _add_format(p)

    p = sub.add_parser("risk", help="Composite risk score")
    _add_path(p); p.add_argument("--max-files", type=int, default=500); _add_format(p)

    p = sub.add_parser("doctor", help="Environment and capability probe")
    _add_format(p)

    p = sub.add_parser("write", help="Gated file write (dry-run unless --confirm)")
    _add_path(p); p.add_argument("--file", required=True)
    content = p.add_mutually_exclusive_group(required=True)
    content.add_argument("--content", default=None)
    content.add_argument("--content-file", default=None, help="Read content from a file, or '-' for stdin")
    p.add_argument("--mode", choices=["create", "overwrite", "append"], default="overwrite")
    p.add_argument("--expected-sha256", default=None); p.add_argument("--allow-sensitive", action="store_true")
    p.add_argument("--confirm", action="store_true", help="Apply the mutation (a backup and audit entry are created)")
    _add_format(p)

    p = sub.add_parser("replace", help="Gated exact-string replacement (dry-run unless --confirm)")
    _add_path(p); p.add_argument("--file", required=True); p.add_argument("--find", required=True)
    p.add_argument("--replace", default=""); p.add_argument("--expected-occurrences", type=int, default=1)
    p.add_argument("--allow-sensitive", action="store_true"); p.add_argument("--confirm", action="store_true"); _add_format(p)

    p = sub.add_parser("changes", help="List rollback-capable change sets")
    _add_path(p); _add_format(p)

    p = sub.add_parser("rollback", help="Roll back a change set (dry-run unless --confirm)")
    _add_path(p); p.add_argument("--change-id", required=True); p.add_argument("--confirm", action="store_true"); _add_format(p)

    p = sub.add_parser("audit", help="Audit log with hash-chain verification")
    _add_path(p); p.add_argument("--max-entries", type=int, default=50); _add_format(p)

    p = sub.add_parser("serve", help="Run the MCP server (stdio default, or --http PORT)")
    p.add_argument("--http", type=int, default=None); p.add_argument("--host", default="127.0.0.1")

    p = sub.add_parser("metrics", help="Heuristic code health metrics (TODOs, complexity hints, large files)")
    _add_path(p); p.add_argument("--max-files", type=int, default=1000); _add_format(p)

    p = sub.add_parser("sbom", help="Offline SBOM-lite (CycloneDX) from manifests")
    _add_path(p); p.add_argument("--max-files", type=int, default=500); _add_format(p)

    p = sub.add_parser("completion", help="Generate shell completion script")
    p.add_argument("--shell", choices=["bash", "zsh", "fish"], default="bash")

    return parser


def _to_sarif(result: dict[str, Any]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    sarif_results = []
    for finding in result.get("findings", []):
        signature = finding.get("signature", "unknown")
        rules.setdefault(
            signature,
            {
                "id": signature,
                "name": signature.replace("-", " ").title(),
                "shortDescription": {"text": f"Secret signature detected ({signature}); value redacted."},
            },
        )
        location: dict[str, Any] = {"artifactLocation": {"uri": finding.get("file", "unknown")}}
        if finding.get("line"):
            location["region"] = {"startLine": finding["line"]}
        sarif_results.append(
            {
                "ruleId": signature,
                "level": "warning",
                "message": {"text": finding.get("preview", "Secret signature finding (redacted).")},
                "locations": [{"physicalLocation": location}],
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "autonomous-sdlc-command-center secret-scan",
                        "version": VERSION,
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def _render_text(command: str, result: dict[str, Any]) -> str:
    lines: list[str] = []
    status = result.get("status")
    if status is not None:
        lines.append(f"status: {status}")
    if command == "snapshot":
        lines.append(f"root: {result.get('scanRoot')}")
        lines.append(f"files sampled: {result.get('fileCountSampled')} (limit {result.get('sampleLimit')}, reached={result.get('sampleLimitReached')})")
        lines.append(f"manifests={len(result.get('manifests', []))} lockfiles={len(result.get('lockfiles', []))} ci={len(result.get('ciFiles', []))} tests={len(result.get('testFiles', []))}")
        lines.append(f"skipped symlinks: {result.get('skippedSymlinkCount')}  non-UTF-8 paths: {result.get('nonUtf8PathCount')}  inaccessible dirs: {result.get('inaccessibleDirectoryCount')}")
        git = result.get("git")
        if git:
            lines.append(f"git: branch={git.get('branch')} clean={git.get('workingTreeClean')} changed={git.get('changedFileCount')}")
    elif command == "release-readiness":
        for check in result.get("checks", []):
            lines.append(f"  [{check['status']:<7}] {check['id']}: {check['detail']}")
        lines.append(f"summary: {result.get('summary')}")
    elif command == "plugin-preflight":
        lines.append(f"summary: {result.get('summary')}")
        for finding in result.get("findings", [])[:50]:
            lines.append(f"  [{finding['severity']:<7}] {finding['id']}: {finding['message']} ({finding.get('file')})")
    elif command == "read":
        if result.get("isBinary"):
            lines.append(f"binary file: {result.get('filePath')} ({result.get('sizeBytes')} bytes)")
        else:
            lines.append(f"file: {result.get('filePath')} ({result.get('sizeBytes')} bytes, truncated={result.get('truncatedBytes') or result.get('truncatedLines')})")
            lines.append(result.get("content") or "")
    elif command == "read-batch":
        lines.append(f"files: {result.get('fileCount')}  succeeded: {result.get('succeeded')}  errored: {result.get('errored')}")
        for entry in result.get("results", []):
            if entry.get("status") == "ok":
                marker = "binary" if entry.get("isBinary") else f"{entry.get('sizeBytes')}B"
                lines.append(f"  [ok]    {entry.get('filePath')} ({marker})")
            else:
                lines.append(f"  [error] {entry.get('filePath')}: {entry.get('error')}")
    elif command == "tree":
        lines.append(f"entries: {result.get('entryCount')}  maxDepth: {result.get('maxDepth')}  limitReached: {result.get('entryLimitReached')}")
        for entry in result.get("entries", [])[:100]:
            indent = "  " * entry["depth"]
            kind = "d" if entry["type"] == "directory" else "f"
            lines.append(f"  {indent}[{kind}] {entry['path']}")
    elif command == "search":
        lines.append(f"matches: {result.get('matchCount')} (limit reached={result.get('resultsLimitReached')})")
        for match in result.get("matches", []):
            lines.append(f"  {match['file']}:{match['line']}: {match['text'].strip()}")
    elif command == "secret-scan":
        lines.append(f"findings: {result.get('findingCount')} (files scanned: {result.get('filesScanned')})")
        for finding in result.get("findings", [])[:100]:
            where = f"{finding['file']}:{finding['line']}" if finding.get("line") else finding["file"]
            lines.append(f"  [{finding['signature']}] {where} -> {finding.get('preview')}")
    elif command == "languages":
        lines.append(f"primary language: {result.get('primaryLanguage')}  total lines: {result.get('totalLines')}")
        for entry in result.get("languages", [])[:15]:
            lines.append(f"  {entry['language']:<16} files={entry['files']:<5} lines={entry['lines']:<8} ({entry['linesPct']}%)")
    elif command == "deps":
        lines.append(f"manifests: {result.get('manifestCount')}  dependencies: {result.get('totalDependencies')} (unique {result.get('uniqueDependencyCount')})")
        for manifest in result.get("manifests", []):
            lines.append(f"  {manifest['file']} [{manifest['ecosystem']}] {manifest['dependencyCount']} dep(s)")
    elif command == "git-history":
        lines.append(f"commits: {result.get('commitCount')}  authors: {result.get('distinctAuthorCount')}")
        for commit in result.get("commits", [])[:20]:
            lines.append(f"  {commit['hash']} {commit['date'][:10]} {commit['author']}: {commit['subject']}")
    elif command == "risk":
        lines.append(f"score: {result.get('score')}/100  grade: {result.get('grade')}  level: {result.get('riskLevel')}")
        for factor in result.get("factors", []):
            lines.append(f"  +{factor['weight']:<3} {factor['id']}: {factor['detail']}")
    elif command == "doctor":
        lines.append(f"core: {result.get('coreVersion')}  python: {result.get('python', {}).get('version')}  os: {result.get('platform', {}).get('system')}")
        for name, version in result.get("executables", {}).items():
            lines.append(f"  {name}: {version or 'not found'}")
        lines.append(f"capabilities: {json.dumps(result.get('capabilities', {}), sort_keys=True)}")
    elif command in {"write", "replace", "rollback"}:
        lines.append(f"changeId: {result.get('changeId')}  dryRun: {result.get('dryRun')}")
        diff = result.get("diff")
        if diff:
            lines.append(f"diff: +{diff.get('linesAdded')} -{diff.get('linesRemoved')}" + (" (preview truncated)" if diff.get("truncated") else ""))
            if diff.get("preview"):
                lines.append(diff["preview"])
        for item in result.get("plan", []) or []:
            lines.append(f"  plan: {item['action']} {item['path']}")
        for item in result.get("applied", []) or []:
            lines.append(f"  applied: {item['action']} {item['path']}")
        if result.get("dryRun"):
            lines.append("dry-run only. Re-run with --confirm to apply (backup + audit entry will be created).")
    elif command == "changes":
        lines.append(f"change sets: {result.get('changeCount')}")
        for change in result.get("changes", []):
            lines.append(f"  {change.get('changeId')}  ops={change.get('operationCount')}  paths={change.get('paths')}")
    elif command == "audit":
        lines.append(f"entries: {result.get('entryCount')}  chain valid: {result.get('chainValid')}")
        for entry in result.get("entries", []):
            lines.append(f"  #{entry.get('seq')} {entry.get('timestampUtc')} {entry.get('operation')} {entry.get('path') or ''}")
    elif command == "metrics":
        lines.append(f"health: {result.get('healthScore')}/100 grade={result.get('grade')} files={result.get('metrics', {}).get('filesScanned')}")
        m = result.get("metrics", {})
        lines.append(f"  todos={m.get('todoCount')} fixmes={m.get('fixmeCount')} large={len(m.get('largeFiles', []))} longLines={m.get('longLines')} complexityHints={len(m.get('complexityHints', []))}")
        for item in result.get("topTodoFiles", [])[:10]:
            lines.append(f"  TODO-heavy: {item['file']} x{item['count']}")
    elif command == "sbom":
        lines.append(f"components: {result.get('componentCount')} unique={result.get('bom', {}).get('metadata', {}).get('component', {}).get('name')} manifests={result.get('manifestCount')}")
        for comp in result.get("bom", {}).get("components", [])[:15]:
            lines.append(f"  {comp.get('ecosystem')}:{comp.get('name')}@{comp.get('version')} [{comp.get('manifest')}]")
    else:
        return json.dumps(result, indent=2, ensure_ascii=False)
    return "\n".join(lines)


def _build_arguments(command: str, args: argparse.Namespace) -> dict[str, Any]:
    if command == "snapshot":
        return {"path": args.path, "maxFiles": args.max_files, "includeGit": args.include_git}
    if command == "release-readiness":
        return {"path": args.path, "maxFiles": args.max_files}
    if command == "plugin-preflight":
        return {} if args.plugin_path is None else {"pluginPath": args.plugin_path}
    if command == "read":
        return {"path": args.path, "filePath": args.file, "maxBytes": args.max_bytes, "maxLines": args.max_lines, "redactSecrets": not args.no_redact}
    if command == "read-batch":
        return {"path": args.path, "filePaths": args.files, "maxBytes": args.max_bytes, "maxLines": args.max_lines, "redactSecrets": not args.no_redact}
    if command == "tree":
        return {"path": args.path, "maxDepth": args.max_depth, "maxEntries": args.max_entries, "includeFiles": not args.dirs_only, "includeDirs": not args.files_only}
    if command == "search":
        return {"path": args.path, "pattern": args.pattern, "filePattern": args.file_pattern, "maxResults": args.max_results, "contextLines": args.context_lines}
    if command == "secret-scan":
        return {"path": args.path, "maxFiles": args.max_files}
    if command in {"languages", "deps"}:
        return {"path": args.path}
    if command == "git-history":
        return {"path": args.path, "maxCommits": args.max_commits}
    if command == "risk":
        return {"path": args.path, "maxFiles": args.max_files}
    if command == "doctor":
        return {}
    if command == "write":
        if args.content_file is not None:
            if args.content_file == "-":
                content = sys.stdin.read()
            else:
                try:
                    with open(args.content_file, "r", encoding="utf-8") as f:
                        content = f.read()
                except FileNotFoundError:
                    raise InputError(f"content file not found: {args.content_file}")
                except IsADirectoryError:
                    raise InputError(f"content file is a directory: {args.content_file}")
                except OSError as exc:
                    raise InputError(f"cannot read content file: {exc}") from exc
        else:
            content = args.content
        return {
            "path": args.path, "filePath": args.file, "content": content, "mode": args.mode,
            "expectedSha256": args.expected_sha256, "allowSensitive": args.allow_sensitive, "confirm": args.confirm,
        }
    if command == "replace":
        return {
            "path": args.path, "filePath": args.file, "find": args.find, "replace": args.replace,
            "expectedOccurrences": args.expected_occurrences, "allowSensitive": args.allow_sensitive, "confirm": args.confirm,
        }
    if command == "changes":
        return {"path": args.path}
    if command == "rollback":
        return {"path": args.path, "changeId": args.change_id, "confirm": args.confirm}
    if command == "audit":
        return {"path": args.path, "maxEntries": args.max_entries}
    if command == "metrics":
        return {"path": args.path, "maxFiles": args.max_files}
    if command == "sbom":
        return {"path": args.path, "maxFiles": args.max_files}
    if command == "completion":
        # Handled specially in main - no core args
        return {"shell": args.shell}
    raise InputError(f"unknown command: {command}")


_HANDLERS: dict[str, Callable[[dict[str, Any] | None], dict[str, Any]]] = {
    "snapshot": repo_snapshot,
    "release-readiness": release_readiness,
    "plugin-preflight": plugin_preflight,
    "read": read_file_content,
    "read-batch": read_multiple_files,
    "tree": directory_tree,
    "search": search_code,
    "secret-scan": secret_scan,
    "languages": language_stats,
    "deps": dependency_inventory,
    "git-history": git_history,
    "risk": risk_score,
    "doctor": doctor,
    "write": write_file,
    "replace": replace_in_file,
    "changes": list_changes,
    "rollback": rollback,
    "audit": audit_log,
}

# Extend with optional extensions if available
if HAS_EXTENSIONS:
    _HANDLERS["metrics"] = code_metrics
    _HANDLERS["sbom"] = sbom_lite
else:
    # Provide stub handlers that explain extension missing
    def _missing_ext(*_a, **_kw):
        raise InputError("extended tools require sdlc_extensions module - reinstall from source")
    _HANDLERS["metrics"] = _missing_ext
    _HANDLERS["sbom"] = _missing_ext


def _completion_script(shell: str) -> str:
    # Try to load from project checkout first, then fallback to embedded
    candidate_paths = [
        Path(__file__).parent.parent / "scripts" / "completions" / f"sdlc.{shell}",
        Path.home() / "Projects" / "autonomous-sdlc-command-center" / "scripts" / "completions" / f"sdlc.{shell}",
        Path.home() / ".local" / "share" / "autonomous-sdlc-command-center" / "completions" / f"sdlc.{shell}",
    ]
    for p in candidate_paths:
        try:
            if p.is_file():
                return p.read_text(encoding="utf-8")
        except OSError:
            continue

    if shell == "bash":
        return """# Bash completion for sdlc CLI
_sdlc_completions() {
  local cur prev commands
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  commands="snapshot release-readiness plugin-preflight read read-batch tree search secret-scan languages deps git-history risk doctor write replace changes rollback audit serve metrics sbom completion"
  if [[ ${COMP_CWORD} -eq 1 ]]; then
    COMPREPLY=( $(compgen -W "${commands} --version --help -v" -- "${cur}") )
    return
  fi
  case "${COMP_WORDS[1]}" in
    snapshot|release-readiness|languages|deps|git-history|risk|tree|search|secret-scan|read|read-batch|write|replace|changes|rollback|audit|metrics|sbom)
      if [[ "${cur}" == --* ]]; then
        COMPREPLY=( $(compgen -W "--path --format --pretty --strict --max-files --include-git --file --max-bytes --max-lines --no-redact --max-depth --max-entries --files-only --dirs-only --pattern --file-pattern --max-results --context-lines --mode --content --content-file --expected-sha256 --allow-sensitive --confirm --find --replace --expected-occurrences --change-id --max-entries --max-commits --help" -- "${cur}") )
      fi
      ;;
    doctor|plugin-preflight)
      COMPREPLY=( $(compgen -W "--format --pretty --plugin-path --help" -- "${cur}") )
      ;;
  esac
}
complete -F _sdlc_completions sdlc
complete -F _sdlc_completions sdlc-mcp
complete -F _sdlc_completions sdlc-universal
"""
    if shell == "zsh":
        return """#compdef sdlc sdlc-mcp sdlc-universal
_sdlc() {
  local -a commands
  commands=(
    'snapshot:Bounded repository inventory'
    'release-readiness:Release-readiness evidence'
    'plugin-preflight:Validate plugin'
    'read:Bounded file read'
    'read-batch:Batch read'
    'tree:Directory listing'
    'search:Regex search'
    'secret-scan:Secret scan'
    'languages:Language stats'
    'deps:Dependency inventory'
    'git-history:Git history'
    'risk:Risk score'
    'doctor:Doctor'
    'write:Gated write'
    'replace:Gated replace'
    'changes:List changes'
    'rollback:Rollback'
    'audit:Audit log'
    'serve:MCP server'
    'metrics:Code metrics'
    'sbom:SBOM Lite'
    'completion:Shell completion'
  )
  _describe 'command' commands
}
_sdlc "$@"
"""
    if shell == "fish":
        return """
complete -c sdlc -f
complete -c sdlc -n '__fish_use_subcommand' -a snapshot -d 'Repository inventory'
complete -c sdlc -n '__fish_use_subcommand' -a release-readiness -d 'Release readiness'
complete -c sdlc -n '__fish_use_subcommand' -a doctor -d 'Doctor'
complete -c sdlc -n '__fish_use_subcommand' -a risk -d 'Risk score'
complete -c sdlc -n '__fish_use_subcommand' -a secret-scan -d 'Secret scan'
complete -c sdlc -n '__fish_use_subcommand' -a metrics -d 'Code metrics'
complete -c sdlc -n '__fish_use_subcommand' -a sbom -d 'SBOM'
complete -c sdlc -n '__fish_use_subcommand' -a search -d 'Search code'
complete -c sdlc -n '__fish_use_subcommand' -a tree -d 'Directory tree'
complete -c sdlc -n '__fish_use_subcommand' -a languages -d 'Language stats'
complete -c sdlc -n '__fish_use_subcommand' -a deps -d 'Dependency inventory'
complete -c sdlc -n '__fish_use_subcommand' -a git-history -d 'Git history'
complete -c sdlc -n '__fish_use_subcommand' -a write -d 'Gated write'
complete -c sdlc -n '__fish_use_subcommand' -a replace -d 'Gated replace'
"""
    raise InputError(f"unsupported shell: {shell}")


def main() -> int:
    args = _parser().parse_args()

    if not args.command:
        # Default to doctor when no command supplied for quick health check
        args.command = "doctor"
        # Ensure format attr exists
        if not hasattr(args, "format"):
            args.format = "json"
        if not hasattr(args, "pretty"):
            args.pretty = False
        if not hasattr(args, "strict"):
            args.strict = False

    if args.command == "serve":
        import sdlc_mcp_server

        sys.argv = [sys.argv[0]] + (["--http", str(args.http), "--host", args.host] if args.http is not None else [])
        return sdlc_mcp_server.main()

    if args.command == "completion":
        try:
            script = _completion_script(args.shell)
            print(script)
            return 0
        except InputError as exc:
            print(json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":")), file=sys.stderr)
            return 2

    try:
        result = _HANDLERS[args.command](_build_arguments(args.command, args))
    except InputError as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":")), file=sys.stderr)
        return 2
    except Exception as exc:  # defensive: never dump a traceback at an operator
        print(json.dumps({"status": "error", "error": f"internal error ({exc.__class__.__name__})"}, separators=(",", ":")), file=sys.stderr)
        return 3

    output_format = getattr(args, "format", "json")
    if output_format == "sarif":
        payload: Any = _to_sarif(result) if args.command == "secret-scan" else result
        print(json.dumps(payload, indent=2 if args.pretty else None, separators=None if args.pretty else (",", ":"), ensure_ascii=False))
    elif output_format == "text":
        print(_render_text(args.command, result))
    else:
        print(json.dumps(result, indent=2 if args.pretty else None, separators=None if args.pretty else (",", ":"), ensure_ascii=False))

    status = result.get("status")
    strict = getattr(args, "strict", False)
    if status in {"fail", "blocked"} or (strict and status in {"warning", "needs-review", "dry-run"}):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
