# Autonomous SDLC Command Center

**Your project's autopilot for quality, security, and delivery readiness.**

The SDLC Command Center is a local-first tool that inspects your software project and tells you, in plain language, what's going on — what shape the code is in, whether there are secrets leaked, if you're ready to release, and how risky the current state is. It can also make safe, approved changes to files with full rollback and audit tracking.

Think of it as a **project health dashboard** that lives in your terminal or connects to your AI coding assistant.

---

## Who is this for?

| If you are... | You can use it to... |
|---|---|
| **A project manager** | Check if a release is ready, see code health scores, understand risk without reading code |
| **A team lead** | Get a quick snapshot of repository structure, dependencies, and delivery signals |
| **A developer** | Search code, read files safely, find secrets, understand language breakdown |
| **A security reviewer** | Scan for leaked secrets, check entropy of tokens, audit file changes |
| **An AI coding agent** | Use 26 built-in tools to inspect, analyze, and safely modify codebases |

---

## What does it do?

The tool answers these questions about any software project:

- **"What's in this repo?"** — File counts, directory structure, language breakdown
- **"Is it ready to ship?"** — Release readiness checks, risk scoring, dependency inventory
- **"Are there secrets in the code?"** — Pattern-based and entropy-based secret detection
- **"What's the code quality?"** — TODO counts, complexity hints, health scoring
- **"Can I safely change a file?"** — Gated writes with backup, rollback, and audit trail
- **"What changed recently?"** — Git history, churn hotspots, author activity

---

## Getting started

### Step 1: Check that Python is installed

Open a terminal and run:

```bash
python3 --version
```

You need Python 3.9 or newer. If you don't have it, download from [python.org](https://www.python.org/downloads/).

### Step 2: Clone or download the project

```bash
git clone https://github.com/Senpai-Sama7/autonomous-sdlc-command-center.git
cd autonomous-sdlc-command-center
```

### Step 3: Run it

**Option A: Using the CLI directly**

```bash
# Check your environment
python3 mcp/sdlc_cli.py doctor

# Scan a project for issues
python3 mcp/sdlc_cli.py snapshot --path /path/to/your/project

# Check if a release is ready
python3 mcp/sdlc_cli.py release-readiness --path /path/to/your/project

# Scan for leaked secrets
python3 mcp/sdlc_cli.py secret-scan --path /path/to/your/project

# Get a risk score (0-100)
python3 mcp/sdlc_cli.py risk --path /path/to/your/project
```

**Option B: Connect to an AI coding assistant**

The tool works as a [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server, which means AI assistants like Claude Desktop, Cursor, Windsurf, and others can use its tools automatically.

```bash
# Start the server (it waits for your AI assistant to connect)
python3 mcp/sdlc_mcp_server.py

# Or run it as a local web service
python3 mcp/sdlc_mcp_server.py --http 8765
```

See [UNIVERSAL_INSTALL.md](UNIVERSAL_INSTALL.md) for setup instructions for each AI assistant.

**Option C: PowerShell (Windows)**

```powershell
.\scripts\commands\repo_snapshot.ps1 -Path C:\your\project
.\scripts\commands\release_readiness.ps1 -Path C:\your\project
```

---

## The 26 tools — what each one does

### Reading and understanding your project

These tools look at your project and report back. They never change anything.

| Tool | What it does in plain English |
|---|---|
| **repo_snapshot** | Gives you a complete inventory: how many files, what types, directory tree, symlinks, non-UTF-8 files, and optional git status |
| **release_readiness** | Answers "can we ship this?" by checking for README, license, tests, git state, and whitespace issues |
| **plugin_preflight** | Validates that plugin manifests and skill contracts are correctly formatted |
| **read_file** | Safely reads a single file with automatic secret redaction and binary detection |
| **read_files** | Reads up to 20 files at once (same safety as read_file) |
| **directory_tree** | Shows the folder structure up to a configurable depth |
| **search_code** | Searches across all text files using regex patterns, with context lines |
| **language_stats** | Breaks down the project by programming language (file count and line count) |
| **dependency_inventory** | Lists all dependencies from package.json, requirements.txt, pyproject.toml, go.mod, Cargo.toml |
| **git_history** | Shows recent commits, distinct authors, and which files change most often |
| **risk_score** | Gives the project a risk grade from A (low risk) to F (high risk) based on multiple signals |
| **doctor** | Checks that the tool itself is working correctly on your system |
| **list_changes** | Shows all file changes that have been made through the write engine (for rollback) |
| **audit_log** | Reads the tamper-evident audit trail and verifies its integrity |

### Finding secrets

| Tool | What it does in plain English |
|---|---|
| **secret_scan** | Looks for patterns that look like API keys, passwords, tokens, and credentials. Always redacts the actual values — it reports where secrets are, not what they are |
| **entropy_scan** *(new)* | Finds secrets that pattern-based scanning misses. Uses math (Shannon entropy) to detect randomly-generated strings like API keys, JWTs, and tokens that don't match any known pattern. Handles deduplication and shows safe previews |

### Code quality

| Tool | What it does in plain English |
|---|---|
| **code_metrics** | Counts TODOs, FIXMEs, large files, long lines, empty files, and flags files with high branch density. Gives an overall health score from A to F |
| **sbom** | Creates a Software Bill of Materials (SBOM) — a list of every dependency your project uses, in a standard format |

### Making changes (safely)

These tools can modify files, but only when you explicitly approve. Every change is backed up first.

| Tool | What it does in plain English |
|---|---|
| **write_file** | Creates or overwrites a file. Shows a preview of what will change before you confirm |
| **replace_in_file** | Finds exact text in a file and replaces it. Verifies the number of matches before applying |
| **replace_in_file_ast** *(new)* | Same as replace_in_file, but smarter for Python files. It understands code structure, so it only replaces text inside string literals — it won't accidentally change variable names or code logic |
| **rollback** | Undoes a previous change by its ID. Restores the original content or deletes files that were created |

### Shadow workspaces (new)

These tools let you make changes in an isolated copy of your project, test them, and only merge back if everything works.

| Tool | What it does in plain English |
|---|---|
| **shadow_create** | Creates a temporary copy of your project (a Git worktree) where you can make changes without affecting the real project |
| **shadow_promote** | Checks if your changes conflict with anything in the real project, then copies them over if it's safe |
| **shadow_destroy** | Cleans up a temporary workspace when you're done with it |
| **shadow_list** | Shows all active temporary workspaces |

---

## How the safety system works

The write engine is designed so that **mistakes are recoverable**. Here's how:

1. **Preview first** — Every change starts as a dry-run. You see exactly what will change (a diff preview) before anything happens.

2. **Confirm to apply** — Nothing changes unless you explicitly say "yes, do it" (pass `confirm: true`).

3. **Backup before change** — The original content is saved in `.sdlc/backups/` before any file is modified.

4. **Atomic writes** — Changes are written to a temporary file first, then swapped in place. If something fails mid-write, the original is preserved.

5. **Audit trail** — Every change is recorded in `.sdlc/audit.jsonl` with a cryptographic hash chain. If anyone tampers with the log, it's detectable.

6. **Rollback** — Any change can be undone by its unique ID. The tool restores the exact original content.

```
You run a write tool
        │
        ▼
   ┌─────────┐
   │ Dry-run │ ──► Shows you the diff preview
   └────┬────┘
        │ confirm: true
        ▼
   ┌─────────┐
   │ Backup  │ ──► Saves original to .sdlc/backups/
   └────┬────┘
        │
        ▼
   ┌─────────┐
   │ Write   │ ──► Atomic temp file + rename
   └────┬────┘
        │
        ▼
   ┌─────────┐
   │ Audit   │ ──► Appends to hash-chained log
   └─────────┘
```

---

## Installation for AI coding assistants

The SDLC Command Center works as an MCP server, which means AI assistants can use its tools automatically. Here's how to connect it:

### Universal install (recommended)

```bash
# Install the CLI and MCP server globally
pip install --user -e .

# The binaries are now at:
#   ~/.local/bin/sdlc        (CLI)
#   ~/.local/bin/sdlc-mcp    (MCP server)
```

### Connecting to your AI assistant

| Assistant | Config location | What to add |
|---|---|---|
| **OpenCode** | `~/.config/opencode/opencode.jsonc` | Add `sdlc-mcp` to the MCP servers section |
| **Claude Desktop** | `~/.config/Claude/claude_desktop_config.json` | Add the server command to `mcpServers` |
| **Claude Code** | `~/.claude.json` | Add to `mcpServers` |
| **Cursor** | `~/.cursor/mcp.json` | Add to `mcpServers` |
| **Windsurf** | `~/.codeium/windsurf/mcp_config.json` | Add to `mcpServers` |
| **VSCode** | `~/.vscode/mcp.json` | Add to `servers` |
| **Gemini** | `~/.gemini/settings.json` | Add to `mcpServers` |

See [UNIVERSAL_INSTALL.md](UNIVERSAL_INSTALL.md) for exact configuration examples for each assistant.

---

## Configuration

### Environment variables

| Variable | Default | What it controls |
|---|---|---|
| `SDLC_RATE_LIMIT_CALLS` | `60` | Maximum calls per tool per time window |
| `SDLC_RATE_LIMIT_WINDOW_SECONDS` | `60` | Time window for rate limiting (seconds) |
| `SDLC_ALLOW_NETWORK_PATHS` | (unset) | Set to `1` to allow scanning network/UNC paths |

### MCP server options

```bash
# Run on stdio (default, for AI assistants)
python3 mcp/sdlc_mcp_server.py

# Run as HTTP server
python3 mcp/sdlc_mcp_server.py --http 8765

# Custom host
python3 mcp/sdlc_mcp_server.py --http 8765 --host 0.0.0.0
```

---

## What's in the box

| Component | Description | Works on |
|---|---|---|
| **MCP Server** | 26 tools over stdio or localhost HTTP | Windows, Linux, macOS (Python 3.9+) |
| **CLI** | Full tool surface for any shell or CI runner | Windows, Linux, macOS (Python 3.9+) |
| **Skills** | 7 workflow skills with machine-readable contracts | Any harness that loads Markdown |
| **PowerShell** | Snapshot, readiness, preflight scripts | Windows PowerShell / pwsh |
| **Tests** | 48 cross-platform smoke tests | Python 3.9+ |
| **Install scripts** | Universal bash and PowerShell installers | Bash, PowerShell |

**No third-party packages. No network calls against targets. No telemetry.**

---

## Running the tests

```bash
# Run the full test suite
python3 scripts/tests/smoke.py

# Expected: 48 passed, 0 failed, 1 skipped (UNC test is Windows-only)
```

---

## Project structure

```
autonomous-sdlc-command-center/
├── mcp/                          # Core Python modules
│   ├── sdlc_core.py              # Shared utilities, file walking, git helpers
│   ├── sdlc_analyze.py           # Read-only analysis tools
│   ├── sdlc_write.py             # Safety-gated write engine
│   ├── sdlc_extensions.py        # Extended tools (metrics, SBOM, entropy, AST)
│   ├── sdlc_shadow.py            # Shadow worktree engine
│   ├── sdlc_mcp_server.py        # MCP server (stdio + HTTP)
│   └── sdlc_cli.py               # Command-line interface
├── scripts/
│   ├── commands/                 # PowerShell automation
│   ├── tests/                    # Smoke tests
│   ├── completions/              # Shell tab-completions (bash, zsh)
│   ├── install.sh                # Universal bash installer
│   └── install.ps1               # PowerShell installer
├── skills/                       # 7 workflow skills
├── hooks/                        # Lifecycle hooks
├── docs/                         # Operating model documentation
├── ANALYSIS_REPORT.md            # Deep analysis and evaluation
├── UNIVERSAL_INSTALL.md          # AI assistant setup guide
├── SECURITY.md                   # Security notes
├── PORTABILITY.md                # Cross-platform compatibility
└── README.md                     # This file
```

---

## Deep dives

- **[Operating Model](docs/OPERATING_MODEL.md)** — How the tool fits into your development workflow
- **[Security Notes](SECURITY.md)** — Detailed security guarantees and safety invariants
- **[Portability](PORTABILITY.md)** — Cross-platform compatibility details
- **[Universal Install](UNIVERSAL_INSTALL.md)** — Step-by-step AI assistant setup
- **[Analysis Report](ANALYSIS_REPORT.md)** — Deep code analysis and quality evaluation

---

## License

See [LICENSE](LICENSE) for details.
