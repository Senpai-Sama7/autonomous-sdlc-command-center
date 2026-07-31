"""Zero-dependency web dashboard for the SDLC control plane.

Serves a single-page dashboard over localhost HTTP using only the stdlib.
The dashboard is READ-ONLY: it renders diagnostics (risk, readiness, audit,
shadows, tools) and never invokes the write engine.

Endpoints:
  GET /                -> dashboard HTML (embedded, no CDN, works offline)
  GET /api/status      -> server version, root, tool inventory
  GET /api/risk        -> risk score result
  GET /api/readiness   -> release readiness result
  GET /api/audit       -> audit log tail + chain validity
  GET /api/shadows     -> active shadow worktree sessions
  GET /api/languages   -> language statistics
  GET /api/doctor      -> environment capability probe

Cross-platform (Windows/Linux/macOS), Python 3.9+, no third-party packages.
"""

from __future__ import annotations

import json
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from sdlc_core import VERSION, release_readiness
from sdlc_analyze import doctor, language_stats, risk_score
from sdlc_write import audit_log
from sdlc_shadow import shadow_list

try:
    from sdlc_mcp_server import TOOLS
except ImportError:
    TOOLS = []

# Bounded concurrency: dashboard API calls scan the filesystem.
_API_LOCK = threading.Lock()


def _safe_call(fn: Callable[..., dict[str, Any]], root: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """Invoke a read-only tool and convert failures into JSON-safe payloads."""

    args: dict[str, Any] = {"path": root}
    if extra:
        args.update(extra)
    with _API_LOCK:
        try:
            return fn(args)
        except Exception as exc:  # dashboard must never 500 on a bad repo
            return {"status": "error", "error": f"{type(exc).__name__}: {exc}"}


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SDLC Command Center</title>
<style>
:root {
  --bg: #0d1117; --panel: #161b22; --border: #30363d; --fg: #e6edf3;
  --muted: #8b949e; --ok: #3fb950; --warn: #d29922; --fail: #f85149;
  --accent: #58a6ff; --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--fg); font: 14px/1.5 -apple-system, "Segoe UI", Roboto, sans-serif; }
header { display: flex; align-items: center; gap: 12px; padding: 14px 20px; border-bottom: 1px solid var(--border); background: var(--panel); flex-wrap: wrap; }
header h1 { font-size: 16px; font-weight: 600; }
header .ver { color: var(--muted); font-family: var(--mono); font-size: 12px; }
header .root { color: var(--muted); font-family: var(--mono); font-size: 12px; overflow: hidden; text-overflow: ellipsis; max-width: 40vw; }
header .spacer { flex: 1; }
.btn { background: var(--panel); color: var(--fg); border: 1px solid var(--border); border-radius: 6px; padding: 5px 12px; font-size: 12px; cursor: pointer; }
.btn:hover { border-color: var(--accent); }
.btn.active { border-color: var(--ok); color: var(--ok); }
main { padding: 20px; max-width: 1280px; margin: 0 auto; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; margin-bottom: 20px; }
.card { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
.card h3 { font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); margin-bottom: 8px; }
.card .big { font-size: 34px; font-weight: 700; font-family: var(--mono); }
.card .sub { color: var(--muted); font-size: 12px; margin-top: 4px; }
.grade-A { color: var(--ok); } .grade-B { color: #7ee787; } .grade-C { color: var(--warn); }
.grade-D, .grade-F { color: var(--fail); }
.dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; flex: none; }
.dot.ok, .dot.pass { background: var(--ok); } .dot.warn, .dot.warning, .dot.unknown { background: var(--warn); } .dot.fail, .dot.error { background: var(--fail); }
section { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 20px; overflow: hidden; }
section > h2 { font-size: 13px; font-weight: 600; padding: 12px 16px; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; }
section > h2 .count { color: var(--muted); font-weight: 400; font-family: var(--mono); font-size: 12px; }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
th, td { text-align: left; padding: 8px 16px; border-bottom: 1px solid var(--border); vertical-align: top; }
th { color: var(--muted); font-weight: 500; font-size: 11px; text-transform: uppercase; letter-spacing: .05em; }
tr:last-child td { border-bottom: none; }
td.mono { font-family: var(--mono); }
.empty { padding: 20px 16px; color: var(--muted); font-size: 13px; }
.badge { display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 11px; font-family: var(--mono); border: 1px solid var(--border); }
.badge.ok, .badge.pass { color: var(--ok); border-color: var(--ok); }
.badge.warn, .badge.warning, .badge.unknown { color: var(--warn); border-color: var(--warn); }
.badge.fail, .badge.error { color: var(--fail); border-color: var(--fail); }
.badge.info { color: var(--accent); border-color: var(--accent); }
.langbar { display: flex; height: 8px; border-radius: 4px; overflow: hidden; margin: 12px 16px; background: var(--border); }
.langbar span { display: block; height: 100%; }
.langlist { padding: 0 16px 14px; display: flex; flex-wrap: wrap; gap: 10px; font-size: 12px; color: var(--muted); }
.langlist b { color: var(--fg); font-weight: 500; }
footer { text-align: center; color: var(--muted); font-size: 11px; padding: 24px; }
.checks { padding: 4px 0; }
.check { display: flex; gap: 10px; padding: 8px 16px; border-bottom: 1px solid var(--border); font-size: 12px; align-items: baseline; }
.check:last-child { border-bottom: none; }
.check .name { font-family: var(--mono); min-width: 180px; }
.check .detail { color: var(--muted); }
@media (max-width: 720px) { .check { flex-direction: column; gap: 2px; } header .root { max-width: 90vw; } }
</style>
</head>
<body>
<header>
  <h1>SDLC Command Center</h1>
  <span class="ver" id="ver">v…</span>
  <span class="root" id="root" title="workspace root"></span>
  <span class="spacer"></span>
  <button class="btn" id="refreshBtn" onclick="refreshAll()">Refresh</button>
  <button class="btn" id="autoBtn" onclick="toggleAuto()">Auto: off</button>
</header>
<main>
  <div class="cards" id="cards"></div>
  <section><h2>Release Readiness <span class="count" id="readinessCount"></span></h2><div class="checks" id="checks"></div></section>
  <section><h2>Audit Log <span class="count" id="auditCount"></span></h2><div id="auditBody"></div></section>
  <section><h2>Shadow Worktrees <span class="count" id="shadowCount"></span></h2><div id="shadowBody"></div></section>
  <section><h2>Languages</h2><div class="langbar" id="langbar"></div><div class="langlist" id="langlist"></div></section>
  <section><h2>Tool Registry <span class="count" id="toolCount"></span></h2><div id="toolBody"></div></section>
  <section><h2>Environment</h2><div id="doctorBody"></div></section>
</main>
<footer>autonomous-sdlc-command-center &middot; zero dependencies &middot; read-only dashboard</footer>
<script>
const $ = id => document.getElementById(id);
const PALETTE = ['#58a6ff','#3fb950','#d29922','#f778ba','#a371f7','#76e3ea','#ffa657','#7ee787','#ff9bce','#d2a8ff'];
let autoTimer = null;

async function api(path) {
  const res = await fetch('/api/' + path);
  if (!res.ok) throw new Error('HTTP ' + res.status);
  return res.json();
}
function esc(s) { return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function badge(status) { return `<span class="badge ${esc(status)}">${esc(status)}</span>`; }
function dot(status) { return `<span class="dot ${esc(status)}"></span>`; }

function card(title, big, bigClass, sub) {
  return `<div class="card"><h3>${esc(title)}</h3><div class="big ${bigClass||''}">${big}</div><div class="sub">${sub||''}</div></div>`;
}

async function loadStatus() {
  const s = await api('status');
  $('ver').textContent = 'v' + s.version;
  $('root').textContent = s.root;
  $('toolCount').textContent = s.toolCount + ' tools';
  const rows = s.tools.map(t => `<tr><td class="mono">${esc(t.name)}</td><td>${esc(t.description)}</td></tr>`).join('');
  $('toolBody').innerHTML = rows ? `<table><tr><th>Tool</th><th>Description</th></tr>${rows}</table>` : '<div class="empty">No tools registered.</div>';
  return s;
}

async function loadRisk() {
  const r = await api('risk');
  const grade = r.grade || '?';
  return card('Risk Score', esc(grade), 'grade-' + esc(grade),
    r.score != null ? `score ${r.score}/100 &middot; ${esc(r.riskLevel || '')}` : esc(r.error || 'unavailable'));
}

async function loadReadiness() {
  const r = await api('readiness');
  const checks = r.checks || [];
  $('readinessCount').textContent = checks.length + ' checks';
  $('checks').innerHTML = checks.length
    ? checks.map(c => `<div class="check">${dot(c.status)}<span class="name">${esc(c.name || c.id || c.check || '')}</span><span class="detail">${esc(c.detail || c.message || '')}</span></div>`).join('')
    : `<div class="empty">${esc(r.error || 'No readiness checks available.')}</div>`;
  const failing = checks.filter(c => c.status === 'fail').length;
  const warn = checks.filter(c => c.status === 'warn' || c.status === 'warning').length;
  const summary = failing ? failing + ' failing' : warn ? warn + ' warnings' : 'all passing';
  return card('Release Readiness', failing ? 'BLOCKED' : warn ? 'WARN' : 'READY', failing ? 'grade-F' : warn ? 'grade-C' : 'grade-A', summary);
}

async function loadAudit() {
  const a = await api('audit');
  $('auditCount').textContent = (a.entryCount || 0) + ' entries';
  const entries = (a.entries || []).slice().reverse();
  $('auditBody').innerHTML = entries.length
    ? `<table><tr><th>Seq</th><th>Time (UTC)</th><th>Action</th><th>Path</th><th>Status</th></tr>` +
      entries.map(e => `<tr><td class="mono">${esc(e.seq)}</td><td class="mono">${esc(e.tsUtc || e.timestamp || '')}</td><td>${esc(e.action || e.op || '')}</td><td class="mono">${esc(e.path || e.file || '')}</td><td>${badge(e.status || 'ok')}</td></tr>`).join('') + '</table>'
    : `<div class="empty">${esc(a.error || 'No writes recorded yet.')}</div>`;
  const valid = a.chainValid !== false;
  return card('Audit Chain', valid ? 'VALID' : 'BROKEN', valid ? 'grade-A' : 'grade-F', (a.entryCount || 0) + ' hash-chained entries');
}

async function loadShadows() {
  const s = await api('shadows');
  $('shadowCount').textContent = (s.activeCount || 0) + ' active';
  const sessions = s.sessions || [];
  $('shadowBody').innerHTML = sessions.length
    ? `<table><tr><th>ID</th><th>Created (UTC)</th><th>Shadow Path</th><th>Status</th></tr>` +
      sessions.map(x => `<tr><td class="mono">${esc((x.sessionId || x.id || '').slice(0, 12))}</td><td class="mono">${esc(x.createdAtUtc || '')}</td><td class="mono">${esc(x.shadowPath || '')}</td><td>${badge(x.status || 'active')}</td></tr>`).join('') + '</table>'
    : `<div class="empty">${esc(s.error || 'No active shadow sessions.')}</div>`;
  return card('Shadow Worktrees', String(s.activeCount || 0), '', 'isolated agent sandboxes');
}

async function loadLanguages() {
  const l = await api('languages');
  const langs = (l.languages || []).slice(0, 10);
  const total = langs.reduce((n, x) => n + (x.lines || 0), 0) || 1;
  $('langbar').innerHTML = langs.map((x, i) => `<span style="width:${(100 * (x.lines || 0) / total).toFixed(1)}%;background:${PALETTE[i % PALETTE.length]}" title="${esc(x.language)}"></span>`).join('');
  $('langlist').innerHTML = langs.map((x, i) => `<span><span class="dot" style="background:${PALETTE[i % PALETTE.length]}"></span><b>${esc(x.language)}</b> ${(x.lines || 0).toLocaleString()} lines</span>`).join('') || '<span>No language data.</span>';
  return card('Primary Language', esc(l.primaryLanguage || '—'), '', (l.totalLines || 0).toLocaleString() + ' lines counted');
}

async function loadDoctor() {
  const d = await api('doctor');
  const caps = d.capabilities || {};
  const rows = Object.entries(caps).map(([k, v]) =>
    `<tr><td class="mono">${esc(k)}</td><td>${typeof v === 'boolean' ? (v ? badge('ok') : badge('warn')) : esc(v)}</td></tr>`).join('');
  const py = d.python || {};
  $('doctorBody').innerHTML = `<table><tr><th>Capability</th><th>Status</th></tr>
    <tr><td class="mono">python</td><td class="mono">${esc(py.version || '')}</td></tr>
    <tr><td class="mono">platform</td><td class="mono">${esc(d.platform || '')}</td></tr>${rows}</table>`;
  return card('Environment', (d.status || 'ok').toUpperCase(), d.status === 'ok' ? 'grade-A' : 'grade-C', 'capability probe');
}

async function refreshAll() {
  try {
    const cards = await Promise.all([
      loadRisk(), loadReadiness(), loadAudit(), loadShadows(), loadLanguages(), loadDoctor(), loadStatus(),
    ]);
    $('cards').innerHTML = cards.filter(c => typeof c === 'string').join('');
  } catch (err) {
    $('cards').innerHTML = card('Connection', 'ERR', 'grade-F', esc(err.message));
  }
}

function toggleAuto() {
  const btn = $('autoBtn');
  if (autoTimer) { clearInterval(autoTimer); autoTimer = null; btn.textContent = 'Auto: off'; btn.classList.remove('active'); }
  else { autoTimer = setInterval(refreshAll, 10000); btn.textContent = 'Auto: 10s'; btn.classList.add('active'); }
}

refreshAll();
</script>
</body>
</html>
"""


class DashboardHandler(BaseHTTPRequestHandler):
    """Read-only dashboard HTTP handler."""

    root: str = "."
    server_version = f"sdlc-dashboard/{VERSION}"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        sys.stderr.write(f"[dashboard] {self.address_string()} {format % args}\n")

    def _send_json(self, payload: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - stdlib signature
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        root = self.root

        if path == "/":
            self._send_html(DASHBOARD_HTML)
            return
        if path == "/health":
            self._send_json({"status": "ok", "version": VERSION})
            return

        routes: dict[str, Callable[[], dict[str, Any]]] = {
            "/api/status": lambda: {
                "status": "ok",
                "version": VERSION,
                "root": root,
                "toolCount": len(TOOLS),
                "tools": [
                    {"name": t.get("name", ""), "description": t.get("description", "")}
                    for t in sorted(TOOLS, key=lambda x: x.get("name", ""))
                ],
            },
            "/api/risk": lambda: _safe_call(risk_score, root),
            "/api/readiness": lambda: _safe_call(release_readiness, root),
            "/api/audit": lambda: _safe_call(audit_log, root, {"maxEntries": 25}),
            "/api/shadows": lambda: _safe_call(shadow_list, root),
            "/api/languages": lambda: _safe_call(language_stats, root),
            "/api/doctor": lambda: _safe_call(doctor, root),
        }
        handler = routes.get(path)
        if handler is None:
            self._send_json({"status": "error", "error": f"unknown endpoint: {path}"}, status=404)
            return
        self._send_json(handler())


def create_dashboard_server(host: str, port: int, root: str) -> ThreadingHTTPServer:
    """Create the dashboard HTTP server bound to host:port."""

    if not 0 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")

    class _Handler(DashboardHandler):
        pass

    _Handler.root = str(Path(root).resolve())
    server = ThreadingHTTPServer((host, port), _Handler)
    server.daemon_threads = True
    return server


def run_dashboard(host: str, port: int, root: str, open_browser: bool = False) -> int:
    """Serve the dashboard until interrupted. Returns process exit code."""

    server = create_dashboard_server(host, port, root)
    actual_host, actual_port = server.server_address[:2]
    url = f"http://{actual_host}:{actual_port}"
    sys.stderr.write(f"sdlc-dashboard {VERSION} on {url} (root={Path(root).resolve()})\n")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
