#compdef sdlc sdlc-mcp sdlc-universal

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
  )
  _describe 'command' commands
}

_sdlc "$@"
