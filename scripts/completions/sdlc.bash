# Bash completion for sdlc CLI
_sdlc_completions() {
  local cur prev commands
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  commands="snapshot release-readiness plugin-preflight read read-batch tree search secret-scan languages deps git-history risk doctor write replace changes rollback audit serve"

  if [[ ${COMP_CWORD} -eq 1 ]]; then
    COMPREPLY=( $(compgen -W "${commands} --version --help -v" -- "${cur}") )
    return
  fi

  case "${COMP_WORDS[1]}" in
    snapshot|release-readiness|languages|deps|git-history|risk|tree|search|secret-scan|read|read-batch|write|replace|changes|rollback|audit)
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
complete -F _sdlc_completions sdlc-universal
