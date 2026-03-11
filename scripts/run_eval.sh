#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"

usage() {
  cat <<'EOF'
Usage: scripts/run_eval.sh [--smoke-only]

Run the current evaluation entrypoints. The scaffold defaults to smoke coverage:
it validates imports, schemas, and repository structure before deeper evaluation
logic is wired to real benchmark cases and kernel runners.
EOF
}

log() {
  printf '[run_eval] %s\n' "$*"
}

main() {
  local smoke_only=0

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --smoke-only)
        smoke_only=1
        ;;
      --help)
        usage
        return 0
        ;;
      *)
        printf 'Unknown argument: %s\n' "$1" >&2
        usage >&2
        return 1
        ;;
    esac
    shift
  done

  cd "${ROOT_DIR}"
  log "running smoke tests"
  "${PYTHON_BIN}" -m pytest tests/test_smoke.py

  if [[ "${smoke_only}" -eq 1 ]]; then
    return 0
  fi

  log "summarizing current benchmark manifests"
  "${PYTHON_BIN}" -m agent.eval --cases-dir benchmark/cases
}

main "$@"

