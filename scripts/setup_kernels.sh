#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KERNELS_DIR="${ROOT_DIR}/.kernels"

usage() {
  cat <<'EOF'
Usage: scripts/setup_kernels.sh [kernel-version...]

Prepare local directories for the kernel versions used in reproduction and
cross-kernel evaluation. This scaffold does not download or build kernels yet;
it creates a predictable layout that later automation can fill in.
EOF
}

log() {
  printf '[setup_kernels] %s\n' "$*"
}

prepare_kernel_dir() {
  local version="$1"
  local target="${KERNELS_DIR}/${version}"
  mkdir -p "${target}/src" "${target}/build" "${target}/artifacts"
  log "prepared ${target}"
}

main() {
  if [[ "${1:-}" == "--help" ]]; then
    usage
    return 0
  fi

  mkdir -p "${KERNELS_DIR}"

  if [[ "$#" -eq 0 ]]; then
    set -- 6.1 6.6 6.8
  fi

  for version in "$@"; do
    prepare_kernel_dir "${version}"
  done

  log "next step: extend this script with kernel fetch/build logic or container setup"
}

main "$@"

