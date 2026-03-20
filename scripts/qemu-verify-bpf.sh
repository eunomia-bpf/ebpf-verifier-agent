#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/qemu-verify-bpf.sh [options] path/to/program.bpf.o

Load a BPF object inside the Debian 11 guest and print the verifier log.

Options:
  --ssh-port PORT      Host port forwarded to guest SSH (default: 2222)
  --ssh-user USER      SSH username (default: root)
  --ssh-key PATH       Private key used for SSH
  --state-dir PATH     QEMU state dir for keys and known_hosts
  --scp-always         Always copy the object over SCP instead of using the 9p mount
  --loadall            Use `bpftool prog loadall` instead of `bpftool prog load`
  -h, --help           Show this help text
EOF
}

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "${SCRIPT_DIR}/.." && pwd)

QEMU_STATE_DIR=${QEMU_STATE_DIR:-${REPO_ROOT}/.cache/qemu/debian-11-5.10}
QEMU_SSH_PORT=${QEMU_SSH_PORT:-2222}
QEMU_SSH_USER=${QEMU_SSH_USER:-root}
QEMU_SSH_KEY=${QEMU_SSH_KEY:-${QEMU_STATE_DIR}/id_ed25519}
SCP_ALWAYS=0
LOAD_MODE=load

while (($# > 0)); do
    case "$1" in
        --ssh-port)
            QEMU_SSH_PORT=$2
            shift 2
            ;;
        --ssh-user)
            QEMU_SSH_USER=$2
            shift 2
            ;;
        --ssh-key)
            QEMU_SSH_KEY=$2
            shift 2
            ;;
        --state-dir)
            QEMU_STATE_DIR=$2
            shift 2
            ;;
        --scp-always)
            SCP_ALWAYS=1
            shift
            ;;
        --loadall)
            LOAD_MODE=loadall
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            break
            ;;
        -*)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
        *)
            break
            ;;
    esac
done

if [[ $# -ne 1 ]]; then
    usage >&2
    exit 2
fi

OBJECT_PATH=$(realpath "$1")
QEMU_STATE_DIR=$(realpath "${QEMU_STATE_DIR}")
QEMU_SSH_KEY=$(realpath "${QEMU_SSH_KEY}")

if [[ ! -f "${OBJECT_PATH}" ]]; then
    echo "BPF object not found: ${OBJECT_PATH}" >&2
    exit 1
fi

if [[ ! -f "${QEMU_SSH_KEY}" ]]; then
    echo "SSH private key not found: ${QEMU_SSH_KEY}" >&2
    echo "Run scripts/qemu-launch-5.10.sh once to create it, then install the matching public key in the guest." >&2
    exit 1
fi

mkdir -p "${QEMU_STATE_DIR}/verifier-logs"

KNOWN_HOSTS="${QEMU_STATE_DIR}/known_hosts"
LOG_PATH="${QEMU_STATE_DIR}/verifier-logs/$(basename "${OBJECT_PATH}").log"

ssh_opts=(
    -i "${QEMU_SSH_KEY}"
    -p "${QEMU_SSH_PORT}"
    -o BatchMode=yes
    -o ConnectTimeout=5
    -o StrictHostKeyChecking=accept-new
    -o UserKnownHostsFile="${KNOWN_HOSTS}"
)

wait_for_ssh() {
    local attempt
    for attempt in $(seq 1 30); do
        if ssh "${ssh_opts[@]}" "${QEMU_SSH_USER}@127.0.0.1" true >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done
    return 1
}

if ! wait_for_ssh; then
    echo "Timed out waiting for SSH on port ${QEMU_SSH_PORT}. Did you run qemu-setup-guest.sh in the guest?" >&2
    exit 1
fi

REMOTE_OBJECT=
if [[ "${SCP_ALWAYS}" == "0" && "${OBJECT_PATH}" == "${REPO_ROOT}/"* ]]; then
    REMOTE_OBJECT=/mnt/host/${OBJECT_PATH#${REPO_ROOT}/}
else
    REMOTE_OBJECT=/tmp/$(basename "${OBJECT_PATH}")
    scp \
        -i "${QEMU_SSH_KEY}" \
        -P "${QEMU_SSH_PORT}" \
        -o BatchMode=yes \
        -o StrictHostKeyChecking=accept-new \
        -o UserKnownHostsFile="${KNOWN_HOSTS}" \
        "${OBJECT_PATH}" \
        "${QEMU_SSH_USER}@127.0.0.1:${REMOTE_OBJECT}" >/dev/null
fi

remote_script=$(cat <<'EOF'
set -euo pipefail

obj=$1
load_mode=$2
pin_path="/sys/fs/bpf/qemu_verify_$$"

mkdir -p /sys/fs/bpf
if ! mountpoint -q /sys/fs/bpf; then
    mount -t bpf bpffs /sys/fs/bpf
fi

cleanup() {
    rm -rf "${pin_path}" 2>/dev/null || true
}
trap cleanup EXIT

set +e
ulimit -l unlimited || true
if [[ "${load_mode}" == "loadall" ]]; then
    output=$(bpftool -d prog loadall "${obj}" "${pin_path}" 2>&1)
else
    output=$(bpftool -d prog load "${obj}" "${pin_path}" 2>&1)
fi
status=$?
set -e

printf 'kernel=%s\n' "$(uname -r)"
printf '%s\n' "${output}"
exit "${status}"
EOF
)

set +e
ssh "${ssh_opts[@]}" "${QEMU_SSH_USER}@127.0.0.1" \
    "bash -s -- '${REMOTE_OBJECT}' '${LOAD_MODE}'" <<<"${remote_script}" | tee "${LOG_PATH}"
status=${PIPESTATUS[0]}
set -e

echo "Verifier log saved to ${LOG_PATH}" >&2
exit "${status}"
