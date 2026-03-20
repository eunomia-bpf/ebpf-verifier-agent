#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/qemu-launch-5.10.sh [options]

Boot the Debian 11 (5.10) cloud image for cross-kernel BPF verification.

Options:
  --image PATH        QCOW2 image path (default: /tmp/debian-11-nocloud-amd64.qcow2)
  --share PATH        Host directory to export over 9p (default: repo root)
  --state-dir PATH    Working directory for keys, logs, and seed ISO
  --ssh-port PORT     Host port forwarded to guest SSH (default: 2222)
  --memory MB         Guest RAM in MiB (default: 4096)
  --cpus N            Guest vCPU count (default: 4)
  --seed              Attach a generated NoCloud seed ISO with an SSH key
  --seed-user USER    Username written into the seed ISO (default: root)
  --daemonize         Run QEMU in the background and log serial output to a file
  --tcg               Use TCG instead of KVM
  -h, --help          Show this help text

Environment overrides:
  QEMU_IMAGE, QEMU_HOST_SHARE_PATH, QEMU_STATE_DIR, QEMU_SSH_PORT,
  QEMU_RAM_MB, QEMU_CPUS, QEMU_USE_SEED, QEMU_SEED_USER,
  QEMU_DAEMONIZE, QEMU_FORCE_TCG
EOF
}

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "${SCRIPT_DIR}/.." && pwd)

QEMU_IMAGE=${QEMU_IMAGE:-/tmp/debian-11-nocloud-amd64.qcow2}
QEMU_HOST_SHARE_PATH=${QEMU_HOST_SHARE_PATH:-${REPO_ROOT}}
QEMU_STATE_DIR=${QEMU_STATE_DIR:-${REPO_ROOT}/.cache/qemu/debian-11-5.10}
QEMU_SSH_PORT=${QEMU_SSH_PORT:-2222}
QEMU_RAM_MB=${QEMU_RAM_MB:-4096}
QEMU_CPUS=${QEMU_CPUS:-4}
QEMU_USE_SEED=${QEMU_USE_SEED:-0}
QEMU_SEED_USER=${QEMU_SEED_USER:-root}
QEMU_SEED_HOSTNAME=${QEMU_SEED_HOSTNAME:-debian11-bpf}
QEMU_DAEMONIZE=${QEMU_DAEMONIZE:-0}
QEMU_FORCE_TCG=${QEMU_FORCE_TCG:-0}

while (($# > 0)); do
    case "$1" in
        --image)
            QEMU_IMAGE=$2
            shift 2
            ;;
        --share)
            QEMU_HOST_SHARE_PATH=$2
            shift 2
            ;;
        --state-dir)
            QEMU_STATE_DIR=$2
            shift 2
            ;;
        --ssh-port)
            QEMU_SSH_PORT=$2
            shift 2
            ;;
        --memory)
            QEMU_RAM_MB=$2
            shift 2
            ;;
        --cpus)
            QEMU_CPUS=$2
            shift 2
            ;;
        --seed)
            QEMU_USE_SEED=1
            shift
            ;;
        --seed-user)
            QEMU_SEED_USER=$2
            shift 2
            ;;
        --daemonize)
            QEMU_DAEMONIZE=1
            shift
            ;;
        --tcg)
            QEMU_FORCE_TCG=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

mkdir -p "${QEMU_STATE_DIR}"

QEMU_IMAGE=$(realpath "${QEMU_IMAGE}")
QEMU_HOST_SHARE_PATH=$(realpath "${QEMU_HOST_SHARE_PATH}")
QEMU_STATE_DIR=$(realpath "${QEMU_STATE_DIR}")

KEY_PATH="${QEMU_STATE_DIR}/id_ed25519"
KEY_PUB_PATH="${KEY_PATH}.pub"
SEED_ISO="${QEMU_STATE_DIR}/seed.iso"
PIDFILE="${QEMU_STATE_DIR}/qemu.pid"
SERIAL_LOG="${QEMU_STATE_DIR}/serial.log"
MONITOR_SOCKET="${QEMU_STATE_DIR}/monitor.sock"

ensure_binary() {
    local tool=$1
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "Required tool not found: ${tool}" >&2
        exit 1
    fi
}

ensure_ssh_key() {
    if [[ -f "${KEY_PATH}" && -f "${KEY_PUB_PATH}" ]]; then
        return
    fi
    ensure_binary ssh-keygen
    ssh-keygen -q -t ed25519 -N '' -f "${KEY_PATH}"
}

write_seed_files() {
    local pubkey
    pubkey=$(<"${KEY_PUB_PATH}")

    cat >"${QEMU_STATE_DIR}/meta-data" <<EOF
instance-id: debian11-bpf
local-hostname: ${QEMU_SEED_HOSTNAME}
EOF

    cat >"${QEMU_STATE_DIR}/user-data" <<EOF
#cloud-config
disable_root: false
ssh_pwauth: false
users:
  - default
  - name: ${QEMU_SEED_USER}
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - ${pubkey}
EOF
}

create_seed_iso() {
    ensure_binary xorriso
    ensure_ssh_key
    write_seed_files
    rm -f "${SEED_ISO}"
    (
        cd "${QEMU_STATE_DIR}"
        xorriso -as mkisofs \
            -quiet \
            -volid cidata \
            -joliet \
            -rock \
            -output "${SEED_ISO}" \
            user-data meta-data >/dev/null
    )
}

if [[ ! -f "${QEMU_IMAGE}" ]]; then
    echo "QCOW2 image not found: ${QEMU_IMAGE}" >&2
    echo "Download it first with:" >&2
    echo "  wget -O /tmp/debian-11-nocloud-amd64.qcow2 https://cloud.debian.org/images/cloud/bullseye/latest/debian-11-nocloud-amd64.qcow2" >&2
    echo "  qemu-img resize /tmp/debian-11-nocloud-amd64.qcow2 8G" >&2
    exit 1
fi

if [[ ! -d "${QEMU_HOST_SHARE_PATH}" ]]; then
    echo "9p export path does not exist: ${QEMU_HOST_SHARE_PATH}" >&2
    exit 1
fi

ensure_binary qemu-system-x86_64

qemu_cmd=(
    qemu-system-x86_64
    -name debian-11-5.10-bpf
    -machine q35
    -m "${QEMU_RAM_MB}"
    -smp "${QEMU_CPUS}"
    -device virtio-rng-pci
    -drive "file=${QEMU_IMAGE},if=virtio,format=qcow2"
    -nic "user,model=virtio-net-pci,hostfwd=tcp::${QEMU_SSH_PORT}-:22"
    -virtfs "local,path=${QEMU_HOST_SHARE_PATH},mount_tag=hostshare,security_model=none,id=hostshare"
    -no-reboot
)

if [[ "${QEMU_FORCE_TCG}" == "1" ]]; then
    qemu_cmd+=(-accel tcg,thread=multi -cpu max)
else
    qemu_cmd+=(-enable-kvm -cpu host)
fi

if [[ "${QEMU_USE_SEED}" == "1" ]]; then
    create_seed_iso
    qemu_cmd+=(-drive "file=${SEED_ISO},if=virtio,media=cdrom,readonly=on,format=raw")
else
    ensure_ssh_key
fi

if [[ "${QEMU_DAEMONIZE}" == "1" ]]; then
    rm -f "${PIDFILE}" "${MONITOR_SOCKET}"
    qemu_cmd+=(
        -display none
        -serial "file:${SERIAL_LOG}"
        -monitor "unix:${MONITOR_SOCKET},server=on,wait=off"
        -daemonize
        -pidfile "${PIDFILE}"
    )
else
    qemu_cmd+=(-nographic -serial mon:stdio)
fi

echo "Image: ${QEMU_IMAGE}"
echo "Share: ${QEMU_HOST_SHARE_PATH}"
echo "State: ${QEMU_STATE_DIR}"
echo "SSH key: ${KEY_PUB_PATH}"
echo "SSH port: ${QEMU_SSH_PORT}"
if [[ "${QEMU_USE_SEED}" == "1" ]]; then
    echo "Seed ISO: ${SEED_ISO}"
fi

if [[ "${QEMU_DAEMONIZE}" == "1" ]]; then
    "${qemu_cmd[@]}"
    echo "QEMU launched in the background."
    echo "PID file: ${PIDFILE}"
    echo "Serial log: ${SERIAL_LOG}"
    echo "Monitor socket: ${MONITOR_SOCKET}"
else
    exec "${qemu_cmd[@]}"
fi
