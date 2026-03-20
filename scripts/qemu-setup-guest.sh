#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: sudo bash scripts/qemu-setup-guest.sh [options]

Run inside the Debian 11 guest after first boot.

Options:
  --authorized-key PATH  Install a host SSH public key for root login
  --skip-smoke-test      Skip compiling and loading the in-guest smoke test
  --test-object PATH     Load an existing .o file instead of building the smoke test
  --mount-point PATH     9p mount point (default: /mnt/host)
  --share-tag TAG        9p mount tag (default: hostshare)
  -h, --help             Show this help text
EOF
}

AUTHORIZED_KEY_PATH=
SKIP_SMOKE_TEST=0
TEST_OBJECT=
HOST_SHARE_MOUNT=${HOST_SHARE_MOUNT:-/mnt/host}
HOST_SHARE_TAG=${HOST_SHARE_TAG:-hostshare}

while (($# > 0)); do
    case "$1" in
        --authorized-key)
            AUTHORIZED_KEY_PATH=$2
            shift 2
            ;;
        --skip-smoke-test)
            SKIP_SMOKE_TEST=1
            shift
            ;;
        --test-object)
            TEST_OBJECT=$2
            shift 2
            ;;
        --mount-point)
            HOST_SHARE_MOUNT=$2
            shift 2
            ;;
        --share-tag)
            HOST_SHARE_TAG=$2
            shift 2
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

if [[ ${EUID} -ne 0 ]]; then
    echo "Run this script as root inside the guest." >&2
    exit 1
fi

log() {
    printf '[qemu-setup] %s\n' "$*"
}

install_packages() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y \
        bpftool \
        ca-certificates \
        clang \
        cloud-guest-utils \
        file \
        fdisk \
        gcc \
        git \
        iproute2 \
        iputils-ping \
        jq \
        libbpf-dev \
        libelf-dev \
        linux-libc-dev \
        make \
        openssh-server \
        pkg-config \
        procps \
        psmisc \
        rsync \
        sudo \
        zlib1g-dev
}

bootstrap_resize_tools() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y cloud-guest-utils fdisk
}

resize_rootfs() {
    local root_source root_fstype disk_name part_num disk part_basename

    root_source=$(findmnt -n -o SOURCE /)
    root_fstype=$(findmnt -n -o FSTYPE /)
    disk_name=$(lsblk -no PKNAME "${root_source}" 2>/dev/null || true)
    part_basename=$(basename -- "${root_source}")

    if [[ "${part_basename}" =~ p([0-9]+)$ ]]; then
        part_num=${BASH_REMATCH[1]}
    elif [[ "${part_basename}" =~ ([0-9]+)$ ]]; then
        part_num=${BASH_REMATCH[1]}
    else
        part_num=
    fi

    if [[ -z "${disk_name}" || -z "${part_num}" ]]; then
        log "Skipping root resize: could not resolve root block device from ${root_source}."
        return
    fi

    disk="/dev/${disk_name}"
    log "Growing partition ${root_source} on ${disk}."
    growpart "${disk}" "${part_num}" || true
    if command -v partprobe >/dev/null 2>&1; then
        partprobe "${disk}" || true
    fi
    udevadm settle || true

    case "${root_fstype}" in
        ext2|ext3|ext4)
            resize2fs "${root_source}"
            ;;
        xfs)
            xfs_growfs /
            ;;
        *)
            log "Skipping filesystem resize: unsupported filesystem ${root_fstype}."
            ;;
    esac
}

mount_host_share() {
    mkdir -p "${HOST_SHARE_MOUNT}"

    if ! grep -qE "^[^#]+[[:space:]]+${HOST_SHARE_MOUNT}[[:space:]]+9p" /etc/fstab; then
        printf '%s %s 9p trans=virtio,version=9p2000.L,msize=262144,cache=loose 0 0\n' \
            "${HOST_SHARE_TAG}" "${HOST_SHARE_MOUNT}" >>/etc/fstab
    fi

    modprobe 9pnet_virtio || true
    if ! mountpoint -q "${HOST_SHARE_MOUNT}"; then
        mount "${HOST_SHARE_MOUNT}" || \
            mount -t 9p -o trans=virtio,version=9p2000.L,msize=262144,cache=loose \
                "${HOST_SHARE_TAG}" "${HOST_SHARE_MOUNT}"
    fi
}

configure_ssh() {
    local pubkey
    [[ -n "${AUTHORIZED_KEY_PATH}" ]] || return

    if [[ ! -f "${AUTHORIZED_KEY_PATH}" ]]; then
        echo "Authorized key file not found: ${AUTHORIZED_KEY_PATH}" >&2
        exit 1
    fi

    mkdir -p /root/.ssh /etc/ssh/sshd_config.d
    chmod 700 /root/.ssh

    pubkey=$(<"${AUTHORIZED_KEY_PATH}")
    touch /root/.ssh/authorized_keys
    if ! grep -qxF "${pubkey}" /root/.ssh/authorized_keys; then
        printf '%s\n' "${pubkey}" >>/root/.ssh/authorized_keys
    fi
    chmod 600 /root/.ssh/authorized_keys

    cat >/etc/ssh/sshd_config.d/99-qemu-root.conf <<'EOF'
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication no
EOF

    systemctl enable --now ssh
}

mount_bpffs() {
    mkdir -p /sys/fs/bpf
    if ! mountpoint -q /sys/fs/bpf; then
        mount -t bpf bpffs /sys/fs/bpf
    fi
}

build_smoke_object() {
    local test_dir src obj
    test_dir=/tmp/qemu-bpf-smoke
    src="${test_dir}/smoke.bpf.c"
    obj="${test_dir}/smoke.bpf.o"

    mkdir -p "${test_dir}"
    cat >"${src}" <<'EOF'
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("socket")
int smoke_socket(struct __sk_buff *skb)
{
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
EOF

    clang -target bpf -O2 -g \
        -I/usr/include/x86_64-linux-gnu \
        -I/usr/include \
        -c "${src}" \
        -o "${obj}"

    printf '%s\n' "${obj}"
}

run_smoke_test() {
    local obj pin_path log_path status
    obj=${TEST_OBJECT}
    if [[ -z "${obj}" ]]; then
        obj=$(build_smoke_object)
    fi

    if [[ ! -f "${obj}" ]]; then
        echo "Smoke test object not found: ${obj}" >&2
        exit 1
    fi

    mount_bpffs
    pin_path="/sys/fs/bpf/qemu_smoke_${RANDOM}"
    log_path=/var/log/qemu-bpf-smoke.log

    log "Loading ${obj} with bpftool."
    set +e
    ulimit -l unlimited || true
    bpftool -d prog load "${obj}" "${pin_path}" >"${log_path}" 2>&1
    status=$?
    set -e

    cat "${log_path}"
    rm -f "${pin_path}" || true

    if [[ -d "${HOST_SHARE_MOUNT}/.cache/qemu" ]]; then
        cp "${log_path}" "${HOST_SHARE_MOUNT}/.cache/qemu/guest-smoke.log"
    fi

    return "${status}"
}

log "Installing the tools needed to grow the root filesystem."
bootstrap_resize_tools
log "Resizing the guest root filesystem."
resize_rootfs
log "Installing guest packages."
install_packages

log "Mounting the host 9p share at ${HOST_SHARE_MOUNT}."
mount_host_share

if [[ -n "${AUTHORIZED_KEY_PATH}" ]]; then
    log "Installing the requested SSH public key for root."
    configure_ssh
fi

if [[ "${SKIP_SMOKE_TEST}" != "1" ]]; then
    log "Running the BPF smoke test."
    run_smoke_test
else
    log "Skipping the smoke test by request."
fi

log "Setup complete."
