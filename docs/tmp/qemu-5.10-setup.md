# Debian 11 QEMU/KVM Setup for 5.10 BPF Verification

Date: 2026-03-19

## Goal

Bring up a Debian 11 guest with a 5.10 kernel, load BPF `.o` files inside that guest, and capture verifier logs for cross-kernel comparison.

## Files Added

- `scripts/qemu-launch-5.10.sh`
- `scripts/qemu-setup-guest.sh`
- `scripts/qemu-verify-bpf.sh`

## Host Prerequisites

- `qemu-system-x86_64`
- `qemu-img`
- KVM access via `/dev/kvm`
- SSH client tools: `ssh`, `scp`, `ssh-keygen`
- Optional seed-ISO fallback tooling: `xorriso`

Observed on this host on 2026-03-19:

- `qemu-system-x86_64`: present
- `qemu-img`: present
- `xorriso`: present
- `/dev/kvm`: present and the current user is in the `kvm` group
- `cloud-localds`, `virt-customize`, `guestfish`: not present

## Setup

1. Download the Debian 11 image:

```bash
wget -O /tmp/debian-11-nocloud-amd64.qcow2 \
  https://cloud.debian.org/images/cloud/bullseye/latest/debian-11-nocloud-amd64.qcow2
```

2. Resize it to leave room for guest packages:

```bash
qemu-img resize /tmp/debian-11-nocloud-amd64.qcow2 8G
```

3. Boot the VM in serial-console mode:

```bash
./scripts/qemu-launch-5.10.sh
```

Notes:

- The launcher exports the repo root into the guest as a 9p share with mount tag `hostshare`.
- The launcher creates an SSH key pair under `.cache/qemu/debian-11-5.10/`.
- Use `--daemonize` if you want QEMU to stay in the background.
- Use `--seed` if the image needs a NoCloud seed ISO for SSH bootstrap.

4. From the guest console, run the setup script from the shared repo:

On this host, on 2026-03-19, the current Debian 11 `nocloud` image booted to `debian login:` on serial console, not straight to a root prompt. Logging in as `root` with no password on the serial console worked.

Mount the repo share first, then run the setup script:

```bash
mkdir -p /mnt/host
mount -t 9p -o trans=virtio,version=9p2000.L,msize=262144 hostshare /mnt/host
bash /mnt/host/scripts/qemu-setup-guest.sh \
  --authorized-key /mnt/host/.cache/qemu/debian-11-5.10/id_ed25519.pub
```

What the guest setup script does:

- installs `cloud-guest-utils` and `fdisk` first, so `growpart` can fix the GPT layout after `qemu-img resize`
- installs `bpftool`, `libbpf-dev`, `clang`, and related tools
- grows the root partition and filesystem if the image was resized
- mounts the 9p repo share at `/mnt/host`
- enables root SSH login by key
- compiles and loads a minimal `SEC("socket")` smoke-test BPF program

5. Verify guest kernel version:

```bash
uname -r
```

Expected result: a `5.10.x` Debian bullseye kernel.

## Verifying a BPF Object

After `qemu-setup-guest.sh` has installed the SSH key and `sshd` is running:

```bash
./scripts/qemu-verify-bpf.sh path/to/program.bpf.o
```

Behavior:

- waits for SSH on `127.0.0.1:2222`
- uses the shared 9p mount automatically if the object lives under this repo
- otherwise copies the object over `scp`
- runs `bpftool -d prog load` in the guest
- prints the verifier output and stores a copy under `.cache/qemu/debian-11-5.10/verifier-logs/`

If the object contains multiple BPF programs, use:

```bash
./scripts/qemu-verify-bpf.sh --loadall path/to/program.bpf.o
```

## Launch Script Notes

Examples:

```bash
./scripts/qemu-launch-5.10.sh --daemonize
./scripts/qemu-launch-5.10.sh --seed
./scripts/qemu-launch-5.10.sh --image /path/to/debian-11-genericcloud-amd64.qcow2 --seed
```

The `--seed` mode exists because this host does not have `cloud-localds` or libguestfs tooling. The launcher generates a `cidata` ISO itself with `xorriso`.

## Troubleshooting

### The VM does not expose a usable root console

On 2026-03-19 the current `debian-11-nocloud-amd64.qcow2` image did expose a serial login prompt and accepted `root` with no password on the console. If that changes for a future image build, try:

```bash
./scripts/qemu-launch-5.10.sh --seed
```

If the `nocloud` image still behaves unexpectedly, try the Debian 11 `genericcloud` image with the same launcher plus `--seed`.

### SSH never comes up

Check these in the guest:

```bash
systemctl status ssh
mount | grep ' /mnt/host '
```

Re-run the guest setup with the launcher-generated public key:

```bash
sudo bash /mnt/host/scripts/qemu-setup-guest.sh \
  --authorized-key /mnt/host/.cache/qemu/debian-11-5.10/id_ed25519.pub
```

### The 9p share does not mount

In the guest:

```bash
modprobe 9pnet_virtio
mount -t 9p -o trans=virtio,version=9p2000.L hostshare /mnt/host
```

### `bpftool prog load` fails with an empty or short log

Try the guest-side smoke test first:

```bash
sudo bash /mnt/host/scripts/qemu-setup-guest.sh --skip-smoke-test
bpftool -d prog load /tmp/qemu-bpf-smoke/smoke.bpf.o /sys/fs/bpf/smoke_test
```

Also try `--loadall` for multi-program objects.

## Test Results

Status on 2026-03-19: worked.

Observed results:

- Boot succeeded under `KVM` with the Debian image from `https://cloud.debian.org/images/cloud/bullseye/latest/debian-11-nocloud-amd64.qcow2`.
- Guest kernel reported `uname -r = 5.10.0-39-amd64`.
- The image did not boot straight to a root shell; it stopped at `debian login:` on serial console.
- Serial login as `root` with no password worked on this image build.
- The first run of `qemu-setup-guest.sh` installed the guest packages and loaded the in-guest smoke-test BPF object successfully.
- After fixing the resize logic to install `fdisk` and parse the partition number from `/dev/vda1`, a second run of `qemu-setup-guest.sh --skip-smoke-test` expanded `/dev/vda1` from about `2.8G` to `7.7G` (`df -h /`).
- `./scripts/qemu-verify-bpf.sh .cache/qemu/debian-11-5.10/host-smoke.bpf.o` succeeded over SSH and captured the verifier log at `.cache/qemu/debian-11-5.10/verifier-logs/host-smoke.bpf.o.log`.

Representative verifier result:

```text
kernel=5.10.0-39-amd64
libbpf: verifier log:
func#0 @0
0: (b7) r0 = 0
1: (95) exit
verification time 11 usec
processed 2 insns
```

Fallback status:

- The `--seed` path was implemented but not required for this host/image combination once the serial-console root login behavior was discovered.
