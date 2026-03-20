# Cross-Kernel Setup Research for `lowering_artifact` Verification

Date: 2026-03-19

This note answers the specific question: how can we run BPF programs against older `5.x` kernels on this machine, so `lowering_artifact` cases can be verified against an actual older verifier?

## Short Answer

- This host is currently running `6.15.11-061511-generic` and has **no installed `5.x` kernels**.
- `QEMU/KVM` is available and usable on this host now.
- **Docker is not a solution** for older-kernel verifier testing, because Docker containers share the host kernel.
- The fastest practical `5.x` path is:
  - **`5.10`**: boot a **Debian 11 bullseye `nocloud` qcow2** image in QEMU/KVM.
  - **`5.15`**: boot an **Ubuntu 22.04 Jammy cloud KVM image** in QEMU/KVM.
  - **`5.4`**: boot an **Ubuntu 20.04 Focal cloud KVM image** in QEMU/KVM.
- The best workflow is to **compile BPF `.o` files once on the host**, then **load the same object inside multiple guest kernels** and capture verifier logs there.

## 1. What Kernels Are Available On This Machine?

### Running kernel

```text
$ uname -r
6.15.11-061511-generic
```

### Bootable kernels under `/boot`

```text
$ ls /boot/vmlinuz-*
/boot/vmlinuz-6.11.0-1002-intel
/boot/vmlinuz-6.13.0+
/boot/vmlinuz-6.13.0-061300-generic
/boot/vmlinuz-6.13.0-rc1chainIO+
/boot/vmlinuz-6.14.0-1007-intel
/boot/vmlinuz-6.14.0-1008-intel
/boot/vmlinuz-6.14.0-37-generic
/boot/vmlinuz-6.15.11-061511-generic
```

### Installed module trees

```text
$ ls /lib/modules
6.11.0-1002-intel
6.11.0-19-generic
6.12.3-061203-generic
6.13.0-061300-generic
6.14.0-1007-intel
6.14.0-1008-intel
6.14.0-22-generic
6.14.0-32-generic
6.14.0-33-generic
6.14.0-34-generic
6.14.0-35-generic
6.14.0-36-generic
6.14.0-37-generic
6.15.11-061511-generic
6.8.0-41-generic
6.8.0-51-generic
6.8.0-52-generic
```

### Installed kernel packages

`dpkg -l 'linux-image-*'` shows only `6.x` kernel packages. There is **no installed `5.4`, `5.10`, or `5.15` host kernel** to boot into directly.

### Current `apt` sources

```text
$ apt-cache search '^linux-image-5\.15'
(no results)

$ apt-cache search '^linux-image-5\.10'
(no results)

$ apt-cache search '^linux-image-5\.4'
(no results)
```

Conclusion: with the host's current Noble `apt` configuration, **old `5.x` kernels are not directly installable from the currently enabled repositories**.

## 2. Is QEMU/KVM Available?

Yes.

```text
$ which qemu-system-x86_64
/usr/bin/qemu-system-x86_64

$ which kvm
/usr/bin/kvm

$ kvm --version
QEMU emulator version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.13)
```

The QEMU binary supports both software and hardware acceleration:

```text
$ qemu-system-x86_64 -accel help
Accelerators supported in QEMU binary:
tcg
kvm
```

KVM is actually present and usable:

```text
$ ls -l /dev/kvm
crw-rw----+ 1 root kvm 10, 232 Mar 19 17:27 /dev/kvm
```

The current user is in the `kvm` group, so non-root QEMU/KVM runs should work:

```text
$ id
uid=1000(yunwei37) gid=1000(yunwei37) groups=...,993(kvm)
```

Supporting host tools:

- Present:
  - `qemu-system-x86_64`
  - `qemu-img`
  - `docker`
  - `clang 18.1.3`
  - `bpftool` at `/usr/local/sbin/bpftool`
- Missing but installable:
  - `cloud-localds` from `cloud-image-utils`
  - `virtiofsd`

Useful QEMU features already built into the local binary:

```text
$ qemu-system-x86_64 -h
...
-fsdev ...
-virtfs local,path=path,mount_tag=tag,...
...
-kernel bzImage
-append cmdline
-initrd file
...
hostfwd=rule
```

So this host already supports the two practical paths we need:

- booting **disk images** with KVM
- booting a **direct kernel/initramfs**
- sharing files through **9p (`-virtfs`)**

## 3. Can We Get Prebuilt `5.4` / `5.10` / `5.15` Kernel Images?

Yes. There are three realistic sources.

### Option A: Ubuntu cloud images

This is the cleanest source for **Ubuntu `5.4`** and **Ubuntu `5.15`** guests.

#### Ubuntu 20.04 Focal for `5.4`

The official Focal release directory still publishes a KVM image:

- `ubuntu-20.04-server-cloudimg-amd64-disk-kvm.img`
- size shown on 2025-06-25: about `596M`

The official manifest for that image includes:

```text
linux-image-5.4.0-216-generic   5.4.0-216.236
linux-image-virtual             5.4.0.216.208
linux-modules-5.4.0-216-generic 5.4.0-216.236
```

So the current official Focal cloud image is still a valid **Ubuntu `5.4` guest**.

Note: the directory marks Focal builds as `[END OF REGULAR SUPPORT]`. That matters for maintenance, but not for reproducing old verifier behavior in a VM.

#### Ubuntu 22.04 Jammy for `5.15`

The official Jammy release directory publishes:

- `ubuntu-22.04-server-cloudimg-amd64-disk-kvm.img`
- size shown on 2026-02-27: about `629M`

The official Jammy manifest includes:

```text
linux-image-5.15.0-171-generic   5.15.0-171.181
linux-image-virtual              5.15.0.171.160
linux-modules-5.15.0-171-generic 5.15.0-171.181
```

So Jammy is the cleanest **Ubuntu `5.15` guest**.

#### Takeaway

- Use **Focal** if you explicitly want a `5.4` Ubuntu verifier.
- Use **Jammy** if you explicitly want a `5.15` Ubuntu verifier.
- Ubuntu cloud images are tied to Ubuntu release/kernel tracks, so they are **not the best route for `5.10`**.

### Option B: Debian 11 bullseye cloud images

This is the cleanest official source for **`5.10`**.

The Debian Cloud Team's official image directory explicitly says:

- plain VM images are suitable for local QEMU
- `nocloud` images do not run cloud-init and **boot directly to a root prompt**

That is unusually useful here.

Current official bullseye image files include:

- `debian-11-nocloud-amd64.qcow2` at about `320M`
- `debian-11-genericcloud-amd64.qcow2` at about `274M`

The official JSON metadata shows:

#### `nocloud`

```text
linux-image-5.10.0-39-amd64  5.10.251-1
linux-image-amd64            5.10.251-1
```

#### `genericcloud`

```text
linux-image-5.10.0-39-cloud-amd64  5.10.251-1
linux-image-cloud-amd64            5.10.251-1
```

So Debian 11 gives an official, current, low-friction **`5.10` guest**.

#### Takeaway

- For a real `5.10` kernel in QEMU, **Debian 11 bullseye is the best prebuilt option**.
- For local use, **`nocloud` is simpler than `genericcloud`** because it avoids cloud-init and boots directly to a root shell.

### Option C: Ubuntu mainline kernel archive

The Ubuntu mainline archive currently exposes `v5.4.*`, `v5.10.*`, and `v5.15.*` directories, including recent entries such as:

- `v5.4.282`
- `v5.10.251`
- `v5.15.199`

Version-specific directories contain prebuilt `.deb` packages such as:

- `linux-image-unsigned-...generic_...amd64.deb`
- `linux-modules-...generic_...amd64.deb`
- headers packages

Example from `v5.10.251/amd64/`:

```text
linux-image-unsigned-5.10.251-0510251-generic_..._amd64.deb
linux-modules-5.10.251-0510251-generic_..._amd64.deb
linux-headers-5.10.251-0510251-generic_..._amd64.deb
```

Example from `v5.15.199/amd64/`:

```text
linux-image-unsigned-5.15.199-0515199-generic_..._amd64.deb
linux-modules-5.15.199-0515199-generic_..._amd64.deb
linux-headers-5.15.199-0515199-generic_..._amd64.deb
```

This is useful if we want:

- an exact kernel version
- direct `-kernel` boot in QEMU
- or a custom rootfs/initramfs

But it is **more manual** than just booting a ready-made cloud disk image.

### Option D: old distro `.deb` packages

Also possible, but not the best first step.

Example: Debian bullseye's official package page still shows:

```text
Package: linux-image-cloud-amd64 (5.10.251-1)
Depends: linux-image-5.10.0-39-cloud-amd64 (= 5.10.251-1)
```

Ubuntu package pages similarly show Jammy `linux-signed` building many `linux-image-5.15.0-*-generic` packages.

So old distro kernel packages are obtainable, but on this host they are **not directly available via current `apt` sources**. That means manual download plus local installation, which is exactly the path we want to avoid on the host.

## 4. Minimal QEMU Setup For BPF Verification

There are four practical choices.

### A. QEMU with prebuilt kernel + initramfs, no disk image

Technically viable, but **not the fastest first working setup**.

What it would require:

1. Download a prebuilt kernel and modules from the Ubuntu mainline archive, or use another prebuilt kernel package source.
2. Build or assemble an initramfs that contains:
   - enough userspace to mount `proc`, `sysfs`, `bpffs`
   - a shell
   - either `bpftool` or a custom loader
   - any needed modules
3. Boot with:

```bash
qemu-system-x86_64 \
  -enable-kvm \
  -cpu host \
  -m 4096 \
  -smp 4 \
  -nographic \
  -kernel /path/to/vmlinuz \
  -initrd /path/to/initrd.img \
  -append 'console=ttyS0 rdinit=/init'
```

Pros:

- exact kernel pinning
- no full guest install
- attractive for later CI

Cons:

- you still need a working rootfs or rich initramfs
- you still need userland tooling for loading BPF and collecting logs
- more assembly work than a cloud image

Verdict: **good future optimization, bad first setup choice**.

### B. QEMU with a cloud or nocloud disk image

This is the **best first working path**.

#### Best `5.10` path: Debian 11 `nocloud`

Minimal boot shape:

```bash
qemu-system-x86_64 \
  -enable-kvm \
  -cpu host \
  -m 4096 \
  -smp 4 \
  -nographic \
  -drive file=debian-11-nocloud-amd64.qcow2,if=virtio,format=qcow2 \
  -nic user,hostfwd=tcp::2222-:22 \
  -virtfs local,path=$PWD,mount_tag=hostshare,security_model=none
```

Why this is attractive:

- official `5.10` guest
- small qcow2 image
- boots directly to root prompt
- no cloud-init dependency

#### Best `5.15` path: Ubuntu 22.04 Jammy KVM image

This is also clean, but usually wants a cloud-init seed ISO to define users and SSH keys. On this host:

- `cloud-localds` is **not installed**
- but `cloud-image-utils` is available from `apt`

Typical boot shape:

```bash
qemu-system-x86_64 \
  -enable-kvm \
  -cpu host \
  -m 4096 \
  -smp 4 \
  -nographic \
  -drive file=ubuntu-22.04-server-cloudimg-amd64-disk-kvm.img,if=virtio \
  -drive file=seed.img,format=raw,if=virtio \
  -nic user,hostfwd=tcp::2222-:22 \
  -virtfs local,path=$PWD,mount_tag=hostshare,security_model=none
```

Verdict: **good**, but slightly more setup than Debian `nocloud`.

### C. Docker with a `5.x` userspace

Not valid for this problem.

Reason: Docker containers share the **host kernel**. A Docker container with Ubuntu 20.04 or Debian 11 userspace still runs against the host `6.15.11` kernel, so the BPF verifier is still the host verifier.

For BPF verifier testing across kernel versions, you need:

- a real older host boot
- or a VM with a real older guest kernel

So **QEMU/KVM is required** if we do not want to reboot the real host.

### D. Install an old kernel package on the host and reboot

Possible, but not recommended.

Problems:

- current `apt` sources do not offer those `5.x` kernels directly
- manual `.deb` installation on the host is invasive
- it changes the real workstation boot configuration
- it requires reboot orchestration
- it does not scale well to a matrix of kernels

Verdict: **not the right first move**.

## 5. Guest Tooling: What Is The Minimum Needed?

For verifier-only research, the guest does **not** need a full clang toolchain if we compile on the host.

### Best minimal split

- Host:
  - compile BPF object files with `clang`
  - optionally build helper binaries
- Guest:
  - receive the `.o`
  - load it with `bpftool` or a small custom loader
  - capture verifier logs

This is better than compiling everything inside every guest.

### Reuse the repo's existing loader

This repo already has [`case_study/selftest_prog_loader.c`](/home/yunwei37/workspace/ebpf-verifier-agent/case_study/selftest_prog_loader.c), which:

- opens a `.bpf.o`
- enables a `16 MiB` verifier log buffer
- autoloads only the selected program
- prints JSON with `load_ok`, `error_message`, and `verifier_log`

That is better for automation than scraping `bpftool --debug` output.

So the ideal guest-side command is not "just run bpftool", but rather:

- either build and run the repo loader inside the guest
- or use `bpftool` for quick manual smoke tests

If we build the loader inside the guest, the guest still needs a small native build environment such as `gcc` plus `libbpf` and `libelf` development packages. If we want zero guest build dependencies, then `bpftool` or a prebuilt guest-compatible loader binary is better.

### File sharing methods

#### Recommended first: `9p` via `-virtfs`

Why:

- the host QEMU binary already supports it
- no extra host package is needed
- it is good enough for sharing `.o`, small sources, and logs

Typical guest mount:

```bash
mkdir -p /mnt/host
mount -t 9p -o trans=virtio,version=9p2000.L hostshare /mnt/host
```

#### Better later: `virtiofs`

Pros:

- better semantics and performance than 9p

Cons on this machine right now:

- `virtiofsd` is not installed

So this is a good second step, not the minimum viable first one.

#### Lowest-friction fallback: SSH / SCP

Because QEMU supports `hostfwd`, we can also:

- boot with `-nic user,hostfwd=tcp::2222-:22`
- `scp` the `.o` into the guest
- run the loader over SSH

This avoids filesystem-sharing issues entirely.

#### Not recommended first: NFS

It works, but it is more setup than needed for this use case.

## 6. Practical Recommendation

### Fastest path overall

If the goal is "get an older real verifier running in QEMU as fast as possible on this machine", the best first step is:

1. Use **Debian 11 bullseye `nocloud`** for `5.10`.
2. Share files with **9p**.
3. Compile BPF objects on the host.
4. Load them in the guest with the repo's loader or `bpftool`.
5. Capture verifier logs into the shared directory.

Why this wins:

- smallest download among the serious options
- no cloud-init dependency
- direct console login
- official `5.10` kernel

### Best Ubuntu-aligned path

If the preference is to stay on Ubuntu guests:

- use **Jammy 22.04** for `5.15`
- use **Focal 20.04** for `5.4`

This is still practical, just slightly more annoying than Debian `nocloud` because it usually wants cloud-init seeding.

### Estimated setup time

Assuming the images are downloaded over a normal connection and we compile on the host:

- Debian 11 `nocloud` `5.10`:
  - first boot: about `10-20 min`
  - to first verifier run: about `15-30 min`
- Ubuntu 22.04 Jammy `5.15`:
  - first boot: about `15-25 min`
  - to first verifier run: about `20-35 min`
- Direct `-kernel/-initrd` custom setup:
  - more like `1-2+ hours` for the first reliable environment

### Expected disk usage

Approximate lower bound per guest:

- Debian 11 `nocloud` qcow2 download: about `320M`
- Debian 11 `genericcloud` qcow2 download: about `274M`
- Ubuntu 20.04 KVM image download: about `596M`
- Ubuntu 22.04 KVM image download: about `629M`

Practical working disk footprint after boot plus some packages:

- minimal verifier-only guest: roughly `2-4 GiB`
- guest with clang/llvm/libbpf toolchain installed inside: more like `5-10 GiB`

### Can this be automated?

Yes.

A small script can automate:

1. image download
2. optional `qemu-img resize`
3. QEMU launch
4. guest bootstrap
5. host-to-guest sharing or copy
6. running the loader
7. collecting JSON verifier logs

For this machine specifically:

- automation for Debian `nocloud` is easiest
- automation for Ubuntu cloud images is also fine, but either needs:
  - `cloud-image-utils`, or
  - another way to preseed credentials

## 7. Cross-Kernel Compilation: Can We Compile Once And Load On Multiple Kernels?

Mostly yes, with important caveats.

### The good part

An eBPF object file compiled by `clang -target bpf` is **not tied to the host runtime kernel version** the way a native x86 kernel module is. In other words:

- compiling the `.o` on host `6.15`
- then loading that same `.o` inside a `5.10` or `5.15` guest

is a valid and desirable workflow.

That is exactly the right shape for a cross-kernel verifier experiment.

### The caveats

It is **not** true that every BPF object is universally kernel-version-independent.

The same `.o` can still fail on older kernels if it uses:

- BPF instructions or program types unsupported there
- helpers unsupported there
- map types unsupported there
- newer attach types or kfuncs
- CO-RE relocations that require target-kernel BTF and type layouts

So the accurate statement is:

- **compile once, load on multiple kernels** is the ideal workflow
- but only if the program's feature set is compatible with the oldest kernel in the matrix

### What this means for `lowering_artifact`

For many `lowering_artifact` cases, this workflow is exactly what we want:

- compile the buggy and fixed versions once on the host
- keep the bytecode constant
- vary only the target kernel verifier
- compare reject/pass behavior and verifier logs

That isolates kernel-verifier differences much better than recompiling inside each guest.

### Recommended policy

- Compile on the host.
- Target the **oldest kernel feature set** you care about.
- Load the same `.o` into each guest.
- If a program depends on newer helpers or BTF features, mark it as not portable to the older kernel instead of forcing the comparison.

## Final Recommendation

For this machine, the fastest credible way to get older-kernel verifier coverage for `lowering_artifact` work is:

1. Start with **Debian 11 `nocloud` in QEMU/KVM** for `5.10`.
2. Add **Ubuntu 22.04 Jammy in QEMU/KVM** for `5.15`.
3. Compile BPF `.o` files on the host once.
4. Use **9p** or SSH to get them into the guest.
5. Run the existing repo loader in the guest and collect JSON verifier logs.

That gives a workable `5.10` / `5.15` verifier matrix without touching the host bootloader or rebooting the workstation.

## Sources

Machine-local observations:

- `uname -r`
- `ls /boot/vmlinuz-*`
- `ls /lib/modules`
- `dpkg -l 'linux-image-*'`
- `apt-cache search '^linux-image-5\.(4|10|15)'`
- `which qemu-system-x86_64`
- `which kvm`
- `kvm --version`
- `qemu-system-x86_64 -accel help`
- `qemu-system-x86_64 -h`
- `ls -l /dev/kvm`
- `id`

Official external sources:

- Ubuntu cloud images index: <https://cloud-images.ubuntu.com/releases/>
- Ubuntu 20.04 release directory: <https://cloud-images.ubuntu.com/releases/focal/release/>
- Ubuntu 20.04 manifest: <https://cloud-images.ubuntu.com/releases/focal/release/ubuntu-20.04-server-cloudimg-amd64.manifest>
- Ubuntu 22.04 release directory: <https://cloud-images.ubuntu.com/releases/jammy/release/>
- Ubuntu 22.04 manifest: <https://cloud-images.ubuntu.com/releases/jammy/release/ubuntu-22.04-server-cloudimg-amd64.manifest>
- Debian official cloud images: <https://cloud.debian.org/images/cloud/>
- Debian bullseye images: <https://cloud.debian.org/images/cloud/bullseye/latest/>
- Debian bullseye `genericcloud` metadata: <https://cloud.debian.org/images/cloud/bullseye/latest/debian-11-genericcloud-amd64.json>
- Debian bullseye `nocloud` metadata: <https://cloud.debian.org/images/cloud/bullseye/latest/debian-11-nocloud-amd64.json>
- Debian bullseye kernel package page: <https://packages.debian.org/bullseye/linux-image-cloud-amd64>
- Debian bullseye `bpftool` package page: <https://packages.debian.org/bullseye/bpftool>
- Ubuntu mainline kernel archive: <https://kernel.ubuntu.com/mainline/>
- Ubuntu mainline `v5.10.251` amd64: <https://kernel.ubuntu.com/mainline/v5.10.251/amd64/>
- Ubuntu mainline `v5.15.199` amd64: <https://kernel.ubuntu.com/mainline/v5.15.199/amd64/>
- QEMU documentation search result showing `-kernel` and `-virtfs` examples: <https://qemu.readthedocs.io/_/downloads/en/v8.1.5/pdf/>
