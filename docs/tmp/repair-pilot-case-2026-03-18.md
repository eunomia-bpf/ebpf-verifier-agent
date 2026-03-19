# Repair Pilot Case: 2026-03-18

## Executive Summary

I screened several corpus candidates and fully closed the local reject -> diagnose -> repair -> pass loop for `stackoverflow-70760516`.

This case is a good proof-of-concept for OBLIGE's repair pipeline because:

- it has a real verifier log and full source in the corpus YAML;
- the current OBLIGE diagnostic classifies it as `lowering_artifact` with `proof_status=established_then_lost`;
- a small source-level repair based on the accepted Stack Overflow answer makes the program pass the verifier on this machine.

Important caveat:

- the corpus ground-truth file currently auto-labels `stackoverflow-70760516` as `source_bug`;
- the current OBLIGE pipeline, the accepted answer, and the local verifier behavior all support a loop-carried proof-loss interpretation instead.

I also checked `stackoverflow-73088287`, which is manually labeled `lowering_artifact`, but on this machine's `6.15.11` kernel the buggy standalone repro loaded successfully, so it could not serve as the local reject/pass pilot even though it is still a useful taxonomy example.

## Candidate Screening

### Cases checked first

- `stackoverflow-70750259`
  - canonical TLS-extension case;
  - manually labeled `lowering_artifact`;
  - current OBLIGE result: `never_established`, so it is a "should be established_then_lost" candidate, not the cleanest local pilot.
- `stackoverflow-79530762`
  - current OBLIGE result: `established_then_lost`;
  - strong diagnostic, but the YAML has no `source_snippets`, so it is weaker for a write-up anchored in the corpus file itself.
- `stackoverflow-73088287`
  - manually labeled `lowering_artifact`;
  - accepted answer is the classic redundant-index-check repair;
  - local standalone repro passed on this kernel, so it was not suitable for a local reject/pass demonstration.

### Why I chose `stackoverflow-70760516`

- real verifier log in the corpus YAML;
- full source in `source_snippets`;
- current OBLIGE output is already `established_then_lost`;
- accepted answer provides a concrete repair strategy;
- I reproduced verifier rejection locally and verified a repaired variant passes locally.

## Chosen Case

- Case ID: `stackoverflow-70760516`
- YAML: `case_study/cases/stackoverflow/stackoverflow-70760516.yaml`
- Stack Overflow title: `BPF verifier fails because of invalid access to packet`

## Why This Looks Like A Lowering / Proof-Loss Artifact

The source does perform a packet-bounds check before reading the next extension header:

```c
if (data_end < (data + sizeof(struct extension))) {
    goto end;
}

struct extension *ext = (struct extension *) data;
data += sizeof(struct extension);

if (data_end < ((char *) ext) + sizeof(struct extension)) {
    goto end;
}

if (ext->type == SERVER_NAME_EXTENSION) {
    ...
}
```

The failure is not "forgot to bounds-check before dereference". The problem is that `data` is advanced by a variable `ext_len` on every loop iteration, so the verifier's tracked packet-offset upper bound keeps growing across the loop back-edge. Eventually the verifier loses the proof that `ext` still points inside the packet even though each iteration performs a local size check.

The accepted answer explains the same core issue in terms of accumulated `umax_value`: repeated `data += ext_len` causes the verifier's worst-case packet offset to exceed the packet-offset tracking budget, and the next `ext->type` read is rejected.

That is exactly the kind of "proof existed in source structure, but the verifier-visible proof was lost after lowering / loop normalization / value tracking" situation OBLIGE is meant to repair conservatively.

## Corpus Verifier Error

The key tail of the corpus log is:

```text
; if (ext->type == SERVER_NAME_EXTENSION) {
14: (71) r6 = *(u8 *)(r0 +0)
invalid access to packet, off=90 size=1, R0(id=22,off=90,r=0)
R0 offset is outside of the packet
```

## OBLIGE Diagnostic On The Corpus Log

Command used:

```bash
python3 - <<'PY'
from interface.extractor.pipeline import generate_diagnostic
import yaml
path='case_study/cases/stackoverflow/stackoverflow-70760516.yaml'
case=yaml.safe_load(open(path))
log=case['verifier_log']['combined']
result=generate_diagnostic(log)
print(result.text)
print(result.json_data['metadata']['proof_status'])
print(result.json_data['failure_class'])
print(result.json_data['metadata']['obligation'])
PY
```

Result:

```text
error[OBLIGE-E001]: lowering_artifact — proof established, then lost before rejection
  ┌─ <source>
  │
12 │     if (data_end < (data + sizeof(struct extension))) {
   │     ──────────────────────────────────── proof established
   │     R0: pkt(range=0, off=90) → pkt(range=0, off=90)
   │
14 │     if (ext->type == SERVER_NAME_EXTENSION) {
   │     ──────────────────────────────────── proof lost: verifier-visible bounds were lost
   │     R0: pkt(range=0, off=90)
   │
14 │     if (ext->type == SERVER_NAME_EXTENSION) {
   │     ──────────────────────────────────── rejected
   │     R0: pkt(range=0, off=90)
   │
  = note: A verifier-visible proof existed earlier but was lost before the rejected instruction.
  = help: Insert a guard using `data_end`.
```

Key metadata:

- `proof_status`: `established_then_lost`
- `failure_class`: `lowering_artifact`
- obligation: `bounds_check`
- required proof: `R0: off + 1 <= range`

## Buggy Source From The Corpus

This is the source snippet stored in the YAML:

```c
struct server_name {
    char server_name[256];
};

struct extension {
    __u16 type;
    __u16 len;
} __attribute__((packed));

struct sni_extension {
    __u16 list_len;
    __u8 type;
    __u16 len;
} __attribute__((packed));

#define SERVER_NAME_EXTENSION 0

SEC("xdp")
int collect_ips_prog(struct xdp_md *ctx) {
    char *data_end = (char *)(long)ctx->data_end;
    char *data = (char *)(long)ctx->data;

    if (data_end < (data + sizeof(__u16))) {
        goto end;
    }

    __u16 extension_method_len = __bpf_htons(*(__u16 *) data);

    data += sizeof(__u16);

    for(int i = 0; i < extension_method_len; i += sizeof(struct extension)) {
        if (data_end < (data + sizeof(struct extension))) {
            goto end;
        }

        struct extension *ext = (struct extension *) data;

        data += sizeof(struct extension);

        ///////////////////// (A) ////////////////////
        if (data_end < ((char *) ext) + sizeof(struct extension)) {
            goto end;
        }

        if (ext->type == SERVER_NAME_EXTENSION) { // Error happens here
            struct server_name sn;

            if (data_end < (data + sizeof(struct sni_extension))) {
                goto end;
            }

            struct sni_extension *sni = (struct sni_extension *) data;

            data += sizeof(struct sni_extension);

            __u16 server_name_len = __bpf_htons(sni->len);

            for(int sn_idx = 0; sn_idx < server_name_len; sn_idx++) {
                if (data_end < data + sn_idx) {
                    goto end;
                }

                if (sn.server_name + sizeof(struct server_name) < sn.server_name + sn_idx) {
                    goto end;
                }

                sn.server_name[sn_idx] = data[sn_idx];
            }

            sn.server_name[server_name_len] = 0;
            goto end;
        }

        __u16 ext_len = __bpf_htons(ext->len);

        if (ext_len > 30000) {
            goto end;
        }

        if (data_end < data + ext_len) {
            goto end;
        }

        data += ext_len;
        i += ext_len;
    }

end:
    return XDP_PASS;
}
```

## Manual Analysis

### Safety condition

At the `ext->type` load, the verifier needs a proof that `ext` still points to a valid `struct extension` in packet memory. In OBLIGE's terms, the missing obligation is:

```text
R0: off + 1 <= range
```

### Where it is established

It is established by the loop-head guard:

```c
if (data_end < (data + sizeof(struct extension))) {
    goto end;
}
```

and redundantly echoed by:

```c
if (data_end < ((char *) ext) + sizeof(struct extension)) {
    goto end;
}
```

### Where it is lost

It is lost across the loop-carried state:

- `data` is advanced by a variable `ext_len`;
- `i` is also advanced by the same `ext_len`;
- the verifier accumulates worst-case packet offset across iterations;
- after enough iterations, the packet-pointer range proof is no longer available at the next `ext->type` load.

### Why the repair works

The accepted-answer repair makes the loop verifier-friendly by bounding the total worst-case pointer growth:

- bound the number of iterations, e.g. `MAX_EXTENSIONS = 32`;
- bound each extension size, e.g. `MAX_EXTENSION_BYTES = 2048`;
- maintain a separate cursor and stop when it exceeds the declared extension region.

This gives the verifier a conservative global bound on how far the cursor can move:

```text
32 * 2048 = 65536
```

That is enough to keep the loop-carried packet offset inside the verifier's packet-offset reasoning budget.

## Local Reproduction On This Machine

### Repro artifacts

I created two standalone XDP repro files:

- `docs/tmp/repair-pilot-70760516-buggy.c`
- `docs/tmp/repair-pilot-70760516-fixed.c`

Note:

- the local repro simplifies the `SERVER_NAME_EXTENSION` branch body to `return XDP_DROP;`;
- this is intentional, because the verifier rejection happens at the `ext->type` read itself, before the SNI-copy body matters;
- the simplification keeps the dereference control-relevant so Clang does not dead-code-eliminate the whole loop.

### Buggy variant

Compile:

```bash
clang -O2 -target bpf -c docs/tmp/repair-pilot-70760516-buggy.c \
  -o /tmp/repair-pilot-70760516-buggy.o
```

Verify:

```bash
sudo -n bpftool -d prog load /tmp/repair-pilot-70760516-buggy.o \
  /sys/fs/bpf/oblige70760516_buggy type xdp
```

Result:

- load failed with exit code `255`;
- verifier rejection reproduced locally.

Key local verifier tail:

```text
15: (2d) if r5 > r2 goto pc+21
16: (71) r0 = *(u8 *)(r6 +0)
invalid access to packet, off=14 size=1, R6(id=3,off=14,r=0)
R6 offset is outside of the packet
```

The exact offset differs from the corpus log because the standalone repro is smaller, but the failure mode is the same: the next-iteration header read is rejected after loop-carried proof loss.

### Repaired variant

Compile:

```bash
clang -O2 -target bpf -c docs/tmp/repair-pilot-70760516-fixed.c \
  -o /tmp/repair-pilot-70760516-fixed.o
```

Verify:

```bash
sudo -n bpftool -d prog load /tmp/repair-pilot-70760516-fixed.o \
  /sys/fs/bpf/oblige70760516_fixed type xdp
```

Result:

- load succeeded with exit code `0`;
- verifier accepted the repaired program on this machine.

Tail of the successful verifier log:

```text
verification time 3327 usec
stack depth 0
processed 971 insns (limit 1000000) max_states_per_insn 4 total_states 17 peak_states 17 mark_read 3
```

## The Repair

The repaired standalone variant uses the accepted-answer strategy:

```c
#define MAX_EXTENSIONS 32
#define MAX_EXTENSION_BYTES 2048

char *cursor = (char *)(unsigned long)ctx->data;
__u16 extension_method_len = *(__u16 *)cursor;
cursor += sizeof(__u16);

for (int i = 0; i < MAX_EXTENSIONS; i++) {
    if (cursor > data + extension_method_len) {
        goto end;
    }

    if (data_end < (cursor + sizeof(struct extension))) {
        goto end;
    }

    struct extension *ext = (struct extension *)cursor;
    cursor += sizeof(struct extension);

    if (ext->type == SERVER_NAME_EXTENSION) {
        return XDP_DROP;
    }

    if (ext->len > MAX_EXTENSION_BYTES) {
        goto end;
    }

    if (data_end < cursor + ext->len) {
        goto end;
    }

    cursor += ext->len;
}
```

This is conservative, but it is exactly the sort of source-level "clamp and restructure" repair that is practical for OBLIGE to synthesize.

## What OBLIGE Would Need To Synthesize Automatically

For this case, a viable automatic repair policy would be:

1. Detect that the failing dereference is on a loop-carried packet cursor whose proof was established at loop entry and then lost at the back-edge.
2. Infer that the cursor growth comes from repeated `cursor += ext_len`.
3. Introduce a verifier-visible global budget on cursor growth.
4. Rewrite the source into a cursor-based loop with:
   - a fixed maximum iteration count, or
   - an explicit cumulative remaining-budget variable.
5. Clamp each per-iteration extension length before it is added to the cursor.

The conservative repair OBLIGE could synthesize first is the one I verified:

- add `MAX_EXTENSIONS`;
- add `MAX_EXTENSION_BYTES`;
- switch to a `cursor` variable;
- guard `cursor > data + extension_method_len`;
- guard `ext->len > MAX_EXTENSION_BYTES`.

A more semantics-preserving second-generation repair would track `remaining = extension_method_len - consumed` and require `ext->len <= remaining`, but the bounded-loop/bounded-chunk repair is already enough to prove the end-to-end concept.

## Final Assessment

### What is proven

- OBLIGE can identify a real packet-bounds proof-loss case from the corpus as `established_then_lost`.
- A simple source-level repair exists.
- A repaired standalone translation of the case passes the verifier on this machine.

### Caveat

- the corpus's current ground-truth file marks `stackoverflow-70760516` as `source_bug`;
- I do not think that label matches the current diagnosis or the accepted-answer explanation particularly well;
- if strict agreement with the existing label set is required, the best manual-labeled fallback is `stackoverflow-73088287`, but that case no longer fails on this kernel, so it is weaker as a local end-to-end pilot.
