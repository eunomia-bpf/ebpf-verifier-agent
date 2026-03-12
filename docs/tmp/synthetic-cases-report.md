# Synthetic Eval Cases Report

- Generated at: `2026-03-12T00:07:00.727302+00:00`
- Total input eval_commits: `591`
- Total generated synthetic cases: `535`
- Output directory: `case_study/cases/eval_commits_synthetic/`

## Breakdown by taxonomy_class

| taxonomy_class | Count |
| --- | ---: |
| `lowering_artifact` | 249 |
| `source_bug` | 220 |
| `verifier_limit` | 50 |
| `env_mismatch` | 16 |

## Breakdown by fix_type

| fix_type | Count |
| --- | ---: |
| `inline_hint` | 221 |
| `other` | 71 |
| `loop_rewrite` | 50 |
| `bounds_check` | 46 |
| `type_cast` | 37 |
| `alignment` | 32 |
| `null_check` | 20 |
| `volatile_hack` | 17 |
| `helper_switch` | 16 |
| `refactor` | 14 |
| `attribute_annotation` | 11 |

## Breakdown by repository

| repository | Count |
| --- | ---: |
| `https://github.com/cilium/cilium` | 344 |
| `https://github.com/libbpf/libbpf` | 147 |
| `https://github.com/iovisor/bcc` | 34 |
| `https://github.com/facebookincubator/katran` | 10 |

## Example cases

### `synth-eval-bcc-02daf8d84ecd`

- Original commit: `02daf8d84ecd23d4b8c55ccf5b4a0246abe38765`
- Repository: `https://github.com/iovisor/bcc`
- Fix type: `other`

```c
// FILE: libbpf-tools/biosnoop.bpf.c
// CONTEXT: int BPF_PROG(block_rq_complete, struct request *rq, int error,
		__builtin_memcpy(&event.comm, piddatap->comm,
				sizeof(event.comm));
		event.pid = piddatap->pid;
	}
	event.delta = delta;
	if (targ_queued && BPF_CORE_READ(rq, q, elevator)) {
		if (!stagep->insert)
			event.qdelta = -1; /* missed or don't insert entry */
```

### `synth-eval-cilium-01af42293701`

- Original commit: `01af42293701884b0307f69953290a25c5e0e318`
- Repository: `https://github.com/cilium/cilium`
- Fix type: `other`

```c
// FILE: bpf/lib/icmp6.h
// CONTEXT: static inline int icmp6_handle_ns(struct __sk_buff *skb, int nh_off)
	} else {
		/* Unknown target address, drop */
		return TC_ACT_SHOT;
	}
}

static inline int icmp6_handle(struct __sk_buff *skb, int nh_off)
{
```

### `synth-eval-katran-07e10334022f`

- Original commit: `07e10334022f08ef3c6536260e1b028cdf8f5074`
- Repository: `https://github.com/facebookincubator/katran`
- Fix type: `other`

```c
// FILE: katran/lib/bpf/balancer_maps.h
#include "katran/lib/bpf/balancer_consts.h"
#include "katran/lib/bpf/balancer_structs.h"

// map, which contains all the vips for which we are doing load balancing
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct vip_definition);
  __type(value, struct vip_meta);
  __uint(max_entries, MAX_VIPS);
```

### `synth-eval-libbpf-0141d9ddeda6`

- Original commit: `0141d9ddeda60283cc00f5efceaa930834acefb6`
- Repository: `https://github.com/libbpf/libbpf`
- Fix type: `alignment`

```c
// FILE: src/libbpf.c
// CONTEXT: static int bpf_object__collect_externs(struct bpf_object *obj)
			if (ext->kcfg.align <= 0) {
				pr_warn("failed to determine alignment of extern (kcfg) '%s': %d\n",
					ext_name, ext->kcfg.align);
				return -EINVAL;
			}
			ext->kcfg.type = find_kcfg_type(obj->btf, t->type,
						        &ext->kcfg.is_signed);
			if (ext->kcfg.type == KCFG_UNKNOWN) {
```

### `synth-eval-bcc-118bf168f9f6`

- Original commit: `118bf168f9f66f757684e653c080d034b34db2ff`
- Repository: `https://github.com/iovisor/bcc`
- Fix type: `inline_hint`

```c
// FILE: libbpf-tools/tcpconnect.bpf.c
// CONTEXT: struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

static __always_inline bool filter_port(__u16 port)
{
	int i;
```

## Issues encountered

- Skipped 56 of 591 eval_commit inputs based on the C-like/Rust filter.
- Skip reason `rust_source` affected 25 case(s).
- Skip reason `not_c_like` affected 24 case(s).
- Skip reason `unsupported_extension` affected 7 case(s).
- The strict filter already exceeded the 200-case target, so no fallback pass was needed.
- All synthetic cases leave `verifier_log` empty because the source eval_commit corpus does not carry logs.
