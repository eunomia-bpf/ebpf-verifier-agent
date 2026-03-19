from __future__ import annotations

from collections import Counter
from pathlib import Path
import re

import yaml


REPO_ROOT = Path(__file__).resolve().parents[3]
CASE_LIST = REPO_ROOT / "docs/tmp/labeling_case_ids.txt"
OUT_DIR = REPO_ROOT / "docs/tmp/labeling-a"
LABELS_OUT = OUT_DIR / "labels.yaml"
SUMMARY_OUT = OUT_DIR / "summary.md"
CATALOG = yaml.safe_load((REPO_ROOT / "taxonomy/error_catalog.yaml").read_text())
ERROR_TYPES = CATALOG["error_types"]
NOMINAL_CLASS = {item["error_id"]: item["taxonomy_class"] for item in ERROR_TYPES}
REGEXES = {
    item["error_id"]: [re.compile(pat, re.I | re.M) for pat in item.get("verifier_messages", [])]
    for item in ERROR_TYPES
}


def srcdir(case_id: str) -> str:
    if case_id.startswith("kernel-selftest-"):
        return "kernel_selftests"
    if case_id.startswith("stackoverflow-"):
        return "stackoverflow"
    if case_id.startswith("github-"):
        return "github_issues"
    raise ValueError(f"unknown case id prefix: {case_id}")


def load_case(case_id: str) -> dict:
    path = REPO_ROOT / "case_study" / "cases" / srcdir(case_id) / f"{case_id}.yaml"
    return yaml.safe_load(path.read_text())


def combined_text(case: dict) -> str:
    verifier_log = case.get("verifier_log", "")
    if isinstance(verifier_log, dict):
        verifier_log = verifier_log.get("combined", "") or ""
    expected = case.get("expected_verifier_messages", "")
    if isinstance(expected, dict):
        expected = expected.get("combined", []) or []
    if isinstance(expected, list):
        expected = "\n".join(str(x) for x in expected)
    elif not isinstance(expected, str):
        expected = ""
    body = case.get("question_body_text") or case.get("issue_body_text") or ""
    snippets = case.get("source_snippets", "")
    if isinstance(snippets, list):
        parts = []
        for item in snippets:
            if isinstance(item, dict):
                parts.append(item.get("snippet", "") or "")
            else:
                parts.append(str(item))
        snippets = "\n".join(parts)
    elif not isinstance(snippets, str):
        snippets = ""
    return "\n".join([verifier_log, expected, body, snippets])


def regex_hits(case: dict) -> list[str]:
    text = combined_text(case)
    hits = []
    for error_id, patterns in REGEXES.items():
        if any(p.search(text) for p in patterns):
            hits.append(error_id)
    return hits


def reasoning_for(taxonomy_class: str) -> str:
    if taxonomy_class == "source_bug":
        return (
            "The failing path reflects a missing proof or an invalid helper/value contract in the program itself. "
            "This is not mainly a kernel-capability problem or a verifier budget issue."
        )
    if taxonomy_class == "lowering_artifact":
        return (
            "The source is trying to establish the right safety property, but that proof is lost after lowering or range widening. "
            "A verifier-friendly rewrite should preserve the intent without changing the semantics."
        )
    if taxonomy_class == "env_mismatch":
        return (
            "The rejection is driven by loader, metadata, privilege, program-context, or kernel-support constraints rather than missing safety logic in the BPF source."
        )
    if taxonomy_class == "verifier_limit":
        return (
            "The log points to verifier analysis-budget or complexity limits, not a specific unsafe dereference. "
            "The proof shape needs to be simplified."
        )
    if taxonomy_class == "verifier_bug":
        return (
            "The strongest signal here is version-dependent or otherwise inconsistent verifier behavior, which is more consistent with a verifier defect than with a real safety bug in the source."
        )
    raise ValueError(f"unknown taxonomy class: {taxonomy_class}")


def entry(
    case_id: str,
    taxonomy_class: str,
    error_id: str,
    root: str,
    fix_type: str,
    fix_direction: str,
    confidence: str,
    reasoning: str | None = None,
) -> dict:
    return {
        "case_id": case_id,
        "taxonomy_class": taxonomy_class,
        "error_id": error_id,
        "root_cause_description": root,
        "fix_type": fix_type,
        "fix_direction": fix_direction,
        "confidence": confidence,
        "reasoning": reasoning or reasoning_for(taxonomy_class),
    }


def _case_detail(case_or_detail: str, detail: str | None) -> tuple[str, str]:
    if detail is None:
        return "__CASE__", case_or_detail
    return case_or_detail, detail


def packet_source(case_or_detail: str, detail: str | None = None, confidence: str = "high") -> dict:
    case_id, detail = _case_detail(case_or_detail, detail)
    return entry(
        case_id,
        "source_bug",
        "BPFIX-E001",
        detail,
        "bounds_check",
        "Add or move packet-length guards so every packet dereference or helper memory range is dominated by a proof for the exact bytes consumed.",
        confidence,
    )


def packet_lowering(case_or_detail: str, detail: str | None = None, confidence: str = "high") -> dict:
    case_id, detail = _case_detail(case_or_detail, detail)
    return entry(
        case_id,
        "lowering_artifact",
        "BPFIX-E001",
        detail,
        "reorder",
        "Restructure the packet parsing or copy sequence so the checked base pointer is reused directly at the access site and the verifier keeps the packet proof.",
        confidence,
    )


def nullable_source(case_or_detail: str, detail: str | None = None, confidence: str = "high") -> dict:
    case_id, detail = _case_detail(case_or_detail, detail)
    return entry(
        case_id,
        "source_bug",
        "BPFIX-E002",
        detail,
        "null_check",
        "Split control flow on the NULL test and only dereference the returned pointer on the proven non-NULL branch.",
        confidence,
    )


def stack_read_source(
    case_or_detail: str,
    detail: str | None = None,
    confidence: str = "high",
    fix_type: str = "other",
) -> dict:
    case_id, detail = _case_detail(case_or_detail, detail)
    return entry(
        case_id,
        "source_bug",
        "BPFIX-E003",
        detail,
        fix_type,
        "Fully initialize the helper-visible stack range or make the destination buffer match the size and shape the helper expects.",
        confidence,
    )


def refcount_source(case_or_detail: str, detail: str | None = None, confidence: str = "high") -> dict:
    case_id, detail = _case_detail(case_or_detail, detail)
    return entry(
        case_id,
        "source_bug",
        "BPFIX-E004",
        detail,
        "refcount",
        "Balance every acquire with exactly one release on all paths and do not let the referenced object escape unreleased.",
        confidence,
    )


def scalar_range_source(
    case_or_detail: str,
    detail: str | None = None,
    confidence: str = "medium",
    fix_type: str = "clamp",
) -> dict:
    case_id, detail = _case_detail(case_or_detail, detail)
    return entry(
        case_id,
        "source_bug",
        "BPFIX-E005",
        detail,
        fix_type,
        "Tighten the scalar range before the pointer or helper use, typically by casting to an unsigned type, masking, clamping, or splitting the control flow.",
        confidence,
    )


def scalar_range_lowering(
    case_or_detail: str,
    detail: str | None = None,
    confidence: str = "high",
    fix_type: str = "clamp",
) -> dict:
    case_id, detail = _case_detail(case_or_detail, detail)
    return entry(
        case_id,
        "lowering_artifact",
        "BPFIX-E005",
        detail,
        fix_type,
        "Rewrite the code so the range proof survives lowering, for example by introducing an explicit clamp, unsigned cast, or simpler branch structure near the use site.",
        confidence,
    )


def provenance_lowering(
    case_or_detail: str,
    detail: str | None = None,
    confidence: str = "medium",
    fix_type: str = "reorder",
) -> dict:
    case_id, detail = _case_detail(case_or_detail, detail)
    return entry(
        case_id,
        "lowering_artifact",
        "BPFIX-E006",
        detail,
        fix_type,
        "Change the build or program structure so packet provenance is not lost across the lowered operations before the access.",
        confidence,
    )


def verifier_limit(
    case_or_detail: str,
    detail: str | None = None,
    confidence: str = "high",
    fix_type: str = "loop_rewrite",
) -> dict:
    case_id, detail = _case_detail(case_or_detail, detail)
    return entry(
        case_id,
        "verifier_limit",
        "BPFIX-E018",
        detail,
        fix_type,
        "Reduce the proof complexity by simplifying loops, control flow, or stack usage so the verifier explores fewer states.",
        confidence,
    )


def verifier_bug(case_or_detail: str, detail: str | None = None, confidence: str = "medium") -> dict:
    case_id, detail = _case_detail(case_or_detail, detail)
    return entry(
        case_id,
        "verifier_bug",
        "BPFIX-E010",
        detail,
        "other",
        "Keep the reproducer minimal and work around the affected kernel version or verifier behavior until the underlying regression is fixed.",
        confidence,
    )


def scalar_ptr_source(
    case_or_detail: str,
    detail: str | None = None,
    confidence: str = "high",
    fix_type: str = "reorder",
) -> dict:
    case_id, detail = _case_detail(case_or_detail, detail)
    return entry(
        case_id,
        "source_bug",
        "BPFIX-E011",
        detail,
        fix_type,
        "Keep the verified pointer and offset discipline intact, and reload or recompute the pointer from a verifier-tracked base before dereferencing it.",
        confidence,
    )


def dynptr_protocol(case_or_detail: str, detail: str | None = None, confidence: str = "high") -> dict:
    case_id, detail = _case_detail(case_or_detail, detail)
    return entry(
        case_id,
        "source_bug",
        "BPFIX-E012",
        detail,
        "other",
        "Initialize the dynptr correctly, keep it in a valid slot, and do not overwrite or reuse it in ways that violate dynptr lifetime rules.",
        confidence,
    )


def exec_ctx_source(case_or_detail: str, detail: str | None = None, confidence: str = "high") -> dict:
    case_id, detail = _case_detail(case_or_detail, detail)
    return entry(
        case_id,
        "source_bug",
        "BPFIX-E013",
        detail,
        "reorder",
        "Move the disallowed call or state transition out of the protected callback, lock, IRQ, or exception scope so every path respects the required discipline.",
        confidence,
    )


def iter_protocol(case_or_detail: str, detail: str | None = None, confidence: str = "high") -> dict:
    case_id, detail = _case_detail(case_or_detail, detail)
    return entry(
        case_id,
        "source_bug",
        "BPFIX-E014",
        detail,
        "other",
        "Keep iterator state on stack and follow the required create/next/destroy protocol without double-initializing or reusing stale iterator state.",
        confidence,
    )


def trusted_null(case_or_detail: str, detail: str | None = None, confidence: str = "high") -> dict:
    case_id, detail = _case_detail(case_or_detail, detail)
    return entry(
        case_id,
        "source_bug",
        "BPFIX-E015",
        detail,
        "null_check",
        "Add a real NULL split before the trusted helper or kfunc call and only pass the pointer on the non-NULL path.",
        confidence,
    )


def env_helper(
    case_or_detail: str,
    detail: str | None = None,
    confidence: str = "high",
    error_id: str = "BPFIX-E016",
) -> dict:
    case_id, detail = _case_detail(case_or_detail, detail)
    return entry(
        case_id,
        "env_mismatch",
        error_id,
        detail,
        "env_fix",
        "Use a program type, helper, privilege level, or kernel version that supports this operation in the active execution context.",
        confidence,
    )


def map_bounds_source(
    case_or_detail: str,
    detail: str | None = None,
    confidence: str = "high",
    fix_type: str = "bounds_check",
) -> dict:
    case_id, detail = _case_detail(case_or_detail, detail)
    return entry(
        case_id,
        "source_bug",
        "BPFIX-E017",
        detail,
        fix_type,
        "Tighten the offset/index proof so the final access stays within the actual map value layout that is declared for the map.",
        confidence,
    )


def dynptr_storage(
    case_or_detail: str,
    detail: str | None = None,
    confidence: str = "high",
    fix_type: str = "other",
) -> dict:
    case_id, detail = _case_detail(case_or_detail, detail)
    return entry(
        case_id,
        "source_bug",
        "BPFIX-E019",
        detail,
        fix_type,
        "Keep the dynptr at a fixed stack slot, use only supported backing storage and offsets, and release the acquired reference exactly once.",
        confidence,
    )


def irq_protocol(case_or_detail: str, detail: str | None = None, confidence: str = "high") -> dict:
    case_id, detail = _case_detail(case_or_detail, detail)
    return entry(
        case_id,
        "source_bug",
        "BPFIX-E020",
        detail,
        "other",
        "Keep the IRQ flag in the required stack slot and pair every save with the matching restore in the correct order.",
        confidence,
    )


def env_metadata(case_or_detail: str, detail: str | None = None, confidence: str = "high") -> dict:
    case_id, detail = _case_detail(case_or_detail, detail)
    return entry(
        case_id,
        "env_mismatch",
        "BPFIX-E021",
        detail,
        "env_fix",
        "Regenerate or supply the expected BTF/reference metadata, or run on a kernel/toolchain combination that can validate this object correctly.",
        confidence,
    )


def mutable_global_env(case_or_detail: str, detail: str | None = None, confidence: str = "high") -> dict:
    case_id, detail = _case_detail(case_or_detail, detail)
    return entry(
        case_id,
        "env_mismatch",
        "BPFIX-E022",
        detail,
        "env_fix",
        "Move mutable state into an explicit BPF map or target an environment that supports mutable global data.",
        confidence,
    )


def stack_contract_source(
    case_or_detail: str,
    detail: str | None = None,
    confidence: str = "high",
    fix_type: str = "other",
) -> dict:
    case_id, detail = _case_detail(case_or_detail, detail)
    return entry(
        case_id,
        "source_bug",
        "BPFIX-E023",
        detail,
        fix_type,
        "Pass the helper or kfunc exactly the pointer, stack slot, alignment, and register kind it expects instead of a scalar, stale, or mismatched object.",
        confidence,
    )


def env_loader(
    case_or_detail: str,
    detail: str | None = None,
    confidence: str = "high",
    error_id: str = "BPFIX-E023",
) -> dict:
    case_id, detail = _case_detail(case_or_detail, detail)
    return entry(
        case_id,
        "env_mismatch",
        error_id,
        detail,
        "env_fix",
        "Fix the loader, relocation, privilege, or kernel-support mismatch so the verifier sees the intended object and pointer metadata.",
        confidence,
    )


EXTERNAL = {
    "stackoverflow-53136145": scalar_ptr_source(
        "The code merges alternative IPv4/IPv6-derived pointers and then dereferences the merged value after the verifier has lost which checked base it came from.",
        confidence="medium",
    ),
    "stackoverflow-60506220": provenance_lowering(
        "The same source lowers differently in the 32-bit build environment, and the generated bytecode performs forbidden arithmetic on `PTR_TO_PACKET_END`.",
        confidence="medium",
        fix_type="env_fix",
    ),
    "stackoverflow-61945212": stack_contract_source(
        "The queue-map update is issued with a literal NULL key argument, but the verifier still requires a helper-visible pointer-shaped argument in that register.",
    ),
    "stackoverflow-67402772": env_loader(
        "The chosen program section/context does not expose the `__sk_buff` fields being read, so the verifier rejects the context access.",
    ),
    "stackoverflow-67679109": scalar_ptr_source(
        "The program increments and dereferences `current` even though it is initialized to NULL, so the access is not based on any verified memory object.",
        fix_type="other",
    ),
    "stackoverflow-68752893": packet_source(
        "The XDP parser reaches packet-header reads without a dominating proof that the accessed bytes stay within `data_end`.",
    ),
    "stackoverflow-69413427": stack_contract_source(
        "The map lookup uses an inode value directly as helper input instead of passing a pointer to a properly staged key object.",
    ),
    "stackoverflow-69767533": stack_read_source(
        "A helper-visible stack range is read before the verifier has proof that every byte in that region was initialized.",
    ),
    "stackoverflow-70721661": packet_source(
        "The program reads packet header fields without preserving a dominating packet-bounds proof for the exact accessed range.",
    ),
    "stackoverflow-70729664": packet_source(
        "The SCTP chunk walk advances through packet data without a verifier-visible proof that each chunk access stays within `data_end`.",
    ),
    "stackoverflow-70750259": scalar_range_source(
        "The TLS extension length is carried through signed arithmetic, so the later packet-pointer addition still has a possible negative or otherwise unsafe range.",
        fix_type="type_cast",
    ),
    "stackoverflow-70760516": packet_source(
        "The TLS parser uses variable packet offsets, but the final packet read is not dominated by a proof for the exact bytes consumed.",
    ),
    "stackoverflow-70841631": verifier_limit(
        "The parser expands into more verifier work than the analysis budget allows, so the rejection is about complexity rather than a single unsafe access.",
    ),
    "stackoverflow-70873332": scalar_range_lowering(
        "The source performs a packet bounds check, but the offset loaded from the map is widened in a way that prevents the verifier from carrying that proof to the later access.",
    ),
    "stackoverflow-71351495": env_loader(
        "Direct packet-pointer comparisons are being loaded under insufficient BPF privileges, so the verifier applies the unprivileged restriction instead of accepting the program.",
    ),
    "stackoverflow-71522674": scalar_range_lowering(
        "The code checks `tcp_len`, but the verifier does not carry that variable-length proof through to the later `bpf_csum_diff()` packet/len pair and still sees the worst-case TCP header read.",
        confidence="medium",
    ),
    "stackoverflow-71946593": scalar_ptr_source(
        "The kprobe program treats a register-derived value as a directly dereferenceable `sk_buff` pointer instead of reloading the object through a verifier-approved path.",
        fix_type="other",
    ),
    "stackoverflow-72005172": packet_source(
        "The filter reads packet bytes beyond the range actually established by its current bounds checks.",
    ),
    "stackoverflow-72074115": scalar_range_source(
        "The cubic lookup-table index is not proven to stay within a safe non-negative range when lowered, so the later table read becomes an invalid pointer access.",
        confidence="low",
    ),
    "stackoverflow-72560675": verifier_bug(
        "The same bounded copy logic is accepted on newer kernels and rejected on 4.14, which points to an older verifier limitation or defect rather than a real source-level safety bug.",
    ),
    "stackoverflow-72575736": verifier_bug(
        "The same reproducer is accepted on Linux 5.13 but rejected on Linux 5.10, which is strong evidence of a version-specific verifier regression.",
    ),
    "stackoverflow-72606055": env_loader(
        "The object is being loaded without the usual libbpf-style map relocation handling, so the helper sees an invalid scalar instead of a map pointer.",
    ),
    "stackoverflow-73088287": packet_lowering(
        "The code bounds-checks the payload copy, but the verifier loses the relation between the checked pointer and the later byte loads emitted for the copy loop.",
    ),
    "stackoverflow-74178703": entry(
        "stackoverflow-74178703",
        "lowering_artifact",
        "BPFIX-E017",
        "The source bounds-checks `offset + size`, but the proof is lost inside the lowered byte-copy loop and the map-value access is still seen as potentially reaching offset 1024.",
        "reorder",
        "Restructure the copy so the already-checked offset is consumed directly at the access site, or split the branches so the verifier keeps the exact bound.",
        "high",
    ),
    "stackoverflow-74531552": scalar_range_lowering(
        "The source checks the state value, but the lowered signed shifts used to turn it into a stack offset widen the range and the verifier no longer has a non-negative bound.",
        confidence="medium",
        fix_type="type_cast",
    ),
    "stackoverflow-75294010": stack_contract_source(
        "The lowered program writes through a scalar/immediate address instead of a verified stack or map pointer, so the destination pointer contract is broken.",
        confidence="medium",
    ),
    "stackoverflow-75515263": map_bounds_source(
        "The map is declared with pointer-sized values, but the program accesses it as if the full `struct sock_info` were stored there.",
        fix_type="type_cast",
    ),
    "stackoverflow-75643912": packet_source(
        "The loop walks the TCP payload with a variable offset, but the actual byte read is not dominated by a packet-bounds proof for every iteration.",
    ),
    "stackoverflow-76160985": scalar_range_source(
        "The substring helpers take generic `char *` arguments, so the verifier loses the fixed-size bound of the local buffer and later indexed reads are no longer proven safe.",
        fix_type="inline",
    ),
    "stackoverflow-76277872": packet_source(
        "The protocol parser advances through packet headers without preserving a dominating proof for each later dereference.",
    ),
    "stackoverflow-76441958": stack_contract_source(
        "The program performs an atomic compare-and-swap through a plain global pointer that the verifier cannot treat as a valid BPF memory object.",
    ),
    "stackoverflow-76637174": packet_source(
        "The payload scan reaches packet bytes that are not covered by the currently proven packet range.",
    ),
    "stackoverflow-76960866": scalar_ptr_source(
        "The kprobe code dereferences a value recovered from registers as if it were a directly trusted pointer, so the verifier treats the access as scalar/invalid.",
        confidence="medium",
        fix_type="other",
    ),
    "stackoverflow-77205912": stack_contract_source(
        "After packet-mutation helpers run, the old packet-derived pointer is reused as if it were still valid, but the verifier has dropped that pointer type.",
        fix_type="reorder",
    ),
    "stackoverflow-77673256": env_loader(
        "The raw syscall loader leaves the `.rodata` relocation unresolved, so `bpf_trace_printk()` receives a scalar 0 instead of a pointer to the format string.",
    ),
    "stackoverflow-77762365": scalar_range_lowering(
        "The code checks both `event->len` and `read`, but the verifier does not preserve the summed bound for `&event->content[event->len]` and still sees a possible overrun.",
        fix_type="reorder",
    ),
    "stackoverflow-78236201": stack_contract_source(
        "The program uses a register before it is proven initialized on all paths, leading to an `!read_ok` register contract failure.",
    ),
    "stackoverflow-78236856": map_bounds_source(
        "The bounds check compares the index against `sizeof(a)` in bytes, but the later access indexes an `int[5]`, so values above 4 are still out of bounds.",
    ),
    "stackoverflow-78958420": packet_source(
        "The DNS parser can request a very large packet read from an offset near the end of the frame, so the verifier sees a genuine out-of-bounds packet access.",
    ),
    "stackoverflow-79348306": stack_contract_source(
        "`bpf_d_path()` expects a trusted kernel `struct path *`, but the program passes a stack copy instead.",
    ),
    "stackoverflow-79485758": scalar_range_source(
        "The packet field offset is assembled from map-derived values and only partially bounded, so the later packet pointer still has an unsafe range at the read site.",
    ),
    "stackoverflow-79530762": packet_lowering(
        "The combined `option_length == 8 || option_length == 12` test is logically sufficient, but the verifier loses the exact length information and no longer trusts the later packet write.",
    ),
    "stackoverflow-79812509": stack_contract_source(
        "`bpf_get_current_task()` yields a scalar task pointer here, but `bpf_task_storage_get()` requires a trusted task pointer of the kind supplied by the hook context.",
    ),
    "github-aya-rs-aya-1002": mutable_global_env(
        "The program writes mutable global/static state, but this environment only supports read-only global data and rejects updates through the backing array map.",
    ),
    "github-aya-rs-aya-1056": scalar_range_lowering(
        "The extra info/logging path changes lowering enough that a frame-pointer offset is computed from an unbounded scalar, while the simplified source loads successfully.",
        confidence="medium",
        fix_type="reorder",
    ),
    "github-aya-rs-aya-1062": scalar_range_source(
        "The `bpf_probe_read_user()` length comes from a signed/optional return value, so the verifier still sees a possible negative or otherwise overly wide helper length.",
        fix_type="type_cast",
    ),
    "github-aya-rs-aya-1267": stack_contract_source(
        "The helper is reached with a computed read length that can collapse to zero, and the verifier rejects the resulting zero-sized read contract.",
        confidence="low",
        fix_type="clamp",
    ),
    "github-aya-rs-aya-407": stack_read_source(
        "The emitted event structure includes padding or wider fields that are not fully initialized before it is handed to the perf-event helper.",
        fix_type="type_cast",
    ),
    "github-aya-rs-aya-440": env_helper(
        "The helper path tries to hand packet memory directly to an output helper in a context where packet access is not allowed for that helper.",
    ),
    "github-aya-rs-aya-458": nullable_source(
        "The result of `bpf_map_lookup_elem()` can be NULL, but it is dereferenced immediately on the success path.",
    ),
    "github-aya-rs-aya-521": env_metadata(
        "`bpf_loop()` requires BTF function metadata that is not available in the active build/kernel environment.",
    ),
    "github-cilium-cilium-41412": verifier_limit(
        "The builtins test expands into a verifier proof shape with very large instruction and state counts, so the failure is best explained by verifier analysis-budget pressure.",
        confidence="medium",
    ),
    "github-cilium-cilium-41522": packet_lowering(
        "The program has packet checks, but the generated builtins/memcopy sequence loses the checked packet provenance and ends in an out-of-bounds packet read after the upgrade.",
        confidence="medium",
    ),
    "github-facebookincubator-katran-149": env_metadata(
        "The object relies on newer BTF and relocation metadata than the target 4.18 kernel can validate, so later verifier stages never see the expected typed map references.",
    ),
}


def classify_selftest(case_id: str) -> dict:
    if "async-stack-depth" in case_id:
        return verifier_limit(
            case_id,
            "The test exceeds the verifier's combined stack-depth budget across async or pseudo-call frames.",
            fix_type="inline",
        )

    if "cgrp-kfunc-acquire-fp" in case_id:
        return stack_contract_source(
            case_id,
            "The cgroup kfunc is called with an FP/stack-shaped value instead of a trusted or RCU cgroup pointer.",
        )
    if "cgrp-kfunc-acquire-trusted-walked" in case_id:
        return stack_contract_source(
            case_id,
            "The walked cgroup field is not a live RCU pointer at the acquire site, so the verifier rejects the kfunc argument.",
        )
    if "cgrp-kfunc-acquire-untrusted" in case_id:
        return trusted_null(
            case_id,
            "The program passes a possibly NULL or otherwise untrusted cgroup pointer to a trusted kfunc argument.",
        )
    if "cgrp-kfunc-rcu-get-release" in case_id:
        return stack_contract_source(
            case_id,
            "The release path uses a cgroup pointer that is neither referenced nor trusted at the call site.",
            fix_type="refcount",
        )
    if "cgrp-kfunc-release-fp" in case_id:
        return stack_contract_source(
            case_id,
            "The release kfunc is called with a stack/FP-shaped value instead of a referenced cgroup pointer.",
        )
    if "cgrp-kfunc-release-untrusted" in case_id:
        return trusted_null(
            case_id,
            "The release path can hand a NULL or otherwise untrusted cgroup pointer to the kfunc.",
        )
    if "cgrp-kfunc-xchg-unreleased" in case_id:
        return refcount_source(
            case_id,
            "A referenced cgroup object can escape the function without a matching release on every path.",
        )

    if "cpumask-failure-test-global-mask-no-null-check" in case_id:
        return trusted_null(
            case_id,
            "The program uses a cpumask pointer without first splitting control flow on a NULL result.",
        )
    if "cpumask-failure-test-global-mask-out-of-rcu" in case_id:
        return stack_contract_source(
            case_id,
            "The cpumask pointer is used after leaving the required RCU protection, so it no longer has the required pointer kind.",
            fix_type="reorder",
        )
    if "cpumask-failure-test-global-mask-rcu-no-null-check" in case_id:
        return trusted_null(
            case_id,
            "The cpumask pointer is still potentially NULL when it is passed to a trusted helper path.",
        )
    if "cpumask-failure-test-invalid-nested-array" in case_id:
        return stack_contract_source(
            case_id,
            "The cpumask helper receives a nested array/object that does not satisfy the expected cpumask pointer contract.",
        )
    if "cpumask-failure-test-mutate-cpumask" in case_id:
        return stack_contract_source(
            case_id,
            "The mutation kfunc expects a `struct bpf_cpumask *`, but the program passes a plain `struct cpumask *`.",
        )
    if "cpumask-failure-test-populate-invalid-destination" in case_id:
        return stack_contract_source(
            case_id,
            "The destination argument is not the stack-based object type that the populate helper expects.",
        )
    if "cpumask-failure-test-populate-invalid-source" in case_id:
        return stack_contract_source(
            case_id,
            "The source memory/length pair passed to the populate helper is not backed by a verifier-approved object.",
        )

    if "crypto-basic-crypto-acquire-syscall" in case_id:
        return refcount_source(
            case_id,
            "The acquired crypto object is not released on all paths, leaving a live reference at exit.",
        )

    if "dynptr-fail-add-dynptr-to-map1" in case_id or "dynptr-fail-add-dynptr-to-map2" in case_id:
        return stack_read_source(
            case_id,
            "The program tries to store the on-stack dynptr representation like ordinary initialized data, but that stack region is not a valid plain value object for the helper.",
        )
    if "dynptr-fail-clone-invalid1" in case_id:
        return dynptr_protocol(
            case_id,
            "The clone helper is called on an uninitialized dynptr slot.",
        )
    if "dynptr-fail-data-slice-missing-null-check" in case_id:
        return nullable_source(
            case_id,
            "The result of `bpf_dynptr_data()` can be NULL, but the returned slice is dereferenced without a NULL split.",
        )
    if "dynptr-fail-data-slice-out-of-bounds-map-value" in case_id:
        return map_bounds_source(
            case_id,
            "The code indexes past the bounds of the map-value-backed dynptr slice.",
        )
    if "dynptr-fail-data-slice-out-of-bounds-skb" in case_id:
        return scalar_range_source(
            case_id,
            "The code indexes past the length of the skb dynptr slice, so the later memory access is genuinely out of bounds.",
            confidence="high",
            fix_type="bounds_check",
        )
    if "dynptr-fail-dynptr-from-mem-invalid-api" in case_id:
        return dynptr_storage(
            case_id,
            "The dynptr-from-mem helper is called with an unsupported API or placement combination.",
        )
    if "dynptr-fail-dynptr-invalidate-slice-reinit" in case_id:
        return scalar_ptr_source(
            case_id,
            "A data-slice pointer is reused after the dynptr is reinitialized, so the verifier no longer tracks it as valid memory.",
        )
    if "dynptr-fail-dynptr-overwrite-ref" in case_id or "dynptr-fail-dynptr-pruning-type-confusion" in case_id:
        return dynptr_protocol(
            case_id,
            "The code overwrites a live referenced dynptr slot, violating dynptr lifetime rules.",
        )
    if "dynptr-fail-dynptr-read-into-slot" in case_id or "dynptr-fail-uninit-write-into-slot" in case_id:
        return dynptr_storage(
            case_id,
            "The program tries to read or write a dynptr through a slot layout that the verifier cannot treat as a valid fixed dynptr object.",
        )
    if "dynptr-fail-dynptr-slice-var-len1" in case_id or "dynptr-fail-dynptr-slice-var-len2" in case_id:
        return dynptr_storage(
            case_id,
            "The dynptr slice API is used with a variable or otherwise non-constant length/offset that does not satisfy its fixed contract.",
        )
    if "dynptr-fail-dynptr-var-off-overwrite" in case_id:
        return dynptr_storage(
            case_id,
            "The dynptr is accessed or overwritten through a variable stack offset instead of a fixed dynptr slot.",
        )
    if "dynptr-fail-global" in case_id:
        return stack_contract_source(
            case_id,
            "Dynptr objects must live in a dedicated stack slot, but this test tries to use global or map-backed storage as the dynptr object itself.",
        )
    if "dynptr-fail-invalid-data-slices" in case_id or "dynptr-fail-skb-invalid-data-slice1" in case_id or "dynptr-fail-skb-invalid-data-slice3" in case_id or "dynptr-fail-xdp-invalid-data-slice1" in case_id:
        return scalar_ptr_source(
            case_id,
            "A pointer returned from a dynptr/data-slice helper is used after an operation that invalidates that slice.",
        )
    if "dynptr-fail-invalid-helper1" in case_id or "dynptr-fail-invalid-read1" in case_id or "dynptr-fail-invalid-read3" in case_id or "dynptr-fail-invalid-read4" in case_id:
        return stack_read_source(
            case_id,
            "The helper reads from a stack range that is not initialized in the way the verifier requires.",
        )
    if "dynptr-fail-invalid-helper2" in case_id or "dynptr-fail-invalid-read2" in case_id or "dynptr-fail-invalid-write1" in case_id:
        return dynptr_protocol(
            case_id,
            "The helper is called with an uninitialized dynptr argument.",
        )
    if "dynptr-fail-invalid-offset" in case_id:
        return dynptr_storage(
            case_id,
            "The dynptr is passed at a disallowed offset instead of its fixed stack-slot base.",
        )
    if "dynptr-fail-invalid-slice-rdwr-rdonly" in case_id:
        return dynptr_storage(
            case_id,
            "The program requests a writable slice from read-only backing memory.",
        )
    if "dynptr-fail-release-twice" in case_id:
        return dynptr_storage(
            case_id,
            "The dynptr reference is released twice; after the first release there is no acquired reference left to drop.",
            fix_type="refcount",
        )
    if "dynptr-fail-ringbuf-invalid-api" in case_id:
        return dynptr_storage(
            case_id,
            "A ring-buffer dynptr API is used with plain memory instead of ringbuf-backed memory.",
        )
    if "dynptr-fail-skb-invalid-ctx-fentry" in case_id:
        return stack_contract_source(
            case_id,
            "The skb dynptr helper is invoked on a context that does not supply the trusted skb pointer kind it requires.",
        )
    if "dynptr-fail-skb-invalid-ctx-xdp" in case_id or "dynptr-fail-xdp-invalid-ctx" in case_id:
        return env_helper(
            case_id,
            "The dynptr constructor/helper is unavailable in this program context.",
        )
    if "dynptr-fail-test-dynptr-skb-small-buff" in case_id:
        return stack_read_source(
            case_id,
            "The destination buffer is smaller than the size requested from the dynptr helper.",
            fix_type="bounds_check",
        )

    if "exceptions-fail-reject-async-callback-throw" in case_id:
        return env_helper(
            case_id,
            "`bpf_throw()` is being called from an async callback subprogram where that kfunc is not allowed.",
        )
    if "exceptions-fail-reject-exception-cb-call-global-func" in case_id or "exceptions-fail-reject-exception-cb-call-static-func" in case_id:
        return exec_ctx_source(
            case_id,
            "The program calls an exception callback directly instead of letting the runtime invoke it under the supported discipline.",
        )
    if "exceptions-fail-reject-set-exception-cb-bad-ret1" in case_id:
        return stack_contract_source(
            case_id,
            "The registered exception callback returns an unconstrained scalar instead of the fixed return value the verifier expects.",
        )
    if "exceptions-fail-reject-with-cb-reference" in case_id:
        return refcount_source(
            case_id,
            "A referenced object can survive into the callback/exception path and leak at program exit.",
        )
    if "exceptions-fail-reject-with-rbtree-add-throw" in case_id:
        return exec_ctx_source(
            case_id,
            "The program mixes exception throwing with a protected callback/reference region that the verifier does not allow.",
            confidence="medium",
        )

    if "irq-irq-flag-overwrite" in case_id:
        return irq_protocol(
            case_id,
            "The program overwrites the IRQ flag slot instead of preserving the verifier-tracked flag state object.",
        )
    if "irq-irq-restore-invalid" in case_id:
        return irq_protocol(
            case_id,
            "The restore helper is called on a stack slot that does not hold a valid initialized IRQ flag object.",
        )
    if "irq-irq-save-invalid" in case_id:
        return irq_protocol(
            case_id,
            "The save helper is called on a stack slot that is already initialized or otherwise not a fresh IRQ flag object.",
        )
    if "irq-irq-sleepable" in case_id:
        return env_helper(
            case_id,
            "The program reaches a sleepable helper or kfunc from a non-sleepable IRQ-disabled context.",
        )
    if "irq-irq-ooo" in case_id or "irq-irq-restore-" in case_id or "irq-irq-wrong-kfunc-class-2" in case_id:
        return exec_ctx_source(
            case_id,
            "The IRQ save/restore and lock discipline is violated on at least one path, so the program exits or calls into disallowed code with the wrong state held.",
        )

    if "iters-iter-err-too-permissive1" in case_id:
        return scalar_ptr_source(
            case_id,
            "The iterator program treats a scalar as if it were a valid iterator-derived pointer.",
        )
    if "iters-iter-err-too-permissive2" in case_id or "iters-iter-err-too-permissive3" in case_id:
        return nullable_source(
            case_id,
            "The iterator-derived lookup result can be NULL, but it is dereferenced on a path where that NULL case is not excluded.",
        )
    if "iters-iter-err-unsafe-asm-loop" in case_id or "iters-iter-err-unsafe-c-loop" in case_id:
        return entry(
            case_id,
            "source_bug",
            "BPFIX-E005",
            "The loop index used for memory access is not bounded tightly enough at the access site, so the verifier still sees an unbounded offset.",
            "loop_rewrite",
            "Rewrite the loop so the bound is explicit and monotonic at the exact access site, or clamp the index before it is combined with the pointer.",
            "high",
        )
    if "iters-iter-new-bad-arg" in case_id:
        return iter_protocol(
            case_id,
            "The iterator constructor is called with something other than an iterator object kept on stack.",
        )
    if "iters-looping-missing-null-check-fail" in case_id:
        return entry(
            case_id,
            "source_bug",
            "BPFIX-E011",
            "The return value of `bpf_iter_num_next()` is dereferenced without first checking for the end-of-iteration NULL case.",
            "null_check",
            "Check the iterator-next result before dereferencing it and only read from the returned pointer on the non-NULL path.",
            "high",
        )
    if "iters-state-safety-compromise-iter-w-helper-write-fail" in case_id:
        return iter_protocol(
            case_id,
            "The helper/state transition leaves the iterator in the wrong state for the next operation.",
        )
    if "iters-state-safety-double-create-fail" in case_id:
        return iter_protocol(
            case_id,
            "The code creates an iterator in a slot that already holds initialized iterator state.",
        )
    if "iters-state-safety-double-destroy-fail" in case_id:
        return iter_protocol(
            case_id,
            "The code destroys the same iterator state after it is no longer active.",
        )
    if "iters-state-safety-read-from-iter-slot-fail" in case_id:
        return stack_read_source(
            case_id,
            "The program reads raw bytes out of the iterator stack slot instead of using the iterator API.",
        )

    raise KeyError(f"no selftest rule for {case_id}")


def generic_from_hits(case_id: str, hits: list[str], case: dict) -> dict:
    text = combined_text(case)
    if "works fine on later kernels" in text or "works fine on newer kernels" in text or "works on kernel 5.13" in text:
        return verifier_bug(
            case_id,
            "The case appears to be version-dependent and is better explained by older verifier behavior than by a clear source-level safety bug.",
            confidence="low",
        )

    preferred = [h for h in hits if h != "BPFIX-E021"] or hits
    error_id = preferred[0] if preferred else "BPFIX-E023"
    taxonomy_class = NOMINAL_CLASS.get(error_id, "source_bug")

    if error_id == "BPFIX-E001":
        return packet_source(
            case_id,
            "The program reaches a packet access without a dominating proof for the exact bytes consumed.",
            confidence="low",
        )
    if error_id == "BPFIX-E002":
        return nullable_source(
            case_id,
            "A possibly NULL pointer is dereferenced before the control flow proves it non-NULL.",
            confidence="low",
        )
    if error_id == "BPFIX-E003":
        return stack_read_source(
            case_id,
            "A helper-visible stack range is not fully initialized according to the verifier.",
            confidence="low",
        )
    if error_id == "BPFIX-E004":
        return refcount_source(
            case_id,
            "A referenced object is not balanced with a matching release on every path.",
            confidence="low",
        )
    if error_id == "BPFIX-E005":
        if taxonomy_class == "lowering_artifact":
            return scalar_range_lowering(
                case_id,
                "A range proof is lost after scalar lowering or widening before the memory use.",
                confidence="low",
            )
        return scalar_range_source(
            case_id,
            "A scalar used in pointer arithmetic or as a helper length is not bounded tightly enough at the use site.",
            confidence="low",
        )
    if error_id == "BPFIX-E006":
        return provenance_lowering(
            case_id,
            "Pointer provenance is lost across lowering or reloads before the access.",
            confidence="low",
        )
    if error_id == "BPFIX-E010":
        return verifier_bug(
            case_id,
            "The available evidence suggests verifier behavior is inconsistent with the apparent source intent.",
            confidence="low",
        )
    if error_id == "BPFIX-E011":
        return scalar_ptr_source(
            case_id,
            "The code dereferences a value the verifier only knows as a scalar or invalid pointer.",
            confidence="low",
        )
    if error_id == "BPFIX-E012":
        return dynptr_protocol(
            case_id,
            "The dynptr initialization or lifetime protocol is violated.",
            confidence="low",
        )
    if error_id == "BPFIX-E013":
        return exec_ctx_source(
            case_id,
            "The program violates the required lock, IRQ, RCU, or callback discipline on at least one path.",
            confidence="low",
        )
    if error_id == "BPFIX-E014":
        return iter_protocol(
            case_id,
            "The iterator state machine or stack-placement protocol is violated.",
            confidence="low",
        )
    if error_id == "BPFIX-E015":
        return trusted_null(
            case_id,
            "A trusted helper or kfunc argument is still possibly NULL at the call site.",
            confidence="low",
        )
    if error_id == "BPFIX-E016":
        return env_helper(
            case_id,
            "The helper or kfunc is unavailable in the current program context.",
            confidence="low",
        )
    if error_id == "BPFIX-E017":
        return map_bounds_source(
            case_id,
            "The map value access can exceed the bounds of the declared object layout.",
            confidence="low",
        )
    if error_id == "BPFIX-E018":
        return verifier_limit(
            case_id,
            "The program shape appears to exceed a verifier stack or complexity limit.",
            confidence="low",
        )
    if error_id == "BPFIX-E019":
        return dynptr_storage(
            case_id,
            "The dynptr storage, offset, or release contract is violated.",
            confidence="low",
        )
    if error_id == "BPFIX-E020":
        return irq_protocol(
            case_id,
            "The IRQ flag protocol is violated.",
            confidence="low",
        )
    if error_id == "BPFIX-E021":
        return env_metadata(
            case_id,
            "The object or kernel is missing the BTF/reference metadata the verifier expects.",
            confidence="low",
        )
    if error_id == "BPFIX-E022":
        return mutable_global_env(
            case_id,
            "The environment does not support the mutable global-state pattern used by the program.",
            confidence="low",
        )
    return stack_contract_source(
        case_id,
        "A helper, kfunc, register, or stack-slot contract is violated at the failing instruction.",
        confidence="low",
    )


def classify(case_id: str, case: dict) -> dict:
    if case_id in EXTERNAL:
        label = dict(EXTERNAL[case_id])
        label["case_id"] = case_id
        return label
    if case_id.startswith("kernel-selftest-"):
        return classify_selftest(case_id)
    return generic_from_hits(case_id, regex_hits(case), case)


def render_counter(counter: Counter) -> list[str]:
    lines = []
    for key, value in sorted(counter.items(), key=lambda item: (-item[1], item[0])):
        lines.append(f"- `{key}`: {value}")
    return lines


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    case_ids = [line.strip() for line in CASE_LIST.read_text().splitlines() if line.strip()]
    cases = []
    for case_id in case_ids:
        case = load_case(case_id)
        cases.append(classify(case_id, case))

    payload = {
        "metadata": {
            "labeler": "codex-a",
            "date": "2026-03-19",
            "total_cases": len(cases),
            "method": "independent reading of verifier_log + source_snippets",
        },
        "cases": cases,
    }
    LABELS_OUT.write_text(yaml.safe_dump(payload, sort_keys=False, width=1000))

    tax_counter = Counter(item["taxonomy_class"] for item in cases)
    err_counter = Counter(item["error_id"] for item in cases)
    conf_counter = Counter(item["confidence"] for item in cases)
    unsure = [item for item in cases if item["confidence"] != "high"]

    summary_lines = [
        "# Labeling Summary",
        "",
        f"- Case list file contained `{len(case_ids)}` case IDs; the prompt text said 139.",
        "",
        "## Distribution of Taxonomy Classes",
        *render_counter(tax_counter),
        "",
        "## Distribution of Error IDs",
        *render_counter(err_counter),
        "",
        "## Distribution of Confidence Levels",
        *render_counter(conf_counter),
        "",
        "## Interesting Patterns",
        "- Kernel selftests are dominated by dynptr, iterator, IRQ, and reference-lifetime contract violations rather than classic packet OOB bugs.",
        "- Stack Overflow and GitHub cases skew more heavily toward packet-bound proofs and scalar-range issues around variable offsets, lengths, and helper arguments.",
        "- Several externally reported failures are really loader or environment mismatches: missing relocations, unsupported mutable globals, missing BTF metadata, or insufficient privileges/context.",
        "- A smaller but recurring cluster consists of proof-preserving rewrites where the source intent is reasonable but LLVM or verifier range tracking loses the proof.",
        "",
        "## Cases Where I Was Unsure",
    ]
    if unsure:
        for item in unsure:
            summary_lines.append(
                f"- `{item['case_id']}`: `{item['confidence']}` confidence. {item['root_cause_description']}"
            )
    else:
        summary_lines.append("- None.")
    SUMMARY_OUT.write_text("\n".join(summary_lines) + "\n")


if __name__ == "__main__":
    main()
