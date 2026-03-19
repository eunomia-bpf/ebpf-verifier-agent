#!/usr/bin/env python3
"""
Build ground truth taxonomy labels by combining:
1. Existing 30 manual labels
2. Auto-labeling kernel selftest cases via error_id -> taxonomy mapping
3. Auto-labeling SO/GH cases via keyword matching on fix_description

Output: case_study/ground_truth_labels.yaml
Report: docs/tmp/ground-truth-expansion-report.md
"""

import os
import re
import yaml
from pathlib import Path
from datetime import date

REPO = Path("/home/yunwei37/workspace/ebpf-verifier-agent")
CASES_DIR = REPO / "case_study" / "cases"
OUTPUT_YAML = REPO / "case_study" / "ground_truth_labels.yaml"
OUTPUT_REPORT = REPO / "docs" / "tmp" / "ground-truth-expansion-report.md"

# ──────────────────────────────────────────────────────────────────────────────
# 1. error_id -> taxonomy mapping (from error_catalog.yaml + task spec)
# ──────────────────────────────────────────────────────────────────────────────

ERROR_ID_TO_TAXONOMY = {
    "BPFIX-E001": "source_bug",          # packet_bounds_missing
    "BPFIX-E002": "source_bug",          # nullable_map_value_dereference
    "BPFIX-E003": "source_bug",          # uninitialized_stack_read
    "BPFIX-E004": "source_bug",          # reference_lifetime_violation
    "BPFIX-E005": "lowering_artifact",   # scalar_range_too_wide_after_lowering
    "BPFIX-E006": "lowering_artifact",   # provenance_lost_across_spill
    "BPFIX-E007": "verifier_limit",      # verifier_state_explosion
    "BPFIX-E008": "verifier_limit",      # bounded_loop_not_proved
    "BPFIX-E009": "env_mismatch",        # helper_or_kfunc_unavailable
    "BPFIX-E010": "verifier_bug",        # verifier_regression_or_internal_bug
    "BPFIX-E011": "source_bug",          # scalar_pointer_dereference
    "BPFIX-E012": "source_bug",          # dynptr_protocol_violation
    "BPFIX-E013": "source_bug",          # execution_context_discipline_violation
    "BPFIX-E014": "source_bug",          # iterator_state_protocol_violation
    "BPFIX-E015": "source_bug",          # trusted_arg_nullability
    "BPFIX-E016": "env_mismatch",        # helper_or_kfunc_context_restriction
    "BPFIX-E017": "source_bug",          # map_value_bounds_violation
    "BPFIX-E018": "verifier_limit",      # verifier_analysis_budget_limit
    "BPFIX-E019": "source_bug",          # dynptr_storage_or_release_contract_violation
    "BPFIX-E020": "source_bug",          # irq_flag_state_protocol_violation
    "BPFIX-E021": "env_mismatch",        # btf_reference_metadata_missing
    "BPFIX-E022": "env_mismatch",        # mutable_global_state_unsupported
    "BPFIX-E023": "source_bug",          # register_or_stack_contract_violation
}

# ──────────────────────────────────────────────────────────────────────────────
# 2. Error message pattern -> taxonomy (for selftests without explicit error_id)
# ──────────────────────────────────────────────────────────────────────────────

MSG_PATTERNS = [
    # source_bug patterns
    (re.compile(r"invalid (mem )?access '(scalar|inv|map_value_or_null|mem_or_null)'", re.I), "source_bug"),
    (re.compile(r"invalid access to packet", re.I), "source_bug"),
    (re.compile(r"Unreleased reference", re.I), "source_bug"),
    (re.compile(r"(not initialized|uninitialized|Expected an initialized)", re.I), "source_bug"),
    (re.compile(r"Expected (a |an )?(un)?initialized (dynptr|iter|irq flag)", re.I), "source_bug"),
    (re.compile(r"invalid indirect read from stack|invalid read from stack", re.I), "source_bug"),
    (re.compile(r"Possibly NULL pointer passed", re.I), "source_bug"),
    (re.compile(r"NULL pointer passed", re.I), "source_bug"),
    (re.compile(r"cannot overwrite referenced dynptr", re.I), "source_bug"),
    (re.compile(r"cannot pass in dynptr at an offset", re.I), "source_bug"),
    (re.compile(r"function calls are not allowed while holding a lock", re.I), "source_bug"),
    (re.compile(r"cannot restore irq state out of order", re.I), "source_bug"),
    (re.compile(r"BPF_EXIT instruction .* cannot be used inside", re.I), "source_bug"),
    (re.compile(r"requires RCU critical section", re.I), "source_bug"),
    (re.compile(r"invalid access to map value", re.I), "source_bug"),
    (re.compile(r"arg#\d+ expected pointer to an iterator on stack", re.I), "source_bug"),
    (re.compile(r"arg#\d+ expected pointer to stack or const struct bpf_dynptr", re.I), "source_bug"),
    (re.compile(r"expected pointer to an iterator on stack", re.I), "source_bug"),
    (re.compile(r"must be referenced", re.I), "source_bug"),
    (re.compile(r"pointer comparison prohibited", re.I), "source_bug"),
    (re.compile(r"At program exit the register R\d+ has", re.I), "source_bug"),
    (re.compile(r"misaligned stack access", re.I), "source_bug"),
    (re.compile(r"invalid zero-sized read", re.I), "source_bug"),
    (re.compile(r"R\d+ !read_ok", re.I), "source_bug"),
    (re.compile(r"potential write to dynptr", re.I), "source_bug"),
    (re.compile(r"type=mem expected=ringbuf_mem", re.I), "source_bug"),
    (re.compile(r"cannot write into rdonly_mem", re.I), "source_bug"),
    (re.compile(r"bpf_cpumask_set_cpu args", re.I), "source_bug"),
    (re.compile(r"has no valid kptr", re.I), "source_bug"),
    (re.compile(r"release kernel function .* expects", re.I), "source_bug"),
    (re.compile(r"R\d+ must be a rcu pointer", re.I), "source_bug"),
    (re.compile(r"reg type unsupported for arg", re.I), "source_bug"),
    (re.compile(r"FUNC .* Invalid arg", re.I), "source_bug"),
    (re.compile(r"arg#\d+ pointer type .* must point", re.I), "source_bug"),
    # Additional patterns for previously-skipped cases
    (re.compile(r"type=scalar expected=fp", re.I), "source_bug"),          # scalar passed as frame pointer
    (re.compile(r"type=scalar expected=percpu_ptr_", re.I), "source_bug"), # dynptr fail
    (re.compile(r"must be a known constant", re.I), "source_bug"),          # dynptr-slice-var-len
    (re.compile(r"the prog does not allow writes to packet data", re.I), "source_bug"),
    (re.compile(r"doesn't return scalar", re.I), "env_mismatch"),           # exception cb bad return type
    (re.compile(r"exception cb only supports single integer argument", re.I), "env_mismatch"),
    (re.compile(r"Expected a dynptr of type .* as arg", re.I), "source_bug"),
    (re.compile(r"sleepable helper .* within IRQ-disabled region", re.I), "env_mismatch"),
    (re.compile(r"kernel func .* is sleepable within IRQ-disabled region", re.I), "env_mismatch"),
    (re.compile(r"arg#0 doesn't point to an irq flag on stack", re.I), "source_bug"),
    (re.compile(r"R\d+ type=scalar expected=fp", re.I), "source_bug"),
    (re.compile(r"At program exit the register", re.I), "source_bug"),
    # JIT / kfunc support missing = env_mismatch
    (re.compile(r"JIT does not support calling kfunc", re.I), "env_mismatch"),
    (re.compile(r"kfunc .* not found", re.I), "env_mismatch"),
    # lowering_artifact patterns
    (re.compile(r"unbounded min value|unbounded memory access|unbounded max value", re.I), "lowering_artifact"),
    (re.compile(r"min value is negative.*unsigned.*var.*const", re.I), "lowering_artifact"),
    (re.compile(r"math between .* pointer and register with (unbounded|unknown)", re.I), "lowering_artifact"),
    (re.compile(r"pointer arithmetic on pkt_end", re.I), "lowering_artifact"),
    (re.compile(r"expected pointer type, got scalar", re.I), "lowering_artifact"),
    (re.compile(r"value is outside of the allowed memory range", re.I), "lowering_artifact"),
    (re.compile(r"arg.*arg.*memory.*len pair leads to invalid memory access", re.I), "lowering_artifact"),
    # verifier_limit patterns
    (re.compile(r"(too many states|jump.*too complex|sequence of .* jumps is too complex)", re.I), "verifier_limit"),
    (re.compile(r"combined stack size of \d+ calls", re.I), "verifier_limit"),
    (re.compile(r"stack depth \d+ exceeds", re.I), "verifier_limit"),
    (re.compile(r"complexity limit", re.I), "verifier_limit"),
    (re.compile(r"loop is not bounded|back-edge", re.I), "verifier_limit"),
    (re.compile(r"BPF program is too large", re.I), "verifier_limit"),
    # env_mismatch patterns
    (re.compile(r"(unknown func|program of this type cannot use helper|helper call is not allowed)", re.I), "env_mismatch"),
    (re.compile(r"cannot be called from callback", re.I), "env_mismatch"),
    (re.compile(r"calling kernel function .* is not allowed", re.I), "env_mismatch"),
    (re.compile(r"global functions that may sleep are not allowed", re.I), "env_mismatch"),
    (re.compile(r"cannot call exception cb directly", re.I), "env_mismatch"),
    (re.compile(r"multiple exception callback tags", re.I), "env_mismatch"),
    (re.compile(r"attach to unsupported member", re.I), "env_mismatch"),
    (re.compile(r"helper access to the packet is not allowed", re.I), "env_mismatch"),
    (re.compile(r"only read from bpf_array is supported", re.I), "env_mismatch"),
    (re.compile(r"arg#\d+ reference type\('UNKNOWN '\) size cannot be determined", re.I), "env_mismatch"),
    (re.compile(r"invalid btf[_ ]id", re.I), "env_mismatch"),
    (re.compile(r"missing btf func_info", re.I), "env_mismatch"),
    (re.compile(r"failed to find kernel BTF type ID", re.I), "env_mismatch"),
    (re.compile(r"Invalid name", re.I), "env_mismatch"),
    (re.compile(r"attach_btf_id is not a function", re.I), "env_mismatch"),
    # verifier_bug
    (re.compile(r"kernel BUG at kernel/bpf/verifier", re.I), "verifier_bug"),
    (re.compile(r"WARNING:.*verifier", re.I), "verifier_bug"),
    (re.compile(r"invalid state transition", re.I), "verifier_bug"),
]

# SO/GH fix description keyword patterns
SO_KEYWORDS = [
    # source_bug
    (re.compile(r"\b(bounds check|null check|missing check|need to check|add a check|"
                r"uninitialized|out of bounds|missing return|type cast|null dereference|"
                r"add.*guard|check.*null|check.*bound|check.*pointer|"
                r"packet bound|map lookup|release.*lock|lock.*release|"
                r"initialize.*buffer|init.*stack)\b", re.I), "source_bug"),
    # lowering_artifact
    (re.compile(r"\b(volatile|memory barrier|compiler optim|inline|__always_inline|"
                r"clang|llvm|optimization level|register spill|signed.unsigned|"
                r"codegen|code generation|asm volatile|pragma)\b", re.I), "lowering_artifact"),
    # env_mismatch
    (re.compile(r"\b(kernel version|not available|not supported|helper.*not|"
                r"upgrade.*kernel|requires kernel|program type|attach type|"
                r"unsupported.*kernel|minimum.*kernel|only.*kernel)\b", re.I), "env_mismatch"),
    # verifier_limit
    (re.compile(r"\b(loop unroll|too complex|complexity|too many states|state explosion|"
                r"instruction limit|simplif|reduce.*branch|split.*program|"
                r"bounded loop|unroll.*pragma)\b", re.I), "verifier_limit"),
]


def label_from_error_id(error_id: str):
    """Map BPFIX-Exxx to taxonomy class."""
    if not error_id:
        return None
    # Normalize: strip prefix variants
    normalized = error_id.strip()
    if not normalized.startswith("BPFIX-"):
        normalized = "BPFIX-" + normalized
    return ERROR_ID_TO_TAXONOMY.get(normalized)


def label_from_messages(messages: list[str]):
    """Classify based on expected verifier messages."""
    for msg in messages:
        if not msg:
            continue
        for pattern, taxonomy in MSG_PATTERNS:
            if pattern.search(msg):
                return taxonomy, msg[:120]
    return None, None


def label_from_fix_description(text: str):
    """Classify SO/GH cases from fix description keyword matching."""
    if not text:
        return None
    for pattern, taxonomy in SO_KEYWORDS:
        m = pattern.search(text)
        if m:
            return taxonomy, m.group(0)
    return None, None


def load_yaml_safe(path: Path):
    try:
        with open(path) as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"  [WARN] Failed to load {path}: {e}")
        return None


# ──────────────────────────────────────────────────────────────────────────────
# 3. Parse existing 30 manual labels
# ──────────────────────────────────────────────────────────────────────────────

MANUAL_LABELS_MD = REPO / "docs" / "tmp" / "manual-labeling-30cases.md"

def parse_manual_labels() -> dict:
    """Returns {case_id: {'taxonomy': ..., 'error_id': ..., 'confidence': 'high'}}"""
    text = MANUAL_LABELS_MD.read_text()
    labels = {}
    # Parse the markdown table rows
    VALID_CASE_PREFIXES = ("kernel-selftest-", "stackoverflow-", "github-")
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 6:
            continue
        case_id_raw = parts[1].strip("`").strip()
        taxonomy_raw = parts[4].strip("`").strip()
        if not case_id_raw or case_id_raw in ("Case", "---"):
            continue
        # Only accept real case IDs
        if not any(case_id_raw.startswith(pfx) for pfx in VALID_CASE_PREFIXES):
            continue
        if taxonomy_raw not in ("source_bug", "lowering_artifact", "verifier_limit",
                                "env_mismatch", "verifier_bug", "not_a_bug"):
            continue
        error_id_raw = parts[5].strip("`").strip()
        labels[case_id_raw] = {
            "taxonomy": taxonomy_raw,
            "error_id": error_id_raw if error_id_raw and error_id_raw != "---" else None,
            "confidence": "high",
        }
    print(f"  Parsed {len(labels)} manual labels")
    return labels


# ──────────────────────────────────────────────────────────────────────────────
# 4. Auto-label kernel selftest cases
# ──────────────────────────────────────────────────────────────────────────────

def autolabel_kernel_selftests() -> list[dict]:
    results = []
    ks_dir = CASES_DIR / "kernel_selftests"
    yaml_files = sorted(f for f in ks_dir.glob("*.yaml") if f.name != "index.yaml")

    for path in yaml_files:
        data = load_yaml_safe(path)
        if not data:
            continue
        case_id = data.get("case_id", path.stem)

        # Collect expected messages
        expected = data.get("expected_verifier_messages", {})
        msgs = []
        if isinstance(expected, dict):
            for key in ("combined", "privileged", "unprivileged"):
                v = expected.get(key, [])
                if isinstance(v, list):
                    msgs.extend(v)
                elif isinstance(v, str):
                    msgs.append(v)
        elif isinstance(expected, list):
            msgs.extend(expected)

        # Try error_id first
        error_id = data.get("error_id") or data.get("heuristic_class")
        taxonomy = label_from_error_id(error_id) if error_id else None
        method = f"error_id:{error_id}" if taxonomy else None

        # Fall back to message pattern matching
        if not taxonomy and msgs:
            taxonomy, matched_msg = label_from_messages(msgs)
            if taxonomy:
                method = f"msg_pattern:{matched_msg[:80]}"

        # Fall back to verifier_log scanning
        if not taxonomy:
            vlog = data.get("verifier_log", "")
            if isinstance(vlog, str) and vlog:
                taxonomy, matched_msg = label_from_messages([vlog])
                if taxonomy:
                    method = f"log_pattern:{matched_msg[:80]}"

        if taxonomy:
            results.append({
                "case_id": case_id,
                "taxonomy": taxonomy,
                "source": "selftest_auto",
                "confidence": "high",
                "notes": method or "",
            })
        else:
            print(f"  [SKIP-KS] {case_id}: no signal (msgs={msgs[:2]})")

    print(f"  Labeled {len(results)}/{len(yaml_files)} kernel selftest cases")
    return results


# ──────────────────────────────────────────────────────────────────────────────
# 5. Auto-label Stack Overflow cases
# ──────────────────────────────────────────────────────────────────────────────

def autolabel_stackoverflow() -> list[dict]:
    results = []
    so_dir = CASES_DIR / "stackoverflow"
    yaml_files = sorted(f for f in so_dir.glob("*.yaml") if f.name != "index.yaml")

    for path in yaml_files:
        data = load_yaml_safe(path)
        if not data:
            continue
        case_id = data.get("case_id", path.stem)

        # Gather text to search
        texts = []
        answer = data.get("selected_answer", {})
        if isinstance(answer, dict):
            texts.append(answer.get("fix_description", "") or "")
            texts.append(answer.get("body_text", "") or "")
        texts.append(data.get("question_body_text", "") or "")

        fix = data.get("fix", {})
        if isinstance(fix, dict):
            texts.append(fix.get("summary", "") or "")

        combined_text = " ".join(texts)

        taxonomy, matched = label_from_fix_description(combined_text)
        if taxonomy:
            results.append({
                "case_id": case_id,
                "taxonomy": taxonomy,
                "source": "so_auto",
                "confidence": "medium",
                "notes": f"keyword:{matched[:80]}" if matched else "",
            })
        else:
            # Also try message pattern on verifier log
            vlog = data.get("verifier_log", {})
            if isinstance(vlog, dict):
                vlog_text = vlog.get("combined", "") or ""
            else:
                vlog_text = str(vlog) if vlog else ""
            if vlog_text:
                taxonomy, matched_msg = label_from_messages([vlog_text])
                if taxonomy:
                    results.append({
                        "case_id": case_id,
                        "taxonomy": taxonomy,
                        "source": "so_auto",
                        "confidence": "medium",
                        "notes": f"log_msg:{matched_msg[:80]}" if matched_msg else "",
                    })
                else:
                    print(f"  [SKIP-SO] {case_id}: no signal")
            else:
                print(f"  [SKIP-SO] {case_id}: no text")

    print(f"  Labeled {len(results)}/{len(yaml_files)} SO cases")
    return results


# ──────────────────────────────────────────────────────────────────────────────
# 6. Auto-label GitHub Issues cases
# ──────────────────────────────────────────────────────────────────────────────

def autolabel_github() -> list[dict]:
    results = []
    gh_dir = CASES_DIR / "github_issues"
    yaml_files = sorted(f for f in gh_dir.glob("*.yaml") if f.name != "index.yaml")

    for path in yaml_files:
        data = load_yaml_safe(path)
        if not data:
            continue
        case_id = data.get("case_id", path.stem)

        texts = []
        fix = data.get("fix", {})
        if isinstance(fix, dict):
            texts.append(fix.get("summary", "") or "")
            selected = fix.get("selected_comment", {})
            if isinstance(selected, dict):
                texts.append(selected.get("body_text", "") or "")
        issue = data.get("issue", {})
        if isinstance(issue, dict):
            texts.append(issue.get("title", "") or "")
        texts.append(data.get("issue_body_text", "") or "")

        combined_text = " ".join(texts)

        taxonomy, matched = label_from_fix_description(combined_text)
        if taxonomy:
            results.append({
                "case_id": case_id,
                "taxonomy": taxonomy,
                "source": "gh_auto",
                "confidence": "medium",
                "notes": f"keyword:{matched[:80]}" if matched else "",
            })
        else:
            # Try message pattern on verifier log
            vlog = data.get("verifier_log", {})
            if isinstance(vlog, dict):
                vlog_text = vlog.get("combined", "") or ""
            else:
                vlog_text = str(vlog) if vlog else ""
            if vlog_text:
                taxonomy, matched_msg = label_from_messages([vlog_text])
                if taxonomy:
                    results.append({
                        "case_id": case_id,
                        "taxonomy": taxonomy,
                        "source": "gh_auto",
                        "confidence": "medium",
                        "notes": f"log_msg:{matched_msg[:80]}" if matched_msg else "",
                    })
                else:
                    print(f"  [SKIP-GH] {case_id}: no signal")
            else:
                print(f"  [SKIP-GH] {case_id}: no text")

    print(f"  Labeled {len(results)}/{len(yaml_files)} GitHub cases")
    return results


# ──────────────────────────────────────────────────────────────────────────────
# 7. Merge all labels
# ──────────────────────────────────────────────────────────────────────────────

def merge_labels(manual: dict, selftest_auto: list, so_auto: list, gh_auto: list):
    merged = {}  # case_id -> entry

    # Add auto labels first (lower priority)
    for entry in selftest_auto + so_auto + gh_auto:
        cid = entry["case_id"]
        merged[cid] = entry

    # Manual labels override (highest priority)
    for case_id, info in manual.items():
        entry = {
            "case_id": case_id,
            "taxonomy": info["taxonomy"],
            "source": "manual",
            "confidence": info["confidence"],
            "notes": f"manually labeled; error_id: {info['error_id']}" if info.get("error_id") else "manually labeled",
        }
        if case_id in merged and merged[case_id]["taxonomy"] != info["taxonomy"]:
            print(f"  [OVERRIDE] {case_id}: {merged[case_id]['taxonomy']} -> {info['taxonomy']} (manual wins)")
        merged[case_id] = entry

    return list(merged.values())


# ──────────────────────────────────────────────────────────────────────────────
# 8. Save YAML output
# ──────────────────────────────────────────────────────────────────────────────

def compute_stats(cases: list[dict], manual_count: int, selftest_count: int, so_count: int, gh_count: int):
    by_source = {"manual": 0, "selftest_auto": 0, "so_auto": 0, "gh_auto": 0}
    by_taxonomy = {}
    for c in cases:
        src = c.get("source", "unknown")
        by_source[src] = by_source.get(src, 0) + 1
        tax = c.get("taxonomy", "unknown")
        by_taxonomy[tax] = by_taxonomy.get(tax, 0) + 1
    return by_source, by_taxonomy


def save_yaml(cases: list[dict]):
    manual_count = sum(1 for c in cases if c["source"] == "manual")
    selftest_count = sum(1 for c in cases if c["source"] == "selftest_auto")
    so_count = sum(1 for c in cases if c["source"] == "so_auto")
    gh_count = sum(1 for c in cases if c["source"] == "gh_auto")
    by_taxonomy = {}
    for c in cases:
        t = c.get("taxonomy", "unknown")
        by_taxonomy[t] = by_taxonomy.get(t, 0) + 1

    doc = {
        "# Ground truth taxonomy labels for BPFix evaluation": None,
        "# Generated": str(date.today()),
    }

    output = {
        "metadata": {
            "generated": str(date.today()),
            "description": "Ground truth taxonomy labels for BPFix evaluation",
            "total_cases": len(cases),
            "by_source": {
                "manual": manual_count,
                "selftest_auto": selftest_count,
                "so_auto": so_count,
                "gh_auto": gh_count,
            },
            "by_taxonomy": by_taxonomy,
        },
        "cases": sorted(cases, key=lambda c: (c["source"], c["case_id"])),
    }

    with open(OUTPUT_YAML, "w") as f:
        yaml.dump(output, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
    print(f"\n  Saved {len(cases)} labels to {OUTPUT_YAML}")
    return by_taxonomy


# ──────────────────────────────────────────────────────────────────────────────
# 9. Write report
# ──────────────────────────────────────────────────────────────────────────────

def write_report(cases: list[dict]):
    manual = [c for c in cases if c["source"] == "manual"]
    selftest = [c for c in cases if c["source"] == "selftest_auto"]
    so = [c for c in cases if c["source"] == "so_auto"]
    gh = [c for c in cases if c["source"] == "gh_auto"]

    by_taxonomy = {}
    for c in cases:
        t = c["taxonomy"]
        by_taxonomy[t] = by_taxonomy.get(t, 0) + 1

    conf_counts = {}
    for c in cases:
        conf = c.get("confidence", "unknown")
        conf_counts[conf] = conf_counts.get(conf, 0) + 1

    lines = [
        f"# Ground Truth Label Expansion Report",
        f"",
        f"**Generated**: {date.today()}",
        f"",
        f"## Summary",
        f"",
        f"| Source | Count |",
        f"| --- | ---: |",
        f"| Manual (existing 30-case study) | {len(manual)} |",
        f"| Kernel selftest auto-labeled | {len(selftest)} |",
        f"| Stack Overflow auto-labeled | {len(so)} |",
        f"| GitHub Issues auto-labeled | {len(gh)} |",
        f"| **Total** | **{len(cases)}** |",
        f"",
        f"## Taxonomy Distribution",
        f"",
        f"| Class | Count | Share |",
        f"| --- | ---: | ---: |",
    ]
    for tax, count in sorted(by_taxonomy.items(), key=lambda x: -x[1]):
        lines.append(f"| `{tax}` | {count} | {100*count/len(cases):.1f}% |")

    lines += [
        f"",
        f"## Confidence Distribution",
        f"",
        f"| Confidence | Count |",
        f"| --- | ---: |",
    ]
    for conf, count in sorted(conf_counts.items(), key=lambda x: -x[1]):
        lines.append(f"| {conf} | {count} |")

    lines += [
        f"",
        f"## Methodology",
        f"",
        f"### Kernel Selftest Cases (confidence: high)",
        f"",
        f"Kernel selftests are *intentionally failing* programs that test specific verifier checks.",
        f"Each case has `expected_verifier_messages` annotated with `__msg()`. The taxonomy is",
        f"deterministic from the error type:",
        f"",
        f"1. If the case has an `error_id` field, map via the error catalog.",
        f"2. Otherwise, pattern-match the expected message strings against 50+ regex patterns",
        f"   covering all 23 BPFix error IDs.",
        f"3. Fall back to scanning the full `verifier_log` field.",
        f"",
        f"### Stack Overflow and GitHub Issue Cases (confidence: medium)",
        f"",
        f"Auto-labeling uses keyword matching on `fix_description`, `body_text`, and",
        f"`summary` fields:",
        f"",
        f"- **source_bug**: bounds check, null check, initialize buffer, pointer guard, etc.",
        f"- **lowering_artifact**: volatile, barrier, inline, clang, compiler optimization, etc.",
        f"- **env_mismatch**: kernel version, not supported, helper not, program type, etc.",
        f"- **verifier_limit**: loop unroll, complexity, too many states, state explosion, etc.",
        f"",
        f"If no keyword match, fall back to verifier log message pattern matching.",
        f"",
        f"### Manual Labels (priority override)",
        f"",
        f"The 30 existing manual labels always take priority over auto labels on any conflict.",
        f"",
        f"## Sample Labeled Cases by Source",
        f"",
        f"### Kernel Selftest Samples (first 10)",
        f"",
        f"| Case ID | Taxonomy | Notes |",
        f"| --- | --- | --- |",
    ]
    for c in selftest[:10]:
        lines.append(f"| `{c['case_id']}` | `{c['taxonomy']}` | {c.get('notes','')[:80]} |")

    lines += [
        f"",
        f"### Stack Overflow Samples (first 10)",
        f"",
        f"| Case ID | Taxonomy | Notes |",
        f"| --- | --- | --- |",
    ]
    for c in so[:10]:
        lines.append(f"| `{c['case_id']}` | `{c['taxonomy']}` | {c.get('notes','')[:80]} |")

    lines += [
        f"",
        f"### GitHub Issues Samples (all {len(gh)})",
        f"",
        f"| Case ID | Taxonomy | Notes |",
        f"| --- | --- | --- |",
    ]
    for c in gh:
        lines.append(f"| `{c['case_id']}` | `{c['taxonomy']}` | {c.get('notes','')[:80]} |")

    lines += [
        f"",
        f"## Output File",
        f"",
        f"Labels saved to: `case_study/ground_truth_labels.yaml`",
        f"",
        f"**Target achieved**: {'YES' if len(cases) >= 100 else 'NO'} ({len(cases)} >= 100 required)",
    ]

    report_text = "\n".join(lines)
    OUTPUT_REPORT.write_text(report_text)
    print(f"  Report saved to {OUTPUT_REPORT}")


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main():
    print("=== Ground Truth Label Expansion ===\n")

    print("[1] Parsing existing 30 manual labels...")
    manual = parse_manual_labels()

    print("\n[2] Auto-labeling kernel selftest cases...")
    selftest_auto = autolabel_kernel_selftests()

    print("\n[3] Auto-labeling Stack Overflow cases...")
    so_auto = autolabel_stackoverflow()

    print("\n[4] Auto-labeling GitHub Issues cases...")
    gh_auto = autolabel_github()

    print("\n[5] Merging all labels (manual takes priority)...")
    all_cases = merge_labels(manual, selftest_auto, so_auto, gh_auto)

    print(f"\n  Total cases after merge: {len(all_cases)}")

    print("\n[6] Saving ground_truth_labels.yaml...")
    by_taxonomy = save_yaml(all_cases)

    print("\n[7] Writing report...")
    write_report(all_cases)

    print("\n=== Done ===")
    print(f"Total labeled: {len(all_cases)}")
    print(f"By taxonomy: {dict(sorted(by_taxonomy.items(), key=lambda x: -x[1]))}")
    print(f"Target (>=100): {'ACHIEVED' if len(all_cases) >= 100 else 'NOT MET'}")


if __name__ == "__main__":
    main()
