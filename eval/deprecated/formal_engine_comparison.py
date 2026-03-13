#!/usr/bin/env python3
"""
Formal Engine Comparison: v3 (heuristic) vs v4 (formal engine).

Compares batch_diagnostic_results_v3.json (241 cases, old heuristic) against
batch_diagnostic_results_v4.json (262 cases, new formal engine) and produces a
detailed Markdown report at docs/tmp/formal-engine-comparison.md.

This script is READ-ONLY — it does not modify any pipeline code.
"""

import json
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).parent.parent
V3_PATH = ROOT / "eval/results/batch_diagnostic_results_v3.json"
V4_PATH = ROOT / "eval/results/batch_diagnostic_results_v4.json"
REPORT_PATH = ROOT / "docs/tmp/formal-engine-comparison.md"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_results(path: Path) -> dict:
    with open(path) as fh:
        return json.load(fh)


def get_diagnostic_json(record: dict) -> dict:
    dj = record.get("diagnostic_json")
    if not dj:
        return {}
    if isinstance(dj, str):
        try:
            return json.loads(dj)
        except json.JSONDecodeError:
            return {}
    return dj if isinstance(dj, dict) else {}


def get_metadata(record: dict) -> dict:
    return get_diagnostic_json(record).get("metadata") or {}


def get_obligation(record: dict) -> dict | None:
    return get_metadata(record).get("obligation")


def get_proof_spans(record: dict) -> list:
    return get_metadata(record).get("proof_spans") or []


def get_causal_chain(record: dict) -> list:
    return get_metadata(record).get("causal_chain") or []


def proof_lost_insn(record: dict) -> int | None:
    """Return the instruction index of the first proof_lost span, or None."""
    for span in get_proof_spans(record):
        if span.get("role") == "proof_lost":
            ir = span.get("insn_range")
            if ir:
                return ir[0]
    return None


def proof_established_insn(record: dict) -> int | None:
    """Return the instruction index of the first proof_established span, or None."""
    for span in get_proof_spans(record):
        if span.get("role") == "proof_established":
            ir = span.get("insn_range")
            if ir:
                return ir[0]
    return None


# ---------------------------------------------------------------------------
# Case matching
# ---------------------------------------------------------------------------

def build_match_table(v3_records: list, v4_records: list):
    """
    Build a mapping from v3 case_id to a list of corresponding v4 case_ids.

    Strategy:
    - stackoverflow / github_issues: exact ID match (IDs are stable across versions).
    - kernel_selftests: v4 appended prog_type + 8-char hex hash to the v3 base name.
      Match by finding the longest v3 ID that is a proper prefix of the v4 ID.
    """
    v3_by_id = {r["case_id"]: r for r in v3_records}
    v4_by_id = {r["case_id"]: r for r in v4_records}

    # Partition by source_dir
    v3_non_self = {
        cid: r for cid, r in v3_by_id.items()
        if r.get("source_dir") in ("stackoverflow", "github_issues")
    }
    v4_non_self = {
        cid: r for cid, r in v4_by_id.items()
        if r.get("source_dir") in ("stackoverflow", "github_issues")
    }
    v3_self = {
        cid: r for cid, r in v3_by_id.items()
        if "kernel_selftests" in (r.get("source_dir") or "")
    }
    v4_self = {
        cid: r for cid, r in v4_by_id.items()
        if r.get("source_dir") == "kernel_selftests"
    }

    match: dict[str, list[str]] = {}

    # Exact matches (SO + GitHub)
    for cid in v3_non_self:
        if cid in v4_non_self:
            match[cid] = [cid]

    # Prefix matches (selftests)
    for cid4 in v4_self:
        best = None
        for cid3 in v3_self:
            if cid4.startswith(cid3 + "-"):
                if best is None or len(cid3) > len(best):
                    best = cid3
        if best:
            match.setdefault(best, [])
            match[best].append(cid4)

    # Cases new in v4 (no v3 equivalent)
    matched_v4 = set()
    for lst in match.values():
        matched_v4.update(lst)
    new_in_v4 = [cid for cid in v4_by_id if cid not in matched_v4]

    # Cases in v3 with no v4 match
    unmatched_v3 = [cid for cid in v3_by_id if cid not in match]

    return match, new_in_v4, unmatched_v3, v3_by_id, v4_by_id


# ---------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------

def summarise_totals(label: str, records: list) -> dict:
    success = [r for r in records if r.get("success")]
    skipped = [r for r in records if r.get("skipped")]
    failed = [r for r in records if not r.get("success") and not r.get("skipped")]
    has_obl = sum(1 for r in success if get_obligation(r))
    has_spans = sum(1 for r in success if r.get("num_spans", 0) > 0)
    has_causal = sum(1 for r in success if get_causal_chain(r))
    ps_dist = Counter(r.get("proof_status") for r in success)
    return {
        "label": label,
        "scanned": len(records),
        "success": len(success),
        "skipped": len(skipped),
        "failed": len(failed),
        "has_obligation": has_obl,
        "obligation_pct": 100 * has_obl / len(success) if success else 0,
        "has_spans": has_spans,
        "spans_pct": 100 * has_spans / len(success) if success else 0,
        "has_causal_chain": has_causal,
        "causal_pct": 100 * has_causal / len(success) if success else 0,
        "proof_status": dict(ps_dist),
    }


def compare_common_cases(match: dict, v3_by_id: dict, v4_by_id: dict):
    """
    For each v3 case that has at least one v4 match, compare metrics.
    When multiple v4 cases map to one v3 case, compare v3 against each v4 child.
    Returns lists of diffs.
    """
    status_changes = []
    obligation_gained = []
    obligation_lost = []
    span_gained = []
    span_lost = []
    causal_new = []
    proof_lost_insn_changes = []
    unchanged = []

    for cid3, v4_ids in match.items():
        r3 = v3_by_id.get(cid3)
        if r3 is None:
            continue

        for cid4 in v4_ids:
            r4 = v4_by_id.get(cid4)
            if r4 is None:
                continue

            # Only compare successfully processed cases
            if not r3.get("success") or not r4.get("success"):
                continue

            diff = {"v3_id": cid3, "v4_id": cid4}
            changed = False

            # Proof status
            ps3 = r3.get("proof_status")
            ps4 = r4.get("proof_status")
            if ps3 != ps4:
                diff["ps_v3"] = ps3
                diff["ps_v4"] = ps4
                status_changes.append(diff.copy())
                changed = True

            # Obligation
            obl3 = bool(get_obligation(r3))
            obl4 = bool(get_obligation(r4))
            if obl3 and not obl4:
                obligation_lost.append(diff.copy())
                changed = True
            elif not obl3 and obl4:
                obligation_gained.append(diff.copy())
                changed = True

            # Spans
            spans3 = r3.get("num_spans", 0)
            spans4 = r4.get("num_spans", 0)
            if spans4 > spans3:
                diff["spans_v3"] = spans3
                diff["spans_v4"] = spans4
                span_gained.append(diff.copy())
                changed = True
            elif spans4 < spans3:
                diff["spans_v3"] = spans3
                diff["spans_v4"] = spans4
                span_lost.append(diff.copy())
                changed = True

            # Causal chain (new in v4)
            if get_causal_chain(r4):
                causal_new.append({"v3_id": cid3, "v4_id": cid4,
                                    "chain": get_causal_chain(r4)})

            # Proof-lost instruction index shift
            pl3 = proof_lost_insn(r3)
            pl4 = proof_lost_insn(r4)
            if pl3 is not None and pl4 is not None and pl3 != pl4:
                diff["pl_v3"] = pl3
                diff["pl_v4"] = pl4
                proof_lost_insn_changes.append(diff.copy())
                changed = True

            if not changed:
                unchanged.append(cid3)

    return {
        "status_changes": status_changes,
        "obligation_gained": obligation_gained,
        "obligation_lost": obligation_lost,
        "span_gained": span_gained,
        "span_lost": span_lost,
        "causal_new": causal_new,
        "proof_lost_insn_changes": proof_lost_insn_changes,
        "unchanged_count": len(unchanged),
    }


def analyse_new_cases(new_in_v4: list, v4_by_id: dict):
    records = [v4_by_id[cid] for cid in new_in_v4 if cid in v4_by_id]
    success = [r for r in records if r.get("success")]
    ps_dist = Counter(r.get("proof_status") for r in success)
    has_obl = sum(1 for r in success if get_obligation(r))
    has_causal = sum(1 for r in success if get_causal_chain(r))
    return {
        "total": len(records),
        "success": len(success),
        "proof_status": dict(ps_dist),
        "has_obligation": has_obl,
        "has_causal_chain": has_causal,
        "samples": [r["case_id"] for r in success[:10]],
    }


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

def pct(n: int, d: int) -> str:
    if d == 0:
        return "N/A"
    return f"{100 * n / d:.1f}%"


def render_report(
    v3_totals: dict,
    v4_totals: dict,
    diffs: dict,
    new_cases: dict,
    unmatched_v3: list,
    match_count: int,
) -> str:
    lines = []
    a = lines.append

    a("# Formal Engine Comparison: v3 (Heuristic) vs v4 (Formal Engine)")
    a("")
    a("Generated by `eval/formal_engine_comparison.py`.")
    a("")

    # -----------------------------------------------------------------------
    a("## 1. Summary Table")
    a("")
    a("| Metric | v3 (heuristic) | v4 (formal engine) | Delta |")
    a("|--------|---------------|-------------------|-------|")

    def row(metric, v3_val, v4_val, delta=""):
        a(f"| {metric} | {v3_val} | {v4_val} | {delta} |")

    row("Cases scanned", v3_totals["scanned"], v4_totals["scanned"])
    row("Cases processed (success)", v3_totals["success"], v4_totals["success"],
        f"+{v4_totals['success'] - v3_totals['success']}")
    row("Cases skipped", v3_totals["skipped"], v4_totals["skipped"],
        f"{v4_totals['skipped'] - v3_totals['skipped']}")

    obl_delta = v4_totals["has_obligation"] - v3_totals["has_obligation"]
    row("Cases with obligation",
        f"{v3_totals['has_obligation']} ({v3_totals['obligation_pct']:.1f}%)",
        f"{v4_totals['has_obligation']} ({v4_totals['obligation_pct']:.1f}%)",
        f"+{obl_delta}" if obl_delta >= 0 else str(obl_delta))

    span_delta = v4_totals["has_spans"] - v3_totals["has_spans"]
    row("Cases with ≥1 span",
        f"{v3_totals['has_spans']} ({v3_totals['spans_pct']:.1f}%)",
        f"{v4_totals['has_spans']} ({v4_totals['spans_pct']:.1f}%)",
        f"+{span_delta}" if span_delta >= 0 else str(span_delta))

    row("Cases with causal chain",
        f"{v3_totals['has_causal_chain']} ({v3_totals['causal_pct']:.1f}%)",
        f"{v4_totals['has_causal_chain']} ({v4_totals['causal_pct']:.1f}%)",
        f"+{v4_totals['has_causal_chain'] - v3_totals['has_causal_chain']}")

    a("")
    a("### Proof Status Distribution")
    a("")
    a("| Proof Status | v3 | v4 |")
    a("|-------------|-----|-----|")
    all_statuses = sorted(set(list(v3_totals["proof_status"].keys()) +
                              list(v4_totals["proof_status"].keys())))
    for ps in all_statuses:
        v3c = v3_totals["proof_status"].get(ps, 0)
        v4c = v4_totals["proof_status"].get(ps, 0)
        a(f"| {ps} | {v3c} | {v4c} |")
    a("")

    # -----------------------------------------------------------------------
    a("## 2. Obligation Coverage Check")
    a("")
    a("The target threshold from Phase 1 is **≥94.2%** obligation coverage.")
    a("")
    v3_obl_pct = v3_totals["obligation_pct"]
    v4_obl_pct = v4_totals["obligation_pct"]
    threshold = 94.2
    v3_pass = "PASS" if v3_obl_pct >= threshold else "FAIL"
    v4_pass = "PASS" if v4_obl_pct >= threshold else "FAIL"
    a(f"- v3 obligation coverage: **{v3_obl_pct:.1f}%** — {v3_pass}")
    a(f"- v4 obligation coverage: **{v4_obl_pct:.1f}%** — {v4_pass}")
    a("")
    if v4_obl_pct >= threshold:
        a("The formal engine **maintains** the ≥94.2% obligation coverage threshold.")
    else:
        a(f"WARNING: The formal engine **drops below** the threshold "
          f"({v4_obl_pct:.1f}% < 94.2%).")
    a("")

    # -----------------------------------------------------------------------
    a("## 3. Case Matching Strategy")
    a("")
    a("Between v3 and v4, kernel-selftest case IDs gained a prog_type and 8-char "
      "hex hash suffix (e.g., `kernel-selftest-foo` → `kernel-selftest-foo-tc-a1b2c3d4`). "
      "Matching was performed by:")
    a("")
    a("- **Exact match**: stackoverflow and github_issues cases (stable IDs).")
    a("- **Prefix match**: kernel_selftests — longest v3 ID that is a proper prefix of v4 ID.")
    a("")
    a(f"| Category | Count |")
    a(f"|----------|-------|")
    a(f"| v3 cases matchable to ≥1 v4 case | {match_count} |")
    a(f"| v3 cases with no v4 equivalent | {len(unmatched_v3)} |")
    a(f"| v4 cases with no v3 equivalent (new) | {new_cases['total']} |")
    a("")

    # -----------------------------------------------------------------------
    a("## 4. Per-Case Diff for Common Cases")
    a("")
    a(f"**{match_count}** v3 cases were matched to v4 equivalents. "
      f"**{diffs['unchanged_count']}** showed identical results across all dimensions.")
    a("")

    # 4a. Status changes
    sc = diffs["status_changes"]
    a(f"### 4a. Proof Status Changes ({len(sc)} cases)")
    a("")
    if sc:
        a("| v3 Case ID | v4 Case ID | v3 Status | v4 Status |")
        a("|-----------|-----------|----------|----------|")
        for d in sc:
            v3id_short = d["v3_id"][-60:] if len(d["v3_id"]) > 60 else d["v3_id"]
            v4id_short = d["v4_id"][-60:] if len(d["v4_id"]) > 60 else d["v4_id"]
            a(f"| `{v3id_short}` | `{v4id_short}` | {d['ps_v3']} | {d['ps_v4']} |")
        a("")
        # Count direction of changes
        ne_to_etl = sum(1 for d in sc if d["ps_v3"] == "never_established"
                        and d["ps_v4"] == "established_then_lost")
        etl_to_ne = sum(1 for d in sc if d["ps_v3"] == "established_then_lost"
                        and d["ps_v4"] == "never_established")
        a(f"- `never_established` → `established_then_lost`: {ne_to_etl} "
          f"(formal engine now detects an establishment point that heuristic missed)")
        a(f"- `established_then_lost` → `never_established`: {etl_to_ne} "
          f"(formal engine could not verify earlier establishment)")
        other_changes = len(sc) - ne_to_etl - etl_to_ne
        if other_changes:
            a(f"- Other transitions: {other_changes}")
    else:
        a("No proof status changes detected.")
    a("")

    # 4b. Obligation changes
    obl_lost = diffs["obligation_lost"]
    obl_gained = diffs["obligation_gained"]
    a(f"### 4b. Obligation Changes")
    a("")
    a(f"- Obligation **gained** in v4: {len(obl_gained)} cases")
    a(f"- Obligation **lost** in v4 (regression): {len(obl_lost)} cases")
    a("")
    if obl_lost:
        a("#### Regressions (obligation present in v3, absent in v4):")
        a("")
        for d in obl_lost[:20]:
            a(f"- `{d['v3_id']}`")
        if len(obl_lost) > 20:
            a(f"- *(and {len(obl_lost) - 20} more)*")
        a("")
    if obl_gained:
        a("#### Improvements (obligation absent in v3, present in v4):")
        a("")
        for d in obl_gained[:20]:
            a(f"- `{d['v3_id']}`")
        if len(obl_gained) > 20:
            a(f"- *(and {len(obl_gained) - 20} more)*")
        a("")

    # 4c. Span changes
    sg = diffs["span_gained"]
    sl = diffs["span_lost"]
    a(f"### 4c. Span Count Changes")
    a("")
    a(f"- Spans **increased** in v4: {len(sg)} cases (improvement)")
    a(f"- Spans **decreased** in v4: {len(sl)} cases (potential regression)")
    a("")
    if sg:
        a("| v3 ID | v3 spans | v4 spans |")
        a("|-------|----------|----------|")
        for d in sg[:15]:
            short = d["v3_id"][-55:] if len(d["v3_id"]) > 55 else d["v3_id"]
            a(f"| `{short}` | {d['spans_v3']} | {d['spans_v4']} |")
        if len(sg) > 15:
            a(f"| *(and {len(sg)-15} more)* | | |")
        a("")
    if sl:
        a("| v3 ID | v3 spans | v4 spans |")
        a("|-------|----------|----------|")
        for d in sl[:15]:
            short = d["v3_id"][-55:] if len(d["v3_id"]) > 55 else d["v3_id"]
            a(f"| `{short}` | {d['spans_v3']} | {d['spans_v4']} |")
        if len(sl) > 15:
            a(f"| *(and {len(sl)-15} more)* | | |")
        a("")

    # 4d. Proof-lost instruction index shifts
    pli = diffs["proof_lost_insn_changes"]
    a(f"### 4d. Proof-Lost Instruction Index Shifts ({len(pli)} cases)")
    a("")
    if pli:
        a("| v3 ID | v3 insn | v4 insn | Delta |")
        a("|-------|---------|---------|-------|")
        for d in pli[:20]:
            short = d["v3_id"][-50:] if len(d["v3_id"]) > 50 else d["v3_id"]
            delta = d["pl_v4"] - d["pl_v3"]
            sign = "+" if delta > 0 else ""
            a(f"| `{short}` | {d['pl_v3']} | {d['pl_v4']} | {sign}{delta} |")
        if len(pli) > 20:
            a(f"| *(and {len(pli)-20} more)* | | | |")
    else:
        a("No proof-lost instruction index shifts detected among comparable cases.")
    a("")

    # 4e. Causal chain
    cc = diffs["causal_new"]
    a(f"### 4e. Causal Chain (Backward Slice) — New in v4")
    a("")
    a(f"**{len(cc)}** matched cases now have a non-empty `causal_chain` in v4 metadata.")
    a("")
    if cc:
        a("Sample causal chains:")
        a("")
        for entry in cc[:5]:
            short = entry["v4_id"][-70:] if len(entry["v4_id"]) > 70 else entry["v4_id"]
            a(f"- `{short}`")
            for step in entry["chain"][:3]:
                a(f"  - insn {step[0]}: {step[1]}")
        a("")

    # -----------------------------------------------------------------------
    a("## 5. New Cases in v4 (No v3 Equivalent)")
    a("")
    nc = new_cases
    a(f"**{nc['total']}** cases appear in v4 but have no corresponding v3 case. "
      f"Of these, **{nc['success']}** were successfully processed.")
    a("")
    if nc["proof_status"]:
        a("| Proof Status | Count |")
        a("|-------------|-------|")
        for ps, cnt in sorted(nc["proof_status"].items()):
            a(f"| {ps} | {cnt} |")
        a("")
    a(f"- Cases with obligation: {nc['has_obligation']}")
    a(f"- Cases with causal chain: {nc['has_causal_chain']}")
    a("")
    if nc["samples"]:
        a("Sample new v4 case IDs:")
        a("")
        for cid in nc["samples"][:10]:
            a(f"- `{cid}`")
    a("")

    # -----------------------------------------------------------------------
    a("## 6. Assessment")
    a("")

    regressions_total = len(obl_lost) + len(sl)
    improvements_total = len(obl_gained) + len(sg) + len(cc)

    a("### Overall Verdict")
    a("")
    verdict_lines = []

    # Obligation coverage
    if v4_obl_pct >= threshold:
        verdict_lines.append(
            f"**Obligation coverage maintained**: {v4_obl_pct:.1f}% >= {threshold}%.")
    else:
        verdict_lines.append(
            f"**REGRESSION in obligation coverage**: {v4_obl_pct:.1f}% < {threshold}%.")

    # Throughput
    throughput_delta = v4_totals["success"] - v3_totals["success"]
    if throughput_delta > 0:
        verdict_lines.append(
            f"**Throughput improved**: +{throughput_delta} more cases processed "
            f"({v4_totals['success']} vs {v3_totals['success']}).")
    elif throughput_delta < 0:
        verdict_lines.append(
            f"**REGRESSION in throughput**: {throughput_delta} fewer cases processed.")

    # Causal chain
    if v4_totals["has_causal_chain"] > 0:
        verdict_lines.append(
            f"**Backward slice (causal_chain) is a new capability**: "
            f"{v4_totals['has_causal_chain']} cases now include causal chain data.")

    # Net regression/improvement
    if regressions_total == 0 and improvements_total > 0:
        verdict_lines.append(
            f"**Strict improvement**: {improvements_total} cases improved, 0 regressions.")
    elif regressions_total > 0 and improvements_total > regressions_total:
        verdict_lines.append(
            f"**Net improvement**: {improvements_total} improvements vs "
            f"{regressions_total} regressions.")
    elif regressions_total > improvements_total:
        verdict_lines.append(
            f"**Net regression**: {regressions_total} regressions vs "
            f"{improvements_total} improvements — review required.")
    else:
        verdict_lines.append(
            f"**Mixed**: {improvements_total} improvements, {regressions_total} regressions.")

    for vl in verdict_lines:
        a(f"- {vl}")
    a("")

    a("### Specific Examples")
    a("")
    a("#### Example Improvements")
    a("")
    if sg:
        ex = sg[0]
        a(f"- `{ex['v3_id']}`: spans increased from {ex['spans_v3']} to {ex['spans_v4']}.")
    if obl_gained:
        a(f"- `{obl_gained[0]['v3_id']}`: gained obligation mapping in v4.")
    if cc:
        ex = cc[0]
        a(f"- `{ex['v4_id']}`: new causal chain — {ex['chain'][0] if ex['chain'] else 'N/A'}.")
    if not sg and not obl_gained and not cc:
        a("- No concrete improvement examples found among matched cases.")
    a("")

    a("#### Example Regressions")
    a("")
    if obl_lost:
        a(f"- `{obl_lost[0]['v3_id']}`: lost obligation in v4 (was present in v3).")
    if sl:
        ex = sl[0]
        a(f"- `{ex['v3_id']}`: span count dropped from {ex['spans_v3']} to {ex['spans_v4']}.")
    if sc:
        ex = sc[0]
        a(f"- `{ex['v3_id']}`: proof status changed from `{ex['ps_v3']}` to `{ex['ps_v4']}`.")
    if not obl_lost and not sl:
        a("- No concrete regression examples found among matched cases.")
    a("")

    a("---")
    a("")
    a("*End of report.*")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print(f"Loading v3 results from {V3_PATH} ...")
    v3_data = load_results(V3_PATH)
    print(f"Loading v4 results from {V4_PATH} ...")
    v4_data = load_results(V4_PATH)

    v3_records = v3_data["results"]
    v4_records = v4_data["results"]

    # Compute overall totals
    v3_totals = summarise_totals("v3", v3_records)
    v4_totals = summarise_totals("v4", v4_records)

    print(f"v3: {v3_totals['success']} successful / {v3_totals['scanned']} scanned")
    print(f"v4: {v4_totals['success']} successful / {v4_totals['scanned']} scanned")

    # Build match table
    print("Building case match table ...")
    match, new_in_v4, unmatched_v3, v3_by_id, v4_by_id = build_match_table(
        v3_records, v4_records
    )
    print(f"  Matched v3→v4: {len(match)} v3 cases")
    print(f"  Unmatched in v3: {len(unmatched_v3)}")
    print(f"  New in v4: {len(new_in_v4)}")

    # Per-case diff
    print("Comparing common cases ...")
    diffs = compare_common_cases(match, v3_by_id, v4_by_id)
    print(f"  Status changes: {len(diffs['status_changes'])}")
    print(f"  Obligation gained: {len(diffs['obligation_gained'])}")
    print(f"  Obligation lost: {len(diffs['obligation_lost'])}")
    print(f"  Spans gained: {len(diffs['span_gained'])}")
    print(f"  Spans lost: {len(diffs['span_lost'])}")
    print(f"  Causal chain: {len(diffs['causal_new'])}")
    print(f"  Proof-lost insn shifts: {len(diffs['proof_lost_insn_changes'])}")
    print(f"  Unchanged: {diffs['unchanged_count']}")

    # New cases
    new_cases = analyse_new_cases(new_in_v4, v4_by_id)

    # Render
    print("Rendering report ...")
    report = render_report(
        v3_totals, v4_totals, diffs, new_cases, unmatched_v3, len(match)
    )

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(REPORT_PATH, "w") as fh:
        fh.write(report)

    print(f"\nReport written to: {REPORT_PATH}")
    print()
    print("=== Quick Summary ===")
    print(f"v3 obligation coverage: {v3_totals['obligation_pct']:.1f}%")
    print(f"v4 obligation coverage: {v4_totals['obligation_pct']:.1f}%")
    print(f"v4 causal chain coverage: {v4_totals['causal_pct']:.1f}%")
    print(f"Proof status changes in matched cases: {len(diffs['status_changes'])}")
    print(f"Obligation regressions: {len(diffs['obligation_lost'])}")
    print(f"Obligation improvements: {len(diffs['obligation_gained'])}")


if __name__ == "__main__":
    main()
