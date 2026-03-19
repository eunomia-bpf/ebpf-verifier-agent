#!/usr/bin/env python3
"""Pilot test: proof engine + repair synthesis on lowering_artifact cases.

Uses established_then_lost cases from batch_diagnostic_results.json.
Tests the full pipeline: trace parse -> predicate inference -> monitoring -> synthesis.
"""

from __future__ import annotations

import json
import sys
import traceback
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from interface.extractor.trace_parser import parse_verifier_trace
from interface.extractor.log_parser import parse_verifier_log
from interface.extractor.engine.monitor import TraceMonitor
from interface.extractor.engine.opcode_safety import (
    OpcodeConditionPredicate,
    find_violated_condition,
    infer_conditions_from_error_insn,
)
from interface.extractor.engine.synthesizer import RepairSynthesizer
from eval.verifier_oracle import verify_fix


def get_verifier_log_text(case_data: dict) -> str:
    """Extract verifier log text from case data."""
    vl = case_data.get("verifier_log", "")
    if isinstance(vl, dict):
        return vl.get("combined", "") or vl.get("raw", "") or ""
    elif isinstance(vl, str):
        return vl
    return ""


def get_source_code(case_data: dict) -> str:
    """Extract source code from case data."""
    src = case_data.get("source_code", "")
    if src:
        return src

    snippets = case_data.get("source_snippets", []) or []
    for s in snippets:
        if isinstance(s, dict):
            code = s.get("code", "")
            if code:
                return code
        elif isinstance(s, str) and s.strip():
            return s
    return ""


def run_pilot(limit: int = 10, compile_only: bool = False) -> None:
    """Run pilot test on established_then_lost cases."""

    results_path = Path(__file__).resolve().parents[1] / "eval/results/batch_diagnostic_results.json"
    with open(results_path) as f:
        batch_data = json.load(f)

    # Handle multiple possible structures
    if isinstance(batch_data, list):
        all_cases = batch_data
    elif isinstance(batch_data, dict):
        all_cases = batch_data.get("results", batch_data.get("cases", []))

    # Use established_then_lost cases (= lowering artifacts by proof status)
    la_cases = [
        c for c in all_cases
        if c.get("proof_status") == "established_then_lost"
        and c.get("case_path")
    ]

    print(f"Found {len(la_cases)} established_then_lost cases")

    # Prioritize SO/GH cases with standalone source (more likely to compile for oracle)
    # Then fall back to cases with good error messages
    prioritized = []
    rest = []
    for c in la_cases:
        path = c.get("case_path", "")
        if not path:
            continue
        # Prefer SO/GitHub cases (more likely to have compilable standalone snippets)
        is_so_gh = "stackoverflow" in path or "github" in path
        try:
            with open(path) as f:
                case_data_check = yaml.safe_load(f) or {}
            vl_text_check = get_verifier_log_text(case_data_check)
            has_good_error = False
            if vl_text_check:
                parsed_check = parse_verifier_log(vl_text_check)
                error_check = parsed_check.error_line or ""
                has_good_error = any(kw in error_check.lower() for kw in [
                    "invalid access", "invalid mem access", "possibly null",
                    "unreleased reference", "leads to invalid", "prohibited",
                    "type=", "r6 invalid", "r2 invalid", "r3 invalid",
                ])
            if (is_so_gh or has_good_error):
                prioritized.append(c)
                continue
        except Exception:
            pass
        rest.append(c)

    ordered_cases = prioritized + rest
    print(f"  Cases with good error messages (prioritized): {len(prioritized)}")
    print(f"Testing first {limit}...\n")

    monitor = TraceMonitor()
    synth = RepairSynthesizer()
    results = []

    for batch_case in ordered_cases[:limit]:
        case_path = batch_case["case_path"]
        case_id = batch_case.get("case_id", Path(case_path).stem)

        try:
            with open(case_path) as f:
                case_data = yaml.safe_load(f) or {}
        except Exception as e:
            results.append({
                "case": case_id,
                "status": "load_error",
                "error": str(e),
            })
            continue

        log_text = get_verifier_log_text(case_data)
        source = get_source_code(case_data)

        if not log_text:
            results.append({
                "case": case_id,
                "status": "no_log",
            })
            continue

        try:
            # Parse
            parsed_log = parse_verifier_log(log_text)
            parsed_trace = parse_verifier_trace(log_text)

            # Infer predicate
            error_msg = parsed_log.error_line or ""
            # Also try error text from trace instructions
            if not error_msg:
                for insn in parsed_trace.instructions:
                    if insn.is_error and insn.error_text:
                        error_msg = insn.error_text
                        break

            # Get the error instruction for opcode-driven analysis
            error_insn = None
            for insn in parsed_trace.instructions:
                if insn.is_error:
                    error_insn = insn
                    break
            if error_insn is None and parsed_trace.instructions:
                error_insn = parsed_trace.instructions[-1]

            pred = None
            if error_insn is not None:
                conditions = infer_conditions_from_error_insn(error_insn)
                violated = find_violated_condition(error_insn, conditions)
                if violated is not None:
                    pred = OpcodeConditionPredicate(violated)

            if not pred:
                results.append({
                    "case": case_id,
                    "status": "no_predicate",
                    "error_msg": error_msg[:100],
                })
                continue

            # Monitor
            mr = monitor.monitor(pred, parsed_trace.instructions)

            # Synthesize
            fix = synth.synthesize(mr, pred, parsed_trace.instructions, source)

            result_entry = {
                "case": case_id,
                "status": "analyzed",
                "proof_status": mr.proof_status,
                "predicate_type": type(pred).__name__,
                "establish_site": mr.establish_site,
                "loss_site": mr.loss_site,
                "loss_reason": mr.loss_reason,
                "has_fix": fix is not None,
                "repair_type": fix.repair_type if fix else None,
                "repair_confidence": getattr(fix, "confidence", None) if fix else None,
                "error_msg": error_msg[:100],
            }

            # Validate with oracle if we have a fix and source code
            if fix and fix.code_patch and source:
                # Apply the patch: try inserting it before the first function body
                try:
                    repaired = _apply_patch(source, fix.code_patch)
                    oracle_result = verify_fix(
                        repaired,
                        verifier_log_hint=log_text,
                        compile_only=compile_only,
                    )
                    result_entry["compiles"] = oracle_result.compiles
                    result_entry["verifier_pass"] = oracle_result.verifier_pass
                    result_entry["oracle_error"] = oracle_result.error
                    result_entry["template_used"] = oracle_result.template_used
                except Exception as e:
                    result_entry["oracle_error"] = str(e)
            elif not source:
                result_entry["oracle_skip"] = "no source code"

            results.append(result_entry)

        except Exception as e:
            results.append({
                "case": case_id,
                "status": "error",
                "error": str(e),
                "traceback": traceback.format_exc()[-500:],
            })

    # Print results
    print("=" * 70)
    print("PILOT TEST RESULTS")
    print("=" * 70)
    for r in results:
        status = r.get("status", "?")
        case = r.get("case", "?")
        if status == "analyzed":
            proof_status = r.get("proof_status", "?")
            pred_type = r.get("predicate_type", "?")
            has_fix = r.get("has_fix", False)
            compiles = r.get("compiles", None)
            vpass = r.get("verifier_pass", None)
            repair = r.get("repair_type", "none")
            print(f"  {case}")
            print(f"    proof_status={proof_status} | pred={pred_type} | repair={repair}")
            print(f"    has_fix={has_fix} | compiles={compiles} | verifier_pass={vpass}")
            if r.get("loss_site"):
                print(f"    establish_at={r.get('establish_site')} loss_at={r.get('loss_site')}")
            if r.get("oracle_skip"):
                print(f"    [oracle skipped: {r['oracle_skip']}]")
        elif status == "no_predicate":
            print(f"  {case}")
            print(f"    [no predicate] error_msg={r.get('error_msg', '')[:60]}")
        else:
            print(f"  {case}: {status} - {r.get('error', '')[:80]}")
        print()

    print("=" * 70)
    analyzed = [r for r in results if r.get("status") == "analyzed"]
    has_fix = [r for r in analyzed if r.get("has_fix")]
    compiles_ok = [r for r in analyzed if r.get("compiles") is True]
    vpass_ok = [r for r in analyzed if r.get("verifier_pass") is True]
    established_then_lost = [r for r in analyzed if r.get("proof_status") == "established_then_lost"]

    print(f"Total cases tested:    {len(results)}")
    print(f"Successfully analyzed: {len(analyzed)}")
    print(f"No predicate:          {sum(1 for r in results if r.get('status') == 'no_predicate')}")
    print(f"Proof status matched:  {len(established_then_lost)} / {len(analyzed)} (established_then_lost)")
    print(f"Synthesis attempted:   {len(has_fix)}")
    print(f"Compiles:              {len(compiles_ok)}")
    print(f"Verifier PASS:         {len(vpass_ok)}")
    print("=" * 70)

    # Save results
    out_path = Path(__file__).resolve().parents[1] / "docs/tmp/synthesis-pilot-results.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nResults saved to: {out_path}")

    return results


def _apply_patch(source: str, patch: str) -> str:
    """Apply a code patch to source code.

    Inserts the patch just before the first function body open brace.
    This is a simple heuristic for the pilot.
    """
    import re

    # Find the first BPF function body
    func_re = re.compile(
        r'((?:SEC\s*\([^)]+\)\s*)?(?:static\s+)?(?:__always_inline\s+)?int\s+\w+\s*\([^)]*\)\s*\{)',
        re.MULTILINE | re.DOTALL,
    )
    match = func_re.search(source)
    if match:
        # Insert patch after the opening brace
        insert_pos = match.end()
        return source[:insert_pos] + "\n    " + patch.replace("\n", "\n    ") + "\n" + source[insert_pos:]

    # Fallback: append to end
    return source + "\n\n/* BPFix repair suggestion */\n" + patch


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Synthesis pilot test")
    parser.add_argument("--limit", type=int, default=10, help="Number of cases to test")
    parser.add_argument("--compile-only", action="store_true", help="Skip verifier loading")
    args = parser.parse_args()

    run_pilot(limit=args.limit, compile_only=args.compile_only)
