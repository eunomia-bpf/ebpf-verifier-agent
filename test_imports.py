#!/usr/bin/env python3
"""Quick import check for all test-related modules."""
import sys
import os
import traceback

os.chdir("/home/yunwei37/workspace/ebpf-verifier-agent")
sys.path.insert(0, "/home/yunwei37/workspace/ebpf-verifier-agent")

modules_to_check = [
    # Interface modules
    "interface.extractor.abstract_domain",
    "interface.extractor.value_lineage",
    "interface.extractor.trace_parser",
    "interface.extractor.log_parser",
    "interface.extractor.diagnoser",
    "interface.extractor.proof_analysis",
    "interface.extractor.proof_engine",
    "interface.extractor.rust_diagnostic",
    "interface.extractor.renderer",
    "interface.extractor.source_correlator",
    "interface.extractor.bpftool_parser",
    "interface.extractor.obligation_inference",
    "interface.extractor.obligation_catalog_formal",
    "interface.api",
    # Eval modules
    "eval.llm_comparison",
    "eval.verifier_oracle",
]

errors = []
ok = []

for mod in modules_to_check:
    try:
        __import__(mod)
        ok.append(mod)
        print(f"OK: {mod}")
    except Exception as e:
        errors.append((mod, type(e).__name__, str(e)))
        print(f"ERROR: {mod}: {type(e).__name__}: {e}")
        traceback.print_exc()
        print()

print(f"\nOK: {len(ok)}, ERRORS: {len(errors)}")
sys.exit(len(errors))
