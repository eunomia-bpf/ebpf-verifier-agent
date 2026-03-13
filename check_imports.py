#!/usr/bin/env python3
"""Check for import errors in all test files."""
import sys
import os
import importlib
import traceback

os.chdir("/home/yunwei37/workspace/ebpf-verifier-agent")
sys.path.insert(0, "/home/yunwei37/workspace/ebpf-verifier-agent")

test_files = [
    "tests.test_abstract_domain",
    "tests.test_api",
    "tests.test_batch_correctness",
    "tests.test_bpftool_parser",
    "tests.test_diagnoser",
    "tests.test_diagnostic_schema",
    "tests.test_llm_comparison",
    "tests.test_log_parser",
    "tests.test_proof_analysis",
    "tests.test_proof_engine",
    "tests.test_renderer",
    "tests.test_source_correlator",
    "tests.test_trace_parser",
    "tests.test_value_lineage",
    "tests.test_verifier_oracle",
]

errors = []
for module_name in test_files:
    try:
        importlib.import_module(module_name)
        print(f"OK: {module_name}")
    except Exception as e:
        print(f"ERROR: {module_name}: {type(e).__name__}: {e}")
        traceback.print_exc()
        errors.append((module_name, str(e)))

print(f"\n{'='*50}")
print(f"Total errors: {len(errors)}")
for name, err in errors:
    print(f"  {name}: {err}")
