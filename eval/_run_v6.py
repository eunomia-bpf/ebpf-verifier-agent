#!/usr/bin/env python3
"""Run batch diagnostic eval v6 and write comparison report."""
import subprocess
import sys
import os

os.chdir('/home/yunwei37/workspace/ebpf-verifier-agent')
sys.path.insert(0, '/home/yunwei37/workspace/ebpf-verifier-agent')

# Run the batch eval directly
import importlib.util
spec = importlib.util.spec_from_file_location(
    "batch_diagnostic_eval",
    "/home/yunwei37/workspace/ebpf-verifier-agent/eval/batch_diagnostic_eval.py"
)
mod = importlib.util.module_from_spec(spec)

import argparse
import sys as _sys

# Override sys.argv
_sys.argv = [
    'batch_diagnostic_eval.py',
    '--results-path', 'eval/results/batch_diagnostic_results_v6.json',
    '--report-path', 'docs/tmp/batch-diagnostic-eval-v6.md',
]

spec.loader.exec_module(mod)
result = mod.main()
print(f"Done, exit code: {result}")
