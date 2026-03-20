from __future__ import annotations

from pathlib import Path

import yaml

from scripts.compile_cilium_eval_commits import (
    classify_load_status,
    extract_declared_file,
    extract_make_compile_flags,
    select_top_cilium_candidates,
)


def test_extract_declared_file() -> None:
    snippet = """// FILE: bpf/lib/nat.h
// CONTEXT: struct nat_entry {
static int demo(void) { return 0; }
"""
    assert extract_declared_file(snippet) == "bpf/lib/nat.h"


def test_extract_make_compile_flags_keeps_defines_and_normalizes_includes(tmp_path: Path) -> None:
    compile_dir = tmp_path / "bpf"
    compile_dir.mkdir()
    output = """
make: Entering directory '/tmp/example/bpf'
clang -DENABLE_IPV4 -D__NR_CPUS__=24 -I../include -I /abs/include -include local.h -c bpf_lxc.c -o bpf_lxc.ll
make: Leaving directory '/tmp/example/bpf'
"""
    assert extract_make_compile_flags(output, compile_dir) == [
        "-DENABLE_IPV4",
        "-D__NR_CPUS__=24",
        f"-I{(compile_dir / '../include').resolve()}",
        "-I",
        "/abs/include",
        "-include",
        str((compile_dir / "local.h").resolve()),
    ]


def test_select_top_cilium_candidates_orders_by_score_then_case_id(tmp_path: Path) -> None:
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    payloads = [
        {
            "case_id": "eval-cilium-b-case",
            "repository": "https://github.com/cilium/cilium",
            "commit_hash": "1" * 40,
            "commit_message": "plain change",
            "buggy_code": "int x = 1;",
        },
        {
            "case_id": "eval-cilium-a-case",
            "repository": "https://github.com/cilium/cilium",
            "commit_hash": "2" * 40,
            "commit_message": "fix obscure llvm bounds issue",
            "fix_type": "inline_hint",
            "buggy_code": "#include <linux/bpf.h>\nSEC(\"xdp\") int x(struct xdp_md *ctx) { return 0; }",
        },
        {
            "case_id": "eval-cilium-c-case",
            "repository": "https://github.com/cilium/cilium",
            "commit_hash": "3" * 40,
            "commit_message": "fix obscure llvm bounds issue",
            "fix_type": "inline_hint",
            "buggy_code": "#include <linux/bpf.h>\nSEC(\"xdp\") int x(struct xdp_md *ctx) { return 0; }",
        },
    ]
    for payload in payloads:
        path = cases_dir / f"{payload['case_id']}.yaml"
        path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

    selected = select_top_cilium_candidates(cases_dir, limit=2)
    assert [candidate.case_id for candidate in selected] == [
        "eval-cilium-a-case",
        "eval-cilium-c-case",
    ]


def test_classify_load_status_distinguishes_rejects_and_loader_errors() -> None:
    assert classify_load_status(0, "") == "loaded"
    assert classify_load_status(1, "invalid access to packet, off=64 size=4") == "verifier_reject"
    assert classify_load_status(1, "libbpf: failed to load object file") == "loader_error"
