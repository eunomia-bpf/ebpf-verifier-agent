#!/usr/bin/env python3
"""Tests for tools/verifier_oracle.py.

These tests run in two tiers:
  1. Compile-only tests — no root needed; fast; always run.
  2. Full verifier tests — require sudo bpftool; skipped if unavailable.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.verifier_oracle import (
    CLANG_FLAGS_UAPI,
    OracleResult,
    _compile,
    _inject_sec_and_license,
    detect_prog_type,
    verify_case,
    verify_fix,
)


# ── fixtures ──────────────────────────────────────────────────────────────────

GOOD_XDP = """\
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_pass(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    char *p = data;
    if ((void *)(p + 1) > data_end)
        return XDP_DROP;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""

# Buggy: accesses beyond packet bounds without a bounds check
BAD_XDP_OOB = """\
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_buggy(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    /* no bounds check — verifier must reject */
    __u16 proto = eth->h_proto;
    return proto ? XDP_PASS : XDP_DROP;
}

char _license[] SEC("license") = "GPL";
"""

# Syntax error — should fail compile
BAD_SYNTAX = """\
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_broken(struct xdp_md *ctx) {
    return XDP_PASS
    /* missing semicolon above */
}

char _license[] SEC("license") = "GPL";
"""

# Incomplete snippet (no includes, no license) — should be auto-wrapped
SNIPPET_XDP_GOOD = """\
SEC("xdp")
int xdp_pass(struct xdp_md *ctx) {
    return XDP_PASS;
}
"""

# Full program sourced from SO case (stackoverflow-70091221 fixed version)
FIXED_70091221 = """\
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

struct bpf_map_def SEC("maps") EVENTS = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u32),
    .max_entries = 1,
};

SEC("xdp")
int _xdp_ip_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if (eth + 1 > data_end) {
        return XDP_PASS;
    }

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (iph + 1 > data_end) {
        return XDP_PASS;
    }

    __u32 ip_src = iph->saddr;
    __u32 key = 0;
    bpf_map_update_elem(&EVENTS, &key, &ip_src, BPF_ANY);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""

BUGGY_70091221 = """\
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

struct bpf_map_def EVENTS = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u32),
    .max_entries = 1,
};

SEC("xdp")
int _xdp_ip_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if (eth + 1 > data_end) {
        return XDP_PASS;
    }

    __u32 key = 0;
    /* Buggy: passes &key (map_value pointer) instead of &EVENTS (map pointer) */
    bpf_map_update_elem(&key, &key, &key, BPF_ANY);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""

# ── SEC injection fixtures ─────────────────────────────────────────────────────

# LLM-generated: function present but no SEC() annotation and no license
SNIPPET_NO_SEC_NO_LICENSE = """\
int prog(struct xdp_md *ctx) {
    return 0;
}
"""

# LLM-generated: has includes, has function, but missing SEC() and license
LLM_WITH_INCLUDES_NO_SEC = """\
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int xdp_prog(struct xdp_md *ctx) {
    return XDP_PASS;
}
"""

# LLM-generated: has includes AND SEC() but missing license variable
LLM_WITH_SEC_NO_LICENSE = """\
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    return XDP_PASS;
}
"""

# Complete program — injection should leave it unchanged
COMPLETE_XDP = """\
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""

# A non-BPF function (plain int/void, not BPF context type) — must not get SEC injected
PLAIN_C_FUNC = """\
static int helper(int x) {
    return x + 1;
}
"""


def _sudo_bpftool_available() -> bool:
    """Return True if sudo bpftool is available for verifier testing."""
    try:
        r = subprocess.run(
            ["sudo", "-n", "bpftool", "version"],
            capture_output=True,
            timeout=5,
        )
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _clang_available() -> bool:
    """Return True if clang is available for BPF compilation."""
    try:
        r = subprocess.run(
            ["clang", "--version"],
            capture_output=True,
            timeout=5,
        )
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _vmlinux_h_available() -> bool:
    """Return True if vmlinux.h is available for BPF compilation with clang -target bpf."""
    import tempfile, os
    if not _clang_available():
        return False
    src = '#include <vmlinux.h>\n#include <bpf/bpf_helpers.h>\n'
    with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
        f.write(src)
        fname = f.name
    try:
        r = subprocess.run(
            ['clang', '-target', 'bpf', '-O2', '-I/usr/include', '-c', fname, '-o', '/dev/null'],
            capture_output=True, timeout=10,
        )
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    finally:
        try:
            os.unlink(fname)
        except OSError:
            pass


def _uapi_headers_available() -> bool:
    """Return True if the oracle's UAPI compile path is usable on this host."""
    import tempfile
    if not _clang_available():
        return False
    src = """\
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int prog(struct xdp_md *ctx) {
    struct ethhdr *eth = (void *)(long)ctx->data;
    return eth ? XDP_PASS : XDP_ABORTED;
}

char _license[] SEC("license") = "GPL";
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "uapi-check.o"
        ok, _stderr = _compile(src, str(out), CLANG_FLAGS_UAPI)
        return ok


def _legacy_map_defs_blocked(result: OracleResult) -> bool:
    log = (result.verifier_log or "").lower()
    return "legacy map definitions" in log and "not supported" in log


HAS_SUDO_BPFTOOL = _sudo_bpftool_available()
HAS_CLANG = _clang_available()
HAS_VMLINUX_H = _vmlinux_h_available()
HAS_UAPI_HEADERS = _uapi_headers_available()

requires_verifier = pytest.mark.skipif(
    not HAS_SUDO_BPFTOOL,
    reason="sudo bpftool not available — skipping full verifier tests",
)
requires_clang = pytest.mark.skipif(
    not HAS_CLANG,
    reason="clang not available — skipping compile tests",
)
requires_vmlinux = pytest.mark.skipif(
    not HAS_VMLINUX_H,
    reason="vmlinux.h not available — skipping vmlinux-based compile tests",
)
requires_uapi = pytest.mark.skipif(
    not HAS_UAPI_HEADERS,
    reason="Linux UAPI kernel headers not available — skipping uapi-based compile tests",
)


# ── unit tests: detect_prog_type ──────────────────────────────────────────────

class TestDetectProgType:
    def test_xdp_from_source(self):
        assert detect_prog_type('SEC("xdp") int prog') == "xdp"

    def test_tc_from_source(self):
        assert detect_prog_type('SEC("tc") int prog') == "tc"

    def test_kprobe_from_log(self):
        assert detect_prog_type("", "kprobe/sys_open") == "kprobe"

    def test_default_xdp(self):
        assert detect_prog_type("int prog(void) { return 0; }") == "xdp"


# ── unit tests: _inject_sec_and_license ──────────────────────────────────────

class TestInjectSecAndLicense:
    """Tests for the _inject_sec_and_license helper (pure-Python, no clang needed)."""

    def test_injects_sec_before_bpf_func(self):
        result = _inject_sec_and_license(SNIPPET_NO_SEC_NO_LICENSE, "xdp")
        assert 'SEC("xdp")' in result
        # SEC must appear before the function definition
        sec_idx = result.index('SEC("xdp")')
        func_idx = result.index("int prog(")
        assert sec_idx < func_idx

    def test_injects_license_when_missing(self):
        result = _inject_sec_and_license(SNIPPET_NO_SEC_NO_LICENSE, "xdp")
        assert 'SEC("license")' in result

    def test_does_not_double_inject_sec(self):
        """If SEC is already present, it must not be added again."""
        result = _inject_sec_and_license(COMPLETE_XDP, "xdp")
        assert result.count('SEC("xdp")') == 1

    def test_does_not_double_inject_license(self):
        """If license is already present, it must not be added again."""
        result = _inject_sec_and_license(COMPLETE_XDP, "xdp")
        assert result.count('SEC("license")') == 1

    def test_idempotent_on_complete_program(self):
        """Injecting into a complete program changes nothing."""
        result = _inject_sec_and_license(COMPLETE_XDP, "xdp")
        assert result == COMPLETE_XDP

    def test_injects_correct_prog_type_tc(self):
        src = 'int tc_prog(struct __sk_buff *skb) { return 0; }\n'
        result = _inject_sec_and_license(src, "tc")
        assert 'SEC("tc")' in result

    def test_does_not_inject_sec_on_plain_helper(self):
        """A plain non-BPF function (no BPF context type) should NOT get SEC injected."""
        result = _inject_sec_and_license(PLAIN_C_FUNC, "xdp")
        assert "SEC" not in result or 'SEC("license")' in result
        # The function itself must not have a SEC line before it
        lines = result.splitlines()
        for i, ln in enumerate(lines):
            if "int helper(" in ln:
                if i > 0:
                    assert "SEC" not in lines[i - 1]

    def test_llm_output_with_includes_no_sec(self):
        """Simulate typical LLM output: includes but no SEC / license."""
        result = _inject_sec_and_license(LLM_WITH_INCLUDES_NO_SEC, "xdp")
        assert 'SEC("xdp")' in result
        assert 'SEC("license")' in result

    def test_llm_output_with_sec_no_license(self):
        """Simulate LLM output that has SEC but forgot license."""
        result = _inject_sec_and_license(LLM_WITH_SEC_NO_LICENSE, "xdp")
        assert 'SEC("xdp")' in result  # still present
        assert 'SEC("license")' in result  # now added

    def test_preserves_existing_sec_annotation(self):
        """If the code already has SEC("xdp"), it should not add another."""
        src = 'SEC("xdp")\nint prog(struct xdp_md *ctx) { return 0; }\n'
        result = _inject_sec_and_license(src, "xdp")
        assert result.count('SEC("xdp")') == 1


# ── compile-only tests ────────────────────────────────────────────────────────

class TestCompileOnly:
    @requires_clang
    def test_good_program_compiles(self):
        result = verify_fix(GOOD_XDP, compile_only=True)
        assert result.compiles is True
        assert result.verifier_pass is None  # not checked in compile-only mode
        assert result.error is None

    def test_syntax_error_fails_compile(self):
        result = verify_fix(BAD_SYNTAX, compile_only=True)
        assert result.compiles is False
        assert result.verifier_pass is None
        assert result.error is not None

    @requires_clang
    def test_good_snippet_compiles(self):
        result = verify_fix(SNIPPET_XDP_GOOD, compile_only=True)
        assert result.compiles is True
        assert result.was_wrapped is True  # snippet was auto-wrapped

    def test_empty_source_fails(self):
        result = verify_fix("", compile_only=True)
        assert result.compiles is False
        assert result.error is not None

    @requires_clang
    def test_result_to_dict(self):
        result = verify_fix(GOOD_XDP, compile_only=True)
        d = result.to_dict()
        assert "compiles" in d
        assert "verifier_pass" in d
        assert "error" in d

    @requires_uapi
    def test_fixed_so_case_compiles(self):
        result = verify_fix(FIXED_70091221, compile_only=True)
        assert result.compiles is True

    @requires_uapi
    def test_uapi_flags_handle_kernel_bool_headers(self, tmp_path):
        src = """\
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int prog(struct xdp_md *ctx) {
    struct ethhdr *eth = (void *)(long)ctx->data;
    return eth ? XDP_PASS : XDP_ABORTED;
}

char _license[] SEC("license") = "GPL";
"""
        out_obj = tmp_path / "uapi-headers.o"
        ok, stderr = _compile(src, str(out_obj), CLANG_FLAGS_UAPI)
        assert ok is True, stderr

    @requires_clang
    def test_template_label_set(self):
        result = verify_fix(GOOD_XDP, compile_only=True)
        assert result.template_used is not None


# ── compile-only SEC injection integration tests ──────────────────────────────

class TestSecInjectionCompile:
    """Integration tests: SEC injection + compilation (no kernel needed)."""

    @requires_clang
    def test_no_sec_snippet_compiles(self):
        """A bare function with BPF context type should auto-get SEC() and compile."""
        result = verify_fix(SNIPPET_NO_SEC_NO_LICENSE, prog_type="xdp", compile_only=True)
        assert result.compiles is True

    @requires_uapi
    def test_llm_includes_no_sec_compiles(self):
        """LLM output with includes but no SEC() should be injected and compile."""
        result = verify_fix(LLM_WITH_INCLUDES_NO_SEC, prog_type="xdp", compile_only=True)
        assert result.compiles is True

    @requires_clang
    def test_llm_includes_with_sec_no_license_compiles(self):
        """LLM output with includes + SEC but no license should compile."""
        result = verify_fix(LLM_WITH_SEC_NO_LICENSE, prog_type="xdp", compile_only=True)
        assert result.compiles is True


# ── full verifier tests ───────────────────────────────────────────────────────

class TestFullVerifier:
    @requires_verifier
    def test_good_program_passes_verifier(self):
        result = verify_fix(GOOD_XDP)
        assert result.compiles is True
        assert result.verifier_pass is True
        assert result.error is None
        assert result.verifier_log is not None

    @requires_verifier
    def test_oob_program_rejected_by_verifier(self):
        result = verify_fix(BAD_XDP_OOB)
        assert result.compiles is True
        assert result.verifier_pass is False
        assert result.error is not None
        assert result.verifier_log is not None

    @requires_verifier
    def test_verifier_log_contains_error(self):
        result = verify_fix(BAD_XDP_OOB)
        assert result.verifier_log is not None
        # The verifier log should mention the invalid access
        log = result.verifier_log.lower()
        assert any(kw in log for kw in ["invalid", "rejected", "failed", "error"])

    @requires_verifier
    @requires_uapi
    def test_fixed_so_case_passes_verifier(self):
        """Fixed version of SO case 70091221 should pass."""
        result = verify_fix(FIXED_70091221)
        assert result.compiles is True
        if _legacy_map_defs_blocked(result):
            pytest.skip("libbpf v1.0+ rejects legacy map definitions during load")
        assert result.verifier_pass is True

    @requires_verifier
    def test_snippet_passes_verifier(self):
        """Simple snippet wrapped in template should pass."""
        result = verify_fix(SNIPPET_XDP_GOOD)
        assert result.compiles is True
        assert result.verifier_pass is True

    @requires_verifier
    def test_syntax_error_gives_no_verifier_result(self):
        result = verify_fix(BAD_SYNTAX)
        assert result.compiles is False
        assert result.verifier_pass is None

    @requires_verifier
    def test_no_sec_bare_snippet_passes_verifier(self):
        """A bare function without SEC() should get auto-injected and pass verifier."""
        result = verify_fix(SNIPPET_NO_SEC_NO_LICENSE, prog_type="xdp")
        assert result.compiles is True
        assert result.verifier_pass is True

    @requires_verifier
    @requires_uapi
    def test_llm_with_includes_no_sec_passes_verifier(self):
        """LLM output with includes but no SEC() should be injected and pass verifier."""
        result = verify_fix(LLM_WITH_INCLUDES_NO_SEC, prog_type="xdp")
        assert result.compiles is True
        assert result.verifier_pass is True


# ── verify_case API ───────────────────────────────────────────────────────────

class TestVerifyCase:
    def test_no_source_code(self):
        result = verify_case({})
        assert result.compiles is False
        assert "No source code" in (result.error or "")

    @requires_clang
    def test_case_with_source_code_field(self):
        case = {"source_code": GOOD_XDP, "case_id": "test-001"}
        result = verify_case(case, compile_only=True)
        assert result.compiles is True

    @requires_clang
    def test_case_with_snippets_sorted_by_length(self):
        """The longest snippet should be tried first (more likely complete)."""
        snippets = [
            'SEC("xdp") int f(struct xdp_md *ctx) { return XDP_PASS; }',  # short, incomplete
            GOOD_XDP,  # long, complete
        ]
        case = {"source_snippets": snippets, "case_id": "test-002"}
        result = verify_case(case, compile_only=True)
        assert result.compiles is True

    @requires_verifier
    def test_real_yaml_case(self, tmp_path):
        """Smoke test: load a real YAML case and verify."""
        import yaml
        # Use the stackoverflow-70091221 case
        yaml_path = ROOT / "bpfix-bench" / "raw" / "so" / "stackoverflow-70091221.yaml"
        if not yaml_path.exists():
            pytest.skip("Case YAML not found")
        with open(yaml_path, "r", encoding="utf-8") as f:
            case_data = yaml.safe_load(f)
        # The original SO snippet is buggy (missing SEC("maps") on the map).
        # We just check that the oracle runs without crashing.
        raw_case = case_data.get("raw", case_data)
        result = verify_case(raw_case)
        assert isinstance(result, OracleResult)
        assert result.compiles in (True, False)  # either is OK


# ── integration: known pass/fail pairs ───────────────────────────────────────

class TestKnownPairsPF:
    """Known pass/fail pairs: fix passes, buggy version fails."""

    @requires_verifier
    def test_fixed_passes_buggy_fails(self):
        good = verify_fix(GOOD_XDP)
        bad = verify_fix(BAD_XDP_OOB)
        assert good.verifier_pass is True
        assert bad.verifier_pass is False

    @requires_verifier
    @requires_uapi
    def test_so70091221_fix_passes(self):
        result = verify_fix(FIXED_70091221)
        if _legacy_map_defs_blocked(result):
            pytest.skip("libbpf v1.0+ rejects legacy map definitions during load")
        assert result.verifier_pass is True

    @requires_verifier
    def test_oob_gives_useful_verifier_log(self):
        result = verify_fix(BAD_XDP_OOB)
        assert result.verifier_log is not None
        assert len(result.verifier_log) > 50


if __name__ == "__main__":
    # Quick smoke test when run directly
    import json
    print("=== Compile-only test: good XDP ===")
    r = verify_fix(GOOD_XDP, compile_only=True)
    print(json.dumps(r.to_dict(), indent=2))

    if HAS_SUDO_BPFTOOL:
        print("\n=== Full verifier test: good XDP ===")
        r = verify_fix(GOOD_XDP)
        print(json.dumps(r.to_dict(), indent=2))

        print("\n=== Full verifier test: buggy XDP (OOB) ===")
        r = verify_fix(BAD_XDP_OOB)
        print(json.dumps(r.to_dict(), indent=2))
    else:
        print("\n[sudo bpftool not available — skipping full verifier tests]")
