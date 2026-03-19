#!/usr/bin/env python3
"""
Verifier-pass oracle for eBPF programs.

Takes LLM-generated (or original) C code, compiles it with clang targeting BPF,
loads it into the kernel via bpftool, and reports whether the eBPF verifier accepts
or rejects the program.

Approach:
  1. Compile-only (clang -target bpf): catches syntax/type errors; fast, no privileges needed
  2. Verifier-load (sudo bpftool prog load): runs the actual kernel verifier; definitive
     pass/fail; requires sudo (available on this machine).

Design notes:
  - Source snippets from SO/GitHub are typically INCOMPLETE. We wrap them in a minimal
    template (includes + SEC() + license) keyed on program type.
  - We use /usr/include/vmlinux.h (system vmlinux.h from BTF) for a self-contained
    include that does not require kernel build headers.
  - Multiple template variants are tried in order; the first that compiles wins.
  - BPF programs are pinned to /sys/fs/bpf/bpfix_<pid>_<n> and cleaned up immediately
    after loading.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ── compile flags ──────────────────────────────────────────────────────────────
KVER = subprocess.run(
    ["uname", "-r"], capture_output=True, text=True, check=False
).stdout.strip()

# Primary: use system vmlinux.h (generated from kernel BTF — works on this machine)
CLANG_FLAGS_VMLINUX = [
    "clang",
    "-target", "bpf",
    "-O2",
    "-g",
    "-Wall",
    "-Wno-unused-value",
    "-Wno-pointer-sign",
    "-Wno-compare-distinct-pointer-types",
    "-Wno-address-of-packed-member",
    "-Wno-gnu-variable-sized-type-not-at-end",
    "-Wno-tautological-compare",
    "-I/usr/include",
]

# Fallback: use uapi kernel headers
CLANG_FLAGS_UAPI = [
    "clang",
    "-target", "bpf",
    "-O2",
    "-g",
    "-Wall",
    "-Wno-unused-value",
    "-Wno-pointer-sign",
    "-Wno-compare-distinct-pointer-types",
    "-Wno-address-of-packed-member",
    "-Wno-tautological-compare",
    f"-I/usr/src/linux-headers-{KVER}/include/uapi",
    f"-I/usr/src/linux-headers-{KVER}/arch/x86/include/generated/uapi",
    f"-I/usr/src/linux-headers-{KVER}/arch/x86/include/uapi",
    f"-I/usr/src/linux-headers-{KVER}/include",
    "-I/usr/include",
]

COMPILE_TIMEOUT = 30   # seconds
LOAD_TIMEOUT = 15      # seconds
BPF_PIN_DIR = "/sys/fs/bpf"

# ── code templates ─────────────────────────────────────────────────────────────
# Each template is tried in order. The first that compiles is used.
# {CODE} is replaced with the source snippet / full program.
# We also provide variants with different include styles.

TEMPLATE_VMLINUX_HEADER = """\
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
"""

TEMPLATE_UAPI_HEADER = """\
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
"""

LICENSE_FOOTER = '\nchar _license[] SEC("license") = "GPL";\n'

# Detect already-complete programs (have their own includes / license)
HAS_INCLUDE_RE = re.compile(r"^\s*#\s*include\s*[<\"]", re.MULTILINE)
HAS_LICENSE_RE = re.compile(r'SEC\s*\(\s*["\']license["\']\s*\)', re.IGNORECASE)
HAS_SEC_RE = re.compile(r'\bSEC\s*\(\s*["\']', re.IGNORECASE)

# Detect BPF program function signatures that may need SEC() injection.
# Matches "int <name>(<context_type> *<param>, ...)" at top level.
# We look for common BPF context types as a heuristic.
_BPF_CONTEXT_TYPES = (
    "xdp_md",
    "__sk_buff",
    "sk_buff",
    "bpf_sock_ops",
    "bpf_sock_addr",
    "bpf_sock",
    "pt_regs",
    "bpf_perf_event_data",
    "bpf_raw_tracepoint_args",
    "bpf_iter__",
    "bpf_fentry",
    "bpf_fexit",
)
# Regex: "int <name>(" where the function body starts with a BPF context type
# We allow optional attributes / qualifiers before "int".
_BPF_FUNC_RE = re.compile(
    r"^(?:static\s+)?int\s+(\w+)\s*\(\s*(?:struct\s+)?(?:"
    + "|".join(re.escape(t) for t in _BPF_CONTEXT_TYPES)
    + r")",
    re.MULTILINE,
)
# A SEC() annotation on the line immediately before a function definition
_SEC_BEFORE_FUNC_RE = re.compile(r'SEC\s*\(\s*["\'][^"\']*["\']\s*\)\s*$')

# Program-type detection from verifier log / source
PROG_TYPE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'\bxdp\b', re.IGNORECASE), "xdp"),
    (re.compile(r'\bsk_skb\b', re.IGNORECASE), "sk_skb"),
    (re.compile(r'\bsock_ops\b', re.IGNORECASE), "sk_ops"),
    (re.compile(r'\braw_tp\b|\braw_tracepoint\b', re.IGNORECASE), "raw_tp"),
    (re.compile(r'\btracepoint\b', re.IGNORECASE), "tp"),
    (re.compile(r'\bkprobe\b', re.IGNORECASE), "kprobe"),
    (re.compile(r'\bkretprobe\b', re.IGNORECASE), "kretprobe"),
    (re.compile(r'\bperf_event\b', re.IGNORECASE), "perf_event"),
    (re.compile(r'\bsched_cls\b|\btc\b', re.IGNORECASE), "tc"),
    (re.compile(r'\bcgroup\b', re.IGNORECASE), "cgroup_skb/ingress"),
    (re.compile(r'\bsocket_filter\b|\bsk_filter\b', re.IGNORECASE), "socket"),
    (re.compile(r'\blwt\b', re.IGNORECASE), "lwt_in"),
    (re.compile(r'\bflow_dissector\b', re.IGNORECASE), "flow_dissector"),
    (re.compile(r'\biter\b', re.IGNORECASE), "iter/task"),
    (re.compile(r'\bfentry\b', re.IGNORECASE), "fentry"),
    (re.compile(r'\bfexit\b', re.IGNORECASE), "fexit"),
    (re.compile(r'\blsm\b', re.IGNORECASE), "lsm"),
]


@dataclass
class OracleResult:
    """Outcome of compiling and/or verifier-loading an eBPF program."""

    compiles: bool
    """True if clang successfully compiled the program to a BPF ELF."""

    verifier_pass: bool | None
    """True if the kernel verifier accepted the program.
    None if the verifier could not be reached (e.g., compilation failed)."""

    error: str | None
    """Human-readable error description, or None on full success."""

    compile_stderr: str | None = None
    """Raw stderr from clang."""

    verifier_log: str | None = None
    """Verifier output (bpftool -d stderr), whether pass or fail."""

    template_used: str | None = None
    """Which template variant succeeded."""

    include_flags_used: list[str] = field(default_factory=list)
    """Which -I flags were used during compilation."""

    was_wrapped: bool = False
    """True if source was wrapped in a template (incomplete snippet)."""

    compile_warnings: list[str] = field(default_factory=list)
    """Non-fatal compiler warnings."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "compiles": self.compiles,
            "verifier_pass": self.verifier_pass,
            "error": self.error,
            "compile_stderr": self.compile_stderr,
            "verifier_log": self.verifier_log,
            "template_used": self.template_used,
            "include_flags_used": self.include_flags_used,
            "was_wrapped": self.was_wrapped,
            "compile_warnings": self.compile_warnings,
        }


# ── threading lock for pin-path uniqueness ────────────────────────────────────
_pin_counter_lock = threading.Lock()
_pin_counter = 0


def _unique_pin_path() -> str:
    global _pin_counter
    with _pin_counter_lock:
        _pin_counter += 1
        n = _pin_counter
    pid = os.getpid()
    return f"{BPF_PIN_DIR}/bpfix_{pid}_{n}_{uuid.uuid4().hex[:6]}"


# ── source preparation ────────────────────────────────────────────────────────

def detect_prog_type(source_code: str, verifier_log: str = "") -> str:
    """Guess the BPF program type from source code or verifier log."""
    combined = (source_code or "") + "\n" + (verifier_log or "")
    for pat, ptype in PROG_TYPE_PATTERNS:
        if pat.search(combined):
            return ptype
    return "xdp"  # safe default — XDP is widely supported


def _inject_sec_and_license(source_code: str, prog_type: str) -> str:
    """
    Robustly inject SEC() annotations and/or a license variable into source_code
    when they are absent, so that bpftool can find and load the BPF program.

    Handles:
    - Functions with BPF context types but no SEC() annotation before them.
    - Missing ``char _license[] SEC("license") = "GPL";`` footer.

    The injections are idempotent: if annotations already exist they are left as-is.
    """
    lines = source_code.splitlines(keepends=True)

    # ── 1. Inject SEC() before BPF function definitions that lack one ──────────
    # We scan line-by-line so we can look at the preceding non-blank, non-comment
    # line to decide whether a SEC() is already present.
    new_lines: list[str] = []
    for i, line in enumerate(lines):
        # Check if this line starts a BPF-like function definition
        stripped = line.strip()
        if _BPF_FUNC_RE.match(stripped):
            # Walk backwards through already-appended output to find the last
            # meaningful line (non-blank, non-comment).
            prev_meaningful = ""
            for prev in reversed(new_lines):
                ps = prev.strip()
                if ps and not ps.startswith("//") and not ps.startswith("*") and not ps.startswith("/*"):
                    prev_meaningful = ps
                    break
            # If the preceding meaningful line is not a SEC() annotation, inject one.
            if not _SEC_BEFORE_FUNC_RE.search(prev_meaningful):
                # Preserve the indentation of the current line (usually none at top level)
                indent = line[: len(line) - len(line.lstrip())]
                new_lines.append(f'{indent}SEC("{prog_type}")\n')
        new_lines.append(line)

    result = "".join(new_lines)

    # ── 2. Inject license footer if missing ────────────────────────────────────
    if not HAS_LICENSE_RE.search(result):
        # Check for common non-GPL-style license declarations too (e.g. a plain
        # char _license[] = "GPL"; without SEC) — rare but possible.
        plain_license_re = re.compile(r'_license\s*\[\s*\]', re.IGNORECASE)
        if not plain_license_re.search(result):
            if not result.endswith("\n"):
                result += "\n"
            result += 'char _license[] SEC("license") = "GPL";\n'

    return result


def _is_complete_program(source_code: str) -> bool:
    """Return True if the source looks like a complete, standalone BPF program."""
    has_include = bool(HAS_INCLUDE_RE.search(source_code))
    has_license = bool(HAS_LICENSE_RE.search(source_code))
    has_sec = bool(HAS_SEC_RE.search(source_code))
    return has_include and (has_license or has_sec)


def _make_candidates(source_code: str, prog_type: str) -> list[tuple[str, str, list[str], bool]]:
    """
    Build (label, source, include_flags, was_wrapped) candidates to try.

    If the source is already complete (has includes + SEC), we try it as-is first.
    We then also try a SEC/license-injected variant in case the LLM produced code
    with includes but without a SEC() annotation (bpftool would say "no BPF programs").
    Finally, wrapped variants are added as fallback for bare snippets.
    """
    candidates: list[tuple[str, str, list[str], bool]] = []

    is_complete = _is_complete_program(source_code)

    if is_complete:
        # Try raw source with both include sets
        candidates.append(("raw-vmlinux", source_code, CLANG_FLAGS_VMLINUX, False))
        candidates.append(("raw-uapi", source_code, CLANG_FLAGS_UAPI, False))

        # Also try with SEC() / license injected — handles LLM outputs that have
        # includes but forgot the SEC() annotation or license variable.
        injected = _inject_sec_and_license(source_code, prog_type)
        if injected != source_code:
            candidates.append(("raw-injected-vmlinux", injected, CLANG_FLAGS_VMLINUX, False))
            candidates.append(("raw-injected-uapi", injected, CLANG_FLAGS_UAPI, False))

    # Always add wrapped variants as fallback.
    # Inject SEC() / license into the snippet before wrapping so that the wrapped
    # result is a valid BPF object with at least one SEC-annotated program.
    snippet = _inject_sec_and_license(source_code, prog_type)
    # The injector adds a license footer, so no separate needs_license check required.
    wrapped_vmlinux = TEMPLATE_VMLINUX_HEADER + "\n" + snippet
    wrapped_uapi = TEMPLATE_UAPI_HEADER + "\n" + snippet

    candidates.append(("wrap-vmlinux", wrapped_vmlinux, CLANG_FLAGS_VMLINUX, True))
    candidates.append(("wrap-uapi", wrapped_uapi, CLANG_FLAGS_UAPI, True))

    return candidates


# ── compilation ───────────────────────────────────────────────────────────────

def _compile(source_code: str, out_obj: str, flags: list[str]) -> tuple[bool, str]:
    """Compile source_code to out_obj. Return (success, stderr)."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".c", prefix="bpfix_", delete=False
    ) as tmp:
        tmp.write(source_code)
        src_path = tmp.name

    try:
        cmd = flags + ["-c", src_path, "-o", out_obj]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=COMPILE_TIMEOUT,
        )
        success = result.returncode == 0
        stderr = (result.stderr or "").strip()
        return success, stderr
    except subprocess.TimeoutExpired:
        return False, "clang timed out"
    except FileNotFoundError:
        return False, "clang not found"
    finally:
        try:
            os.unlink(src_path)
        except OSError:
            pass


# ── verifier loading ──────────────────────────────────────────────────────────

def _load_with_bpftool(obj_path: str) -> tuple[bool, str]:
    """
    Load a compiled BPF object into the kernel via bpftool.
    Returns (verifier_accepted, verifier_log_text).
    Cleans up the pin path immediately.
    """
    pin_path = _unique_pin_path()
    cmd = ["sudo", "bpftool", "-d", "prog", "load", obj_path, pin_path]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=LOAD_TIMEOUT,
        )
        # Combine stdout+stderr — bpftool -d writes verifier log to stderr
        log = (result.stderr or "").strip()
        accepted = result.returncode == 0
        return accepted, log
    except subprocess.TimeoutExpired:
        return False, "bpftool timed out"
    except FileNotFoundError:
        return False, "bpftool not found"
    finally:
        # Always clean up the pin, ignore errors (file may not exist if load failed)
        subprocess.run(
            ["sudo", "rm", "-f", pin_path],
            capture_output=True,
            timeout=5,
        )


def _extract_verifier_log_section(bpftool_stderr: str) -> str:
    """Extract the BEGIN/END PROG LOAD LOG section from bpftool -d output."""
    begin = "-- BEGIN PROG LOAD LOG --"
    end = "-- END PROG LOAD LOG --"
    start_idx = bpftool_stderr.find(begin)
    if start_idx == -1:
        # No structured log — return the full stderr (still useful)
        return bpftool_stderr
    end_idx = bpftool_stderr.find(end, start_idx)
    if end_idx == -1:
        return bpftool_stderr[start_idx:]
    return bpftool_stderr[start_idx: end_idx + len(end)]


# ── public API ────────────────────────────────────────────────────────────────

def verify_fix(
    source_code: str,
    prog_type: str | None = None,
    verifier_log_hint: str = "",
    compile_only: bool = False,
) -> OracleResult:
    """
    Compile and/or verify an eBPF program fix.

    Args:
        source_code: C source code (complete program or snippet).
        prog_type: BPF program type hint (e.g., "xdp", "tc", "kprobe").
                   Auto-detected from source+verifier_log_hint if None.
        verifier_log_hint: Original verifier log from the case, used for prog_type detection.
        compile_only: If True, skip bpftool loading (faster, but no verifier result).

    Returns:
        OracleResult with compiles/verifier_pass/error/verifier_log.
    """
    if not source_code or not source_code.strip():
        return OracleResult(
            compiles=False,
            verifier_pass=None,
            error="Empty source code",
        )

    if prog_type is None:
        prog_type = detect_prog_type(source_code, verifier_log_hint)

    candidates = _make_candidates(source_code, prog_type)

    with tempfile.TemporaryDirectory(prefix="bpfix_oracle_") as tmpdir:
        for label, candidate_src, flags, was_wrapped in candidates:
            obj_path = str(Path(tmpdir) / f"prog_{label}.o")
            success, stderr = _compile(candidate_src, obj_path, flags)

            if not success:
                # Try next candidate
                continue

            # Compilation succeeded
            warnings = [
                line for line in stderr.splitlines()
                if "warning:" in line.lower() and "note:" not in line.lower()
            ]

            if compile_only:
                return OracleResult(
                    compiles=True,
                    verifier_pass=None,
                    error=None,
                    compile_stderr=stderr if stderr else None,
                    template_used=label,
                    include_flags_used=[f for f in flags if f.startswith("-I")],
                    was_wrapped=was_wrapped,
                    compile_warnings=warnings,
                )

            # Try loading into verifier
            accepted, bpftool_log = _load_with_bpftool(obj_path)
            verifier_section = _extract_verifier_log_section(bpftool_log)

            return OracleResult(
                compiles=True,
                verifier_pass=accepted,
                error=None if accepted else _extract_error_message(bpftool_log),
                compile_stderr=stderr if stderr else None,
                verifier_log=verifier_section,
                template_used=label,
                include_flags_used=[f for f in flags if f.startswith("-I")],
                was_wrapped=was_wrapped,
                compile_warnings=warnings,
            )

        # All candidates failed to compile
        # Return the error from the last attempt
        last_stderr = ""
        last_label = ""
        for label, candidate_src, flags, was_wrapped in candidates:
            obj_path = str(Path(tmpdir) / f"prog_last_{label}.o")
            ok, stderr = _compile(candidate_src, obj_path, flags)
            if not ok:
                last_stderr = stderr
                last_label = label

        return OracleResult(
            compiles=False,
            verifier_pass=None,
            error=f"Compilation failed ({last_label}): {_first_error_line(last_stderr)}",
            compile_stderr=last_stderr,
        )


def _extract_error_message(bpftool_log: str) -> str:
    """Extract a concise error message from bpftool output."""
    # Look for verifier error lines (not libbpf preamble)
    error_patterns = [
        re.compile(r"^(invalid .*|R\d+ .*|back-edge .*|too many .*|.*: unknown opcode.*)", re.MULTILINE),
        re.compile(r"^(processed \d+ insns.*)", re.MULTILINE),
    ]
    for pat in error_patterns:
        m = pat.search(bpftool_log)
        if m:
            return m.group(1).strip()
    # Fallback: first error-looking line
    for line in bpftool_log.splitlines():
        line = line.strip()
        if line and not line.startswith("libbpf:") and not line.startswith("--"):
            if "error" in line.lower() or "failed" in line.lower() or "invalid" in line.lower():
                return line
    return bpftool_log[:200].strip()


def _first_error_line(stderr: str) -> str:
    """Return the first meaningful error line from clang stderr."""
    for line in stderr.splitlines():
        if "error:" in line.lower():
            return line.strip()
    return (stderr[:200] or "unknown error").strip()


# ── batch API ─────────────────────────────────────────────────────────────────

def verify_case(case_data: dict[str, Any], compile_only: bool = False) -> OracleResult:
    """
    Verify an eBPF case loaded from a YAML case file.

    Tries source_snippets in order, falling back to source_code field.
    Returns the result of the first snippet that compiles.
    """
    # Extract source candidates from case
    sources: list[str] = []
    if isinstance(case_data.get("source_code"), str) and case_data["source_code"].strip():
        sources.append(case_data["source_code"])

    snippets = case_data.get("source_snippets") or []
    if isinstance(snippets, list):
        # Prefer longer snippets (more likely to be complete programs)
        sorted_snippets = sorted(
            [s for s in snippets if isinstance(s, str) and s.strip()],
            key=len,
            reverse=True,
        )
        sources.extend(sorted_snippets)

    if not sources:
        return OracleResult(
            compiles=False,
            verifier_pass=None,
            error="No source code found in case",
        )

    # Extract verifier log for prog_type detection
    vl = case_data.get("verifier_log", {})
    if isinstance(vl, dict):
        verifier_log_hint = vl.get("combined") or ""
    elif isinstance(vl, str):
        verifier_log_hint = vl
    else:
        verifier_log_hint = ""

    # Try each source
    last_result = None
    for src in sources:
        result = verify_fix(
            source_code=src,
            verifier_log_hint=verifier_log_hint,
            compile_only=compile_only,
        )
        if result.compiles:
            return result
        last_result = result

    return last_result or OracleResult(
        compiles=False,
        verifier_pass=None,
        error="All sources failed to compile",
    )


# ── CLI for quick testing ─────────────────────────────────────────────────────

def _cli() -> None:
    import argparse
    import json
    import yaml

    parser = argparse.ArgumentParser(
        description="BPFix verifier-pass oracle: compile + verify eBPF programs"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # verify-file: compile and verify a single C file
    p_file = subparsers.add_parser("verify-file", help="Verify a single .c file")
    p_file.add_argument("source", help="Path to .c BPF source file")
    p_file.add_argument("--compile-only", action="store_true",
                        help="Only compile, skip verifier loading")
    p_file.add_argument("--prog-type", default=None,
                        help="BPF program type hint (xdp, tc, kprobe, ...)")

    # verify-case: verify a case from a YAML file
    p_case = subparsers.add_parser("verify-case", help="Verify a case YAML file")
    p_case.add_argument("yaml_path", help="Path to case YAML file")
    p_case.add_argument("--compile-only", action="store_true")
    p_case.add_argument("--snippet-index", type=int, default=None,
                        help="Use specific snippet index from source_snippets")

    # batch: run over a directory of case YAML files
    p_batch = subparsers.add_parser("batch", help="Batch verify a directory of cases")
    p_batch.add_argument("case_dir", help="Directory of .yaml case files")
    p_batch.add_argument("--compile-only", action="store_true")
    p_batch.add_argument("--limit", type=int, default=None,
                         help="Max number of cases to test")
    p_batch.add_argument("--out", default=None, help="Output JSON file for results")

    args = parser.parse_args()

    if args.command == "verify-file":
        source = Path(args.source).read_text(encoding="utf-8")
        result = verify_fix(
            source_code=source,
            prog_type=args.prog_type,
            compile_only=args.compile_only,
        )
        print(json.dumps(result.to_dict(), indent=2))

    elif args.command == "verify-case":
        with open(args.yaml_path, "r", encoding="utf-8") as f:
            case_data = yaml.safe_load(f) or {}
        if args.snippet_index is not None:
            snippets = case_data.get("source_snippets") or []
            if args.snippet_index < len(snippets):
                result = verify_fix(
                    source_code=snippets[args.snippet_index],
                    compile_only=args.compile_only,
                )
            else:
                print(f"snippet_index {args.snippet_index} out of range ({len(snippets)} snippets)")
                return
        else:
            result = verify_case(case_data, compile_only=args.compile_only)
        print(f"Case: {case_data.get('case_id', args.yaml_path)}")
        print(json.dumps(result.to_dict(), indent=2))

    elif args.command == "batch":
        case_dir = Path(args.case_dir)
        yaml_files = sorted(case_dir.glob("*.yaml"))
        if args.limit:
            yaml_files = yaml_files[: args.limit]

        results = []
        passed = failed_verifier = failed_compile = 0
        for yaml_path in yaml_files:
            if yaml_path.name == "index.yaml":
                continue
            with open(yaml_path, "r", encoding="utf-8") as f:
                case_data = yaml.safe_load(f) or {}
            case_id = case_data.get("case_id", yaml_path.stem)
            result = verify_case(case_data, compile_only=args.compile_only)
            entry = {"case_id": case_id, **result.to_dict()}
            results.append(entry)
            status = (
                "PASS" if result.verifier_pass
                else "FAIL-VERIFIER" if result.compiles
                else "FAIL-COMPILE"
            )
            if args.compile_only:
                status = "COMPILES" if result.compiles else "FAIL-COMPILE"
            print(f"  {case_id}: {status}")
            if result.verifier_pass:
                passed += 1
            elif result.compiles:
                failed_verifier += 1
            else:
                failed_compile += 1

        total = len(results)
        print(f"\nBatch summary ({total} cases):")
        if args.compile_only:
            print(f"  Compiles:       {passed + failed_verifier} / {total}")
            print(f"  Compile-fail:   {failed_compile} / {total}")
        else:
            print(f"  Verifier PASS:  {passed} / {total}")
            print(f"  Verifier FAIL:  {failed_verifier} / {total}")
            print(f"  Compile FAIL:   {failed_compile} / {total}")

        if args.out:
            import json
            Path(args.out).write_text(json.dumps(results, indent=2), encoding="utf-8")
            print(f"Results saved to {args.out}")


if __name__ == "__main__":
    _cli()
