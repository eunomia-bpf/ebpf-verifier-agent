# eBPF Decompiler / Disassembly Analysis for OBLIGE

- Local check: `which bpftool` -> `/usr/local/sbin/bpftool`
- Local version: `bpftool v7.7.0` (`libbpf v1.7`)

## Available tools

- `bpftool prog dump xlated [linum]`:
  dumps translated eBPF instructions from the kernel for an already loaded program.
  If `line_info` is present, it shows source lines; `linum` adds filename, line, and column.
  This is disassembly, not decompilation.
- Ghidra eBPF processor:
  built into official Ghidra since 10.3; supports disassembly and pseudo-C decompilation of eBPF ELF objects.
  Useful for offline reverse engineering, but it is manual and not verifier-aware.
- Other public tools found:
  `ebpf-disasm`, `rbpf`, and GoBPFLD expose disassembly / decoding functionality.
  I did not find a mature standalone BPF-to-C decompiler beyond Ghidra's decompiler path.

## Relevance to OBLIGE

- For OBLIGE's main path, original source files are not required if the verbose verifier log already contains BTF source annotations.
- The parser treats `; ... @ file:line` lines as source annotations and attaches them to subsequent instructions.
  See `interface/extractor/trace_parser.py`.
- Proof events are then correlated back to source spans via those inline annotations.
  See `interface/extractor/source_correlator.py`.
- If no source annotation is available, OBLIGE already falls back to bytecode-level spans (`<bytecode>`), rather than failing.
  This behavior is implemented in `source_correlator.py` and exercised in `tests/test_renderer.py`.
- If even the trace is too sparse, `rust_diagnostic.py` synthesizes a placeholder rejected span from the verifier headline/error text.

## Production deployment scenario

- Important constraint: `bpftool prog dump xlated` only works for programs that are already loaded.
- In the kernel-upgrade failure case, the interesting artifact is usually a program that now fails during `BPF_PROG_LOAD`, so there may be no loaded program ID to dump on the new kernel.
- Practical workflow:
  1. Re-run the production loader on the target kernel with verbose verifier logging enabled and capture the full verifier log.
  2. Feed that log to OBLIGE.
  3. If BTF line annotations are present, OBLIGE can localize the failure without source files.
  4. If annotations are absent, OBLIGE still produces bytecode-indexed spans.
  5. Use `bpftool dump xlated linum` only as a supplemental view for a successfully loaded reference instance (old kernel, staging, or another host), not as the primary artifact for the failed load.
  6. Use Ghidra only when no useful verifier log is available and offline object-file reverse engineering is necessary.

## `bpftool dump xlated linum` vs verifier-log BTF annotations

- Both rely on BTF `line_info`.
- `bpftool dump xlated linum` gives a static translated-instruction listing plus source/filename/line metadata.
- Verifier logs give the same kind of source anchors, but also include abstract register state, control-flow context, and the actual rejection/error text.
- For OBLIGE, verifier logs are strictly more valuable than `bpftool` dumps because OBLIGE reasons over verifier state transitions, not just instruction listings.

## Recommendation for the paper

- Decompiler integration is probably not worth implementing as a core paper feature.
- The main reason is that OBLIGE already handles the no-source case in the most relevant deployment mode:
  verbose verifier log with BTF annotations -> source spans;
  no annotations -> bytecode spans.
- `bpftool` is useful but only for already loaded programs, so it does not solve the key production failure mode by itself.
- Ghidra is useful for offline reverse engineering, but it is heavyweight, manual, and orthogonal to OBLIGE's verifier-log-driven analysis.
- Best paper framing:
  treat decompiler / offline reverse-engineering support as future work or a deployment aid, not as part of the core contribution.

## Pointers

- Kernel BTF docs: https://www.kernel.org/doc/html/latest/bpf/btf.html
- Local `bpftool-prog(8)` man page documents `linum` for `dump xlated`
- Official Ghidra eBPF module: https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Processors/eBPF
- eBPF-for-Ghidra README: https://github.com/Nalen98/eBPF-for-Ghidra
