# Analysis Integration Todo

This is the working checklist for turning BPFix from a verifier-log formatter
into a reusable proof-lifecycle diagnostic engine.

## Community Target

BPFix should be useful without changing a developer's BPF workflow. A user
should be able to pipe a failed `bpftool`, libbpf-rs, Aya, or BCC load log into
`bpfix` and get a Rust-style diagnostic that says:

- what proof obligation the verifier needed
- where that proof was established, if visible in the trace
- where the proof was lost or became verifier-invisible, if visible
- where the verifier finally rejected the program
- what source rewrite is likely to make the proof visible again

The innovative part is not prettier formatting. The useful part is recovering a
source-level proof lifecycle from the verifier's per-instruction abstract-state
trace.

## Done

- [x] Keep `bpfix` as a userspace log post-processor for the first public path.
- [x] Import the `bpfopt` analysis code into `crates/bpfanalysis`.
- [x] Parse verifier state snapshots from log-level-2 verifier output.
- [x] Add `bpfanalysis::analyze_verifier_log` as the public analysis API for the
      CLI.
- [x] Infer first-pass proof obligations from terminal verifier errors.
- [x] Emit proof lifecycle events: `proof_established`, `proof_lost`, and
      `rejected`.
- [x] Map proof events to source spans when verifier logs include
      `; source @ file:line` annotations.
- [x] Refactor `crates/bpfix` so multi-span diagnostics come from
      `bpfanalysis`, not CLI-local source scanning.
- [x] Cover the branch-merge provenance example
      `stackoverflow-53136145` in analysis and CLI tests.
- [x] Preserve benchmark metadata support so replay cases can still supply
      adjudicated taxonomy class and repair direction.

## Next

- [ ] Add an optional object input, for example `bpfix --object prog.o
      verifier.log`, so BPFix can correlate logs with BTF and instruction
      metadata even when source comments are sparse.
- [ ] Build a `ProgramCFG` from object instructions and connect verifier states
      to `InsnSite` instead of only raw PCs.
- [ ] Move source correlation from log comments to BTF line records when an
      object is available.
- [ ] Generalize proof-lost detection beyond pointer provenance into scalar
      range loss, nullable pointer refinement loss, stack initialization loss,
      and reference lifecycle leaks.
- [ ] Track register lineage across copies, spills, reloads, and branch joins so
      proof events follow the value that matters instead of only one register
      number.
- [ ] Rank repair hints from the detected proof lifecycle rather than only the
      terminal error class.
- [ ] Add golden tests for at least one representative case per obligation
      class.
- [ ] Add `bpfix check -- <command>` to run a user's existing load/test command,
      capture verifier output, and print diagnostics only on failure.
- [ ] Keep JSON stable enough for editors and CI integrations.

## Current Limitations

- The first public API is log-driven. It does not yet require source code or an
  object file, but object/BTF input will improve precision.
- Source spans require verifier logs with source comments unless a future object
  input is provided.
- The proof-lost engine is strongest today for pointer provenance and branch
  merge failures. Other obligation classes still need deeper value-lineage
  tracking.
- Benchmark `case.yaml` metadata is used only as supplemental truth for replay
  cases. Real user logs still rely on the analysis output and terminal verifier
  message.
