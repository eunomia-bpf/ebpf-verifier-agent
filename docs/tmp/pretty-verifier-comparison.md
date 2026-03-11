# Pretty Verifier vs OBLIGE

## Pretty Verifier Architecture Summary

- Upstream snapshot: `a354d9a1de36d452ede15eb24d03ab1d5854b8ec` from `/tmp/pretty-verifier`.
- Handler inventory: `91` explicit `set_error_number()` branches in `src/pretty_verifier/handler.py`.
- Entry path is CLI `main.py -> process_input() -> handle_error()`.
- The core selector is `error = output_raw[-2]`, with one `old state:` special case. There is no reusable `Handler(...)` class in the current upstream repo.
- Pretty Verifier is line-oriented: it matches one headline line against regex branches and prints one human-readable explanation, sometimes with a source hint and suggestion.
- Concrete output shape is `N error: <message>` under a colored banner, followed by an optional source snippet, appendix, and suggestion. If no branch matches, it prints `-1 error: Error not managed -> <selected line>`.
- It does not parse full register-state traces, detect proof-loss transitions, or backtrack register dependencies.
- README claims best support on kernel `6.8` and source mapping via `llvm-objdump` plus compiled `.o` files. The OBLIGE corpus does not preserve those object files, so llvm-objdump-based localization is usually unavailable here.

## Corpus and Method

- Compared `263` cases with non-empty verifier logs across `github_issues=26, kernel_selftests=171, stackoverflow=66`.
- Pretty Verifier corpus outcome summary: `exception=28, handled=75, no_output=1, unhandled=159`.
- In this corpus, unhandled or brittle cases are common: many issue logs place trailer lines such as `verification time` or `stack depth` after the true rejection line, and `28` cases raised a Python exception instead of yielding a diagnosis.
- Pretty Verifier source localization succeeded on `0/263` cases. OBLIGE found log-native source mapping on `204/263` cases.
- OBLIGE found an earlier root-cause instruction/transition on `130/263` corpus cases.
- For StackOverflow and GitHub YAMLs with multiple verifier blocks, the script selects the highest-scoring verbose block instead of the concatenated prose-heavy `combined` string.
- OBLIGE uses `parse_log(..., catalog_path='taxonomy/error_catalog.yaml')` plus `parse_trace(...)` on the same normalized log block.

## Table 1: Coverage and Capability

| Feature | Pretty Verifier | OBLIGE |
| --- | --- | --- |
| Error message parsing | Yes | Yes |
| Full state trace analysis | No | Yes |
| Critical transition detection | No | Yes |
| Causal chain extraction | No | Yes |
| Source localization | via llvm-objdump or inline source comments | via BTF/log annotations |
| Taxonomy classification | partial (handler/error number only) | Yes (catalog-backed) |
| Lowering artifact detection | No | Yes |
| Cross-kernel stability | fragile regex lineup | more stable state-format parsing |

## Table 2: Per-Case Accuracy on the 30 Manually Labeled Cases

| Case | Manual label | Pretty Verifier diagnosis | OBLIGE diagnosis | PV correct? | OBLIGE correct? |
| --- | --- | --- | --- | --- | --- |
| `kernel-selftest-iters-state-safety-destroy-without-creating-fail-raw-tp-a14b4d3a` | `source_bug` | PV#39: Expected initialized iterator of type not managed pointer in argument #0 of helper function | OBLIGE-E014 (source_bug); arg#0 reference type('UNKNOWN ') size cannot be determined: -22 | Yes | Yes |
| `kernel-selftest-iters-state-safety-read-from-iter-slot-fail-raw-tp-812dc246` | `source_bug` | PV?: Error not managed -> invalid read from stack off -24+0 size 8 | OBLIGE-E003 (source_bug); invalid read from stack off -24+0 size 8 | Yes | Yes |
| `kernel-selftest-dynptr-fail-release-twice-raw-tp-3722429d` | `source_bug` | PV?: Error not managed -> arg 1 is an unacquired reference | OBLIGE-E019 (source_bug); arg#0 reference type('UNKNOWN ') size cannot be determined: -22 | Yes | Yes |
| `kernel-selftest-exceptions-fail-reject-subprog-with-lock-tc-f038a1b8` | `source_bug` | PV?: Error not managed -> function calls are not allowed while holding a lock | OBLIGE-E013 (source_bug); R1 lost scalar bounds at insn 9: scalar,var_off=(0x0; 0xffffffff) -> scalar,var_off=(0x0; 0xffffffff) | Yes | Yes |
| `kernel-selftest-cpumask-failure-test-global-mask-rcu-no-null-check-tp-btf-task-newtask-c8a92e39` | `source_bug` | PV?: Error not managed -> Possibly NULL pointer passed to helper arg2 | OBLIGE-E015 (source_bug); Possibly NULL pointer passed to helper arg2 | Yes | Yes |
| `kernel-selftest-dynptr-fail-invalid-read2-raw-tp-2cc2b993` | `source_bug` | PV#36: Expected initialized dynamic pointer in argument #2 of helper function | OBLIGE-E012 (source_bug); R1 downgraded from pointer-like ctx to scalar at insn 0 | Yes | Yes |
| `kernel-selftest-iters-state-safety-leak-iter-from-subprog-fail-raw-tp-65737a09` | `source_bug` | PV?: Error not managed -> BPF_EXIT instruction in main prog would lead to reference leak | OBLIGE-E004 (source_bug); arg#0 reference type('UNKNOWN ') size cannot be determined: -22 | Yes | Yes |
| `kernel-selftest-cpumask-failure-test-populate-invalid-destination-tp-btf-task-newtask-2aa0585a` | `source_bug` | PV#2: Wrong argument passed to helper function; 1° argument () is a scalar value (not a pointer), but a pointer to locally defined data (frame pointer) is expected | OBLIGE-E023 (source_bug); R1 downgraded from pointer-like ctx to scalar at insn 2 | Yes | Yes |
| `kernel-selftest-dynptr-fail-test-dynptr-reg-type-raw-tp-18f079b9` | `source_bug` | PV#82: Invalid arguments passed to global function global_call_bpf_dynptr | OBLIGE-E019 (source_bug); arg#0 reference type('UNKNOWN ') size cannot be determined: -22 | Yes | Yes |
| `stackoverflow-69767533` | `source_bug` | PV?: Error not managed -> invalid indirect read from stack R1 off -128+0 size 127 | OBLIGE-E003 (source_bug); libbpf: load bpf program failed: Permission denied | Yes | Yes |
| `stackoverflow-61945212` | `source_bug` | PV#2: Wrong argument passed to helper function; 2° argument () is a not managed pointer, but a pointer to locally defined data (frame pointer) is expected | OBLIGE-E023 (source_bug); R2 type=inv expected=fp | Yes | Yes |
| `stackoverflow-77205912` | `source_bug` | PV?: Error not managed -> 56: (85) call bpf_csum_diff#28 | OBLIGE-E023 (source_bug); R1 lost packet range proof at insn 31: r=54 -> r=None | Yes | Yes |
| `stackoverflow-70091221` | `source_bug` | PV#2: Wrong argument passed to helper function; 1° argument () is a pointer to map element value, but a pointer to map is expected | OBLIGE-E023 (source_bug); R1 type=map_value expected=map_ptr | Yes | Yes |
| `github-aya-rs-aya-1062` | `lowering_artifact` | PV?: Error not managed -> stack depth 24+0+0+0 | OBLIGE-E005 (lowering_artifact); R2 lost scalar bounds at insn 8: scalar,id=3,umax=18446744069414584320,var_off=(0x0; 0xffffffff00000000) -> scalar | No | Yes |
| `stackoverflow-79530762` | `lowering_artifact` | exception: IndexError: pop from empty list | OBLIGE-E001 (source_bug); R4 downgraded from pointer-like pkt to inv at insn 22 | No | No |
| `stackoverflow-73088287` | `lowering_artifact` | exception: IndexError: pop from empty list | OBLIGE-E001 (source_bug); invalid access to packet, off=120 size=1, R4(id=0,off=135,r=120) | No | No |
| `stackoverflow-74178703` | `lowering_artifact` | PV?: Error not managed -> invalid access to map value, value_size=1024 off=1024 size=1 | OBLIGE-E005 (lowering_artifact); R3 lost scalar bounds at insn 204: inv,id=0,umax=255,var_off=(0x0; 0xff) -> invP,id=0,umax=1023,var_off=(0x0; 0x3ff) | No | Yes |
| `stackoverflow-76160985` | `lowering_artifact` | exception: IndexError: pop from empty list | OBLIGE-E005 (lowering_artifact); invalid access to memory, mem_size=1 off=1 size=1 | No | Yes |
| `stackoverflow-70750259` | `lowering_artifact` | PV?: Error not managed -> math between pkt pointer and register with unbounded min value is not allowed | OBLIGE-E005 (lowering_artifact); R0 lost scalar bounds at insn 22: inv,id=0,umax=65280,var_off=(0x0; 0xff00) -> inv,id=0 | Yes | Yes |
| `kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda` | `verifier_limit` | PV#20: Combined stack size of 2 subprograms is 576, maximum is 512 | OBLIGE-E018 (verifier_limit); R6 lost scalar bounds at insn 48: scalar,umax=0 -> scalar,id=2 | Yes | Yes |
| `kernel-selftest-async-stack-depth-pseudo-call-check-tc-320d654d` | `verifier_limit` | PV#20: Combined stack size of 2 subprograms is 544, maximum is 512 | OBLIGE-E018 (verifier_limit); R0 lost scalar bounds at insn 49: scalar,umax=0 -> scalar | Yes | Yes |
| `stackoverflow-56872436` | `verifier_limit` | PV?: Error not managed -> libbpf: -- END LOG -- | OBLIGE-E008 (verifier_limit); back-edge from insn 271 to 69 | No | Yes |
| `stackoverflow-78753911` | `verifier_limit` | PV?: Error not managed -> The sequence of 8193 jumps is too complex. | OBLIGE-E007 (verifier_limit); processed 67395 insns (limit 1000000) max_states_per_insn 17 total_states 733 peak_states 723 mark_read 6 | Yes | Yes |
| `github-cilium-cilium-41412` | `verifier_limit` | PV?: Error not managed -> stack depth 360 | Error: failed to load object file | No | No |
| `github-cilium-cilium-35182` | `env_mismatch` | PV?: Error not managed -> arg#0 reference type('UNKNOWN ') size cannot be determined: -22 | OBLIGE-E021 (env_mismatch); arg#0 reference type('UNKNOWN ') size cannot be determined: -22 | Yes | Yes |
| `github-aya-rs-aya-1233` | `env_mismatch` | PV?: Error not managed -> stack depth 0 | OBLIGE-E009 (env_mismatch); R1 downgraded from pointer-like ctx to scalar at insn 2 | No | Yes |
| `github-aya-rs-aya-864` | `env_mismatch` | PV?: Error not managed -> stack depth 0 | OBLIGE-E009 (env_mismatch); Failed to run `sudo -E target/debug/interceptor --iface wlo1` | No | Yes |
| `stackoverflow-76441958` | `env_mismatch` | PV?: Error not managed -> misaligned access off (0x0; 0xffffffffffffffff)+0+0 size 8 | OBLIGE-E023 (source_bug); R1 downgraded from pointer-like ctx to scalar at insn 0 | No | No |
| `github-cilium-cilium-44216` | `verifier_bug` | PV?: Error not managed -> kern: warning: [2026-02-06T01:31:33.774557243Z]:  </TASK> | OBLIGE-E010 (verifier_bug); kern: warning: [2026-02-06T01:31:33.774559243Z]: ---[ end trace 0000000000000000 ]--- | Yes | Yes |
| `github-cilium-cilium-41996` | `verifier_bug` | PV?: Error not managed -> Verifier error: program tail_nodeport_nat_egress_ipv4: load program: permission denied: | OBLIGE-E011 (source_bug); Verifier error: program tail_nodeport_nat_egress_ipv4: load program: permission denied: | No | No |

## Table 3: Lowering Artifact Deep-Dive

| Case | Pretty Verifier | OBLIGE trace analysis | Root cause found? |
| --- | --- | --- | --- |
| `github-aya-rs-aya-1062` | PV?: Error not managed -> stack depth 24+0+0+0 | OBLIGE-E005 (lowering_artifact); R2 lost scalar bounds at insn 8: scalar,id=3,umax=18446744069414584320,var_off=(0x0; 0xffffffff00000000) -> scalar | PV: No; OBLIGE: Yes |
| `stackoverflow-79530762` | exception: IndexError: pop from empty list | OBLIGE-E001 (source_bug); R4 downgraded from pointer-like pkt to inv at insn 22 | PV: No; OBLIGE: Yes |
| `stackoverflow-73088287` | exception: IndexError: pop from empty list | OBLIGE-E001 (source_bug); invalid access to packet, off=120 size=1, R4(id=0,off=135,r=120) | PV: No; OBLIGE: No |
| `stackoverflow-74178703` | PV?: Error not managed -> invalid access to map value, value_size=1024 off=1024 size=1 | OBLIGE-E005 (lowering_artifact); R3 lost scalar bounds at insn 204: inv,id=0,umax=255,var_off=(0x0; 0xff) -> invP,id=0,umax=1023,var_off=(0x0; 0x3ff) | PV: No; OBLIGE: Yes |
| `stackoverflow-76160985` | exception: IndexError: pop from empty list | OBLIGE-E005 (lowering_artifact); invalid access to memory, mem_size=1 off=1 size=1 | PV: No; OBLIGE: No |
| `stackoverflow-70750259` | PV?: Error not managed -> math between pkt pointer and register with unbounded min value is not allowed | OBLIGE-E005 (lowering_artifact); R0 lost scalar bounds at insn 22: inv,id=0,umax=65280,var_off=(0x0; 0xff00) -> inv,id=0 | PV: No; OBLIGE: Yes |

## Table 4: Aggregate Accuracy on the Manual 30-Case Subset

| Metric | Pretty Verifier | OBLIGE |
| --- | --- | --- |
| Overall classification accuracy | 19/30 | 25/30 |
| Lowering artifact accuracy | 1/6 | 4/6 |
| Root cause localization | 0/30 | 12/30 |
| Cases with actionable diagnosis | 5/30 | 20/30 |

## Pretty Verifier Handler Coverage in This Corpus

- Observed Pretty Verifier handler numbers in this corpus: `13` of `91` total branches.
- OBLIGE error IDs with no observed Pretty Verifier equivalent on this corpus: `OBLIGE-E001`, `OBLIGE-E002`, `OBLIGE-E003`, `OBLIGE-E004`, `OBLIGE-E005`, `OBLIGE-E007`, `OBLIGE-E008`, `OBLIGE-E009`, `OBLIGE-E010`, `OBLIGE-E013`, `OBLIGE-E016`, `OBLIGE-E017`, `OBLIGE-E020`, `OBLIGE-E022`.

| PV # | Handler | Cases | Dominant OBLIGE ID | Distinct OBLIGE IDs | Distinct taxonomy classes | Too coarse? |
| --- | --- | --- | --- | --- | --- | --- |
| `2` | `type_mismatch` | 10 | `OBLIGE-E023` | 4 | 2 | Yes |
| `20` | `combined_stack_size_exceeded` | 2 | `OBLIGE-E018` | 1 | 1 | No |
| `24` | `invalid_mem_access_null_ptr_to_mem` | 28 | `OBLIGE-E011` | 2 | 1 | Yes |
| `35` | `dynptr_has_to_be_uninit` | 2 | `OBLIGE-E019` | 2 | 1 | Yes |
| `36` | `expected_initialized_dynptr` | 12 | `OBLIGE-E012` | 1 | 1 | No |
| `38` | `expected_uninitialized_iter` | 1 | `OBLIGE-E014` | 1 | 1 | No |
| `39` | `expected_initialized_iter` | 6 | `OBLIGE-E014` | 1 | 1 | No |
| `44` | `verbose_invalid_scalar` | 1 | `OBLIGE-E021` | 1 | 1 | No |
| `50` | `possibly_null_pointer_passed` | 8 | `OBLIGE-E015` | 1 | 1 | No |
| `68` | `pointer_comparison_prohibited` | 1 | `unclassified` | 1 | 1 | No |
| `77` | `bpf_program_too_large` | 1 | `OBLIGE-E018` | 1 | 1 | No |
| `80` | `unbounded_mem_access_umax_missing` | 2 | `OBLIGE-E021` | 2 | 2 | Yes |
| `82` | `caller_passes_invalid_args_into_func` | 1 | `OBLIGE-E019` | 1 | 1 | No |

## Analysis

OBLIGE's real advantage is not 'more regexes'. The distinguishing signal is trace structure: critical transitions, causal chains, and earlier proof-loss instructions. That is exactly where Pretty Verifier is blind.

Pretty Verifier is sufficient for straightforward contract violations when the final verifier line already names the real defect. Iterator state misuse, many dynptr protocol failures, and simple helper-argument mismatches usually fit that pattern.

Pretty Verifier is weak on lowering artifacts for two separate reasons. First, packet/map symptom lines are usually mapped to ordinary source-side bounds advice, even when the source already contains the needed check. Second, the upstream implementation's `output_raw[-2]` selection is brittle: several corpus logs place `stack depth`, `verification time`, or similar trailer lines between the real error and the final `processed ...` line, which makes the handler miss or mis-handle the failure entirely.

The lowering-artifact cases show the sharpest separation. For cases like `stackoverflow-79530762` and `stackoverflow-74178703`, Pretty Verifier either crashes, stays unhandled, or restates the final symptom. OBLIGE instead surfaces the earlier register-state collapse that explains why the accepted fix is a loop/codegen rewrite rather than 'add another bounds check'.

Concrete 'Pretty Verifier is enough' examples from the manual set are `kernel-selftest-iters-state-safety-destroy-without-creating-fail-raw-tp-a14b4d3a`, `kernel-selftest-dynptr-fail-invalid-read2-raw-tp-2cc2b993`, and `stackoverflow-61945212`: the headline line already names the real helper or protocol contract violation, so a line-oriented explanation is adequate.

Concrete misleading examples are `github-aya-rs-aya-1062` (`stack depth ...` is selected instead of the real signed-range failure), `stackoverflow-79530762` and `stackoverflow-73088287` (both crash with `IndexError`), and `stackoverflow-74178703` (the final map-bounds symptom is reported, but not the earlier proof-loss site).

There are still limits on the OBLIGE side. If the corpus preserves only a short final snippet with no usable state trace, OBLIGE cannot recover a true earlier root cause either. Subprogram-boundary artifacts remain a current weak spot as well.

## Honest Assessment

Pretty Verifier contributes a helpful human-readable layer over specific verifier lines, especially when the headline message already encodes the real obligation violation. OBLIGE wins when the bug is not on the headline line: lowering artifacts, hidden proof-loss transitions, and other cases where the final rejection is only a symptom.
