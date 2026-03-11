# Motivation Evidence: eBPF Verifier Diagnostics Are a Real Developer Pain Point

Run date: 2026-03-11

## Executive Summary

The evidence is not subtle: eBPF developers repeatedly report that verifier failures are hard to understand, hard to localize, sensitive to compiler/kernel details, and often phrased at the wrong abstraction level. In our own case-study corpus, many questions are not about writing unsafe programs; they are about understanding why apparently safe programs were rejected, why the reported failing instruction is not the real cause, or why a program works on one kernel but not another.

Three patterns stand out.

- The verifier often reports the final symptom, not the proof-loss site. Our confirmed lowering-artifact study shows that message-line-only diagnosis is correct on only **2/6** cases, while trace analysis finds an earlier proof-loss transition in **4/5** analyzable traces; in all four, the root-cause instruction differs from the final failing access. Source: [lowering-artifact-analysis](./lowering-artifact-analysis.md), [manual-labeling-30cases](./manual-labeling-30cases.md).
- The workaround corpus is dominated by verifier-facing rewrites, not straightforward bug fixes. In `591` `eval_commits` cases, **376/591 (63.6%)** fall into workaround-heavy fix types such as `inline_hint`, `loop_rewrite`, `type_cast`, `volatile_hack`, `refactor`, and `attribute_annotation`, suggesting that many failures are really proof-shaping problems.
- Rich diagnostics exist, but they are buried in flat logs. In the local corpus, only `92/502` cases even have non-empty verifier logs, and those non-empty logs average **57.7 lines**; `35` exceed `100` lines, `12` exceed `200`, and `2` exceed `500`. Source: [verbose-log-audit](./verbose-log-audit.md) plus a corpus parser pass over `verifier_log.combined`.

## Corpus Statistics

- Local case-study corpus size: **502** cases. Source: [verbose-log-audit](./verbose-log-audit.md).
- Cases with any verifier log: **92/502**. Cases with register-state dumps: **51**. Cases with BTF-style source annotations: **35**. Cases with backtracking markers: **23**. Source: [verbose-log-audit](./verbose-log-audit.md), [paper-contribution-analysis](./paper-contribution-analysis.md).
- Stack Overflow confusion signal: a conservative keyword scan over `question_body_text` found **19/76 (25.0%)** SO cases explicitly using confusion/frustration language or an “even though...” contradiction.
- Average verifier log length:
  - **50.2 lines** across all `502` case-study cases.
  - **57.7 lines** across the `92` non-empty logs.
  - `35/92` non-empty logs exceed `100` lines, `12/92` exceed `200`, `2/92` exceed `500`.
- Manual benchmark signal: in the 30-case manually labeled benchmark, headline/message-only heuristic classification matches the manual class in **23/30 (76.7%)** overall, but only **2/6 (33.3%)** on confirmed `lowering_artifact` cases. Sources: [manual-labeling-30cases](./manual-labeling-30cases.md), [lowering-artifact-analysis](./lowering-artifact-analysis.md).
- Workaround-heavy fix-type distribution in `eval_commits`:
  - `inline_hint`: **229**
  - `loop_rewrite`: **64**
  - `type_cast`: **38**
  - `volatile_hack`: **18**
  - `refactor`: **16**
  - `attribute_annotation`: **11**
  - Combined “diagnostic was likely surface-level or misleading” subset: **376/591 (63.6%)**

## Category A: “I checked the bounds but verifier still rejects”

This is the clearest recurring pain point in the corpus. Developers add bounds checks, inspect the generated code, and still get rejected because the verifier loses the proof after lowering or register reshaping.

- [SO 74178703](https://stackoverflow.com/questions/74178703/ebpf-invalid-access-to-map-value-even-with-bounds-check): “invalid access to map value even though I have performed bounds checking.” The accepted answer says the verifier “lost information from the previous bounds check.”
- [SO 70873332](https://stackoverflow.com/questions/70873332/invalid-access-to-packet-even-though-check-made-before-access): title is already the complaint: “Invalid access to packet even though check made before access.”
- [SO 79485758](https://stackoverflow.com/questions/79485758/invalid-access-to-packet-while-parsing-packet-in-an-ebpf-program): the asker asks why the error appears “even though I have check for packet bounds.” The accepted answer calls it a “corner-case limitation.”
- [SO 78525670](https://stackoverflow.com/questions/78525670/ebpf-verifier-error-unbounded-variable-offset-read-when-read-is-safe-and-withi): title: “unbounded variable-offset read” “when read is safe and within bounds.”
- [SO 77762365](https://stackoverflow.com/questions/77762365/ebpf-value-is-outside-of-the-allowed-memory-range-when-reading-data-into-arra): “I did a bounds check on both the read length and the offset, but verifier still complain.”
- [SO 73088287](https://stackoverflow.com/questions/73088287/how-do-i-copy-data-to-buffer-in-ebpf): “I checked the length of payload should be less than MTU... But I can't pass the verifier.” The answer explains that the checked and dereferenced pointer paths diverged in different registers.
- [SO 79530762](https://stackoverflow.com/questions/79530762/question-about-how-the-ebpf-verifier-behaves-in-my-specific-use-case): the developer reports that `if (option_length == 8 || option_length == 12)` fails, but splitting the branches makes it pass; the accepted answer says “the verifier seems to get lost because of how the compiler optimized the code.”
- [BCC issue #5062](https://github.com/iovisor/bcc/issues/5062): the reporter notes that “the verifier was actually checking for `R9` but then later in assembly using `R0` w/o checks.”

Why this matters: this is not ordinary “forgot a guard” debugging. It is a source/bytecode/proof mismatch problem.

## Category B: “The error message doesn’t tell me what to fix”

Many developer questions are really requests for translation: from verifier jargon and register state into a source-level explanation and a concrete repair.

- [SO 68752893](https://stackoverflow.com/questions/68752893/how-to-read-understand-the-bpf-kernel-verifier-analysis-to-debug-the-error): title: “How to read/understand the bpf kernel verifier analysis to debug the error?”
- [SO 70760516](https://stackoverflow.com/questions/70760516/bpf-verifier-fails-because-of-invalid-access-to-packet): “I also don't understand the instructions where it's failing.”
- [SO 78236856](https://stackoverflow.com/questions/78236856/r2-max-value-is-outside-of-the-allowed-memory-range-after-explicit-bounds-checki): “I don't have enough experience with reading its output properly.”
- [SO 69192685](https://stackoverflow.com/questions/69192685/whats-func-info-in-ebpf-verifier): “I don't understand how these two values are set before processed by the verifier.”
- [SO 77673256](https://stackoverflow.com/questions/77673256/how-to-link-load-rodata-section-when-loading-bpf-program-with-raw-syscalls): “This is confusing to me.” The reported error says `r1` is a scalar when the author expects an `fp`.
- [SO 78266602](https://stackoverflow.com/questions/78266602/using-a-program-of-type-raw-tracepoint-to-trace-sched-wakeup-bpf-verifies-that-t): “I don't know why.”
- [Aya issue 1056](https://github.com/aya-rs/aya/issues/1056): the verifier headline is “last insn is not an exit or jmp,” but the maintainer’s actual diagnosis is: “You are calling panic somewhere. You can't panic or unwrap anywhere in ebpf code.”
- [Aya issue 863](https://github.com/aya-rs/aya/issues/863): “took me a long time to figure out and still failed.” The visible error is only `Permission denied (os error 13)`.

Why this matters: the current interface makes developers reverse-engineer verifier internals just to get to a plausible source-level fix.

## Category C: “It works on one kernel but not another”

Cross-kernel and cross-toolchain drift is not edge noise; it is a recurring source of verifier pain.

- [SO 72575736](https://stackoverflow.com/questions/72575736/linux-kernel-5-10-verifier-rejects-ebpf-xdp-program-that-is-fine-for-kernel-5-13): the question states the packet access “fails on kernel 5.10, but works fine on 5.13.”
- [Cilium issue 41996](https://github.com/cilium/cilium/issues/41996): after upgrading to Cilium 1.18, pods “lose network connectivity” on `4.18.0-553...`; another user reports “same issue” on Ubuntu `5.15.0-67`.
- [Cilium issue 44216](https://github.com/cilium/cilium/issues/44216): “Cluster network completely goes down after an upgrade to kernel 6.18.5.”
- [Cilium issue 37478](https://github.com/cilium/cilium/issues/37478): maintainer comment: “issues like this are often highly related to the kernel version.”
- [Aya commit 11c227743de9](https://github.com/aya-rs/aya/commit/11c227743de9ef149871df44c9d99979749d1b00): diff summary says the inlining change keeps verifier-visible state in a form “older kernels accept.”
- [Katran commit 5d1e2ca8b9d7](https://github.com/facebookincubator/katran/commit/5d1e2ca8b9d71a1175352ff3994237f4e6530c1e): the commit explicitly avoids “older-kernel verifier rejection.”
- [DepSurf project / paper](https://sites.google.com/view/depsurf-bpf/home): reports that **83%** of studied extensions hit at least one kernel mismatch; a highlighted example says `biotop` became incompatible with Linux `v5.16` “due to one inlined function.”

Why this matters: a flat verifier log with no kernel-version or dependency context makes portability failures look like random breakage.

## Category D: “The error points to the wrong place”

The most painful cases are not just cryptic; they are causally misleading. The final rejection line points at the symptom instruction, while the real proof collapse happened earlier or in a different function.

- [SO 70750259](https://stackoverflow.com/questions/70750259/bpf-verification-error-when-trying-to-extract-sni-from-tls-packet): “I'm confused where the error actually is.” The author adds that “commenting out unrelated pieces affects other pieces of code.”
- [SO 74178703](https://stackoverflow.com/questions/74178703/ebpf-invalid-access-to-map-value-even-with-bounds-check): the complaint is at `memcpy`, but the accepted answer says the verifier had already “lost information from the previous bounds check.”
- [SO 79530762](https://stackoverflow.com/questions/79530762/question-about-how-the-ebpf-verifier-behaves-in-my-specific-use-case): the failure shows up on the store, but the accepted answer says the problem is how the compiler optimized the earlier proof path.
- [Aya issue 1056](https://github.com/aya-rs/aya/issues/1056): the visible message is “last insn is not an exit or jmp,” but the actual cause is a hidden panic path.
- [BCC issue #5062](https://github.com/iovisor/bcc/issues/5062): the developer reports that verifier checking happened on `R9`, while the actual load later used `R0`.
- [bpf@vger mail on the same case](https://www.spinics.net/lists/bpf/msg95383.html): the root-cause reply says “the verifier does not recognize equivalent bounds check on register R0.”
- [Local lowering-artifact study](./lowering-artifact-analysis.md): in **4/4** successful trace-analysis cases, the root-cause transition was at an instruction different from the final failing access.

Why this matters: if the message localizes the wrong instruction, developers add guards in the wrong place and churn through non-fixes.

## Category E: “I don’t know if this is a real bug or a verifier limitation”

Several threads are fundamentally classification problems: is the code unsafe, is the verifier too conservative, is the compiler producing verifier-hostile code, or is this a kernel bug/regression?

- [SO 70873332](https://stackoverflow.com/questions/70873332/invalid-access-to-packet-even-though-check-made-before-access): the accepted answer calls it a “corner-case of the verifier.”
- [SO 79485758](https://stackoverflow.com/questions/79485758/invalid-access-to-packet-while-parsing-packet-in-an-ebpf-program): the accepted answer calls it a “corner-case limitation of the eBPF verifier.”
- [SO 70729664](https://stackoverflow.com/questions/70729664/need-help-in-xdp-program-failing-to-load-with-error-r7-offset-is-outside-of-the): accepted answer: “You are hitting a corner-case limitation of the verifier.”
- [SO 79530762](https://stackoverflow.com/questions/79530762/question-about-how-the-ebpf-verifier-behaves-in-my-specific-use-case): “the verifier seems to get lost because of how the compiler optimized the code.”
- [SO 56872436](https://stackoverflow.com/questions/56872436/bpf-verifier-rejecting-xdp-program-due-to-back-edge-even-though-pragma-unroll-is): “back-edge even though pragma unroll is used” is exactly the “is my code wrong or is this a verifier limit?” failure mode.
- [Cilium issue 44216](https://github.com/cilium/cilium/issues/44216): maintainer says the warnings are a “known issue upstream,” i.e. a verifier/kernel bug rather than a source fix.
- [HotOS 2023](https://doi.org/10.1145/3593856.3595892): frames the problem as structural, not just user mistakes: kernel-extension verification faces “limited scalability, portability.”

Why this matters: without a clear distinction between `source_bug`, `lowering_artifact`, `verifier_limit`, and `verifier_bug`, developers cannot tell whether to rewrite code, change the compiler shape, or upgrade the kernel.

## Category F: “The log is too long to read”

Even when the verifier emits enough information, it is often buried in logs long enough that developers focus only on the last line.

- [Local log audit](./verbose-log-audit.md): non-empty logs average **57.7** lines; `35` exceed `100`, `12` exceed `200`, and `2` exceed `500`.
- [Cilium issue 37478](https://github.com/cilium/cilium/issues/37478): the issue title literally ends with “(4703 line(s) omitted).”
- [Aya issue 1267](https://github.com/aya-rs/aya/issues/1267): the attached verifier log is **544** lines long, but the user-facing title is only “Receiving Permission denied (os error 13).”
- [Aya issue 1062](https://github.com/aya-rs/aya/issues/1062): **337** lines of log for a root cause that turns out to be `ctx.ret().unwrap()`.
- [SO 70760516](https://stackoverflow.com/questions/70760516/bpf-verifier-fails-because-of-invalid-access-to-packet): **331** log lines for a packet-range proof issue.
- [SO 79485758](https://stackoverflow.com/questions/79485758/invalid-access-to-packet-while-parsing-packet-in-an-ebpf-program): **208** log lines, yet the actionable explanation is still a one-paragraph accepted answer.
- [Linux Foundation / NCC verifier audit](https://www.linuxfoundation.org/press/linux-foundation-releases-open-source-technology-security-audit-of-the-ebpf-verifier): the audit says documentation should better explain “what the verifier enforces and why,” and that current docs are often “incomplete” or “too specific.” The accompanying report explicitly recommends better explanation of verifier behavior.

Why this matters: a long flat log is not the same thing as a usable diagnostic.

## Greatest Hits

These five examples are the strongest motivation anchors for a verifier-diagnostics paper.

1. [SO 74178703](https://stackoverflow.com/questions/74178703/ebpf-invalid-access-to-map-value-even-with-bounds-check): explicit “even with bounds check” rejection; accepted answer shows proof loss, not source unsafety.
2. [Aya issue 1056](https://github.com/aya-rs/aya/issues/1056): headline says “last insn is not an exit or jmp”; real fix is “don’t panic/unwrap.”
3. [SO 72575736](https://stackoverflow.com/questions/72575736/linux-kernel-5-10-verifier-rejects-ebpf-xdp-program-that-is-fine-for-kernel-5-13): the same verifier-visible logic passes on one kernel and fails on another.
4. [Cilium issue 37478](https://github.com/cilium/cilium/issues/37478): a real production issue whose title already contains “(4703 line(s) omitted).”
5. [BCC issue #5062](https://github.com/iovisor/bcc/issues/5062) and the matching [mailing-list reply](https://www.spinics.net/lists/bpf/msg95383.html): maintainer-level confirmation that the verifier missed an equivalent bounds proof on a different register.

## Academic and Expert References by Pain Point

### A / D / E: source-safe code can still be rejected, and the message often hides the real cause

- [Rex (USENIX ATC 2025)](https://www.usenix.org/conference/atc25/presentation/jia): studies **72 verifier-workaround commits** over **12 years** and explicitly frames the problem as a language-verifier gap. This supports Categories A, D, and E.
- [HotOS 2023: Kernel Extension Verification is Untenable](https://doi.org/10.1145/3593856.3595892): argues verifier-based extension ecosystems face structural limitations in scalability and portability, which supports Category E.
- [Linux Foundation / NCC verifier audit PDF](https://84b736e1-8a97-4eb5-8d88-d7e7bbd52f4b.usrfiles.com/ugd/84b736_d7531d2cce504e049b9ef1331e9e995b.pdf): recommends explaining “what the verifier enforces and why,” which directly supports Categories B and E.

### B / F: diagnostics are hard to interpret even when information exists

- [Deokar et al., 2024](https://doi.org/10.1145/3672197.3673429): empirical study of **743** Stack Overflow eBPF questions; the slide deck explicitly includes “Error Handling and Verifier Messages” among the recurring challenge areas. Public talk slides: [PDF](https://pchaigno.github.io/ebpf2024-talks/ebpf2024-04-deokar-an-empirical-study-on-the-challenges-of-ebpf-application-development.pdf).
- [Linux Foundation / NCC verifier audit](https://www.linuxfoundation.org/press/linux-foundation-releases-open-source-technology-security-audit-of-the-ebpf-verifier): independently notes that existing documentation is often incomplete or too specific.

### C: portability and kernel-dependency mismatch are central, not rare

- [DepSurf project site](https://sites.google.com/view/depsurf-bpf/home): reports that **83%** of studied extensions are affected by at least one kernel mismatch.
- DepSurf’s public paper example says `biotop` became incompatible with Linux `v5.16` “due to one inlined function,” which strongly supports Category C.

## Notes on Method

- Local corpus quotes came from `case_study/cases/{stackoverflow,github_issues}/*.yaml`, using `question_body_text`, `selected_answer.body_text`, `issue_body_text`, and `fix.selected_comment.body_text` when present.
- The Stack Overflow confusion count is heuristic: it uses conservative keyword matching over question bodies and should be presented as an estimate, not a manually audited label.
- The “message points to symptom vs root cause” statistic should be cited carefully as a **manual-benchmark** result:
  - overall headline-class agreement: **23/30**
  - confirmed lowering-artifact agreement: **2/6**
  - earlier proof-loss site recovered by trace analysis: **4/5** analyzable traces
- The “misleading fix-type” subset is an interpretation over `eval_commits`: it counts fix types that primarily reshape verifier-visible proof (`inline_hint`, `loop_rewrite`, `type_cast`, `volatile_hack`, `refactor`, `attribute_annotation`) rather than straightforward functional bug fixes.
