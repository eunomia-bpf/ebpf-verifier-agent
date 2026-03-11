# Literature Survey for OBLIGE

## Scope

OBLIGE treats eBPF verifier feedback as a systems interface problem: current tooling exposes verbose logs, but not a stable, typed account of what proof obligation failed, where it failed, or what kind of repair is appropriate. This survey organizes related work into three themes: evidence that verifier failures are a real developer-experience bottleneck, prior attempts to improve or work around verifier diagnostics, and recent LLM-assisted eBPF development systems that depend on verifier feedback in different ways [Deokar et al. 2024] [Jia et al. 2023] [Kgent 2024].

## Evidence That Verifier Diagnostics Are a Developer Bottleneck

Deokar et al. study 743 Stack Overflow questions about eBPF and identify multiple categories of developer challenges, including verifier-related problems [Deokar et al. 2024]. This is important because it grounds verifier pain in a broad developer corpus rather than isolated anecdotes. At the same time, the work is descriptive: it shows that verifier-related issues are common, but it does not propose improvements to the verifier interface itself [Deokar et al. 2024].

Jia et al.'s HotOS paper argues that kernel extension verification is becoming untenable because verifier complexity, verifier bugs, and limits on expressiveness increasingly act as liabilities [Jia et al. 2023]. This sharpens the problem statement from a systems perspective: the verifier is not just difficult to use, but difficult to maintain and reason about as a platform boundary. However, the paper identifies the problem more than it specifies a new diagnostic interface [Jia et al. 2023].

Rex extends that critique with a concrete retrospective study of 72 verifier-related workaround commits drawn from Cilium, Aya, and Katran [Rex 2025]. Jia et al. classify these workarounds into patterns such as splitting programs, hinting LLVM, changing code shape, and working around verifier bugs [Rex 2025]. The key result is that many of the affected programs were safe but still rejected by a conservative or buggy verifier, reinforcing that verifier rejection and program unsafety are not the same thing [Rex 2025]. Yet Rex remains retrospective: it explains where developers lost time, but it does not introduce a new interface for making failures easier to diagnose prospectively [Rex 2025].

The 2024 NCC Group/Linux Foundation eBPF audit reaches a similar conclusion from an assurance and documentation angle [NCC/Linux Foundation 2024]. One of its findings is verifier documentation clarity, and it explicitly notes that verifier output can be hard to understand, with developers often relying on trial and error against verbose logs [NCC/Linux Foundation 2024]. This matters because it shows the problem is visible not only in research papers and issue trackers, but also in security-review and ecosystem-governance contexts.

DepSurf addresses a different, but adjacent, source of eBPF developer friction: dependency mismatches [DepSurf 2025]. Its reported result that 83% of real-world programs are affected by dependency mismatches shows that eBPF failures are often multi-layered rather than purely local code bugs [DepSurf 2025]. Even so, DepSurf focuses on dependency surface analysis rather than the structure of verifier diagnostics, so it does not fill the interface gap OBLIGE targets [DepSurf 2025].

## Diagnostic Tooling and Interface-Oriented Related Work

Pretty Verifier is the closest direct precursor to OBLIGE among the provided works because it tries to make verifier failures intelligible at the source-code level [Pretty Verifier 2025]. It maps verifier errors back to C source lines, reports that Linux 6.8 contains more than 500 `verbose()` calls in the verifier, and identifies 79 distinct error types tied to C source defects [Pretty Verifier 2025]. This is a meaningful step toward localization. However, the approach is userspace and regex-based, which makes it fragile across kernel versions; it also stops short of extracting stable proof obligations or a durable error taxonomy that other tools can depend on [Pretty Verifier 2025].

The `ebpf-verifier-errors` GitHub repository is a community attempt to structure verifier failures around examples, source context, and suggested solutions [`ebpf-verifier-errors`]. Its issue templates are notable because they already move toward a machine-friendly collection format, and the repository explicitly names AI/chatbot tooling as a target use case [`ebpf-verifier-errors`]. The limitation is that the structure is manual and curatorial rather than a schema emitted by the verifier or a stable extraction layer; it is useful as a corpus, but not as a diagnostic interface [`ebpf-verifier-errors`].

The existing kernel and libbpf infrastructure shows that important pieces of a structured interface already exist, even if they are not assembled into one today [Kernel infrastructure]. BTF `line_info` can map bytecode instructions to source file, line, and column; `BPF_PROG_LOAD` already exposes `log_buf`, `log_size`, and `log_level`; libbpf offers `bpf_prog_linfo__new` and `bpf_prog_linfo__lfind` for programmatic access; and `BPF_MAP_TYPE_INSN_ARRAY` preserves instruction offset correspondence [Kernel infrastructure]. These primitives do not constitute a stable diagnostic schema by themselves, but they make OBLIGE technically plausible without assuming entirely new visibility mechanisms.

## LLM-Assisted eBPF Development

Kgent is directly relevant because it places verifier feedback inside an LLM synthesis loop [Kgent 2024]. The system feeds raw verifier error text back to the model on the next iteration, using the verifier as a refinement signal for program generation [Kgent 2024]. This demonstrates that verifier diagnostics are already functioning as an API for automated tools. The weakness is that the API is raw text: if the feedback is verbose, unstable, or underspecified, the model receives the same limitations as a human developer [Kgent 2024].

Gao et al.'s "Offloading the Tedious Task of Writing eBPF Programs" is another example of LLM-based eBPF program generation [Gao et al. 2025]. Even from the limited facts provided here, it marks eBPF generation as an active LLM application area rather than a niche experiment [Gao et al. 2025]. For OBLIGE, the implication is straightforward: as more generation systems target eBPF, the quality of verifier-facing feedback becomes more important as a machine interface, not just a human debugging aid.

SimpleBPF takes a different route by combining a DSL, LLM-based code generation, and a semantic checker in an attempt to avoid verifier debugging altogether [SimpleBPF 2025]. That is a valuable design point, but it depends on restricting the programming model to what the DSL can express [SimpleBPF 2025]. It does not address the much larger installed base of C- and Rust-based eBPF development, where developers still confront verifier failures directly.

"Kernel Extension DSLs Should Be Verifier-Safe!" pushes the same family of ideas further by arguing that DSL compilers should only emit verifier-accepted code [Kernel Extension DSLs Should Be Verifier-Safe! 2025]. This is a strong preventive stance, but it again assumes that developers are willing or able to move into a DSL pipeline [Kernel Extension DSLs Should Be Verifier-Safe! 2025]. OBLIGE addresses a complementary problem: improving failure explanation for existing general-purpose eBPF code, rather than replacing that workflow.

## Comparison Table

| Work | Main contribution | Limitation relative to OBLIGE |
| --- | --- | --- |
| [Deokar et al. 2024] | Empirical study of 743 Stack Overflow eBPF questions; identifies challenge categories including verifier issues | Documents pain points but does not propose interface improvements |
| [Jia et al. 2023] | Argues verifier complexity, bugs, and expressiveness limits are becoming untenable | Strong problem statement, but no diagnostic interface |
| [Rex 2025] | Studies 72 workaround commits across Cilium, Aya, and Katran; classifies workaround patterns | Retrospective analysis only; no new interface |
| [Pretty Verifier 2025] | Maps verifier errors back to C source lines; identifies 79 C-source-related error types | Regex-based and version-fragile; no obligation extraction or stable taxonomy |
| [Kgent 2024] | Uses raw verifier feedback in an LLM synthesis loop | Treats raw text as the interface; feedback remains unstructured |
| [SimpleBPF 2025] | Uses DSL + LLM codegen + semantic checking to avoid verifier debugging | Limited to DSL-expressible programs |
| [Gao et al. 2025] | LLM-based eBPF program generation | Does not by itself provide structured verifier diagnostics |
| [Kernel Extension DSLs Should Be Verifier-Safe! 2025] | Proposes verifier-safe DSL compilation | Does not help existing C/Rust eBPF code |
| [DepSurf 2025] | Dependency surface analysis; reports 83% of real-world programs affected by dependency mismatches | Focuses on dependency failures, not verifier diagnostic structure |
| [NCC/Linux Foundation 2024] | Audit identifies verifier documentation clarity as an ecosystem issue | Finds the DX problem, but not a structured solution |
| [`ebpf-verifier-errors`] | Community corpus of logs, source context, and solutions with AI/chatbot use in mind | Manual curation; no stable emitted schema |
| [Kernel infrastructure] | Existing source mapping, logging, and instruction-correlation primitives | Building blocks only; no unified, typed diagnostic layer |

## References

- [Deokar et al. 2024] Deokar et al., "An Empirical Study on the Challenges of eBPF Application Development," ACM SIGCOMM eBPF Workshop 2024. DOI: `10.1145/3672197.3673429`.
- [Jia et al. 2023] Jinghao Jia, Raj Sahu, Adam Oswald, Dan Williams, Michael V. Le, and Tianyin Xu, "Kernel Extension Verification is Untenable," HotOS 2023. DOI: `10.1145/3593856.3595892`.
- [Rex 2025] Jia et al., Rex, USENIX ATC 2025.
- [Pretty Verifier 2025] Pretty Verifier, Politecnico di Torino, 2025.
- [Kgent 2024] Kgent, ACM SIGCOMM eBPF Workshop 2024. DOI: `10.1145/3672197.3673434`.
- [SimpleBPF 2025] SimpleBPF, 2025.
- [Gao et al. 2025] Xiangyu Gao et al., "Offloading the Tedious Task of Writing eBPF Programs," SIGCOMM eBPF Workshop 2025. DOI: `10.1145/3748355.3748369`.
- [Kernel Extension DSLs Should Be Verifier-Safe! 2025] "Kernel Extension DSLs Should Be Verifier-Safe!," 2025.
- [DepSurf 2025] DepSurf, 2025.
- [NCC/Linux Foundation 2024] NCC Group/Linux Foundation eBPF audit, 2024.
- [`ebpf-verifier-errors`] `parttimenerd/ebpf-verifier-errors` GitHub repository.
- [Kernel infrastructure] Existing kernel and libbpf mechanisms relevant to diagnostic extraction: BTF `line_info`, `BPF_PROG_LOAD` logging fields, libbpf line-info helpers, and `BPF_MAP_TYPE_INSN_ARRAY`.

## Research Gap Summary

Taken together, the literature shows a consistent pattern. Empirical studies, systems critiques, workaround analyses, and external audits all agree that verifier behavior is a major eBPF developer-experience bottleneck [Deokar et al. 2024] [Jia et al. 2023] [Rex 2025] [NCC/Linux Foundation 2024]. Existing improvement efforts either explain failures after the fact, make raw logs somewhat easier to read, or collect examples for human and AI reuse [Pretty Verifier 2025] [`ebpf-verifier-errors`]. LLM-based systems already rely on verifier output as an iterative signal, but they mostly consume raw text or avoid the problem by narrowing the programming model to a DSL [Kgent 2024] [SimpleBPF 2025] [Kernel Extension DSLs Should Be Verifier-Safe! 2025].

What is still missing is a stable, programmatic diagnostic layer for general-purpose eBPF development. In particular, the provided works do not supply a durable interface that turns verifier failures into typed error identifiers, source spans, and explicit missing obligations, even though existing kernel infrastructure already exposes much of the raw information needed to build such a layer [Kernel infrastructure]. That is the gap OBLIGE fills: it sits between opaque verifier internals and downstream humans or agents, turning free-text failures into structured obligation-oriented diagnostics that can support debugging, repair, evaluation, and longitudinal tooling across kernel versions.
