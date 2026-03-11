# Literature Survey for OBLIGE

This survey focuses on prior work most relevant to OBLIGE: structured, source-aware, machine-usable diagnostics for the Linux eBPF verifier. The recurring pattern across the literature is consistent: verifier failures are a real developer bottleneck; existing systems either consume the verifier's raw text heuristically, avoid the verifier through DSLs, or redesign the programming model entirely. OBLIGE fits into the gap between those approaches by targeting the current verifier stack directly and turning existing low-level signals into structured diagnostics.

Unless noted otherwise, citations below use primary sources. For two 2025 projects, the publicly accessible sources I could verify were project papers/repos rather than a formal venue page; I call that out explicitly.

## 1. eBPF Community Pain Points: the 2024 Stack Overflow study

**Citation.** Mugdha Deokar, Jingyang Men, Lucas Castanheira, Ayush Bhardwaj, and Theophilus A. Benson. *An Empirical Study on the Challenges of eBPF Application Development.* In *Proceedings of the SIGCOMM Workshop on eBPF and Kernel Extensions*, 2024, pp. 1-8. DOI: `10.1145/3672197.3673429`.  
Paper: https://doi.org/10.1145/3672197.3673429  
Official workshop slides with detailed figures: https://pchaigno.github.io/assets/ebpf24-slides/ebpf24_slides-deokar.pdf

**Key findings relevant to OBLIGE.**

- The study analyzes **743 Stack Overflow questions** tagged `bpf`.
- The authors classify questions along four dimensions: **hook point type**, **ecosystem**, **development process**, and **programming language**.
- In the **ecosystem-focused breakdown** shown in the official slide deck, the main problem buckets are:
  - **eBPF tools and utilities**: **42.0%**
  - **error handling and verifier messages**: **19.3%**
  - **kernel integration and cgroup usage**: **16.6%**
  - **eBPF maps**: **11.0%**
  - **performance and optimizations**: **7.1%**
  - **others**: **4.0%**
- The stacked ecosystem-by-stage chart in the same slide deck shows **66 verifier/error-handling questions** broken down as **55 debugging**, **5 design**, and **6 development** cases.
- The study's broader conclusion is that eBPF development pain is not just about writing packet logic or tracing logic; a large fraction of pain sits in the surrounding toolchain and the verifier-facing development workflow.

**What gap it leaves.**

- The study identifies pain points, but it does not provide a new diagnostic mechanism.
- It shows that verifier-related pain is substantial, but it stops at categorization rather than converting verifier failures into structured, actionable, source-linked output.

**How OBLIGE positions against it.**

- This paper is evidence that OBLIGE is solving a real, community-observed problem, not an edge case.
- OBLIGE directly targets the verifier/error-message slice that the study isolates, while also helping with adjacent tooling pain by producing diagnostics that IDEs, CLIs, agents, and documentation systems can consume.

## 2. HotOS 2023: *Kernel Extension Verification is Untenable*

**Citation.** Jinghao Jia, Raj Sahu, Adam Oswald, Dan Williams, Michael V. Le, and Tianyin Xu. *Kernel Extension Verification is Untenable.* In *Proceedings of the 19th Workshop on Hot Topics in Operating Systems (HotOS '23)*, 2023, pp. 150-157. DOI: `10.1145/3593856.3595892`.  
DOI page: https://doi.org/10.1145/3593856.3595892

**Key findings relevant to OBLIGE.**

- The paper frames kernel-extension systems as a four-way tradeoff among **safety**, **development burden**, **performance**, and **functionality**.
- Its central argument is that eBPF's verifier-centric model is hitting **diminishing returns**: as the extension surface grows, the verifier must become more complex, and that complexity raises both implementation risk and developer burden.
- The paper argues that **ubiquitous verification is a poor fit** for rich in-kernel extension systems.
- Instead, it advocates a **language approach**: move more of the safety burden into the programming language, compiler, and trusted abstractions rather than trying to verify increasingly rich low-level programs after the fact.

**What gap it leaves.**

- The paper is fundamentally a critique and a design argument; it does not improve today's verifier UX.
- It does not help developers who must still ship against the current Linux verifier, current loaders, and current C/Rust eBPF workflows.

**How OBLIGE positions against it.**

- OBLIGE is **complementary**, not contradictory.
- HotOS argues that verifier-centric ecosystems do not scale indefinitely; OBLIGE addresses the near-term reality that the verifier exists today, is widely deployed, and remains a central source of friction.
- If the ecosystem moves toward more language-based safety, structured diagnostics are still useful for compilers, language runtimes, migration tools, and mixed low-level/high-level extension stacks.

## 3. Rex (USENIX ATC 2025)

**Citation.** Jinghao Jia, Ruowen Qin, Milo Craun, Egor Lukiyanov, Ayush Bansal, Minh Phan, Michael V. Le, Hubertus Franke, Hani Jamjoom, Tianyin Xu, and Dan Williams. *Rex: Closing the Language-Verifier Gap with Safe and Usable Kernel Extensions.* In *2025 USENIX Annual Technical Conference (USENIX ATC 25)*, 2025, pp. 325-342.  
USENIX page: https://www.usenix.org/conference/atc25/presentation/jia

**Key findings relevant to OBLIGE.**

- Rex studies **72 verifier-workaround commits** collected over **12 years**.
- The paper's Table 1 classifies workarounds into four main groups:
  - **44.4%**: change LLVM code generation to be more verifier-friendly
  - **36.1%**: rewrite logic into verifier-friendly but semantically equivalent code
  - **11.1%**: decompose code into helper functions or loops
  - **8.3%**: replace with a less efficient alternative
- The key result is not merely that developers made mistakes; it is that many programs were **intended to be safe** yet still had to be rewritten to satisfy verifier behavior.
- Rex treats this as a **language-verifier gap**: programmers write in the source language's natural style, but the verifier reasons about a lower-level form with different constraints.

**What gap it leaves.**

- Rex reduces pain by designing a safer, verifier-aware extension language and compilation strategy, but it does not solve diagnostics for the huge installed base of handwritten eBPF programs.
- It does not replace the need to explain verifier rejections in existing C/libbpf/bpftool workflows.

**How OBLIGE positions against it.**

- Rex is strong motivation for OBLIGE: its workaround study shows that verifier rejection is often not a simple "bug in the program," but a mismatch between intent and verifier reasoning.
- OBLIGE complements Rex by exposing that mismatch explicitly and structurally.
- Even in a Rex-like future, structured diagnostics remain useful for compiler debugging, fallback paths, unsupported patterns, and mixed-language ecosystems.

## 4. Pretty Verifier (Politecnico di Torino, 2025)

**Citation.** Sebastiano Miano, Roberto Lezzi, Gabriele Lospinoso, and Fulvio Risso. *Pretty Verifier: Towards Friendly eBPF Verification Errors.* Politecnico di Torino project paper and implementation repository, 2025. I could verify the title/authors from the publicly accessible project paper and the implementation from the public repository, but I did **not** find a separate venue page in the accessible sources.  
Implementation repository: https://github.com/netgroup-polito/pretty-verifier

**Key findings relevant to OBLIGE.**

- Pretty Verifier is the closest prior work in spirit to OBLIGE's user-facing goal.
- It improves verifier UX by combining:
  - the original **`.c` source**
  - the compiled **`.o` object file**
  - the raw **verifier log**
  - an internal **knowledge base** of verifier logic and common failure modes
- Its implementation maps verifier instruction numbers back to C source using **`llvm-objdump --disassemble -l`** over the object file's debug information, then emits a source-level error message and often a fix hint.
- The project paper reports **79 distinct verifier error message types**. The current public repository has evolved further and now contains **83 enumerated handlers**, which suggests the handler set continued to expand after the paper snapshot.

**Methodology.**

- The repository README states that the tool consumes source, object, verifier output, and an internal knowledge base.
- The implementation is largely **pattern driven**: `handler.py` matches raw verifier strings with regular expressions and routes them to error-specific renderers.
- The source mapper in `utils.py` reconstructs source locations from the object's debug/disassembly view and stitches those locations back into the reported verifier trace.

**Limitations relevant to OBLIGE.**

- The README states that the tool works best on **kernel 6.8** and only **partially** on older/newer kernels.
- Because it is fundamentally driven by **raw verifier text patterns**, it is vulnerable to kernel-version wording changes.
- It requires the user to have the **source file** and **debuggable object file** available.
- It is primarily a **C/source-level post-processor**, not a stable machine-readable interface for agents, IDEs, or downstream tooling.

**What gap it leaves.**

- Pretty Verifier improves presentation, but the diagnostic substrate is still **unstructured text** plus heuristics.
- It does not define a stable schema for failure class, source span, verifier state, semantic expectation, or repair metadata.

**How OBLIGE positions against it.**

- Pretty Verifier is best viewed as a strong precursor on the **consumer side** of the problem.
- OBLIGE should position itself as a more fundamental, **producer-side** improvement: structured diagnostics emitted from or near the verifier/runtime boundary itself, so tools like Pretty Verifier no longer need to reverse-engineer unstable text logs.

## 5. Kgent (eBPF Workshop 2024)

**Citation.** Yusheng Zheng, Yiwei Yang, Maolin Chen, and Andrew Quinn. *Kgent: Kernel Extensions Large Language Model Agent.* In *Proceedings of the SIGCOMM Workshop on eBPF and Kernel Extensions*, 2024, pp. 30-36. DOI: `10.1145/3672197.3673434`.  
DOI page: https://doi.org/10.1145/3672197.3673434

**Key findings relevant to OBLIGE.**

- Kgent is an early agentic eBPF synthesis system that places the verifier directly inside an **LLM synthesis loop**.
- Its architecture has four relevant pieces:
  - a **prompter** that prepares the code-generation prompt
  - an **LLM** that generates candidate eBPF code
  - a **compiler/loader** that compiles and attempts to load the program
  - a **verifier-feedback loop** that retries if the verifier rejects the candidate
- On failure, Kgent appends the **previous code** and **all verifier error messages** to the next prompt and asks the model to try again.
- The paper reports that Kgent can generate roughly **1.2K lines of eBPF code in about three minutes**, solves **9/10 tasks**, and averages about **30% success across 10 runs**.

**Why the verifier-feedback mechanism matters to OBLIGE.**

- Kgent treats verifier output as a repair signal, which is directly aligned with OBLIGE's research direction.
- But the feedback channel is just **raw text appended verbatim** to the next prompt.

**Limitations of raw text feedback.**

- The feedback is **not source-linked**.
- It is **not structured** into failure type, object, location, or expected invariant.
- It is potentially **token-heavy** and sensitive to wording changes across kernels.
- It forces the LLM to infer semantics from prose that was not designed for machines.

**What gap it leaves.**

- Kgent demonstrates demand for machine-consumable verifier feedback, but it does not change the feedback substrate itself.

**How OBLIGE positions against it.**

- OBLIGE is not another synthesis agent; it is infrastructure that could make Kgent-like systems materially better.
- A structured diagnostic schema would let an agent consume fields such as source span, failing instruction, pointer/register state, missing check, map/helper/context assumptions, and repair hints directly instead of re-parsing prose logs.

## 6. SimpleBPF (2025)

**Citation.** Xiangyu Gao, Xiangfeng Zhu, Bhavana Vannarth Shobhana, Yiwei Yang, Arvind Krishnamurthy, and Ratul Mahajan. *Offloading the Tedious Task of Writing eBPF Programs.* In *Proceedings of the 3rd Workshop on eBPF and Kernel Extensions*, 2025, pp. 63-69. DOI: `10.1145/3748355.3748369`. The paper introduces the **SimpleBPF** system.  
DOI page: https://doi.org/10.1145/3748355.3748369

**Key findings relevant to OBLIGE.**

- SimpleBPF takes a different route from diagnostic tooling: it tries to **avoid** verifier debugging by moving developers into a **high-level DSL**.
- Its pipeline is:
  - natural-language intent
  - LLM generation of a **SimpleBPF DSL** program
  - a **semantic checker**
  - compilation from DSL to eBPF C
  - compilation/loading into the kernel
- The semantic checker is important: the paper reports that it catches **44%** of incorrect DSL programs and avoids **42%** of otherwise useless verifier interactions.
- The paper also reports that their initial verifier-driven retry mechanism was **not effective**; on verifier rejection, their best fallback is to **restart generation** instead of deeply repairing the rejected program.

**How it sidesteps verifier debugging.**

- The main idea is to perform domain-specific validation before generating general-purpose eBPF C.
- That means many errors are stopped in the DSL layer rather than being debugged as raw verifier failures.

**What gap it leaves.**

- SimpleBPF is domain- and abstraction-specific; it does not improve diagnostics for arbitrary handwritten eBPF programs.
- Its own evaluation effectively confirms that raw verifier logs are a poor repair substrate for LLM workflows.

**How OBLIGE positions against it.**

- OBLIGE complements DSL systems like SimpleBPF rather than competing with them.
- If structured verifier diagnostics existed, systems like SimpleBPF could use them for targeted repair instead of discarding a failed attempt and restarting generation.
- OBLIGE also addresses the much broader population of existing C/libbpf/bpftool users that DSLs do not replace.

## 7. Verifier-safe DSL proposals (2025)

**Citation.** Franco Solleza, Justus Adam, Akshay Narayan, Malte Schwarzkopf, Andrew Crotty, and Nesime Tatbul. *Kernel Extension DSLs Should Be Verifier-Safe!* In *Proceedings of the 3rd Workshop on eBPF and Kernel Extensions*, 2025, pp. 55-62. DOI: `10.1145/3748355.3748368`.  
DOI page: https://doi.org/10.1145/3748355.3748368

**Key findings relevant to OBLIGE.**

- This paper makes the argument that a kernel-extension DSL compiler should generate code that is **not merely semantically correct**, but specifically **accepted by the verifier**.
- The paper points out that conventional compiler optimizations can transform DSL programs into low-level eBPF that is still semantically equivalent but becomes **verifier-hostile**.
- The practical consequence is important: if the compiler emits verifier-rejected code, then the DSL no longer shields users from verifier complexity.
- The paper therefore argues for **verifier-safe compilation** as a design requirement for DSL-based kernel extensions.

**What gap it leaves.**

- This approach helps when a DSL owns the entire frontend and code-generation pipeline.
- It does not help the enormous amount of existing handwritten eBPF code, nor does it help explain verifier failures when they do occur.

**How OBLIGE positions against it.**

- OBLIGE is broader and lower-level.
- Verifier-safe DSLs are one way to reduce failures; OBLIGE makes failures understandable and machine-usable when they still happen.
- OBLIGE could also support verifier-safe compilers by providing a structured signal about exactly which verifier invariant or dataflow fact was violated.

## 8. DepSurf (2025)

**Citation.** Junxiao Zhang, Samantha Mathews, Hiep Nguyen, Ryan Stutsman, and Asaf Cidon. *DepSurf: Measuring and Analyzing the Dependency Surface of Kernel Extensions.* Public project paper and project site, 2025. I verified the title/authors and key claims from the public project materials and paper PDF, but I did **not** find a separate formal venue page in the accessible sources.  
Project site: https://sites.google.com/view/depsurf-bpf/home

**Key findings relevant to OBLIGE.**

- DepSurf studies the **dependency surface** of kernel extensions: not just explicit eBPF API usage, but also the hidden assumptions extensions make about kernel behavior and surrounding infrastructure.
- Its headline result is that **83%** of the evaluated extensions are affected by at least one **kernel mismatch**.
- The paper argues that these mismatches are not benign; they can lead to **compatibility**, **safety**, and **performance** problems when extensions move across kernel versions or environments.

**Implications for structured diagnostics.**

- Verifier diagnostics that talk only about a local rejected instruction are incomplete for cross-kernel use cases.
- Inference from DepSurf's result: good diagnostics should also surface **which dependency assumptions were in play**:
  - hook-point expectations
  - helper availability
  - map/type expectations
  - BTF/type-layout assumptions
  - kernel-version and subsystem context

**What gap it leaves.**

- DepSurf identifies the compatibility problem, but it does not define a verifier-facing diagnostic format that exposes these dependencies at load time.

**How OBLIGE positions against it.**

- OBLIGE can position itself as the **diagnostic complement** to DepSurf's analysis.
- DepSurf explains why cross-kernel failures are common; OBLIGE can make those failures inspectable by surfacing structured kernel-version- and dependency-aware metadata instead of a flat log string.

## 9. NCC / Linux Foundation 2024 verifier audit

**Citation.** NCC Group. *eBPF Verifier Code Audit.* Sponsored by The Linux Foundation, 2024.  
Linux Foundation announcement and report link: https://www.linuxfoundation.org/press/linux-foundation-releases-open-source-technology-security-audit-of-the-ebpf-verifier

**Key findings relevant to OBLIGE.**

- The audit's documentation finding is directly relevant: it says that additional details on **what the verifier enforces and why** should be added to the documentation.
- The report explicitly notes that verifier documentation already exists, but is often **incomplete** or **too specific**.
- This matters because it independently validates the same pain point seen in community studies and developer tooling projects: the verifier's behavior is hard to understand from today's documentation and logs.

**What gap it leaves.**

- The audit diagnoses the clarity problem, but it does not propose a concrete runtime/tooling interface for solving it.

**How OBLIGE positions against it.**

- OBLIGE can be framed as **executable documentation** for verifier reasoning.
- Instead of only expanding prose docs, OBLIGE would expose the verifier's reasoning as structured data at the point where developers actually need it: compile/load/debug time.

## 10. `ebpf-verifier-errors` GitHub repository

**Citation.** `parttimenerd`. *ebpf-verifier-errors.* GitHub repository, ongoing. Accessed 2026-03-11.  
Repository: https://github.com/parttimenerd/ebpf-verifier-errors

**What it collects.**

- The repository collects verifier failures as **GitHub issues**, with one issue per submission.
- The issue template captures:
  - **cause description**
  - **cause code**
  - **verifier error log**
  - **solution description**
  - **solution code**
  - **source**
  - **kernel version**
  - **clang version**
  - **additional remarks**

**Its stated goal.**

- The README states that verifier errors, code context, and resolutions should be collected so they can be **searched by others** and used as a **data source for tooling**.

**Why it matters to OBLIGE.**

- This repository is evidence that the community already sees verifier failures as a reusable **diagnostic corpus** rather than a purely local debugging nuisance.
- It is especially relevant for AI- and tool-oriented work because it pairs failures with **before/after code** and remediation narratives.

**What gap it leaves.**

- The repository is still a **manual, crowdsourced, issue-based** collection.
- The data is not emitted from the verifier in a stable schema, so quality and completeness vary by submitter.
- It is excellent as a seed corpus, but not a replacement for a structured diagnostic interface.

**How OBLIGE positions against it.**

- OBLIGE can use such repositories as evaluation data or training data, but its main contribution is different: generate structured diagnostics **at source**, not after ad hoc manual reporting.

## 11. Kernel infrastructure relevant to OBLIGE

This section matters because OBLIGE does not need to invent all of its plumbing from scratch. Linux and libbpf already expose several ingredients that are diagnostic-adjacent, but they are fragmented.

### 11.1 BTF `line_info` and `.BTF.ext`

**Citation.** Linux kernel documentation. *BPF Type Format (BTF).*  
Docs: https://docs.kernel.org/bpf/btf.html

**Relevant facts.**

- BTF was extended beyond type info to include **function info** and **line info**.
- During `BPF_PROG_LOAD`, userspace can pass:
  - `func_info`
  - `func_info_cnt`
  - `line_info`
  - `line_info_cnt`
  - `line_info_rec_size`
- The kernel documentation defines `struct bpf_line_info` with:
  - `insn_off`
  - `file_name_off`
  - `line_off`
  - `line_col`
- The same documentation states that `bpf_prog_info` can later return **line info** for translated bytecode and **jited_line_info** for JIT output.
- The BTF docs explicitly say line info can help **debugging verification failure**.

**Why this matters to OBLIGE.**

- This is a kernel-supported path from instruction offsets to source locations.
- OBLIGE can build on BTF line info to make diagnostics source-aware without relying only on post hoc text parsing.

### 11.2 `BPF_PROG_LOAD` verifier log interface

**Citation.** Linux manual page. *bpf(2).*  
Man page: https://man7.org/linux/man-pages/man2/bpf.2.html

**Relevant facts.**

- `BPF_PROG_LOAD` accepts three core logging fields:
  - `log_level`
  - `log_size`
  - `log_buf`
- `log_buf` receives the verifier's multi-line rejection log.
- `log_level = 0` disables logging; nonzero logging requires a caller-provided buffer.
- If the buffer is too small, the call can fail with **`ENOSPC`**.
- The man page explicitly warns that verifier output is intended for program authors and may evolve over time; in other words, it is **not a stable structured API**.

**Why this matters to OBLIGE.**

- This is the current de facto interface that all higher-level tools consume.
- OBLIGE should be framed as an improvement over this unstable text channel, not a reinvention of how programs are loaded.

### 11.3 libbpf line-info helpers

**Citation.** eBPF Docs / libbpf userspace API. *`bpf_prog_linfo__new`.*  
Docs: https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_prog_linfo__new/

**Relevant facts.**

- `bpf_prog_linfo__new(const struct bpf_prog_info *info)` returns a `struct bpf_prog_linfo *`.
- The docs describe it as getting the **line info for a BPF program**.
- The resulting structure exposes:
  - `raw_linfo`: original-program line-info records
  - `raw_jited_linfo`: JITed-program line-info records
  - per-function counts/indexes
  - record sizes and total counts
- The documentation notes that the original line-info instruction offsets are relative to the **program before loading**, while JITed line info refers to the **JITed program**.

**Why this matters to OBLIGE.**

- libbpf already exposes a convenient userspace wrapper for the line-info machinery.
- OBLIGE can leverage this instead of rebuilding raw `bpf_prog_info` parsing itself.

### 11.4 `BPF_MAP_TYPE_INSN_ARRAY`

**Citation.** eBPF Docs. *Map type `BPF_MAP_TYPE_INSN_ARRAY`.*  
Docs: https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_INSN_ARRAY/

**Relevant facts.**

- This map type is designed to track instruction-offset changes from:
  - original bytecode
  - translated bytecode
  - JITed bytecode
- The current docs say it is useful for mapping **JITed instructions back to original eBPF instructions**, which can then be tied further back to source using **BTF line info and/or DWARF**.
- The docs mark it as a **v6.19** feature and note that the documentation is still incomplete because more kernel use cases are expected.

**Why this matters to OBLIGE.**

- This is highly relevant to future-proof structured diagnostics, especially for correlating verifier/load-time reasoning with post-load profiling or JIT-level observations.
- It gives OBLIGE a path toward richer instruction identity across compilation stages.

## Research Gap Summary

Across these papers and projects, the gap is now clear.

- Community evidence shows that verifier-facing debugging is a real and nontrivial source of eBPF development pain.
- Systems papers such as HotOS 2023 and Rex show that the problem is structural: the verifier is both essential and a source of false rejection, workaround churn, and language/verifier mismatch.
- Tools such as Pretty Verifier and Kgent prove that developers and agents want better verifier feedback, but both still consume the verifier's **raw text** and reconstruct meaning heuristically.
- DSL efforts such as SimpleBPF and verifier-safe compiler work reduce exposure to verifier pain, but they do so by **avoiding** or **containing** the problem, not by solving diagnostics for the general ecosystem.
- DepSurf and the NCC audit add a second requirement: diagnostics must be not only human-readable, but also **kernel-aware**, **dependency-aware**, and useful across versions and environments.
- Linux already exposes useful primitives such as `log_buf`, BTF `line_info`, libbpf line-info helpers, and instruction-offset mapping infrastructure, but these are not assembled into a coherent structured diagnostic interface.

**OBLIGE's research niche** is therefore not "yet another prettier log parser," not "yet another eBPF DSL," and not "replace the verifier." Its niche is:

- turning verifier failures into **structured diagnostics**
- making them **source-aware**
- making them **machine-consumable**
- carrying enough **kernel/dependency context** to be useful across kernels
- and serving as a substrate for humans, IDEs, CI systems, LLM agents, compiler pipelines, and future verifier-safe tooling.

That combination is exactly what the existing literature points to but does not yet provide.
