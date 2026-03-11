# OBLIGE：计划与进度

> 本文档是 OBLIGE 项目的单一 hub。
> **编辑规则**：
> - 任何 TODO/实验/文档引用条目被取代时，必须至少保留一行并标注状态，不得直接删除。
> - 每个任务做完 → 立即更新本文档（任务条目状态 + 关键数据 + 文档路径）。
> - 每次 context 压缩后 → 完整读取本文档恢复全局状态。
> - 用 codex background 跑任务，不阻塞主对话。
> 上次更新：2026-03-11 (方向再调整：Rust-style multi-span diagnostics via proof trace meta-analysis)

---

## 1. 论文定位与策略

### 1.1 核心 Thesis：Rust-Quality Diagnostics via Proof Trace Meta-Analysis（2026-03-11 再调整）

> **旧 thesis（已放弃）**：verifier 缺少诊断信息，需要 kernel-side hooks 暴露 abstract state。
> **第一次调整**：发现 LOG_LEVEL2 已有完整 abstract state，问题是 unstructured。做 proof trace analysis。
> **第二次调整（当前）**：分类准确率不是贡献（LLM 已做到 95%+）。真正的贡献是 **diagnostic output 的质量**——类比 Rust 的 borrow checker 错误信息。

> **当前 thesis**：
> eBPF verifier 的 LOG_LEVEL2 trace 是 abstract interpretation 的完整输出，包含 proof lifecycle 的所有信息（proof 在哪里建立、传播、丢失）。
> OBLIGE 对这个 trace 做 **meta-analysis**——backward slicing、proof obligation inference、proof propagation tracking——然后结合 BTF source annotation，生成 **Rust-quality multi-span source-level diagnostics**。
>
> **关键类比**：Rust borrow checker 无法证明内存安全 → 指出多个源码位置 + 因果标签（"borrow occurs here", "conflict here"）。
> eBPF verifier 无法证明程序安全 → OBLIGE 做同样的事：指出 proof-established、proof-lost、rejected 的源码位置。
> 纯 userspace，不需要改 kernel。

**OBLIGE 输出示例**：
```
error[OBLIGE-E005]: lowering_artifact — packet access with lost bounds proof
  ┌─ xdp_prog.c
   │
38 │     if (data + ext_len <= data_end) {
   │         ─────────────────────────── proof established
   │         R3: pkt(range=0) → pkt(range=14)
   │
42 │     __u16 ext_len = __bpf_htons(ext->len);
   │                     ────────────────────── proof lost: OR destroys bounds
   │                     R0: scalar(umax=255) → scalar(unbounded)
   │
45 │     void *next = data + ext_len;
   │                  ─────────────── rejected: pkt_ptr + unbounded
   │
   = note: Bounds check exists (line 38) but LLVM's lowering breaks it.
   = help: Add explicit clamp: if (ext_len > 1500) return XDP_DROP;
```

#### Verifier Log 已有的信息（LOG_LEVEL2）

```
; __u16 ext_len = __bpf_htons(ext->len);     ← BTF source line annotation
19: (71) r6 = *(u8 *)(r0 +2)                 ← instruction
20: R0=pkt(id=0,off=2,r=6)                   ← 完整 register abstract state
    R6_w=inv(id=0,umax_value=255,                (type, bounds, offset, range)
    var_off=(0x0; 0xff))
...
22: (4f) r0 |= r6                            ← critical transition
23: R0_w=inv(id=0)                            ← bounds 丢失！
...
math between pkt pointer and register with    ← final error (症状，不是原因)
unbounded min value is not allowed
```

**已有**：per-instruction register state (type/bounds/offset/range/var_off)、BTF source lines、backtracking annotations、control flow merge points

**缺失的（OBLIGE 要提取的）**：
1. Critical state transition — 在哪条指令 proof 丢失了（上例：insn 22 的 OR）
2. Causal chain — 从 error point 反向追溯到 root cause instruction
3. Source mapping — critical transition 对应源码哪一行
4. Error classification — stable error type（不是 free-text message）
5. Repair guidance — 应该怎么改

#### 类比定位

| 系统 | 输入 | 做了什么 | 没做什么 |
|------|------|----------|----------|
| Pretty Verifier (GitHub tool, 未发表) | error message 那一行 | regex 匹配 + source mapping | 不分析 state trace，跨版本 break |
| Model checking counterexample analysis | counterexample trace | 提取 property violation 原因 | 不适用于 eBPF abstract interpreter |
| **OBLIGE** | **完整 verifier state trace** | **state transition analysis + causal chain** | — |

#### 论文逻辑链条（更新版）

1. eBPF 广泛部署，verifier 必须拒绝不安全程序
2. 拒绝时 verifier 输出 verbose log（LOG_LEVEL2）包含完整 abstract state trace
3. 这个 trace 有时 500-1000+ 行，开发者无法有效利用
4. **Semantic opacity 的根源不是信息缺失，而是 unstructured trace 中的 needle-in-haystack**
5. 现有工具（Pretty Verifier）只 parse error message 那一行，忽略了 trace 里的丰富 state 信息
6. LLM agent（Kgent）直接消费 raw text，同样受限于 trace 噪音
7. **OBLIGE 解析完整 proof trace，提取 critical transition + causal chain + structured diagnosis**
8. 纯 userspace，不改 kernel，今天就能部署

### 1.2 Novelty（2026-03-11 再调整）

**核心 novelty（不是分类准确率——LLM 已做到 95%+）**：
1. **Meta-analysis of abstract interpretation output** — verifier 做了 abstract interpretation，OBLIGE 对其输出再做 backward slicing + proof propagation。这是"分析的分析"，在 eBPF 领域首创
2. **Leveraging verifier's own `mark_precise` backtracking** — verifier 内部的 precision tracking（`last_idx`, `first_idx`, `regs=`, `before N:` ）是 verifier 自己算好的根因链，但只以 debug text 暴露。OBLIGE 提取并结构化它
3. **Rust-quality multi-span diagnostics for eBPF** — 多个源码位置 + 因果标签（proof established / propagated / lost / rejected）。没有人做过
4. **Proof obligation inference from verifier's type system** — 对每种访问类型，从 error message + register state 推导 "verifier 需要什么条件"（packet: `reg.off+size <= reg.range`）。不是启发式，是基于 verifier 类型系统
5. **Proof propagation analysis** — 从 proof-establishing branch 正向追踪：proof 是否传播到实际访问的 register？没有传播 → lowering artifact。没有建立 → source bug
6. **实证研究** — 64% of 591 production commits 是 proof-reshaping workaround，不是 source bug fix

**与 Pretty Verifier 的本质差异**：
- Pretty Verifier：parse **1 行** error message（91 regex）→ 1 个 enhanced text + 1 个建议
- OBLIGE：parse **500 行** state trace → **多个源码位置** + 因果链 + proof lifecycle + 结构化 JSON

**Go 条件（全部满足才提交）**：
1. Benchmark ≥80 个 labeled cases，覆盖全 5 类 ✅ 302 cases, 30 labeled
2. Rust-style multi-span diagnostic engine end-to-end 跑通 ❌（codex 实现中）
3. OBLIGE 输出的 source spans 覆盖实际 fix 位置（vs PV: 1 span only）❌
4. A/B repair experiment：OBLIGE 输出 + LLM vs raw log + LLM，修复质量差异 ❌
5. 信息压缩质量：500 行 → 3-5 个带标签的源码跨度，expert 评估 sufficiency ❌

### 1.3 与 existing work 的关键差异

| Work | 做了什么 | 没做什么（我们的空位） |
|------|----------|----------------------|
| Deokar et al. (eBPF'24) | 743 SO 问题，19.3% verifier | 只描述痛点 |
| HotOS'23 | Verifier untenable 论证 | 没提出新工具 |
| Rex (ATC'25) | 72 workaround commits 分类 | 回顾性分析，不是工具 |
| Pretty Verifier (GitHub, 未发表) | 83 regex handlers + source mapping | **只 parse error message，不分析 state trace**；跨版本 break |
| Kgent (eBPF'24) | verifier text → LLM loop | raw text 限制质量 |
| SimpleBPF / verifier-safe DSL | DSL 绕开 verifier | 只覆盖 DSL 子集 |
| ebpf-verifier-errors | 社区收集 log+fix | 手动, 无分析工具 |

### 1.4 核心设计约束

1. **纯 userspace** — 不需要 kernel patch，解析现有 verbose log
2. **Agent 是 application，不是 contribution** — 论文贡献是 trace analysis，不是 agent
3. **分析 state trace，不只是 error message** — 这是与 Pretty Verifier 的核心区别
4. **Passes verifier ≠ semantic correctness** — 必须有 task-level oracle
5. **Register state format stability > error message stability** — 跨版本稳定性的基础

---

## 2. 五类 Failure Taxonomy

| Class | 含义 | 典型信号 | 占比 |
|-------|------|----------|:---:|
| `source_bug` | 源码真缺 bounds/null/refcount check | "invalid access to packet", "invalid mem access" | **88.1%** (266/302 heuristic) |
| `lowering_artifact` | LLVM 生成 verifier-unfriendly bytecode | "unbounded min value" after spill/reload | **4.0%** (12/302) |
| `verifier_limit` | 程序安全但超了分析能力 | "too many states", "loop not bounded" | **1.3%** (4/302) |
| `env_mismatch` | helper/kfunc/BTF/attach target 不匹配 | "unknown func", "helper not allowed" | **6.3%** (19/302) |
| `verifier_bug` | verifier 自己的 bug | regression across versions | **0.3%** (1/302) |

**人工验证**：30 cases labeled，heuristic agreement 76.7%（κ=0.652）。Lowering artifacts 系统性被误分类为 source_bug（4/6）。

**决策顺序**（消歧义时）：verifier_bug → env_mismatch → lowering_artifact → verifier_limit → source_bug

**完整定义**：`taxonomy/taxonomy.yaml`

---

## 3. Error Catalog

当前 23 个 stable error IDs（OBLIGE-E001 ~ E023），覆盖率 87.1%（263/302）。

| ID | Short Name | Class | Matches | 典型 verifier message |
|----|-----------|-------|:---:|----------------------|
| E001 | packet_bounds_missing | source_bug | 18 | "invalid access to packet" |
| E002 | nullable_map_value_dereference | source_bug | 8 | "invalid mem access 'map_value_or_null'" |
| E003 | uninitialized_stack_read | source_bug | 9 | "invalid indirect read from stack" |
| E004 | reference_lifetime_violation | source_bug | 17 | "Unreleased reference id=" |
| E005 | scalar_range_too_wide_after_lowering | lowering_artifact | 23 | "unbounded min value" |
| E006 | provenance_lost_across_spill | lowering_artifact | 0 | "expected pointer type, got scalar" |
| E007 | verifier_state_explosion | verifier_limit | 1 | "too many states" |
| E008 | bounded_loop_not_proved | verifier_limit | 1 | "loop is not bounded" |
| E009 | helper_or_kfunc_unavailable | env_mismatch | 3 | "unknown func" |
| E010 | verifier_regression_or_internal_bug | verifier_bug | 1 | "kernel BUG at" |
| E011 | scalar_pointer_dereference | source_bug | 38 | "invalid mem access 'scalar'" |
| E012 | dynptr_protocol_violation | source_bug | 22 | "Expected an initialized dynptr" |
| E013 | execution_context_discipline | source_bug | 19 | "cannot restore irq state" |
| E014 | iterator_state_protocol | source_bug | 10 | "expected an initialized iter_num" |
| E015 | trusted_arg_nullability | source_bug | 8 | "Possibly NULL pointer passed" |
| E016 | helper_kfunc_context_restriction | env_mismatch | 12 | "cannot be called from callback" |
| E017 | map_value_bounds_violation | source_bug | 1 | "invalid access to map value" |
| E018 | verifier_analysis_budget_limit | verifier_limit | 2 | "combined stack size" |
| E019-E023 | (round 2 expansion) | mixed | 59 | various |

**完整定义**：`taxonomy/error_catalog.yaml`

---

## 4. Proof Trace Analysis（新核心）

### 4.1 Verifier state trace 包含什么

每条指令的 register state dump：
```
R0=pkt(id=0,off=2,r=6,imm=0)    → type=pkt, offset=2, range=6
R1=inv(id=0,umax=255,var_off=(0x0;0xff))  → type=scalar, bounds=[0,255]
fp-8=map_value(off=0,ks=4,vs=8)  → stack slot, map value pointer
```

Control flow annotations：
```
from 67 to 109: R0=inv0 R1_w=inv0 ...   → branch merge
last_idx 39 first_idx 36                  → backtracking
regs=1 stack=0 before 38: (c7) r0 s>>= 32  → which earlier insn affected current state
```

BTF source lines：
```
; if (data_end < (data + ext_len)) {      → source annotation
42: (bf) r3 = r1
```

### 4.2 OBLIGE Rust-Style Diagnostic Engine（实现中）

**Pipeline**：raw verifier log → 5 步 → Rust-style multi-span output

#### Step 1: Enhanced Backtracking Extraction
利用 verifier 自己的 `mark_precise` backtracking（已在 LOG_LEVEL2 中输出）：
```
last_idx 24 first_idx 12           ← 反向追踪范围
regs=1 stack=0 before 23: (dc) r0 = be16 r0    ← R0 (bit 0)
regs=41 stack=0 before 21: (67) r0 <<= 8       ← R0+R6 (bits 0,6)
```
提取为结构化 `BacktrackChain`，替代我们的启发式 causal chain。

#### Step 2: Proof Obligation Inference + Propagation
**义务推断**：从 error message + register state 推导 verifier 的 proof requirement：
- Packet: `reg.type==pkt && reg.off+size <= reg.range`
- Map value: `0 <= reg.off && reg.off+size <= value_size`
- Stack: `reg.off` within frame bounds
- Helper arg: `reg.type == expected_type`
- Null check: `reg.type != *_or_null`

**证明传播分析**：从 proof-establishing branch 正向追踪：
- 找到 narrowing branch（`if r5 > r2 goto` → R0.range 变窄）
- 追踪 proof 是否通过 copy/move 传播到实际被访问的 register
- 没有传播 → lowering artifact（compiler 用了不同 register）
- 没有建立 → source bug

#### Step 3: Source Correlation via BTF
- 从 trace 的 `; source_text @ file:line` 提取 BTF source mapping
- 每个 proof event（建立/传播/丢失/拒绝）映射到源码位置
- 连续 bytecode 指令合并为单个 source-level span

#### Step 4: Multi-Span Diagnostic Renderer
**Human-readable（Rust-style）**：多个源码位置 + 角色标签 + register state 变化 + note/help
**Structured JSON**（供 LLM/CI 消费）：
```json
{
  "error_id": "OBLIGE-E005",
  "taxonomy_class": "lowering_artifact",
  "proof_status": "established_then_lost",
  "spans": [
    {"role": "proof_established", "source": {"file": "xdp_prog.c", "line": 38},
     "insn_idx": 8, "source_text": "if (data + ext_len <= data_end)",
     "state_change": "R3: pkt(range=0) → pkt(range=14)"},
    {"role": "proof_lost", "source": {"file": "xdp_prog.c", "line": 42},
     "insn_idx": 22, "source_text": "__bpf_htons(ext->len)",
     "state_change": "R0: scalar(umax=255) → scalar(unbounded)",
     "reason": "OR operation merges byte values, destroying bounds"},
    {"role": "rejected", "source": {"file": "xdp_prog.c", "line": 45},
     "insn_idx": 24, "source_text": "void *next = data + ext_len",
     "state_change": "R5: pkt_ptr + unbounded scalar"}
  ],
  "obligation": {"type": "packet_access", "required": "reg.off+size <= reg.range"},
  "note": "Source has valid bounds check but LLVM lowering breaks it",
  "help": "Add explicit clamp: if (ext_len > 1500) return XDP_DROP;"
}
```

### 4.3 技术挑战

1. **Meta-analysis of abstract interpretation** — 对 verifier 输出的 per-instruction abstract state 做二阶分析（backward slicing + proof propagation）
2. **Leveraging `mark_precise`** — verifier 自己的 precision tracking 是最精确的根因链，但只以 debug text 暴露
3. **Proof obligation inference** — 从 error message pattern 推导形式化的 proof requirement，不是 pattern matching
4. **Source correlation** — BTF annotation 并非总是存在；需要 fallback 到 bytecode-level spans
5. **Information compression** — 500 行 → 3-5 个 spans，选择标准：proof lifecycle 的关键节点

---

## 5. Case Corpus 摘要

| 来源 | Cases | 特点 | 文档 |
|------|:---:|------|------|
| Kernel selftests | 200 (可扩展到 1026) | `__msg()` 标注 expected error；66 memory/bounds, 53 dynptr/iterator, 34 control-flow/locking, 25 ref lifetime, 12 nullability | `docs/tmp/selftests-collection-report.md` |
| Stack Overflow | 76 | 66 有 verifier log, 59 有源码, 66 有 fix description | `docs/tmp/stackoverflow-collection-report.md` |
| GitHub issues | 26 | Cilium 7, Aya 18, Katran 1；含 verifier regression case | `docs/tmp/github-collection-report.md` |
| **Total** | **302** | 目标 ≥80 labeled，实际远超 | — |

**注意**：302 cases 中有完整 verbose log（含 state trace）的主要是 SO 和 GitHub 来源。Kernel selftests 只有 expected error message，没有完整 state dump。后续需要补充 selftests 的完整 verbose log。

---

## 6. 评估计划（2026-03-11 再更新）

### 6.1 Required Baselines

1. `raw_verbose_log` — 原始 verifier LOG_LEVEL2 verbose output（500-1000+ 行）
2. `pretty_verifier` — PV 的 1 行 error + 1 条 suggestion（作为 existing tool baseline）
3. `oblige_diagnostic` — OBLIGE Rust-style multi-span output（structured JSON + text）

### 6.2 Required Questions（按优先级）

1. **Span coverage**: OBLIGE 输出的 source spans 是否覆盖了实际 fix 的位置？（vs PV: 1 span only）❌
2. **Information compression**: 500 行 → 3-5 个 labeled spans，expert 评估是否 sufficient？ ❌
3. **Repair guidance (A/B experiment)**: OBLIGE 输出 + LLM vs raw log + LLM，修复质量差异？ ❌
4. **Classification**: OBLIGE 分类准确率？（sanity check，不是主要贡献）✅ 23/30 (77%)
5. 跨 kernel 版本稳定性？ ❌（暂缓，先做 6.1-6.4）

### 6.3 A/B Repair Experiment Design（核心评估）

| | Condition A | Condition B |
|---|---|---|
| 输入 | buggy code + raw verifier log | buggy code + raw log + OBLIGE Rust-style output |
| LLM 任务 | 生成修复代码 | 生成修复代码 |
| 测量 1 | 修复是否通过 verifier？ | 修复是否通过 verifier？ |
| 测量 2 | 修复类型是否正确？（inline vs bounds check） | 修复类型是否正确？ |
| 测量 3 | 修复位置是否正确？（root cause vs symptom site） | 修复位置是否正确？ |

**关键预测**：在 lowering_artifact 上，Condition A 的 LLM 会在 symptom site 加 bounds check（错），Condition B 会在 root cause site 做 inline/rewrite（对）。

**Case selection**: 20-30 个有已知修复的 case（eval_commits），聚焦 lowering_artifact。

### 6.4 Required Metrics

- **Span coverage** — OBLIGE spans 覆盖 fix location 的比例
- **Information compression ratio** — 500 lines → N spans
- **Repair success rate** — A/B 条件下 fix 通过 verifier 的比例
- **Repair type accuracy** — fix 类型是否正确（inline vs bounds check vs loop rewrite）
- **Root cause localization** — root_cause span 指向修复发生的位置比例
- Trace analysis latency（overhead）

### 6.5 已完成的实验

| 实验 | 结果 | 文档 |
|------|------|------|
| PV comparison (30 cases) | OBLIGE 25/30 vs PV 19/30; root-cause 12/30 vs 0/30 | `docs/tmp/pretty-verifier-comparison.md` |
| LLM classification (22 cases) | 所有条件 95%+，confirms classification is NOT the contribution | `docs/tmp/llm-multi-model-experiment.md` |
| Diagnoser 30-case eval | 23/30 (77%), source_bug 9/13, lowering 5/6 | `docs/tmp/diagnoser-30case-evaluation.md` |
| Cross-log stability (33 cases) | 20/33 stable, 12/33 text-varies-but-id-stable | `docs/tmp/cross-log-stability-analysis.md` |
| Cross-kernel feasibility | QEMU/KVM feasible, Docker won't work, deferred | `docs/tmp/cross-kernel-feasibility-report.md` |

---

## 7. 文档索引

| 文档 | 路径 | 维护者 |
|------|------|:---:|
| **本文档（唯一 hub）** | `docs/research-plan.md` | Claude |
| 论文 outline | `docs/paper-outline.md` | Claude（需更新） |
| 文献综述 | `docs/tmp/literature-survey.md` | Codex |
| Selftests 收集报告 | `docs/tmp/selftests-collection-report.md` | Codex |
| SO 收集报告 | `docs/tmp/stackoverflow-collection-report.md` | Codex |
| GitHub 收集报告 | `docs/tmp/github-collection-report.md` | Codex |
| Taxonomy 覆盖分析 | `docs/tmp/taxonomy-coverage-report.md` | Codex |
| Catalog 扩展 R2 报告 | `docs/tmp/catalog-expansion-round2-report.md` | Codex |
| 人工标注 30 cases | `docs/tmp/manual-labeling-30cases.md` | Codex |
| Verifier source 分析 | `docs/tmp/verifier-source-analysis.md` | Codex |
| PV comparison 报告 | `docs/tmp/pretty-verifier-comparison.md` | Codex |
| LLM 实验报告 | `docs/tmp/llm-multi-model-experiment.md` | Codex |
| Diagnoser 30-case 评估 | `docs/tmp/diagnoser-30case-evaluation.md` | Codex |
| Cross-log 稳定性分析 | `docs/tmp/cross-log-stability-analysis.md` | Codex |
| Cross-kernel 可行性 | `docs/tmp/cross-kernel-feasibility-report.md` | Codex |
| Diagnoser 实现报告 | `docs/tmp/diagnoser-report.md` | Codex |
| Taxonomy 定义 | `taxonomy/taxonomy.yaml` | Codex |
| Error catalog | `taxonomy/error_catalog.yaml` | Codex |
| Obligation catalog | `taxonomy/obligation_catalog.yaml` | Codex |
| 诊断 JSON schema | `interface/schema/diagnostic.json` | Codex |

---

## 8. 任务追踪

> **规则**：
> - 所有重要数据和文档路径只在本列表维护，不在别处重复。
> - 每次执行 codex 都必须输出文档到 `docs/tmp/` 或 `eval/results/`，并在对应条目记录路径和关键数据。
> - 条目被取代时保留一行标注状态，不得删除。

### Phase 1: Case Collection ✅

| # | 任务 | 状态 | 关键数据 / 文档 |
|---|------|:---:|------|
| 1 | Repo scaffold + CLAUDE.md | ✅ | 34 files, ~4200 LOC。`CLAUDE.md` |
| 2 | 文献综述 | ✅ | 418 行，12 works，精确引用。`docs/tmp/literature-survey.md` |
| 3 | Taxonomy 定义（5 classes） | ✅ | 186 行 YAML，含 decision order、inclusion/exclusion signals。`taxonomy/taxonomy.yaml` |
| 4 | Error catalog（10 IDs） | ✅ | OBLIGE-E001~E010，覆盖 5 classes。`taxonomy/error_catalog.yaml` |
| 5 | Obligation catalog | ✅ | OBLIGE-O001~O023。`taxonomy/obligation_catalog.yaml` |
| 6 | 诊断 JSON schema | ✅ | 183 行，含 sourceSpan/abstractState/missingObligation/$defs。`interface/schema/diagnostic.json` |
| 7 | Log parser skeleton | ✅ | catalog-backed pattern matching + evidence collection。`interface/extractor/log_parser.py` |
| 8 | Benchmark collectors（3 scripts） | ✅ | ~1500 LOC total。`case_study/collect_{stackoverflow,kernel_selftests,github_issues}.py` + `case_study/collector_utils.py` |
| 9 | Kernel selftests collection | ✅ | **200 cases**。`docs/tmp/selftests-collection-report.md` |
| 10 | Stack Overflow collection | ✅ | **76 cases**。`docs/tmp/stackoverflow-collection-report.md` |
| 11 | GitHub issues collection | ✅ | **26 cases**。`docs/tmp/github-collection-report.md` |
| 12 | Taxonomy 覆盖分析 | ✅ | 14.6% → 87.1%（263/302）。`docs/tmp/taxonomy-coverage-report.md` |
| 13 | 人工标注 30 个高质量 case | ✅ | 76.7% agreement（κ=0.652）。`docs/tmp/manual-labeling-30cases.md` |
| 14 | Error catalog 扩展（两轮） | ✅ | 10→23 IDs。`docs/tmp/catalog-expansion-round2-report.md` |
| 15 | Rex 72 commits 手动收集 20-30 个 | ❌ | 暂缓，优先做 proof trace analysis |

### Phase 2: Proof Trace Analysis

| # | 任务 | 状态 | 关键数据 / 文档 |
|---|------|:---:|------|
| 20 | Verifier source analysis（kernel/bpf/verifier.c） | ✅ | 90 check_\* 函数，547 verbose() calls。`docs/tmp/verifier-source-analysis.md` |
| 21 | Check function → failure class mapping | ✅ | 77 个 check_\* crosswalk。`docs/tmp/verifier-source-analysis.md` |
| 22 | ~~Stable error_id namespace 设计~~ | ✅ | 23 error IDs (E001-E023), 87.1% coverage. `taxonomy/error_catalog.yaml` |
| 23 | ~~Diagnostic information loss 分析~~ | 替换为 #25 | |
| 25 | **Verbose log 信息量分析** | ❌ | 量化：case corpus 中有多少有完整 state trace？trace 平均多长？有 BTF source line 的比例？ |
| 26 | State trace parser prototype | ✅ | `interface/extractor/trace_parser.py` (977 lines), 4 transition types, causal chains, 5/5 tests passing |
| 27 | Critical transition detector | ✅ | BOUNDS_COLLAPSE, TYPE_DOWNGRADE, PROVENANCE_LOSS, RANGE_LOSS. In trace_parser.py |
| 28 | Causal chain extractor | ✅ | Register dependency chain from error → root. In trace_parser.py |
| 29 | Diagnoser v1 (end-to-end) | ✅ | `interface/extractor/diagnoser.py` (730 lines), 23/30 (77%). `docs/tmp/diagnoser-30case-evaluation.md` |

### Phase 2b: Rust-Style Diagnostic Engine（当前核心，2026-03-11 开始）

| # | 任务 | 状态 | 关键数据 / 文档 |
|---|------|:---:|------|
| 35 | Enhanced backtracking extraction (`mark_precise` chains) | ✅ | `BacktrackLink`/`BacktrackChain` in trace_parser.py; `extract_backtrack_chains()` handles cross-state splits; 9/9 tests pass |
| 36 | Proof obligation inference + proof propagation analysis | ✅ | `interface/extractor/proof_analysis.py` (701 lines); `ProofEvent`/`ProofObligation`/`ProofLifecycle`; correctly finds loss at insn 22 for SO-70750259 |
| 37 | BTF source correlation | ✅ | `interface/extractor/source_correlator.py` (374 lines); maps proof events to source spans via BTF annotation; fallback to bytecode spans |
| 38 | Multi-span diagnostic renderer (Rust-style text + JSON) | ✅ | `interface/extractor/renderer.py` (167 lines); Rust-style text + structured JSON |
| 39 | Top-level entry point | ✅ | `interface/extractor/rust_diagnostic.py` (539 lines); `generate_diagnostic()` end-to-end pipeline; 27/27 tests pass |

### Phase 3: Evaluation（原 Phase 5 合并）

| # | 任务 | 状态 | 关键数据 / 文档 |
|---|------|:---:|------|
| 40 | Span coverage evaluation | ❌ | OBLIGE spans 覆盖 fix location 的比例 |
| 41 | Information compression evaluation | ❌ | 500 行 → N spans, expert 评估 sufficiency |
| 42 | **A/B repair experiment** | ❌ | raw log + LLM vs OBLIGE + LLM，20-30 cases |
| 43 | PV comparison on Rust-style output | ❌ | 扩展现有 PV comparison |
| 44 | Cross-kernel stability evaluation | ❌ 暂缓 | QEMU/KVM, ≥3 kernel versions |
| 45 | Overhead measurement | ❌ | Trace analysis latency |

### Phase 4: Paper

| # | 任务 | 状态 | 关键数据 / 文档 |
|---|------|:---:|------|
| 60 | Paper outline | ✅→需更新 | `docs/paper-outline.md`（需按 Rust-style 方向重写） |
| 61 | Motivating example | ❌ | stackoverflow-70750259: 500 行 log → 3 个 labeled spans → 1 行 fix |
| 62 | Paper draft | ❌ | LaTeX |
| 63 | Figures | ❌ | pipeline 图 + Rust-style 输出示例 + span coverage 图 |

---

## 9. 关键决策记录

| 决策 | 结论 | 原因 |
|------|------|------|
| 题目不写 "LLM + eBPF" | ✅ | Reviewer 会当 prompt engineering |
| Agent 是 application 不是 contribution | ✅ | 论文核心是 diagnostic output quality |
| 纯 userspace | ✅ | Verifier 已输出足够信息，不需要 kernel patch |
| Passes verifier ≠ 成功 | ✅ | 必须有 semantic oracle |
| 不删旧条目 | ✅ | 对齐 JIT 论文的 hub 规则 |
| Codex 做所有代码/分析 | ✅ | Claude 只做调度/文档/review |
| 放弃 "obligation extraction" framing | ✅ | 本质是 lookup table，不是真正的 extraction |
| 采用 "proof trace analysis" framing | ✅ | 分析完整 state trace 而非 error message |
| Pretty Verifier 未发表 | 确认 | 只是 GitHub 项目，不构成 peer-reviewed prior art |
| Verifier LOG_LEVEL2 已有完整 abstract state | 确认 | 不需要 kernel-side hooks 暴露新信息 |
| **分类准确率不是贡献** | ✅（新） | LLM 已做到 95%+。OBLIGE 贡献是 diagnostic output quality，不是 classifier |
| **Rust-style multi-span 是目标输出** | ✅（新） | 类比 Rust borrow checker：多个源码位置 + 因果标签。没有人对 eBPF 做过 |
| **Meta-analysis of abstract interpretation** | ✅（新） | 对 verifier 的 abstract interpretation 输出做二阶分析（backward slicing + proof propagation）|
| **利用 verifier 的 mark_precise** | ✅（新） | verifier 自己的 precision tracking 是最精确的根因链，只需提取和结构化 |
| **A/B repair experiment 是核心评估** | ✅（新） | 不是测分类，是测"OBLIGE 输出是否帮 LLM 生成更好的修复" |
| **Cross-kernel 暂缓** | ✅（新） | 先做 Rust-style engine + repair experiment，再做跨版本稳定性 |
