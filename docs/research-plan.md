# OBLIGE：计划与进度

> ## **第一优先级：实现必须配得上 claims，不是降 claims 配实现。目标 OSDI/ATC。**
>
> Critical review (2026-03-13) 发现论文 claims 与代码严重脱节。方向不是降低 claims，而是**重新实现核心引擎**使其配得上 OSDI/ATC level 的 novelty。具体见 §10 Implementation Gap Closure Plan。

> 本文档是 OBLIGE 项目的单一 hub。
> **编辑规则**：
> - 任何 TODO/实验/文档引用条目被取代时，必须至少保留一行并标注状态，不得直接删除。
> - 每个任务做完 → 立即更新本文档（任务条目状态 + 关键数据 + 文档路径）。
> - 每次 context 压缩后 → 完整读取本文档恢复全局状态。
> - 用 sonnet agent 跑实现/分析任务。codex 额度已尽（至 2026-03-18）。
> 上次更新：2026-03-13 evening（critical review done; claims audit done; implementation gap plan added; target OSDI/ATC confirmed）

---

## 0. 当前快照（2026-03-13）

- Batch v5：**262/262 成功**（formal engine only），proof_established 115 (43.9%), proof_lost 99 (37.8%), rejected 262 (100%), BTF 172 (65.6%), causal_chain 24
- Obligation coverage：**100%**（262/262 have `missing_obligation`）
- Tests：**268 passing**（heuristic 已清理，formal engine only）
- Latency v3：**median 25.3ms, P95 41.2ms, max 89.3ms**，Pearson r=0.802
- A/B repair v3：**56 cases**（本地 GPT-OSS 20B）；B consistently > A +7.1pp（21.4%→28.6%），lowering +9.1pp。绝对准确率低（20B 太弱），McNemar p=0.22
- A/B repair v4：**❌ 待运行**（Qwen3.5-122B-A10B，56 cases）
- Formal engine comparison：v3→v4 +21 eligible cases, +21 causal chains, obligation 94.19%→94.27%
- Per-language：C 274 / Rust 21 / Go 7，全部成功
- Paper：**9 pages**, **ACM SIGPLAN format**, **compiled**（`docs/paper/main.tex`）。6 个数字不一致待修
- Title：`OBLIGE: Fast, Precise Root-Cause Diagnosis of eBPF Verification Failures`
- Framing：**abstract state transition analysis**（第四次调整）
- 文件清理完成：deprecated files → `eval/results/deprecated/`, `eval/deprecated/`, `docs/tmp/deprecated/`
- 新增：`value_lineage.py`, `Makefile`（根目录一键操作）

---

## 1. 论文定位与策略

### 1.1 核心 Thesis：Abstract State Transition Analysis（2026-03-12 第四次调整）

> **旧 thesis（已放弃）**：verifier 缺少诊断信息，需要 kernel-side hooks 暴露 abstract state。
> **第一次调整**：发现 LOG_LEVEL2 已有完整 abstract state，问题是 unstructured。做 proof trace analysis。
> **第二次调整**：分类准确率不是贡献（LLM 已做到 95%+）。真正的贡献是 diagnostic output 的质量。
> **第三次调整**：核心 insight 是 proof obligation lifecycle。但 obligation inference 本质是 lookup table，不够 general。
> **第四次调整（当前）**：核心 insight 是 **abstract state transition analysis** — verifier trace 是 proof attempt 的完整记录，直接分析 abstract state 的变化即可定位 root cause，不需要预先知道 obligation 是什么。

> **当前 thesis**：
> Verifier 的 LOG_LEVEL2 trace 记录了完整的 abstract state 序列 [s_0, s_1, ..., s_n]。每条指令要么推进、维持、或破坏 safety argument。
> 通过分析 abstract state 在每条指令的 **transition**（bounds collapse、type downgrade、provenance loss、range loss），可以自动定位 proof 被破坏的精确位置 — root cause — **无需预先知道哪个 safety property 被检查**。
>
> **Key insight**: The verifier trace IS the proof attempt. Abstract state transitions reveal where the proof broke:
> - 检测 safety-relevant state 退化的指令（bounds 变宽、type 降级、provenance 丢失）
> - **Transition pattern** 直接分类 failure：从未建立 = source bug，建立后破坏 = lowering artifact
> - Error message 作为 **focus mechanism**（zoom in 到最相关的 transitions），不作为分析基础
>
> **Generality**: 适用于任何输出 per-step abstract state 的 abstract interpreter（Rust borrow checker、WebAssembly validator、Java bytecode verifier）。
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

#### 论文逻辑链条（2026-03-12 更新，abstract state transition analysis framing）

1. **Context + Problem (Para 1)**: eBPF critical → verifier rejection = 500-line trace → last line = symptom, root cause buried 30-500 lines earlier
2. **Evidence + Why existing fails (Para 2)**: 591 commits 分析 → 63.6% 是 proof-reshaping workarounds（根因是 verifier over-approximation，不是 diagnostics 差）。修复需要知道 proof *在哪里*断了。PV regex on final line; LLMs treat as text; neither finds the state transition that broke the proof
3. **Key insight (Para 3)**: Verifier trace = proof attempt record. Abstract state transitions（bounds collapse, type downgrade, provenance loss）直接揭示 root cause。Transition pattern 分类 failure：从未建立 = source bug，建立后破坏 = lowering artifact。不需要预先知道 obligation
4. **Example (Para 4)**: Figure 1 (SO #70750259) — bounds check established (line 3), OR destroys bounds (line 7), rejected (line 8). OBLIGE shows 3 labeled spans with state transitions vs PV's 1 hint
5. **System + Results + Contributions (Para 5)**: State transition detection + backward slicing + interval arithmetic, 94% coverage, Rust-style rendering. 3 contribution bullets

### 1.2 Novelty（2026-03-12 第四次调整 — abstract state transition analysis）

**核心 novelty（不是分类准确率——LLM 已做到 95%+）**：

**论文三大贡献（对应 Introduction contribution bullets）**：
1. **Abstract state transition analysis framework** — 将 verifier trace 视为 proof attempt 的完整记录，通过分析每条指令的 abstract state 变化（bounds collapse、type downgrade、provenance loss、range loss）自动定位 root cause。不需要预先知道 obligation 是什么 — transition pattern 本身就分类 failure（从未建立 = source bug，建立后破坏 = lowering artifact）。适用于任何输出 per-step abstract state 的 abstract interpreter
2. **The OBLIGE diagnostic engine** — 五阶段 pipeline（trace parsing → state transition detection → backward slicing via mark_precise → BTF source correlation → multi-span rendering），interval arithmetic 三值评估（satisfied/violated/unknown），27ms median latency，纯 userspace，不改 kernel
3. **Evaluation on 302 real-world failures** — 94.2% coverage，lowering artifact +30pp repair accuracy，root-cause localization 67% vs PV 0%

**支撑 novelty**：
- **Meta-analysis of abstract interpretation output** — 对 verifier AI 输出做二阶分析（second-order abstract interpretation）
- **Leveraging verifier's own `mark_precise` backtracking** — 提取并结构化 verifier 自己的根因链，完整 BFS 无深度限制
- **Interval arithmetic + tnum** — 精确匹配 verifier 的 scalar 追踪（[umin,umax]×[smin,smax] + tnum value/mask），三值评估
- **Language-agnostic**: bytecode level 分析 → C/Rust/Go 都适用
- **Soundness from verifier**: OBLIGE labels 的 soundness 继承自 verifier AI 的 soundness

**与 Pretty Verifier 的本质差异**：
- Pretty Verifier：parse **1 行** error message（91 regex）→ 1 个 enhanced text + 1 个建议
- OBLIGE：parse **500 行** state trace → **多个源码位置** + 因果链 + abstract state transitions + 结构化 JSON

**Obligation 的角色（降级为 focus mechanism）**：
- Obligation 从 error message 推断 verifier 需要的 safety condition → 用作 focus mechanism（zoom in 到最相关的 transitions）
- 核心分析不依赖 obligation catalog — 直接分析 abstract state diff 找到 safety-relevant 退化
- 已有的 obligation_catalog_formal.py（35 个从 verifier.c 提取的 precondition）作为 precision 增强，不是 foundation

**Go 条件（全部满足才提交）**：
1. Benchmark ≥80 个 labeled cases，覆盖全 5 类 ✅ 302 cases, 30 labeled
2. Rust-style multi-span diagnostic engine end-to-end 跑通 ✅ `generate_diagnostic()` + 241/241 batch success
3. OBLIGE 输出的 source spans 覆盖实际 fix 位置（vs PV: 1 span only）✅ 101/263 covered；manual 12/14 (86%)
4. A/B repair experiment：OBLIGE 输出 + LLM vs raw log + LLM，修复质量差异 ✅ 54 cases；`lowering_artifact` fix-type +30pp（3/10 → 6/10）
5. 信息压缩质量：500 行 → 3-5 个带标签的源码跨度，expert 评估 sufficiency ❌（已有 241-case batch + deep quality analysis，尚缺 expert study）

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

### 4.2 OBLIGE Rust-Style Diagnostic Engine（已实现）

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

### 5b. Synthetic Cases from eval_commits（2026-03-12）

从 591 个 eval_commits 中提取 C 代码，生成 535 个 synthetic case（`case_study/cases/eval_commits_synthetic/`）。每个保留完整 provenance（original_case_id, original_commit, original_repository, original_commit_message）。

| Taxonomy | Count |
|----------|:---:|
| lowering_artifact | 249 |
| source_bug | 220 |
| verifier_limit | 50 |
| env_mismatch | 16 |

**Total eval corpus**: 241 有 log + 535 synthetic = **776 cases**。`docs/tmp/synthetic-cases-report.md`

---

## 6. 评估计划（2026-03-12 同步）

### 6.1 Required Baselines

1. `raw_verbose_log` — 原始 verifier LOG_LEVEL2 verbose output（500-1000+ 行）
2. `pretty_verifier` — PV 的 1 行 error + 1 条 suggestion（作为 existing tool baseline）
3. `oblige_diagnostic` — OBLIGE Rust-style multi-span output（structured JSON + text）

### 6.2 Required Questions（按优先级）

1. **Span coverage**: OBLIGE 输出的 source spans 是否覆盖了实际 fix 的位置？（vs PV: 1 span only）✅ 101/263 covered；manual 12/14 (86%)
2. **Information compression**: 500 行 → 3-5 个 labeled spans，expert 评估是否 sufficient？ ❌（已有 batch/deep-quality 数据，尚缺 expert sufficiency study）
3. **Repair guidance (A/B experiment)**: OBLIGE 输出 + LLM vs raw log + LLM，修复质量差异？ ✅ 54-case v2 complete；`lowering_artifact` +30pp（3/10 → 6/10），overall headline mixed
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

**Case selection（v2 实际）**：54 个有已知修复的 case。目标配比为 8 env / 15 lowering / 23 source / 8 limit；实际可用为 8 env / 10 lowering / 28 source / 8 limit。

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
| **Batch diagnostic eval (241 cases, v1/v2; 已被 v3 取代)** | **历史 batch 汇总；当前论文数字请看 v3** | `docs/tmp/batch-diagnostic-eval.md`, `docs/tmp/batch-diagnostic-eval-v2.md` |
| **Batch diagnostic eval (241 cases, v3; 当前)** | **241/241 成功; obligation 94.2% (227/241); BTF 62.7%; rejected 100%; established 42.7%; lost 37.3%; taxonomy: source_bug 45.2%, env_mismatch 34.4%, lowering 12.0%, limit 8.3%** | `docs/tmp/batch-diagnostic-eval-v3.md` |
| **Synthetic case generation** | **535 cases from eval_commits (249 lowering, 220 source_bug, 50 limit, 16 env)** | `docs/tmp/synthetic-cases-report.md` |
| **Span coverage eval (263 cases)** | **101/263 covered (38%), manual 12/14 (86%), KS rejected 85/102 (83%); 535 synthetic fix-pattern 分析** | `docs/tmp/span-coverage-eval.md` |
| **Deep quality analysis** | **119 单 span 正确; 14→~2 unknown taxonomy; 3 false satisfied; SO BTF 是数据问题; 5 级 priority 修复建议** | `docs/tmp/output-quality-analysis.md` |
| **Synthetic compilation pilot** | **0/20 编译成功; snippets 缺完整上下文; 需从原始 repo checkout** | `docs/tmp/synthetic-compilation-report.md` |
| **A/B repair experiment (30 cases, v1; 已被 v2 取代)** | **整体持平 10/30; lowering_artifact +25pp (0→25%); source_bug -23pp; root-cause +7pp; semantic +7pp** | `docs/tmp/repair-experiment-report.md` |
| **A/B repair experiment (54 cases, v2; 当前)** | **54 cases; `lowering_artifact` fix-type +30pp（3/10→6/10）; overall: A location 53/54 vs B 48/54, A fix_type 46/54 vs B 43/54** | `docs/tmp/repair-experiment-v2-results.md` |
| **Paper data audit (2026-03-12)** | **sync paper-facing numbers: obligation 94.2%/96.4%, tests 101, latency 27/43/92, A/B headline +30pp** | `docs/tmp/paper-data-audit.md` |
| **Quality fix round 2** | **unknown taxonomy 14→2; false satisfied 3→0; round-2 report 44/44 tests pass; current suite 101 passing** | `docs/tmp/quality-fix-round2-report.md` |
| **Full code review** | **7 阶段 pipeline; 双重 parse; JSON schema 不匹配; 109/241 catalog override; 116/241 obligation=null** | `docs/tmp/full-code-review.md` |
| **Novelty gap analysis** | **4 个 claim 全部过度声称; 需 formal predicate + real backward slice; MVP ~3 周** | `docs/tmp/novelty-gap-analysis.md` |

---

## 7. 文档索引

| 文档 | 路径 | 维护者 |
|------|------|:---:|
| **本文档（唯一 hub）** | `docs/research-plan.md` | Claude |
| 论文 outline（historical） | `docs/paper-outline.md` | Claude |
| 论文 draft source | `docs/paper/main.tex` | Claude |
| 论文 PDF（compiled） | `docs/paper/main.pdf` | Claude |
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
| Batch diagnostic 评估（v1，已被 v3 取代） | `docs/tmp/batch-diagnostic-eval.md` | Codex |
| Batch diagnostic 评估（v3，当前） | `docs/tmp/batch-diagnostic-eval-v3.md` | Codex |
| Synthetic cases 报告 | `docs/tmp/synthetic-cases-report.md` | Codex |
| Span coverage 评估 | `docs/tmp/span-coverage-eval.md` | Codex |
| Output quality 分析 | `docs/tmp/output-quality-analysis.md` | Codex |
| Span coverage 结果 JSON | `eval/results/span_coverage_results.json` | Codex |
| Span coverage 评估脚本 | `eval/span_coverage_eval.py` | Codex |
| Synthetic compilation 报告 | `docs/tmp/synthetic-compilation-report.md` | Codex |
| Synthetic compilation 脚本 | `eval/compile_synthetic_cases.py` | Codex |
| A/B repair 实验报告（v1，已被 v2 取代） | `docs/tmp/repair-experiment-report.md` | Codex |
| A/B repair 实验报告（v2，当前） | `docs/tmp/repair-experiment-v2-results.md` | Codex |
| A/B repair 实验脚本 | `eval/repair_experiment.py` | Codex |
| A/B repair 结果 JSON（v1） | `eval/results/repair_experiment_results.json` | Codex |
| A/B repair 结果 JSON（v2，当前） | `eval/results/repair_experiment_results.v2.json` | Codex |
| Quality fix round 2 报告 | `docs/tmp/quality-fix-round2-report.md` | Codex |
| Paper data audit | `docs/tmp/paper-data-audit.md` | Codex |
| Full code review | `docs/tmp/full-code-review.md` | Codex |
| Novelty gap analysis | `docs/tmp/novelty-gap-analysis.md` | Codex |
| Strategic review (2026-03-12) | `docs/tmp/strategic-review-2026-03-12.md` | Codex |
| Multi-language analysis | `docs/tmp/multi-language-analysis.md` | Codex |
| Decompiler analysis | `docs/tmp/decompiler-analysis.md` | Codex |
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
| 36 | Proof obligation inference + proof propagation analysis（旧 heuristic 版） | ✅→被 #50 取代 | `interface/extractor/proof_analysis.py`; heuristic event labeling，novelty 不够 |
| 37 | BTF source correlation | ✅ | `interface/extractor/source_correlator.py` (374 lines); maps proof events to source spans via BTF annotation; fallback to bytecode spans |
| 38 | Multi-span diagnostic renderer (Rust-style text + JSON) | ✅ | `interface/extractor/renderer.py` (167 lines); Rust-style text + structured JSON |
| 39 | Top-level entry point | ✅ | `interface/extractor/rust_diagnostic.py` (539 lines); `generate_diagnostic()` end-to-end pipeline; 27/27 tests pass |
| 50 | **Real proof engine (formal predicate tracking)** | ✅ R3+集成+扩展 | `proof_engine.py`; **integration 历史结果 42.3%→60.2% (145/241)**；当前审计值：**obligation 94.2% (227/241 eval), 96.4% (397/412 full pipeline); tests 101 passing**；10 families；catalog override 109→18；JSON schema 统一；source_bug 合同特化。`docs/tmp/proof-engine-integration-report.md`, `docs/tmp/paper-data-audit.md` |

### Phase 2c: Formal Foundation（2026-03-12 加入论文）

| # | 任务 | 状态 | 关键数据 / 文档 |
|---|------|:---:|------|
| 55 | **Obligation status lattice + transfer function** | ✅ 已补实现 | 论文形式化 + `abstract_domain.py` interval arithmetic 三值评估。Phase 2e #81 完成 |
| 56 | **Soundness theorem (Proposition 1)** | ✅ in paper | Prop 1 重述 verifier soundness — 保留，诚实标注为 "proof sketch" |
| 57 | **Backward obligation slice** | ✅ 已修复 | depth-10 已移除，完整 BFS + mark_precise chain。Phase 2e #83 完成 |
| 58 | **Generalization beyond eBPF** | ✅ in paper | Paper §3 includes paragraph: framework applies to any verifier/type-checker producing per-step abstract state traces |

### Phase 2d: Generality（2026-03-12 开始）

| # | 任务 | 状态 | 关键数据 / 文档 |
|---|------|:---:|------|
| 70 | **Multi-language analysis** | ✅ | 25/25 non-C cases 全部成功（18 Rust/Aya + 7 Go/Cilium）。obligation: Aya 10/18, Cilium 6/7。`docs/tmp/multi-language-analysis.md` |
| 71 | **Decompiler integration analysis** | ✅ | bpftool_parser.py 实现；source fallback 集成。结论：decompiler 不作为核心功能，OBLIGE 已有 BTF fallback + bytecode spans。`docs/tmp/decompiler-analysis.md` |
| 72 | **Per-language eval table** | ✅ | C 274 (235 success, 97.4% obl) / Rust 21 (20 success, 60.0% obl) / Go 7 (7 success, 85.7% obl)。`eval/results/per_language_eval.json`, `docs/tmp/per-language-eval.md` |

### Phase 2e: 真正做到位 — Formal Predicate Engine（2026-03-12 决定）

> **背景**：代码审计发现论文的 formal claims 与实现严重不符。obligation inference 是 lookup table，predicate evaluation 是简单值比较，backward slice 硬编码深度 10。决定：真正实现，不糊弄。

| # | 任务 | 状态 | 关键数据 / 文档 |
|---|------|:---:|------|
| 80 | **从 verifier source 提取 obligation preconditions** | ✅ | `obligation_catalog_formal.py`：35 个 FormalObligation，来源于 verifier.c 真实 C 条件，83% 可从 trace 评估。已集成进 pipeline |
| 81 | **Interval arithmetic based predicate evaluation** | ✅ | `abstract_domain.py`：ScalarBounds（[umin,umax]×[smin,smax] + tnum），三值评估，tnum 算术。已集成进 `_eval_atom_on_state()`。248 tests |
| 82 | **Register value lineage 完整实现** | ✅ | `interface/extractor/value_lineage.py`：ValueNode/ValueLineage，支持 MOV/STORE/LOAD/ALU+const/ALU+reg/CALL。集成到 TraceIR，用于 alias fallback + backward slice seed expansion。20 tests in test_value_lineage.py。v5 batch: +3 proof spans vs v4 |
| 83 | **完整 backward obligation slice** | ✅ | depth-10 限制已移除，改用 visited set BFS。完整遍历 mark_precise chain。causal_chain 在 21/262 cases 中出现。123 tests |
| 84 | **Predicate evaluation 单元测试** | ✅ | 125 tests in test_abstract_domain.py，覆盖 interval arithmetic、tnum、三值评估、各 obligation family |
| 85 | **End-to-end 验证：formal engine vs 旧 heuristic** | ✅ | v3→v4: +21 eligible (241→262), +21 causal chains (0→21), obligation 94.19%→94.27%。26 improvements vs 7 regressions。`docs/tmp/formal-engine-comparison.md` |
| 86 | **A/B 实验 v3** | ✅ 完成 | 本地 GPT-OSS 20B，56 cases。**B consistently > A**：overall +7.1pp（21.4%→28.6%），lowering +9.1pp（1/11→2/11），source_bug +6.9pp（9/29→11/29）。**source-bug regression 已修复**（v2 是 -14pp）。但绝对准确率低（20B 太弱），McNemar p=0.22 不显著。需要更强模型重跑。`eval/results/repair_experiment_results_v3.json`, `docs/tmp/repair-experiment-v3-results.md` |
| 87 | **本地 LLM eval 基础设施** | ✅ | `scripts/local_llm_eval.py`：自动启动 llama-server，OpenAI-compatible API，信号处理。`docs/local-llm-guide.md`。TinyLlama 测试通过 3/3 |

### Phase 3: Evaluation（原 Phase 5 合并）

| # | 任务 | 状态 | 关键数据 / 文档 |
|---|------|:---:|------|
| 40 | Span coverage evaluation | ✅ | **101/263 covered (38%), manual 12/14 (86%), KS rejected match 85/102 (83%)**; 152 unknown（fix 不可定位）。`docs/tmp/span-coverage-eval.md`, `eval/results/span_coverage_results.json` |
| 41 | Deep output quality analysis | ✅ | 119 单 span 是正确行为（95 never_established）; 14 unknown taxonomy→~2 可修; 3 false satisfied 可修; SO BTF 是数据问题不是 parser 问题。`docs/tmp/output-quality-analysis.md` |
| 42 | **A/B repair experiment** | ✅ v2 完成 | **54 cases；`lowering_artifact` fix-type +30pp（3/10→6/10）**。overall：A location 53/54 vs B 48/54；A fix_type 46/54 vs B 43/54。仅 10 个 lowering case 满足可用性要求，因此其余名额由 source_bug 回填。`docs/tmp/repair-experiment-report.md`, `docs/tmp/repair-experiment-v2-results.md` |
| 43 | Quality fix round 2 | ✅ | **unknown taxonomy 14→2; false satisfied 3→0; round-2 report 44/44 tests; current suite 101 passing; 241/241 batch; 12 新 catalog patterns**。`docs/tmp/quality-fix-round2-report.md`, `docs/tmp/paper-data-audit.md` |
| 44 | Compile synthetic cases | ✅ 失败 | **0/20 pilot 编译成功**（snippets 是 diff 片段，缺完整上下文）。需从原始 repo checkout 完整源文件才可行。`docs/tmp/synthetic-compilation-report.md` |
| 45 | PV comparison on Rust-style output | ❌ | 扩展现有 PV comparison |
| 46 | Cross-kernel stability evaluation | ❌ 暂缓 | QEMU/KVM, ≥3 kernel versions |
| 47 | Overhead measurement | ✅ | **中位 25.3ms, P95 41.2ms, max 89.3ms**，Pearson r=0.802（log lines vs latency）。262/262 cases，0 failures。`eval/results/latency_benchmark_v3.json` |

### Phase 4: Paper

| # | 任务 | 状态 | 关键数据 / 文档 |
|---|------|:---:|------|
| 60 | Paper outline | ✅ | `docs/paper-outline.md`（historical outline；当前 draft 以 `docs/paper/main.tex` 为准） |
| 61 | Motivating example | ❌ | stackoverflow-70750259: 500 行 log → 3 个 labeled spans → 1 行 fix |
| 62 | Paper draft | ✅ compiled | `docs/paper/main.tex`, `docs/paper/main.pdf`；**ACM SIGPLAN format，9 pages**；标题：`OBLIGE: Fast, Precise Root-Cause Diagnosis of eBPF Verification Failures`；使用 `\sys` macro；Introduction 无 subsection，OSDI/SOSP 风格；framing 已更新为 **abstract state transition analysis**（2026-03-12） |
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
| **Formal treatment in paper** | ✅（新） | Obligation lattice L={⊥,unknown,satisfied,violated}，soundness from verifier AI，backward slice。论文 §3 |
| **Language-agnostic claim** | ✅（新） | 25/25 non-C cases 成功。Aya obligation 56%, Cilium 86%。quality 取决于 log richness 而非语言 |
| **Decompiler as deployment story** | ✅（新） | bpftool_parser.py 实现。BTF fallback + bytecode spans 已支持。不作为论文核心功能 |
| **P1 code review fixes** | ✅（新） | 18 项 correctness + structure 修复。proof_engine/rust_diagnostic/trace_parser 拆分为子模块。120 tests |
| **Formal engine 必须真正做到位** | ✅（新） | 代码审计发现：obligation inference = lookup table，predicate eval = 值比较，backward slice = depth-10。决定：实现 interval arithmetic、从 verifier source 提取 preconditions、完整 backward slice。不糊弄 |
| **A/B 实验必须重做** | ✅（新） | 当前 A/B：整体 regression（-6pp），source-bug -14pp，仅 10 lowering cases。必须修复 source-bug regression + 扩大 case 数 + 加 verifier-pass oracle |
| **63.6% framing 需修正** | ✅（新） | 63.6% workarounds 的根因是 verifier over-approximation，不是 diagnostics 差。OBLIGE 不能减少这 63.6%，只能帮开发者更快找到正确的修复方式。论文不应说 "poor diagnostics 导致不必要工作"，应说 "verifier rejection 是严重问题，OBLIGE 帮开发者更快、更准确地修复" |
| **单 agent 做 build+code+test** | ✅（新） | 构建、修改代码和运行测试不要拆分成不同 subagent。一个 agent 完成全部：写代码→测试→发现 bug→修复→重跑。拆分会导致 test agent 发现 bug 但无法修复 |
| **Makefile 一键操作** | ✅（新） | 根目录 Makefile 提供 `make test`, `make eval-all`, `make eval-repair-qwen`, `make paper` 等。以后所有操作用 Makefile target，不需要记住复杂命令 |
| **实现必须配得上 claims** | ✅（新，2026-03-13） | Critical review 发现 paper claims 与代码脱节。方向：重新实现核心引擎，不是降 claims。详见 §10 |
| **目标 OSDI/ATC** | ✅（确认，2026-03-13） | 不降级到 workshop/tools track。实现要配得上 top venue |

---

## 10. Implementation Gap Closure Plan（2026-03-13 新增，第一优先级）

> **原则**：论文写什么，代码就必须做什么。不是"调整措辞让 claim 变弱"，而是"把实现做到论文描述的水平"。
> **目标**：OSDI / ATC。

### 10.1 Critical Review 诊断（docs/tmp/critical-review-2026-03-13.md）

| 论文 Claim | 当前实现 | Gap | 严重度 |
|------------|----------|-----|--------|
| "Abstract state transition analysis" | 读 verifier 已算好的 bounds 做 field comparison | 不是 analysis，是 reading | **致命** |
| "Interval arithmetic + tnum" | tnum 函数写了但评估路径几乎不用 | 写了没用 | **高** |
| "Formal predicate evaluation" | if-else field comparison dispatch table | 不是 formal | **高** |
| "Backward obligation slice" | 跟着 mark_precise chain + value lineage heuristic，无 CFG | 不是真正的 slicing | **高** |
| "+30pp repair accuracy" in abstract | 只是 10 个 lowering cases，overall -6pp | 误导 | **致命** |
| 56.5% 只产出单 span | never_established cases 无 lifecycle 分析 | 方法覆盖率低 | **中** |
| "19 obligation families" | 7 个 atoms=[]，不产出 lifecycle | 夸大 | **中** |

### 10.2 要做的事（按优先级）

#### P0：重新实现核心引擎（使 claims 成为事实）

| # | 任务 | 当前状态 | 目标状态 | 怎么做 |
|---|------|----------|----------|--------|
| 100 | **真正的 abstract state transition analysis** | 读预计算值做比较 | 在 trace 上运行轻量 abstract interpreter：对每条指令的 pre→post state 计算 transfer function，检测 state 退化 | 实现 `AbstractTransitionAnalyzer`：输入=traced instruction sequence，输出=每条指令的 state transition classification（narrowing/widening/type-change/no-change）+ 检测 critical transitions（bounds collapse 用 interval arithmetic 而不是 field comparison） |
| 101 | **真正用 interval arithmetic** | tnum 函数存在但没调用者 | 所有 predicate evaluation 走 abstract domain | 改 `_eval_atom_on_state()`：所有 atom 类型都经过 `ScalarBounds` 的 interval arithmetic evaluation；用 tnum 推导 ALU 指令后的 bounds（AND/OR/SHIFT）；实现 transfer function for 常见 BPF 指令 |
| 102 | **真正的 backward slicing with CFG** | 跟着 mark_precise + heuristic | 构建 trace-level CFG，做 proper reaching-definition + control-dependence slicing | 从 trace 中的 branch/jump 指令重建 CFG edges；实现 reaching definition analysis；backward slice = data dependence ∪ control dependence from transition witness |
| 103 | **消除 heuristic fallback** | 6% cases 回退到 heuristic status | formal engine 覆盖所有 cases | 给 7 个 atoms=[] 的 family 添加 predicate atoms；确保 formal engine 路径处理所有 262 cases |
| 104 | **A/B 实验达到统计显著** | v3: p=0.22, N=56, 20B model | p<0.05, N≥100, strong model, verifier-pass oracle | 用 verifier oracle 做客观评判；如可能用 API model（GPT-4/Claude）；扩大 case 数 |
| 105 | **Root-cause ground truth** | 无法自动验证 | 至少 30 cases 有 expert validation | Manual annotation: 30 个 established_then_lost cases，expert 判断 proof_lost 位置是否正确 |

#### P1：评估补强

| # | 任务 | 状态 |
|---|------|------|
| 110 | Verifier-pass oracle 集成到 A/B | ✅ 已实现 `--use-oracle` |
| 111 | Root-cause validation 脚本 | ✅ 已实现 `eval/root_cause_validation.py`，51.5% backtracking rate |
| 112 | Batch v6 with updated engine | ✅ 报告完成（interval arithmetic +2 cases） |
| 113 | A/B v5 with Qwen3.5 + oracle | 🔄 跑着，12/56 |
| 114 | Paper 数字全面更新 | ❌ 等 v5 + 重实现完成后统一更新 |

#### P2：论文重写（等 P0 实现完成后）

| # | 任务 | 说明 |
|---|------|------|
| 120 | 重写 §3 formal section | 基于真正实现的 abstract interpreter + CFG slicing |
| 121 | 重写 abstract 和 introduction | 基于真实数据，不夸大 |
| 122 | 加 case study section | 3-5 个详细 examples 展示完整 pipeline |
| 123 | 更新所有 evaluation tables | 基于重实现后的新 batch + A/B 数据 |

### 10.3 当前进展（2026-03-13 evening）

- ✅ Critical review + claims audit 完成，gap 已精确定位
- ✅ Verifier oracle 实现 + 集成
- ✅ Root-cause validation 框架
- ✅ tnum/interval arithmetic 小幅改进（+2 cases）
- 🔄 A/B v5 实验跑着
- ❌ P0 核心引擎重实现尚未开始 — **这是决定论文命运的关键**
