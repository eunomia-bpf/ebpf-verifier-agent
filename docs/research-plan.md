# OBLIGE：计划与进度

> 本文档是 OBLIGE 项目的单一 hub。
> **编辑规则**：
> - 任何 TODO/实验/文档引用条目被取代时，必须至少保留一行并标注状态，不得直接删除。
> - 每个任务做完 → 立即更新本文档（任务条目状态 + 关键数据 + 文档路径）。
> - 每次 context 压缩后 → 完整读取本文档恢复全局状态。
> - 用 codex background 跑任务，不阻塞主对话。
> 上次更新：2026-03-11

---

## 1. 论文定位与策略

### 1.1 核心 Thesis：诊断是接口问题，不是文案问题

> eBPF verifier 是 kernel 的 admission controller。
> 当 `BPF_PROG_LOAD` 失败时，唯一的诊断通道是 `log_buf` 里的自由文本。
> 这段文本缺 source localizability、缺 obligation specificity、缺 kernel stability、混淆 failure classes。
> **OBLIGE 把 verifier 从 text-producing black box 变成 typed diagnostic oracle，暴露 proof obligations 和 cross-layer mappings。**

#### 论文逻辑链条（Abstract → Conclusion）

1. eBPF 广泛部署（网络、追踪、安全、调度）
2. Verifier 是 admission controller，必须拒绝不安全程序
3. 拒绝时唯一的反馈是 `log_buf` 自由文本
4. 自由文本：指向 insn offset 不是源码行、报症状不报缺失证明、跨版本不稳定
5. 开发者被迫 trial-and-error（NCC 2024 audit 确认）
6. LLM agent 已经在消费 verifier 反馈（Kgent），但 raw text 限制了修复质量
7. Verifier 内部 **已经** 维护了丰富的 abstract state（类型、区间、nullability、引用）
8. **OBLIGE 提取这些现有语义，变成稳定的结构化诊断接口**

#### 类比定位

| 系统 | 耦合了什么 | 分离出什么 |
|------|-----------|-----------|
| Pretty Verifier | verifier text + source mapping | 后处理增强（regex-based） |
| Rex | verifier rejection + source workaround | 回顾性分类 |
| Kgent | verifier text + LLM | 把 raw text 当 API |
| **OBLIGE** | **verifier abstract state + diagnostic interface** | **stable typed failure semantics** |

### 1.2 OSDI/SOSP Novelty

**真正 novel 的部分**：
1. **Obligation extraction** — 不是 parse 文本，而是从 verifier check points 直接提取"缺了什么证明"
2. **Stable error taxonomy** — 10→30 个 OBLIGE-Exxx IDs，跨 kernel 版本不变
3. **Cross-layer mapping** — source ↔ bytecode ↔ verifier state ↔ environment 四层联动
4. **Discrete action space** — 把修复空间离散化，让 agent 做有界搜索而非自由猜测
5. **量化诊断质量** — 第一个在 real-world corpus 上系统评测 verifier diagnostic quality

**与 JIT 论文的方法论对称**：

| JIT 论文 | OBLIGE |
|----------|--------|
| 31 matched microbenchmarks | 80-150 matched failure cases |
| kernel JIT vs llvmbpf (identical ELF) | raw log vs structured diagnostic (identical failure) |
| JIT-dump 分解 instruction surplus | verbose() 分解 diagnostic information loss |
| "3 improvements 覆盖 89% gap" | "N error classes 覆盖 X% failures" |
| pass ablation | diagnostic layer ablation |
| external validation on 162 real programs | cross-kernel validation on N versions |

**Go 条件（全部满足才提交）**：
1. Benchmark ≥80 个 labeled cases，覆盖全 5 类 ✅ 已有 302 raw cases
2. Structured interface 在 benchmark 上 end-to-end 跑通 ❌
3. 4-condition evaluation 完成，raw log vs structured 有显著差异 ❌
4. Cross-kernel stability 数据（≥3 kernel versions） ❌
5. Semantic oracle 不只是 passes verifier ❌

### 1.3 与 existing work 的关键差异

| Work | 做了什么 | 没做什么（我们的空位） |
|------|----------|----------------------|
| Deokar et al. (eBPF'24) | 743 SO 问题，19.3% verifier | 只描述痛点 |
| HotOS'23 | Verifier untenable 论证 | 没提出新接口 |
| Rex (ATC'25) | 72 workaround commits 分类 | 回顾性分析 |
| Pretty Verifier (PoliTo'25) | 79 error types + source mapping | userspace regex, 版本脆弱, 无 obligation |
| Kgent (eBPF'24) | verifier text → LLM loop | raw text 限制质量 |
| SimpleBPF / verifier-safe DSL | DSL 绕开 verifier | 只覆盖 DSL 子集 |
| DepSurf (2025) | 83% 依赖 mismatch | 关注依赖不是诊断 |
| ebpf-verifier-errors | 社区收集 log+fix | 手动, 无 schema |

### 1.4 核心设计约束

1. **Agent 是 application，不是 contribution** — 论文贡献是接口，不是 agent
2. **Passes verifier ≠ semantic correctness** — 必须有 task-level oracle
3. **Stability > expressiveness** — error_id 必须跨 kernel 版本稳定
4. **Userspace first, kernel later** — 先做 userspace extractor 快速迭代，OSDI 版本最好有 kernel-side hook
5. **不改 verifier 安全保证** — OBLIGE 只观察，不影响 accept/reject 决策
6. **不能只做 log beautification** — 必须有 obligation extraction 和 action space

---

## 2. 五类 Failure Taxonomy

| Class | 含义 | 典型信号 | 占比（待填） |
|-------|------|----------|:---:|
| `source_bug` | 源码真缺 bounds/null/refcount check | "invalid access to packet", "invalid mem access" | 🔄 |
| `lowering_artifact` | LLVM 生成 verifier-unfriendly bytecode | "unbounded min value" after spill/reload | 🔄 |
| `verifier_limit` | 程序安全但超了分析能力 | "too many states", "loop not bounded" | 🔄 |
| `env_mismatch` | helper/kfunc/BTF/attach target 不匹配 | "unknown func", "helper not allowed" | 🔄 |
| `verifier_bug` | verifier 自己的 bug | regression across versions | 🔄 |

**决策顺序**（消歧义时）：verifier_bug → env_mismatch → lowering_artifact → verifier_limit → source_bug

**完整定义**：`taxonomy/taxonomy.yaml`

---

## 3. Error Catalog

当前 10 个 stable error IDs（OBLIGE-E001 ~ E010），覆盖全 5 类。

| ID | Short Name | Class | 典型 verifier message |
|----|-----------|-------|----------------------|
| E001 | packet_bounds_missing | source_bug | "invalid access to packet" |
| E002 | nullable_map_value_dereference | source_bug | "invalid mem access 'map_value_or_null'" |
| E003 | uninitialized_stack_read | source_bug | "invalid indirect read from stack" |
| E004 | reference_lifetime_violation | source_bug | "Unreleased reference id=" |
| E005 | scalar_range_too_wide_after_lowering | lowering_artifact | "unbounded min value" |
| E006 | provenance_lost_across_spill | lowering_artifact | "expected pointer type, got scalar" |
| E007 | verifier_state_explosion | verifier_limit | "too many states" |
| E008 | bounded_loop_not_proved | verifier_limit | "loop is not bounded" |
| E009 | helper_or_kfunc_unavailable | env_mismatch | "unknown func" |
| E010 | verifier_regression_or_internal_bug | verifier_bug | "kernel BUG at" |

**完整定义**：`taxonomy/error_catalog.yaml`

**目标**：扩展到 ~30 个 IDs，覆盖 benchmark 中 ≥90% 的 cases。

---

## 4. 结构化诊断 Schema

```json
{
  "error_id": "OBLIGE-E002",
  "taxonomy_class": "source_bug",
  "source_span": {"file": "xdp.c", "line": 58, "col": 12, "function": "xdp_main"},
  "bytecode": {"func": "xdp_main", "insn_off": 137},
  "expected_state": {"summary": "PTR_TO_MAP_VALUE_OR_NULL"},
  "observed_state": {"summary": "SCALAR_VALUE"},
  "missing_obligation": {
    "obligation_id": "OBLIGE-O002",
    "title": "null-check map_lookup result before dereference",
    "repair_hints": ["ADD_NULL_CHECK", "SPLIT_CONTROL_FLOW"]
  },
  "environment": {"prog_type": "XDP", "kernel": "6.8"}
}
```

**完整 JSON Schema**：`interface/schema/diagnostic.json`

---

## 5. Benchmark Corpus 摘要

| 来源 | Cases | 特点 | 文档 |
|------|:---:|------|------|
| Kernel selftests | 200 (可扩展到 1026) | `__msg()` 标注 expected error；66 memory/bounds, 53 dynptr/iterator, 34 control-flow/locking, 25 ref lifetime, 12 nullability | `docs/tmp/selftests-collection-report.md` |
| Stack Overflow | 76 | 66 有 verifier log, 59 有源码, 66 有 fix description | `docs/tmp/stackoverflow-collection-report.md` |
| GitHub issues | 26 | Cilium 7, Aya 18, Katran 1；含 verifier regression case | `docs/tmp/github-collection-report.md` |
| **Total** | **302** | 目标 ≥80 labeled，实际远超 | — |

**Case 数据路径**：`benchmark/cases/{kernel_selftests,stackoverflow,github_issues}/*.yaml`（gitignore，index.yaml 追踪）

---

## 6. 评估计划

### 6.1 Required Baselines

1. `raw_log` — 原始 verifier verbose output（Kgent baseline）
2. `enhanced_log` — raw log + source line info（Pretty Verifier style）
3. `structured` — OBLIGE 结构化 JSON
4. `structured+retrieval` — OBLIGE + 检索相似历史修复

### 6.2 Required Questions

1. Raw verifier log 到底缺了什么信息？（source localizability, obligation specificity, kernel stability）🔄
2. 哪些 failure classes 真正阻碍 repair？ 🔄
3. Structured interface 提升多少 repair effectiveness？ ❌
4. Structured interface 跨 kernel 版本稳定性？ ❌
5. Load-time overhead 是否可接受？ ❌

### 6.3 Required Metrics

- Error class accuracy
- Source localization accuracy（exact line / ±3 lines / wrong function）
- Proof-obligation precision and recall
- Minimal-slice reduction ratio
- Repair success rate / iterations / wall-clock time
- Patch semantic correctness（oracle，不只是 verifier pass）
- Cross-kernel error_id stability score
- Verifier load latency / diagnostic object size

### 6.4 Required Kernel Versions

5.15, 6.1, 6.6, 6.8, 6.12（至少 3 个）

---

## 7. 文档索引

| 文档 | 路径 | 维护者 |
|------|------|:---:|
| **本文档（唯一 hub）** | `docs/research-plan.md` | Claude |
| 论文 outline | `docs/paper-outline.md` | Claude |
| 文献综述 | `docs/tmp/literature-survey.md` | Codex |
| Selftests 收集报告 | `docs/tmp/selftests-collection-report.md` | Codex |
| SO 收集报告 | `docs/tmp/stackoverflow-collection-report.md` | Codex |
| GitHub 收集报告 | `docs/tmp/github-collection-report.md` | Codex |
| Taxonomy 覆盖分析 | `docs/tmp/taxonomy-coverage-report.md` | Codex（运行中） |
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

### Phase 1: Benchmark Construction

| # | 任务 | 状态 | 关键数据 / 文档 |
|---|------|:---:|------|
| 1 | Repo scaffold + CLAUDE.md | ✅ | 34 files, ~4200 LOC。`CLAUDE.md` |
| 2 | 文献综述 | ✅ | 418 行，12 works，精确引用。`docs/tmp/literature-survey.md` |
| 3 | Taxonomy 定义（5 classes） | ✅ | 186 行 YAML，含 decision order、inclusion/exclusion signals。`taxonomy/taxonomy.yaml` |
| 4 | Error catalog（10 IDs） | ✅ | OBLIGE-E001~E010，覆盖 5 classes。`taxonomy/error_catalog.yaml` |
| 5 | Obligation catalog | ✅ | OBLIGE-O001~O010。`taxonomy/obligation_catalog.yaml` |
| 6 | 诊断 JSON schema | ✅ | 183 行，含 sourceSpan/abstractState/missingObligation/$defs。`interface/schema/diagnostic.json` |
| 7 | Log parser skeleton | ✅ | catalog-backed pattern matching + evidence collection。`interface/extractor/log_parser.py` |
| 8 | Benchmark collectors（3 scripts） | ✅ | ~1500 LOC total。`benchmark/collect_{stackoverflow,kernel_selftests,github_issues}.py` + `benchmark/collector_utils.py` |
| 9 | Kernel selftests collection | ✅ | **200 cases**（可扩到 1026）。66 memory/bounds, 53 dynptr, 34 control-flow, 25 ref, 12 null, 10 other。`docs/tmp/selftests-collection-report.md` |
| 10 | Stack Overflow collection | ✅ | **76 cases**。66 有 log, 59 有 source, 66 有 fix。`docs/tmp/stackoverflow-collection-report.md` |
| 11 | GitHub issues collection | ✅ | **26 cases**。Cilium 7, Aya 18, Katran 1。含 `cilium#44216` verifier regression。`docs/tmp/github-collection-report.md` |
| 12 | **Taxonomy 覆盖分析** | 🔄 | Codex 运行中。目标：现有 10 IDs 覆盖率 + 未覆盖 top-20 messages + 建议新 IDs。`docs/tmp/taxonomy-coverage-report.md`，`eval/results/taxonomy_coverage.json` |
| 13 | 人工标注 30 个高质量 case | ❌ | 验证 taxonomy 在真实 case 上的 inter-rater agreement |
| 14 | Error catalog 扩展到 ~30 IDs | ❌ | 依赖 #12 的 gap analysis |
| 15 | Rex 72 commits 手动收集 20-30 个 | ❌ | Safe-but-rejected cases，最能体现 OBLIGE 价值 |

### Phase 2: Taxonomy & Semantic Choke Points

| # | 任务 | 状态 | 关键数据 / 文档 |
|---|------|:---:|------|
| 20 | Verifier source analysis（kernel/bpf/verifier.c） | ❌ | 识别 check_mem_access, check_helper_call 等关键函数；量化 verbose() 调用分布 |
| 21 | Check function → failure class mapping | ❌ | 哪些 check 函数覆盖最多 real-world failures |
| 22 | Stable error_id namespace 设计 | ❌ | 版本化规则、新 ID 添加策略 |
| 23 | Diagnostic information loss 分析 | ❌ | 类比 JIT 论文的 instruction surplus decomposition |

### Phase 3: Structured Diagnostic Interface

| # | 任务 | 状态 | 关键数据 / 文档 |
|---|------|:---:|------|
| 30 | Userspace log parser 完善 | ❌ | 从 skeleton 到能处理 302 个 cases |
| 31 | BTF/line_info source mapper | ❌ | 利用 libbpf bpf_prog_linfo 接口 |
| 32 | Obligation extractor | ❌ | 从 verifier log + error_id 推断 missing proof obligation |
| 33 | End-to-end extractor pipeline | ❌ | raw log → structured JSON，对 benchmark 全量跑通 |
| 34 | Kernel-side diagnostic hooks（optional for OSDI） | ❌ | 在 verifier check points 直接 emit structured events |

### Phase 4: Minimal Slice & Action Space

| # | 任务 | 状态 | 关键数据 / 文档 |
|---|------|:---:|------|
| 40 | Minimal failing slice computation | ❌ | control + data dependency slice |
| 41 | Discrete action space 定义 | ❌ | ADD_BOUNDS_GUARD, ADD_NULL_CHECK, etc. |
| 42 | Action → error_id mapping | ❌ | 每个 error_id 的推荐 repair actions |

### Phase 5: Agent Evaluation

| # | 任务 | 状态 | 关键数据 / 文档 |
|---|------|:---:|------|
| 50 | Repair loop driver 完善 | ❌ | 从 skeleton 到能调 LLM + verifier |
| 51 | Semantic oracle 实现 | ❌ | Task-level tests / reference behavior checking |
| 52 | 4-condition × 2-consumer evaluation | ❌ | raw_log / enhanced_log / structured / structured+retrieval × human / agent |
| 53 | Cross-kernel stability evaluation | ❌ | 同根因跨 ≥3 kernel versions |
| 54 | Overhead measurement | ❌ | Verifier load latency / diagnostic size |

### Phase 6: Paper

| # | 任务 | 状态 | 关键数据 / 文档 |
|---|------|:---:|------|
| 60 | Paper outline | ✅ | `docs/paper-outline.md` |
| 61 | Motivating example | ❌ | 一个具体 XDP 程序：raw log 20 行 → 修复 2 行 null check |
| 62 | Paper draft | ❌ | LaTeX |
| 63 | Figures | ❌ | 8 key figures（见 paper outline） |

---

## 9. 关键决策记录

| 决策 | 结论 | 原因 |
|------|------|------|
| 题目不写 "LLM + eBPF" | ✅ | Reviewer 会当 prompt engineering |
| Agent 是 application 不是 contribution | ✅ | 论文核心是接口设计 |
| Userspace first | ✅ | 快速迭代；kernel patch 作为 stretch goal |
| Passes verifier ≠ 成功 | ✅ | 必须有 semantic oracle |
| 不删旧条目 | ✅ | 对齐 JIT 论文的 hub 规则 |
| Codex 做所有代码/分析 | ✅ | Claude 只做调度/文档/review |
