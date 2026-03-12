# Synthetic Compilation Report

Run date: 2026-03-12

## Environment

- Cases root: `/home/yunwei37/workspace/ebpf-verifier-agent/case_study/cases/eval_commits_synthetic`
- Host kernel: `6.15.11-061511-generic`
- Clang: `Ubuntu clang version 18.1.3 (1ubuntu1)`
- bpftool: `bpftool v7.7.0`
- Loader: `/home/yunwei37/workspace/ebpf-verifier-agent/case_study/selftest_prog_loader.c`
- Pilot shape: 5 each of `inline_hint, bounds_check, null_check, loop_rewrite` (20 total)
- Multi-file snippets were reduced to the highest-scoring BPF-like `// FILE:` fragment before compilation.
- Custom Cilium-style section macros were rewritten to loadable libbpf sections when possible.

## Pilot Results

- Cases attempted: 20
- Compile success: 0/20 (0.0%)
- Load failure: 0/0 (0.0%)
- Verifier logs captured on rejected loads: 0/0 (0.0%)
- YAML files updated with verifier logs: 0

| fix_type | cases | compile_ok | compile_rate | load_failed | load_failure_rate | verifier_logs | log_capture_rate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| bounds_check | 5 | 0 | 0.0% | 0 | 0.0% | 0 | 0.0% |
| inline_hint | 5 | 0 | 0.0% | 0 | 0.0% | 0 | 0.0% |
| loop_rewrite | 5 | 0 | 0.0% | 0 | 0.0% | 0 | 0.0% |
| null_check | 5 | 0 | 0.0% | 0 | 0.0% | 0 | 0.0% |

### Pilot Cases

`synth-eval-bcc-118bf168f9f6`, `synth-eval-bcc-45f5df4c5942`, `synth-eval-cilium-394e72478a8d`, `synth-eval-cilium-7de434985f89`, `synth-eval-cilium-f132c2a4dd27`, `synth-eval-bcc-a75f0180b714`, `synth-eval-cilium-06c6520c57ad`, `synth-eval-cilium-de679382fe1e`, `synth-eval-cilium-fdca23e2b23f`, `synth-eval-cilium-ff54dbd703b6`, `synth-eval-cilium-0aa0f68b0765`, `synth-eval-cilium-46024c6c4a30`, `synth-eval-cilium-77685c2280ae`, `synth-eval-cilium-f51f4dfac542`, `synth-eval-libbpf-c008eb921eec`, `synth-eval-cilium-126cc503abab`, `synth-eval-cilium-58aaaf61a6c5`, `synth-eval-cilium-717a4683f507`, `synth-eval-cilium-7a98029b6b2c`, `synth-eval-cilium-d8b783be3808`

### Pilot Compile Failures

| message | count |
| --- | ---: |
| `too many errors emitted, stopping now [-ferror-limit=]` | 7 |
| `expected ';' after top level declarator` | 2 |
| `expected ')'` | 2 |
| `expected function body after function declarator` | 2 |
| `use of undeclared identifier 'filter_ports_len'; did you mean 'filter_port'?` | 1 |
| `'section' attribute only applies to functions, global variables, Objective-C methods, and Objective-C properties` | 1 |
| `unknown type name 'daddr'` | 1 |
| `unknown type name '_'` | 1 |
| `type name does not allow storage class to be specified` | 1 |
| `call to undeclared function 'ipv4_policy'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]` | 1 |
| `expected ';' at end of declaration` | 1 |

### Pilot Loader Error Messages

| message | count |
| --- | ---: |
| none | 0 |

### Pilot False Negatives

- None.

## Full Run

- Skipped. Pilot compile success was 0.0%, which did not exceed the required 30.0% threshold.

## Timing

- Started: 2026-03-12T01:09:52.434705+00:00
- Finished: 2026-03-12T01:09:59.181966+00:00
- Duration seconds: 6.7
