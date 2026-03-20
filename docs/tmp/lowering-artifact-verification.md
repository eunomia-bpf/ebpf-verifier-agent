# Lowering Artifact Verification

## Scope

- `eval_commits` candidates attempted: `30`
  Selection policy: repo priority `katran -> bcc -> cilium`, then heuristic lowering-artifact score.
- Existing non-quarantined SO/GH lowering_artifact cases attempted: `18`
- Total attempted: `48`
- Buggy compiled: `13`
- Buggy verifier reject: `0`
- Fixed compiled: `13`
- Fixed verifier pass: `7`
- Fully confirmed: `0`

## Dataset Split

- `eval_commits`: `30` attempted, `12` buggy compiled, `0` buggy reject.
- Existing SO/GH: `18` attempted, `1` buggy compiled, `0` buggy reject.

## Per-Repo Breakdown

| Bucket | Attempted | Buggy Compiled | Buggy Reject | Fixed Compiled | Fixed Pass | Confirmed |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| aya | 2 | 0 | 0 | 0 | 0 | 0 |
| bcc | 20 | 8 | 0 | 8 | 6 | 0 |
| katran | 10 | 4 | 0 | 4 | 0 | 0 |
| stackoverflow | 16 | 1 | 0 | 1 | 1 | 0 |

## Failure Reasons

- Cases where header extraction still led to at least one successful compile: `12`

| Reason | Count |
| --- | ---: |
| `compile_error` | 70 |
| `no_target_file` | 24 |
| `pass` | 15 |
| `load_error` | 10 |
| `no_buggy_source` | 10 |
| `buggy=pass, fixed=pass` | 7 |
| `buggy=load_error, fixed=load_error` | 5 |
| `buggy=pass, fixed=fail` | 1 |
| `fail` | 1 |

## Confirmed Cases

- No case reached `buggy reject + fixed pass` on this host/kernel with the generated standalone units.

## Attempted Cases

| Case ID | Source | Repo | Buggy Compile | Buggy Result | Fixed Compile | Fixed Result | Status | Selected File / Origin | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `eval-bcc-03f9322cc688` | eval_commits | bcc | no | compile_error | no | compile_error | failed | `libbpf-tools/tcpstates.c` | compile_error |
| `eval-bcc-118bf168f9f6` | eval_commits | bcc | yes | pass | yes | pass | partial | `libbpf-tools/tcpconnect.bpf.c` | buggy=pass, fixed=pass |
| `eval-bcc-16508e5684b1` | eval_commits | bcc | no | compile_error | no | compile_error | failed | `libbpf-tools/opensnoop.c` | compile_error |
| `eval-bcc-18208507666d` | eval_commits | bcc | no | compile_error | no | compile_error | failed | `libbpf-tools/filelife.c` | compile_error |
| `eval-bcc-1d659c7f3388` | eval_commits | bcc | no | no_target_file | no | no_target_file | failed | `n/a` | no_target_file |
| `eval-bcc-2070a2aefb0b` | eval_commits | bcc | no | no_target_file | no | no_target_file | failed | `n/a` | no_target_file |
| `eval-bcc-45f5df4c5942` | eval_commits | bcc | yes | load_error | yes | load_error | partial | `libbpf-tools/numamove.bpf.c` | buggy=load_error, fixed=load_error |
| `eval-bcc-5a547e73d31d` | eval_commits | bcc | no | compile_error | no | compile_error | failed | `libbpf-tools/tcptracer.c` | compile_error |
| `eval-bcc-799acc7ca2c6` | eval_commits | bcc | yes | pass | yes | fail | partial | `libbpf-tools/softirqs.bpf.c` | buggy=pass, fixed=fail |
| `eval-bcc-8206f547b8e3` | eval_commits | bcc | no | no_target_file | no | no_target_file | failed | `n/a` | no_target_file |
| `eval-bcc-8319d52dc883` | eval_commits | bcc | no | no_target_file | no | no_target_file | failed | `n/a` | no_target_file |
| `eval-bcc-89c7f409b4a6` | eval_commits | bcc | yes | pass | yes | pass | partial | `libbpf-tools/ksnoop.bpf.c` | buggy=pass, fixed=pass |
| `eval-bcc-952415e490bd` | eval_commits | bcc | yes | pass | yes | pass | partial | `libbpf-tools/biolatency.bpf.c` | buggy=pass, fixed=pass |
| `eval-bcc-a75f0180b714` | eval_commits | bcc | yes | pass | yes | pass | partial | `libbpf-tools/tcprtt.bpf.c` | buggy=pass, fixed=pass |
| `eval-bcc-b0f891d129a9` | eval_commits | bcc | no | no_target_file | no | no_target_file | failed | `n/a` | no_target_file |
| `eval-bcc-d4e505c1e4ed` | eval_commits | bcc | yes | pass | yes | pass | partial | `libbpf-tools/bitesize.bpf.c` | buggy=pass, fixed=pass |
| `eval-bcc-f09b5b8acdd5` | eval_commits | bcc | no | no_target_file | no | no_target_file | failed | `n/a` | no_target_file |
| `eval-bcc-f2006eaa5901` | eval_commits | bcc | yes | pass | yes | pass | partial | `libbpf-tools/cpufreq.bpf.c` | buggy=pass, fixed=pass |
| `eval-bcc-f6c8cfe4244a` | eval_commits | bcc | no | no_target_file | no | no_target_file | failed | `n/a` | no_target_file |
| `eval-bcc-feadea6d789f` | eval_commits | bcc | no | no_target_file | no | no_target_file | failed | `n/a` | no_target_file |
| `eval-katran-07e10334022f` | eval_commits | katran | no | compile_error | no | compile_error | failed | `katran/lib/bpf/balancer_kern.c` | compile_error |
| `eval-katran-1c79d8c6db85` | eval_commits | katran | no | compile_error | no | compile_error | failed | `katran/lib/bpf/balancer_kern.c` | compile_error |
| `eval-katran-5d1e2ca8b9d7` | eval_commits | katran | no | compile_error | no | compile_error | failed | `katran/decap/bpf/decap_kern.c` | compile_error |
| `eval-katran-745374f1cf04` | eval_commits | katran | no | compile_error | no | compile_error | failed | `katran/decap/bpf/decap.bpf.c` | compile_error |
| `eval-katran-918c0e169773` | eval_commits | katran | yes | load_error | yes | load_error | partial | `katran/lib/bpf/balancer_kern.c` | buggy=load_error, fixed=load_error |
| `eval-katran-996c74a07133` | eval_commits | katran | no | compile_error | no | compile_error | failed | `katran/decap/bpf/decap.bpf.c` | compile_error |
| `eval-katran-a20ebf46f0d5` | eval_commits | katran | no | compile_error | no | compile_error | failed | `katran/decap/bpf/decap.bpf.c` | compile_error |
| `eval-katran-d195c045a01b` | eval_commits | katran | yes | load_error | yes | load_error | partial | `katran/lib/bpf/balancer_kern.c` | buggy=load_error, fixed=load_error |
| `eval-katran-d3c0229b0731` | eval_commits | katran | yes | load_error | yes | load_error | partial | `katran/lib/bpf/balancer_kern.c` | buggy=load_error, fixed=load_error |
| `eval-katran-d4edcd2c5a99` | eval_commits | katran | yes | load_error | yes | load_error | partial | `katran/lib/bpf/balancer_kern.c` | buggy=load_error, fixed=load_error |
| `github-aya-rs-aya-1056` | github_issues | aya | no | compile_error | no | compile_error | failed | `source_snippets` | compile_error |
| `github-aya-rs-aya-1062` | github_issues | aya | no | compile_error | no | compile_error | failed | `source_snippets` | compile_error |
| `stackoverflow-53136145` | stackoverflow | stackoverflow | no | compile_error | no | compile_error | failed | `source_snippets` | compile_error |
| `stackoverflow-60506220` | stackoverflow | stackoverflow | no | no_buggy_source | no | n/a | failed | `source_snippets` | no_buggy_source |
| `stackoverflow-70729664` | stackoverflow | stackoverflow | no | no_buggy_source | no | compile_error | failed | `source_snippets` | no_buggy_source |
| `stackoverflow-70750259` | stackoverflow | stackoverflow | no | compile_error | no | compile_error | failed | `source_snippets` | compile_error |
| `stackoverflow-70873332` | stackoverflow | stackoverflow | no | compile_error | no | compile_error | failed | `source_snippets` | compile_error |
| `stackoverflow-71522674` | stackoverflow | stackoverflow | no | compile_error | no | compile_error | failed | `source_snippets` | compile_error |
| `stackoverflow-72074115` | stackoverflow | stackoverflow | no | compile_error | no | compile_error | failed | `source_snippets` | compile_error |
| `stackoverflow-72560675` | stackoverflow | stackoverflow | no | compile_error | no | compile_error | failed | `source_snippets` | compile_error |
| `stackoverflow-72575736` | stackoverflow | stackoverflow | no | compile_error | no | compile_error | failed | `source_snippets` | compile_error |
| `stackoverflow-73088287` | stackoverflow | stackoverflow | no | compile_error | no | compile_error | failed | `source_snippets` | compile_error |
| `stackoverflow-74178703` | stackoverflow | stackoverflow | no | compile_error | no | compile_error | failed | `source_snippets` | compile_error |
| `stackoverflow-76160985` | stackoverflow | stackoverflow | yes | pass | yes | pass | partial | `source_snippets` | buggy=pass, fixed=pass |
| `stackoverflow-76637174` | stackoverflow | stackoverflow | no | no_buggy_source | no | compile_error | failed | `source_snippets` | no_buggy_source |
| `stackoverflow-77762365` | stackoverflow | stackoverflow | no | no_buggy_source | no | compile_error | failed | `source_snippets` | no_buggy_source |
| `stackoverflow-79485758` | stackoverflow | stackoverflow | no | compile_error | no | compile_error | failed | `source_snippets` | compile_error |
| `stackoverflow-79530762` | stackoverflow | stackoverflow | no | no_buggy_source | no | compile_error | failed | `source_snippets` | no_buggy_source |
