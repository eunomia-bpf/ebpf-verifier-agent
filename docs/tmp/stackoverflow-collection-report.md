# Stack Overflow Collection Report

Run date: 2026-03-11

Command executed:

```bash
python3 benchmark/collect_stackoverflow.py \
  --output-dir benchmark/cases/stackoverflow \
  --max-questions 100 \
  --verbose
```

## Result

- Collected 76 Stack Overflow verifier-failure cases into `benchmark/cases/stackoverflow`.
- `benchmark/cases/stackoverflow/index.yaml` reports `case_count: 76`.
- Coverage details from the saved YAMLs:
  - 66 cases include extracted verifier log blocks.
  - 59 cases include extracted source snippets.
  - 66 cases include a selected answer with a summarized fix description.
- The search phase fetched 153 unique candidate questions; 76 survived the final relevance/failure filters.

## Representative Cases

1. `stackoverflow-70750259`  
   BPF verification error when trying to extract SNI from TLS packet  
   https://stackoverflow.com/questions/70750259/bpf-verification-error-when-trying-to-extract-sni-from-tls-packet  
   Representative packet-pointer range analysis failure. The accepted answer explains that `ext_len` is still unbounded from the verifier's perspective, so adding it to a packet pointer requires an extra bound check.

2. `stackoverflow-56872436`  
   BPF verifier rejecting XDP program due to back-edge even though pragma unroll is used  
   https://stackoverflow.com/questions/56872436/bpf-verifier-rejecting-xdp-program-due-to-back-edge-even-though-pragma-unroll-is  
   Good loop-structure case. The verifier still sees a back-edge; the accepted answer points to a working fully-unrolled loop form.

3. `stackoverflow-72575736`  
   Linux Kernel 5.10 verifier rejects eBPF XDP program that is fine for kernel 5.13  
   https://stackoverflow.com/questions/72575736/linux-kernel-5-10-verifier-rejects-ebpf-xdp-program-that-is-fine-for-kernel-5-13  
   Useful kernel-version-specific case. The answer ties the failure to a verifier bugfix present in 5.13 but missing from the 5.10 tree being used.

4. `stackoverflow-79812509`  
   BPF LSM: `bpf_task_storage_get` expects a trusted pointer  
   https://stackoverflow.com/questions/79812509/bpf-lsm-bpf-task-storage-get-expects-a-trusted-pointer  
   Strong modern typed-pointer example. The fix is to use `bpf_get_current_task_btf` so the verifier retains trusted pointer type information.

5. `stackoverflow-78753911`  
   eBPF: The sequence of 8193 jumps is too complex  
   https://stackoverflow.com/questions/78753911/ebpf-the-sequence-of-8193-jumps-is-too-complex  
   Representative state-explosion case. The issue is verifier path explosion rather than literal jump count.

6. `stackoverflow-79348306`  
   BPF verifier rejects the use of path pointer as argument to the `bpf_d_path` helper function  
   https://stackoverflow.com/questions/79348306/bpf-verifier-rejects-the-use-of-path-pointer-as-argument-to-the-bpf-d-path-helpe  
   Good helper-argument typing case. The verifier expects a trusted pointer-compatible type for `bpf_d_path`.

## Issues Encountered

- The script initially failed because `collect_stackoverflow.py` did not accept `--verbose`. I added a compatibility `--verbose` flag without changing the default logging behavior.
- The first run collected 78 YAMLs, but 2 were discussion-style false positives rather than concrete failure reports:
  - `stackoverflow-70403212` (`Why is eBPF said to be safer than LKM?`)
  - `stackoverflow-78524800` (`How do I study the performance of eBPF helper function calls?`)
- To fix that, I tightened the filter so no-log threads must also contain explicit failure language before being kept, then reran the collector and removed the two stale files from the initial pass.
- No Stack Exchange API rate-limit/backoff or response-format issues occurred during the successful run.
