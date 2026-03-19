# Quality Pass Summary

- Root cause descriptions changed: `139`
- New confidence distribution:
  - `high`: `96`
  - `medium`: `33`
  - `low`: `10`
- Kernel selftests marked as intentional negatives: `85`
- Borderline `env_mismatch` cases: `6`
  - `kernel-selftest-dynptr-fail-invalid-slice-rdwr-rdonly-cgroup-skb-ingress-61688196`
  - `kernel-selftest-exceptions-fail-reject-async-callback-throw-tc-a86cf7b1`
  - `kernel-selftest-irq-irq-sleepable-global-subprog-indirect-syscall-c96d09ca`
  - `kernel-selftest-irq-irq-sleepable-helper-global-subprog-syscall-7d470f89`
  - `stackoverflow-76441958`
  - `github-aya-rs-aya-440`
- Lowering artifact evidence quality distribution:
  - `strong`: `8`
  - `medium`: `7`
  - `weak`: `5`
