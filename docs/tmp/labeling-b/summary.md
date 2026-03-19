# Labeling B Summary

## Distribution of taxonomy classes
- `env_mismatch`: 15
- `lowering_artifact`: 18
- `source_bug`: 100
- `verifier_bug`: 2
- `verifier_limit`: 4

## Distribution of error IDs
- `BPFIX-E001`: 6
- `BPFIX-E002`: 4
- `BPFIX-E003`: 2
- `BPFIX-E004`: 3
- `BPFIX-E005`: 15
- `BPFIX-E006`: 3
- `BPFIX-E010`: 2
- `BPFIX-E011`: 8
- `BPFIX-E012`: 13
- `BPFIX-E013`: 12
- `BPFIX-E014`: 5
- `BPFIX-E015`: 5
- `BPFIX-E016`: 10
- `BPFIX-E017`: 5
- `BPFIX-E018`: 4
- `BPFIX-E019`: 16
- `BPFIX-E020`: 4
- `BPFIX-E021`: 4
- `BPFIX-E022`: 1
- `BPFIX-E023`: 17

## Distribution of confidence levels
- `high`: 122
- `medium`: 14
- `low`: 3

## Cases where I was unsure
- `stackoverflow-53136145`
- `stackoverflow-67402772`
- `stackoverflow-69767533`
- `stackoverflow-70729664`
- `stackoverflow-70750259`
- `stackoverflow-70760516`
- `stackoverflow-71522674`
- `stackoverflow-72560675`
- `stackoverflow-72575736`
- `stackoverflow-73088287`
- `stackoverflow-75643912`
- `stackoverflow-76160985`
- `stackoverflow-76637174`
- `stackoverflow-77762365`
- `github-aya-rs-aya-1056`
- `github-cilium-cilium-41412`
- `github-cilium-cilium-41522`

## Any patterns noticed
- Many kernel selftests map cleanly to dynptr protocol errors, iterator protocol errors, and IRQ or exception discipline errors.
- Most `lowering_artifact` cases involve packet or map bounds that are checked in source but lose proof after scalar arithmetic, loop lowering, or helper and subprogram boundaries.
- The `env_mismatch` cases are concentrated in loader or relocation problems, unsupported helper or context combinations, and runtime configuration differences.
- The lowest-confidence cases are the node-specific or version-specific regressions where the source looks plausible but the target verifier behaves inconsistently.
