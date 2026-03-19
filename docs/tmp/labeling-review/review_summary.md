# Labeling Review Summary

## Agreement Statistics

- Overall agreement: `124/139` (89.21%)
- Cohen's kappa: `0.737`
- Disagreement count: `15`

| Class | A Count | B Count | Both | Union | Agreement Rate |
| --- | --- | --- | --- | --- | --- |
| `source_bug` | 110 | 100 | 99 | 111 | 89.19% |
| `lowering_artifact` | 10 | 18 | 8 | 20 | 40.00% |
| `verifier_limit` | 4 | 4 | 3 | 5 | 60.00% |
| `env_mismatch` | 13 | 15 | 13 | 15 | 86.67% |
| `verifier_bug` | 2 | 2 | 1 | 3 | 33.33% |

## Adjudication Summary

- Inter-label disagreements reviewed: `15`
- Additional manual-calibration overrides: `1`
- Total adjudicated cases in v3: `16`

A-to-final transition counts:
- `source_bug -> lowering_artifact`: `9`
- `source_bug -> env_mismatch`: `2`
- `lowering_artifact -> source_bug`: `1`
- `lowering_artifact -> verifier_bug`: `1`
- `verifier_bug -> lowering_artifact`: `1`

B-to-final transition counts:
- `env_mismatch -> verifier_limit`: `1`
- `lowering_artifact -> source_bug`: `1`
- `source_bug -> env_mismatch`: `1`
- `verifier_limit -> lowering_artifact`: `1`

## Validation Against Manual 30

- Manual labels parsed: `30`
- Overlap with the 139-case set: `18`
- Taxonomy-class match rate: `18/18` (100.00%)
- Error-ID match rate on catalog-matched overlaps: `14/16` (87.50%)
- No taxonomy-class mismatches remain on the overlapping manual cases.

## Final Taxonomy Distribution

| Class | Count | Share |
| --- | --- | --- |
| `source_bug` | 100 | 71.94% |
| `lowering_artifact` | 18 | 12.95% |
| `verifier_limit` | 4 | 2.88% |
| `env_mismatch` | 15 | 10.79% |
| `verifier_bug` | 2 | 1.44% |

## Recommended Human Review

- `github-cilium-cilium-41522`: The issue report is explicitly node-specific and regression-shaped, and the available case data does not show a concrete source-level check omission that would explain acceptance on the other nodes. That makes verifier-side regression the better fit, but the evidence is incomplete.
- `stackoverflow-70729664`: The failure is not an explicit complexity-limit rejection. The stronger evidence is the accepted explanation that the bounded `size` proof is lost after spill/reload when the loop gets large, which fits proof loss after lowering better than either `source_bug` or `verifier_limit`.
- `stackoverflow-72560675`: The failure is version-sensitive, but the source can be rewritten into an equivalent verifier-friendly form without changing the intended safety policy. That makes this closer to proof loss in an older verifier than to a pure verifier-bug label.
- `stackoverflow-75643912`: This source-level condition is genuinely too weak for a one-byte dereference at the equality boundary, and the accepted rewrite fixes the check itself rather than only changing code shape. That is stronger evidence for a real packet-bounds bug than for a lowering artifact.
- `stackoverflow-76637174`: The accepted answer points to loop rewrite and explicit verifier-friendly cursor checks, not to a fundamentally missing source safety condition. The rejection comes from proof shape and looped packet-pointer reconstruction.
- `stackoverflow-79485758`: The failing dereference already has a bounds check immediately above it. The selected explanation in the case data is a verifier corner case around packet-offset maxima, which is stronger evidence for lowering-induced proof loss than for a missing source guard.
- `stackoverflow-76441958`: This case is a calibration override against the manual labels. The source and log surface a scalar-pointer misuse, but the accepted explanation is architecture-dependent alignment behavior for atomic operations on user memory, which is better modeled as an environment mismatch.
