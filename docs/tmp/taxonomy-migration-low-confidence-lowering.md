# Low-Confidence Lowering Artifact Migration

Manual review of the three low-confidence current `lowering_artifact` blocking
cases under the orthogonal taxonomy scheme.

| case_id | old_class | new_class | mechanism_tags | obligation_ids | evidence_tags | decision rationale |
| --- | --- | --- | --- | --- | --- | --- |
| `stackoverflow-53136145` | `lowering_artifact` | `lowering_artifact` | `packet_bounds`, `pointer_provenance` | `BPFIX-O001`, `BPFIX-O006` | `source_check_present`, `cfg_join_widening`, `accepted_with_equivalent_lowering` | Remains `lowering_artifact`. The source checks the IPv4 and IPv6 header branches before deriving `udph`, but the post-branch pointer selection obscures which checked packet pointer is live. The accepted workaround uses an equivalent verifier-visible branch/condition, so this is pointer-provenance loss across a CFG join rather than a missing packet precondition. |
| `stackoverflow-70729664` | `lowering_artifact` | `lowering_artifact` | `packet_bounds`, `scalar_range`, `spill_reload_loss` | `BPFIX-O001`, `BPFIX-O005` | `source_check_present`, `proof_established_then_lost`, `spill_reload_loss`, `accepted_with_equivalent_lowering` | Remains `lowering_artifact`. The source clamps chunk size and checks `nh->pos + size` against `data_end`, while the trace and accepted answer show the bounded size being saved to stack before the comparison, reloaded as imprecise, and widened enough that the later packet-range proof is not retained. The verifier-friendly rewrite adds range preservation/clamping rather than a new packet-safety intent. |
| `stackoverflow-76637174` | `lowering_artifact` | `source_bug` | `packet_bounds`, `scalar_range` | `BPFIX-O001` | `source_check_incomplete`, `accepted_fix_adds_bounds_check` | Downgraded to `source_bug`. The failing loop checks `data + i < data_end`, but the accepted answer identifies the first issue as not accounting for the one-byte read width in the loop bound and then adds an explicit `+ 1` access guard plus a bounded loop. The verifier trace shows the access proof was not established for the rejected byte load, not that an established proof was later lost by lowering. |

Summary: `stackoverflow-53136145` and `stackoverflow-70729664` remain
`lowering_artifact` because each has concrete source-level proof-loss evidence.
`stackoverflow-76637174` is downgraded to `source_bug` because the strongest
available evidence is an incomplete packet-bound precondition at source level.
