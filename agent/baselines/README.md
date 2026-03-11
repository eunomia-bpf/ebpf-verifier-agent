# Baseline Conditions

This directory is reserved for the baseline diagnostic conditions used in agent and human studies.

- `raw_log`: untouched verifier output.
- `enhanced_log`: raw log plus catalog labels or source mapping hints.
- `structured_interface`: JSON diagnostic conforming to `interface/schema/diagnostic.json`.
- `dsl_guided`: structured diagnostic plus a restricted repair action space.

Concrete prompt templates, transformation scripts, or frozen baseline artifacts can be added here as the evaluation harness matures.

