#![allow(dead_code)]

//! eBPF bytecode and verifier-log analysis primitives.
//!
//! The core analysis modules are imported from the `bpfopt` project and kept
//! behind a small public surface that is useful for user-facing diagnostics.

pub mod analysis;
pub mod insn;
pub mod pass;
pub mod passes;

mod proof;
mod verifier_log;

pub use proof::{
    analyze_verifier_log, ProofEvent, ProofEventRole, ProofObligation, SourceLocation,
    VerifierLogAnalysis,
};

#[cfg(test)]
pub(crate) mod test_helpers;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierLogSummary {
    pub state_count: usize,
}

pub fn summarize_verifier_log(log: &str) -> anyhow::Result<VerifierLogSummary> {
    Ok(VerifierLogSummary {
        state_count: verifier_log::verifier_states_from_log(log)?.len(),
    })
}
