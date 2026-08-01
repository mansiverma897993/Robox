//! Robox's deterministic analysis kernel.
//!
//! The MVP parses Rust with `syn`, builds lightweight project and relationship
//! models, and runs explainable rules. Compiler CFG/DFG, symbolic execution,
//! rust-analyzer integration, and LLM review belong behind extension traits;
//! they are deliberately not claimed by this implementation.

mod domain;
mod engine;
mod rules;

pub use domain::*;
pub use engine::{EngineError, ScanEngine};
pub use rules::{Rule, RuleContext, RuleMetadata, RuleRegistry};
