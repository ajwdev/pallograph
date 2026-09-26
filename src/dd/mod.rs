// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Differential-dataflow evaluation backend.
//!
//! # Architecture
//!
//! The public entry point is [`evaluate`], which satisfies the same contract as
//! `InterpreterBackend::evaluate`: given a flat slice of EDB facts and Mangle rule
//! source strings, return a map from relation name to the set of derived tuples.
//!
//! # Phasing
//!
//! - **Phase 0 (current):** stub — returns only the EDB facts.  Wiring is correct;
//!   the `Val`/`Row` wrapper types and their parity tests are the Phase 0 deliverable.
//! - **Phase 1:** non-recursive joins + filters via `lower.rs` + `build.rs`.
//! - **Phase 2:** negation (antijoin).
//! - **Phase 3:** recursion (`iterate`/`Variable`).
//! - **Phase 4:** `Let` / `MatchField` / `IterateList` + string builtins. Full parity.
//! - **Phase 5 (deferred):** true incremental evaluation with persistent `InputSession`s.

pub(crate) mod value;

use std::collections::HashMap;

use anyhow::Result;
use mangle_common::Value;

/// Evaluate the Datalog program defined by `rule_sources` against `edb`.
///
/// Returns a map from relation name to the fully-derived set of tuples (both EDB
/// and IDB relations), equivalent to what `InterpreterBackend::evaluate` produces.
///
/// **Phase 0 stub:** currently returns only the EDB facts with no rule evaluation.
/// Full DD evaluation arrives in Phases 1-4.
pub(crate) fn evaluate(
    edb: &[(String, Vec<Value>)],
    _rule_sources: &[String],
) -> Result<HashMap<String, Vec<Vec<Value>>>> {
    let mut facts: HashMap<String, Vec<Vec<Value>>> = HashMap::new();
    for (rel, tuple) in edb {
        facts.entry(rel.clone()).or_default().push(tuple.clone());
    }
    Ok(facts)
}
