// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Differential-dataflow evaluation backend.
//!
//! # Overview
//!
//! This module owns the shared frontend for the DD backend: [`build_strata`]
//! compiles Mangle rule sources into lowered, stratum-ordered rules.  Both the
//! batch path (`DdBackend::evaluate`) and the persistent incremental path build
//! their dataflow from the same strata.
//!
//! The actual dataflow construction and worker lifecycle live in
//! [`session::DdSession`].  Batch evaluation is just a session that is spawned,
//! snapshotted, and dropped; there is no separate one-shot evaluator.

pub mod build;
pub mod lower;
pub mod session;
pub mod value;

use anyhow::{Context, Result};
use mangle_ast::Arena;
use mangle_ir::Inst;

use crate::engine::EDB_DECLS;
use lower::{LoweredRule, lower_op};

// ---------------------------------------------------------------------------
// Strata compilation (shared between batch evaluate and DdSession)
// ---------------------------------------------------------------------------

/// A single compiled stratum: a set of rules and whether they form a recursive SCC.
pub struct StratumWork {
    pub is_recursive: bool,
    pub rules: Vec<LoweredRule>,
}

/// Compile `rule_sources` into lowered, stratum-ordered rules.
///
/// Returns `(strata, edb_relation_names)`.  All Ir/Arena lifetimes are resolved
/// to owned data before returning; the caller does not need to hold Ir alive.
pub fn build_strata(rule_sources: &[String]) -> Result<(Vec<StratumWork>, Vec<String>)> {
    use mangle_ir::InstId;
    use std::collections::HashSet;

    let mut sources: Vec<&str> = vec![EDB_DECLS];
    for s in rule_sources {
        sources.push(s.as_str());
    }

    let arena = Arena::new_with_global_interner();
    let (mut ir, stratified) =
        mangle_driver::compile_units(&sources, &arena).context("compile rules")?;

    if !ir.temporal_predicates.is_empty() {
        let names: Vec<&str> = ir
            .temporal_predicates
            .iter()
            .map(|id| ir.resolve_name(*id))
            .collect();
        anyhow::bail!(
            "DD backend does not support temporal predicates ({})",
            names.join(", ")
        );
    }

    let edb_rels: Vec<String> = stratified
        .extensional_preds()
        .iter()
        .filter_map(|pred| arena.predicate_name(*pred))
        .map(|s| s.to_string())
        .collect();

    let mut strata = Vec::new();

    for stratum in stratified.strata() {
        let mut stratum_pred_names: HashSet<String> = HashSet::new();
        for pred in &stratum {
            if let Some(name) = arena.predicate_name(*pred) {
                stratum_pred_names.insert(name.to_string());
            }
        }

        let mut rule_ids: Vec<InstId> = Vec::new();
        for (i, inst) in ir.insts.iter().enumerate() {
            if let Inst::Rule { head, .. } = inst {
                if let Inst::Atom { predicate, .. } = ir.get(*head) {
                    if stratum_pred_names.contains(ir.resolve_name(*predicate)) {
                        rule_ids.push(InstId::new(i));
                    }
                }
            }
        }

        if rule_ids.is_empty() {
            strata.push(StratumWork {
                is_recursive: false,
                rules: vec![],
            });
            continue;
        }

        let mut is_recursive = false;
        'outer: for &rule_id in &rule_ids {
            if let Inst::Rule { premises, .. } = ir.get(rule_id) {
                for &premise in premises {
                    if let Inst::Atom { predicate, .. } = ir.get(premise) {
                        if stratum_pred_names.contains(ir.resolve_name(*predicate)) {
                            is_recursive = true;
                            break 'outer;
                        }
                    }
                }
            }
        }

        let mut lowered = Vec::new();
        for rule_id in rule_ids {
            let planner = mangle_analysis::Planner::new(&mut ir);
            let op = planner.plan_rule(rule_id).context("plan rule")?;
            lowered.push(lower_op(&op, &ir).context("lower rule")?);
        }

        strata.push(StratumWork {
            is_recursive,
            rules: lowered,
        });
    }

    Ok((strata, edb_rels))
    // ir, stratified, arena all dropped here; lowered rules are fully owned.
}
