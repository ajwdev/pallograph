// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Differential-dataflow evaluation backend.
//!
//! # Overview
//!
//! `evaluate()` is the public entry point.  It satisfies the same contract as
//! `InterpreterBackend::evaluate`: given EDB facts + Mangle rule sources, return
//! a map of relation → derived tuples.
//!
//! # Batch execution model
//!
//! We call `timely::execute_directly` (single-threaded), which builds a dataflow
//! graph in a `worker.dataflow(|scope| {...})` call, feeds EDB data through
//! `InputSession` handles, steps the worker to completion, and returns results
//! collected via `inspect_batch` into `Arc<Mutex<...>>` sinks.
//!
//! # Phases
//!
//! - **Phase 0**: wiring + `Val`/`Row` wrapper.
//! - **Phase 1** (current): non-recursive strata — `Scan`, `Join`, `Cmp`, `Insert`.
//! - **Phase 2**: `Antijoin` / `CallFilter` (negation + string builtins).
//! - **Phase 3**: `iterate`/`Variable` for recursive strata.
//! - **Phase 4**: `Let` / `MatchField` / `IterateList`. Full parity milestone.
//! - **Phase 5** (deferred): persistent `InputSession`s for true incremental eval.

pub(crate) mod build;
pub(crate) mod lower;
pub(crate) mod value;
pub(crate) mod session;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use differential_dataflow::input::{Input, InputSession};
use differential_dataflow::operators::iterate::VecVariable;
use differential_dataflow::VecCollection;
use mangle_ast::Arena;
use timely::order::Product;
use mangle_common::Value;
use mangle_ir::Inst;

use crate::engine::EDB_DECLS;
use build::build_rule;
use lower::{LoweredRule, lower_op};
use value::Row;

// ---------------------------------------------------------------------------
// Strata compilation (shared between batch evaluate and DdSession)
// ---------------------------------------------------------------------------

/// A single compiled stratum: a set of rules and whether they form a recursive SCC.
pub(crate) struct StratumWork {
    pub(crate) is_recursive: bool,
    pub(crate) rules: Vec<LoweredRule>,
}

/// Compile `rule_sources` into lowered, stratum-ordered rules.
///
/// Returns `(strata, edb_relation_names)`.  All Ir/Arena lifetimes are resolved
/// to owned data before returning; the caller does not need to hold Ir alive.
pub(crate) fn build_strata(
    rule_sources: &[String],
) -> Result<(Vec<StratumWork>, Vec<String>)> {
    use std::collections::HashSet;
    use mangle_ir::InstId;

    let mut sources: Vec<&str> = vec![EDB_DECLS];
    for s in rule_sources {
        sources.push(s.as_str());
    }

    let arena = Arena::new_with_global_interner();
    let (mut ir, stratified) =
        mangle_driver::compile_units(&sources, &arena).context("compile rules")?;

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
            strata.push(StratumWork { is_recursive: false, rules: vec![] });
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

        strata.push(StratumWork { is_recursive, rules: lowered });
    }

    Ok((strata, edb_rels))
    // ir, stratified, arena all dropped here; lowered rules are fully owned.
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Evaluate `rule_sources` against `edb` using differential-dataflow.
///
/// Returns a map from relation name to the fully-derived set of tuples (EDB + IDB),
/// equivalent to `InterpreterBackend::evaluate`.
pub(crate) fn evaluate(
    edb: &[(String, Vec<Value>)],
    rule_sources: &[String],
) -> Result<HashMap<String, Vec<Vec<Value>>>> {
    // -----------------------------------------------------------------------
    // Step 1: compile rules and plan + lower all strata while Ir is alive.
    // All name/string resolution must happen here before execute_directly.
    // -----------------------------------------------------------------------
    let (strata_work, all_edb_rels) = build_strata(rule_sources)?;

    // -----------------------------------------------------------------------
    // Step 2: group EDB facts by relation and convert to Row.
    // -----------------------------------------------------------------------
    let mut edb_by_rel: HashMap<String, Vec<Row>> = HashMap::new();
    for (rel, tuple) in edb {
        edb_by_rel
            .entry(rel.clone())
            .or_default()
            .push(Row::from(tuple.as_slice()));
    }

    // Union of declared EDB relations + any relations present in the facts slice.
    let mut input_rels: std::collections::HashSet<String> =
        all_edb_rels.into_iter().collect();
    input_rels.extend(edb_by_rel.keys().cloned());
    let input_rels: Vec<String> = input_rels.into_iter().collect();

    // -----------------------------------------------------------------------
    // Step 3: run the dataflow.
    //
    // Sink: relation → { row → accumulated_diff }
    // We use Arc<Mutex<...>> because execute_directly requires 'static closures.
    // -----------------------------------------------------------------------
    let sink: Arc<Mutex<HashMap<String, HashMap<Row, isize>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let sink_clone = Arc::clone(&sink);
    let edb_by_rel_owned = edb_by_rel;
    let input_rels_owned = input_rels;

    timely::execute_directly(move |worker| -> Result<()> {
        // Build the dataflow; the closure returns input handles to feed data through.
        let mut handles: HashMap<String, InputSession<u32, Row, isize>> = worker
            .dataflow::<u32, _, _>({
                let sink = Arc::clone(&sink_clone);
                let input_rels = input_rels_owned;
                let strata_work = strata_work;

                move |scope| -> HashMap<String, InputSession<u32, Row, isize>> {
                    let mut handles: HashMap<String, InputSession<u32, Row, isize>> =
                        HashMap::new();
                    let mut rels: HashMap<String, VecCollection<'_, u32, Row>> = HashMap::new();

                    // One InputSession per EDB relation.
                    for rel in &input_rels {
                        let (handle, collection) = scope.new_collection::<Row, isize>();
                        rels.insert(rel.clone(), collection);
                        handles.insert(rel.clone(), handle);
                    }

                    // Unit collection: one empty row — used by unit rules (no body).
                    let unit_coll = scope.new_collection_from(vec![Row(vec![])]).1;

                    // Process strata in dependency order.
                    for stratum in &strata_work {
                        if stratum.rules.is_empty() {
                            continue;
                        }

                        if stratum.is_recursive {
                            // Phase 3: recursive fixpoint via Variable / iterative scope.
                            //
                            // For each in-stratum head predicate, create a VecVariable
                            // seeded with whatever base facts already exist (usually none),
                            // build every rule (base + recursive) inside the iterative scope
                            // using the live variable collections, bind each variable to
                            // (current ∪ new_facts).distinct(), then leave results back to
                            // the outer scope.
                            //
                            // `scope` is Copy, so it can be captured by the closure for
                            // the .leave(scope) calls while also being the receiver of
                            // .iterative().
                            let head_preds: std::collections::HashSet<String> = stratum
                                .rules
                                .iter()
                                .map(|r| r.head_rel.clone())
                                .collect();

                            let results: HashMap<String, VecCollection<'_, u32, Row>> =
                                scope.iterative::<u64, _, _>(|nested| {
                                    let summary = Product::new(Default::default(), 1u64);

                                    // Enter all outer relations into the nested scope.
                                    let mut inner_rels: HashMap<
                                        String,
                                        VecCollection<'_, Product<u32, u64>, Row>,
                                    > = rels
                                        .iter()
                                        .map(|(k, v)| (k.clone(), v.clone().enter(nested)))
                                        .collect();
                                    let inner_unit = unit_coll.clone().enter(nested);

                                    // Create a Variable for each in-stratum head predicate.
                                    let mut vars: HashMap<
                                        String,
                                        VecVariable<'_, Product<u32, u64>, Row, isize>,
                                    > = HashMap::new();
                                    let mut var_colls: HashMap<
                                        String,
                                        VecCollection<'_, Product<u32, u64>, Row>,
                                    > = HashMap::new();
                                    for pred in &head_preds {
                                        if let Some(seed) = inner_rels.remove(pred) {
                                            // Pre-existing base in rels (unusual but handled).
                                            let (var, coll) = VecVariable::new_from(seed, summary);
                                            vars.insert(pred.clone(), var);
                                            var_colls.insert(pred.clone(), coll);
                                        } else {
                                            // Fresh recursive predicate — start empty.
                                            let (var, coll) = VecVariable::new(nested, summary);
                                            vars.insert(pred.clone(), var);
                                            var_colls.insert(pred.clone(), coll);
                                        }
                                    }
                                    // Expose the live variable collections for rules to scan.
                                    for (pred, coll) in &var_colls {
                                        inner_rels.insert(pred.clone(), coll.clone());
                                    }

                                    // Build all rules (base + recursive) against inner_rels.
                                    let mut by_head: HashMap<
                                        String,
                                        Vec<VecCollection<'_, Product<u32, u64>, Row>>,
                                    > = HashMap::new();
                                    for rule in &stratum.rules {
                                        match build_rule(rule, &inner_rels, &inner_unit) {
                                            Ok(coll) => {
                                                by_head
                                                    .entry(rule.head_rel.clone())
                                                    .or_default()
                                                    .push(coll);
                                            }
                                            Err(e) => {
                                                eprintln!(
                                                    "dd(recursive): skipping rule for `{}`: {e}",
                                                    rule.head_rel
                                                );
                                            }
                                        }
                                    }

                                    // Bind each Variable to (current ∪ new_facts).distinct()
                                    // and leave results back to the outer scope.
                                    let mut out: HashMap<String, VecCollection<'_, u32, Row>> =
                                        HashMap::new();
                                    for (pred, var) in vars {
                                        let curr = var_colls.remove(&pred).unwrap();
                                        let full = match by_head.remove(&pred) {
                                            Some(colls) => {
                                                let new_facts = colls
                                                    .into_iter()
                                                    .reduce(|a, b| a.concat(b))
                                                    .unwrap();
                                                curr.concat(new_facts).distinct()
                                            }
                                            None => curr.distinct(),
                                        };
                                        var.set(full.clone());
                                        out.insert(pred, full.leave(scope));
                                    }
                                    out
                                });

                            // Merge recursive results into rels.
                            for (pred, coll) in results {
                                match rels.entry(pred) {
                                    std::collections::hash_map::Entry::Occupied(mut e) => {
                                        let old = e.get().clone();
                                        *e.get_mut() = old.concat(coll).distinct();
                                    }
                                    std::collections::hash_map::Entry::Vacant(e) => {
                                        e.insert(coll);
                                    }
                                }
                            }
                        } else {
                            // Phase 1/2: non-recursive strata — single pass.
                            let mut by_head: HashMap<String, Vec<VecCollection<'_, u32, Row>>> =
                                HashMap::new();

                            for rule in &stratum.rules {
                                match build_rule(rule, &rels, &unit_coll) {
                                    Ok(coll) => {
                                        by_head
                                            .entry(rule.head_rel.clone())
                                            .or_default()
                                            .push(coll);
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "dd: skipping rule for `{}`: {e}",
                                            rule.head_rel
                                        );
                                    }
                                }
                            }

                            // Concat + distinct per head relation, merge into rels.
                            for (head_rel, colls) in by_head {
                                let idb = colls
                                    .into_iter()
                                    .reduce(|a, b| a.concat(b))
                                    .unwrap()
                                    .distinct();
                                match rels.entry(head_rel) {
                                    std::collections::hash_map::Entry::Occupied(mut e) => {
                                        let old = e.get().clone();
                                        *e.get_mut() = old.concat(idb).distinct();
                                    }
                                    std::collections::hash_map::Entry::Vacant(e) => {
                                        e.insert(idb);
                                    }
                                }
                            }
                        }
                    }

                    // Attach inspect_batch sinks to collect results after stepping.
                    for (rel_name, coll) in rels {
                        let rel_name_owned = rel_name.clone();
                        let sink = Arc::clone(&sink);
                        coll.inspect_batch(move |_t: &u32, batch: &[(Row, u32, isize)]| {
                            let mut s = sink.lock().unwrap();
                            let rel_map = s.entry(rel_name_owned.clone()).or_default();
                            for (row, _t, diff) in batch {
                                *rel_map.entry(row.clone()).or_insert(0) += diff;
                            }
                        });
                    }

                    handles
                }
            });

        // Feed EDB data.
        for (rel, rows) in &edb_by_rel_owned {
            if let Some(handle) = handles.get_mut(rel) {
                for row in rows {
                    handle.insert(row.clone());
                }
            }
        }
        // Advance all handles and flush.
        for handle in handles.values_mut() {
            handle.advance_to(1);
            handle.flush();
        }
        // Drop handles to close the input streams.  Timely cannot quiesce while
        // live InputSessions exist (they signal that more data may still arrive).
        drop(handles);

        // Step until the dataflow finishes.
        while worker.has_dataflows() {
            worker.step_or_park(None);
        }

        Ok(())
    })
    .context("execute_directly")?;

    // -----------------------------------------------------------------------
    // Step 4: convert the sink into HashMap<String, Vec<Vec<Value>>>.
    // -----------------------------------------------------------------------
    let raw = Arc::try_unwrap(sink)
        .map_err(|_| anyhow::anyhow!("sink Arc still held after execute_directly"))?
        .into_inner()
        .unwrap();

    let mut facts: HashMap<String, Vec<Vec<Value>>> = HashMap::new();
    for (rel, row_map) in raw {
        let tuples: Vec<Vec<Value>> = row_map
            .into_iter()
            .filter(|(_, count)| *count > 0)
            .map(|(row, _)| row.into_values())
            .collect();
        facts.insert(rel, tuples);
    }

    Ok(facts)
}
