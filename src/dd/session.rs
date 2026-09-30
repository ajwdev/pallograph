// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Persistent, incremental DD session.
//!
//! # Overview
//!
//! `DdSession` wraps a timely worker running on a background thread.  The worker
//! builds the full dataflow once and keeps its `InputSession` handles alive, so
//! subsequent fact additions/retractions only push deltas rather than rebuilding
//! the entire pipeline.
//!
//! # Communication
//!
//! The REPL thread and the worker communicate via a `crossbeam-channel` pair:
//!
//! ```text
//!   REPL thread  ──[Command]──►  worker thread
//!                ◄──[ack/rows]──
//! ```
//!
//! `std::sync::mpsc::Receiver` is `!Sync`, which would violate timely's `Fn +
//! Send + Sync + 'static` closure bound.  `crossbeam_channel::Receiver` is
//! `Send + Sync` and its `try_recv` takes `&self`, so it works inside the closure.
//!
//! # Query path (Milestone B)
//!
//! Output collections are arranged with `arrange_by_self()`, which writes all updates
//! into a `TraceAgent` (a shared handle on the accumulated ordered log).  On a
//! `Command::Query`, the worker cursors the relevant trace at the current frontier,
//! sums the diffs, and returns all rows with a positive total count.
//!
//! `TraceAgent` is `!Send` (it uses `Rc` internally), so it cannot be moved to the
//! REPL thread.  All cursoring happens on the worker thread; the REPL receives only
//! the finished `Vec<Vec<Value>>`.
//!
//! After each settled `Commit`, both the logical and physical compaction frontiers are
//! advanced to the new epoch.  This collapses history so that memory stays bounded —
//! we never need time-travel queries.
//!
//! # Shutdown safety
//!
//! `WorkerGuards::drop` **blocks** until the worker thread joins
//! (`timely::execute.rs`, `initialize.rs:422`).  If we drop the guard while the
//! worker is still spinning in its command loop, we deadlock.  `DdSession::drop`
//! sends `Command::Shutdown` first and waits for the ack before releasing the guard.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use crossbeam_channel::{bounded, unbounded, Receiver, Sender};
use differential_dataflow::input::{Input, InputSession};
use differential_dataflow::operators::arrange::TraceAgent;
use differential_dataflow::operators::iterate::VecVariable;
use differential_dataflow::trace::implementations::KeySpine;
use differential_dataflow::trace::{Cursor, TraceReader};
use differential_dataflow::VecCollection;
use mangle_common::Value;
use timely::order::Product;
use timely::progress::frontier::AntichainRef;
use timely::communication::WorkerGuards;

use super::build::build_rule;
use super::value::Row;
use super::build_strata;

// ---------------------------------------------------------------------------
// Command protocol
// ---------------------------------------------------------------------------

pub enum Command {
    /// Insert one row into a relation (not visible until next Commit).
    Insert { rel: String, row: Row },
    /// Retract one row from a relation (not visible until next Commit).
    Remove { rel: String, row: Row },
    /// Advance to the next epoch, step until settled, then ack.
    /// Blocks the caller (via ack channel) until the worker has quiesced.
    Commit { ack: Sender<()> },
    /// Snapshot a relation from the sink and send it back.
    /// Milestone A: the worker reads the mutex on behalf of the caller so
    /// the API is uniform; Milestone B will cursor the trace instead.
    Query { rel: String, resp: Sender<Vec<Vec<Value>>> },
    /// Snapshot EVERY relation's current contents (EDB + IDB) and send them back.
    /// Used by the batch `DdBackend::evaluate` path.
    SnapshotAll { resp: Sender<HashMap<String, Vec<Vec<Value>>>> },
    /// Attempt to add new IDB rules by layering a fresh dataflow.
    ///
    /// The worker checks whether the new rule's head predicate (`new_head`) is
    /// already materialized.  If it is, or if any new stratum is recursive,
    /// acks `NeedsRebuild`; otherwise builds the layered dataflow and acks
    /// `Layered`.
    AddRules {
        all_rule_sources: Vec<String>,
        /// Head predicate of the newly added rule(s), pre-extracted by the caller.
        new_head: Option<String>,
        ack: Sender<AddOutcome>,
    },
    /// Terminate the worker loop.  Must be sent (and acked) before dropping the guard.
    Shutdown { ack: Sender<()> },
}

/// Result of a `Command::AddRules` request.
#[derive(Debug)]
pub enum AddOutcome {
    /// A new dataflow was layered; no EDB rehydration was needed.
    Layered,
    /// The rule extends an existing predicate or is recursive; caller must rebuild.
    NeedsRebuild,
    /// The rule set is invalid (compile error, or a rule the DD builder cannot
    /// translate).  The caller should reject it and keep the existing session.
    Error(String),
}

// ---------------------------------------------------------------------------
// Trace draining
// ---------------------------------------------------------------------------

/// Concrete trace type produced by `arrange_by_self()` on a `Row` collection.
/// Spelled out so `drain_trace` can be a plain (non-generic) function — the
/// `Key`/`Diff` GATs resist a generic signature.
type RowTrace = TraceAgent<KeySpine<Row, u32, isize>>;

/// Drain all rows with a positive accumulated count from a single trace.
///
/// Shared by `Command::Query` (one relation) and `Command::SnapshotAll` (every
/// relation).  Cursoring requires `&mut` on the trace; the returned `Vec` is
/// owned, so the caller can iterate `traces` mutably without borrow conflicts.
fn drain_trace(trace: &mut RowTrace) -> Vec<Vec<Value>> {
    let (mut cursor, storage) = trace.cursor();
    let mut result = Vec::new();
    while cursor.key_valid(&storage) {
        while cursor.val_valid(&storage) {
            let mut count: isize = 0;
            cursor.map_times(&storage, |_t, diff| {
                count += diff;
            });
            if count > 0 {
                result.push(cursor.key(&storage).to_owned().into_values());
            }
            cursor.step_val(&storage);
        }
        cursor.step_key(&storage);
    }
    result
}

// ---------------------------------------------------------------------------
// DdSession
// ---------------------------------------------------------------------------

/// A running differential-dataflow session backed by a persistent worker thread.
pub struct DdSession {
    /// Command sender — cheap to clone for concurrent feeders.
    tx: Sender<Command>,
    /// Worker thread guard — `Some` until drop, when we Shutdown+join.
    guard: Option<WorkerGuards<()>>,
}

impl DdSession {
    /// Spawn a persistent worker for `rule_sources` and seed it with `edb`.
    ///
    /// After this returns the worker is fully settled at epoch 1 with the initial
    /// EDB visible.
    pub fn spawn(
        edb: &[(String, Vec<Value>)],
        rule_sources: &[String],
    ) -> Result<Self> {
        // -----------------------------------------------------------------------
        // Compile all strata while we still have &rule_sources available.
        // -----------------------------------------------------------------------
        let (strata_work, all_edb_rels) = build_strata(rule_sources)?;

        // -----------------------------------------------------------------------
        // Group EDB facts by relation and convert to Row.
        // -----------------------------------------------------------------------
        let mut edb_by_rel: HashMap<String, Vec<Row>> = HashMap::new();
        for (rel, tuple) in edb {
            edb_by_rel
                .entry(rel.clone())
                .or_default()
                .push(Row::from(tuple.as_slice()));
        }

        let mut input_rels_set: std::collections::HashSet<String> =
            all_edb_rels.into_iter().collect();
        input_rels_set.extend(edb_by_rel.keys().cloned());
        let input_rels: Vec<String> = input_rels_set.into_iter().collect();

        // Wrap non-Copy data in Arc so the Fn closure (which timely may call
        // more than once per worker) can clone rather than move them.
        let strata_work = Arc::new(strata_work);
        let input_rels = Arc::new(input_rels);
        let edb_by_rel = Arc::new(edb_by_rel);

        // Unbounded so that Insert/Remove/Commit commands never block the sender
        // while the worker is busy stepping.
        let (tx, rx): (Sender<Command>, Receiver<Command>) = unbounded();

        // `timely::execute` spawns the worker onto a background thread and returns
        // as soon as the thread is launched — it does NOT wait for the closure body
        // to run.  Without this rendezvous, `spawn()` would return before the initial
        // EDB seed/settle below has actually happened, racing the caller against the
        // worker thread.  `ready_tx` carries `Ok(())` once settle completes, or
        // `Err(msg)` if any rule failed to translate; `spawn()` blocks on
        // `ready_rx` before returning and propagates that result.
        let (ready_tx, ready_rx): (
            Sender<Result<(), String>>,
            Receiver<Result<(), String>>,
        ) = bounded(1);

        // -----------------------------------------------------------------------
        // Launch the worker.
        //
        // timely::execute requires `Fn + Send + Sync + 'static`.  Every variable
        // captured by the closure must therefore be `Send + Sync`.  That is why:
        //   - we use crossbeam_channel (Receiver is Sync; std mpsc Receiver is !Sync)
        //   - all state (handles, probe, epoch) lives *inside* the closure, not as
        //     captured `&mut`s (Fn, not FnMut)
        // -----------------------------------------------------------------------
        let guard = timely::execute(timely::Config::thread(), move |worker| {
            let ready_tx = ready_tx.clone();
            // ------------------------------------------------------------------
            // Build the dataflow once and collect InputSession handles + probe.
            // ------------------------------------------------------------------
            // Clone Arc handles here (inside the Fn body) rather than moving the
            // originals.  This satisfies the Fn bound: the outer closure can be
            // invoked multiple times without consuming these values.
            let probe = timely::dataflow::ProbeHandle::new();
            let strata_work = Arc::clone(&strata_work);
            let input_rels = Arc::clone(&input_rels);
            let edb_by_rel = Arc::clone(&edb_by_rel);

            let (mut handles, mut traces, build_errors) = worker
                .dataflow::<u32, _, _>({
                    let input_rels = Arc::clone(&input_rels);
                    let strata_work = strata_work;
                    let probe_ref = probe.clone();

                    move |scope| {
                        let mut handles: HashMap<String, InputSession<u32, Row, isize>> =
                            HashMap::new();
                        let mut rels: HashMap<String, VecCollection<'_, u32, Row>> =
                            HashMap::new();
                        // Any rule the DD builder can't translate is collected here and
                        // reported back to spawn() so it fails loudly rather than
                        // silently dropping the rule (which would yield wrong results).
                        let mut build_errors: Vec<String> = Vec::new();

                        for rel in input_rels.iter() {
                            let (handle, coll) = scope.new_collection::<Row, isize>();
                            rels.insert(rel.clone(), coll);
                            handles.insert(rel.clone(), handle);
                        }

                        let unit_coll = scope.new_collection_from(vec![Row(vec![])]).1;

                        for stratum in strata_work.iter() {
                            if stratum.rules.is_empty() {
                                continue;
                            }

                            if stratum.is_recursive {
                                let head_preds: std::collections::HashSet<String> = stratum
                                    .rules
                                    .iter()
                                    .map(|r| r.head_rel.clone())
                                    .collect();

                                let results: HashMap<String, VecCollection<'_, u32, Row>> =
                                    scope.iterative::<u64, _, _>(|nested| {
                                        let summary =
                                            Product::new(Default::default(), 1u64);

                                        let mut inner_rels: HashMap<
                                            String,
                                            VecCollection<'_, Product<u32, u64>, Row>,
                                        > = rels
                                            .iter()
                                            .map(|(k, v)| (k.clone(), v.clone().enter(nested)))
                                            .collect();
                                        let inner_unit = unit_coll.clone().enter(nested);

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
                                                let (var, coll) =
                                                    VecVariable::new_from(seed, summary);
                                                vars.insert(pred.clone(), var);
                                                var_colls.insert(pred.clone(), coll);
                                            } else {
                                                let (var, coll) =
                                                    VecVariable::new(nested, summary);
                                                vars.insert(pred.clone(), var);
                                                var_colls.insert(pred.clone(), coll);
                                            }
                                        }
                                        for (pred, coll) in &var_colls {
                                            inner_rels.insert(pred.clone(), coll.clone());
                                        }

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
                                                    build_errors.push(format!(
                                                        "rule for `{}`: {e}",
                                                        rule.head_rel
                                                    ));
                                                }
                                            }
                                        }

                                        let mut out: HashMap<
                                            String,
                                            VecCollection<'_, u32, Row>,
                                        > = HashMap::new();
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
                                let mut by_head: HashMap<
                                    String,
                                    Vec<VecCollection<'_, u32, Row>>,
                                > = HashMap::new();

                                for rule in &stratum.rules {
                                    match build_rule(rule, &rels, &unit_coll) {
                                        Ok(coll) => {
                                            by_head
                                                .entry(rule.head_rel.clone())
                                                .or_default()
                                                .push(coll);
                                        }
                                        Err(e) => {
                                            build_errors.push(format!(
                                                "rule for `{}`: {e}",
                                                rule.head_rel
                                            ));
                                        }
                                    }
                                }

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

                        // Arrange each output collection.
                        //
                        // `arrange_by_self` writes every update into an ordered, on-worker
                        // trace (TraceAgent).  Queries cursor the trace at the current
                        // frontier; compaction keeps memory bounded after each commit.
                        // probe_with is called before arranging so the ProbeHandle
                        // registers this edge in the dataflow graph.
                        let mut traces = HashMap::new();
                        for (rel_name, coll) in rels {
                            let arranged = coll.probe_with(&probe_ref).arrange_by_self();
                            traces.insert(rel_name, arranged.trace);
                        }

                        (handles, traces, build_errors)
                    }
                });

            // If any rule failed to translate, abandon the (unrun) dataflow and
            // report the failure to spawn() instead of silently proceeding with
            // an incomplete rule set.
            if !build_errors.is_empty() {
                let _ = ready_tx.send(Err(build_errors.join("\n")));
                return;
            }

            // ------------------------------------------------------------------
            // Seed the worker with the initial EDB at epoch 1, then settle.
            // ------------------------------------------------------------------
            for (rel, rows) in edb_by_rel.iter() {
                if let Some(handle) = handles.get_mut(rel) {
                    for row in rows {
                        handle.insert(row.clone());
                    }
                }
            }
            for handle in handles.values_mut() {
                handle.advance_to(1);
                handle.flush();
            }
            // Step until the initial EDB is fully propagated.
            worker.step_or_park_while(None, || probe.less_than(&1u32));

            // Tell `spawn()` the initial seed/settle is done and it's safe to
            // hand the session to the caller.
            let _ = ready_tx.send(Ok(()));

            // ------------------------------------------------------------------
            // Command loop.
            // ------------------------------------------------------------------
            // The epoch monotonically increases.  Insert/Remove commands buffer
            // diffs into the InputSession; Commit advances the epoch and steps
            // the worker until the probe clears, then acks.  Shutdown exits.
            let mut epoch: u32 = 1;

            loop {
                match rx.recv() {
                    Err(_) => break, // sender dropped — treat as Shutdown
                    Ok(cmd) => match cmd {
                        Command::Insert { rel, row } => {
                            if let Some(h) = handles.get_mut(&rel) {
                                h.insert(row);
                            }
                        }
                        Command::Remove { rel, row } => {
                            if let Some(h) = handles.get_mut(&rel) {
                                h.remove(row);
                            }
                        }
                        Command::Commit { ack } => {
                            epoch += 1;
                            for h in handles.values_mut() {
                                h.advance_to(epoch);
                                h.flush();
                            }
                            worker.step_or_park_while(None, || probe.less_than(&epoch));
                            // Compact traces to the new frontier so history collapses
                            // and memory stays bounded (we never do time-travel queries).
                            let frontier_elems = [epoch];
                            let frontier = AntichainRef::new(&frontier_elems);
                            for trace in traces.values_mut() {
                                trace.set_logical_compaction(frontier);
                                trace.set_physical_compaction(frontier);
                            }
                            let _ = ack.send(());
                        }
                        Command::Query { rel, resp } => {
                            let rows =
                                traces.get_mut(&rel).map(drain_trace).unwrap_or_default();
                            let _ = resp.send(rows);
                        }
                        Command::SnapshotAll { resp } => {
                            let mut out: HashMap<String, Vec<Vec<Value>>> = HashMap::new();
                            for (rel, trace) in traces.iter_mut() {
                                out.insert(rel.clone(), drain_trace(trace));
                            }
                            let _ = resp.send(out);
                        }
                        Command::AddRules { all_rule_sources, new_head, ack } => {
                            // Check if the new rule extends an already-materialized predicate.
                            // If so the existing trace is stale and only a full rebuild is correct.
                            let extends_existing = new_head.as_deref()
                                .map(|h| traces.contains_key(h))
                                .unwrap_or(true); // conservative: unknown head → rebuild

                            if extends_existing {
                                let _ = ack.send(AddOutcome::NeedsRebuild);
                                continue;
                            }

                            // Compile the full accumulated rule set to find strata for new preds.
                            let (all_strata, _edb_rels) = match build_strata(&all_rule_sources) {
                                Ok(r) => r,
                                Err(e) => {
                                    let _ = ack.send(AddOutcome::Error(format!(
                                        "compile error: {e:#}"
                                    )));
                                    continue;
                                }
                            };

                            // Select strata whose head predicates are all new (not yet materialized).
                            // Strata with existing head preds are already correctly materialized — skip.
                            let to_layer: Vec<super::StratumWork> = all_strata
                                .into_iter()
                                .filter(|s| {
                                    !s.rules.is_empty()
                                        && s.rules.iter().all(|r| !traces.contains_key(&r.head_rel))
                                })
                                .collect();

                            // Recursive new predicates need the iterative/VecVariable import path.
                            // Fall back to rebuild for now (worse-is-better: correct and rare).
                            if to_layer.iter().any(|s| s.is_recursive) || to_layer.is_empty() {
                                let _ = ack.send(AddOutcome::NeedsRebuild);
                                continue;
                            }

                            // Layer a new dataflow that imports all current traces.
                            // This runs synchronously on the worker thread, so TraceAgent (!Send)
                            // is fine as a captured variable in the FnOnce closure.
                            let imported_traces: HashMap<String, _> =
                                traces.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                            let probe_ref = probe.clone();

                            let (mut new_traces, layer_errors) =
                                worker.dataflow::<u32, _, _>(move |scope| {
                                // Import each existing trace as a VecCollection.
                                let mut rels: HashMap<String, VecCollection<'_, u32, Row>> =
                                    imported_traces
                                        .into_iter()
                                        .map(|(name, mut trace)| {
                                            let coll = trace
                                                .import(scope)
                                                .as_collection(|row, _| row.clone());
                                            (name, coll)
                                        })
                                        .collect();

                                let unit_coll =
                                    scope.new_collection_from(vec![Row(vec![])]).1;
                                let mut new_inner: HashMap<String, _> = HashMap::new();
                                let mut layer_errors: Vec<String> = Vec::new();

                                for stratum in &to_layer {
                                    let mut by_head: HashMap<
                                        String,
                                        Vec<VecCollection<'_, u32, Row>>,
                                    > = HashMap::new();
                                    for rule in &stratum.rules {
                                        match build_rule(rule, &rels, &unit_coll) {
                                            Ok(coll) => {
                                                by_head
                                                    .entry(rule.head_rel.clone())
                                                    .or_default()
                                                    .push(coll);
                                            }
                                            Err(e) => {
                                                layer_errors.push(format!(
                                                    "rule for `{}`: {e}",
                                                    rule.head_rel
                                                ));
                                            }
                                        }
                                    }
                                    for (head_rel, colls) in by_head {
                                        let idb = colls
                                            .into_iter()
                                            .reduce(|a, b| a.concat(b))
                                            .unwrap()
                                            .distinct();
                                        // Expose to subsequent strata in this batch (linear chain).
                                        rels.insert(head_rel.clone(), idb.clone());
                                        let arranged = idb.probe_with(&probe_ref).arrange_by_self();
                                        new_inner.insert(head_rel, arranged.trace);
                                    }
                                }

                                (new_inner, layer_errors)
                            });

                            // A rule failed to translate: reject the addition and keep
                            // the existing session intact (the just-built dataflow is
                            // abandoned, unsettled).
                            if !layer_errors.is_empty() {
                                let _ = ack.send(AddOutcome::Error(layer_errors.join("\n")));
                                continue;
                            }

                            // Settle the new dataflow to the current epoch.
                            worker.step_or_park_while(None, || probe.less_than(&epoch));

                            // Compact to the current frontier so history stays bounded.
                            let frontier_elems = [epoch];
                            let frontier = AntichainRef::new(&frontier_elems);
                            for trace in new_traces.values_mut() {
                                trace.set_logical_compaction(frontier);
                                trace.set_physical_compaction(frontier);
                            }

                            // Merge new relation traces into the session.
                            traces.extend(new_traces);
                            let _ = ack.send(AddOutcome::Layered);
                        }
                        Command::Shutdown { ack } => {
                            // Advance all handles to a sentinel epoch so timely knows
                            // no more data is coming, then ack before returning.
                            epoch += 1;
                            for h in handles.values_mut() {
                                h.advance_to(epoch);
                                h.flush();
                            }
                            let _ = ack.send(());
                            return;
                        }
                    },
                }
            }
        })
        .map_err(|e| anyhow::anyhow!("timely::execute failed: {e}"))?;

        // Block until the worker thread has finished the initial seed/settle
        // (see `ready_tx` above) so callers can rely on the documented
        // "settled at epoch 1" invariant.  A build failure surfaces here.
        match ready_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(msg)) => {
                // The worker has already returned; dropping the guard joins it.
                return Err(anyhow::anyhow!(
                    "dd backend cannot evaluate these rules:\n{msg}"
                ));
            }
            Err(e) => {
                return Err(anyhow::anyhow!("worker exited before settling: {e}"));
            }
        }

        Ok(DdSession {
            tx,
            guard: Some(guard),
        })
    }

    // -------------------------------------------------------------------------
    // Fact mutation API
    // -------------------------------------------------------------------------

    /// Buffer an insert delta.  Not visible until `commit()`.
    pub fn insert(&self, rel: String, row: Row) {
        let _ = self.tx.send(Command::Insert { rel, row });
    }

    /// Buffer a retract delta.  Not visible until `commit()`.
    pub fn retract(&self, rel: String, row: Row) {
        let _ = self.tx.send(Command::Remove { rel, row });
    }

    /// Flush buffered deltas and block until the worker has settled.
    pub fn commit(&self) {
        let (ack_tx, ack_rx) = bounded(1);
        let _ = self.tx.send(Command::Commit { ack: ack_tx });
        let _ = ack_rx.recv();
    }

    /// Query current results for `rel`.
    ///
    /// Milestone A: reads the `Arc<Mutex>` sink via the worker (uniform API).
    /// Milestone B: will cursor a TraceAgent on the worker thread instead.
    pub fn query(&self, rel: &str) -> Vec<Vec<Value>> {
        let (resp_tx, resp_rx) = bounded(1);
        let _ = self.tx.send(Command::Query {
            rel: rel.to_string(),
            resp: resp_tx,
        });
        resp_rx.recv().unwrap_or_default()
    }

    /// Snapshot every relation (EDB + all derived IDB) at the current frontier.
    ///
    /// Used by the batch `DdBackend::evaluate` path: spawn a session, snapshot,
    /// then drop.  Mirrors `query()` but returns all relations at once.
    pub fn snapshot_all(&self) -> HashMap<String, Vec<Vec<Value>>> {
        let (resp_tx, resp_rx) = bounded(1);
        let _ = self.tx.send(Command::SnapshotAll { resp: resp_tx });
        resp_rx.recv().unwrap_or_default()
    }

    /// Attempt to add a new IDB rule by layering a fresh dataflow on top of the
    /// current one.  If the rule extends an existing materialized predicate or is
    /// recursive, falls back to a full `rebuild` automatically.
    ///
    /// `new_head` is the head predicate of the newly added rule, pre-extracted
    /// by the caller (see `engine::extract_head_pred`).  `all_rule_sources` is the
    /// full accumulated rule set including the new rule.
    pub fn add_idb(
        &mut self,
        new_head: Option<&str>,
        edb: &[(String, Vec<Value>)],
        all_rule_sources: &[String],
    ) -> Result<()> {
        let (ack_tx, ack_rx) = bounded(1);
        let _ = self.tx.send(Command::AddRules {
            all_rule_sources: all_rule_sources.to_vec(),
            new_head: new_head.map(|s| s.to_string()),
            ack: ack_tx,
        });
        match ack_rx.recv()? {
            AddOutcome::Layered => Ok(()),
            AddOutcome::NeedsRebuild => self.rebuild(edb, all_rule_sources),
            AddOutcome::Error(msg) => Err(anyhow::anyhow!(
                "dd backend cannot evaluate this rule:\n{msg}"
            )),
        }
    }

    /// Clone the sender so a concurrent feeder (e.g. a K8s watcher) can
    /// push `Insert`/`Remove`/`Commit` commands from another thread.
    pub fn sender(&self) -> Sender<Command> {
        self.tx.clone()
    }

    /// Rebuild the session from scratch (for rule changes).
    ///
    /// Shuts down the existing worker, spawns a new one with the updated
    /// `rule_sources`, and re-seeds it with `edb`.
    pub fn rebuild(
        &mut self,
        edb: &[(String, Vec<Value>)],
        rule_sources: &[String],
    ) -> Result<()> {
        // Shutdown the existing worker (joining it) before spawning the next one
        // so we never have two workers alive simultaneously.
        self.shutdown_worker();
        *self = Self::spawn(edb, rule_sources)?;
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    fn shutdown_worker(&mut self) {
        if self.guard.is_some() {
            let (ack_tx, ack_rx) = bounded(1);
            let _ = self.tx.send(Command::Shutdown { ack: ack_tx });
            // Block until the worker acknowledges — it will return immediately after.
            let _ = ack_rx.recv();
            // Now safe to drop the guard: the worker thread has already returned.
            self.guard = None;
        }
    }
}

impl Drop for DdSession {
    fn drop(&mut self) {
        // Must send Shutdown before dropping the guard, or WorkerGuards::drop will
        // block forever waiting for a worker loop that never exits.
        self.shutdown_worker();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use mangle_common::Value;

    fn v_str(s: &str) -> Value {
        Value::String(s.to_string())
    }

    /// Regression: an `IndexLookup` join must lower to a KEYED `Step::Join`
    /// (non-empty key columns), not a cross product. The mangle planner lowers
    /// `reachable(X,Z) :- reachable(X,Y), link(Y,Z)` as an IndexLookup keyed on
    /// Y; the DD backend must honor `col_idx` rather than cross-producting and
    /// leaning on the downstream equality Filter.
    #[test]
    fn indexlookup_lowers_to_keyed_join() {
        use crate::dd::lower::Step;
        let rules = vec!["Decl link(Src, Dst).\nDecl reachable(Src, Dst).\n\
             reachable(X, Y) :- link(X, Y).\n\
             reachable(X, Z) :- reachable(X, Y), link(Y, Z)."
            .to_string()];
        let (strata, _edb) = crate::dd::build_strata(&rules).expect("build_strata");

        let mut saw_join = false;
        for stratum in &strata {
            for rule in &stratum.rules {
                for step in &rule.steps {
                    if let Step::Join { left_key_cols, right_key_cols, .. } = step {
                        saw_join = true;
                        assert!(
                            !left_key_cols.is_empty() && !right_key_cols.is_empty(),
                            "IndexLookup join lowered to a cross product (empty key cols): {step:?}"
                        );
                    }
                }
            }
        }
        assert!(saw_join, "expected a Join in the lowered transitive-closure rules");
    }

    /// Spin up a session with a trivial rule and verify query results.
    #[test]
    fn session_basic_query() {
        let edb: Vec<(String, Vec<Value>)> = vec![
            ("edge".to_string(), vec![v_str("a"), v_str("b")]),
            ("edge".to_string(), vec![v_str("b"), v_str("c")]),
        ];

        // rule: path(X, Y) :- edge(X, Y).
        let rules = vec![
            "Decl edge(Src, Dst).\nDecl path(Src, Dst).\npath(X, Y) :- edge(X, Y)."
                .to_string(),
        ];

        let session = DdSession::spawn(&edb, &rules).expect("spawn");
        let mut results = session.query("path");
        results.sort();
        assert_eq!(
            results,
            vec![
                vec![v_str("a"), v_str("b")],
                vec![v_str("b"), v_str("c")],
            ]
        );
    }

    /// Insert a new fact, commit, and verify it becomes visible.
    #[test]
    fn session_incremental_insert() {
        let edb: Vec<(String, Vec<Value>)> = vec![
            ("edge".to_string(), vec![v_str("a"), v_str("b")]),
        ];

        let rules = vec![
            "Decl edge(Src, Dst).\nDecl path(Src, Dst).\npath(X, Y) :- edge(X, Y)."
                .to_string(),
        ];

        let session = DdSession::spawn(&edb, &rules).expect("spawn");

        // Before insert: only a→b
        let before = session.query("path");
        assert_eq!(before.len(), 1);

        // Insert b→c, commit, then check
        session.insert("edge".to_string(), Row::from(&[v_str("b"), v_str("c")][..]));
        session.commit();

        let mut after = session.query("path");
        after.sort();
        assert_eq!(
            after,
            vec![
                vec![v_str("a"), v_str("b")],
                vec![v_str("b"), v_str("c")],
            ]
        );
    }

    /// Retract a fact, commit, and verify it disappears.
    #[test]
    fn session_incremental_retract() {
        let edb: Vec<(String, Vec<Value>)> = vec![
            ("edge".to_string(), vec![v_str("a"), v_str("b")]),
            ("edge".to_string(), vec![v_str("b"), v_str("c")]),
        ];

        let rules = vec![
            "Decl edge(Src, Dst).\nDecl path(Src, Dst).\npath(X, Y) :- edge(X, Y)."
                .to_string(),
        ];

        let session = DdSession::spawn(&edb, &rules).expect("spawn");

        // Both edges visible initially
        assert_eq!(session.query("path").len(), 2);

        // Retract b→c
        session.retract("edge".to_string(), Row::from(&[v_str("b"), v_str("c")][..]));
        session.commit();

        let after = session.query("path");
        assert_eq!(after, vec![vec![v_str("a"), v_str("b")]]);
    }

    /// Dropping a session must complete promptly (no deadlock).
    #[test]
    fn session_drop_promptness() {
        let edb: Vec<(String, Vec<Value>)> = vec![
            ("edge".to_string(), vec![v_str("x"), v_str("y")]),
        ];
        let rules = vec![
            "Decl edge(Src, Dst).\nDecl path(Src, Dst).\npath(X, Y) :- edge(X, Y)."
                .to_string(),
        ];
        let session = DdSession::spawn(&edb, &rules).expect("spawn");
        drop(session); // Must not block
    }

    // -----------------------------------------------------------------------
    // Phase 6: layered dataflow tests
    // -----------------------------------------------------------------------

    /// Add a new view IDB by layering; results match a fresh batch evaluate.
    #[test]
    fn layer_view_matches_batch() {
        let edb: Vec<(String, Vec<Value>)> = vec![
            ("edge".to_string(), vec![v_str("a"), v_str("b")]),
            ("edge".to_string(), vec![v_str("b"), v_str("c")]),
        ];

        let base_rules = vec![
            "Decl edge(Src, Dst).\nDecl path(Src, Dst).\npath(X, Y) :- edge(X, Y)."
                .to_string(),
        ];

        let mut session = DdSession::spawn(&edb, &base_rules).expect("spawn");

        // Layer a view: view(X) :- path(X, _).
        let mut all_rules = base_rules.clone();
        all_rules.push("Decl view(Src).\nview(X) :- path(X, _).".to_string());
        session
            .add_idb(Some("view"), &edb, &all_rules)
            .expect("add_idb");

        let mut results = session.query("view");
        results.sort();
        // view should contain the source nodes of every path edge: a and b
        assert_eq!(results, vec![vec![v_str("a")], vec![v_str("b")]]);
    }

    /// After layering a view, inserting a new fact propagates to the view.
    #[test]
    fn layer_view_tracks_fact_deltas() {
        let edb: Vec<(String, Vec<Value>)> = vec![
            ("edge".to_string(), vec![v_str("a"), v_str("b")]),
        ];

        let base_rules = vec![
            "Decl edge(Src, Dst).\nDecl path(Src, Dst).\npath(X, Y) :- edge(X, Y)."
                .to_string(),
        ];

        let mut session = DdSession::spawn(&edb, &base_rules).expect("spawn");

        let mut all_rules = base_rules.clone();
        all_rules.push("Decl view(Src).\nview(X) :- path(X, _).".to_string());
        session
            .add_idb(Some("view"), &edb, &all_rules)
            .expect("add_idb");

        // Before insert: only a
        let before = session.query("view");
        assert_eq!(before, vec![vec![v_str("a")]]);

        // Insert b→c, commit — view should now also contain b.
        session.insert("edge".to_string(), Row::from(&[v_str("b"), v_str("c")][..]));
        session.commit();

        let mut after = session.query("view");
        after.sort();
        assert_eq!(after, vec![vec![v_str("a")], vec![v_str("b")]]);
    }

    /// Layer two views in sequence; the second references the first (linear chain).
    #[test]
    fn layer_chain() {
        let edb: Vec<(String, Vec<Value>)> = vec![
            ("edge".to_string(), vec![v_str("a"), v_str("b")]),
            ("edge".to_string(), vec![v_str("b"), v_str("c")]),
        ];

        let base_rules = vec![
            "Decl edge(Src, Dst).\nDecl path(Src, Dst).\npath(X, Y) :- edge(X, Y)."
                .to_string(),
        ];

        let mut session = DdSession::spawn(&edb, &base_rules).expect("spawn");

        // Layer view1: view1(X) :- path(X, _).
        let mut rules_v1 = base_rules.clone();
        rules_v1.push("Decl view1(Src).\nview1(X) :- path(X, _).".to_string());
        session
            .add_idb(Some("view1"), &edb, &rules_v1)
            .expect("add_idb view1");

        // Layer view2: view2(X) :- view1(X).
        let mut rules_v2 = rules_v1.clone();
        rules_v2.push("Decl view2(Src).\nview2(X) :- view1(X).".to_string());
        session
            .add_idb(Some("view2"), &edb, &rules_v2)
            .expect("add_idb view2");

        let mut results = session.query("view2");
        results.sort();
        assert_eq!(results, vec![vec![v_str("a")], vec![v_str("b")]]);
    }

    /// Adding a rule for an existing predicate falls back to rebuild; results are correct.
    #[test]
    fn layer_fallback_on_extend() {
        let edb: Vec<(String, Vec<Value>)> = vec![
            ("edge".to_string(), vec![v_str("a"), v_str("b")]),
        ];

        let base_rules = vec![
            "Decl edge(Src, Dst).\nDecl path(Src, Dst).\npath(X, Y) :- edge(X, Y)."
                .to_string(),
        ];

        let mut session = DdSession::spawn(&edb, &base_rules).expect("spawn");

        // Add a second rule for the existing `path` predicate.
        // This should trigger NeedsRebuild internally.
        let mut all_rules = base_rules.clone();
        all_rules.push("path(X, X) :- edge(X, _).".to_string());
        session
            .add_idb(Some("path"), &edb, &all_rules)
            .expect("add_idb fallback");

        // After rebuild, path should include both original edges and the reflexive pairs.
        let mut results = session.query("path");
        results.sort();
        assert!(
            results.contains(&vec![v_str("a"), v_str("b")]),
            "original edge missing: {results:?}"
        );
        assert!(
            results.contains(&vec![v_str("a"), v_str("a")]),
            "reflexive pair missing: {results:?}"
        );
    }

    /// The DD backend's build-time guard for `Step::CallFilter` must reject any
    /// function name it doesn't implement, sourced from the single
    /// `is_supported_call_filter` list.
    ///
    /// NOTE: this is a direct unit test of the guard predicate rather than an
    /// end-to-end spawn test, because a typo'd `:string:` name never reaches the
    /// DD backend as a `Step::CallFilter`. The mangle planner has a hardcoded
    /// allowlist of builtin predicate names (`:string:starts_with`,
    /// `:string:ends_with`, `:string:contains`, `:match_prefix`, `:match_field`,
    /// ...); only those become a `Condition::Call`. Any other `:`-prefixed atom
    /// (e.g. the typo `:string:startswith`) falls through to the default arm and
    /// is planned as an ordinary relation join instead. So the guard fires only
    /// when the mangle allowlist grows to include a builtin the DD backend has
    /// not yet implemented, keeping the two lists from drifting apart silently.
    #[test]
    fn dd_call_filter_guard_rejects_unsupported() {
        use crate::dd::build::is_supported_call_filter;
        // Every name the mangle planner turns into a Condition::Call today.
        assert!(is_supported_call_filter(":string:starts_with"));
        assert!(is_supported_call_filter(":string:ends_with"));
        assert!(is_supported_call_filter(":string:contains"));
        assert!(is_supported_call_filter(":match_prefix"));
        // A typo / not-yet-implemented builtin must be rejected.
        assert!(!is_supported_call_filter(":string:startswith"));
        assert!(!is_supported_call_filter(":string:matches"));
    }

    /// A rule with a VALID string builtin must spawn successfully and produce
    /// the expected filtered results (the guard must not break valid rules).
    #[test]
    fn session_supported_call_filter_ok() {
        let edb: Vec<(String, Vec<Value>)> = vec![
            ("name".to_string(), vec![v_str("alpha")]),
            ("name".to_string(), vec![v_str("beta")]),
        ];

        let rules = vec![
            "Decl name(N).\nDecl hit(N).\nhit(N) :- name(N), :string:starts_with(N, \"al\")."
                .to_string(),
        ];

        let session = DdSession::spawn(&edb, &rules).expect("spawn with valid builtin");
        let mut results = session.query("hit");
        results.sort();
        assert_eq!(results, vec![vec![v_str("alpha")]]);
    }
}
