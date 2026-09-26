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
//! # Milestones
//!
//! - **Milestone A** (current): sink is the existing `Arc<Mutex<HashMap<…>>>`.
//!   The worker's `inspect_batch` callbacks update it incrementally (+diff / -diff).
//!   REPL reads a relation by acquiring the mutex — no worker round-trip for queries.
//!   This proves the persistent worker + delta feeding end-to-end.
//!
//! - **Milestone B** (planned): replace sink with `arrange_by_self` + `TraceAgent`.
//!   Queries become a `Command::Query` that the worker answers by cursoring the trace.
//!   `TraceAgent` is `!Send`, so it cannot be moved to the REPL thread; it stays on
//!   the worker thread and is accessed only via the channel.
//!
//! # Shutdown safety
//!
//! `WorkerGuards::drop` **blocks** until the worker thread joins
//! (`timely::execute.rs`, `initialize.rs:422`).  If we drop the guard while the
//! worker is still spinning in its command loop, we deadlock.  `DdSession::drop`
//! sends `Command::Shutdown` first and waits for the ack before releasing the guard.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use crossbeam_channel::{bounded, unbounded, Receiver, Sender};
use differential_dataflow::input::{Input, InputSession};
use differential_dataflow::operators::iterate::VecVariable;
use differential_dataflow::VecCollection;
use mangle_common::Value;
use timely::order::Product;
use timely::communication::WorkerGuards;

use super::build::build_rule;
use super::value::Row;
use super::build_strata;

// ---------------------------------------------------------------------------
// Command protocol
// ---------------------------------------------------------------------------

pub(crate) enum Command {
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
    /// Terminate the worker loop.  Must be sent (and acked) before dropping the guard.
    Shutdown { ack: Sender<()> },
}

// ---------------------------------------------------------------------------
// DdSession
// ---------------------------------------------------------------------------

/// A running differential-dataflow session backed by a persistent worker thread.
pub(crate) struct DdSession {
    /// Command sender — cheap to clone for concurrent feeders.
    tx: Sender<Command>,
    /// Worker thread guard — `Some` until drop, when we Shutdown+join.
    guard: Option<WorkerGuards<()>>,
    /// Milestone A query path: shared sink updated by inspect_batch.
    sink: Arc<Mutex<HashMap<String, HashMap<Row, isize>>>>,
}

impl DdSession {
    /// Spawn a persistent worker for `rule_sources` and seed it with `edb`.
    ///
    /// After this returns the worker is fully settled at epoch 1 with the initial
    /// EDB visible.
    pub(crate) fn spawn(
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

        // -----------------------------------------------------------------------
        // Shared sink (Milestone A query path) and command channel.
        // -----------------------------------------------------------------------
        let sink: Arc<Mutex<HashMap<String, HashMap<Row, isize>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Unbounded so that Insert/Remove/Commit commands never block the sender
        // while the worker is busy stepping.
        let (tx, rx): (Sender<Command>, Receiver<Command>) = unbounded();

        let sink_for_worker = Arc::clone(&sink);
        let sink_for_session = Arc::clone(&sink);

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

            let mut handles: HashMap<String, InputSession<u32, Row, isize>> = worker
                .dataflow::<u32, _, _>({
                    let sink = Arc::clone(&sink_for_worker);
                    let input_rels = Arc::clone(&input_rels);
                    let strata_work = strata_work;
                    let probe_ref = probe.clone();

                    move |scope| -> HashMap<String, InputSession<u32, Row, isize>> {
                        let mut handles: HashMap<String, InputSession<u32, Row, isize>> =
                            HashMap::new();
                        let mut rels: HashMap<String, VecCollection<'_, u32, Row>> =
                            HashMap::new();

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
                                                    eprintln!(
                                                        "dd(session/recursive): skipping \
                                                         rule for `{}`: {e}",
                                                        rule.head_rel
                                                    );
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
                                            eprintln!(
                                                "dd(session): skipping rule for `{}`: {e}",
                                                rule.head_rel
                                            );
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

                        // Attach incremental inspect_batch sinks.
                        //
                        // Unlike the batch path (which rebuilds the dataflow from scratch
                        // every time), here the sink is maintained incrementally: each
                        // batch carries +diff / -diff counts that are applied in-place.
                        // Entries that reach zero are removed to keep memory bounded.
                        for (rel_name, coll) in rels {
                            let sink = Arc::clone(&sink);
                            let probe_ref = probe_ref.clone();
                            coll.probe_with(&probe_ref)
                                .inspect_batch(move |_t: &u32, batch: &[(Row, u32, isize)]| {
                                    let mut s = sink.lock().unwrap();
                                    let rel_map = s.entry(rel_name.clone()).or_default();
                                    for (row, _t, diff) in batch {
                                        let counter =
                                            rel_map.entry(row.clone()).or_insert(0);
                                        *counter += diff;
                                        if *counter == 0 {
                                            rel_map.remove(row);
                                        }
                                    }
                                });
                        }

                        handles
                    }
                });

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
                            let _ = ack.send(());
                        }
                        Command::Query { rel, resp } => {
                            // Milestone A: read from the Arc<Mutex> sink directly.
                            // Milestone B will cursor a TraceAgent here instead.
                            let s = sink_for_worker.lock().unwrap();
                            let rows: Vec<Vec<Value>> = s
                                .get(&rel)
                                .map(|map| {
                                    map.iter()
                                        .filter(|(_, count)| **count > 0)
                                        .map(|(row, _)| row.clone().into_values())
                                        .collect()
                                })
                                .unwrap_or_default();
                            let _ = resp.send(rows);
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

        Ok(DdSession {
            tx,
            guard: Some(guard),
            sink: sink_for_session,
        })
    }

    // -------------------------------------------------------------------------
    // Fact mutation API
    // -------------------------------------------------------------------------

    /// Buffer an insert delta.  Not visible until `commit()`.
    pub(crate) fn insert(&self, rel: String, row: Row) {
        let _ = self.tx.send(Command::Insert { rel, row });
    }

    /// Buffer a retract delta.  Not visible until `commit()`.
    pub(crate) fn retract(&self, rel: String, row: Row) {
        let _ = self.tx.send(Command::Remove { rel, row });
    }

    /// Flush buffered deltas and block until the worker has settled.
    pub(crate) fn commit(&self) {
        let (ack_tx, ack_rx) = bounded(1);
        let _ = self.tx.send(Command::Commit { ack: ack_tx });
        let _ = ack_rx.recv();
    }

    /// Query current results for `rel`.
    ///
    /// Milestone A: reads the `Arc<Mutex>` sink via the worker (uniform API).
    /// Milestone B: will cursor a TraceAgent on the worker thread instead.
    pub(crate) fn query(&self, rel: &str) -> Vec<Vec<Value>> {
        let (resp_tx, resp_rx) = bounded(1);
        let _ = self.tx.send(Command::Query {
            rel: rel.to_string(),
            resp: resp_tx,
        });
        resp_rx.recv().unwrap_or_default()
    }

    /// Clone the sender so a concurrent feeder (e.g. a K8s watcher) can
    /// push `Insert`/`Remove`/`Commit` commands from another thread.
    pub(crate) fn sender(&self) -> Sender<Command> {
        self.tx.clone()
    }

    /// Rebuild the session from scratch (for rule changes).
    ///
    /// Shuts down the existing worker, spawns a new one with the updated
    /// `rule_sources`, and re-seeds it with `edb`.
    pub(crate) fn rebuild(
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
}
