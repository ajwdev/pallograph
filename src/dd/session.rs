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
use crossbeam_channel::{Receiver, Sender, bounded, unbounded};
use differential_dataflow::VecCollection;
use differential_dataflow::input::{Input, InputSession};
use differential_dataflow::operators::arrange::TraceAgent;
use differential_dataflow::operators::iterate::VecVariable;
use differential_dataflow::trace::implementations::KeySpine;
use differential_dataflow::trace::{Cursor, TraceReader};
use mangle_common::Value;
use timely::communication::WorkerGuards;
use timely::order::Product;
use timely::progress::frontier::AntichainRef;

use super::build::{
    Annotation, build_rule, eval_aggregate, eval_call_filter, eval_cmp, eval_expr,
    iterate_list_row, match_field_row, min_reduce_annotations, slot_val,
};
use super::lower::{LoweredRule, Slot, Step};
use super::value::{Row, SENTINEL_EDB, Val};
use super::{ProvenanceMode, build_strata};

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
    ///
    /// Responds with `Err` while any rule has live evaluation errors.
    Query {
        rel: String,
        resp: Sender<std::result::Result<Vec<Vec<Value>>, String>>,
    },
    /// Snapshot EVERY relation's current contents (EDB + IDB) and send them back.
    /// Used by the batch `DdBackend::evaluate` path.
    /// Responds with `Err` while any rule has live evaluation errors.
    SnapshotAll {
        resp: Sender<std::result::Result<HashMap<String, Vec<Vec<Value>>>, String>>,
    },
    /// Lazy provenance: look up a fact's stored `(rule_id, min_height)`
    /// annotation. `None` if the fact is not derived / has no annotation.
    /// (`docs/souffle-lazy-provenance-design.md` calls this `GetAnnotation`.)
    WhyHeight {
        rel: String,
        fact: Row,
        resp: Sender<Option<Annotation>>,
    },
    /// Lazy provenance backward-chaining step: given the rule that achieved the
    /// minimal-height derivation of `head`, find one grounding of that rule
    /// whose positive premises all have stored height strictly less than
    /// `max_height`. Returns the premises (each with its own `(rule_id,
    /// height)`) so the caller can recurse; `None` if no such grounding exists.
    /// (The design doc calls this `Subproof`.)
    WhyStep {
        rule_id: u32,
        head: Row,
        max_height: u32,
        resp: Sender<Option<Grounding>>,
    },
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

/// One backward-chaining subproof step result (lazy provenance): the positive
/// premises of a single grounding of the achieving rule, each carrying its own
/// annotation so the caller can descend.
#[derive(Debug, Clone)]
pub struct Grounding {
    pub rule_id: u32,
    pub premises: Vec<Premise>,
    /// The negated body atoms of this grounding, each a non-descendable
    /// `¬rel(args)` absent-leaf. These held (the key was absent from `rel`) for
    /// the grounding to fire, so a renderer prints them as satisfied-absence
    /// conditions. The lazy path does not explain *why* the fact is absent
    /// (no Soufflé why-not). Empty for rules with no negation.
    pub negated: Vec<NegatedFact>,
}

/// A negated body atom in a reconstructed [`Grounding`]: the absent condition
/// `¬rel(args)` that held for the grounding to fire. Rendered as a leaf; never
/// descended into. `args` are the resolved argument values in relation-column
/// order; `None` is an anonymous/wildcard argument (rendered `_`).
#[derive(Debug, Clone)]
pub struct NegatedFact {
    pub rel: String,
    pub args: Vec<Option<Val>>,
}

/// One positive premise of a [`Grounding`], with its stored annotation.
#[derive(Debug, Clone)]
pub struct Premise {
    pub rel: String,
    pub row: Row,
    /// `SENTINEL_EDB` if this premise is a base fact.
    pub rule_id: u32,
    /// `0` if this premise is a base fact.
    pub height: u32,
}

// ---------------------------------------------------------------------------
// Trace draining
// ---------------------------------------------------------------------------

/// Concrete trace type produced by `arrange_by_self()` on a `Row` collection.
/// Spelled out so `drain_trace` can be a plain (non-generic) function — the
/// `Key`/`Diff` GATs resist a generic signature.
type RowTrace = TraceAgent<KeySpine<Row, u64, isize>>;

/// Trace produced by `arrange_by_self()` on a lazy-annotation collection
/// `(Row, (rule_id, height))`. One entry per derived fact after the min-reduce.
type AnnotationTrace = TraceAgent<KeySpine<(Row, Annotation), u64, isize>>;

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

/// Concatenate a dataflow's runtime error collections and arrange them.
///
/// Always returns a trace (empty when no rule can error) so the caller can
/// treat every dataflow uniformly.
fn arrange_errors<'scope>(
    error_colls: Vec<VecCollection<'scope, u64, Row>>,
    unit_coll: &VecCollection<'scope, u64, Row>,
    probe: &timely::dataflow::ProbeHandle<u64>,
) -> RowTrace {
    let errors = error_colls
        .into_iter()
        .reduce(|a, b| a.concat(b))
        .unwrap_or_else(|| unit_coll.clone().filter(|_| false));
    errors.distinct().probe_with(probe).arrange_by_self().trace
}

/// `Err` with every distinct live evaluation error, if there are any.
///
/// The interpreter fails the whole evaluation on the first such error; a
/// dataflow can't stop mid-flight, so instead reads are refused for as long
/// as any error row is live.
fn live_errors(error_traces: &mut [RowTrace]) -> std::result::Result<(), String> {
    let mut msgs: Vec<String> = error_traces
        .iter_mut()
        .flat_map(drain_trace)
        .map(|row| match row.first() {
            Some(Value::String(m)) => m.clone(),
            other => format!("{other:?}"),
        })
        .collect();
    if msgs.is_empty() {
        return Ok(());
    }
    msgs.sort();
    msgs.dedup();
    Err(format!("evaluation error: {}", msgs.join("\n")))
}

/// Look up the stored `(rule_id, height)` annotation for `fact` in an
/// annotation trace. Full scan (the fact count in the MVP fixtures is tiny);
/// a production impl would `seek_key`. Returns the live entry with positive
/// accumulated count, or `None`.
fn lookup_annotation(trace: &mut AnnotationTrace, fact: &Row) -> Option<Annotation> {
    let (mut cursor, storage) = trace.cursor();
    while cursor.key_valid(&storage) {
        // The key is the whole `(Row, Annotation)` pair (arrange_by_self).
        let (row, annotation) = cursor.key(&storage).clone();
        if &row == fact {
            let mut count: isize = 0;
            cursor.map_times(&storage, |_t, diff| count += diff);
            if count > 0 {
                return Some(annotation);
            }
        }
        cursor.step_key(&storage);
    }
    None
}

/// Drain every live `(fact, (rule_id, height))` annotation from a trace into a
/// map `fact -> Annotation`. Used by the backward-chaining `WhyStep` to test each
/// candidate premise's height. (One entry per fact after the min-reduce.)
fn drain_annotations(trace: &mut AnnotationTrace) -> HashMap<Row, Annotation> {
    let (mut cursor, storage) = trace.cursor();
    let mut out = HashMap::new();
    while cursor.key_valid(&storage) {
        let (row, annotation) = cursor.key(&storage).clone();
        let mut count: isize = 0;
        cursor.map_times(&storage, |_t, diff| count += diff);
        if count > 0 {
            out.insert(row, annotation);
        }
        cursor.step_key(&storage);
    }
    out
}

/// Drain the live rows of a `RowTrace` into a `Vec<Row>` (not converted to
/// `Value`). Used by `WhyStep` to enumerate candidate premise tuples.
fn drain_trace_rows(trace: &mut RowTrace) -> Vec<Row> {
    let (mut cursor, storage) = trace.cursor();
    let mut result = Vec::new();
    while cursor.key_valid(&storage) {
        while cursor.val_valid(&storage) {
            let mut count: isize = 0;
            cursor.map_times(&storage, |_t, diff| count += diff);
            if count > 0 {
                result.push(cursor.key(&storage).to_owned());
            }
            cursor.step_val(&storage);
        }
        cursor.step_key(&storage);
    }
    result
}

/// Reconstruct one grounding of `rule` whose head projects to `head` and whose
/// positive premises all have stored height `< max_height`.
///
/// We replay every body step (exhaustively, mirroring `build_rule`) as an
/// in-memory nested-loop join over the materialised premise rows (`rows_of`),
/// threading the running wide-row assignment, then filter to those wide rows
/// whose head projection equals `head` and whose every positive premise passes
/// the strict-height guard. The first such grounding is returned.
///
/// - `Antijoin` (negation) replays as a row filter (drop wide rows whose key is
///   present in the negated relation). The surviving grounding's negated atoms
///   are surfaced as `¬rel(args)` absent-leaves in `Grounding::negated` — not
///   descended into.
/// - `Reduce` (aggregation) is a leaf: the aggregate is recomputed in-memory to
///   match `head`, and the grounding has no positive premises (no descent).
///
/// `rows_of(rel)` yields the live tuples of `rel`; `annotation_of(rel, tuple)` yields
/// its stored `(rule_id, height)` (EDB facts have height 0 / `SENTINEL_EDB`).
fn reconstruct_grounding(
    rule: &LoweredRule,
    head: &Row,
    max_height: u32,
    rows_of: &mut dyn FnMut(&str) -> Vec<Row>,
    annotation_of: &mut dyn FnMut(&str, &Row) -> Annotation,
) -> Option<Grounding> {
    // Build the set of candidate wide rows by replaying Scan/Join.
    let mut wide: Vec<Row> = Vec::new();
    let mut seeded = false;
    let n_steps = rule.steps.len();

    for (idx, step) in rule.steps.iter().enumerate() {
        match step {
            Step::Unit => {
                wide = vec![Row::empty()];
                seeded = true;
            }
            Step::Scan { rel, .. } => {
                wide = rows_of(rel);
                seeded = true;
            }
            Step::Join {
                rel,
                left_key_cols,
                right_key_cols,
                right_new_cols,
            } => {
                if !seeded {
                    return None;
                }
                let right_rows = rows_of(rel);
                let mut next: Vec<Row> = Vec::new();
                for left in &wide {
                    let lkey: Vec<Val> = left_key_cols.iter().map(|&i| left.0[i].clone()).collect();
                    for right in &right_rows {
                        let rkey: Vec<Val> =
                            right_key_cols.iter().map(|&i| right.0[i].clone()).collect();
                        if lkey == rkey {
                            next.push(
                                left.appended(right_new_cols.iter().map(|&i| right.0[i].clone())),
                            );
                        }
                    }
                }
                wide = next;
            }
            Step::Cmp { op, left, right } => {
                // Pure positive row filter; no premise, no height contribution.
                wide.retain(|row| eval_cmp(*op, &slot_val(left, row), &slot_val(right, row)));
            }
            Step::Antijoin {
                rel,
                left_key_slots,
                right_key_cols,
                const_filters,
            } => {
                // Replay the antijoin as a row filter: keep wide rows whose key
                // is absent from the (const-filtered) negated relation. Mirrors
                // the DD Antijoin builder in build.rs. Height-neutral: negated
                // atoms are not premises. The surviving grounding's `¬rel(args)`
                // leaves are surfaced at the Insert step via `rule.negated_atoms`.
                let neg_rows = rows_of(rel);
                let neg_keys: Vec<Vec<Val>> = neg_rows
                    .iter()
                    .filter(|row| const_filters.iter().all(|(col, val)| &row.0[*col] == val))
                    .map(|row| right_key_cols.iter().map(|&i| row.0[i].clone()).collect())
                    .collect();
                wide.retain(|row| {
                    let lkey: Vec<Val> = left_key_slots.iter().map(|s| slot_val(s, row)).collect();
                    !neg_keys.contains(&lkey)
                });
            }
            Step::Reduce {
                key_cols,
                aggregates,
            } => {
                // Aggregation leaf: recompute the aggregate over each group so a
                // wide row matching `head` can be produced. The resulting fact
                // has no positive premises (interpreter parity) and does not
                // descend. Mirrors build.rs's Step::Reduce.
                use std::collections::BTreeMap;
                let mut groups: BTreeMap<Vec<Val>, Vec<Row>> = BTreeMap::new();
                for row in std::mem::take(&mut wide) {
                    let key: Vec<Val> = key_cols.iter().map(|&i| row.0[i].clone()).collect();
                    groups.entry(key).or_default().push(row);
                }
                let mut next: Vec<Row> = Vec::new();
                for (key, rows) in groups {
                    // eval_aggregate takes (&Row, isize) with multiplicity 1 in
                    // batch mode (distinct facts).
                    let input: Vec<(&Row, isize)> = rows.iter().map(|r| (r, 1isize)).collect();
                    let agg_vals: Vec<Val> = aggregates
                        .iter()
                        .map(|a| eval_aggregate(a, &input))
                        .collect();
                    next.push(Row(key.into_iter().chain(agg_vals).collect()));
                }
                wide = next;
            }
            Step::Insert { proj, .. } if idx + 1 != n_steps => {
                // Intermediate Insert (aggregation lowers as: materialise into a
                // `$temp_grp_N` relation, then Reduce). This is a pure projection,
                // not the head derivation — reshape `wide` and continue. Mirrors
                // build.rs, which only emits provenance at the final Insert.
                wide = wide
                    .into_iter()
                    .map(|row| {
                        Row(proj
                            .iter()
                            .map(|s| match s {
                                Slot::Col(i) => row.0[*i].clone(),
                                Slot::Const(v) => v.clone(),
                            })
                            .collect())
                    })
                    .collect();
            }
            Step::Insert { proj, .. } => {
                // Keep only wide rows whose head projection matches `head`, and
                // whose every positive premise passes the strict-height guard.
                for row in &wide {
                    let projected: Vec<Val> = proj
                        .iter()
                        .map(|s| match s {
                            Slot::Col(i) => row.0[*i].clone(),
                            Slot::Const(v) => v.clone(),
                        })
                        .collect();
                    if Row(projected.into()) != *head {
                        continue;
                    }
                    // Gather premises and check the height guard.
                    let mut premises = Vec::new();
                    let mut ok = true;
                    for pa in &rule.premise_atoms {
                        let premise = Row(pa.arg_cols.iter().map(|&i| row.0[i].clone()).collect());
                        let (rid, h) = annotation_of(&pa.rel, &premise);
                        if h >= max_height {
                            ok = false;
                            break;
                        }
                        premises.push(Premise {
                            rel: pa.rel.clone(),
                            row: premise,
                            rule_id: rid,
                            height: h,
                        });
                    }
                    if ok {
                        // Surface the negated body atoms as absent-leaves. Their
                        // args are read from the same matching wide row (the
                        // antijoin already guaranteed the key is absent).
                        let negated = rule
                            .negated_atoms
                            .iter()
                            .map(|na| NegatedFact {
                                rel: na.rel.clone(),
                                args: na
                                    .arg_slots
                                    .iter()
                                    .map(|slot| slot.as_ref().map(|s| slot_val(s, row)))
                                    .collect(),
                            })
                            .collect();
                        return Some(Grounding {
                            rule_id: rule.rule_id,
                            premises,
                            negated,
                        });
                    }
                }
                return None;
            }
            // The remaining steps are per-row filters/extensions, replayed with
            // the same helpers `build.rs` uses so both sides see the same rows.
            // A row whose evaluation errors is dropped, as in the dataflow (the
            // session refuses reads while any error is live, so `::why` never
            // runs against such a row anyway).
            Step::CallFilter { func, args, negate } => {
                wide.retain(|row| eval_call_filter(func, args, row).is_ok_and(|b| b != *negate));
            }
            Step::Let { expr } => {
                wide = wide
                    .into_iter()
                    .filter_map(|row| {
                        let v = eval_expr(expr, &row).ok()?;
                        Some(row.appended(std::iter::once(v)))
                    })
                    .collect();
            }
            Step::MatchField { struct_slot, field } => {
                wide = wide
                    .into_iter()
                    .filter_map(|row| match_field_row(struct_slot, field, row))
                    .collect();
            }
            Step::IterateList { source_slot } => {
                wide = wide
                    .into_iter()
                    .flat_map(|row| iterate_list_row(source_slot, row))
                    .collect();
            }
        }
    }
    None
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
    /// Relations the dataflow has an input handle for. The worker silently
    /// drops inserts into any other relation, so callers must `rebuild` first.
    inputs: std::collections::HashSet<String>,
    /// Which provenance strategy this session builds (`Off`/`Lazy`).
    /// Preserved across `rebuild` so a provenance session stays one.
    mode: ProvenanceMode,
}

impl DdSession {
    /// Spawn a persistent worker for `rule_sources` and seed it with `edb`.
    ///
    /// After this returns the worker is fully settled at epoch 1 with the initial
    /// EDB visible. Provenance is disabled; use [`DdSession::spawn_mode`] with
    /// [`ProvenanceMode::Lazy`] to build annotations for `::why`.
    pub fn spawn(edb: &[(String, Vec<Value>)], rule_sources: &[String]) -> Result<Self> {
        Self::spawn_mode(edb, rule_sources, ProvenanceMode::Off)
    }

    /// Spawn a persistent worker with an explicit provenance [`ProvenanceMode`].
    pub fn spawn_mode(
        edb: &[(String, Vec<Value>)],
        rule_sources: &[String],
        mode: ProvenanceMode,
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
        let known_inputs = input_rels_set.clone();
        let input_rels: Vec<String> = input_rels_set.into_iter().collect();

        // Index every rule by its rule_id so the worker can look a rule back up
        // by id for lazy `WhyStep` backward-chaining.
        let rules_by_id: HashMap<u32, LoweredRule> = strata_work
            .iter()
            .flat_map(|s| s.rules.iter().cloned())
            .map(|r| (r.rule_id, r))
            .collect();

        // Wrap non-Copy data in Arc so the Fn closure (which timely may call
        // more than once per worker) can clone rather than move them.
        let strata_work = Arc::new(strata_work);
        let input_rels = Arc::new(input_rels);
        let edb_by_rel = Arc::new(edb_by_rel);
        let rules_by_id = Arc::new(rules_by_id);

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
        let (ready_tx, ready_rx): (Sender<Result<(), String>>, Receiver<Result<(), String>>) =
            bounded(1);

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
            let rules_by_id = Arc::clone(&rules_by_id);

            let (mut handles, mut traces, mut annotation_traces, build_errors, error_trace) =
                worker.dataflow::<u64, _, _>({
                    let input_rels = Arc::clone(&input_rels);
                    let probe_ref = probe.clone();

                    move |scope| {
                        let mut handles: HashMap<String, InputSession<u64, Row, isize>> =
                            HashMap::new();
                        let mut rels: HashMap<String, VecCollection<'_, u64, Row>> = HashMap::new();
                        // Any rule the DD builder can't translate is collected here and
                        // reported back to spawn() so it fails loudly rather than
                        // silently dropping the rule (which would yield wrong results).
                        let mut build_errors: Vec<String> = Vec::new();
                        // Runtime evaluation errors from every rule (see
                        // `build_rule`), arranged below into `error_trace`.
                        let mut error_colls: Vec<VecCollection<'_, u64, Row>> = Vec::new();

                        // Lazy provenance: a sibling annotation collection per
                        // relation, `(fact_row, (rule_id, min_height))`. Empty
                        // unless mode == Lazy.
                        let mut annotations: HashMap<
                            String,
                            VecCollection<'_, u64, (Row, Annotation)>,
                        > = HashMap::new();

                        for rel in input_rels.iter() {
                            let (handle, coll) = scope.new_collection::<Row, isize>();
                            if mode.lazy() {
                                // Seed EDB annotations: height 0, sentinel rule id.
                                annotations.insert(
                                    rel.clone(),
                                    coll.clone().map(|row| (row, (SENTINEL_EDB, 0u32))),
                                );
                            }
                            rels.insert(rel.clone(), coll);
                            handles.insert(rel.clone(), handle);
                        }

                        let unit_coll = scope.new_collection_from(vec![Row::empty()]).1;

                        for stratum in strata_work.iter() {
                            if stratum.rules.is_empty() {
                                continue;
                            }

                            if stratum.is_recursive {
                                let head_preds: std::collections::HashSet<String> =
                                    stratum.rules.iter().map(|r| r.head_rel.clone()).collect();

                                let (results, inner_annotations): (
                                    HashMap<String, VecCollection<'_, u64, Row>>,
                                    HashMap<String, VecCollection<'_, u64, (Row, Annotation)>>,
                                ) = scope.iterative::<u32, _, _>(|nested| {
                                    let summary = Product::new(Default::default(), 1u32);

                                    let mut inner_rels: HashMap<
                                        String,
                                        VecCollection<'_, Product<u64, u32>, Row>,
                                    > = rels
                                        .iter()
                                        .map(|(k, v)| (k.clone(), v.clone().enter(nested)))
                                        .collect();
                                    let inner_unit = unit_coll.clone().enter(nested);

                                    // Enter the annotation siblings too.
                                    let mut inner_annotations: HashMap<
                                        String,
                                        VecCollection<'_, Product<u64, u32>, (Row, Annotation)>,
                                    > = annotations
                                        .iter()
                                        .map(|(k, v)| (k.clone(), v.clone().enter(nested)))
                                        .collect();

                                    let mut vars: HashMap<
                                        String,
                                        VecVariable<'_, Product<u64, u32>, Row, isize>,
                                    > = HashMap::new();
                                    let mut var_colls: HashMap<
                                        String,
                                        VecCollection<'_, Product<u64, u32>, Row>,
                                    > = HashMap::new();
                                    // Annotation VecVariables, coupled with the
                                    // fact vars but keeping a side collection —
                                    // they do not drive termination (the fact
                                    // `distinct()` does). Seeded empty (the head
                                    // predicate is IDB, so no EDB annotation).
                                    let mut annotation_variables: HashMap<
                                        String,
                                        VecVariable<
                                            '_,
                                            Product<u64, u32>,
                                            (Row, Annotation),
                                            isize,
                                        >,
                                    > = HashMap::new();
                                    let mut annotation_variable_collections: HashMap<
                                        String,
                                        VecCollection<'_, Product<u64, u32>, (Row, Annotation)>,
                                    > = HashMap::new();
                                    for pred in &head_preds {
                                        if let Some(seed) = inner_rels.remove(pred) {
                                            let (var, coll) = VecVariable::new_from(seed, summary);
                                            vars.insert(pred.clone(), var);
                                            var_colls.insert(pred.clone(), coll);
                                        } else {
                                            let (var, coll) = VecVariable::new(nested, summary);
                                            vars.insert(pred.clone(), var);
                                            var_colls.insert(pred.clone(), coll);
                                        }
                                        if mode.lazy() {
                                            let seed_annotation = inner_annotations.remove(pred);
                                            let (annotation_variable, annotation_collection) =
                                                match seed_annotation {
                                                    Some(s) => VecVariable::new_from(s, summary),
                                                    None => VecVariable::new(nested, summary),
                                                };
                                            annotation_variables
                                                .insert(pred.clone(), annotation_variable);
                                            annotation_variable_collections
                                                .insert(pred.clone(), annotation_collection);
                                        }
                                    }
                                    for (pred, coll) in &var_colls {
                                        inner_rels.insert(pred.clone(), coll.clone());
                                    }
                                    for (pred, coll) in &annotation_variable_collections {
                                        inner_annotations.insert(pred.clone(), coll.clone());
                                    }

                                    let mut by_head: HashMap<
                                        String,
                                        Vec<VecCollection<'_, Product<u64, u32>, Row>>,
                                    > = HashMap::new();
                                    let mut inner_errors = Vec::new();
                                    let mut annotations_by_head: HashMap<
                                        String,
                                        Vec<
                                            VecCollection<'_, Product<u64, u32>, (Row, Annotation)>,
                                        >,
                                    > = HashMap::new();
                                    for rule in &stratum.rules {
                                        match build_rule(
                                            rule,
                                            &inner_rels,
                                            &inner_annotations,
                                            &inner_unit,
                                            &mut inner_errors,
                                            mode,
                                        ) {
                                            Ok((coll, annotation)) => {
                                                by_head
                                                    .entry(rule.head_rel.clone())
                                                    .or_default()
                                                    .push(coll);
                                                if let Some(a) = annotation {
                                                    annotations_by_head
                                                        .entry(rule.head_rel.clone())
                                                        .or_default()
                                                        .push(a);
                                                }
                                            }
                                            Err(e) => {
                                                build_errors.push(format!(
                                                    "rule for `{}`: {e}",
                                                    rule.head_rel
                                                ));
                                            }
                                        }
                                    }

                                    let mut out: HashMap<String, VecCollection<'_, u64, Row>> =
                                        HashMap::new();
                                    let mut out_annotations: HashMap<
                                        String,
                                        VecCollection<'_, u64, (Row, Annotation)>,
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
                                        out.insert(pred.clone(), full.leave(scope));

                                        // Couple the annotation variable: concat
                                        // the carried annotations with this round's
                                        // candidates and min-reduce per fact. This
                                        // is the DD realisation of the height update
                                        // equation h'(t) = min_g (1 + max_i h(t_i)).
                                        if mode.lazy() {
                                            let annotation_variable =
                                                annotation_variables.remove(&pred).unwrap();
                                            let current_annotations =
                                                annotation_variable_collections
                                                    .remove(&pred)
                                                    .unwrap();
                                            let candidates = match annotations_by_head.remove(&pred)
                                            {
                                                Some(colls) => {
                                                    let cands = colls
                                                        .into_iter()
                                                        .reduce(|a, b| a.concat(b))
                                                        .unwrap();
                                                    current_annotations.concat(cands)
                                                }
                                                None => current_annotations,
                                            };
                                            let min_annotation = min_reduce_annotations(candidates);
                                            annotation_variable.set(min_annotation.clone());
                                            out_annotations
                                                .insert(pred.clone(), min_annotation.leave(scope));
                                        }
                                    }
                                    error_colls
                                        .extend(inner_errors.into_iter().map(|e| e.leave(scope)));
                                    (out, out_annotations)
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
                                for (pred, coll) in inner_annotations {
                                    // A recursive head predicate is fully produced
                                    // by this stratum; its annotation is the leave.
                                    annotations.insert(pred, coll);
                                }
                            } else {
                                let mut by_head: HashMap<String, Vec<VecCollection<'_, u64, Row>>> =
                                    HashMap::new();
                                let mut annotations_by_head: HashMap<
                                    String,
                                    Vec<VecCollection<'_, u64, (Row, Annotation)>>,
                                > = HashMap::new();

                                for rule in &stratum.rules {
                                    match build_rule(
                                        rule,
                                        &rels,
                                        &annotations,
                                        &unit_coll,
                                        &mut error_colls,
                                        mode,
                                    ) {
                                        Ok((coll, annotation)) => {
                                            by_head
                                                .entry(rule.head_rel.clone())
                                                .or_default()
                                                .push(coll);
                                            if let Some(a) = annotation {
                                                annotations_by_head
                                                    .entry(rule.head_rel.clone())
                                                    .or_default()
                                                    .push(a);
                                            }
                                        }
                                        Err(e) => {
                                            build_errors
                                                .push(format!("rule for `{}`: {e}", rule.head_rel));
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
                                for (head_rel, colls) in annotations_by_head {
                                    let cands =
                                        colls.into_iter().reduce(|a, b| a.concat(b)).unwrap();
                                    let merged = match annotations.remove(&head_rel) {
                                        Some(prev) => prev.concat(cands),
                                        None => cands,
                                    };
                                    annotations.insert(head_rel, min_reduce_annotations(merged));
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
                        let error_trace = arrange_errors(error_colls, &unit_coll, &probe_ref);

                        // Arrange the lazy annotation collections into traces.
                        let mut annotation_traces: HashMap<String, AnnotationTrace> =
                            HashMap::new();
                        for (rel_name, coll) in annotations {
                            let arranged = coll.probe_with(&probe_ref).arrange_by_self();
                            annotation_traces.insert(rel_name, arranged.trace);
                        }

                        (
                            handles,
                            traces,
                            annotation_traces,
                            build_errors,
                            error_trace,
                        )
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
            worker.step_or_park_while(None, || probe.less_than(&1u64));

            // Tell `spawn()` the initial seed/settle is done and it's safe to
            // hand the session to the caller.
            let _ = ready_tx.send(Ok(()));

            // ------------------------------------------------------------------
            // Command loop.
            // ------------------------------------------------------------------
            // The epoch monotonically increases.  Insert/Remove commands buffer
            // diffs into the InputSession; Commit advances the epoch and steps
            // the worker until the probe clears, then acks.  Shutdown exits.
            let mut epoch: u64 = 1;
            // One error trace per dataflow (the initial one plus each layer).
            let mut error_traces: Vec<RowTrace> = vec![error_trace];

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
                            for trace in traces.values_mut().chain(error_traces.iter_mut()) {
                                trace.set_logical_compaction(frontier);
                                trace.set_physical_compaction(frontier);
                            }
                            // Keep annotation traces compacted in lockstep with the
                            // row traces so lazy reconstruction reads a consistent
                            // frontier (design §5.5).
                            for trace in annotation_traces.values_mut() {
                                trace.set_logical_compaction(frontier);
                                trace.set_physical_compaction(frontier);
                            }
                            let _ = ack.send(());
                        }
                        Command::Query { rel, resp } => {
                            let result = live_errors(&mut error_traces).map(|()| {
                                traces.get_mut(&rel).map(drain_trace).unwrap_or_default()
                            });
                            let _ = resp.send(result);
                        }
                        Command::SnapshotAll { resp } => {
                            let result = live_errors(&mut error_traces).map(|()| {
                                let mut out: HashMap<String, Vec<Vec<Value>>> = HashMap::new();
                                for (rel, trace) in traces.iter_mut() {
                                    out.insert(rel.clone(), drain_trace(trace));
                                }
                                out
                            });
                            let _ = resp.send(result);
                        }
                        Command::WhyHeight { rel, fact, resp } => {
                            let annotation = annotation_traces
                                .get_mut(&rel)
                                .and_then(|t| lookup_annotation(t, &fact));
                            let _ = resp.send(annotation);
                        }
                        Command::WhyStep {
                            rule_id,
                            head,
                            max_height,
                            resp,
                        } => {
                            // Look up the achieving rule by id.
                            let result = match rules_by_id.get(&rule_id) {
                                None => None,
                                Some(rule) => {
                                    // Materialise the live rows of each relation
                                    // once (small fixtures) and a fact->annotation map so
                                    // the height guard can be applied.
                                    let mut row_cache: HashMap<String, Vec<Row>> = HashMap::new();
                                    let mut annotation_cache: HashMap<
                                        String,
                                        HashMap<Row, Annotation>,
                                    > = HashMap::new();
                                    // Collect every relation reconstruction will
                                    // read via `rows_of`, straight from the rule's
                                    // steps: Scan/Join sources (positive premises
                                    // and aggregate group sources, which are not in
                                    // `premise_atoms`) and Antijoin negated rels.
                                    let mut step_rels: std::collections::HashSet<String> =
                                        std::collections::HashSet::new();
                                    for step in &rule.steps {
                                        match step {
                                            Step::Scan { rel, .. }
                                            | Step::Join { rel, .. }
                                            | Step::Antijoin { rel, .. } => {
                                                step_rels.insert(rel.clone());
                                            }
                                            _ => {}
                                        }
                                    }
                                    for rel_name in step_rels {
                                        if let Some(t) = traces.get_mut(&rel_name) {
                                            row_cache.insert(rel_name.clone(), drain_trace_rows(t));
                                        }
                                        if let Some(t) = annotation_traces.get_mut(&rel_name) {
                                            annotation_cache
                                                .insert(rel_name.clone(), drain_annotations(t));
                                        }
                                    }
                                    let mut rows_of = |rel: &str| -> Vec<Row> {
                                        row_cache.get(rel).cloned().unwrap_or_default()
                                    };
                                    let mut annotation_of =
                                        |rel: &str, tuple: &Row| -> Annotation {
                                            annotation_cache
                                                .get(rel)
                                                .and_then(|m| m.get(tuple).copied())
                                                // No annotation ⇒ treat as base fact.
                                                .unwrap_or((SENTINEL_EDB, 0))
                                        };
                                    reconstruct_grounding(
                                        rule,
                                        &head,
                                        max_height,
                                        &mut rows_of,
                                        &mut annotation_of,
                                    )
                                }
                            };
                            let _ = resp.send(result);
                        }
                        Command::AddRules {
                            all_rule_sources,
                            new_head,
                            ack,
                        } => {
                            // Check if the new rule extends an already-materialized predicate.
                            // If so the existing trace is stale and only a full rebuild is correct.
                            let extends_existing = new_head
                                .as_deref()
                                .map(|h| traces.contains_key(h))
                                .unwrap_or(true); // conservative: unknown head → rebuild

                            // The layering path below builds no lazy annotations
                            // and the worker's `rules_by_id` is fixed at spawn,
                            // so a provenance session always rebuilds instead.
                            if extends_existing || mode.lazy() {
                                let _ = ack.send(AddOutcome::NeedsRebuild);
                                continue;
                            }

                            // Compile the full accumulated rule set to find strata for new preds.
                            let (all_strata, _edb_rels) = match build_strata(&all_rule_sources) {
                                Ok(r) => r,
                                Err(e) => {
                                    let _ = ack
                                        .send(AddOutcome::Error(format!("compile error: {e:#}")));
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

                            let (mut new_traces, layer_errors, mut layer_error_trace) = worker
                                .dataflow::<u64, _, _>(move |scope| {
                                    // Import each existing trace as a VecCollection.
                                    let mut rels: HashMap<String, VecCollection<'_, u64, Row>> =
                                        imported_traces
                                            .into_iter()
                                            .map(|(name, mut trace)| {
                                                let coll = trace
                                                    .import(scope)
                                                    .as_collection(|row, _| row.clone());
                                                (name, coll)
                                            })
                                            .collect();

                                    let unit_coll = scope.new_collection_from(vec![Row::empty()]).1;
                                    let mut new_inner: HashMap<String, _> = HashMap::new();
                                    let mut layer_errors: Vec<String> = Vec::new();
                                    let mut layer_error_colls = Vec::new();

                                    for stratum in &to_layer {
                                        let mut by_head: HashMap<
                                            String,
                                            Vec<VecCollection<'_, u64, Row>>,
                                        > = HashMap::new();
                                        for rule in &stratum.rules {
                                            // Provenance is not tracked on the layering
                                            // path (lazy sessions always rebuild, see
                                            // above); ignore the annotation collection.
                                            let empty_annotations: HashMap<
                                                String,
                                                VecCollection<'_, u64, (Row, Annotation)>,
                                            > = HashMap::new();
                                            match build_rule(
                                                rule,
                                                &rels,
                                                &empty_annotations,
                                                &unit_coll,
                                                &mut layer_error_colls,
                                                ProvenanceMode::Off,
                                            ) {
                                                Ok((coll, _annotation)) => {
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
                                            let arranged =
                                                idb.probe_with(&probe_ref).arrange_by_self();
                                            new_inner.insert(head_rel, arranged.trace);
                                        }
                                    }

                                    let layer_error_trace =
                                        arrange_errors(layer_error_colls, &unit_coll, &probe_ref);
                                    (new_inner, layer_errors, layer_error_trace)
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
                            for trace in new_traces
                                .values_mut()
                                .chain(std::iter::once(&mut layer_error_trace))
                            {
                                trace.set_logical_compaction(frontier);
                                trace.set_physical_compaction(frontier);
                            }

                            // Merge new relation traces into the session.
                            traces.extend(new_traces);
                            error_traces.push(layer_error_trace);
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
            inputs: known_inputs,
            mode,
        })
    }

    // -------------------------------------------------------------------------
    // Fact mutation API
    // -------------------------------------------------------------------------

    /// Buffer an insert delta.  Not visible until `commit()`.
    pub fn insert(&self, rel: String, row: Row) {
        let _ = self.tx.send(Command::Insert { rel, row });
    }

    /// True if the dataflow can accept facts for `rel` without a `rebuild`.
    pub fn has_input(&self, rel: &str) -> bool {
        self.inputs.contains(rel)
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
    ///
    /// Fails while any rule has live evaluation errors (e.g. a `:string:*`
    /// built-in applied to a non-string), mirroring the interpreter.
    pub fn query(&self, rel: &str) -> Result<Vec<Vec<Value>>> {
        let (resp_tx, resp_rx) = bounded(1);
        let _ = self.tx.send(Command::Query {
            rel: rel.to_string(),
            resp: resp_tx,
        });
        resp_rx
            .recv()
            .unwrap_or_else(|_| Ok(Vec::new()))
            .map_err(anyhow::Error::msg)
    }

    /// Snapshot every relation (EDB + all derived IDB) at the current frontier.
    ///
    /// Used by the batch `DdBackend::evaluate` path: spawn a session, snapshot,
    /// then drop.  Mirrors `query()` but returns all relations at once.
    ///
    /// Fails while any rule has live evaluation errors, like [`Self::query`].
    pub fn snapshot_all(&self) -> Result<HashMap<String, Vec<Vec<Value>>>> {
        let (resp_tx, resp_rx) = bounded(1);
        let _ = self.tx.send(Command::SnapshotAll { resp: resp_tx });
        resp_rx
            .recv()
            .unwrap_or_else(|_| Ok(HashMap::new()))
            .map_err(anyhow::Error::msg)
    }

    // -------------------------------------------------------------------------
    // Lazy (Soufflé-style) provenance query API
    // -------------------------------------------------------------------------

    /// True if this session builds lazy provenance annotations, i.e. the
    /// `why_height`/`why_step` queries below can answer.
    pub fn has_provenance(&self) -> bool {
        self.mode.lazy()
    }

    /// Lazy provenance: look up a fact's stored `(rule_id, min_height)`.
    /// `None` if the session was not spawned with [`ProvenanceMode::Lazy`], or the
    /// fact has no derivation.
    pub fn why_height(&self, rel: &str, fact: &Row) -> Option<Annotation> {
        let (resp_tx, resp_rx) = bounded(1);
        let _ = self.tx.send(Command::WhyHeight {
            rel: rel.to_string(),
            fact: fact.clone(),
            resp: resp_tx,
        });
        resp_rx.recv().unwrap_or(None)
    }

    /// Lazy provenance backward-chaining step: return one grounding of the
    /// rule that achieved `head`'s minimal-height derivation, whose positive
    /// premises all have height strictly less than `max_height`. Recurse on the
    /// returned premises (each carries its own `(rule_id, height)`) until you
    /// bottom out at EDB facts (height 0). `None` if no such grounding exists.
    pub fn why_step(&self, rule_id: u32, head: &Row, max_height: u32) -> Option<Grounding> {
        let (resp_tx, resp_rx) = bounded(1);
        let _ = self.tx.send(Command::WhyStep {
            rule_id,
            head: head.clone(),
            max_height,
            resp: resp_tx,
        });
        resp_rx.recv().unwrap_or(None)
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
    pub fn rebuild(&mut self, edb: &[(String, Vec<Value>)], rule_sources: &[String]) -> Result<()> {
        // Shutdown the existing worker (joining it) before spawning the next one
        // so we never have two workers alive simultaneously.
        let mode = self.mode;
        self.shutdown_worker();
        *self = Self::spawn_mode(edb, rule_sources, mode)?;
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

    fn v_num(n: i64) -> Value {
        Value::Number(n)
    }

    /// Regression: an `IndexLookup` join must lower to a KEYED `Step::Join`
    /// (non-empty key columns), not a cross product. The mangle planner lowers
    /// `reachable(X,Z) :- reachable(X,Y), link(Y,Z)` as an IndexLookup keyed on
    /// Y; the DD backend must honor `col_idx` rather than cross-producting and
    /// leaning on the downstream equality Filter.
    #[test]
    fn indexlookup_lowers_to_keyed_join() {
        use crate::dd::lower::Step;
        let rules = vec![
            "Decl link(Src, Dst).\nDecl reachable(Src, Dst).\n\
             reachable(X, Y) :- link(X, Y).\n\
             reachable(X, Z) :- reachable(X, Y), link(Y, Z)."
                .to_string(),
        ];
        let (strata, _edb) = crate::dd::build_strata(&rules).expect("build_strata");

        let mut saw_join = false;
        for stratum in &strata {
            for rule in &stratum.rules {
                for step in &rule.steps {
                    if let Step::Join {
                        left_key_cols,
                        right_key_cols,
                        ..
                    } = step
                    {
                        saw_join = true;
                        assert!(
                            !left_key_cols.is_empty() && !right_key_cols.is_empty(),
                            "IndexLookup join lowered to a cross product (empty key cols): {step:?}"
                        );
                    }
                }
            }
        }
        assert!(
            saw_join,
            "expected a Join in the lowered transitive-closure rules"
        );
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
            "Decl edge(Src, Dst).\nDecl path(Src, Dst).\npath(X, Y) :- edge(X, Y).".to_string(),
        ];

        let session = DdSession::spawn(&edb, &rules).expect("spawn");
        let mut results = session.query("path").unwrap();
        results.sort();
        assert_eq!(
            results,
            vec![vec![v_str("a"), v_str("b")], vec![v_str("b"), v_str("c")],]
        );
    }

    /// Insert a new fact, commit, and verify it becomes visible.
    #[test]
    fn session_incremental_insert() {
        let edb: Vec<(String, Vec<Value>)> =
            vec![("edge".to_string(), vec![v_str("a"), v_str("b")])];

        let rules = vec![
            "Decl edge(Src, Dst).\nDecl path(Src, Dst).\npath(X, Y) :- edge(X, Y).".to_string(),
        ];

        let session = DdSession::spawn(&edb, &rules).expect("spawn");

        // Before insert: only a→b
        let before = session.query("path").unwrap();
        assert_eq!(before.len(), 1);

        // Insert b→c, commit, then check
        session.insert("edge".to_string(), Row::from(&[v_str("b"), v_str("c")][..]));
        session.commit();

        let mut after = session.query("path").unwrap();
        after.sort();
        assert_eq!(
            after,
            vec![vec![v_str("a"), v_str("b")], vec![v_str("b"), v_str("c")],]
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
            "Decl edge(Src, Dst).\nDecl path(Src, Dst).\npath(X, Y) :- edge(X, Y).".to_string(),
        ];

        let session = DdSession::spawn(&edb, &rules).expect("spawn");

        // Both edges visible initially
        assert_eq!(session.query("path").unwrap().len(), 2);

        // Retract b→c
        session.retract("edge".to_string(), Row::from(&[v_str("b"), v_str("c")][..]));
        session.commit();

        let after = session.query("path").unwrap();
        assert_eq!(after, vec![vec![v_str("a"), v_str("b")]]);
    }

    /// Dropping a session must complete promptly (no deadlock).
    #[test]
    fn session_drop_promptness() {
        let edb: Vec<(String, Vec<Value>)> =
            vec![("edge".to_string(), vec![v_str("x"), v_str("y")])];
        let rules = vec![
            "Decl edge(Src, Dst).\nDecl path(Src, Dst).\npath(X, Y) :- edge(X, Y).".to_string(),
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
            "Decl edge(Src, Dst).\nDecl path(Src, Dst).\npath(X, Y) :- edge(X, Y).".to_string(),
        ];

        let mut session = DdSession::spawn(&edb, &base_rules).expect("spawn");

        // Layer a view: view(X) :- path(X, _).
        let mut all_rules = base_rules.clone();
        all_rules.push("Decl view(Src).\nview(X) :- path(X, _).".to_string());
        session
            .add_idb(Some("view"), &edb, &all_rules)
            .expect("add_idb");

        let mut results = session.query("view").unwrap();
        results.sort();
        // view should contain the source nodes of every path edge: a and b
        assert_eq!(results, vec![vec![v_str("a")], vec![v_str("b")]]);
    }

    /// After layering a view, inserting a new fact propagates to the view.
    #[test]
    fn layer_view_tracks_fact_deltas() {
        let edb: Vec<(String, Vec<Value>)> =
            vec![("edge".to_string(), vec![v_str("a"), v_str("b")])];

        let base_rules = vec![
            "Decl edge(Src, Dst).\nDecl path(Src, Dst).\npath(X, Y) :- edge(X, Y).".to_string(),
        ];

        let mut session = DdSession::spawn(&edb, &base_rules).expect("spawn");

        let mut all_rules = base_rules.clone();
        all_rules.push("Decl view(Src).\nview(X) :- path(X, _).".to_string());
        session
            .add_idb(Some("view"), &edb, &all_rules)
            .expect("add_idb");

        // Before insert: only a
        let before = session.query("view").unwrap();
        assert_eq!(before, vec![vec![v_str("a")]]);

        // Insert b→c, commit — view should now also contain b.
        session.insert("edge".to_string(), Row::from(&[v_str("b"), v_str("c")][..]));
        session.commit();

        let mut after = session.query("view").unwrap();
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
            "Decl edge(Src, Dst).\nDecl path(Src, Dst).\npath(X, Y) :- edge(X, Y).".to_string(),
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

        let mut results = session.query("view2").unwrap();
        results.sort();
        assert_eq!(results, vec![vec![v_str("a")], vec![v_str("b")]]);
    }

    /// Adding a rule for an existing predicate falls back to rebuild; results are correct.
    #[test]
    fn layer_fallback_on_extend() {
        let edb: Vec<(String, Vec<Value>)> =
            vec![("edge".to_string(), vec![v_str("a"), v_str("b")])];

        let base_rules = vec![
            "Decl edge(Src, Dst).\nDecl path(Src, Dst).\npath(X, Y) :- edge(X, Y).".to_string(),
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
        let mut results = session.query("path").unwrap();
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
        // Check modes, reached only via negation.
        assert!(is_supported_call_filter(":list:member"));
        assert!(is_supported_call_filter(":match_field"));
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
        let mut results = session.query("hit").unwrap();
        results.sort();
        assert_eq!(results, vec![vec![v_str("alpha")]]);
    }

    /// A negated built-in stays correct as facts are inserted and retracted.
    #[test]
    fn session_negated_builtin_incremental() {
        let edb: Vec<(String, Vec<Value>)> = vec![
            ("name".to_string(), vec![v_str("alpha")]),
            ("name".to_string(), vec![v_str("beta")]),
        ];
        let rules = vec![
            "Decl name(N).\nDecl miss(N).\nmiss(N) :- name(N), !:string:starts_with(N, \"al\")."
                .to_string(),
        ];

        let session = DdSession::spawn(&edb, &rules).expect("spawn");
        assert_eq!(session.query("miss").unwrap(), vec![vec![v_str("beta")]]);

        session.insert("name".to_string(), Row::from(&[v_str("gamma")][..]));
        session.insert("name".to_string(), Row::from(&[v_str("alps")][..]));
        session.commit();
        let mut after_insert = session.query("miss").unwrap();
        after_insert.sort();
        assert_eq!(
            after_insert,
            vec![vec![v_str("beta")], vec![v_str("gamma")]]
        );

        session.retract("name".to_string(), Row::from(&[v_str("beta")][..]));
        session.commit();
        assert_eq!(session.query("miss").unwrap(), vec![vec![v_str("gamma")]]);
    }

    /// A built-in type error makes reads fail while the offending fact is
    /// live, and retracting it makes reads succeed again.
    #[test]
    fn session_eval_error_tracks_offending_fact() {
        let edb: Vec<(String, Vec<Value>)> = vec![
            ("name".to_string(), vec![v_str("alpha")]),
            ("name".to_string(), vec![v_str("beta")]),
        ];
        let rules = vec![
            "Decl name(N).\nDecl miss(N).\nmiss(N) :- name(N), !:string:starts_with(N, \"al\")."
                .to_string(),
        ];

        let session = DdSession::spawn(&edb, &rules).expect("spawn");
        assert_eq!(session.query("miss").unwrap(), vec![vec![v_str("beta")]]);

        let bad = Row::from(&[Value::Number(5)][..]);
        session.insert("name".to_string(), bad.clone());
        session.commit();
        let err = session
            .query("miss")
            .expect_err("type error should fail the read");
        assert!(
            format!("{err:#}").contains(":string:starts_with: expected string arguments"),
            "unexpected error: {err:#}"
        );
        assert!(session.snapshot_all().is_err());

        session.retract("name".to_string(), bad);
        session.commit();
        assert_eq!(session.query("miss").unwrap(), vec![vec![v_str("beta")]]);
    }

    /// A failing `let` function behaves like a built-in type error: reads
    /// fail while the offending fact is live, and recover once it is retracted.
    #[test]
    fn session_let_error_tracks_offending_fact() {
        let edb: Vec<(String, Vec<Value>)> = vec![("num".to_string(), vec![Value::Number(1)])];
        let rules = vec![
            "Decl num(X).\nDecl next(Y).\nnext(Y) :- num(X) |> let Y = fn:plus(X, 1).".to_string(),
        ];

        let session = DdSession::spawn(&edb, &rules).expect("spawn");
        assert_eq!(session.query("next").unwrap(), vec![vec![Value::Number(2)]]);

        let bad = Row::from(&[v_str("x")][..]);
        session.insert("num".to_string(), bad.clone());
        session.commit();
        let err = session
            .query("next")
            .expect_err("fn:plus on a string should fail the read");
        assert!(
            format!("{err:#}").contains("fn:plus: expected integer"),
            "unexpected error: {err:#}"
        );

        session.retract("num".to_string(), bad);
        session.commit();
        assert_eq!(session.query("next").unwrap(), vec![vec![Value::Number(2)]]);
    }

    // -----------------------------------------------------------------------
    // Lazy (Soufflé-style) provenance
    // -----------------------------------------------------------------------

    /// End-to-end lazy provenance on the canonical transitive-closure fixture.
    ///
    /// Fixture: edges a→b, b→c. Rules:
    ///   path(X, Y) :- edge(X, Y).                  // base, height 1
    ///   path(X, Z) :- edge(X, Y), path(Y, Z).      // recursive
    ///
    /// Shortest proof of path(a, c):
    ///   path(a,c)  [rule=recursive, height 2]
    ///     ├─ edge(a,b)  [EDB, height 0]
    ///     └─ path(b,c)  [rule=base, height 1]
    ///          └─ edge(b,c)  [EDB, height 0]
    ///
    /// We reconstruct this proof purely via the lazy backward-chaining commands
    /// (`why_height` / `why_step`), asserting each descent strictly decreases
    /// height and bottoms out at EDB facts (height 0). This directly exercises
    /// the min-height-in-fixpoint convergence (design §2.4 risk #1).
    #[test]
    fn lazy_provenance_transitive_closure() {
        let edb: Vec<(String, Vec<Value>)> = vec![
            ("edge".to_string(), vec![v_str("a"), v_str("b")]),
            ("edge".to_string(), vec![v_str("b"), v_str("c")]),
        ];
        let rules = vec![
            "Decl edge(Src, Dst).\nDecl path(Src, Dst).\n\
             path(X, Y) :- edge(X, Y).\n\
             path(X, Z) :- edge(X, Y), path(Y, Z)."
                .to_string(),
        ];

        let session =
            DdSession::spawn_mode(&edb, &rules, ProvenanceMode::Lazy).expect("spawn lazy");

        // path should contain a→b, b→c (base) and a→c (transitive).
        let mut paths = session.query("path").unwrap();
        paths.sort();
        assert_eq!(
            paths,
            vec![
                vec![v_str("a"), v_str("b")],
                vec![v_str("a"), v_str("c")],
                vec![v_str("b"), v_str("c")],
            ],
            "transitive closure wrong: {paths:?}"
        );

        let ac = Row::from(&[v_str("a"), v_str("c")][..]);

        // 1) path(a,c) has the transitive minimal height 2.
        let (rid_ac, h_ac) = session
            .why_height("path", &ac)
            .expect("path(a,c) must have an annotation");
        assert_eq!(h_ac, 2, "path(a,c) minimal proof height should be 2");

        // 2) Backward-chain one step: the grounding's premises must all be
        //    strictly below height 2.
        let g_ac = session
            .why_step(rid_ac, &ac, h_ac)
            .expect("subproof for path(a,c) must exist");
        assert_eq!(g_ac.premises.len(), 2, "recursive rule has 2 premises");
        for p in &g_ac.premises {
            assert!(
                p.height < h_ac,
                "premise {:?} height {} not < {}",
                p.row,
                p.height,
                h_ac
            );
        }

        // Identify the recursive premise path(b,c) (height 1) and the EDB
        // premise edge(a,b) (height 0).
        let bc = Row::from(&[v_str("b"), v_str("c")][..]);
        let path_premise = g_ac
            .premises
            .iter()
            .find(|p| p.rel == "path")
            .expect("recursive premise on `path`");
        assert_eq!(
            path_premise.row, bc,
            "recursive premise should be path(b,c)"
        );
        assert_eq!(
            path_premise.height, 1,
            "path(b,c) minimal height should be 1"
        );

        let edge_premise = g_ac
            .premises
            .iter()
            .find(|p| p.rel == "edge")
            .expect("EDB premise on `edge`");
        assert_eq!(edge_premise.height, 0, "EDB premise must be height 0");
        assert_eq!(
            edge_premise.rule_id, SENTINEL_EDB,
            "EDB premise must carry the sentinel rule id"
        );

        // 3) Descend into path(b,c): its subproof must bottom out at edge(b,c),
        //    an EDB fact at height 0, strictly below path(b,c)'s height 1.
        let g_bc = session
            .why_step(path_premise.rule_id, &bc, path_premise.height)
            .expect("subproof for path(b,c) must exist");
        assert_eq!(
            g_bc.premises.len(),
            1,
            "base rule path(X,Y):-edge(X,Y) has 1 premise"
        );
        let leaf = &g_bc.premises[0];
        assert_eq!(leaf.rel, "edge");
        assert_eq!(leaf.row, bc, "leaf should be edge(b,c)");
        assert_eq!(leaf.height, 0, "leaf EDB fact must be height 0");
        assert!(
            leaf.height < path_premise.height,
            "descent must strictly decrease height"
        );
        assert_eq!(leaf.rule_id, SENTINEL_EDB);
    }

    /// Lazy provenance over stratified negation. The reconstructed proof of a
    /// fact derived through `!rel(...)` must include the positive premises and
    /// surface the negated condition as a `¬rel(args)` absent-leaf (not silently
    /// omit it, and not descend into it), then bottom out at EDB facts.
    ///
    /// Program (same shape as the parity `stratified_negation` fixture):
    ///   reachable(X,Y) :- edge(X,Y).
    ///   reachable(X,Z) :- reachable(X,Y), edge(Y,Z).
    ///   unreachable(X,Y) :- node(X), node(Y), !reachable(X,Y).
    ///
    /// With nodes {1,2,3} and edge(1,2): reachable = {(1,2)}, so unreachable
    /// contains e.g. (1,3) — its two positive premises are node(1), node(3)
    /// (EDB, height 0) and the negated `¬reachable(1,3)` held.
    #[test]
    fn lazy_provenance_stratified_negation() {
        let edb: Vec<(String, Vec<Value>)> = vec![
            ("node".to_string(), vec![v_num(1)]),
            ("node".to_string(), vec![v_num(2)]),
            ("node".to_string(), vec![v_num(3)]),
            ("edge".to_string(), vec![v_num(1), v_num(2)]),
        ];
        let rules = vec![
            "Decl node(N).\nDecl edge(A, B).\nDecl reachable(A, B).\nDecl unreachable(A, B).\n\
             reachable(X, Y) :- edge(X, Y).\n\
             reachable(X, Z) :- reachable(X, Y), edge(Y, Z).\n\
             unreachable(X, Y) :- node(X), node(Y), !reachable(X, Y)."
                .to_string(),
        ];

        let session =
            DdSession::spawn_mode(&edb, &rules, ProvenanceMode::Lazy).expect("spawn lazy");

        // Sanity: (1,3) is unreachable (only reachable pair is (1,2)).
        let u13 = Row::from(&[v_num(1), v_num(3)][..]);
        let unreachable = session.query("unreachable").unwrap();
        assert!(
            unreachable.contains(&vec![v_num(1), v_num(3)]),
            "expected unreachable(1,3); got {unreachable:?}"
        );

        // unreachable(1,3) is a one-step (non-recursive) derivation → height 1.
        let (rid, h) = session
            .why_height("unreachable", &u13)
            .expect("unreachable(1,3) must have an annotation");
        assert_eq!(h, 1, "non-recursive derivation has height 1");

        let g = session
            .why_step(rid, &u13, h)
            .expect("subproof for unreachable(1,3) must exist");

        // Two positive premises: node(1) and node(3), both EDB (height 0).
        assert_eq!(
            g.premises.len(),
            2,
            "node(X), node(Y) are the 2 positive premises"
        );
        for p in &g.premises {
            assert_eq!(p.rel, "node");
            assert_eq!(p.height, 0, "EDB premise height 0");
            assert_eq!(p.rule_id, SENTINEL_EDB, "EDB premise carries sentinel id");
            assert!(
                p.height < h,
                "premise height must be strictly below head height"
            );
        }
        let premise_values: Vec<Vec<Value>> = g
            .premises
            .iter()
            .map(|p| p.row.clone().into_values())
            .collect();
        assert!(
            premise_values.contains(&vec![v_num(1)]),
            "node(1) premise present"
        );
        assert!(
            premise_values.contains(&vec![v_num(3)]),
            "node(3) premise present"
        );

        // The negated condition is shown as a ¬reachable(1,3) absent-leaf.
        assert_eq!(g.negated.len(), 1, "one negated atom: !reachable(X,Y)");
        let neg = &g.negated[0];
        assert_eq!(neg.rel, "reachable");
        let neg_args: Vec<Option<Value>> = neg
            .args
            .iter()
            .map(|a| a.clone().map(Value::from))
            .collect();
        assert_eq!(
            neg_args,
            vec![Some(v_num(1)), Some(v_num(3))],
            "¬reachable absent-leaf must carry the bound args (1,3)"
        );
    }

    /// Lazy provenance treats an aggregate-derived fact as a leaf: it has a
    /// well-defined base height (1), no positive premises, and reconstructs
    /// without descending into the contributing group. Exercises both
    /// `fn:count` and `fn:sum`.
    #[test]
    fn lazy_provenance_aggregation_is_leaf() {
        let edb: Vec<(String, Vec<Value>)> = vec![
            ("item".to_string(), vec![v_str("a"), v_num(10)]),
            ("item".to_string(), vec![v_str("a"), v_num(5)]),
            ("item".to_string(), vec![v_str("b"), v_num(3)]),
        ];

        // fn:count
        {
            let rules = vec![
                "Decl item(Cat, Val).\nDecl cnt(Cat, N).\n\
                 cnt(Cat, N) :- item(Cat, Val) |> do fn:group_by(Cat), let N = fn:count(Val)."
                    .to_string(),
            ];
            let session = DdSession::spawn_mode(&edb, &rules, ProvenanceMode::Lazy)
                .expect("spawn lazy count");

            // Cat "a" has 2 items.
            let mut cnt = session.query("cnt").unwrap();
            cnt.sort();
            assert_eq!(
                cnt,
                vec![vec![v_str("a"), v_num(2)], vec![v_str("b"), v_num(1)]],
                "count wrong: {cnt:?}"
            );

            let fact = Row::from(&[v_str("a"), v_num(2)][..]);
            let (rid, h) = session
                .why_height("cnt", &fact)
                .expect("cnt(a,2) must have an annotation");
            assert_eq!(h, 1, "aggregate fact is a base-height-1 leaf");

            let g = session
                .why_step(rid, &fact, h)
                .expect("subproof for cnt(a,2) must exist");
            assert!(
                g.premises.is_empty(),
                "aggregate leaf has no positive premises (no descent); got {:?}",
                g.premises
            );
            assert!(g.negated.is_empty(), "aggregate leaf has no negated atoms");
        }

        // fn:sum
        {
            let rules = vec![
                "Decl item(Cat, Val).\nDecl total(Cat, S).\n\
                 total(Cat, S) :- item(Cat, Val) |> do fn:group_by(Cat), let S = fn:sum(Val)."
                    .to_string(),
            ];
            let session =
                DdSession::spawn_mode(&edb, &rules, ProvenanceMode::Lazy).expect("spawn lazy sum");

            // Cat "a": 10 + 5 = 15.
            let fact = Row::from(&[v_str("a"), v_num(15)][..]);
            let (rid, h) = session
                .why_height("total", &fact)
                .expect("total(a,15) must have an annotation");
            assert_eq!(h, 1, "aggregate fact is a base-height-1 leaf");

            let g = session
                .why_step(rid, &fact, h)
                .expect("subproof for total(a,15) must exist");
            assert!(g.premises.is_empty(), "sum aggregate leaf has no premises");
        }
    }

    /// Coverage: a diamond graph where path(a,d) has two shortest derivations
    /// (via b and via c), both height 2. The min-height reduce must settle on
    /// height 2 (deterministic tie-break on rule_id), and the reconstructed
    /// grounding's premises must be strictly below height 2.
    #[test]
    fn lazy_provenance_diamond_multi_derivation() {
        let edb: Vec<(String, Vec<Value>)> = vec![
            ("edge".to_string(), vec![v_str("a"), v_str("b")]),
            ("edge".to_string(), vec![v_str("a"), v_str("c")]),
            ("edge".to_string(), vec![v_str("b"), v_str("d")]),
            ("edge".to_string(), vec![v_str("c"), v_str("d")]),
        ];
        let rules = vec![
            "Decl edge(Src, Dst).\nDecl path(Src, Dst).\n\
             path(X, Y) :- edge(X, Y).\n\
             path(X, Z) :- edge(X, Y), path(Y, Z)."
                .to_string(),
        ];
        let session =
            DdSession::spawn_mode(&edb, &rules, ProvenanceMode::Lazy).expect("spawn lazy diamond");

        let ad = Row::from(&[v_str("a"), v_str("d")][..]);
        let (rid, h) = session
            .why_height("path", &ad)
            .expect("path(a,d) must have an annotation");
        assert_eq!(
            h, 2,
            "path(a,d) shortest height is 2 (two equal-length paths)"
        );

        let g = session
            .why_step(rid, &ad, h)
            .expect("subproof for path(a,d) must exist");
        assert_eq!(g.premises.len(), 2, "recursive rule: edge + path premises");
        for p in &g.premises {
            assert!(
                p.height < h,
                "premise {:?} height {} not < {}",
                p.row,
                p.height,
                h
            );
        }
        // The recursive premise must be path(b,d) or path(c,d) (either shortest).
        let path_premise = g
            .premises
            .iter()
            .find(|p| p.rel == "path")
            .expect("a path premise");
        let pv = path_premise.row.clone().into_values();
        assert!(
            pv == vec![v_str("b"), v_str("d")] || pv == vec![v_str("c"), v_str("d")],
            "recursive premise should be path(b,d) or path(c,d); got {pv:?}"
        );
        assert_eq!(path_premise.height, 1, "the intermediate path has height 1");
    }

    /// Coverage: `CallFilter` builtins, both polarities. Each head has two
    /// candidate premises and only the filter tells them apart, so a replay
    /// that mis-evaluates the filter picks the wrong premise (not just none).
    #[test]
    fn lazy_provenance_call_filter() {
        let edb: Vec<(String, Vec<Value>)> = vec![
            ("name".to_string(), vec![v_num(1), v_str("apple")]),
            ("name".to_string(), vec![v_num(1), v_str("banana")]),
            ("name".to_string(), vec![v_num(2), v_str("avocado")]),
            ("name".to_string(), vec![v_num(2), v_str("cherry")]),
        ];
        let rules = vec![
            "Decl name(X, N).\nDecl has_a(X).\nDecl no_a(X).\n\
             has_a(X) :- name(X, N), :string:starts_with(N, \"a\").\n\
             no_a(X) :- name(X, N), !:string:starts_with(N, \"a\")."
                .to_string(),
        ];
        let session =
            DdSession::spawn_mode(&edb, &rules, ProvenanceMode::Lazy).expect("spawn lazy");

        for (rel, x, want) in [("has_a", 1, "apple"), ("no_a", 2, "cherry")] {
            let fact = Row::from(&[v_num(x)][..]);
            let (rid, h) = session
                .why_height(rel, &fact)
                .unwrap_or_else(|| panic!("{rel}({x}) must have an annotation"));
            let g = session
                .why_step(rid, &fact, h)
                .unwrap_or_else(|| panic!("subproof for {rel}({x}) must exist"));
            assert_eq!(g.premises.len(), 1);
            assert_eq!(
                g.premises[0].row,
                Row::from(&[v_num(x), v_str(want)][..]),
                "{rel}({x}) must be explained by name({x}, {want:?})"
            );
        }
    }

    /// Coverage: a multi-premise non-recursive rule (a 3-way join) reconstructs
    /// with all three positive premises at height 0 (all EDB).
    #[test]
    fn lazy_provenance_multi_premise_nonrecursive() {
        let edb: Vec<(String, Vec<Value>)> = vec![
            ("a".to_string(), vec![v_num(1), v_num(2)]),
            ("b".to_string(), vec![v_num(2), v_num(3)]),
            ("c".to_string(), vec![v_num(3), v_num(4)]),
        ];
        let rules = vec![
            "Decl a(X, Y).\nDecl b(Y, Z).\nDecl c(Z, W).\nDecl tri(X, W).\n\
             tri(X, W) :- a(X, Y), b(Y, Z), c(Z, W)."
                .to_string(),
        ];
        let session =
            DdSession::spawn_mode(&edb, &rules, ProvenanceMode::Lazy).expect("spawn lazy tri");

        let fact = Row::from(&[v_num(1), v_num(4)][..]);
        let (rid, h) = session
            .why_height("tri", &fact)
            .expect("tri(1,4) must have an annotation");
        assert_eq!(
            h, 1,
            "single non-recursive derivation over EDB has height 1"
        );

        let g = session
            .why_step(rid, &fact, h)
            .expect("subproof must exist");
        assert_eq!(
            g.premises.len(),
            3,
            "three-way join has 3 positive premises"
        );
        let rels: Vec<&str> = g.premises.iter().map(|p| p.rel.as_str()).collect();
        assert!(rels.contains(&"a") && rels.contains(&"b") && rels.contains(&"c"));
        for p in &g.premises {
            assert_eq!(p.height, 0, "all premises are EDB (height 0)");
        }
    }

    /// Coverage: a rule with a constant in the head. The head projection mixes a
    /// `Slot::Const` with a `Slot::Col`, so reconstruction's projection-match and
    /// the annotation head projection must both honour constants.
    #[test]
    fn lazy_provenance_constant_in_head() {
        let edb: Vec<(String, Vec<Value>)> = vec![
            ("src".to_string(), vec![v_str("x")]),
            ("src".to_string(), vec![v_str("y")]),
        ];
        let rules = vec![
            "Decl src(A).\nDecl tagged(Tag, A).\n\
             tagged(\"const\", A) :- src(A)."
                .to_string(),
        ];
        let session = DdSession::spawn_mode(&edb, &rules, ProvenanceMode::Lazy)
            .expect("spawn lazy const-head");

        let fact = Row::from(&[v_str("const"), v_str("x")][..]);
        let (rid, h) = session
            .why_height("tagged", &fact)
            .expect("tagged(const,x) must have an annotation");
        assert_eq!(h, 1, "non-recursive EDB derivation has height 1");

        let g = session
            .why_step(rid, &fact, h)
            .expect("subproof must exist");
        assert_eq!(g.premises.len(), 1, "one premise: src(A)");
        assert_eq!(g.premises[0].rel, "src");
        assert_eq!(g.premises[0].row.clone().into_values(), vec![v_str("x")]);
        assert_eq!(g.premises[0].height, 0);
    }
}
