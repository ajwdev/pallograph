// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Translate a `LoweredRule` into a differential-dataflow `VecCollection<Row>`.
//!
//! Each `Step` in the rule's pipeline transforms the current collection, growing
//! the row schema as variables are bound.  The final `Insert` step projects the
//! head arguments.

use std::collections::HashMap;

use anyhow::{Result, bail};
use differential_dataflow::VecCollection;
use timely::progress::Timestamp;

use mangle_common::Value;
use mangle_interpreter::eval_function;

use crate::dd::lower::{CmpOp, LoweredAggregate, LoweredRule, OwnedExpr, Slot, Step};
use crate::dd::value::{CompoundKindMirror, OrdF64, Row, Val};

/// A fact's lazy-provenance annotation, `(rule_id, height)`, kept in a *side*
/// collection keyed by the fact's `Row`.
///
/// `height` is the depth of the fact's shortest proof tree: 0 for an EDB
/// fact, otherwise `1 + max(premise heights)`, minimised over all of the
/// fact's derivations. `rule_id` is the rule that achieved that minimum
/// ([`SENTINEL_EDB`](crate::dd::value::SENTINEL_EDB) for EDB facts).
///
/// Storing just this per fact, instead of every derivation, is enough to
/// rebuild one minimal-height proof on demand at `::why` time: find a
/// grounding of `rule_id` whose premises all have strictly lower heights, then
/// recurse into each premise (`reconstruct_grounding` in `session.rs`). The
/// strict decrease is what guarantees the walk terminates.
///
/// The technique comes from the Soufflé Datalog engine: Zhao, Subotić &
/// Scholz, "Debugging Large-scale Datalog: A Scalable Provenance Evaluation
/// Strategy", TOPLAS 2020. Design notes: `docs/lazy-provenance.md`.
pub type Annotation = (u32, u32);

/// Collapse a collection of candidate annotations `(fact, (rule_id, height))`
/// to one annotation per fact: the minimal `(height, rule_id)` (smallest height
/// wins; tie-break on smallest rule_id for determinism). This is the DD
/// realisation of the provenance-lattice join `min` (the `min_g` in the height
/// update equation `h'(t) = min_g (1 + max_i h(t_i))`).
///
/// Output multiplicity is always 1, so the result is a proper set (one
/// annotation per fact). Runs inside the recursive scope for recursive heads,
/// where `reduce`'s differential retractions give the "re-fire on height
/// improvement" behaviour for free.
pub fn min_reduce_annotations<'scope, T>(
    candidates: VecCollection<'scope, T, (Row, Annotation)>,
) -> VecCollection<'scope, T, (Row, Annotation)>
where
    T: Timestamp + differential_dataflow::lattice::Lattice + Ord + 'static,
{
    candidates.reduce(
        |_fact, input: &[(&Annotation, isize)], output: &mut Vec<(Annotation, isize)>| {
            // Pick lexicographically-minimal (height, rule_id).
            let best = input
                .iter()
                .map(|((rid, h), _)| (*h, *rid))
                .min()
                .expect("reduce group is non-empty");
            let (h, rid) = best;
            output.push(((rid, h), 1));
        },
    )
}

// ---------------------------------------------------------------------------
// Slot helper
// ---------------------------------------------------------------------------

#[inline]
pub fn slot_val(slot: &Slot, row: &Row) -> Val {
    match slot {
        Slot::Col(i) => row.0[*i].clone(),
        Slot::Const(v) => v.clone(),
    }
}

// ---------------------------------------------------------------------------
// Cmp evaluation
// ---------------------------------------------------------------------------

pub fn eval_cmp(op: CmpOp, left: &Val, right: &Val) -> bool {
    match op {
        CmpOp::Eq => left == right,
        CmpOp::Neq => left != right,
        CmpOp::Lt => left < right,
        CmpOp::Le => left <= right,
        CmpOp::Gt => left > right,
        CmpOp::Ge => left >= right,
    }
}

// ---------------------------------------------------------------------------
// Expr evaluation
// ---------------------------------------------------------------------------

/// Evaluate a `let` expression against one row.
///
/// Calls the interpreter's own `eval_function`, so errors (e.g. `fn:plus` on
/// a string) carry the same messages and fail the same evaluations as upstream
/// mangle. See `Step::Let` for how they are surfaced.
pub fn eval_expr(expr: &OwnedExpr, row: &Row) -> Result<Val> {
    match expr {
        OwnedExpr::Value(slot) => Ok(slot_val(slot, row)),
        OwnedExpr::Call { func, args } => {
            let vals: Vec<Value> = args.iter().map(|s| slot_val(s, row).into()).collect();
            Ok(Val::from(&eval_function(func, &vals)?))
        }
    }
}

/// `Step::MatchField` on one row: append the struct's `field` value, or drop
/// the row if the slot is not a struct or lacks the field. Shared with lazy
/// provenance replay (`session.rs`) so both see the same rows.
pub fn match_field_row(struct_slot: &Slot, field: &str, row: Row) -> Option<Row> {
    match slot_val(struct_slot, &row) {
        Val::Compound(CompoundKindMirror::Struct, kvs) => {
            // Struct layout: [k1, v1, k2, v2, ...]
            let (pairs, _) = kvs.as_chunks::<2>();
            pairs
                .iter()
                .find(|[key, _]| matches!(key, Val::Name(n) if &**n == field))
                .map(|[_, value]| row.appended(std::iter::once(value.clone())))
        }
        _ => None,
    }
}

/// `Step::IterateList` on one row: one output row per list (or pair) element,
/// appended. Shared with lazy provenance replay like [`match_field_row`].
pub fn iterate_list_row(source_slot: &Slot, row: Row) -> Vec<Row> {
    match slot_val(source_slot, &row) {
        Val::Compound(CompoundKindMirror::List, elems)
        | Val::Compound(CompoundKindMirror::Pair, elems) => elems
            .into_iter()
            .map(|elem| row.appended(std::iter::once(elem)))
            .collect(),
        _ => vec![],
    }
}

// ---------------------------------------------------------------------------
// Built-in predicate filters (Condition::Call)
// ---------------------------------------------------------------------------

/// The set of `CallFilter` builtins the DD backend supports.
///
/// Single source of truth shared by [`is_supported_call_filter`] (build-time
/// validation) and [`eval_call_filter`] (runtime evaluation) so the two cannot
/// drift apart.
const SUPPORTED_CALL_FILTERS: &[&str] = &[
    ":string:starts_with",
    ":string:ends_with",
    ":string:contains",
    ":match_prefix",
    // Check modes, only reached via negation (`!:list:member`, `!:match_field`).
    // The positive forms bind variables and lower to IterateList / MatchField.
    ":list:member",
    ":match_field",
];

/// True if `func` is a `CallFilter` builtin the DD backend can evaluate.
pub(crate) fn is_supported_call_filter(func: &str) -> bool {
    SUPPORTED_CALL_FILTERS.contains(&func)
}

/// Evaluate a built-in predicate against one row.
///
/// Type errors follow upstream mangle's interpreter (`eval_builtin_predicate`):
/// `:string:*` and `:match_prefix` return `Err` on wrong argument types, while
/// the `:list:member` / `:match_field` check modes return `false`. The error
/// messages match the interpreter's too. This is deliberate parity, not a
/// considered semantics; if upstream (or we) decide a type mismatch should
/// just be `false`, change it here and drop the error collection in
/// `Step::CallFilter`.
pub fn eval_call_filter(func: &str, args: &[Slot], row: &Row) -> Result<bool> {
    let vals: Vec<Val> = args.iter().map(|s| slot_val(s, row)).collect();
    match func {
        ":string:starts_with" => {
            let (Val::String(s), Val::String(prefix)) = (&vals[0], &vals[1]) else {
                bail!(":string:starts_with: expected string arguments");
            };
            Ok(s.starts_with(&**prefix))
        }
        ":string:ends_with" => {
            let (Val::String(s), Val::String(suffix)) = (&vals[0], &vals[1]) else {
                bail!(":string:ends_with: expected string arguments");
            };
            Ok(s.ends_with(&**suffix))
        }
        ":string:contains" => {
            let (Val::String(s), Val::String(needle)) = (&vals[0], &vals[1]) else {
                bail!(":string:contains: expected string arguments");
            };
            Ok(s.contains(&**needle))
        }
        ":match_prefix" => {
            let (Val::Name(name), Val::Name(prefix)) = (&vals[0], &vals[1]) else {
                bail!(":match_prefix: expected name arguments");
            };
            // Strictly longer, matching the interpreter: `/a` is not a prefix match of `/a`.
            Ok(name.starts_with(&**prefix) && name.len() > prefix.len())
        }
        // :list:member(Elem, List) check mode. A non-list yields false,
        // matching the interpreter (so the negation keeps the row).
        ":list:member" => match &vals[1] {
            Val::Compound(CompoundKindMirror::List, elems) => Ok(elems.contains(&vals[0])),
            _ => Ok(false),
        },
        // :match_field(Struct, Field, Value) check mode: the struct has the
        // field with that value. A non-struct or missing field yields false,
        // matching the interpreter.
        ":match_field" => match (&vals[0], &vals[1]) {
            (Val::Compound(CompoundKindMirror::Struct, kvs), Val::Name(_)) => {
                // Struct layout: [k1, v1, k2, v2, ...]
                Ok(kvs
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .any(|kv| kv[0] == vals[1] && kv[1] == vals[2]))
            }
            _ => Ok(false),
        },
        other => bail!("unsupported CallFilter function: {other}"),
    }
}

// ---------------------------------------------------------------------------
// Aggregate evaluation (for Step::Reduce)
// ---------------------------------------------------------------------------

/// Evaluate one aggregate function over a DD reduce group.
///
/// `input: &[(&Row, isize)]` — each entry is a full pre-key row with its
/// accumulated multiplicity (always positive in batch mode).
///
/// Mirrors the interpreter's `eval_aggregate` semantics exactly.
pub fn eval_aggregate(agg: &LoweredAggregate, input: &[(&Row, isize)]) -> Val {
    // Helper: read the aggregate argument from a row (Col index or Const value).
    let arg = |row: &Row| -> Val {
        slot_val(
            agg.arg_slot
                .as_ref()
                .expect("aggregate requires 1 argument"),
            row,
        )
    };
    match agg.func.as_str() {
        "fn:count" => {
            let n: isize = input.iter().map(|(_, diff)| diff).sum();
            Val::Number(n as i64)
        }
        "fn:sum" => {
            let mut sum: i64 = 0;
            for (row, diff) in input {
                if let Val::Number(n) = arg(row) {
                    sum += n * (*diff as i64);
                }
            }
            Val::Number(sum)
        }
        "fn:float:sum" => {
            let mut sum: f64 = 0.0;
            for (row, diff) in input {
                let v = match arg(row) {
                    Val::Float(OrdF64(f)) => f,
                    Val::Number(n) => n as f64,
                    _ => 0.0,
                };
                sum += v * (*diff as f64);
            }
            Val::Float(OrdF64(sum))
        }
        "fn:max" => input
            .iter()
            .map(|(row, _)| arg(row))
            .max()
            .expect("fn:max on empty group (DD guarantees non-empty)"),
        "fn:float:max" => input
            .iter()
            .map(|(row, _)| arg(row))
            .max()
            .expect("fn:float:max on empty group (DD guarantees non-empty)"),
        "fn:min" => input
            .iter()
            .map(|(row, _)| arg(row))
            .min()
            .expect("fn:min on empty group (DD guarantees non-empty)"),
        "fn:float:min" => input
            .iter()
            .map(|(row, _)| arg(row))
            .min()
            .expect("fn:float:min on empty group (DD guarantees non-empty)"),
        "fn:collect" | "fn:collect_distinct" => {
            let distinct = agg.func == "fn:collect_distinct";
            let mut out: Vec<Val> = Vec::new();
            for (row, diff) in input {
                let val = arg(row);
                if distinct {
                    if !out.contains(&val) {
                        out.push(val);
                    }
                } else {
                    for _ in 0..*diff {
                        out.push(val.clone());
                    }
                }
            }
            Val::Compound(CompoundKindMirror::List, out)
        }
        other => panic!("unsupported aggregate function: {other}"),
    }
}

// ---------------------------------------------------------------------------
// Main entry: build one rule into a Collection
// ---------------------------------------------------------------------------

/// Build a DD collection for `rule` using `rels` as the input (EDB + already-
/// computed IDB) relations.
///
/// `T` is the timestamp used by the enclosing timely dataflow scope.  Typically
/// `T = u64` for the top-level batch scope; `T = Product<u64, u32>` for the
/// recursive inner scope in Phase 3.
///
/// Runtime evaluation errors (see [`eval_call_filter`]) are pushed onto
/// `errors` as single-column rows holding the message.
///
/// Returns the output `VecCollection<Row>` — its rows are the tuples to be
/// inserted into `rule.head_rel`.  Call `.distinct()` after concatenating all
/// rules for the same head relation.
///
/// # Provenance
///
/// With `provenance` on, also returns a parallel annotation collection
/// `Collection<(Row, (rule_id, height))>`: one candidate annotation per
/// grounding of this rule, `height = 1 + max(premise heights)`. The premise
/// heights are looked up by joining the pre-projection row against each
/// positive premise relation's *annotation* sibling collection (`annotations`).
/// The per-fact `min` over all groundings/rules is done by the caller
/// (`session.rs`) via a `reduce`. With it off, the annotation return is `None`
/// and no extra operators are built.
///
/// Returns `(head_rows, annotations)`.
pub fn build_rule<'scope, T>(
    rule: &LoweredRule,
    rels: &HashMap<String, VecCollection<'scope, T, Row>>,
    annotations: &HashMap<String, VecCollection<'scope, T, (Row, Annotation)>>,
    unit_coll: &VecCollection<'scope, T, Row>,
    errors: &mut Vec<VecCollection<'scope, T, Row>>,
    provenance: bool,
) -> Result<(
    VecCollection<'scope, T, Row>,
    Option<VecCollection<'scope, T, (Row, Annotation)>>,
)>
where
    T: Timestamp + differential_dataflow::lattice::Lattice + Ord + 'static,
{
    let mut curr: Option<VecCollection<'scope, T, Row>> = None;
    let mut annotation: Option<VecCollection<'scope, T, (Row, Annotation)>> = None;
    let n_steps = rule.steps.len();

    // Lazy provenance covers every body step. Only `Scan`/`Join` contribute
    // premises (and so height); everything else is height-neutral:
    //
    // - `Cmp` and `CallFilter` are pure row filters (the mangle planner adds a
    //   redundant `Cmp(Eq)` even after a keyed join, so `Cmp` is common).
    // - `Let`, `MatchField` and `IterateList` only append columns. A later
    //   premise may key on one, which is fine: replay appends the same columns
    //   in the same order, so `premise_atoms[..].arg_cols` index identically.
    // - `Antijoin` is height-neutral: negated atoms are excluded from
    //   `premise_atoms`. The lazy path records them separately in
    //   `negated_atoms` for rendering only.
    // - `Reduce` (aggregation) is treated as a leaf: aggregate rules carry empty
    //   `premise_atoms` (interpreter parity), so the height join-chain yields the
    //   base height 1 and reconstruction terminates with no descent.
    //
    // `reconstruct_grounding` (session.rs) must replay each step identically.

    for (idx, step) in rule.steps.iter().enumerate() {
        match step {
            // ---------------------------------------------------------------
            // Unit — seed collection for unit rules (no body).
            // ---------------------------------------------------------------
            Step::Unit => {
                curr = Some(unit_coll.clone());
            }

            // ---------------------------------------------------------------
            // Scan — seeds the pipeline from an EDB/IDB relation.
            // ---------------------------------------------------------------
            Step::Scan { rel } => {
                let base = rels
                    .get(rel)
                    .ok_or_else(|| anyhow::anyhow!("relation `{rel}` not found in rels"))?;
                curr = Some(base.clone());
            }

            // ---------------------------------------------------------------
            // Join — equijoin the current pipeline against another relation.
            //
            // We re-key both sides on the shared vars, then join_map to
            // assemble the extended row.  Zero shared vars → cross product
            // (key = empty Row), which is correct but O(n²).
            // ---------------------------------------------------------------
            Step::Join {
                rel,
                left_key_cols,
                right_key_cols,
                right_new_cols,
            } => {
                let left = curr
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("Join before Scan"))?;
                let right = rels
                    .get(rel)
                    .ok_or_else(|| anyhow::anyhow!("relation `{rel}` not found in rels"))?
                    .clone();

                let lkc = left_key_cols.clone();
                let rkc = right_key_cols.clone();
                let rnc = right_new_cols.clone();

                // Re-key left as (key, full_row) for join.
                let left_keyed: VecCollection<'scope, T, (Row, Row)> = left.map(move |row| {
                    let key = Row(lkc.iter().map(|&i| row.0[i].clone()).collect());
                    (key, row)
                });

                // Re-key right as (key, new_vals) — only new (non-key) columns.
                let right_keyed: VecCollection<'scope, T, (Row, Row)> = right.map(move |row| {
                    let key = Row(rkc.iter().map(|&i| row.0[i].clone()).collect());
                    let new_vals = Row(rnc.iter().map(|&i| row.0[i].clone()).collect());
                    (key, new_vals)
                });

                curr = Some(left_keyed.join_map(
                    right_keyed,
                    |_key, left_full: &Row, right_new: &Row| {
                        left_full.appended(right_new.0.iter().cloned())
                    },
                ));
            }

            // ---------------------------------------------------------------
            // Cmp — row-wise comparison filter.
            // ---------------------------------------------------------------
            Step::Cmp { op, left, right } => {
                let pipeline = curr
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("Cmp before Scan"))?;
                let op = *op;
                let left = left.clone();
                let right = right.clone();
                curr = Some(pipeline.filter(move |row| {
                    eval_cmp(op, &slot_val(&left, row), &slot_val(&right, row))
                }));
            }

            // ---------------------------------------------------------------
            // Antijoin — Phase 2.
            //
            // left_key_slots index into the left pipeline row.
            // right_key_cols are the parallel column positions in neg_rel itself.
            // const_filters filter neg_rel before building its key projection.
            // ---------------------------------------------------------------
            Step::Antijoin {
                rel,
                left_key_slots,
                right_key_cols,
                const_filters,
            } => {
                let pipeline = curr
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("Antijoin before Scan"))?;
                let neg_rel = rels
                    .get(rel)
                    .ok_or_else(|| anyhow::anyhow!("antijoin relation `{rel}` not found"))?
                    .clone();

                let lks = left_key_slots.clone();
                let rkc = right_key_cols.clone();
                let cf = const_filters.clone();

                // Project left pipeline to (key, full_row).
                let keyed_input: VecCollection<'scope, T, (Row, Row)> = pipeline.map(move |row| {
                    let key = Row(lks.iter().map(|s| slot_val(s, &row)).collect());
                    (key, row)
                });

                // Filter neg_rel by constant args, then project to key columns.
                let neg_keys: VecCollection<'scope, T, Row> = neg_rel.flat_map(move |row| {
                    for (col, val) in &cf {
                        if &row.0[*col] != val {
                            return vec![];
                        }
                    }
                    vec![Row(rkc.iter().map(|&i| row.0[i].clone()).collect())]
                });

                curr = Some(keyed_input.antijoin(neg_keys).map(|(_key, row)| row));
            }

            // ---------------------------------------------------------------
            // CallFilter — Phase 2 string builtins.
            // ---------------------------------------------------------------
            Step::CallFilter { func, args, negate } => {
                let pipeline = curr
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("CallFilter before Scan"))?;
                // Validate at build time: an unsupported/typo'd builtin would
                // otherwise be swallowed by `.unwrap_or(false)` in the filter
                // closure, silently dropping every row. Fail loudly instead.
                if !is_supported_call_filter(func) {
                    bail!("unsupported CallFilter function (DD backend limitation): {func}");
                }
                let func = func.clone();
                let args = args.clone();
                let negate = *negate;
                // A dataflow can't abort mid-evaluation the way the interpreter
                // does, so an evaluation error drops the row (in both polarities)
                // and is emitted into `errors` instead. The session refuses to
                // answer reads while any error rows are live, which matches the
                // interpreter failing the whole evaluation. Retracting the
                // offending fact retracts its error row too.
                let (err_func, err_args) = (func.clone(), args.clone());
                errors.push(pipeline.clone().flat_map(move |row| {
                    eval_call_filter(&err_func, &err_args, &row)
                        .err()
                        .map(|e| Row(vec![Val::String(e.to_string().into())].into()))
                }));
                curr = Some(pipeline.filter(move |row| {
                    eval_call_filter(&func, &args, row).is_ok_and(|b| b != negate)
                }));
            }

            // ---------------------------------------------------------------
            // Let — append a computed column. Phase 4.
            // ---------------------------------------------------------------
            Step::Let { expr } => {
                let pipeline = curr
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("Let before Scan"))?;
                let expr = expr.clone();
                // Same scheme as `CallFilter`: a failing row is dropped and its
                // error emitted into `errors`. Evaluate once and tag each row
                // with its outcome, since functions can be costlier than checks.
                let evaluated = pipeline.map(move |row| match eval_expr(&expr, &row) {
                    Ok(v) => (None, row.appended(std::iter::once(v))),
                    Err(e) => (Some(e.to_string()), row),
                });
                errors.push(
                    evaluated.clone().flat_map(|(err, _row)| {
                        err.map(|m| Row(vec![Val::String(m.into())].into()))
                    }),
                );
                curr = Some(evaluated.flat_map(|(err, row)| err.is_none().then_some(row)));
            }

            // ---------------------------------------------------------------
            // MatchField — flat_map over struct fields. Phase 4.
            // ---------------------------------------------------------------
            Step::MatchField { struct_slot, field } => {
                let pipeline = curr
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("MatchField before Scan"))?;
                let struct_slot = struct_slot.clone();
                let field = field.clone();
                curr =
                    Some(pipeline.flat_map(move |row| match_field_row(&struct_slot, &field, row)));
            }

            // ---------------------------------------------------------------
            // IterateList — flat_map over list elements. Phase 4.
            // ---------------------------------------------------------------
            Step::IterateList { source_slot } => {
                let pipeline = curr
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("IterateList before Scan"))?;
                let source_slot = source_slot.clone();
                curr = Some(pipeline.flat_map(move |row| iterate_list_row(&source_slot, row)));
            }

            // ---------------------------------------------------------------
            // Reduce — GroupBy aggregation via DD's `reduce` operator.
            //
            // We map the current collection to (key_Row, full_Row) keyed on
            // `key_cols`, then reduce over each group to compute the aggregates.
            // The output row is key ++ [agg_result ...] with multiplicity 1.
            // ---------------------------------------------------------------
            Step::Reduce {
                key_cols,
                aggregates,
            } => {
                let pipeline = curr
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("Reduce before Scan"))?;
                let kc = key_cols.clone();
                let aggs = aggregates.clone();

                // Re-key as (key_Row, full_Row) so reduce can access the arg columns.
                let keyed: VecCollection<'scope, T, (Row, Row)> = pipeline.map(move |row| {
                    let key = Row(kc.iter().map(|&i| row.0[i].clone()).collect());
                    (key, row)
                });

                // reduce: for each group compute aggregates and push V2 = Row(agg_vals).
                // DD's reduce output is Collection<T, (K, V2), R2> = (key_Row, agg_Row).
                let reduced: VecCollection<'scope, T, (Row, Row)> = keyed.reduce(
                    move |_key, input: &[(&Row, isize)], output: &mut Vec<(Row, isize)>| {
                        let agg_vals: Vec<Val> =
                            aggs.iter().map(|a| eval_aggregate(a, input)).collect();
                        output.push((Row(agg_vals.into()), 1));
                    },
                );

                // Flatten (key_Row, agg_Row) into a single Row: key ++ aggs.
                curr =
                    Some(reduced.map(|(key, aggs)| {
                        Row(key.0.iter().chain(aggs.0.iter()).cloned().collect())
                    }));
            }

            // ---------------------------------------------------------------
            // Insert — final projection into the head relation's tuple shape.
            // ---------------------------------------------------------------
            Step::Insert { proj } => {
                let pipeline = curr
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("Insert before Scan"))?;

                // -------------------------------------------------------------
                // Lazy provenance: emit one candidate annotation per grounding.
                //
                // height = 1 + max over positive premises of premise.height.
                // We look up each premise's height by joining the wide pre-
                // projection `pipeline` row against that premise relation's
                // annotation sibling collection (keyed by the premise tuple).
                // The per-fact `min` over groundings/rules happens in the caller.
                //
                // Only the final Insert is a derivation of the head: aggregation
                // rules carry an intermediate Insert into a temp relation before
                // the Reduce.
                // -------------------------------------------------------------
                if provenance && idx + 1 == n_steps {
                    let head_proj = proj.clone();
                    let atoms = rule.premise_atoms.clone();
                    let rule_id = rule.rule_id;

                    // Carry (wide_row, running_max_height) through a chain of
                    // joins, one per positive premise atom. Start max = 0.
                    let mut acc: VecCollection<'scope, T, (Row, u32)> =
                        pipeline.clone().map(|row| (row, 0u32));

                    for pa in &atoms {
                        let arg_cols = pa.arg_cols.clone();
                        let premise_annotations = annotations.get(&pa.rel).ok_or_else(|| {
                            anyhow::anyhow!(
                                "lazy provenance: no annotation collection for premise `{}`",
                                pa.rel
                            )
                        })?;

                        // Key the accumulator by this premise's tuple.
                        let acc_keyed: VecCollection<'scope, T, (Row, (Row, u32))> =
                            acc.map(move |(row, max_h)| {
                                let premise =
                                    Row(arg_cols.iter().map(|&i| row.0[i].clone()).collect());
                                (premise, (row, max_h))
                            });

                        // Key the premise annotations by their fact tuple; value
                        // = its height (we ignore the premise's own rule_id here).
                        let premise_keyed: VecCollection<'scope, T, (Row, u32)> =
                            premise_annotations
                                .clone()
                                .map(|(fact, (_rid, h))| (fact, h));

                        acc = acc_keyed.join_map(
                            premise_keyed,
                            |_premise, (row, max_h): &(Row, u32), premise_height: &u32| {
                                (row.clone(), (*max_h).max(*premise_height))
                            },
                        );
                    }

                    // Project the head and finalise height = 1 + max.
                    annotation = Some(acc.map(move |(row, max_h)| {
                        let head = Row(head_proj.iter().map(|s| slot_val(s, &row)).collect());
                        (head, (rule_id, max_h + 1))
                    }));
                }

                let proj = proj.clone();
                curr = Some(
                    pipeline.map(move |row| Row(proj.iter().map(|s| slot_val(s, &row)).collect())),
                );
            }
        }
    }

    let head = curr.ok_or_else(|| anyhow::anyhow!("rule produced no collection (empty steps?)"))?;
    Ok((head, annotation))
}
