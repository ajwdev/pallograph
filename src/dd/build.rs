// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Translate a `LoweredRule` into a differential-dataflow `VecCollection<Row>`.
//!
//! Each `Step` in the rule's pipeline transforms the current collection, growing
//! the row schema as variables are bound.  The final `Insert` step projects the
//! head arguments.

use std::collections::HashMap;

use anyhow::{bail, Result};
use differential_dataflow::VecCollection;
use timely::progress::Timestamp;

use mangle_common::Value;
use mangle_interpreter::eval_function;

use crate::dd::lower::{CmpOp, LoweredAggregate, LoweredRule, OwnedExpr, Slot, Step};
use crate::dd::value::{CompoundKindMirror, OrdF64, Val, Row};

// ---------------------------------------------------------------------------
// Slot helper
// ---------------------------------------------------------------------------

#[inline]
fn slot_val(slot: &Slot, row: &Row) -> Val {
    match slot {
        Slot::Col(i) => row.0[*i].clone(),
        Slot::Const(v) => v.clone(),
    }
}

// ---------------------------------------------------------------------------
// Cmp evaluation
// ---------------------------------------------------------------------------

fn eval_cmp(op: CmpOp, left: &Val, right: &Val) -> bool {
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

fn eval_expr(expr: &OwnedExpr, row: &Row) -> Val {
    match expr {
        OwnedExpr::Value(slot) => slot_val(slot, row),
        OwnedExpr::Call { func, args } => {
            let vals: Vec<Value> = args.iter().map(|s| slot_val(s, row).into()).collect();
            let result = eval_function(func, &vals)
                .unwrap_or_else(|e| panic!("Let fn:{func} failed: {e}"));
            Val::from(&result)
        }
    }
}

// ---------------------------------------------------------------------------
// String builtin filters (Condition::Call)
// ---------------------------------------------------------------------------

fn eval_call_filter(func: &str, args: &[Slot], row: &Row) -> Result<bool> {
    let vals: Vec<Val> = args.iter().map(|s| slot_val(s, row)).collect();
    match func {
        ":string:starts_with" => {
            let (Val::String(s), Val::String(prefix)) = (&vals[0], &vals[1]) else {
                return Ok(false);
            };
            Ok(s.starts_with(prefix.as_str()))
        }
        ":string:ends_with" => {
            let (Val::String(s), Val::String(suffix)) = (&vals[0], &vals[1]) else {
                return Ok(false);
            };
            Ok(s.ends_with(suffix.as_str()))
        }
        ":string:contains" => {
            let (Val::String(s), Val::String(needle)) = (&vals[0], &vals[1]) else {
                return Ok(false);
            };
            Ok(s.contains(needle.as_str()))
        }
        ":match_prefix" => {
            let (Val::Name(name), Val::Name(prefix)) = (&vals[0], &vals[1]) else {
                return Ok(false);
            };
            Ok(name.starts_with(prefix.as_str()))
        }
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
fn eval_aggregate(agg: &LoweredAggregate, input: &[(&Row, isize)]) -> Val {
    // Helper: read the aggregate argument from a row (Col index or Const value).
    let arg = |row: &Row| -> Val {
        slot_val(agg.arg_slot.as_ref().expect("aggregate requires 1 argument"), row)
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
/// `T = u32` for the top-level batch scope; `T = Product<u32, u32>` for the
/// recursive inner scope in Phase 3.
///
/// Returns the output `VecCollection<Row>` — its rows are the tuples to be
/// inserted into `rule.head_rel`.  Call `.distinct()` after concatenating all
/// rules for the same head relation.
pub fn build_rule<'scope, T>(
    rule: &LoweredRule,
    rels: &HashMap<String, VecCollection<'scope, T, Row>>,
    unit_coll: &VecCollection<'scope, T, Row>,
) -> Result<VecCollection<'scope, T, Row>>
where
    T: Timestamp + differential_dataflow::lattice::Lattice + Ord + 'static,
{
    let mut curr: Option<VecCollection<'scope, T, Row>> = None;

    for step in &rule.steps {
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
            Step::Scan { rel, n_cols: _ } => {
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
            Step::Join { rel, left_key_cols, right_key_cols, right_new_cols } => {
                let left = curr.take().ok_or_else(|| anyhow::anyhow!("Join before Scan"))?;
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

                curr = Some(left_keyed.join_map(right_keyed, |_key, left_full: &Row, right_new: &Row| {
                    let mut result = left_full.clone();
                    result.0.extend(right_new.0.iter().cloned());
                    result
                }));
            }

            // ---------------------------------------------------------------
            // Cmp — row-wise comparison filter.
            // ---------------------------------------------------------------
            Step::Cmp { op, left, right } => {
                let pipeline = curr.take().ok_or_else(|| anyhow::anyhow!("Cmp before Scan"))?;
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
            Step::Antijoin { rel, left_key_slots, right_key_cols, const_filters } => {
                let pipeline = curr.take().ok_or_else(|| anyhow::anyhow!("Antijoin before Scan"))?;
                let neg_rel = rels
                    .get(rel)
                    .ok_or_else(|| anyhow::anyhow!("antijoin relation `{rel}` not found"))?
                    .clone();

                let lks = left_key_slots.clone();
                let rkc = right_key_cols.clone();
                let cf = const_filters.clone();

                // Project left pipeline to (key, full_row).
                let keyed_input: VecCollection<'scope, T, (Row, Row)> =
                    pipeline.map(move |row| {
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
            Step::CallFilter { func, args } => {
                let pipeline = curr.take().ok_or_else(|| anyhow::anyhow!("CallFilter before Scan"))?;
                let func = func.clone();
                let args = args.clone();
                curr = Some(pipeline.filter(move |row| {
                    eval_call_filter(&func, &args, row).unwrap_or(false)
                }));
            }

            // ---------------------------------------------------------------
            // Let — append a computed column. Phase 4.
            // ---------------------------------------------------------------
            Step::Let { expr } => {
                let pipeline = curr.take().ok_or_else(|| anyhow::anyhow!("Let before Scan"))?;
                let expr = expr.clone();
                curr = Some(pipeline.map(move |mut row| {
                    let v = eval_expr(&expr, &row);
                    row.0.push(v);
                    row
                }));
            }

            // ---------------------------------------------------------------
            // MatchField — flat_map over struct fields. Phase 4.
            // ---------------------------------------------------------------
            Step::MatchField { struct_slot, field } => {
                let pipeline = curr.take().ok_or_else(|| anyhow::anyhow!("MatchField before Scan"))?;
                let struct_slot = struct_slot.clone();
                let field = field.clone();
                curr = Some(pipeline.flat_map(move |row| {
                    let sv = slot_val(&struct_slot, &row);
                    match sv {
                        Val::Compound(CompoundKindMirror::Struct, kvs) => {
                            // Struct layout: [k1, v1, k2, v2, ...]
                            let mut i = 0;
                            while i + 1 < kvs.len() {
                                if kvs[i] == Val::Name(field.clone()) {
                                    let mut r = row;
                                    r.0.push(kvs[i + 1].clone());
                                    return vec![r];
                                }
                                i += 2;
                            }
                            vec![]
                        }
                        _ => vec![],
                    }
                }));
            }

            // ---------------------------------------------------------------
            // IterateList — flat_map over list elements. Phase 4.
            // ---------------------------------------------------------------
            Step::IterateList { source_slot } => {
                let pipeline = curr.take().ok_or_else(|| anyhow::anyhow!("IterateList before Scan"))?;
                let source_slot = source_slot.clone();
                curr = Some(pipeline.flat_map(move |row| {
                    let sv = slot_val(&source_slot, &row);
                    match sv {
                        Val::Compound(CompoundKindMirror::List, elems)
                        | Val::Compound(CompoundKindMirror::Pair, elems) => elems
                            .into_iter()
                            .map(|elem| {
                                let mut r = row.clone();
                                r.0.push(elem);
                                r
                            })
                            .collect(),
                        _ => vec![],
                    }
                }));
            }

            // ---------------------------------------------------------------
            // Reduce — GroupBy aggregation via DD's `reduce` operator.
            //
            // We map the current collection to (key_Row, full_Row) keyed on
            // `key_cols`, then reduce over each group to compute the aggregates.
            // The output row is key ++ [agg_result ...] with multiplicity 1.
            // ---------------------------------------------------------------
            Step::Reduce { key_cols, aggregates } => {
                let pipeline =
                    curr.take().ok_or_else(|| anyhow::anyhow!("Reduce before Scan"))?;
                let kc = key_cols.clone();
                let aggs = aggregates.clone();

                // Re-key as (key_Row, full_Row) so reduce can access the arg columns.
                let keyed: VecCollection<'scope, T, (Row, Row)> = pipeline.map(move |row| {
                    let key = Row(kc.iter().map(|&i| row.0[i].clone()).collect());
                    (key, row)
                });

                // reduce: for each group compute aggregates and push V2 = Row(agg_vals).
                // DD's reduce output is Collection<T, (K, V2), R2> = (key_Row, agg_Row).
                let reduced: VecCollection<'scope, T, (Row, Row)> =
                    keyed.reduce(move |_key, input: &[(&Row, isize)], output: &mut Vec<(Row, isize)>| {
                        let agg_vals: Vec<Val> =
                            aggs.iter().map(|a| eval_aggregate(a, input)).collect();
                        output.push((Row(agg_vals), 1));
                    });

                // Flatten (key_Row, agg_Row) into a single Row: key ++ aggs.
                curr = Some(reduced.map(|(key, aggs)| {
                    Row(key.0.into_iter().chain(aggs.0).collect())
                }));
            }

            // ---------------------------------------------------------------
            // Insert — final projection into the head relation's tuple shape.
            // ---------------------------------------------------------------
            Step::Insert { head_rel: _, proj } => {
                let pipeline = curr.take().ok_or_else(|| anyhow::anyhow!("Insert before Scan"))?;
                let proj = proj.clone();
                curr = Some(pipeline.map(move |row| {
                    Row(proj.iter().map(|s| slot_val(s, &row)).collect())
                }));
            }
        }
    }

    curr.ok_or_else(|| anyhow::anyhow!("rule produced no collection (empty steps?)"))
}
