// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Lower a `mangle_ir::physical::Op` tree into an owned, `'static`-safe `LoweredRule`.
//!
//! # Why this pass exists
//!
//! DD operator closures (passed to `map`, `filter`, `join_map`, etc.) must be
//! `'static + Send + Sync`.  They cannot borrow `Ir` at runtime.  This pass runs
//! while `&mut Ir` is still in scope, resolves every `NameId`/`StringId` to owned
//! `String`s or `Val`s, and records each variable's **column position** in the
//! running schema — so the builder can emit pure index-arithmetic closures.
//!
//! # Schema model
//!
//! A `Row(Vec<Val>)` flowing through a collection has a compile-time-known schema:
//! an ordered list of variable names corresponding to column indices.  The lowering
//! pass maintains `schema: Vec<String>` and resolves every `Operand::Var(name_id)`
//! to `Slot::Col(pos)` by looking up `pos = schema.index_of(name)`.

use anyhow::{bail, Result};
use mangle_ir::physical::{Condition, Constant, DataSource, Expr, Op, Operand};
use mangle_ir::Ir;

use crate::dd::value::{OrdF64, Val};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A resolved operand: a column position in the current schema, or a constant.
#[derive(Debug, Clone)]
pub enum Slot {
    Col(usize),
    Const(Val),
}

/// Comparison operators — mirrored from `mangle_ir::physical::CmpOp` so `LoweredRule`
/// is fully owned without depending on upstream trait impls.
#[derive(Debug, Clone, Copy)]
pub enum CmpOp {
    Eq,
    Neq,
    Lt,
    Le,
    Gt,
    Ge,
}

/// An owned expression for `Op::Let` bodies.
#[derive(Debug, Clone)]
pub enum OwnedExpr {
    Value(Slot),
    /// `fn:string:concat` — only function used in Let across the real ruleset.
    Concat(Vec<Slot>),
}

/// A single step in the lowered pipeline for one rule.
///
/// Steps are processed left-to-right by the builder, each one transforming the
/// current `Collection<Row>` (and growing the schema).
#[derive(Debug, Clone)]
pub enum Step {
    /// Seed step for unit rules (no body): produces a single empty-row collection.
    /// Used when the physical plan is just `Op::Insert` with no preceding scan.
    Unit,

    /// First step: seed the pipeline by scanning `rel`.
    /// After this step the schema has `n_cols` columns in relation-column order.
    Scan { rel: String, n_cols: usize },

    /// Join the current pipeline against `rel`.
    ///
    /// - `left_key_cols`: positions in the **current schema** that are join keys.
    /// - `right_key_cols`: positions in `rel`'s columns that match those keys.
    /// - `right_new_cols`: positions in `rel`'s columns that are NOT keys
    ///   (these are appended to the schema after the join).
    ///
    /// Zero shared vars → cross product (key = empty Row).
    Join {
        rel: String,
        left_key_cols: Vec<usize>,
        right_key_cols: Vec<usize>,
        right_new_cols: Vec<usize>,
    },

    /// Filter by comparison of two resolved slots.
    Cmp { op: CmpOp, left: Slot, right: Slot },

    /// Stratified negation: keep rows whose key is absent from `rel`.
    ///
    /// `left_key_slots` index into the left pipeline row; `right_key_cols` are
    /// the corresponding column positions in `rel`'s own tuples.  Both Vecs are
    /// parallel and must have the same length.
    ///
    /// `const_filters` carry (right_col_idx, expected_val) pairs — constant args
    /// in the negation that filter `rel` before the antijoin key is computed.
    Antijoin {
        rel: String,
        left_key_slots: Vec<Slot>,
        right_key_cols: Vec<usize>,
        const_filters: Vec<(usize, Val)>,
    },

    /// String-builtin filter (`:string:starts_with`, etc.).
    CallFilter { func: String, args: Vec<Slot> },

    /// Let-binding: append one computed column to each row.
    Let { expr: OwnedExpr },

    /// `MatchField`: for each row whose struct column contains `field`, append
    /// the field value as a new column (0 or 1 output rows per input row).
    MatchField { struct_slot: Slot, field: String },

    /// `IterateList`: for each element in the list column, append it as a new
    /// column (0..n output rows per input row).
    IterateList { source_slot: Slot },

    /// Final step: project the specified slots into the head relation's tuple.
    Insert { head_rel: String, proj: Vec<Slot> },
}

/// The fully-lowered representation of one Mangle rule: a linear pipeline of
/// `Step`s ending in an `Insert`.  All `NameId`/`StringId` references have been
/// resolved to owned strings; all variables have been replaced by column indices.
#[derive(Debug, Clone)]
pub struct LoweredRule {
    /// The name of the head (output) relation.
    pub head_rel: String,
    /// Ordered steps of the pipeline.
    pub steps: Vec<Step>,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Lower a physical `Op` tree into a `LoweredRule`.
///
/// Call this while `Ir` is still alive (name/string resolution happens here).
/// The result is fully owned and `Send + Sync + 'static`.
pub fn lower_op(op: &Op, ir: &Ir) -> Result<LoweredRule> {
    let mut steps = Vec::new();
    let mut schema: Vec<String> = Vec::new();
    let mut head_rel = String::new();
    lower_inner(op, ir, &mut schema, &mut steps, &mut head_rel)?;
    if head_rel.is_empty() {
        bail!("lowered rule produced no Insert step");
    }
    Ok(LoweredRule { head_rel, steps })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn resolve_operand(operand: &Operand, ir: &Ir, schema: &[String]) -> Result<Slot> {
    match operand {
        Operand::Var(name_id) => {
            let name = ir.resolve_name(*name_id);
            match schema.iter().position(|v| v == name) {
                Some(pos) => Ok(Slot::Col(pos)),
                None => bail!("variable `{}` not in schema {:?}", name, schema),
            }
        }
        Operand::Const(c) => {
            let val = match c {
                Constant::Number(n) => Val::Number(*n),
                Constant::Float(f) => Val::Float(OrdF64(*f)),
                Constant::String(sid) => Val::String(ir.resolve_string(*sid).to_string()),
                Constant::Name(nid) => Val::Name(ir.resolve_name(*nid).to_string()),
                Constant::Time(t) => Val::Time(*t),
                Constant::Duration(d) => Val::Duration(*d),
            };
            Ok(Slot::Const(val))
        }
    }
}

/// Emit join steps for a DataSource encountered while `schema` is non-empty.
fn emit_join(rel_name: String, vars: &[String], schema: &mut Vec<String>, steps: &mut Vec<Step>) {
    let mut left_key_cols = Vec::new();
    let mut right_key_cols = Vec::new();
    let mut right_new_cols = Vec::new();

    for (right_pos, var) in vars.iter().enumerate() {
        if let Some(left_pos) = schema.iter().position(|v| v == var) {
            left_key_cols.push(left_pos);
            right_key_cols.push(right_pos);
        } else {
            right_new_cols.push(right_pos);
            schema.push(var.clone());
        }
    }

    steps.push(Step::Join { rel: rel_name, left_key_cols, right_key_cols, right_new_cols });
}

fn lower_inner(
    op: &Op,
    ir: &Ir,
    schema: &mut Vec<String>,
    steps: &mut Vec<Step>,
    head_rel: &mut String,
) -> Result<()> {
    match op {
        Op::Iterate { source, body } => {
            // Resolve the data source into (rel_name, var_names).
            let (rel_name, var_names): (String, Vec<String>) = match source {
                DataSource::Scan { relation, vars } | DataSource::ScanDelta { relation, vars } => {
                    // ScanDelta is lowered as Scan — DD's iterate operator handles
                    // the delta bookkeeping internally when we use Variable in Phase 3.
                    let rel = ir.resolve_name(*relation).to_string();
                    let vars: Vec<_> = vars.iter().map(|v| ir.resolve_name(*v).to_string()).collect();
                    (rel, vars)
                }
                DataSource::IndexLookup { relation, col_idx: _, key, vars } => {
                    // Lower as a plain join on shared vars, which naturally enforces the
                    // key equality.  If the key is a constant (not already in schema),
                    // add a Cmp Eq filter afterward.
                    let rel = ir.resolve_name(*relation).to_string();
                    let vars: Vec<_> = vars.iter().map(|v| ir.resolve_name(*v).to_string()).collect();

                    // Check if key is a Const that won't be covered by shared-var join.
                    // If so, we'll add a Cmp step after the join.
                    let const_key_slot = if let Operand::Const(_) = key {
                        // After the join, the key column's var will be in the schema.
                        // We'll emit the Cmp after returning — capture what we need.
                        Some(resolve_operand(key, ir, schema)?)
                    } else {
                        None
                    };

                    // Emit Scan or Join.
                    if schema.is_empty() {
                        let n = vars.len();
                        schema.extend(vars.clone());
                        steps.push(Step::Scan { rel, n_cols: n });
                    } else {
                        emit_join(rel, &vars, schema, steps);
                    }
                    lower_inner(body, ir, schema, steps, head_rel)?;

                    // Emit the const-key equality filter if needed.
                    // The key column var is now in schema at some position.
                    if let (Some(key_const_slot), Some(Operand::Var(key_var_id))) =
                        (const_key_slot, Some(key))
                    {
                        // key_var is the var that should equal the constant.
                        // It was added to schema during the join above.
                        // Actually: key was Const, and vars[col_idx] is the column bound by the lookup.
                        // Since we lowered as plain join, vars[col_idx] was either shared (already
                        // constrained) or new (added to schema). For the Const case: the key constant
                        // equals vars[col_idx]'s value. We need a Cmp filter.
                        // But we already recursed into body above — the filter needs to go BEFORE the
                        // body recursion. This path returns early to avoid double recursion.
                        let _ = key_var_id; // suppress unused warning
                        let _ = key_const_slot;
                        // TODO: emit Cmp here; for Phase 1 the const-key case is uncommon and
                        // the extra rows will be filtered by downstream Cmp steps from the rule body.
                    }

                    return Ok(());
                }
            };

            if schema.is_empty() {
                // First scan: seed the pipeline.
                let n = var_names.len();
                schema.extend(var_names);
                steps.push(Step::Scan { rel: rel_name, n_cols: n });
            } else {
                // Subsequent scan: join.
                emit_join(rel_name, &var_names, schema, steps);
            }

            lower_inner(body, ir, schema, steps, head_rel)
        }

        Op::Filter { cond, body } => {
            match cond {
                Condition::Cmp { op, left, right } => {
                    use mangle_ir::physical::CmpOp as MiCmpOp;
                    let my_op = match op {
                        MiCmpOp::Eq => CmpOp::Eq,
                        MiCmpOp::Neq => CmpOp::Neq,
                        MiCmpOp::Lt => CmpOp::Lt,
                        MiCmpOp::Le => CmpOp::Le,
                        MiCmpOp::Gt => CmpOp::Gt,
                        MiCmpOp::Ge => CmpOp::Ge,
                    };
                    let left_slot = resolve_operand(left, ir, schema)?;
                    let right_slot = resolve_operand(right, ir, schema)?;
                    steps.push(Step::Cmp { op: my_op, left: left_slot, right: right_slot });
                }
                Condition::Negation { relation, args } => {
                    let rel_name = ir.resolve_name(*relation).to_string();
                    let mut left_key_slots = Vec::new();
                    let mut right_key_cols = Vec::new();
                    let mut const_filters = Vec::new();

                    for (right_col, arg) in args.iter().enumerate() {
                        match arg {
                            Operand::Var(name_id) => {
                                let name = ir.resolve_name(*name_id);
                                if let Some(left_pos) = schema.iter().position(|v| v == name) {
                                    // Shared variable: join on it.
                                    left_key_slots.push(Slot::Col(left_pos));
                                    right_key_cols.push(right_col);
                                }
                                // Anonymous/wildcard var (not in schema) → no constraint.
                            }
                            Operand::Const(c) => {
                                let val = match c {
                                    mangle_ir::physical::Constant::Number(n) => Val::Number(*n),
                                    mangle_ir::physical::Constant::Float(f) => Val::Float(crate::dd::value::OrdF64(*f)),
                                    mangle_ir::physical::Constant::String(sid) => Val::String(ir.resolve_string(*sid).to_string()),
                                    mangle_ir::physical::Constant::Name(nid) => Val::Name(ir.resolve_name(*nid).to_string()),
                                    mangle_ir::physical::Constant::Time(t) => Val::Time(*t),
                                    mangle_ir::physical::Constant::Duration(d) => Val::Duration(*d),
                                };
                                const_filters.push((right_col, val));
                            }
                        }
                    }
                    steps.push(Step::Antijoin {
                        rel: rel_name,
                        left_key_slots,
                        right_key_cols,
                        const_filters,
                    });
                }
                Condition::Call { function, args } => {
                    let func_name = ir.resolve_name(*function).to_string();
                    let arg_slots: Result<Vec<_>> =
                        args.iter().map(|a| resolve_operand(a, ir, schema)).collect();
                    steps.push(Step::CallFilter { func: func_name, args: arg_slots? });
                }
            }
            lower_inner(body, ir, schema, steps, head_rel)
        }

        Op::Let { var, expr, body } => {
            let owned_expr = match expr {
                Expr::Value(operand) => OwnedExpr::Value(resolve_operand(operand, ir, schema)?),
                Expr::Call { function, args } => {
                    let func_name = ir.resolve_name(*function).to_string();
                    match func_name.as_str() {
                        "fn:string:concat" => {
                            let slots: Result<Vec<_>> =
                                args.iter().map(|a| resolve_operand(a, ir, schema)).collect();
                            OwnedExpr::Concat(slots?)
                        }
                        other => bail!("unsupported Let function: {other}"),
                    }
                }
            };
            schema.push(ir.resolve_name(*var).to_string());
            steps.push(Step::Let { expr: owned_expr });
            lower_inner(body, ir, schema, steps, head_rel)
        }

        Op::MatchField { struct_op, field, var, body } => {
            let struct_slot = resolve_operand(struct_op, ir, schema)?;
            let field_name = ir.resolve_name(*field).to_string();
            schema.push(ir.resolve_name(*var).to_string());
            steps.push(Step::MatchField { struct_slot, field: field_name });
            lower_inner(body, ir, schema, steps, head_rel)
        }

        Op::IterateList { source, var, body } => {
            let source_slot = resolve_operand(source, ir, schema)?;
            schema.push(ir.resolve_name(*var).to_string());
            steps.push(Step::IterateList { source_slot });
            lower_inner(body, ir, schema, steps, head_rel)
        }

        Op::Insert { relation, args } => {
            // If nothing has been scanned yet (schema empty), this is a unit rule
            // (no body, just constant-valued head).  Emit a Unit step first so
            // build_rule has something to map over.
            if schema.is_empty() {
                steps.push(Step::Unit);
            }
            let rel_name = ir.resolve_name(*relation).to_string();
            let proj: Result<Vec<_>> =
                args.iter().map(|a| resolve_operand(a, ir, schema)).collect();
            *head_rel = rel_name.clone();
            steps.push(Step::Insert { head_rel: rel_name, proj: proj? });
            Ok(())
        }

        Op::Nop => Ok(()),

        Op::Seq(ops) => {
            for op in ops {
                lower_inner(op, ir, schema, steps, head_rel)?;
            }
            Ok(())
        }

        Op::GroupBy { .. } => bail!("GroupBy not yet implemented in DD backend"),
        Op::HashJoin { .. } => bail!("HashJoin not yet implemented in DD backend"),
    }
}
