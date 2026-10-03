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

use anyhow::{Result, bail};
use mangle_ir::Ir;
use mangle_ir::physical::{Aggregate, Condition, Constant, DataSource, Expr, Op, Operand};

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
    /// Any `fn:*` scalar function call.  Delegated at build time to the
    /// interpreter's `eval_function` via `Val→Value→Val` round-trip.
    Call {
        func: String,
        args: Vec<Slot>,
    },
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
    /// After this step the schema holds `rel`'s columns in relation-column order.
    Scan { rel: String },

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

    /// Built-in predicate filter (`:string:starts_with`, etc.). With `negate`
    /// set, keeps rows where the predicate is false.
    CallFilter {
        func: String,
        args: Vec<Slot>,
        negate: bool,
    },

    /// Let-binding: append one computed column to each row.
    Let { expr: OwnedExpr },

    /// `MatchField`: for each row whose struct column contains `field`, append
    /// the field value as a new column (0 or 1 output rows per input row).
    MatchField { struct_slot: Slot, field: String },

    /// `IterateList`: for each element in the list column, append it as a new
    /// column (0..n output rows per input row).
    IterateList { source_slot: Slot },

    /// GroupBy / aggregation: group the current rows by `key_cols` and compute
    /// one aggregate per entry.  Output schema = key columns ++ aggregate result
    /// columns (in `aggregates` order).
    Reduce {
        key_cols: Vec<usize>,
        aggregates: Vec<LoweredAggregate>,
    },

    /// Final step: project the specified slots into the head relation's tuple.
    Insert { proj: Vec<Slot> },
}

/// One lowered aggregate in a `Step::Reduce`.
///
/// The aggregate result column is appended to the output row after all group-key
/// columns.  `arg_slot` is the pre-reduce source of the aggregate argument:
/// `Slot::Col(i)` for a variable, `Slot::Const(v)` for a literal, `None` for
/// zero-argument aggregates like `fn:count`.
#[derive(Debug, Clone)]
pub struct LoweredAggregate {
    pub func: String,
    pub arg_slot: Option<Slot>,
}

/// A negated body atom, recorded so the lazy provenance path can show it as a
/// non-descendable `¬rel(args)` leaf in a reconstructed proof.
///
/// `arg_slots` reads each argument of the negated atom from the rule's wide
/// pre-`Insert` row: `Some(Slot::Col(i))`/`Some(Slot::Const(v))` for a bound
/// variable or a literal, and `None` for an anonymous/wildcard argument that is
/// not addressable in the row (rendered as `_`). This is purely for rendering
/// the absent condition; it records no premise and contributes no height, so it
/// does not change the existing premise/height semantics.
#[derive(Debug, Clone)]
pub struct NegatedAtom {
    pub rel: String,
    pub arg_slots: Vec<Option<Slot>>,
}

/// A positive relation lookup in a rule body: an atom that must hold for the
/// rule to fire. The facts it matches are that derivation's *premises*, the
/// children `::why` shows under a derived fact. For
///
/// ```text
/// path(X, Z) :- path(X, Y), edge(Y, Z), !blocked(Z), :match_field(...).
/// ```
///
/// the premise atoms are `path(X, Y)` and `edge(Y, Z)`. Negated atoms like
/// `!blocked(Z)` are not premises (see [`NegatedAtom`]), and neither are
/// builtins, `let`s or comparisons: they filter rows or add computed columns,
/// but no fact is derived *from* them.
///
/// `arg_cols` maps the atom's argument positions (in relation-column order) to
/// their column index in the rule's final pre-`Insert` row. Because the builder
/// only ever *appends* columns before the final `Insert` (the sole reshaper is
/// `Step::Reduce`, which applies only to premise-less aggregate rules), these
/// indices stay valid all the way to the head projection — so
/// `build_rule` can reconstruct each premise tuple `Row(row[arg_cols])` at the
/// moment it emits the head.
#[derive(Debug, Clone)]
pub struct PremiseAtom {
    /// The relation the atom looks up, e.g. `"edge"`.
    pub rel: String,
    /// Where each argument sits in the rule's joined row. For the example
    /// above the row is `[X, Y, Z]`, so `path(X, Y)` is `[0, 1]` and
    /// `edge(Y, Z)` is `[1, 2]`.
    pub arg_cols: Vec<usize>,
}

/// The fully-lowered representation of one Mangle rule: a linear pipeline of
/// `Step`s ending in an `Insert`.  All `NameId`/`StringId` references have been
/// resolved to owned strings; all variables have been replaced by column indices.
#[derive(Debug, Clone)]
pub struct LoweredRule {
    /// A stable, compile-time-assigned identity for this rule, sourced from the
    /// rule's `InstId` in `build_strata`. Used by the lazy (Soufflé-style)
    /// provenance path to annotate each derived fact with "the rule that
    /// achieved its minimal-height derivation" and to look the rule back up at
    /// `::why` time for backward-chaining. Deterministic across runs.
    pub rule_id: u32,
    /// The name of the head (output) relation.
    pub head_rel: String,
    /// Ordered steps of the pipeline.
    pub steps: Vec<Step>,
    /// The positive body atoms, in body order — the premises whose heights
    /// feed lazy provenance annotations. Empty for unit rules and (by design,
    /// matching the interpreter) for aggregate rules.
    pub premise_atoms: Vec<PremiseAtom>,
    /// The negated body atoms, in body order. Consumed only by the lazy
    /// (Soufflé-style) provenance reconstruction, which surfaces each as a
    /// `¬rel(args)` absent-leaf in the proof. Does not affect `premise_atoms`
    /// or height. Empty unless the rule has `!rel(...)` atoms.
    pub negated_atoms: Vec<NegatedAtom>,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Lower a physical `Op` tree into a `LoweredRule`.
///
/// Call this while `Ir` is still alive (name/string resolution happens here).
/// The result is fully owned and `Send + Sync + 'static`.
pub fn lower_op(op: &Op, ir: &Ir, rule_id: u32) -> Result<LoweredRule> {
    let mut steps = Vec::new();
    let mut schema: Vec<String> = Vec::new();
    let mut head_rel = String::new();
    let mut premise_atoms = Vec::new();
    let mut negated_atoms = Vec::new();
    lower_inner(
        op,
        ir,
        &mut schema,
        &mut steps,
        &mut head_rel,
        &mut premise_atoms,
        &mut negated_atoms,
    )?;
    if head_rel.is_empty() {
        bail!("lowered rule produced no Insert step");
    }
    Ok(LoweredRule {
        rule_id,
        head_rel,
        steps,
        premise_atoms,
        negated_atoms,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn resolve_constant(c: &Constant, ir: &Ir) -> Val {
    match c {
        Constant::Number(n) => Val::Number(*n),
        Constant::Float(f) => Val::Float(OrdF64(*f)),
        Constant::String(sid) => Val::String(ir.resolve_string(*sid).into()),
        Constant::Name(nid) => Val::Name(ir.resolve_name(*nid).into()),
        Constant::Time(t) => Val::Time(*t),
        Constant::Duration(d) => Val::Duration(*d),
    }
}

fn resolve_operand(operand: &Operand, ir: &Ir, schema: &[String]) -> Result<Slot> {
    match operand {
        Operand::Var(name_id) => {
            let name = ir.resolve_name(*name_id);
            match schema.iter().position(|v| v == name) {
                Some(pos) => Ok(Slot::Col(pos)),
                None => bail!("variable `{}` not in schema {:?}", name, schema),
            }
        }
        Operand::Const(c) => Ok(Slot::Const(resolve_constant(c, ir))),
    }
}

/// Resolve a `DataSource` to `(rel_name, var_names)`.
///
/// Used only for HashJoin sources.  `DataSource` is a shared enum used in
/// both `Op::Iterate` and `Op::HashJoin`, but `try_plan_hash_join` always
/// constructs both sides as `DataSource::Scan` — it never emits `IndexLookup`
/// inside a `HashJoin`.  The `IndexLookup` arm is unreachable in practice;
/// `bail!` is a trip-wire in case the planner changes.
fn resolve_data_source(source: &DataSource, ir: &Ir) -> Result<(String, Vec<String>)> {
    match source {
        DataSource::Scan { relation, vars } | DataSource::ScanDelta { relation, vars } => {
            let rel = ir.resolve_name(*relation).to_string();
            let vars: Vec<_> = vars
                .iter()
                .map(|v| ir.resolve_name(*v).to_string())
                .collect();
            Ok((rel, vars))
        }
        DataSource::IndexLookup { .. } => {
            bail!("IndexLookup as a HashJoin source is not supported")
        }
    }
}

/// Emit join steps for a DataSource encountered while `schema` is non-empty.
fn emit_join(
    rel_name: String,
    vars: &[String],
    schema: &mut Vec<String>,
    steps: &mut Vec<Step>,
    premise_atoms: &mut Vec<PremiseAtom>,
) {
    let mut left_key_cols = Vec::new();
    let mut right_key_cols = Vec::new();
    let mut right_new_cols = Vec::new();
    // The final row column holding each of this atom's args, in relation order.
    let mut arg_cols = Vec::new();

    for (right_pos, var) in vars.iter().enumerate() {
        if let Some(left_pos) = schema.iter().position(|v| v == var) {
            left_key_cols.push(left_pos);
            right_key_cols.push(right_pos);
            arg_cols.push(left_pos);
        } else {
            right_new_cols.push(right_pos);
            arg_cols.push(schema.len());
            schema.push(var.clone());
        }
    }

    steps.push(Step::Join {
        rel: rel_name.clone(),
        left_key_cols,
        right_key_cols,
        right_new_cols,
    });
    premise_atoms.push(PremiseAtom {
        rel: rel_name,
        arg_cols,
    });
}

fn lower_aggregate(agg: &Aggregate, ir: &Ir, schema: &[String]) -> Result<LoweredAggregate> {
    let func = ir.resolve_name(agg.func).to_string();
    let arg_slot = match agg.args.first() {
        None => None,
        Some(Operand::Var(name_id)) => {
            let name = ir.resolve_name(*name_id);
            let col = schema.iter().position(|v| v == name).ok_or_else(|| {
                anyhow::anyhow!("aggregate arg `{name}` not in schema {schema:?}")
            })?;
            Some(Slot::Col(col))
        }
        Some(Operand::Const(c)) => Some(Slot::Const(resolve_constant(c, ir))),
    };
    Ok(LoweredAggregate { func, arg_slot })
}

/// Lower one filter condition into `steps`.
///
/// `negate` is set under `Condition::Not`. The planner only emits `Not` around
/// built-in checks (`Cmp` and `Call`) whose arguments are all bound, so the
/// negated form is still a plain row filter: comparisons flip their operator
/// (exact, since both `Val` and `Value` orderings are total) and calls carry a
/// `negate` flag evaluated at runtime.
fn lower_cond(
    cond: &Condition,
    negate: bool,
    ir: &Ir,
    schema: &[String],
    steps: &mut Vec<Step>,
    negated_atoms: &mut Vec<NegatedAtom>,
) -> Result<()> {
    match cond {
        Condition::Cmp { op, left, right } => {
            use mangle_ir::physical::CmpOp as MiCmpOp;
            let my_op = match (op, negate) {
                (MiCmpOp::Eq, false) | (MiCmpOp::Neq, true) => CmpOp::Eq,
                (MiCmpOp::Neq, false) | (MiCmpOp::Eq, true) => CmpOp::Neq,
                (MiCmpOp::Lt, false) | (MiCmpOp::Ge, true) => CmpOp::Lt,
                (MiCmpOp::Le, false) | (MiCmpOp::Gt, true) => CmpOp::Le,
                (MiCmpOp::Gt, false) | (MiCmpOp::Le, true) => CmpOp::Gt,
                (MiCmpOp::Ge, false) | (MiCmpOp::Lt, true) => CmpOp::Ge,
            };
            let left_slot = resolve_operand(left, ir, schema)?;
            let right_slot = resolve_operand(right, ir, schema)?;
            steps.push(Step::Cmp {
                op: my_op,
                left: left_slot,
                right: right_slot,
            });
        }
        Condition::Negation { .. } if negate => {
            // Double negation of a relation lookup is a semi-join; the planner
            // never emits it.
            bail!("negated relation negation is not supported by the DD backend: !{cond:?}")
        }
        Condition::Negation { relation, args } => {
            let rel_name = ir.resolve_name(*relation).to_string();
            let mut left_key_slots = Vec::new();
            let mut right_key_cols = Vec::new();
            let mut const_filters = Vec::new();
            // Full argument list (in relation-column order) for rendering
            // the `¬rel(args)` absent-leaf on the lazy provenance path.
            // `None` = anonymous/wildcard var, not addressable in the row.
            let mut render_slots: Vec<Option<Slot>> = Vec::new();

            for (right_col, arg) in args.iter().enumerate() {
                match arg {
                    Operand::Var(name_id) => {
                        let name = ir.resolve_name(*name_id);
                        if let Some(left_pos) = schema.iter().position(|v| v == name) {
                            // Shared variable: join on it.
                            left_key_slots.push(Slot::Col(left_pos));
                            right_key_cols.push(right_col);
                            render_slots.push(Some(Slot::Col(left_pos)));
                        } else {
                            // Anonymous/wildcard var (not in schema) → no
                            // constraint, not renderable from the row.
                            render_slots.push(None);
                        }
                    }
                    Operand::Const(c) => {
                        let val = resolve_constant(c, ir);
                        const_filters.push((right_col, val.clone()));
                        render_slots.push(Some(Slot::Const(val)));
                    }
                }
            }
            negated_atoms.push(NegatedAtom {
                rel: rel_name.clone(),
                arg_slots: render_slots,
            });
            steps.push(Step::Antijoin {
                rel: rel_name,
                left_key_slots,
                right_key_cols,
                const_filters,
            });
        }
        Condition::Call { function, args } => {
            let func_name = ir.resolve_name(*function).to_string();
            let arg_slots: Result<Vec<_>> = args
                .iter()
                .map(|a| resolve_operand(a, ir, schema))
                .collect();
            steps.push(Step::CallFilter {
                func: func_name,
                args: arg_slots?,
                negate,
            });
        }
        Condition::Not(inner) => lower_cond(inner, !negate, ir, schema, steps, negated_atoms)?,
    }
    Ok(())
}

fn lower_inner(
    op: &Op,
    ir: &Ir,
    schema: &mut Vec<String>,
    steps: &mut Vec<Step>,
    head_rel: &mut String,
    premise_atoms: &mut Vec<PremiseAtom>,
    negated_atoms: &mut Vec<NegatedAtom>,
) -> Result<()> {
    match op {
        Op::Iterate { source, body } => {
            match source {
                DataSource::Scan { relation, vars } | DataSource::ScanDelta { relation, vars } => {
                    // ScanDelta is lowered as Scan — DD's iterate operator handles
                    // the delta bookkeeping internally when we use Variable in Phase 3.
                    let rel_name = ir.resolve_name(*relation).to_string();
                    let var_names: Vec<_> = vars
                        .iter()
                        .map(|v| ir.resolve_name(*v).to_string())
                        .collect();

                    if schema.is_empty() {
                        schema.extend(var_names);
                        steps.push(Step::Scan {
                            rel: rel_name.clone(),
                        });
                        premise_atoms.push(PremiseAtom {
                            rel: rel_name,
                            arg_cols: (0..schema.len()).collect(),
                        });
                    } else {
                        emit_join(rel_name, &var_names, schema, steps, premise_atoms);
                    }

                    lower_inner(
                        body,
                        ir,
                        schema,
                        steps,
                        head_rel,
                        premise_atoms,
                        negated_atoms,
                    )
                }

                DataSource::IndexLookup {
                    relation,
                    col_idx,
                    key,
                    vars,
                } => {
                    // The planner emits an indexed join: `relation` looked up with
                    // `col_idx` keyed on `key`, naming the looked-up columns as fresh
                    // vars ($scan_N) and expressing the key equality as a *separate*
                    // downstream Filter (`Compare $scan_N = key`).
                    //
                    // Lower it as a real keyed Join, NOT a cross product: key the
                    // current schema column holding `key` against `relation`'s
                    // `col_idx` column. Append ALL of `relation`'s columns (including
                    // col_idx) so the output schema is byte-identical to the old
                    // plain-join path — that keeps the $scan_N column present for the
                    // planner's follow-up Filter, which then holds trivially (a no-op
                    // on already-equal rows). Any *other* shared columns are still
                    // enforced by their own downstream Filters, exactly as before.
                    let rel = ir.resolve_name(*relation).to_string();
                    let var_names: Vec<String> = vars
                        .iter()
                        .map(|v| ir.resolve_name(*v).to_string())
                        .collect();

                    // Column position of the key variable in the current schema, if
                    // `key` is a Var already bound. `None` for a constant key or an
                    // as-yet-unbound var.
                    let key_pos = match key {
                        Operand::Var(name_id) => {
                            let name = ir.resolve_name(*name_id);
                            schema.iter().position(|v| v == name)
                        }
                        Operand::Const(_) => None,
                    };

                    if schema.is_empty() {
                        // First atom of the body: seed with a plain scan.
                        schema.extend(var_names);
                        steps.push(Step::Scan { rel: rel.clone() });
                        premise_atoms.push(PremiseAtom {
                            rel,
                            arg_cols: (0..schema.len()).collect(),
                        });
                    } else if let Some(kpos) = key_pos {
                        // Keyed (indexed) join on `key == relation[col_idx]`.
                        let base = schema.len();
                        let arity = var_names.len();
                        schema.extend(var_names);
                        premise_atoms.push(PremiseAtom {
                            rel: rel.clone(),
                            arg_cols: (base..base + arity).collect(),
                        });
                        steps.push(Step::Join {
                            rel,
                            left_key_cols: vec![kpos],
                            right_key_cols: vec![*col_idx],
                            // Append every column (col_idx included) so the schema —
                            // and the planner's redundant equality Filter — is unchanged.
                            right_new_cols: (0..arity).collect(),
                        });
                    } else {
                        // Constant key, or key var not yet in schema: fall back to a
                        // shared-var join; the downstream Filter enforces the key.
                        // Uncommon in practice.
                        emit_join(rel, &var_names, schema, steps, premise_atoms);
                    }

                    lower_inner(
                        body,
                        ir,
                        schema,
                        steps,
                        head_rel,
                        premise_atoms,
                        negated_atoms,
                    )
                }
            }
        }

        Op::Filter { cond, body } => {
            lower_cond(cond, false, ir, schema, steps, negated_atoms)?;
            lower_inner(
                body,
                ir,
                schema,
                steps,
                head_rel,
                premise_atoms,
                negated_atoms,
            )
        }

        Op::Let { var, expr, body } => {
            let owned_expr = match expr {
                Expr::Value(operand) => OwnedExpr::Value(resolve_operand(operand, ir, schema)?),
                Expr::Call { function, args } => {
                    let func_name = ir.resolve_name(*function).to_string();
                    let slots: Result<Vec<_>> = args
                        .iter()
                        .map(|a| resolve_operand(a, ir, schema))
                        .collect();
                    OwnedExpr::Call {
                        func: func_name,
                        args: slots?,
                    }
                }
            };
            schema.push(ir.resolve_name(*var).to_string());
            steps.push(Step::Let { expr: owned_expr });
            lower_inner(
                body,
                ir,
                schema,
                steps,
                head_rel,
                premise_atoms,
                negated_atoms,
            )
        }

        Op::MatchField {
            struct_op,
            field,
            var,
            body,
        } => {
            let struct_slot = resolve_operand(struct_op, ir, schema)?;
            let field_name = ir.resolve_name(*field).to_string();
            schema.push(ir.resolve_name(*var).to_string());
            steps.push(Step::MatchField {
                struct_slot,
                field: field_name,
            });
            lower_inner(
                body,
                ir,
                schema,
                steps,
                head_rel,
                premise_atoms,
                negated_atoms,
            )
        }

        Op::IterateList { source, var, body } => {
            let source_slot = resolve_operand(source, ir, schema)?;
            schema.push(ir.resolve_name(*var).to_string());
            steps.push(Step::IterateList { source_slot });
            lower_inner(
                body,
                ir,
                schema,
                steps,
                head_rel,
                premise_atoms,
                negated_atoms,
            )
        }

        Op::Insert { relation, args } => {
            // If nothing has been scanned yet (schema empty), this is a unit rule
            // (no body, just constant-valued head).  Emit a Unit step first so
            // build_rule has something to map over.
            if schema.is_empty() {
                steps.push(Step::Unit);
            }
            let rel_name = ir.resolve_name(*relation).to_string();
            let proj: Result<Vec<_>> = args
                .iter()
                .map(|a| resolve_operand(a, ir, schema))
                .collect();
            *head_rel = rel_name;
            steps.push(Step::Insert { proj: proj? });
            Ok(())
        }

        Op::Nop => Ok(()),

        Op::Seq(ops) => {
            // Each sub-op in a Seq is an independent pipeline (typically the
            // planner emits Seq only for aggregation rules):
            //
            //   op[0]: scan premises, insert into $temp_grp_N  (materialise)
            //   op[1]: GroupBy { source: $temp_grp_N, ... }    (aggregate)
            //
            // In DD we don't need an intermediate relation — we inline op[0]'s
            // pipeline directly as the source for op[1], replacing op[1]'s
            // opening Scan{$temp_grp_N} with op[0]'s accumulated steps.
            //
            // Each sub-op is lowered with a fresh schema so they don't
            // cross-contaminate.  After inlining, the combined steps form a
            // single pipeline: premises → (Insert acting as projection) →
            // Reduce → Insert{final_head}.

            let mut active_steps: Vec<Step> = Vec::new();
            let mut active_head: String = String::new();

            for op in ops {
                let mut sub_schema: Vec<String> = Vec::new();
                let mut sub_steps: Vec<Step> = Vec::new();
                let mut sub_head: String = String::new();
                // Seq is only emitted for aggregation, whose derived facts carry
                // empty premises (interpreter parity). Lower each sub-op with a
                // throwaway premise vec so the rule's premise_atoms stays empty.
                let mut sub_premises: Vec<PremiseAtom> = Vec::new();
                let mut sub_negated: Vec<NegatedAtom> = Vec::new();
                lower_inner(
                    op,
                    ir,
                    &mut sub_schema,
                    &mut sub_steps,
                    &mut sub_head,
                    &mut sub_premises,
                    &mut sub_negated,
                )?;

                if active_steps.is_empty() {
                    // First sub-op: take its steps as-is.
                    active_steps = sub_steps;
                    active_head = sub_head;
                } else {
                    // Subsequent sub-op must start with Scan{prev_head} — that's
                    // the temp-relation read we're inlining away.  If the planner
                    // ever emits a different Seq shape (e.g. a future optimisation),
                    // we want a loud failure rather than silently wrong results.
                    match sub_steps.first() {
                        Some(Step::Scan { rel, .. }) if rel == &active_head => {
                            active_steps.extend(sub_steps.into_iter().skip(1));
                            active_head = sub_head;
                        }
                        other => bail!(
                            "Op::Seq: expected Scan{{{active_head}}} as first step of sub-op, \
                             got {other:?}"
                        ),
                    }
                }
            }

            *schema = Vec::new(); // schema is owned by sub-ops; caller sees empty
            steps.extend(active_steps);
            *head_rel = active_head;
            Ok(())
        }

        // -----------------------------------------------------------------------
        // HashJoin — a planner optimisation for 2-way equijoins (MANGLE_HASHJOIN=1).
        // Semantically identical to nested-loop join; lower as Scan + Join.
        // -----------------------------------------------------------------------
        Op::HashJoin {
            build_source,
            probe_source,
            join_keys: _,
            body,
        } => {
            let (build_rel, build_vars) = resolve_data_source(build_source, ir)?;
            let (probe_rel, probe_vars) = resolve_data_source(probe_source, ir)?;

            // Seed from the build side.
            schema.extend(build_vars.clone());
            steps.push(Step::Scan {
                rel: build_rel.clone(),
            });
            premise_atoms.push(PremiseAtom {
                rel: build_rel,
                arg_cols: (0..build_vars.len()).collect(),
            });

            // Join on the probe side — shared vars become keys automatically.
            emit_join(probe_rel, &probe_vars, schema, steps, premise_atoms);

            lower_inner(
                body,
                ir,
                schema,
                steps,
                head_rel,
                premise_atoms,
                negated_atoms,
            )
        }

        // -----------------------------------------------------------------------
        // GroupBy — aggregation: group by keys, compute aggregates, continue body.
        // -----------------------------------------------------------------------
        Op::GroupBy {
            source,
            vars,
            keys,
            aggregates,
            body,
        } => {
            // Resolve the source relation and seed the schema.
            let src_rel = ir.resolve_name(*source).to_string();
            let var_names: Vec<String> = vars
                .iter()
                .map(|v| ir.resolve_name(*v).to_string())
                .collect();
            schema.extend(var_names.clone());
            steps.push(Step::Scan { rel: src_rel });

            // Resolve group-by key positions within the source schema.
            let key_cols: Vec<usize> = keys
                .iter()
                .map(|k| {
                    let name = ir.resolve_name(*k);
                    schema
                        .iter()
                        .position(|v| v == name)
                        .ok_or_else(|| anyhow::anyhow!("GroupBy key `{name}` not in schema"))
                })
                .collect::<Result<_>>()?;

            // Lower each aggregate.
            let lowered_aggs: Vec<LoweredAggregate> = aggregates
                .iter()
                .map(|agg| lower_aggregate(agg, ir, schema))
                .collect::<Result<_>>()?;

            // Emit the Reduce step.
            steps.push(Step::Reduce {
                key_cols: key_cols.clone(),
                aggregates: lowered_aggs,
            });
            // Aggregate facts carry empty premises (interpreter parity): the
            // GroupBy source scan above is a reshaped, not a body-atom, read.
            premise_atoms.clear();

            // Rewrite schema: key columns first, then one column per aggregate result.
            // The body's Insert/Cmp steps will resolve against this new schema.
            let mut new_schema: Vec<String> = key_cols.iter().map(|&i| schema[i].clone()).collect();
            for agg in aggregates {
                new_schema.push(ir.resolve_name(agg.var).to_string());
            }
            *schema = new_schema;

            lower_inner(
                body,
                ir,
                schema,
                steps,
                head_rel,
                premise_atoms,
                negated_atoms,
            )
        }
    }
}
