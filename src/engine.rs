// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::{Context, Result};
use mangle_ast::Arena;
use mangle_common::{Store, Value};
use mangle_driver::compile_units;
use mangle_interpreter::{Interpreter, MemStore, ProvenanceEntry};
use mangle_ir::physical::{Condition, Constant, DataSource, Op, Operand};
use mangle_ir::{Inst, InstId, Ir, NameId};

use crate::edb::{Fact, ObjectFacts, ObjectKey};

pub(crate) const EDB_DECLS: &str = include_str!("../rules/00_edb_prelude.mg");

/// Snapshot of all derived facts after an evaluation pass.
#[derive(Clone)]
pub struct EvalStore {
    facts: HashMap<String, Vec<Vec<Value>>>,
    pub provenance: Vec<ProvenanceEntry>,
}

/// True for relations a frozen state (`\snapshot`) or a `Diff` should not
/// see: the interpreter's GroupBy scratch space (`$temp_grp_0`; the DD
/// backend has none) and a `?-` query's result relation (`_0`, `_1`, ...).
pub(crate) fn is_scratch_relation(name: &str) -> bool {
    name.starts_with('$')
        || name
            .strip_prefix('_')
            .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
}

impl EvalStore {
    pub fn scan(&self, relation: &str) -> &[Vec<Value>] {
        self.facts
            .get(relation)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    pub fn relation_names(&self) -> impl Iterator<Item = &str> {
        self.facts.keys().map(String::as_str)
    }

    /// Build an `EvalStore` directly from already-evaluated facts, with no
    /// provenance. Used to freeze a snapshot's facts and, in tests, to build
    /// an `EvalStore` without running the engine.
    pub fn from_facts(facts: HashMap<String, Vec<Vec<Value>>>) -> EvalStore {
        EvalStore {
            facts,
            provenance: Vec::new(),
        }
    }

    /// Clone this eval state, leaving out scratch relations (see
    /// `is_scratch_relation`). `\snapshot` freezes a copy this way: later
    /// mutations to the live engine state must not change it, and the copy
    /// must not include query results or interpreter temporaries.
    pub fn frozen_copy(&self) -> EvalStore {
        let facts = self
            .facts
            .iter()
            .filter(|(name, _)| !is_scratch_relation(name))
            .map(|(name, tuples)| (name.clone(), tuples.clone()))
            .collect();
        let provenance = self
            .provenance
            .iter()
            .filter(|entry| !is_scratch_relation(&entry.derived.0))
            .cloned()
            .collect();
        EvalStore { facts, provenance }
    }
}

/// Documentation for a single relation column, derived from a `Decl`'s head
/// argument names, `bound [...]` types, and `arg(Col, "...")` descr atoms.
#[derive(Debug, Default, Clone)]
pub struct ColumnDoc {
    pub name: String,
    pub ty: Option<String>,
    pub description: Option<String>,
}

/// Documentation for a relation, derived from its `Decl`. `description` comes
/// from a `doc("...")` descr atom; `columns` is positional.
#[derive(Debug, Default, Clone)]
pub struct RelationDoc {
    pub description: Option<String>,
    pub columns: Vec<ColumnDoc>,
}

pub struct CompiledProgram {
    ir: Ir,
    strata: Vec<HashSet<&'static str>>, // static lifetime because of global interner in Arena
}

impl CompiledProgram {
    pub fn new(sources: &[&str]) -> Result<Self> {
        let arena = Arena::new_with_global_interner();
        let (ir, stratified) = compile_units(sources, &arena).context("compile rules")?;

        let mut strata = Vec::new();
        for stratum in stratified.strata() {
            let pred_names: HashSet<&'static str> = stratum
                .iter()
                .filter_map(|pred| arena.predicate_name(*pred))
                .collect();
            strata.push(pred_names);
        }

        Ok(Self { ir, strata })
    }

    /// Every relation the compiled program declares or defines by a rule/fact.
    pub fn defined_relations(&self) -> std::collections::HashSet<String> {
        let mut out = std::collections::HashSet::new();
        for inst in &self.ir.insts {
            let atom = match inst {
                Inst::Decl { atom, .. } => *atom,
                Inst::Rule { head, .. } => *head,
                _ => continue,
            };
            if let Inst::Atom { predicate, .. } = self.ir.get(atom) {
                out.insert(self.ir.resolve_name(*predicate).to_string());
            }
        }
        out
    }

    /// Extract per-relation documentation from the compiled `Decl`s in the IR:
    /// column names (from the decl head), types (from `bound [...]`), the
    /// relation description (from a `doc("...")` descr atom), and per-column
    /// descriptions (from `arg(Col, "...")` descr atoms).
    pub fn relation_docs(&self) -> HashMap<String, RelationDoc> {
        let mut docs = HashMap::new();
        for inst in &self.ir.insts {
            let Inst::Decl {
                atom,
                descr,
                bounds,
                ..
            } = inst
            else {
                continue;
            };
            let Inst::Atom { predicate, args } = self.ir.get(*atom) else {
                continue;
            };
            let rel_name = self.ir.resolve_name(*predicate).to_string();

            // Column names from the decl head arguments.
            let mut columns: Vec<ColumnDoc> = args
                .iter()
                .map(|a| ColumnDoc {
                    name: match self.ir.get(*a) {
                        Inst::Var(n) => self.ir.resolve_name(*n).to_string(),
                        other => format!("{other:?}"),
                    },
                    ..Default::default()
                })
                .collect();

            // Types from the first bound decl, applied positionally.
            if let Some(first) = bounds.first()
                && let Inst::BoundDecl { base_terms } = self.ir.get(*first)
            {
                for (col, term) in columns.iter_mut().zip(base_terms.iter()) {
                    col.ty = Some(self.format_type(*term));
                }
            }

            // Descriptions from descr atoms: doc(...) for the relation,
            // arg(Col, "...") for individual columns.
            let mut description = None;
            for d in descr {
                let Inst::Atom { predicate, args } = self.ir.get(*d) else {
                    continue;
                };
                match self.ir.resolve_name(*predicate) {
                    "doc" => {
                        if let Some(text) = args.first().and_then(|a| self.string_of(*a)) {
                            description = Some(text);
                        }
                    }
                    "arg" => {
                        if let (Some(col_name), Some(text)) = (
                            args.first().and_then(|a| self.var_name_of(*a)),
                            args.get(1).and_then(|a| self.string_of(*a)),
                        ) && let Some(col) = columns.iter_mut().find(|c| c.name == col_name)
                        {
                            col.description = Some(text);
                        }
                    }
                    _ => {}
                }
            }

            docs.insert(
                rel_name,
                RelationDoc {
                    description,
                    columns,
                },
            );
        }
        docs
    }

    /// Resolve a string literal instruction to its value, if it is one.
    fn string_of(&self, id: InstId) -> Option<String> {
        match self.ir.get(id) {
            Inst::String(s) => Some(self.ir.resolve_string(*s).to_string()),
            _ => None,
        }
    }

    /// Resolve a variable instruction to its name, if it is one.
    fn var_name_of(&self, id: InstId) -> Option<String> {
        match self.ir.get(id) {
            Inst::Var(n) => Some(self.ir.resolve_name(*n).to_string()),
            _ => None,
        }
    }

    /// Render a type bound term: a plain name like `/string`, or a composite
    /// like `fn:List<...>` rendered with its applied arguments.
    fn format_type(&self, id: InstId) -> String {
        match self.ir.get(id) {
            Inst::Name(n) => self.ir.resolve_name(*n).to_string(),
            Inst::ApplyFn { function, args } => {
                let inner: Vec<String> = args.iter().map(|a| self.format_type(*a)).collect();
                format!("{}<{}>", self.ir.resolve_name(*function), inner.join(", "))
            }
            other => format!("{other:?}"),
        }
    }

    fn format_slice_name_ids(&self, vars: &[NameId]) -> String {
        format!(
            "[{}]",
            vars.iter()
                .map(|v| self.ir.resolve_name(*v))
                .map(|v| { if v.starts_with("_Anon") { "_" } else { v } })
                .collect::<Vec<_>>()
                .join(", ")
        )
    }

    fn format_operand(&self, key: &Operand) -> String {
        match key {
            Operand::Var(v) => self.ir.resolve_name(*v).to_string(),
            Operand::Const(c) => match c {
                Constant::String(id) => format!("\"{}\"", self.ir.resolve_string(*id)),
                Constant::Name(id) => self.ir.resolve_name(*id).to_string(),
                Constant::Number(num) => format!("{}", num),
                Constant::Float(num) => format!("{}", num),
                Constant::Time(nanos) => format!("{}", nanos),
                Constant::Duration(nanos) => format!("{}", nanos),
            },
        }
    }

    fn fprint_op(&self, w: &mut impl std::io::Write, op: &Op, level: usize) -> Result<()> {
        let (node_prefix, prop_prefix) = if level > 0 {
            let indent = 2 + (level - 1) * 6;
            (
                format!("{:indent$}->  ", "", indent = indent),
                format!("{:indent$}", "", indent = indent + 6),
            )
        } else {
            // root of the tree
            (String::from(""), String::from("  "))
        };

        match op {
            Op::Iterate { source, body } => {
                write!(w, "{}Iterate on ", node_prefix)?;

                match source {
                    DataSource::Scan { relation, vars } => {
                        writeln!(w, "{}", self.ir.resolve_name(*relation))?;
                        writeln!(
                            w,
                            "{}Scan {}",
                            prop_prefix,
                            self.format_slice_name_ids(vars)
                        )?;
                    }
                    DataSource::ScanDelta { relation, vars } => {
                        writeln!(w, "{}", self.ir.resolve_name(*relation))?;
                        writeln!(
                            w,
                            "{}DeltaScan {}",
                            prop_prefix,
                            self.format_slice_name_ids(vars)
                        )?;
                    }
                    DataSource::IndexLookup {
                        relation,
                        key,
                        vars,
                        ..
                    } => {
                        writeln!(w, "{}", self.ir.resolve_name(*relation))?;
                        writeln!(
                            w,
                            "{}IndexLookup {}",
                            prop_prefix,
                            self.format_slice_name_ids(vars)
                        )?;
                        writeln!(w, "{}Key on {}", prop_prefix, self.format_operand(key))?;
                    }
                }

                self.fprint_op(w, body, level + 1)
            }
            Op::Filter { cond, body } => {
                writeln!(w, "{}Filter", node_prefix)?;

                match cond {
                    Condition::Cmp { op, left, right } => {
                        writeln!(
                            w,
                            "{}Compare: {} {} {}",
                            prop_prefix,
                            self.format_operand(left),
                            match op {
                                mangle_ir::physical::CmpOp::Eq => "=",
                                mangle_ir::physical::CmpOp::Neq => "!=",
                                mangle_ir::physical::CmpOp::Lt => "<",
                                mangle_ir::physical::CmpOp::Le => "<=",
                                mangle_ir::physical::CmpOp::Gt => ">",
                                mangle_ir::physical::CmpOp::Ge => ">=",
                            },
                            self.format_operand(right)
                        )?;
                    }
                    Condition::Negation { relation, args } => {
                        writeln!(
                            w,
                            "{}Negation: !{}({})",
                            prop_prefix,
                            self.ir.resolve_name(*relation),
                            args.iter()
                                .map(|arg| self.format_operand(arg))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )?;
                    }
                    Condition::Call { function, args } => {
                        writeln!(
                            w,
                            "{}Call(todo) {}{:?}",
                            prop_prefix,
                            self.ir.resolve_name(*function),
                            args,
                        )?;
                    }
                    Condition::Not(inner) => {
                        writeln!(w, "{}Not {:?}", prop_prefix, inner)?;
                    }
                }

                self.fprint_op(w, body, level + 1)
            }
            Op::Insert { relation, args } => Ok(writeln!(
                w,
                "{}Insert `{}` [{}]",
                node_prefix,
                self.ir.resolve_name(*relation),
                args.iter()
                    .map(|arg| self.format_operand(arg))
                    .collect::<Vec<_>>()
                    .join(", ")
            )?),
            Op::MatchField {
                struct_op,
                field,
                var,
                body,
            } => {
                writeln!(
                    w,
                    "{}MatchField {} #> {} as {}",
                    node_prefix,
                    self.format_operand(struct_op),
                    self.ir.resolve_name(*field),
                    self.ir.resolve_name(*var)
                )?;

                self.fprint_op(w, body, level + 1)
            }
            Op::IterateList { source, var, body } => {
                writeln!(
                    w,
                    "{}IterateList {} #> {}",
                    node_prefix,
                    self.format_operand(source),
                    self.ir.resolve_name(*var)
                )?;

                self.fprint_op(w, body, level + 1)
            }
            _ => Ok(write!(w, "{}(unimplemented: {:?})", node_prefix, op)?),
        }
    }

    fn print_op(&self, op: &Op, level: usize) -> Result<()> {
        self.fprint_op(&mut std::io::stdout(), op, level)
    }

    pub fn dump_plan(&mut self) -> Result<()> {
        for (i, pred_names) in self.strata.iter().enumerate() {
            println!(
                "● Stratum {i} ({})",
                pred_names
                    .iter()
                    .map(|s| format!("`{}`", s))
                    .collect::<Vec<_>>()
                    .join(", ")
            );

            // Step B: collect rule_ids — must finish before calling Planner (&mut ir)
            let mut initial_ids: Vec<InstId> = vec![];
            let mut delta_ids: Vec<(InstId, NameId)> = vec![];

            for (idx, inst) in self.ir.insts.iter().enumerate() {
                if let mangle_ir::Inst::Rule { head, premises, .. } = inst
                    && let mangle_ir::Inst::Atom { predicate, .. } = self.ir.get(*head)
                {
                    let name = self.ir.resolve_name(*predicate);

                    if !pred_names.contains(name) {
                        continue;
                    }
                    initial_ids.push(mangle_ir::InstId::new(idx));

                    // For each recursive premise, add a delta plan entry for semi-naive evaluation.
                    for p in premises {
                        if let mangle_ir::Inst::Atom {
                            predicate: pname, ..
                        } = self.ir.get(*p)
                            && pred_names.contains(self.ir.resolve_name(*pname))
                        {
                            delta_ids.push((mangle_ir::InstId::new(idx), *pname));
                        }
                    }
                }
            }

            if initial_ids.is_empty() {
                continue;
            }

            // Step C: plan each rule and print the physical Op tree
            for rule_id in initial_ids {
                let planner = mangle_analysis::Planner::new(&mut self.ir);
                let op = planner.plan_rule(rule_id)?;
                self.print_op(&op, 1)?;
            }

            if !delta_ids.is_empty() {
                println!("↻ Recursive");
                for (rule_id, pred) in delta_ids {
                    let planner = mangle_analysis::Planner::new(&mut self.ir).with_delta(pred);
                    let op = planner.plan_rule(rule_id)?;
                    self.print_op(&op, 1)?;
                }
            }

            println!();
        }

        Ok(())
    }
}

pub trait Backend {
    fn evaluate(&self, edb: &[(String, Vec<Value>)], rule_sources: &[String]) -> Result<EvalStore>;

    /// Whether `::why` can explain facts with this backend. The interpreter
    /// fills `EvalStore::provenance`; the DD backend with `provenance` on
    /// answers through the live session instead (`Engine::provenance_session`).
    /// When false, `::why` must refuse rather than silently print nothing.
    fn supports_provenance(&self) -> bool {
        false
    }

    /// Start a persistent incremental session seeded with `edb` + `rule_sources`,
    /// if this backend has one. `Engine` owns it and keeps it in sync with every
    /// mutation; the default (interpreter) has none and recomputes on demand.
    fn spawn_session(
        &self,
        _edb: &[(String, Vec<Value>)],
        _rule_sources: &[String],
    ) -> Result<Option<crate::dd::session::DdSession>> {
        Ok(None)
    }
}

/// The differential-dataflow backend.
///
/// `provenance` builds lazy `(rule_id, min_height)` provenance annotations
/// in the live session so `::why` can backward-chain a proof on demand; it is
/// off by default because the annotations add operators to every rule.
pub struct DdBackend {
    pub provenance: bool,
}

impl Backend for DdBackend {
    fn supports_provenance(&self) -> bool {
        self.provenance
    }

    fn spawn_session(
        &self,
        edb: &[(String, Vec<Value>)],
        rule_sources: &[String],
    ) -> Result<Option<crate::dd::session::DdSession>> {
        // `::why` queries this live session (see `Engine::provenance_session`).
        crate::dd::session::DdSession::spawn_with_provenance(edb, rule_sources, self.provenance)
            .map(Some)
    }

    fn evaluate(&self, edb: &[(String, Vec<Value>)], rule_sources: &[String]) -> Result<EvalStore> {
        // Batch mode = spawn a persistent session, snapshot every relation, drop.
        // spawn() blocks until the worker is settled at epoch 1, so snapshot_all()
        // sees fully-derived state.  Dropping the session shuts the worker down.
        // Lazy provenance lives in a live session (see `spawn_session`), not in
        // a snapshot, so this throwaway session never builds annotations and
        // `EvalStore::provenance` stays empty.
        let session =
            crate::dd::session::DdSession::spawn(edb, rule_sources).context("spawn dd session")?;
        let facts = session.snapshot_all()?;
        Ok(EvalStore {
            facts,
            provenance: vec![],
        })
    }
}

pub struct InterpreterBackend;

impl Backend for InterpreterBackend {
    fn supports_provenance(&self) -> bool {
        true
    }

    fn evaluate(&self, edb: &[(String, Vec<Value>)], rule_sources: &[String]) -> Result<EvalStore> {
        let mut sources: Vec<&str> = vec![EDB_DECLS];
        for s in rule_sources {
            sources.push(s);
        }

        let arena = Arena::new_with_global_interner();
        let (mut ir, stratified) = compile_units(&sources, &arena).context("compile rules")?;

        let mut store = MemStore::new();
        for (rel, tuple) in edb {
            store.add_fact(rel, tuple.clone());
        }

        let interpreter = execute_with_provenance(&mut ir, &stratified, Box::new(store))?;
        let (store_box, prov) = interpreter.into_parts();
        let store_ref = &*store_box;

        let mut facts: HashMap<String, Vec<Vec<Value>>> = HashMap::new();
        for rel in store_ref.relation_names() {
            let rows = store_ref
                .scan(&rel)
                .with_context(|| format!("scan {rel}"))?
                .collect::<Vec<_>>();
            facts.insert(rel, rows);
        }

        let provenance = prov.map(|p| p.entries).unwrap_or_default();
        Ok(EvalStore { facts, provenance })
    }
}

/// Replicated from mangle-driver's `execute()`, with provenance enabled.
fn execute_with_provenance<'a>(
    ir: &'a mut Ir,
    stratified: &mangle_analysis::StratifiedProgram<'a>,
    store: Box<dyn Store + 'a>,
) -> Result<Interpreter<'a>> {
    let arena = stratified.arena();

    // Phase 1: pre-plan all strata (requires mutable IR access).
    enum StratumPlan {
        NonRecursive(Vec<Op>),
        Recursive {
            initial_ops: Vec<Op>,
            delta_plans: Vec<Op>,
        },
    }

    let mut strata_plans: Vec<Option<StratumPlan>> = Vec::new();

    for stratum in stratified.strata() {
        let mut stratum_pred_names: HashSet<String> = HashSet::new();
        for pred in &stratum {
            if let Some(name) = arena.predicate_name(*pred) {
                stratum_pred_names.insert(name.to_string());
            }
        }

        let mut rule_ids: Vec<InstId> = Vec::new();
        for (i, inst) in ir.insts.iter().enumerate() {
            if let Inst::Rule { head, .. } = inst
                && let Inst::Atom { predicate, .. } = ir.get(*head)
                && stratum_pred_names.contains(ir.resolve_name(*predicate))
            {
                rule_ids.push(InstId::new(i));
            }
        }

        if rule_ids.is_empty() {
            strata_plans.push(None);
            continue;
        }

        let mut is_recursive = false;
        'outer: for &rule_id in &rule_ids {
            if let Inst::Rule { premises, .. } = ir.get(rule_id) {
                for &premise in premises {
                    if let Inst::Atom { predicate, .. } = ir.get(premise)
                        && stratum_pred_names.contains(ir.resolve_name(*predicate))
                    {
                        is_recursive = true;
                        break 'outer;
                    }
                }
            }
        }

        if !is_recursive {
            let mut ops = Vec::new();
            for rule_id in rule_ids {
                let planner = mangle_analysis::Planner::new(ir);
                ops.push(planner.plan_rule(rule_id)?);
            }
            strata_plans.push(Some(StratumPlan::NonRecursive(ops)));
        } else {
            let mut initial_ops = Vec::new();
            for &rule_id in &rule_ids {
                let planner = mangle_analysis::Planner::new(ir);
                initial_ops.push(planner.plan_rule(rule_id)?);
            }

            let mut delta_plans = Vec::new();
            for &rule_id in &rule_ids {
                let premises = if let Inst::Rule { premises, .. } = ir.get(rule_id) {
                    premises.clone()
                } else {
                    continue;
                };
                for &premise in &premises {
                    if let Inst::Atom { predicate, .. } = ir.get(premise) {
                        let pred_name = ir.resolve_name(*predicate).to_string();
                        if stratum_pred_names.contains(&pred_name) {
                            let predicate = *predicate;
                            let planner = mangle_analysis::Planner::new(ir).with_delta(predicate);
                            delta_plans.push(planner.plan_rule(rule_id)?);
                        }
                    }
                }
            }
            strata_plans.push(Some(StratumPlan::Recursive {
                initial_ops,
                delta_plans,
            }));
        }
    }

    let temporal_pred_names: Vec<String> = ir
        .temporal_predicates
        .iter()
        .map(|name_id| ir.resolve_name(*name_id).to_string())
        .collect();

    // Phase 2: execute with provenance enabled.
    let mut interpreter = Interpreter::new(ir, store).with_provenance();

    for pred in stratified.extensional_preds() {
        if let Some(name) = arena.predicate_name(pred) {
            interpreter.store_mut().create_relation(name);
        }
    }

    for plan in strata_plans {
        match plan {
            Some(StratumPlan::NonRecursive(ops)) => {
                for op in ops {
                    interpreter.execute(&op)?;
                }
            }
            Some(StratumPlan::Recursive {
                initial_ops,
                delta_plans,
            }) => {
                for op in initial_ops {
                    interpreter.execute(&op)?;
                }
                interpreter.store_mut().merge_deltas();
                loop {
                    let mut changes = 0;
                    for op in &delta_plans {
                        changes += interpreter.execute(op)?;
                    }
                    if changes == 0 {
                        break;
                    }
                    interpreter.store_mut().merge_deltas();
                }
                for name in &temporal_pred_names {
                    interpreter.store_mut().coalesce_temporal(name);
                }
            }
            None => {}
        }
        interpreter.store_mut().merge_deltas();
        for name in &temporal_pred_names {
            interpreter.store_mut().coalesce_temporal(name);
        }
    }

    Ok(interpreter)
}

/// One change to apply to the live EDB. Add and update are the same engine
/// operation (retract the old facts for the key if present, insert the new
/// ones), so both are an [`Change::Upsert`]; the summary tells them apart by
/// whether the key already existed. [`Change::Retract`] drops the object
/// loaded under a key, used when a delta removes it.
pub enum Change {
    Upsert(ObjectFacts),
    Retract(ObjectKey),
}

/// What [`Engine::apply_changes`] did, by outcome. `added` and `updated`
/// count [`Change::Upsert`]s whose key was absent or already present;
/// `retracted` counts [`Change::Retract`]s that hit a loaded object, and
/// `removed_absent` the ones whose key was already gone (not an error: the
/// cluster may have dropped it before the delta did).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ApplySummary {
    pub added: usize,
    pub updated: usize,
    pub retracted: usize,
    pub removed_absent: usize,
}

/// A copy of what the engine evaluates: the facts loaded from the cluster
/// or added since (EDB), and the rule sources, `\define` rules included.
/// `\snapshot` saves one so `\rollback` can put it back. The rules behind
/// `?-` results (`_N`) are left out: those results belong to the REPL
/// session, not to the state a snapshot saves. The duplicate index is left
/// out too; [`Engine::restore_inputs`] rebuilds it.
#[derive(Clone)]
pub struct EngineInputs {
    edb: Vec<(String, Vec<Value>)>,
    rule_sources: Vec<String>,
}

pub struct Engine {
    /// EDB facts collected at load time; replayed on each evaluate.
    edb: Vec<(String, Vec<Value>)>,
    /// The same facts as `edb`, hashed so the duplicate check on insert is
    /// constant time. Every write to `edb` keeps this in sync.
    edb_index: HashSet<(String, Vec<Value>)>,
    /// Mangle source for each rule file, plus any REPL-defined rules.
    rule_sources: Vec<String>,
    backend: Box<dyn Backend>,
    /// Persistent incremental DD session, started by `Backend::spawn_session`
    /// (present for the DD backend, absent for the interpreter).  When Some, fact
    /// mutations are fed directly to the worker rather than waiting for a full
    /// recompute.
    session: Option<crate::dd::session::DdSession>,
    /// How many times a fact insert rebuilt the live session. Lets tests
    /// check that a batch insert rebuilds at most once.
    #[cfg(test)]
    rebuild_count: usize,
}

/// Load `fixtures/testdata/small/` manifests and `rules/*.mg` files into the raw
/// `(edb, rule_sources)` pair consumed by `Backend::evaluate`.
///
/// Intended for benchmarks and integration tests; not used in the binary.
/// Always uses the checked-in small fixture, so the `small_*` benchmarks'
/// regression baseline stays comparable run over run. See
/// `load_medium_bench_fixtures` for the fetched, anonymized cluster dump.
pub fn load_bench_fixtures() -> Result<(Vec<(String, Vec<Value>)>, Vec<String>)> {
    load_bench_fixtures_from("fixtures/testdata/small")
}

/// Load the medium fixture (an anonymized cluster dump fetched from a
/// release by `hack/fetch-fixtures.sh medium`) plus `rules/*.mg`.
///
/// Fails with fetch instructions if the dump is missing, or if its
/// `.sha256` stamp does not match the pin in `fixtures/testdata/medium.env`.
pub fn load_medium_bench_fixtures() -> Result<(Vec<(String, Vec<Value>)>, Vec<String>)> {
    const DIR: &str = "fixtures/testdata/medium";
    const PIN: &str = "fixtures/testdata/medium.env";
    const HINT: &str = "run `hack/fetch-fixtures.sh medium`";

    let pin = std::fs::read_to_string(PIN).with_context(|| format!("read {PIN}"))?;
    let want = pin
        .lines()
        .find_map(|l| l.strip_prefix("SHA256="))
        .map(str::trim)
        .with_context(|| format!("no SHA256= line in {PIN}"))?;
    let have = std::fs::read_to_string(format!("{DIR}/.sha256"))
        .map_err(|_| anyhow::anyhow!("medium fixture not found at {DIR}; {HINT}"))?;
    if have.trim() != want {
        anyhow::bail!("medium fixture at {DIR} is stale (pin is {want}); {HINT}");
    }
    load_bench_fixtures_from(DIR)
}

/// Same as `load_bench_fixtures`, but loads manifests from `dir` instead of
/// the small fixture. Used by the medium benchmarks and the anonymizer
/// equivalence test.
pub fn load_bench_fixtures_from(dir: &str) -> Result<(Vec<(String, Vec<Value>)>, Vec<String>)> {
    let mut store = MemStore::new();
    crate::edb::load_from_manifests(&mut store, vec![dir.to_string()])
        .with_context(|| format!("load {dir}"))?;

    let mut edb: Vec<(String, Vec<Value>)> = Vec::new();
    for rel in store.relation_names() {
        let rel: String = rel;
        for tuple in store.get_facts(&rel) {
            edb.push((rel.clone(), tuple));
        }
    }

    let rule_files = glob::glob("rules/*.mg")
        .context("glob rules")?
        .collect::<Result<Vec<_>, _>>()
        .context("glob entries")?;
    let mut rules: Vec<String> = rule_files
        .iter()
        .map(|p| std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display())))
        .collect::<Result<Vec<_>>>()?;
    rules.sort();
    Ok((edb, rules))
}

impl Engine {
    pub fn new(edb_store: MemStore, rules_dir: &Path, backend: Box<dyn Backend>) -> Result<Self> {
        Self::with_objects(edb_store, Vec::new(), rules_dir, backend)
    }

    /// Like [`Self::new`], plus k8s objects run through the projection
    /// pipeline. When two objects share a key, the later one wins, so a
    /// profile can list a cluster snapshot and then manifests that override
    /// some of its objects.
    pub fn with_objects(
        edb_store: MemStore,
        objects: Vec<ObjectFacts>,
        rules_dir: &Path,
        backend: Box<dyn Backend>,
    ) -> Result<Self> {
        let rule_files =
            glob::glob(&rules_dir.join("*.mg").to_string_lossy()).context("glob rules")?;

        let mut rule_sources = Vec::new();
        for entry in rule_files {
            let path = entry?;
            let src = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            rule_sources.push(src);
        }

        Self::from_objects(
            crate::edb::drain_store(edb_store),
            objects,
            rule_sources,
            backend,
        )
    }

    /// [`Self::from_parts`] plus k8s objects, whose facts join `edb`.
    ///
    /// Duplicates are dropped here rather than through
    /// [`Self::upsert_objects`], whose EDB scan per load would make startup
    /// quadratic in the number of objects.
    fn from_objects(
        mut edb: Vec<Fact>,
        objects: Vec<ObjectFacts>,
        rule_sources: Vec<String>,
        backend: Box<dyn Backend>,
    ) -> Result<Self> {
        let (objects, _) = last_per_key(objects);
        edb.extend(objects.into_iter().flat_map(|object| object.facts));
        Self::from_parts(edb, rule_sources, backend)
    }

    /// Construct an Engine directly from pre-loaded data, bypassing all file I/O.
    ///
    /// Use in benchmarks to isolate Datalog evaluation cost from data-source
    /// loading.  Call `load_bench_fixtures()` once to get `(edb, rules)`, then
    /// pass clones into this constructor per iteration.
    pub fn from_parts(
        edb: Vec<(String, Vec<Value>)>,
        rule_sources: Vec<String>,
        backend: Box<dyn Backend>,
    ) -> Result<Self> {
        // Backends with a persistent session (DD) start it here, so fact
        // mutations feed deltas to the worker rather than forcing a full
        // recompute. Rule changes still trigger a full worker rebuild.
        let session = backend.spawn_session(&edb, &rule_sources)?;
        let edb_index = edb.iter().cloned().collect();
        Ok(Self {
            edb,
            edb_index,
            rule_sources,
            backend,
            session,
            #[cfg(test)]
            rebuild_count: 0,
        })
    }

    /// Query a relation from the live DD session.
    ///
    /// Returns an empty vec if no session is active or the relation is unknown,
    /// and an error while any rule has live evaluation errors.
    pub fn query_live(&self, rel: &str) -> Result<Vec<Vec<Value>>> {
        match &self.session {
            Some(s) => s.query(rel),
            None => Ok(vec![]),
        }
    }

    /// True if a live incremental session is active.
    pub fn has_session(&self) -> bool {
        self.session.is_some()
    }

    /// Whether the active backend populates provenance (drives `::why`).
    pub fn supports_provenance(&self) -> bool {
        self.backend.supports_provenance()
    }

    /// The live DD session, if it builds lazy provenance annotations. `::why`
    /// backward-chains against it instead of reading `EvalStore::provenance`.
    pub fn provenance_session(&self) -> Option<&crate::dd::session::DdSession> {
        self.session.as_ref().filter(|s| s.has_provenance())
    }

    /// Add a new rule (from the REPL, e.g. `::define` or `::source`) and mark
    /// state as dirty. In a provenance session the rule gets provenance, so
    /// `::why` can explain its facts.
    ///
    /// When an incremental session is live, the rule is layered into it, or the
    /// session is rebuilt when layering can't be used (the rule extends an
    /// existing predicate, is recursive, or needs provenance). A rule the DD
    /// backend cannot translate is reported as an error (and left in
    /// `rule_sources` for the caller to roll back) rather than silently dropped.
    pub fn add_rule(&mut self, rule: String) -> Result<()> {
        self.add_rule_with_provenance(rule, true)
    }

    /// Add the temporary rule behind a `?-` query. Like [`Self::add_rule`], but
    /// it never gets provenance, so a provenance session layers it on instead
    /// of rebuilding: query results are throwaway and `::why` is for the core
    /// relations.
    pub fn add_query_rule(&mut self, rule: String) -> Result<()> {
        self.add_rule_with_provenance(rule, false)
    }

    fn add_rule_with_provenance(&mut self, rule: String, needs_provenance: bool) -> Result<()> {
        let new_head = extract_head_pred(&rule);
        self.rule_sources.push(rule);
        if let Some(s) = &mut self.session {
            s.add_idb(
                new_head.as_deref(),
                &self.edb,
                &self.rule_sources,
                needs_provenance,
            )?;
        }
        Ok(())
    }

    /// Return the arity of an existing EDB relation, or None if no facts exist yet.
    pub fn relation_arity(&self, relation: &str) -> Option<usize> {
        self.edb
            .iter()
            .find(|(r, _)| r == relation)
            .map(|(_, t)| t.len())
    }

    /// Insert a ground fact into the EDB. Returns true if inserted, false if already present.
    pub fn add_fact(&mut self, relation: String, tuple: Vec<Value>) -> bool {
        let entry = (relation, tuple);
        if !self.edb_index.contains(&entry) {
            // The DD worker drops facts for relations it has no input handle
            // for, so a brand-new relation needs the session rebuilt.
            let known = self.session.as_ref().is_none_or(|s| s.has_input(&entry.0));
            if known {
                if let Some(s) = &self.session {
                    let row = crate::dd::value::Row::from(entry.1.as_slice());
                    s.insert(entry.0.clone(), row);
                    s.commit();
                }
                self.push_fact(entry);
            } else {
                self.push_fact(entry);
                self.rebuild_session();
            }
            true
        } else {
            false
        }
    }

    /// Insert many ground facts at once. Returns how many were new.
    ///
    /// Same result as calling [`Self::add_fact`] for each, but the live
    /// session settles once (one commit) instead of once per fact, and is
    /// rebuilt at most once even when the facts span many new relations.
    pub fn add_facts(&mut self, facts: impl IntoIterator<Item = (String, Vec<Value>)>) -> usize {
        let mut inserted = 0;
        let mut needs_rebuild = false;
        for entry in facts {
            if self.edb_index.contains(&entry) {
                continue;
            }
            if let Some(s) = &self.session {
                if s.has_input(&entry.0) {
                    let row = crate::dd::value::Row::from(entry.1.as_slice());
                    s.insert(entry.0.clone(), row);
                } else {
                    // A rebuild hydrates the session from the whole EDB, so
                    // facts for a new relation only need to land in `edb`.
                    needs_rebuild = true;
                }
            }
            self.push_fact(entry);
            inserted += 1;
        }
        if needs_rebuild {
            self.rebuild_session();
        } else if let Some(s) = &self.session
            && inserted > 0
        {
            s.commit();
        }
        inserted
    }

    /// Append a fact to the EDB and its index.
    fn push_fact(&mut self, entry: (String, Vec<Value>)) {
        self.edb_index.insert(entry.clone());
        self.edb.push(entry);
    }

    /// Re-spawn the live session from the current EDB and rules, if there
    /// is one, printing rather than returning any error.
    fn rebuild_session(&mut self) {
        if let Err(e) = self.try_rebuild_session() {
            eprintln!("Error rebuilding incremental session: {e:#}");
        }
    }

    /// Re-spawn the live session from the current EDB and rules, if there is one.
    fn try_rebuild_session(&mut self) -> Result<()> {
        #[cfg(test)]
        {
            self.rebuild_count += 1;
        }
        if let Some(s) = &mut self.session {
            s.rebuild(&self.edb, &self.rule_sources)?;
        }
        Ok(())
    }

    /// Copy the engine's current facts and rules, minus the rules behind
    /// `?-` results (`_N`), for `\snapshot`.
    pub fn save_inputs(&self) -> EngineInputs {
        let rule_sources = self
            .rule_sources
            .iter()
            .filter(|rule| !extract_head_pred(rule).is_some_and(|head| is_scratch_relation(&head)))
            .cloned()
            .collect();
        EngineInputs {
            edb: self.edb.clone(),
            rule_sources,
        }
    }

    /// Replace the engine's facts and rules with `inputs`, for `\rollback`.
    /// The live session, if any, is rebuilt once from them.
    pub fn restore_inputs(&mut self, inputs: &EngineInputs) -> Result<()> {
        self.edb = inputs.edb.clone();
        self.edb_index = self.edb.iter().cloned().collect();
        self.rule_sources = inputs.rule_sources.clone();
        self.try_rebuild_session()
    }

    /// Remove a ground fact from the EDB. Returns true if a matching fact was found and removed.
    pub fn retract_fact(&mut self, relation: &str, tuple: &[Value]) -> bool {
        let removed = self.remove_fact(relation, tuple);
        if removed && let Some(s) = &self.session {
            s.commit();
        }
        removed
    }

    /// Remove one copy of a fact from the EDB and its index, and buffer the
    /// retraction for the live session without committing it, so a batch of
    /// retractions can share one commit.
    fn remove_fact(&mut self, relation: &str, tuple: &[Value]) -> bool {
        let Some(pos) = self
            .edb
            .iter()
            .position(|(r, t)| r == relation && t.as_slice() == tuple)
        else {
            return false;
        };
        if let Some(s) = &self.session {
            let row = crate::dd::value::Row::from(tuple);
            s.retract(relation.to_string(), row);
        }
        let entry = self.edb.remove(pos);
        // The EDB can hold a fact more than once (two objects that emit the
        // same fact each add a copy); the index keeps the fact until the
        // last copy goes.
        if !self.edb.contains(&entry) {
            self.edb_index.remove(&entry);
        }
        true
    }

    /// Load k8s objects from a FactSource through the projection pipeline,
    /// replacing any object already loaded under the same key.
    pub fn populate_from(
        &mut self,
        source: &mut dyn crate::edb::FactSource,
    ) -> Result<ApplySummary> {
        let objects = crate::edb::object_facts(source)?;
        Ok(self.upsert_objects(objects))
    }

    /// Insert each object's facts, first retracting the facts the same
    /// object (same group, kind, namespace and name, any version) emitted
    /// when it was last loaded, at startup or earlier in the session.
    /// Without this the EDB would hold both versions' `k8s/5` rows and rules
    /// would see the union of old and new.
    ///
    /// The old facts are not stored anywhere: each matching `k8s/5` row's
    /// Data holds the whole object, so [`crate::edb::regenerate_facts`]
    /// rebuilds it and recomputes what it emitted. Finding the rows is one
    /// scan of the EDB per call.
    ///
    /// A fact both versions emit is retracted and re-added, which nets out.
    /// A fact another object also emits survives, as each object added its
    /// own copy.
    pub fn upsert_objects(&mut self, objects: Vec<ObjectFacts>) -> ApplySummary {
        self.apply_changes(objects.into_iter().map(Change::Upsert).collect())
    }

    /// Apply a batch of adds, updates and retracts to the live EDB in one
    /// pass: find the `k8s/5` rows the batch touches with a single EDB scan,
    /// retract each along with the facts it emitted (via
    /// [`crate::edb::regenerate_facts`]), then insert the upserts' facts.
    /// The whole batch shares one session commit (or one rebuild), so a delta
    /// of many changes settles the dataflow once.
    ///
    /// Objects not named in `changes` are left alone. A key named by both an
    /// upsert and a retract is not expected from a 3-way delta; the upsert
    /// wins, since its facts are inserted after the shared retract pass.
    pub fn apply_changes(&mut self, changes: Vec<Change>) -> ApplySummary {
        let mut upserts: Vec<ObjectFacts> = Vec::new();
        let mut retract_keys: HashSet<ObjectKey> = HashSet::new();
        for change in changes {
            match change {
                Change::Upsert(object) => upserts.push(object),
                Change::Retract(key) => {
                    retract_keys.insert(key);
                }
            }
        }
        // Later copies of a key win, matching a single object re-listed in
        // one batch. The collapsed count is not reported: nothing was
        // replaced in the EDB, the batch just named the object twice.
        let (upserts, _collapsed) = last_per_key(upserts);
        let upsert_keys: HashSet<&ObjectKey> = upserts.iter().map(|object| &object.key).collect();
        let upsert_count = upsert_keys.len();

        let mut present_upsert: HashSet<ObjectKey> = HashSet::new();
        let mut present_retract: HashSet<ObjectKey> = HashSet::new();
        let previous: Vec<Vec<Value>> = self
            .edb
            .iter()
            .filter(|(relation, _)| relation == "k8s")
            .filter_map(|(_, tuple)| {
                let key = ObjectKey::of_k8s_tuple(tuple)?;
                if upsert_keys.contains(&key) {
                    present_upsert.insert(key);
                    Some(tuple.clone())
                } else if retract_keys.contains(&key) {
                    present_retract.insert(key);
                    Some(tuple.clone())
                } else {
                    None
                }
            })
            .collect();

        let mut changed = false;
        let mut needs_rebuild = false;
        for tuple in &previous {
            // Retract the row found, not the regenerated one, so a
            // hand-written row with an unusual Data still goes.
            changed |= self.remove_fact("k8s", tuple);
            for (relation, old) in crate::edb::regenerate_facts(tuple) {
                if relation != "k8s" {
                    changed |= self.remove_fact(&relation, &old);
                }
            }
        }
        for entry in upserts.into_iter().flat_map(|object| object.facts) {
            if let Some(s) = &self.session {
                if s.has_input(&entry.0) {
                    s.insert(
                        entry.0.clone(),
                        crate::dd::value::Row::from(entry.1.as_slice()),
                    );
                } else {
                    // A rebuild hydrates the session from the whole EDB.
                    needs_rebuild = true;
                }
            }
            self.push_fact(entry);
            changed = true;
        }
        if needs_rebuild {
            self.rebuild_session();
        } else if let Some(s) = &self.session
            && changed
        {
            s.commit();
        }
        ApplySummary {
            added: upsert_count - present_upsert.len(),
            updated: present_upsert.len(),
            retracted: present_retract.len(),
            removed_absent: retract_keys.len() - present_retract.len(),
        }
    }

    pub fn rules_len(&self) -> usize {
        self.rule_sources.len()
    }

    pub fn truncate_rules(&mut self, len: usize) {
        self.rule_sources.truncate(len);
        if let Some(s) = &mut self.session {
            let _ = s.rebuild(&self.edb, &self.rule_sources);
        }
    }

    /// Remove all rules whose head matches `predicate`.
    pub fn remove_rules_for(&mut self, predicate: &str) {
        let prefix = format!("{predicate}(");
        self.rule_sources
            .retain(|s| !s.trim_start().starts_with(&prefix));
        if let Some(s) = &mut self.session {
            let _ = s.rebuild(&self.edb, &self.rule_sources);
        }
    }

    pub fn compile(&self) -> Result<CompiledProgram> {
        let mut sources = vec![EDB_DECLS];
        for s in &self.rule_sources {
            sources.push(s.as_str());
        }

        CompiledProgram::new(&sources)
    }

    pub fn evaluate(&self) -> Result<EvalStore> {
        // A live session is kept in sync by every mutator, so snapshot it
        // rather than spawning (and settling) a second dataflow.
        if let Some(s) = &self.session {
            return Ok(EvalStore {
                facts: s.snapshot_all()?,
                provenance: vec![],
            });
        }
        self.backend.evaluate(&self.edb, &self.rule_sources)
    }

    /// Evaluate `rule` as the only rule source, against a frozen state's rows
    /// for `relations` as the only input facts (EDB). Used by `\use <name>` so
    /// a `?-` query under a snapshot runs just the query rule over the frozen
    /// facts: the live engine's rule set is not re-run, and this never
    /// touches the live engine (no session, no `self.edb`, no `self.rule_sources`).
    pub fn evaluate_query_on(
        &self,
        state: &EvalStore,
        relations: &[String],
        rule: String,
    ) -> Result<EvalStore> {
        let mut edb: Vec<(String, Vec<Value>)> = Vec::new();
        for rel in relations {
            for tuple in state.scan(rel) {
                edb.push((rel.clone(), tuple.clone()));
            }
        }
        self.backend.evaluate(&edb, std::slice::from_ref(&rule))
    }

    /// Names of every relation the engine knows: declared, defined by a rule
    /// or fact in the sources, or holding EDB rows.
    pub fn known_relations(&self) -> std::collections::HashSet<String> {
        let mut known = self
            .compile()
            .map(|c| c.defined_relations())
            .unwrap_or_default();
        known.extend(self.edb.iter().map(|(r, _)| r.clone()));
        known
    }

    /// Per-relation documentation (descriptions + column types) extracted from
    /// the compiled `Decl`s. Recomputed on demand; `::show` is infrequent.
    pub fn relation_docs(&self) -> Result<HashMap<String, RelationDoc>> {
        Ok(self.compile()?.relation_docs())
    }
}

/// Keep only the last object loaded under each key, in load order, and
/// count how many earlier ones were dropped.
fn last_per_key(objects: Vec<ObjectFacts>) -> (Vec<ObjectFacts>, usize) {
    let mut last: HashMap<ObjectKey, usize> = HashMap::new();
    for (i, object) in objects.iter().enumerate() {
        last.insert(object.key.clone(), i);
    }
    let dropped = objects.len() - last.len();
    let kept = objects
        .into_iter()
        .enumerate()
        .filter(|(i, object)| last[&object.key] == *i)
        .map(|(_, object)| object)
        .collect();
    (kept, dropped)
}

/// Extract the head predicate name from a Mangle rule source string.
///
/// Scans for the first non-empty, non-`Decl`, non-comment line and returns
/// the identifier before the opening `(`.  Returns `None` if the source
/// contains only declarations (or cannot be parsed).
fn extract_head_pred(rule_src: &str) -> Option<String> {
    for line in rule_src.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("Decl") || line.starts_with("//") {
            continue;
        }
        if let Some(pred) = line.split('(').next() {
            let pred = pred.trim();
            if !pred.is_empty() {
                return Some(pred.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Load the fixtures/testdata/small/ manifests + rules/*.mg files and return the raw
    /// (edb, rule_sources) pair that both backends consume.
    fn load_fixtures() -> Result<(Vec<(String, Vec<Value>)>, Vec<String>)> {
        let mut edb_store = MemStore::new();
        crate::edb::load_from_manifests(
            &mut edb_store,
            vec!["fixtures/testdata/small".to_string()],
        )
        .context("load testdata")?;
        let edb = crate::edb::drain_store(edb_store);

        let rule_files = glob::glob("rules/*.mg")
            .context("glob rules")?
            .collect::<Result<Vec<_>, _>>()
            .context("glob entries")?;
        let mut rules: Vec<String> = rule_files
            .iter()
            .map(|p| std::fs::read_to_string(p).with_context(|| format!("read {}", p.display())))
            .collect::<Result<Vec<_>>>()?;
        rules.sort(); // deterministic order
        Ok((edb, rules))
    }

    #[test]
    fn bench_evaluate_compare() {
        let (edb, rules) = load_fixtures().expect("load fixtures");
        let n = 10;

        let t0 = std::time::Instant::now();
        for _ in 0..n {
            InterpreterBackend.evaluate(&edb, &rules).unwrap();
        }
        let interp_avg = t0.elapsed() / n;

        let t0 = std::time::Instant::now();
        for _ in 0..n {
            DdBackend { provenance: false }
                .evaluate(&edb, &rules)
                .unwrap();
        }
        let dd_avg = t0.elapsed() / n;

        println!("interpreter avg: {:?}", interp_avg);
        println!("dd          avg: {:?}", dd_avg);
        println!(
            "ratio dd/interp: {:.1}x",
            dd_avg.as_secs_f64() / interp_avg.as_secs_f64()
        );
    }

    /// Assert that every relation produced by the two backends contains the
    /// exact same set of tuples (order-independent).
    #[test]
    fn dd_matches_interpreter() {
        let (edb, rules) = load_fixtures().expect("load fixtures");

        let interp = InterpreterBackend
            .evaluate(&edb, &rules)
            .expect("interpreter failed");
        let dd = DdBackend { provenance: false }
            .evaluate(&edb, &rules)
            .expect("dd failed");

        let all_rels: std::collections::HashSet<&str> =
            interp.relation_names().chain(dd.relation_names()).collect();

        let mut failures: Vec<String> = Vec::new();
        for rel in &all_rels {
            // Skip planner-internal temp relations (e.g. $temp_grp_0).
            // The interpreter materialises these as a side-effect of GroupBy
            // planning; the DD backend inlines them and never exposes them.
            if rel.starts_with('$') {
                continue;
            }

            let mut interp_tuples = interp.scan(rel).to_vec();
            let mut dd_tuples = dd.scan(rel).to_vec();
            interp_tuples.sort();
            dd_tuples.sort();
            if interp_tuples != dd_tuples {
                failures.push(format!(
                    "{rel}: interpreter={}, dd={}",
                    interp_tuples.len(),
                    dd_tuples.len()
                ));
                // Show first differing tuple for quick diagnosis.
                for t in &interp_tuples {
                    if !dd_tuples.contains(t) {
                        failures.push(format!("  missing from dd:   {t:?}"));
                        break;
                    }
                }
                for t in &dd_tuples {
                    if !interp_tuples.contains(t) {
                        failures.push(format!("  extra in dd:       {t:?}"));
                        break;
                    }
                }
            }
        }

        assert!(
            failures.is_empty(),
            "parity failures:\n{}",
            failures.join("\n")
        );
    }

    // -----------------------------------------------------------------------
    // DD lazy provenance (::why) tests
    // -----------------------------------------------------------------------

    fn s(x: &str) -> Value {
        Value::String(x.to_string())
    }

    /// Diamond graph: a→b, a→c, b→d, c→d, with transitive closure over it.
    fn diamond() -> (Vec<(String, Vec<Value>)>, Vec<String>) {
        let edb = vec![
            ("edge".into(), vec![s("a"), s("b")]),
            ("edge".into(), vec![s("a"), s("c")]),
            ("edge".into(), vec![s("b"), s("d")]),
            ("edge".into(), vec![s("c"), s("d")]),
        ];
        let rules = vec![
            "Decl edge(Src, Dst).\nDecl path(Src, Dst).\n\
             path(X, Y) :- edge(X, Y).\n\
             path(X, Z) :- path(X, Y), edge(Y, Z)."
                .to_string(),
        ];
        (edb, rules)
    }

    /// Facts for several brand-new relations, the shape of a `::snapshot`:
    /// copies of `edge` and `path` under a `snap__` prefix, plus repeats that
    /// must be skipped.
    fn snapshot_style_facts() -> Vec<(String, Vec<Value>)> {
        let mut facts = Vec::new();
        for (src, dst) in [("a", "b"), ("a", "c"), ("b", "d"), ("c", "d")] {
            facts.push(("snap__edge".to_string(), vec![s(src), s(dst)]));
            facts.push(("snap__path".to_string(), vec![s(src), s(dst)]));
        }
        facts.push(("snap__path".to_string(), vec![s("a"), s("d")]));
        facts.push(("snap__edge".to_string(), vec![s("a"), s("b")]));
        facts.push(("snap__node".to_string(), vec![s("a")]));
        facts.push(("edge".to_string(), vec![s("d"), s("e")]));
        facts
    }

    fn sorted_store(store: EvalStore) -> Vec<(String, Vec<Vec<Value>>)> {
        let mut relations: Vec<_> = store
            .facts
            .into_iter()
            .map(|(rel, mut tuples)| {
                tuples.sort();
                (rel, tuples)
            })
            .filter(|(_, tuples)| !tuples.is_empty())
            .collect();
        relations.sort();
        relations
    }

    /// `add_facts` across several new relations gives the DD session the
    /// same facts as the interpreter, and counts only the new ones.
    #[test]
    fn add_facts_dd_matches_interpreter() {
        let (edb, rules) = diamond();
        let mut interpreter =
            Engine::from_parts(edb.clone(), rules.clone(), Box::new(InterpreterBackend)).unwrap();
        let mut dd =
            Engine::from_parts(edb, rules, Box::new(DdBackend { provenance: false })).unwrap();

        assert_eq!(interpreter.add_facts(snapshot_style_facts()), 11);
        assert_eq!(dd.add_facts(snapshot_style_facts()), 11);
        assert_eq!(dd.add_facts(snapshot_style_facts()), 0, "all duplicates");

        let expected = sorted_store(interpreter.evaluate().unwrap());
        let actual = sorted_store(dd.evaluate().unwrap());
        assert_eq!(actual, expected);
        let derived = actual.iter().find(|(rel, _)| rel == "path").unwrap();
        assert!(
            derived.1.contains(&vec![s("a"), s("e")]),
            "the new edge(d, e) reached the existing rules"
        );
    }

    /// A batch spanning many new relations rebuilds the DD session once,
    /// where one `add_fact` per fact rebuilds once per new relation.
    #[test]
    fn add_facts_rebuilds_session_at_most_once() {
        let (edb, rules) = diamond();
        let mut engine =
            Engine::from_parts(edb, rules, Box::new(DdBackend { provenance: false })).unwrap();
        let facts: Vec<(String, Vec<Value>)> = (0..20)
            .map(|i| (format!("snap__relation_{i}"), vec![Value::Number(i)]))
            .collect();
        engine.add_facts(facts);
        assert_eq!(engine.rebuild_count, 1);

        // Facts for relations the session already has inputs for commit
        // without a rebuild.
        engine.add_facts(vec![
            ("edge".to_string(), vec![s("d"), s("e")]),
            ("snap__relation_0".to_string(), vec![Value::Number(100)]),
        ]);
        assert_eq!(engine.rebuild_count, 1);

        for i in 0..3 {
            engine.add_fact(format!("single_{i}"), vec![Value::Number(i)]);
        }
        assert_eq!(engine.rebuild_count, 4);
    }

    /// Non-scratch relations of two engines' evaluations must match. Used by
    /// the incremental-negation parity tests below, which compare the live DD
    /// session (`evaluate` snapshots it) against the interpreter's recompute.
    fn assert_same_facts(dd: &Engine, interp: &Engine) {
        let keep = |store: EvalStore| -> Vec<(String, Vec<Vec<Value>>)> {
            sorted_store(store)
                .into_iter()
                .filter(|(rel, _)| !is_scratch_relation(rel))
                .collect()
        };
        let actual = keep(dd.evaluate().unwrap());
        let expected = keep(interp.evaluate().unwrap());
        assert_eq!(actual, expected);
    }

    /// A rule with a negated body atom, added to a
    /// live DD session while the negated relation has no input yet, used to
    /// fail the layering path with "antijoin relation not found". The
    /// interpreter treats the missing negated relation as empty, so the rule
    /// fires for every row. The batch path `assert_parity` exercises is
    /// already correct; only the incremental layering path regressed.
    #[test]
    fn incremental_negation_rule_without_negated_relation() {
        let edb = vec![
            ("item".to_string(), vec![s("a")]),
            ("item".to_string(), vec![s("b")]),
            ("item".to_string(), vec![s("c")]),
        ];
        let rule = "blocked(X) :- item(X), !allow(X).".to_string();

        let mut interp =
            Engine::from_parts(edb.clone(), vec![], Box::new(InterpreterBackend)).unwrap();
        let mut dd =
            Engine::from_parts(edb, vec![], Box::new(DdBackend { provenance: false })).unwrap();
        interp.add_rule(rule.clone()).unwrap();
        // Before the fix this returns Err("antijoin relation `allow` not found").
        dd.add_rule(rule).unwrap();

        assert_same_facts(&dd, &interp);
        let mut blocked = dd.query_live("blocked").unwrap();
        blocked.sort();
        assert_eq!(blocked, vec![vec![s("a")], vec![s("b")], vec![s("c")]]);
    }

    /// Once a negation rule is in place, facts added incrementally to the
    /// negated relation must update the antijoin. After the fix
    /// tested in incremental_negation_rule_without_negated_relation,
    /// the first such fact rebuilds the session (registering the relation as
    /// a live empty input), and later facts feed it as deltas; the derived
    /// relation must shrink to match the interpreter.
    #[test]
    fn incremental_facts_added_to_negated_relation() {
        let edb = vec![
            ("item".to_string(), vec![s("a")]),
            ("item".to_string(), vec![s("b")]),
            ("item".to_string(), vec![s("c")]),
        ];
        let rule = "blocked(X) :- item(X), !allow(X).".to_string();

        let mut interp =
            Engine::from_parts(edb.clone(), vec![], Box::new(InterpreterBackend)).unwrap();
        let mut dd =
            Engine::from_parts(edb, vec![], Box::new(DdBackend { provenance: false })).unwrap();
        interp.add_rule(rule.clone()).unwrap();
        dd.add_rule(rule).unwrap();

        let more = vec![
            ("allow".to_string(), vec![s("a")]),
            ("allow".to_string(), vec![s("b")]),
        ];
        assert_eq!(interp.add_facts(more.clone()), 2);
        assert_eq!(dd.add_facts(more), 2);

        assert_same_facts(&dd, &interp);
        let mut allow = dd.query_live("allow").unwrap();
        allow.sort();
        assert_eq!(allow, vec![vec![s("a")], vec![s("b")]], "both facts kept");
        assert_eq!(dd.query_live("blocked").unwrap(), vec![vec![s("c")]]);
    }

    /// Retracting one of two copies of a fact keeps it in the duplicate
    /// index, so re-adding it is still a no-op until the last copy goes.
    #[test]
    fn retract_keeps_index_in_sync() {
        let (mut edb, rules) = diamond();
        edb.push(edb[0].clone());
        let mut engine = Engine::from_parts(edb, rules, Box::new(InterpreterBackend)).unwrap();
        let saved = engine.save_inputs();
        let ab = vec![s("a"), s("b")];
        assert!(engine.retract_fact("edge", &ab));
        assert!(!engine.add_fact("edge".to_string(), ab.clone()));
        assert!(engine.retract_fact("edge", &ab));
        assert!(engine.add_fact("edge".to_string(), ab.clone()));

        engine.restore_inputs(&saved).unwrap();
        assert!(!engine.add_fact("edge".to_string(), ab));
    }

    /// Objects handed straight to the projection pipeline.
    struct Objects(Vec<serde_json::Value>);

    impl crate::edb::FactSource for Objects {
        fn k8s_objects(
            &mut self,
        ) -> Result<Vec<(kube::api::DynamicObject, Option<(String, String)>)>> {
            self.0
                .drain(..)
                .map(|json| Ok((serde_json::from_value(json)?, None)))
                .collect()
        }
    }

    fn objects(json: Vec<serde_json::Value>) -> Vec<ObjectFacts> {
        crate::edb::object_facts(&mut Objects(json)).unwrap()
    }

    /// A ConfigMap `name` labelled `tier=<tier>`.
    fn config_map(name: &str, tier: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": name, "namespace": "default", "labels": {"tier": tier}},
            "data": {"tier": tier},
        })
    }

    /// A NodePool `pool` in `api_version` whose nodes get `zone=<zone>`.
    fn node_pool(api_version: &str, zone: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": api_version,
            "kind": "NodePool",
            "metadata": {"name": "pool"},
            "spec": {"template": {"metadata": {"labels": {"zone": zone}}}},
        })
    }

    /// Both backends, started with `startup` objects on top of the diamond.
    fn object_engines(startup: Vec<ObjectFacts>) -> [Engine; 2] {
        let (edb, rules) = diamond();
        let backends: [Box<dyn Backend>; 2] = [
            Box::new(InterpreterBackend),
            Box::new(DdBackend { provenance: false }),
        ];
        backends.map(|backend| {
            Engine::from_objects(edb.clone(), startup.clone(), rules.clone(), backend).unwrap()
        })
    }

    fn rows(engine: &Engine, relation: &str) -> Vec<Vec<Value>> {
        let store = engine.evaluate().unwrap();
        let mut rows = store.scan(relation).to_vec();
        rows.sort();
        rows
    }

    /// The `tier` labels on ConfigMaps, as (name, tier) pairs.
    fn tiers(engine: &Engine) -> Vec<(Value, Value)> {
        rows(engine, "object_label")
            .into_iter()
            .map(|row| (row[3].clone(), row[5].clone()))
            .collect()
    }

    /// Loading an object again replaces the facts its last load emitted,
    /// whether that load was at startup or earlier in the session.
    #[test]
    fn upsert_replaces_object_facts() {
        let startup = objects(vec![config_map("x", "web"), config_map("y", "db")]);
        for mut engine in object_engines(startup) {
            let summary = engine.upsert_objects(objects(vec![config_map("x", "api")]));
            assert_eq!(
                summary,
                ApplySummary {
                    updated: 1,
                    ..Default::default()
                }
            );
            assert_eq!(
                tiers(&engine),
                [(s("x"), s("api")), (s("y"), s("db"))],
                "x replaced, y untouched"
            );
            assert_eq!(rows(&engine, "k8s").len(), 2);

            engine.upsert_objects(objects(vec![config_map("x", "cache")]));
            assert_eq!(tiers(&engine), [(s("x"), s("cache")), (s("y"), s("db"))]);
            assert_eq!(rows(&engine, "k8s").len(), 2);
            assert_eq!(rows(&engine, "edge").len(), 4);
        }
    }

    /// One upsert object by hand, for building a `Change::Upsert`.
    fn one(json: serde_json::Value) -> ObjectFacts {
        objects(vec![json]).pop().unwrap()
    }

    /// A retract drops one object's facts, keeps the rest, and reports it;
    /// a retract of a key that is not loaded changes nothing and counts as
    /// removed-but-absent (the cluster may have dropped it before the delta).
    #[test]
    fn apply_changes_retracts_by_key() {
        let startup = objects(vec![config_map("x", "web"), config_map("y", "db")]);
        for mut engine in object_engines(startup) {
            let summary = engine.apply_changes(vec![
                Change::Retract(ObjectKey::new("v1", "ConfigMap", "default", "x")),
                Change::Retract(ObjectKey::new("v1", "ConfigMap", "default", "gone")),
            ]);
            assert_eq!(
                summary,
                ApplySummary {
                    retracted: 1,
                    removed_absent: 1,
                    ..Default::default()
                }
            );
            assert_eq!(tiers(&engine), [(s("y"), s("db"))], "x retracted, y kept");
            assert_eq!(rows(&engine, "k8s").len(), 1);
        }
    }

    /// One batch of an add, an update and a retract settles once and reports
    /// each outcome, matching a 3-way delta applied to the live cluster.
    #[test]
    fn apply_changes_mixes_add_update_retract() {
        let startup = objects(vec![config_map("x", "web"), config_map("y", "db")]);
        for mut engine in object_engines(startup) {
            let summary = engine.apply_changes(vec![
                Change::Upsert(one(config_map("z", "cache"))),
                Change::Upsert(one(config_map("x", "api"))),
                Change::Retract(ObjectKey::new("v1", "ConfigMap", "default", "y")),
            ]);
            assert_eq!(
                summary,
                ApplySummary {
                    added: 1,
                    updated: 1,
                    retracted: 1,
                    removed_absent: 0,
                }
            );
            assert_eq!(
                tiers(&engine),
                [(s("x"), s("api")), (s("z"), s("cache"))],
                "z added, x updated, y retracted"
            );
            assert_eq!(rows(&engine, "k8s").len(), 2);
        }
    }

    /// A fact two objects emit stays while either is still loaded with it.
    /// NodePools in two API groups are two objects, but both emit
    /// `nodepool_label("pool", "zone", ...)`.
    #[test]
    fn upsert_keeps_fact_another_object_emits() {
        let startup = objects(vec![
            node_pool("karpenter.sh/v1", "a"),
            node_pool("other.dev/v1", "a"),
        ]);
        let zone = |z: &str| vec![s("pool"), s("zone"), s(z)];
        for mut engine in object_engines(startup) {
            engine.upsert_objects(objects(vec![node_pool("karpenter.sh/v1", "b")]));
            assert_eq!(rows(&engine, "nodepool_label"), [zone("a"), zone("b")]);
            engine.upsert_objects(objects(vec![node_pool("other.dev/v1", "b")]));
            assert_eq!(rows(&engine, "nodepool_label"), [zone("b")]);
        }
    }

    /// Another version in the same API group is the same object.
    #[test]
    fn upsert_matches_any_version_in_group() {
        let startup = objects(vec![node_pool("karpenter.sh/v1beta1", "a")]);
        for mut engine in object_engines(startup) {
            let summary = engine.upsert_objects(objects(vec![node_pool("karpenter.sh/v1", "b")]));
            assert_eq!(summary.updated, 1);
            let k8s = rows(&engine, "k8s");
            assert_eq!(k8s.len(), 1);
            assert_eq!(k8s[0][0], s("karpenter.sh/v1"));
            assert_eq!(
                rows(&engine, "nodepool_label"),
                [vec![s("pool"), s("zone"), s("b")]]
            );
        }
    }

    /// The same object twice in one load: the later copy wins.
    #[test]
    fn upsert_same_object_twice_in_one_load() {
        for mut engine in object_engines(vec![]) {
            let summary = engine.upsert_objects(objects(vec![
                config_map("x", "web"),
                config_map("x", "api"),
            ]));
            // Two copies of one key collapse to a single new object: an add,
            // with nothing replaced in the EDB.
            assert_eq!(
                summary,
                ApplySummary {
                    added: 1,
                    ..Default::default()
                }
            );
            assert_eq!(tiers(&engine), [(s("x"), s("api"))]);
            assert_eq!(rows(&engine, "k8s").len(), 1);
        }
    }

    /// Restoring saved inputs undoes an upsert of a startup object, an
    /// added fact and an added rule, leaving the same facts as before, and
    /// rebuilds the DD session once. `?-` result rules (`_N`) are never
    /// saved, so none survive a restore, whenever they were added.
    #[test]
    fn restore_inputs_undoes_upsert_of_startup_object() {
        let startup = objects(vec![config_map("x", "web"), config_map("y", "db")]);
        for mut engine in object_engines(startup) {
            let before = sorted_store(engine.evaluate().unwrap());
            let rules_before = engine.rules_len();
            engine
                .add_query_rule("_0(X) :- path(X, \"d\").".to_string())
                .unwrap();
            let saved = engine.save_inputs();
            engine
                .add_query_rule("_1(X) :- path(\"a\", X).".to_string())
                .unwrap();

            engine.upsert_objects(objects(vec![config_map("x", "api")]));
            engine.add_fact("edge".to_string(), vec![s("d"), s("e")]);
            engine
                .add_rule("reach_e(X) :- path(X, \"e\").".to_string())
                .unwrap();
            assert_eq!(tiers(&engine), [(s("x"), s("api")), (s("y"), s("db"))]);

            let rebuilds = engine.rebuild_count;
            engine.restore_inputs(&saved).unwrap();
            assert_eq!(engine.rebuild_count, rebuilds + 1);
            assert_eq!(engine.rules_len(), rules_before);
            assert_eq!(tiers(&engine), [(s("x"), s("web")), (s("y"), s("db"))]);
            let after = engine.evaluate().unwrap();
            assert!(after.scan("_0").is_empty() && after.scan("_1").is_empty());
            assert_eq!(sorted_store(after), before);
            // The duplicate index matches the restored EDB: the retracted
            // startup row can't be re-added, the dropped edge can.
            assert!(!engine.add_fact("edge".to_string(), vec![s("a"), s("b")]));
            assert!(engine.add_fact("edge".to_string(), vec![s("d"), s("e")]));
        }
    }

    /// `--provenance` gives `Engine` a live lazy session, and backward-chaining
    /// path(a,d) yields one shortest proof whose premises are real facts with
    /// strictly lower heights, bottoming out at EDB edges.
    #[test]
    fn dd_provenance_lazy_session_explains_fact() {
        use crate::dd::value::{Row, SENTINEL_EDB};

        let (edb, rules) = diamond();
        let engine =
            Engine::from_parts(edb, rules, Box::new(DdBackend { provenance: true })).unwrap();
        let session = engine
            .provenance_session()
            .expect("provenance on => lazy session");

        let ad = Row::from([s("a"), s("d")].as_slice());
        let (rid, h) = session
            .why_height("path", &ad)
            .expect("path(a,d) annotated");
        assert_eq!(h, 2, "path(a,d) shortest proof height");
        let g = session
            .why_step(rid, &ad, h)
            .expect("grounding for path(a,d)");
        assert_eq!(g.premises.len(), 2);
        for p in &g.premises {
            assert!(p.height < h, "premise {p:?} not strictly lower");
            if p.rel == "edge" {
                assert_eq!((p.rule_id, p.height), (SENTINEL_EDB, 0));
            }
        }
    }

    /// Adding a rule to a lazy session rebuilds it (layering builds no
    /// annotations), so the new rule's facts are explainable too.
    #[test]
    fn dd_provenance_survives_add_rule() {
        use crate::dd::value::Row;

        let (edb, rules) = diamond();
        let mut engine =
            Engine::from_parts(edb, rules, Box::new(DdBackend { provenance: true })).unwrap();
        engine
            .add_rule("from_a(Y) :- path(\"a\", Y).".to_string())
            .unwrap();
        let session = engine.provenance_session().expect("still a lazy session");

        let fd = Row::from([s("d")].as_slice());
        let (rid, h) = session
            .why_height("from_a", &fd)
            .expect("from_a(d) annotated");
        assert_eq!(h, 3, "from_a(d) = 1 + height of path(a,d)");
        assert!(session.why_step(rid, &fd, h).is_some());
    }

    /// On the shipped k8s rules (struct/list access, builtins, negation,
    /// aggregation, recursion), every derived fact has an annotation and a
    /// one-step grounding whose premises are real facts with strictly lower
    /// heights and matching annotations. Each premise is itself checked as a
    /// fact, so by induction every full `::why` tree bottoms out at EDB.
    #[test]
    fn dd_provenance_explains_every_shipped_fact() {
        use crate::dd::value::{Row, SENTINEL_EDB};

        let (edb, rules) = load_fixtures().expect("load fixtures");
        let plain = DdBackend { provenance: false }
            .evaluate(&edb, &rules)
            .expect("dd without provenance");
        let engine =
            Engine::from_parts(edb, rules, Box::new(DdBackend { provenance: true })).unwrap();
        let session = engine
            .provenance_session()
            .expect("provenance on => lazy session");
        let facts = session.snapshot_all().unwrap();

        let mut derived = 0;
        for (rel, tuples) in &facts {
            if rel.starts_with('$') {
                continue;
            }
            // Annotations must not change what gets derived.
            let mut with: Vec<_> = tuples.clone();
            let mut without: Vec<_> = plain.scan(rel).to_vec();
            with.sort();
            without.sort();
            assert_eq!(with, without, "provenance changed facts of `{rel}`");

            for t in tuples {
                let row = Row::from(t.as_slice());
                let (rid, h) = session
                    .why_height(rel, &row)
                    .unwrap_or_else(|| panic!("no annotation for {rel}{t:?}"));
                if rid == SENTINEL_EDB {
                    assert_eq!(h, 0, "EDB fact {rel}{t:?} must have height 0");
                    continue;
                }
                derived += 1;
                let g = session
                    .why_step(rid, &row, h)
                    .unwrap_or_else(|| panic!("no grounding for {rel}{t:?} (rule {rid}, h {h})"));
                for p in &g.premises {
                    assert!(p.height < h, "{rel}{t:?}: premise {p:?} not lower");
                    let vals = p.row.clone().into_values();
                    assert!(
                        facts.get(&p.rel).is_some_and(|ts| ts.contains(&vals)),
                        "{rel}{t:?}: premise {p:?} is not a fact"
                    );
                    assert_eq!(
                        session.why_height(&p.rel, &p.row),
                        Some((p.rule_id, p.height)),
                        "{rel}{t:?}: premise {p:?} annotation mismatch"
                    );
                }
            }
        }
        assert!(derived > 0, "fixtures derived no facts");
        eprintln!("explained {derived} derived facts");
    }

    /// A `?-` query rule layers onto a provenance session without provenance:
    /// its results are queryable but not annotated (a rebuild would have
    /// annotated them), and the core relations stay explainable.
    #[test]
    fn dd_provenance_query_rule_layers_without_provenance() {
        use crate::dd::value::Row;

        let (edb, rules) = diamond();
        let mut engine =
            Engine::from_parts(edb, rules, Box::new(DdBackend { provenance: true })).unwrap();
        engine
            .add_query_rule("_0(Y) :- path(\"a\", Y).".to_string())
            .unwrap();

        let mut results = engine.query_live("_0").unwrap();
        results.sort();
        assert_eq!(results, vec![vec![s("b")], vec![s("c")], vec![s("d")]]);

        let session = engine.provenance_session().expect("still a lazy session");
        assert!(!session.has_provenance_for("_0"), "query rule was layered");
        assert!(session.has_provenance_for("path"));
        let ad = Row::from([s("a"), s("d")].as_slice());
        assert_eq!(session.why_height("path", &ad).map(|a| a.1), Some(2));
    }

    /// Heights track fact deltas in the live session: a shortcut edge lowers
    /// path(a,d) to height 1, retracting it restores 2, and retracting one arm
    /// of the diamond leaves a proof through the other.
    #[test]
    fn dd_provenance_heights_follow_deltas() {
        use crate::dd::value::Row;

        let (edb, rules) = diamond();
        let mut engine =
            Engine::from_parts(edb, rules, Box::new(DdBackend { provenance: true })).unwrap();
        let ad = Row::from([s("a"), s("d")].as_slice());
        let height = |e: &Engine| e.provenance_session().unwrap().why_height("path", &ad);

        assert_eq!(height(&engine).map(|a| a.1), Some(2));
        engine.add_fact("edge".into(), vec![s("a"), s("d")]);
        assert_eq!(height(&engine).map(|a| a.1), Some(1), "shortcut edge");
        engine.retract_fact("edge", &[s("a"), s("d")]);
        assert_eq!(height(&engine).map(|a| a.1), Some(2), "shortcut retracted");

        engine.retract_fact("edge", &[s("b"), s("d")]);
        let session = engine.provenance_session().unwrap();
        let (rid, h) = session
            .why_height("path", &ad)
            .expect("still derivable via c");
        let g = session.why_step(rid, &ad, h).expect("grounding via c");
        assert!(
            g.premises
                .iter()
                .any(|p| p.row == Row::from([s("c"), s("d")].as_slice())),
            "proof must go through c once b->d is gone: {g:?}"
        );
    }

    /// With the flag off, the session builds no annotations.
    #[test]
    fn dd_provenance_off_has_no_provenance_session() {
        let (edb, rules) = diamond();
        let engine =
            Engine::from_parts(edb, rules, Box::new(DdBackend { provenance: false })).unwrap();
        assert!(engine.has_session());
        assert!(engine.provenance_session().is_none());
    }

    /// A fact for a relation the session did not start with must reach the
    /// dataflow (not be silently dropped) and match the interpreter.
    #[test]
    fn dd_add_fact_new_relation_is_visible() {
        let rules = vec!["Decl known(X).".to_string()];
        let mut dd = Engine::from_parts(
            vec![],
            rules.clone(),
            Box::new(DdBackend { provenance: false }),
        )
        .unwrap();
        assert!(dd.has_session());
        assert!(dd.add_fact("brand_new".into(), vec![Value::String("x".into())]));

        let live = dd.query_live("brand_new").unwrap();
        assert_eq!(live, vec![vec![Value::String("x".into())]]);

        let mut interp = Engine::from_parts(vec![], rules, Box::new(InterpreterBackend)).unwrap();
        interp.add_fact("brand_new".into(), vec![Value::String("x".into())]);
        let store = interp.evaluate().unwrap();
        assert_eq!(live, store.scan("brand_new").to_vec());
        assert_eq!(
            dd.evaluate().unwrap().scan("brand_new"),
            store.scan("brand_new")
        );
    }

    /// A relation that is declared but never derived or populated is still a
    /// session input, so rules added later can reference it and see no rows.
    #[test]
    fn dd_declared_but_empty_relation_is_queryable() {
        let rules = vec!["Decl lonely(X).".to_string()];
        let mut dd =
            Engine::from_parts(vec![], rules, Box::new(DdBackend { provenance: false })).unwrap();
        assert!(dd.query_live("lonely").unwrap().is_empty());
        dd.add_rule("Decl seen(X).\nseen(X) :- lonely(X).".to_string())
            .expect("rule over declared-but-empty relation");
        assert!(dd.query_live("seen").unwrap().is_empty());
        let store = dd.evaluate().unwrap();
        assert!(store.scan("lonely").is_empty());
        assert!(store.scan("seen").is_empty());
    }

    // -----------------------------------------------------------------------
    // Negated built-in predicates (Condition::Not)
    //
    // Each case runs on both backends and is checked against a hand-written
    // expectation, not just backend-vs-backend: before mangle-rs 0.9.1 both
    // backends planned `!:builtin(..)` as a lookup of a never-populated
    // relation, so they agreed with each other while both being wrong.
    // -----------------------------------------------------------------------

    use mangle_common::CompoundKind;

    fn num(n: i64) -> Value {
        Value::Number(n)
    }
    fn st(s: &str) -> Value {
        Value::String(s.to_string())
    }
    fn nm(s: &str) -> Value {
        Value::Name(s.to_string())
    }
    fn list(vs: Vec<Value>) -> Value {
        Value::Compound(CompoundKind::List, vs)
    }
    /// Struct layout is interleaved: [k1, v1, k2, v2, ...].
    fn strukt(fields: &[(&str, Value)]) -> Value {
        let mut kvs = Vec::new();
        for (k, v) in fields {
            kvs.push(nm(k));
            kvs.push(v.clone());
        }
        Value::Compound(CompoundKind::Struct, kvs)
    }

    fn facts(rel: &str, rows: Vec<Vec<Value>>) -> Vec<(String, Vec<Value>)> {
        rows.into_iter().map(|r| (rel.to_string(), r)).collect()
    }

    /// Evaluate `rules` on both backends and assert each yields exactly
    /// `expected` for `rel`.
    fn assert_both(
        edb: &[(String, Vec<Value>)],
        rules: &str,
        rel: &str,
        mut expected: Vec<Vec<Value>>,
    ) {
        expected.sort();
        let rules = vec![rules.to_string()];
        let backends: [(&str, &dyn Backend); 2] = [
            ("interpreter", &InterpreterBackend),
            ("dd", &DdBackend { provenance: false }),
        ];
        for (name, backend) in backends {
            let store = backend
                .evaluate(edb, &rules)
                .unwrap_or_else(|e| panic!("{name} failed: {e:#}"));
            let mut got = store.scan(rel).to_vec();
            got.sort();
            assert_eq!(got, expected, "{name} backend, relation {rel}");
        }
    }

    #[test]
    fn negated_cmp_builtins() {
        let edb = facts(
            "np_pair",
            vec![
                vec![num(1), num(2)],
                vec![num(4), num(4)],
                vec![num(5), num(3)],
            ],
        );
        let lt = vec![vec![num(4), num(4)], vec![num(5), num(3)]];
        let le = vec![vec![num(5), num(3)]];
        let gt = vec![vec![num(1), num(2)], vec![num(4), num(4)]];
        let ge = vec![vec![num(1), num(2)]];
        for (op, expected) in [("lt", lt), ("le", le), ("gt", gt), ("ge", ge)] {
            let rules =
                format!("Decl np_pair(X, Y).\nnp_out(X, Y) :- np_pair(X, Y), !:{op}(X, Y).");
            assert_both(&edb, &rules, "np_out", expected);
        }
    }

    #[test]
    fn negated_cmp_against_constant() {
        let edb = facts("np_num", vec![vec![num(1)], vec![num(3)], vec![num(5)]]);
        assert_both(
            &edb,
            "Decl np_num(X).\nnp_out(X) :- np_num(X), !:lt(X, 3).",
            "np_out",
            vec![vec![num(3)], vec![num(5)]],
        );
    }

    #[test]
    fn negated_time_and_duration_cmp() {
        let edb = vec![
            ("np_t".to_string(), vec![Value::Time(10), Value::Time(20)]),
            ("np_t".to_string(), vec![Value::Time(30), Value::Time(20)]),
            (
                "np_d".to_string(),
                vec![Value::Duration(5), Value::Duration(5)],
            ),
            (
                "np_d".to_string(),
                vec![Value::Duration(9), Value::Duration(5)],
            ),
        ];
        assert_both(
            &edb,
            "Decl np_t(A, B).\nnp_tout(A) :- np_t(A, B), !:time:lt(A, B).",
            "np_tout",
            vec![vec![Value::Time(30)]],
        );
        assert_both(
            &edb,
            "Decl np_d(A, B).\nnp_dout(A) :- np_d(A, B), !:duration:gt(A, B).",
            "np_dout",
            vec![vec![Value::Duration(5)]],
        );
    }

    #[test]
    fn negated_string_builtins() {
        let edb = facts(
            "np_s",
            vec![vec![st("alpha")], vec![st("beta")], vec![st("gamma")]],
        );
        let cases = [
            (
                r#"!:string:starts_with(S, "al")"#,
                vec![st("beta"), st("gamma")],
            ),
            (
                r#"!:string:ends_with(S, "ta")"#,
                vec![st("alpha"), st("gamma")],
            ),
            (
                r#"!:string:contains(S, "mm")"#,
                vec![st("alpha"), st("beta")],
            ),
        ];
        for (premise, expected) in cases {
            let rules = format!("Decl np_s(S).\nnp_out(S) :- np_s(S), {premise}.");
            let expected = expected.into_iter().map(|v| vec![v]).collect();
            assert_both(&edb, &rules, "np_out", expected);
        }
    }

    /// `:match_prefix` requires the name to be strictly longer than the
    /// prefix, so `/a` does not match itself and survives the negation.
    #[test]
    fn negated_match_prefix() {
        let edb = facts(
            "np_n",
            vec![vec![nm("/a")], vec![nm("/a/b")], vec![nm("/c/d")]],
        );
        assert_both(
            &edb,
            "Decl np_n(N).\nnp_out(N) :- np_n(N), !:match_prefix(N, /a).",
            "np_out",
            vec![vec![nm("/a")], vec![nm("/c/d")]],
        );
    }

    /// Positive form of the same strictness rule.
    #[test]
    fn match_prefix_excludes_exact_match() {
        let edb = facts(
            "np_n",
            vec![vec![nm("/a")], vec![nm("/a/b")], vec![nm("/c/d")]],
        );
        assert_both(
            &edb,
            "Decl np_n(N).\nnp_out(N) :- np_n(N), :match_prefix(N, /a).",
            "np_out",
            vec![vec![nm("/a/b")]],
        );
    }

    /// A non-list second argument makes the check false, so the negation
    /// keeps the row.
    #[test]
    fn negated_list_member() {
        let edb = [
            facts(
                "np_holder",
                vec![
                    vec![list(vec![num(1), num(2)])],
                    vec![list(vec![])],
                    vec![st("not a list")],
                ],
            ),
            facts("np_elem", vec![vec![num(1)], vec![num(3)]]),
        ]
        .concat();
        let rules = "Decl np_holder(L).\nDecl np_elem(E).\n\
                     np_out(E, L) :- np_holder(L), np_elem(E), !:list:member(E, L).";
        assert_both(
            &edb,
            rules,
            "np_out",
            vec![
                vec![num(3), list(vec![num(1), num(2)])],
                vec![num(1), list(vec![])],
                vec![num(3), list(vec![])],
                vec![num(1), st("not a list")],
                vec![num(3), st("not a list")],
            ],
        );
    }

    /// Evaluate `rules` on both backends and assert each fails with an error
    /// mentioning `needle`.
    fn assert_both_err(edb: &[(String, Vec<Value>)], rules: &str, needle: &str) {
        let rules = vec![rules.to_string()];
        let backends: [(&str, &dyn Backend); 2] = [
            ("interpreter", &InterpreterBackend),
            ("dd", &DdBackend { provenance: false }),
        ];
        for (name, backend) in backends {
            match backend.evaluate(edb, &rules) {
                Ok(_) => {
                    panic!("{name} backend succeeded, expected an error containing {needle:?}")
                }
                Err(e) => {
                    let msg = format!("{e:#}");
                    assert!(
                        msg.contains(needle),
                        "{name} backend error {msg:?} lacks {needle:?}"
                    );
                }
            }
        }
    }

    /// Following upstream mangle, a `:string:*` built-in on a non-string fails
    /// the whole evaluation, in both the positive and negated forms.
    #[test]
    fn string_builtin_type_error_fails_both_backends() {
        let edb = facts(
            "np_s",
            vec![vec![st("alpha")], vec![Value::Null], vec![num(5)]],
        );
        for premise in [
            r#":string:starts_with(S, "al")"#,
            r#"!:string:starts_with(S, "al")"#,
        ] {
            let rules = format!("Decl np_s(S).\nnp_out(S) :- np_s(S), {premise}.");
            assert_both_err(
                &edb,
                &rules,
                ":string:starts_with: expected string arguments",
            );
        }
    }

    /// The error also surfaces from inside a recursive stratum.
    #[test]
    fn builtin_type_error_in_recursive_rule_fails_both_backends() {
        let edb = [
            facts("np_start", vec![vec![st("n1")]]),
            facts(
                "np_edge",
                vec![vec![st("n1"), st("n2")], vec![st("n2"), num(3)]],
            ),
        ]
        .concat();
        let rules = "Decl np_start(X).\nDecl np_edge(X, Y).\n\
                     np_reach(X) :- np_start(X).\n\
                     np_reach(Y) :- np_reach(X), np_edge(X, Y), :string:starts_with(Y, \"n\").";
        assert_both_err(
            &edb,
            rules,
            ":string:starts_with: expected string arguments",
        );
    }

    /// A failing function in a `let` fails the whole evaluation.
    #[test]
    fn let_function_error_fails_both_backends() {
        let edb = facts("np_v", vec![vec![num(1)], vec![st("x")]]);
        assert_both_err(
            &edb,
            "Decl np_v(X).\nnp_out(Y) :- np_v(X) |> let Y = fn:plus(X, 1).",
            "fn:plus: expected integer",
        );
    }

    /// The happy path still evaluates normally.
    #[test]
    fn let_function_ok() {
        let edb = facts("np_v", vec![vec![num(1)], vec![num(41)]]);
        assert_both(
            &edb,
            "Decl np_v(X).\nnp_out(Y) :- np_v(X) |> let Y = fn:plus(X, 1).",
            "np_out",
            vec![vec![num(2)], vec![num(42)]],
        );
    }

    /// Same for `:match_prefix` on a non-name.
    #[test]
    fn match_prefix_type_error_fails_both_backends() {
        let edb = facts("np_n", vec![vec![nm("/a/b")], vec![st("/a/c")]]);
        assert_both_err(
            &edb,
            "Decl np_n(N).\nnp_out(N) :- np_n(N), !:match_prefix(N, /a).",
            ":match_prefix: expected name arguments",
        );
    }

    /// A missing field or a non-struct scrutinee makes the check false, so
    /// the negation keeps the row.
    #[test]
    fn negated_match_field() {
        let matching = strukt(&[("/kind", st("a"))]);
        let other_value = strukt(&[("/kind", st("b"))]);
        let missing_field = strukt(&[("/other", st("a"))]);
        let edb = facts(
            "np_obj",
            vec![
                vec![matching],
                vec![other_value.clone()],
                vec![missing_field.clone()],
                vec![st("not a struct")],
            ],
        );
        assert_both(
            &edb,
            "Decl np_obj(S).\nnp_out(S) :- np_obj(S), !:match_field(S, /kind, \"a\").",
            "np_out",
            vec![
                vec![other_value],
                vec![missing_field],
                vec![st("not a struct")],
            ],
        );
    }
}
