// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::{Context, Result, bail};
use mangle_ast::Arena;
use mangle_common::{Store, Value};
use mangle_driver::compile_units;
use mangle_interpreter::{Interpreter, MemStore, ProvenanceEntry};
use mangle_ir::physical::{Condition, Constant, DataSource, Op, Operand};
use mangle_ir::{Inst, InstId, Ir, NameId};

const EDB_DECLS: &str = include_str!("../rules/00_edb_prelude.mg");

/// Snapshot of all derived facts after an evaluation pass.
pub struct EvalStore {
    facts: HashMap<String, Vec<Vec<Value>>>,
    pub provenance: Vec<ProvenanceEntry>,
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
    // TODO We might not need this
    arena: Arena,
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

        Ok(Self { ir, arena, strata })
    }

    /// Extract per-relation documentation from the compiled `Decl`s in the IR:
    /// column names (from the decl head), types (from `bound [...]`), the
    /// relation description (from a `doc("...")` descr atom), and per-column
    /// descriptions (from `arg(Col, "...")` descr atoms).
    pub fn relation_docs(&self) -> HashMap<String, RelationDoc> {
        let mut docs = HashMap::new();
        for inst in &self.ir.insts {
            let Inst::Decl { atom, descr, bounds, .. } = inst else {
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

            docs.insert(rel_name, RelationDoc { description, columns });
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
                .intersperse_with(|| ", ")
                .collect::<String>()
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
                                .intersperse_with(|| ", ".to_string())
                                .collect::<String>()
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
                    .intersperse_with(|| ", ".to_string())
                    .collect::<String>()
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
            _ => Ok(write!(w, "{}(unimplemented: {:?})", node_prefix, &op)?),
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
                    .intersperse_with(|| ", ".to_string())
                    .collect::<String>()
            );

            // Step B: collect rule_ids — must finish before calling Planner (&mut ir)
            let mut initial_ids: Vec<InstId> = vec![];
            let mut delta_ids: Vec<(InstId, NameId)> = vec![];

            for (idx, inst) in self.ir.insts.iter().enumerate() {
                if let mangle_ir::Inst::Rule { head, premises, .. } = inst {
                    if let mangle_ir::Inst::Atom { predicate, .. } = self.ir.get(*head) {
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
                            {
                                if pred_names.contains(self.ir.resolve_name(*pname)) {
                                    delta_ids.push((mangle_ir::InstId::new(idx), *pname));
                                }
                            }
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
}

pub struct DdBackend;

impl Backend for DdBackend {
    fn evaluate(
        &self,
        _edb: &[(String, Vec<Value>)],
        _rule_sources: &[String],
    ) -> Result<EvalStore> {
        bail!("DD backend not yet implemented")
    }
}

pub struct InterpreterBackend;

impl Backend for InterpreterBackend {
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
        Recursive { initial_ops: Vec<Op>, delta_plans: Vec<Op> },
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
            if let Inst::Rule { head, .. } = inst {
                if let Inst::Atom { predicate, .. } = ir.get(*head) {
                    if stratum_pred_names.contains(ir.resolve_name(*predicate)) {
                        rule_ids.push(InstId::new(i));
                    }
                }
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
                    if let Inst::Atom { predicate, .. } = ir.get(premise) {
                        if stratum_pred_names.contains(ir.resolve_name(*predicate)) {
                            is_recursive = true;
                            break 'outer;
                        }
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
            strata_plans.push(Some(StratumPlan::Recursive { initial_ops, delta_plans }));
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
            Some(StratumPlan::Recursive { initial_ops, delta_plans }) => {
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


pub struct Engine {
    /// EDB facts collected at load time; replayed on each evaluate.
    edb: Vec<(String, Vec<Value>)>,
    /// Mangle source for each rule file, plus any REPL-defined rules.
    rule_sources: Vec<String>,
    backend: Box<dyn Backend>,
    /// Lengths of edb and rule_sources after initial load — used by reset_session.
    edb_base_len: usize,
    rules_base_len: usize,
}

impl Engine {
    pub fn new(edb_store: MemStore, rules_dir: &Path, backend: Box<dyn Backend>) -> Result<Self> {
        let rule_files =
            glob::glob(&rules_dir.join("*.mg").to_string_lossy()).context("glob rules")?;

        let mut rule_sources = Vec::new();
        for entry in rule_files {
            let path = entry?;
            let src = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            rule_sources.push(src);
        }

        let edb = drain_store(edb_store);
        let edb_base_len = edb.len();
        let rules_base_len = rule_sources.len();

        Ok(Self {
            edb,
            rule_sources,
            backend,
            edb_base_len,
            rules_base_len,
        })
    }

    /// Add a new rule (from the REPL) and mark state as dirty.
    pub fn add_rule(&mut self, rule: String) {
        self.rule_sources.push(rule);
    }

    /// Return the arity of an existing EDB relation, or None if no facts exist yet.
    pub fn relation_arity(&self, relation: &str) -> Option<usize> {
        self.edb.iter().find(|(r, _)| r == relation).map(|(_, t)| t.len())
    }

    /// Insert a ground fact into the EDB. Returns true if inserted, false if already present.
    pub fn add_fact(&mut self, relation: String, tuple: Vec<Value>) -> bool {
        let entry = (relation, tuple);
        if !self.edb.contains(&entry) {
            self.edb.push(entry);
            true
        } else {
            false
        }
    }

    /// Remove a ground fact from the EDB. Returns true if a matching fact was found and removed.
    pub fn retract_fact(&mut self, relation: &str, tuple: &[Value]) -> bool {
        if let Some(pos) = self.edb.iter().position(|(r, t)| r == relation && t.as_slice() == tuple) {
            self.edb.remove(pos);
            true
        } else {
            false
        }
    }

    /// Load facts from a FactSource through the k8s projection pipeline, appending to the EDB.
    pub fn populate_from(&mut self, source: &mut dyn crate::edb::FactSource) -> Result<()> {
        let mut tmp = mangle_interpreter::MemStore::new();
        crate::edb::populate(&mut tmp, source)?;
        self.edb.extend(drain_store(tmp));
        Ok(())
    }


    /// Reset all REPL session state: drop added rules and EDB temporaries, restore
    /// to the state at initial load.
    pub fn reset_session(&mut self) {
        self.edb.truncate(self.edb_base_len);
        self.rule_sources.truncate(self.rules_base_len);
    }

    pub fn rules_len(&self) -> usize {
        self.rule_sources.len()
    }

    pub fn truncate_rules(&mut self, len: usize) {
        self.rule_sources.truncate(len);
    }


    /// Remove all rules whose head matches `predicate`.
    pub fn remove_rules_for(&mut self, predicate: &str) {
        let prefix = format!("{predicate}(");
        self.rule_sources.retain(|s| !s.trim_start().starts_with(&prefix));
    }

    pub fn compile(&self) -> Result<CompiledProgram> {
        let mut sources = vec![EDB_DECLS];
        for s in &self.rule_sources {
            sources.push(s.as_str());
        }

        CompiledProgram::new(&sources)
    }

    pub fn evaluate(&self) -> Result<EvalStore> {
        self.backend.evaluate(&self.edb, &self.rule_sources)
    }

    /// Per-relation documentation (descriptions + column types) extracted from
    /// the compiled `Decl`s. Recomputed on demand; `::show` is infrequent.
    pub fn relation_docs(&self) -> Result<HashMap<String, RelationDoc>> {
        Ok(self.compile()?.relation_docs())
    }
}

/// Drain all facts from a MemStore into a Vec for later replay.
fn drain_store(store: MemStore) -> Vec<(String, Vec<Value>)> {
    let mut out = Vec::new();
    for rel in store.relation_names() {
        let rel: String = rel;
        for tuple in store.get_facts(&rel) {
            out.push((rel.clone(), tuple));
        }
    }
    out
}
