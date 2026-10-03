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

pub(crate) const EDB_DECLS: &str = include_str!("../rules/00_edb_prelude.mg");

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

pub struct Engine {
    /// EDB facts collected at load time; replayed on each evaluate.
    edb: Vec<(String, Vec<Value>)>,
    /// Mangle source for each rule file, plus any REPL-defined rules.
    rule_sources: Vec<String>,
    backend: Box<dyn Backend>,
    /// Lengths of edb and rule_sources after initial load — used by reset_session.
    edb_base_len: usize,
    rules_base_len: usize,
    /// Persistent incremental DD session, started by `Backend::spawn_session`
    /// (present for the DD backend, absent for the interpreter).  When Some, fact
    /// mutations are fed directly to the worker rather than waiting for a full
    /// recompute.
    session: Option<crate::dd::session::DdSession>,
}

/// Load `testdata/` manifests and `rules/*.mg` files into the raw
/// `(edb, rule_sources)` pair consumed by `Backend::evaluate`.
///
/// Intended for benchmarks and integration tests; not used in the binary.
pub fn load_bench_fixtures() -> Result<(Vec<(String, Vec<Value>)>, Vec<String>)> {
    let mut store = MemStore::new();
    crate::edb::load_from_manifests(&mut store, vec!["testdata".to_string()])
        .context("load testdata")?;

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
        let rule_files =
            glob::glob(&rules_dir.join("*.mg").to_string_lossy()).context("glob rules")?;

        let mut rule_sources = Vec::new();
        for entry in rule_files {
            let path = entry?;
            let src = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            rule_sources.push(src);
        }

        Self::from_parts(drain_store(edb_store), rule_sources, backend)
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
        let edb_base_len = edb.len();
        let rules_base_len = rule_sources.len();
        // Backends with a persistent session (DD) start it here, so fact
        // mutations feed deltas to the worker rather than forcing a full
        // recompute. Rule changes still trigger a full worker rebuild.
        let session = backend.spawn_session(&edb, &rule_sources)?;
        Ok(Self {
            edb,
            rule_sources,
            backend,
            edb_base_len,
            rules_base_len,
            session,
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
        if !self.edb.contains(&entry) {
            // The DD worker drops facts for relations it has no input handle
            // for, so a brand-new relation needs the session rebuilt.
            let known = self.session.as_ref().is_none_or(|s| s.has_input(&entry.0));
            if known {
                if let Some(s) = &self.session {
                    let row = crate::dd::value::Row::from(entry.1.as_slice());
                    s.insert(entry.0.clone(), row);
                    s.commit();
                }
                self.edb.push(entry);
            } else {
                self.edb.push(entry);
                self.rebuild_session();
            }
            true
        } else {
            false
        }
    }

    /// Re-spawn the live session from the current EDB and rules, if there is one.
    fn rebuild_session(&mut self) {
        if let Some(s) = &mut self.session
            && let Err(e) = s.rebuild(&self.edb, &self.rule_sources)
        {
            eprintln!("Error rebuilding incremental session: {e:#}");
        }
    }

    /// Remove a ground fact from the EDB. Returns true if a matching fact was found and removed.
    pub fn retract_fact(&mut self, relation: &str, tuple: &[Value]) -> bool {
        if let Some(pos) = self
            .edb
            .iter()
            .position(|(r, t)| r == relation && t.as_slice() == tuple)
        {
            if let Some(s) = &self.session {
                let row = crate::dd::value::Row::from(tuple);
                s.retract(relation.to_string(), row);
                s.commit();
            }
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
        if let Some(s) = &mut self.session {
            s.rebuild(&self.edb, &self.rule_sources)?;
        }
        Ok(())
    }

    /// Reset all REPL session state: drop added rules and EDB temporaries, restore
    /// to the state at initial load.
    pub fn reset_session(&mut self) {
        self.edb.truncate(self.edb_base_len);
        self.rule_sources.truncate(self.rules_base_len);
        if let Some(s) = &mut self.session {
            let _ = s.rebuild(&self.edb, &self.rule_sources);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Load the testdata/ manifests + rules/*.mg files and return the raw
    /// (edb, rule_sources) pair that both backends consume.
    fn load_fixtures() -> Result<(Vec<(String, Vec<Value>)>, Vec<String>)> {
        let mut edb_store = MemStore::new();
        crate::edb::load_from_manifests(&mut edb_store, vec!["testdata".to_string()])
            .context("load testdata")?;
        let edb = drain_store(edb_store);

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
