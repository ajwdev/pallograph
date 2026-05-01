use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use mangle_ast::Arena;
use mangle_common::{Store, Value};
use mangle_driver::{compile_units, execute};
use mangle_interpreter::MemStore;

/// Snapshot of all derived facts after an evaluation pass.
pub struct EvalStore {
    facts: HashMap<String, Vec<Vec<Value>>>,
}

impl EvalStore {
    pub fn scan(&self, relation: &str) -> &[Vec<Value>] {
        self.facts.get(relation).map(|v| v.as_slice()).unwrap_or(&[])
    }

    pub fn relation_names(&self) -> impl Iterator<Item = &str> {
        self.facts.keys().map(String::as_str)
    }
}

/// EDB declarations prepended to the rule sources so the analyzer knows
/// which predicates are extensional (pre-loaded into the store).
const EDB_DECLS: &str = r#"
Decl k8s(ApiVersion, Kind, Namespace, Name, Data).
Decl user_groups(Username, Group).
Decl api_resource(ApiGroup, Resource).
Decl object_label(ApiVersion, Kind, Namespace, Name, LabelKey, LabelValue).
Decl selector_match_label(ApiVersion, Kind, Namespace, Name, LabelKey, LabelValue).
Decl selector_expr_in(ApiVersion, Kind, Namespace, Name, LabelKey, AllowedValue).
Decl selector_expr_notin(ApiVersion, Kind, Namespace, Name, LabelKey, ExcludedValue).
Decl selector_expr_exists(ApiVersion, Kind, Namespace, Name, LabelKey).
Decl selector_expr_notexists(ApiVersion, Kind, Namespace, Name, LabelKey).
"#;

pub struct Engine {
    /// EDB facts collected at load time; replayed on each evaluate.
    edb: Vec<(String, Vec<Value>)>,
    /// Mangle source for each rule file, plus any REPL-defined rules.
    rule_sources: Vec<String>,
}

impl Engine {
    pub fn new(edb_store: MemStore, rules_dir: &Path) -> Result<Self> {
        let rule_files = glob::glob(&rules_dir.join("*.mg").to_string_lossy())
            .context("glob rules")?;

        let mut rule_sources = Vec::new();
        for entry in rule_files {
            let path = entry?;
            let src = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            rule_sources.push(src);
        }

        // Drain the MemStore into our EDB vec for re-use on each evaluate.
        let edb = drain_store(edb_store);

        Ok(Self { edb, rule_sources })
    }

    /// Add a new rule (from the REPL) and mark state as dirty.
    pub fn add_rule(&mut self, rule: String) {
        self.rule_sources.push(rule);
    }

    /// Compile rules and run semi-naive evaluation over the current EDB.
    /// Returns a snapshot of all derived facts.
    pub fn evaluate(&self) -> Result<EvalStore> {
        // Build sources: EDB declarations + each rule file.
        let mut sources: Vec<&str> = vec![EDB_DECLS];
        for s in &self.rule_sources {
            sources.push(s);
        }

        let arena = Arena::new_with_global_interner();
        let (mut ir, stratified) =
            compile_units(&sources, &arena).context("compile rules")?;

        // Populate a fresh MemStore with EDB facts.
        let mut store = MemStore::new();
        for (rel, tuple) in &self.edb {
            store.add_fact(rel, tuple.clone());
        }

        let interpreter =
            execute(&mut ir, &stratified, Box::new(store)).context("execute")?;

        // Collect all facts into an owned map before dropping the interpreter + arena.
        let store_ref = interpreter.store();
        let mut facts: HashMap<String, Vec<Vec<Value>>> = HashMap::new();
        for rel in store_ref.relation_names() {
            let rows = store_ref
                .scan(&rel)
                .with_context(|| format!("scan {rel}"))?
                .collect::<Vec<_>>();
            facts.insert(rel, rows);
        }

        Ok(EvalStore { facts })
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
