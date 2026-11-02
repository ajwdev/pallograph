// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! What a client asks of the core: the engine, its rules and facts, and the
//! named snapshots. The REPL is the only client today, through
//! [`LocalCore`], which answers in-process; a remote client would implement
//! [`Core`] over the wire instead.
//!
//! Commands move onto the [`Core`] trait one at a time. Until one has, the
//! REPL reaches the engine and snapshots through [`LocalCore`]'s own methods.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::Result;
use kube::api::DynamicObject;
use mangle_common::Value;
use mangle_interpreter::ProvenanceEntry;

use crate::dd::session::{LazyProvenance, NegatedFact, ProofNode, ProofTree};
use crate::dd::value::Row;
use crate::delta::diff_object_sides;
use crate::edb::{ObjectFacts, expression_facts, single_object_facts};
use crate::engine::{ApplySummary, Change, Engine, EvalStore, RelationDoc};
use crate::query::{
    self, body_relations, count_top_level_args, extract_vars, single_atom, split_atom,
    split_projection, suggest,
};
use crate::selector::parse_selector;
use crate::snapshot::{Diff, FrozenState};
use crate::source::source_program;

/// Which state a read sees.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum At {
    /// The engine as it is now.
    Live,
    /// A named snapshot, frozen when it was taken.
    Snapshot(String),
}

/// Rows a query returns, one name per column.
#[derive(Debug, PartialEq)]
pub struct Rows {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
    /// Set when the query named one relation and no variables (`?- direct_perm`,
    /// or with only constants): the rows are that relation's whole tuples, so
    /// a client can print them as `relation(a, b, ...)`. `None` for variable
    /// bindings.
    pub relation: Option<String>,
}

/// Why a query was refused or failed. Each displays as the line the REPL
/// prints for it.
#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    #[error("No snapshot named '{0}'.")]
    UnknownSnapshot(String),
    /// Relations the query names that the state doesn't know, each with up to
    /// three near names.
    #[error("{}", unknown_relation_lines(.0))]
    UnknownRelations(Vec<(String, Vec<String>)>),
    #[error("{relation} has {arity} columns, got {given} arguments.")]
    TooManyArguments {
        relation: String,
        arity: usize,
        given: usize,
    },
    #[error("No variables to bind. Name one (e.g. X).")]
    NoVariables,
    #[error("Projection variable(s) not bound by the body: {}.", .0.join(", "))]
    UnboundProjection(Vec<String>),
    #[error("Parse error: {0}")]
    Parse(String),
    /// Not a `#[source]`: the message already carries the whole cause chain.
    #[error("Error: {0:#}")]
    Evaluation(anyhow::Error),
}

/// One line per unknown relation, naming any near names.
fn unknown_relation_lines(unknown: &[(String, Vec<String>)]) -> String {
    let lines: Vec<String> = unknown
        .iter()
        .map(|(name, near)| {
            if near.is_empty() {
                format!("Unknown relation '{name}'.")
            } else {
                format!(
                    "Unknown relation '{name}'. Did you mean: {}?",
                    near.join(", ")
                )
            }
        })
        .collect();
    lines.join("\n")
}

/// The core, as a client sees it.
pub trait Core {
    /// The version a read at [`At::Live`] sees (see [`Engine::version`]).
    fn version(&self) -> u64;

    /// Answer a `?-` query body: a conjunction of atoms, optionally behind an
    /// anonymous head (`_(X, Y) :- ...`) naming the columns to report. A
    /// query is a read and leaves nothing behind.
    fn query(&self, at: &At, query: &str) -> Result<Rows, QueryError>;

    /// Explain how each fact matching `fact` was derived (its provenance).
    /// `fact` is one atom: constants pick facts out and `_` (or a missing
    /// trailing argument) matches anything. No matching facts is an empty
    /// list, not an error.
    fn provenance(&self, at: &At, fact: &str) -> Result<Vec<ProvenanceTree>, ProvenanceError>;

    /// Freeze the live state as a snapshot named `name`, which reads can then
    /// name with [`At::Snapshot`].
    fn snapshot(&self, name: &str) -> Result<SnapshotInfo, SnapshotError>;

    fn has_snapshot(&self, name: &str) -> bool;

    /// The facts added and removed going from `before` to `after`, in every
    /// relation or only in `relation`.
    fn diff(&self, before: &At, after: &At, relation: Option<&str>) -> Result<Diff, DiffError>;

    /// Describe relations: with no `names`, every relation holding facts in
    /// the state, sorted by name; otherwise each of `names`, in order, known
    /// or not.
    fn relations(&self, at: &At, names: &[&str]) -> Result<Vec<RelationInfo>, ReadError>;

    /// Add a fact to the live state. `false` if it was already there.
    fn assert_fact(&self, fact: Fact) -> Result<bool, WriteError>;

    /// Remove a fact from the live state. `false` if it wasn't there.
    fn retract_fact(&self, fact: &Fact) -> Result<bool, WriteError>;

    /// Remove `old` and add `new` in one step. `false` if `old` wasn't there;
    /// `new` is added either way.
    fn replace_fact(&self, old: &Fact, new: Fact) -> Result<bool, WriteError>;

    /// Add a rule to the live state. A rule that doesn't compile or evaluate
    /// is rejected and the rules are left as they were.
    fn define(&self, rule: &str) -> Result<(), WriteError>;

    /// Add a Mangle program: its ground facts as facts, the rest as rules.
    /// All or nothing: on an error, nothing it added is kept.
    fn source(&self, program: &str) -> Result<(), WriteError>;

    /// Add rows to `relation`, all of one width. Returns how many were new.
    fn load_facts(&self, relation: &str, rows: Vec<Vec<Value>>) -> Result<usize, WriteError>;

    /// Load Kubernetes objects, each replacing any object already loaded
    /// under the same group, kind, namespace and name.
    fn load_objects(&self, objects: Vec<KubeObject>) -> Result<ApplySummary, WriteError>;

    /// Apply the change from `base` to `head` (two renders of the same
    /// manifests) to the live objects, as a GitOps sync would: head-only
    /// objects are added, changed ones replaced, base-only ones removed,
    /// and identical ones left alone so live drift survives.
    fn apply_delta(
        &self,
        base: Vec<KubeObject>,
        head: Vec<KubeObject>,
    ) -> Result<DeltaSummary, WriteError>;

    /// The objects a kubectl-style label `selector` matches in `namespace`
    /// (`""` for cluster-scoped objects), of `kind` or of any kind. A read:
    /// the selector is evaluated against the state without being added to it.
    /// Rows are `apiVersion, kind, namespace, name`, sorted.
    fn match_selector(
        &self,
        at: &At,
        kind: Option<&str>,
        namespace: &str,
        selector: &str,
    ) -> Result<Rows, MatchError>;
}

/// Why a selector match failed. Each displays as the line the REPL prints
/// for it.
#[derive(Debug, thiserror::Error)]
pub enum MatchError {
    #[error("Selector parse error: {0:#}")]
    Selector(anyhow::Error),
    #[error("No snapshot named '{0}'.")]
    UnknownSnapshot(String),
    #[error("Error: {0:#}")]
    Evaluation(anyhow::Error),
}

/// A Kubernetes object as read from a cluster or manifest, with its
/// (apiVersion, kind) when the source gives them separately (cluster lists
/// leave them off each item). The core turns objects into facts itself, so
/// they always match its rules.
pub type KubeObject = (DynamicObject, Option<(String, String)>);

/// What [`Core::apply_delta`] did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DeltaSummary {
    pub added: usize,
    pub updated: usize,
    pub removed: usize,
    /// In both renders with the same content, so left as live has it.
    pub unchanged: usize,
    /// Removed by the delta but already gone from the live state.
    pub removed_absent: usize,
}

/// A relation, as `show` describes it.
#[derive(Debug, Clone)]
pub struct RelationInfo {
    pub name: String,
    /// The width of the relation's rows, when the state holds any.
    pub arity: Option<usize>,
    /// From the relation's `Decl`, if it has one.
    pub doc: Option<RelationDoc>,
}

/// One ground fact: a relation and a row of constants.
#[derive(Debug, Clone, PartialEq)]
pub struct Fact {
    pub relation: String,
    pub row: Vec<Value>,
}

/// Why a write was refused or failed. Each displays as the line the REPL
/// prints for it.
#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    #[error("arity mismatch: {relation}/{arity} expects {arity} arg(s), got {given}")]
    ArityMismatch {
        relation: String,
        arity: usize,
        given: usize,
    },
    /// A row in a batch for [`Core::load_facts`] was the wrong width; none
    /// of the batch was added.
    #[error(
        "Load error: arity mismatch: {relation}/{arity} expects {arity} column(s), \
         but tuple {index} has {given} — check your query or source"
    )]
    RowArityMismatch {
        relation: String,
        arity: usize,
        index: usize,
        given: usize,
    },
    /// The write landed but the state didn't evaluate afterwards, or a rule
    /// was rejected.
    #[error("Error: {0:#}")]
    Evaluation(anyhow::Error),
}

/// A snapshot just taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotInfo {
    pub name: String,
    /// Relations holding at least one fact.
    pub relations: usize,
    pub facts: usize,
}

/// Why a snapshot wasn't taken. Each displays as the line the REPL prints
/// for it.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("Snapshot names cannot be empty or contain spaces.")]
    InvalidName,
    #[error("Snapshot '{0}' already exists.")]
    AlreadyExists(String),
    #[error("Error: {0:#}")]
    Evaluation(anyhow::Error),
}

/// Why a diff failed. Each displays as the line the REPL prints for it.
#[derive(Debug, thiserror::Error)]
pub enum DiffError {
    #[error("No snapshot named '{0}'.")]
    UnknownSnapshot(String),
    /// A relation the program never declares or derives would diff as
    /// empty, which is misleading.
    #[error("Unknown relation '{0}'.")]
    UnknownRelation(String),
    #[error("Error: {0:#}")]
    Evaluation(anyhow::Error),
}

/// How deep a provenance tree goes before its branches stop at
/// [`Derivation::DepthLimit`].
const PROVENANCE_MAX_DEPTH: usize = 12;

/// A fact and how it came to hold.
#[derive(Debug, Clone, PartialEq)]
pub struct ProvenanceTree {
    pub relation: String,
    pub row: Vec<Value>,
    pub derivation: Derivation,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Derivation {
    /// Loaded from the cluster or added, not derived (EDB).
    Input,
    /// Derived by a rule. A fact derivable several ways still gets one proof:
    /// the interpreter records only the derivation that first inserted it,
    /// and the DD backend rebuilds one with the fewest steps.
    Rule(RuleApplication),
    /// Derived by a rule with no positive premises.
    NoPremises,
    /// The fact is already being explained further up this branch.
    Cycle,
    /// Deeper than the limit, so not expanded.
    DepthLimit,
    /// Provenance has no answer for this fact.
    Unexplained(Unexplained),
}

/// One rule firing: the facts it joined, and the negated premises that held
/// because no matching fact existed.
#[derive(Debug, Clone, PartialEq)]
pub struct RuleApplication {
    pub premises: Vec<ProvenanceTree>,
    pub absent: Vec<AbsentFact>,
}

/// A negated premise, `!relation(args)`, that held. `None` marks a position
/// the rule left open.
#[derive(Debug, Clone, PartialEq)]
pub struct AbsentFact {
    pub relation: String,
    pub args: Vec<Option<Value>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unexplained {
    /// The session records no provenance.
    NotRecorded,
    /// The snapshot was taken without provenance.
    NotCaptured,
    /// The relation has no provenance annotations.
    NotTracked,
    /// A fact with no annotation, which is a provenance bug.
    NoAnnotation,
    /// No grounding of the fact's rule was found.
    NoGrounding,
}

impl Unexplained {
    pub fn reason(self) -> &'static str {
        match self {
            Unexplained::NotRecorded => "no provenance for this session",
            Unexplained::NotCaptured => "no provenance captured for this snapshot",
            Unexplained::NotTracked => "no provenance tracked for this relation",
            Unexplained::NoAnnotation => "no annotation: provenance bug",
            Unexplained::NoGrounding => "no grounding found",
        }
    }
}

/// Why a provenance request was refused or failed. Each displays as the line
/// the REPL prints for it.
#[derive(Debug, thiserror::Error)]
pub enum ProvenanceError {
    #[error(
        "why needs provenance, which is off for this session. Re-run with \
         `--backend dd --provenance`, or use `--backend interpreter`."
    )]
    NotEnabled,
    #[error("No snapshot named '{0}'.")]
    UnknownSnapshot(String),
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("Error: {0:#}")]
    Evaluation(anyhow::Error),
}

/// The state a read at an [`At`] resolved to.
enum State<'a> {
    Live(Arc<EvalStore>),
    Frozen(&'a FrozenState),
}

impl State<'_> {
    fn store(&self) -> &EvalStore {
        match self {
            State::Live(store) => store,
            State::Frozen(frozen) => &frozen.store,
        }
    }

    fn frozen(&self) -> Option<&FrozenState> {
        match self {
            State::Live(_) => None,
            State::Frozen(frozen) => Some(frozen),
        }
    }
}

/// Why a read at an [`At`] failed: the snapshot doesn't exist, or the live
/// state didn't evaluate. Methods with more ways to fail take it into their
/// own error type.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error("No snapshot named '{0}'.")]
    UnknownSnapshot(String),
    #[error("Error: {0:#}")]
    Evaluation(anyhow::Error),
}

impl From<ReadError> for QueryError {
    fn from(error: ReadError) -> Self {
        match error {
            ReadError::UnknownSnapshot(name) => QueryError::UnknownSnapshot(name),
            ReadError::Evaluation(e) => QueryError::Evaluation(e),
        }
    }
}

impl From<ReadError> for ProvenanceError {
    fn from(error: ReadError) -> Self {
        match error {
            ReadError::UnknownSnapshot(name) => ProvenanceError::UnknownSnapshot(name),
            ReadError::Evaluation(e) => ProvenanceError::Evaluation(e),
        }
    }
}

impl From<ReadError> for DiffError {
    fn from(error: ReadError) -> Self {
        match error {
            ReadError::UnknownSnapshot(name) => DiffError::UnknownSnapshot(name),
            ReadError::Evaluation(e) => DiffError::Evaluation(e),
        }
    }
}

/// The live state evaluated at some engine version.
struct LiveStore {
    version: u64,
    store: Arc<EvalStore>,
}

/// The core, in-process. Owns the shared engine (which a cluster watcher may
/// also be feeding), the named snapshots, and the live state last evaluated
/// from the engine, which it re-evaluates once the engine's version moves.
///
/// Locks are taken engine first, then snapshots, then the live state.
pub struct LocalCore {
    engine: Arc<Mutex<Engine>>,
    snapshots: Mutex<BTreeMap<String, FrozenState>>,
    live: Mutex<LiveStore>,
}

impl LocalCore {
    /// `live` is the engine's state, already evaluated at its current version.
    pub fn new(engine: Arc<Mutex<Engine>>, live: EvalStore) -> Self {
        let version = lock(&engine).version();
        LocalCore {
            engine,
            snapshots: Mutex::new(BTreeMap::new()),
            live: Mutex::new(LiveStore {
                version,
                store: Arc::new(live),
            }),
        }
    }

    /// Hold the engine, for a command not yet on [`Core`].
    pub fn engine(&self) -> MutexGuard<'_, Engine> {
        lock(&self.engine)
    }

    /// Hold the named snapshots, for a command not yet on [`Core`]. Take
    /// the engine first if the command needs both.
    pub fn snapshots(&self) -> MutexGuard<'_, BTreeMap<String, FrozenState>> {
        lock(&self.snapshots)
    }

    /// The live state at `engine`'s current version, evaluating it again only
    /// if the version moved since it was last evaluated. `engine` is the one
    /// this core owns, already held by the caller.
    pub fn live_store(&self, engine: &Engine) -> Result<Arc<EvalStore>> {
        let mut live = lock(&self.live);
        if live.version != engine.version() {
            live.store = Arc::new(engine.evaluate()?);
            live.version = engine.version();
        }
        Ok(Arc::clone(&live.store))
    }

    /// Keep `store`, which the caller just evaluated from `engine`, as the
    /// live state, so the next read doesn't evaluate it again.
    pub fn remember_live(&self, engine: &Engine, store: EvalStore) -> Arc<EvalStore> {
        let store = Arc::new(store);
        *lock(&self.live) = LiveStore {
            version: engine.version(),
            store: Arc::clone(&store),
        };
        store
    }

    /// Catch the live state up after a write. A DD session already holds the
    /// change and the next read reads it from there, so a run of writes stays
    /// fast. The interpreter evaluates now, so a write that breaks a rule
    /// fails here rather than on some later read.
    fn settle(&self, engine: &Engine) -> Result<(), WriteError> {
        if !engine.has_session() {
            let store = engine.evaluate().map_err(WriteError::Evaluation)?;
            self.remember_live(engine, store);
        }
        Ok(())
    }

    /// Evaluate the live state now and keep it, for the loading writes,
    /// which report the state as evaluated on both backends.
    fn evaluate_live(&self, engine: &Engine) -> Result<(), WriteError> {
        let store = engine.evaluate().map_err(WriteError::Evaluation)?;
        self.remember_live(engine, store);
        Ok(())
    }

    /// The live state as last evaluated, which may be behind the engine.
    /// For tab completion, where an older list of relations is fine.
    pub fn last_live(&self) -> Arc<EvalStore> {
        Arc::clone(&lock(&self.live).store)
    }

    /// Resolve `at` to the state a read sees. `engine` and `snapshots` are
    /// this core's, already held by the caller.
    fn read_state<'a>(
        &self,
        engine: &Engine,
        snapshots: &'a BTreeMap<String, FrozenState>,
        at: &At,
    ) -> Result<State<'a>, ReadError> {
        match at {
            At::Live => self
                .live_store(engine)
                .map(State::Live)
                .map_err(ReadError::Evaluation),
            At::Snapshot(name) => snapshots
                .get(name)
                .map(State::Frozen)
                .ok_or_else(|| ReadError::UnknownSnapshot(name.clone())),
        }
    }

    /// Every row of `relation` matching the constants in `body`: `_` and
    /// missing trailing arguments match anything. On the live state with a
    /// DD session, the rows come straight from the session.
    fn tuples(
        &self,
        engine: &Engine,
        store: &EvalStore,
        live: bool,
        relation: &str,
        body: &str,
        columns: &[String],
    ) -> Result<Rows, QueryError> {
        let session_rows: Vec<Vec<Value>>;
        let rows: &[Vec<Value>] = if live && engine.has_session() {
            session_rows = engine
                .query_live(relation)
                .map_err(QueryError::Evaluation)?;
            &session_rows
        } else {
            store.scan(relation)
        };
        let parsed = match split_atom(body) {
            Some((_, inner)) if !inner.trim().is_empty() => {
                query::parse_query(body).map_err(|e| QueryError::Parse(e.to_string()))?
            }
            _ => query::ParsedQuery {
                predicate: relation.to_string(),
                args: vec![],
            },
        };
        let matched: Vec<Vec<Value>> = query::filter_tuples(rows, &parsed)
            .into_iter()
            .cloned()
            .collect();
        let width = matched.iter().map(Vec::len).max().unwrap_or(0);
        Ok(Rows {
            columns: (0..width)
                .map(|i| columns.get(i).cloned().unwrap_or_else(|| format!("c{i}")))
                .collect(),
            rows: matched,
            relation: Some(relation.to_string()),
        })
    }
}

impl Core for LocalCore {
    fn version(&self) -> u64 {
        self.engine().version()
    }

    fn query(&self, at: &At, query: &str) -> Result<Rows, QueryError> {
        let engine = self.engine();
        let snapshots = self.snapshots();
        let state = self.read_state(&engine, &snapshots, at)?;
        let store = state.store();

        let (projection, body) = split_projection(query.trim());
        // A typo'd relation is an empty result on the interpreter and an
        // opaque error on DD; catch it up front either way.
        let known = match at {
            At::Live => {
                let mut known = engine.known_relations();
                known.extend(store.relation_names().map(str::to_string));
                known
            }
            At::Snapshot(_) => known_relations_in_use(&engine, store),
        };
        let unknown: Vec<(String, Vec<String>)> = body_relations(body)
            .into_iter()
            .filter(|relation| !known.contains(relation))
            .map(|relation| {
                let near = suggest(&relation, &known);
                (relation, near)
            })
            .collect();
        if !unknown.is_empty() {
            return Err(QueryError::UnknownRelations(unknown));
        }

        let existing = extract_vars(body);
        let single = single_atom(body);
        let columns = single
            .map(|relation| column_keys(&engine, relation))
            .unwrap_or_default();
        if let Some(relation) = single {
            let given = split_atom(body).map_or(0, |(_, inner)| count_top_level_args(inner));
            if let Some(arity) = relation_arity(store, relation, &columns)
                && given > arity
            {
                return Err(QueryError::TooManyArguments {
                    relation: relation.to_string(),
                    arity,
                    given,
                });
            }
            // No named variables: list whole tuples, not bindings.
            if existing.is_empty() {
                let live = *at == At::Live;
                return self.tuples(&engine, store, live, relation, body, &columns);
            }
        } else if existing.is_empty() {
            return Err(QueryError::NoVariables);
        }

        let (completed, mut vars) = match auto_complete_partial(body, store, &columns) {
            Some((completed, added)) => {
                let mut all = existing;
                all.extend(added);
                (completed, all)
            }
            None => (body.to_string(), existing),
        };
        // A projection narrows the reported columns to the named variables;
        // each must be bound somewhere in the body.
        if let Some(projection) = projection {
            let unbound: Vec<String> = projection
                .iter()
                .filter(|name| !vars.contains(name))
                .cloned()
                .collect();
            if !unbound.is_empty() {
                return Err(QueryError::UnboundProjection(unbound));
            }
            vars = projection;
        }

        // Evaluate just the query rule over the state's facts and keep
        // nothing: the engine's rules and facts are left alone.
        let result_name = "__query";
        let rule = format!("{result_name}({}) :- {completed}.", vars.join(", "));
        let result = engine
            .evaluate_query_on(store, &body_relations(body), rule)
            .map_err(QueryError::Evaluation)?;
        Ok(Rows {
            columns: vars,
            rows: result.scan(result_name).to_vec(),
            relation: None,
        })
    }

    fn provenance(&self, at: &At, fact: &str) -> Result<Vec<ProvenanceTree>, ProvenanceError> {
        let engine = self.engine();
        if !engine.supports_provenance() {
            return Err(ProvenanceError::NotEnabled);
        }
        let snapshots = self.snapshots();
        let state = self.read_state(&engine, &snapshots, at)?;
        let (store, frozen) = (state.store(), state.frozen());
        let parsed =
            query::parse_query(fact.trim()).map_err(|e| ProvenanceError::Parse(e.to_string()))?;
        let relation = parsed.predicate.as_str();

        // A live DD session holds the current rows; a frozen snapshot is
        // read from its own store, as it has no session.
        let session_rows: Vec<Vec<Value>>;
        let rows: &[Vec<Value>] = if frozen.is_none() && engine.has_session() {
            session_rows = engine
                .query_live(relation)
                .map_err(ProvenanceError::Evaluation)?;
            &session_rows
        } else {
            store.scan(relation)
        };
        let matched = query::filter_tuples(rows, &parsed);

        if engine.has_session() {
            // DD: one shortest proof, rebuilt on demand from the live
            // session's annotations, or from the copy a snapshot froze.
            let provenance: Option<&dyn LazyProvenance> = match frozen {
                Some(frozen) => frozen
                    .lazy_provenance
                    .as_ref()
                    .map(|p| p as &dyn LazyProvenance),
                None => engine
                    .provenance_session()
                    .map(|s| s as &dyn LazyProvenance),
            };
            Ok(matched
                .into_iter()
                .map(|tuple| {
                    let derivation = match provenance {
                        None if frozen.is_some() => {
                            Derivation::Unexplained(Unexplained::NotCaptured)
                        }
                        None => Derivation::Unexplained(Unexplained::NotRecorded),
                        Some(provenance) if !provenance.has_provenance_for(relation) => {
                            Derivation::Unexplained(Unexplained::NotTracked)
                        }
                        Some(provenance) => {
                            let row = Row::from(tuple.as_slice());
                            let annotation = provenance.why_height(relation, &row);
                            // One round trip builds the whole tree; map it here.
                            let tree = provenance.why_proof(
                                relation,
                                &row,
                                annotation,
                                PROVENANCE_MAX_DEPTH,
                            );
                            proof_node_to_derivation(tree.node)
                        }
                    };
                    ProvenanceTree {
                        relation: relation.to_string(),
                        row: tuple.clone(),
                        derivation,
                    }
                })
                .collect())
        } else {
            // Interpreter: the store (frozen under a snapshot) carries the
            // derivation it recorded for each fact.
            let index = recorded_derivations(&store.provenance);
            Ok(matched
                .into_iter()
                .map(|tuple| ProvenanceTree {
                    relation: relation.to_string(),
                    row: tuple.clone(),
                    derivation: recorded_derivation(&index, relation, tuple, 1, &mut Vec::new()),
                })
                .collect())
        }
    }

    fn snapshot(&self, name: &str) -> Result<SnapshotInfo, SnapshotError> {
        if name.is_empty() || name.contains(char::is_whitespace) {
            return Err(SnapshotError::InvalidName);
        }
        let engine = self.engine();
        let mut snapshots = self.snapshots();
        if snapshots.contains_key(name) {
            return Err(SnapshotError::AlreadyExists(name.to_string()));
        }
        // On DD the provenance lives in the session, not the store, so `why`
        // under the snapshot needs its own copy.
        let lazy_provenance = engine
            .provenance_session()
            .map(|session| session.freeze_provenance())
            .transpose()
            .map_err(SnapshotError::Evaluation)?;
        let store = self
            .live_store(&engine)
            .map_err(SnapshotError::Evaluation)?
            .frozen_copy();
        let info = SnapshotInfo {
            name: name.to_string(),
            relations: store
                .relation_names()
                .filter(|relation| !store.scan(relation).is_empty())
                .count(),
            facts: store
                .relation_names()
                .map(|relation| store.scan(relation).len())
                .sum(),
        };
        snapshots.insert(
            name.to_string(),
            FrozenState {
                store,
                lazy_provenance,
                inputs: engine.save_inputs(),
            },
        );
        Ok(info)
    }

    fn has_snapshot(&self, name: &str) -> bool {
        self.snapshots().contains_key(name)
    }

    fn diff(&self, before: &At, after: &At, relation: Option<&str>) -> Result<Diff, DiffError> {
        let engine = self.engine();
        let snapshots = self.snapshots();
        let before = self.read_state(&engine, &snapshots, before)?;
        let after = self.read_state(&engine, &snapshots, after)?;
        if let Some(relation) = relation
            && !engine.known_relations().contains(relation)
        {
            return Err(DiffError::UnknownRelation(relation.to_string()));
        }
        let mut diff = Diff::between(before.store(), after.store());
        if let Some(relation) = relation {
            diff.added.retain(|name, _| name == relation);
            diff.removed.retain(|name, _| name == relation);
        }
        Ok(diff)
    }

    fn relations(&self, at: &At, names: &[&str]) -> Result<Vec<RelationInfo>, ReadError> {
        let engine = self.engine();
        let snapshots = self.snapshots();
        let state = self.read_state(&engine, &snapshots, at)?;
        let store = state.store();
        let mut docs = engine.relation_docs().unwrap_or_default();
        let names: Vec<String> = if names.is_empty() {
            // Names starting with `:` are built-ins, not relations anyone
            // declared.
            let mut held: Vec<String> = store
                .relation_names()
                .filter(|name| !name.starts_with(':'))
                .map(str::to_string)
                .collect();
            held.sort_unstable();
            held
        } else {
            names.iter().map(|name| name.to_string()).collect()
        };
        Ok(names
            .into_iter()
            .map(|name| RelationInfo {
                arity: store.scan(&name).first().map(Vec::len),
                doc: docs.remove(&name),
                name,
            })
            .collect())
    }

    fn assert_fact(&self, fact: Fact) -> Result<bool, WriteError> {
        let mut engine = self.engine();
        check_arity(&engine, &fact)?;
        if !engine.add_fact(fact.relation, fact.row) {
            return Ok(false);
        }
        self.settle(&engine)?;
        Ok(true)
    }

    fn retract_fact(&self, fact: &Fact) -> Result<bool, WriteError> {
        let mut engine = self.engine();
        if !engine.retract_fact(&fact.relation, &fact.row) {
            return Ok(false);
        }
        self.settle(&engine)?;
        Ok(true)
    }

    fn replace_fact(&self, old: &Fact, new: Fact) -> Result<bool, WriteError> {
        let mut engine = self.engine();
        check_arity(&engine, &new)?;
        let removed = engine.retract_fact(&old.relation, &old.row);
        engine.add_fact(new.relation, new.row);
        self.settle(&engine)?;
        Ok(removed)
    }

    fn define(&self, rule: &str) -> Result<(), WriteError> {
        let mut engine = self.engine();
        let checkpoint = engine.rules_len();
        let rule = format!("{}.", rule.trim().trim_end_matches('.').trim());
        let result = engine.add_rule(rule).and_then(|()| engine.evaluate());
        match result {
            Ok(store) => {
                self.remember_live(&engine, store);
                Ok(())
            }
            Err(e) => {
                engine.truncate_rules(checkpoint);
                Err(WriteError::Evaluation(e))
            }
        }
    }

    fn source(&self, program: &str) -> Result<(), WriteError> {
        let mut engine = self.engine();
        let store = source_program(&mut engine, program).map_err(WriteError::Evaluation)?;
        self.remember_live(&engine, store);
        Ok(())
    }

    fn load_facts(&self, relation: &str, rows: Vec<Vec<Value>>) -> Result<usize, WriteError> {
        let mut engine = self.engine();
        // Rows must match the relation's existing facts, or else each other.
        let width = engine
            .relation_arity(relation)
            .or_else(|| rows.first().map(Vec::len));
        if let Some(arity) = width
            && let Some((index, row)) = rows.iter().enumerate().find(|(_, row)| row.len() != arity)
        {
            return Err(WriteError::RowArityMismatch {
                relation: relation.to_string(),
                arity,
                index,
                given: row.len(),
            });
        }
        let inserted = engine.add_facts(rows.into_iter().map(|row| (relation.to_string(), row)));
        self.evaluate_live(&engine)?;
        Ok(inserted)
    }

    fn load_objects(&self, objects: Vec<KubeObject>) -> Result<ApplySummary, WriteError> {
        let objects = project(&objects);
        let mut engine = self.engine();
        let summary = engine.upsert_objects(objects);
        self.evaluate_live(&engine)?;
        Ok(summary)
    }

    fn apply_delta(
        &self,
        base: Vec<KubeObject>,
        head: Vec<KubeObject>,
    ) -> Result<DeltaSummary, WriteError> {
        let (changes, added, updated, unchanged) =
            diff_object_sides(project(&base), project(&head));
        let removed = changes
            .iter()
            .filter(|change| matches!(change, Change::Retract(_)))
            .count();
        let mut engine = self.engine();
        let applied = engine.apply_changes(changes);
        self.evaluate_live(&engine)?;
        Ok(DeltaSummary {
            added,
            updated,
            removed,
            unchanged,
            removed_absent: applied.removed_absent,
        })
    }

    fn match_selector(
        &self,
        at: &At,
        kind: Option<&str>,
        namespace: &str,
        selector: &str,
    ) -> Result<Rows, MatchError> {
        let expressions = parse_selector(selector).map_err(MatchError::Selector)?;
        // The selector's facts, owned by a query object no real object can
        // collide with; `labels.mg` matches them like any selector.
        let owner = vec![
            Value::String("pallograph.dev/query".to_string()),
            Value::String("Match".to_string()),
            Value::String(namespace.to_string()),
            Value::String("query".to_string()),
        ];
        let facts: Vec<(String, Vec<Value>)> = expressions
            .iter()
            .flat_map(|expression| expression_facts(&owner, expression))
            .map(|(relation, args)| (relation.to_string(), args))
            .collect();

        let engine = self.engine();
        let snapshots = self.snapshots();
        let inputs = match at {
            At::Live => None,
            At::Snapshot(name) => Some(
                &snapshots
                    .get(name)
                    .ok_or_else(|| MatchError::UnknownSnapshot(name.clone()))?
                    .inputs,
            ),
        };
        let store = engine
            .evaluate_with(inputs, &facts)
            .map_err(MatchError::Evaluation)?;

        // selector_matches columns: 0 SelApiVersion, 1 SelKind, 2
        // SelNamespace, 3 SelName, 4 ObjApiVersion, 5 ObjKind, 6
        // ObjNamespace, 7 ObjName. Only objects in `namespace` count, like
        // `kubectl -n`: labels.mg also pairs a namespaced selector with
        // cluster-scoped objects, which negative selectors (matching by
        // absence) would otherwise surface.
        let namespace = Value::String(namespace.to_string());
        let kind = kind.map(|kind| Value::String(kind.to_string()));
        let mut rows: Vec<Vec<Value>> = store
            .scan("selector_matches")
            .iter()
            .filter(|row| row.len() == 8 && row[0..4] == owner[..])
            .filter(|row| row[6] == namespace)
            .filter(|row| kind.as_ref().is_none_or(|kind| row[5] == *kind))
            .map(|row| row[4..8].to_vec())
            .collect();
        rows.sort();
        Ok(Rows {
            columns: ["apiVersion", "kind", "namespace", "name"]
                .map(str::to_string)
                .to_vec(),
            rows,
            relation: None,
        })
    }
}

/// Turn objects into the facts each emits, keyed by object.
fn project(objects: &[KubeObject]) -> Vec<ObjectFacts> {
    objects
        .iter()
        .map(|(object, type_hint)| {
            let type_hint = type_hint
                .as_ref()
                .map(|(api_version, kind)| (api_version.as_str(), kind.as_str()));
            single_object_facts(object, type_hint)
        })
        .collect()
}

/// Refuse a fact whose width doesn't match its relation's existing facts.
fn check_arity(engine: &Engine, fact: &Fact) -> Result<(), WriteError> {
    match engine.relation_arity(&fact.relation) {
        Some(arity) if arity != fact.row.len() => Err(WriteError::ArityMismatch {
            relation: fact.relation.clone(),
            arity,
            given: fact.row.len(),
        }),
        _ => Ok(()),
    }
}

/// The premises the interpreter recorded for each derived fact, keyed by
/// the fact. It records a fact only when an insert first adds it, so there
/// is one entry per fact.
type RecordedDerivations = HashMap<(String, Vec<Value>), Vec<(String, Vec<Value>)>>;

fn recorded_derivations(entries: &[ProvenanceEntry]) -> RecordedDerivations {
    let mut index = RecordedDerivations::new();
    for entry in entries {
        index
            .entry(entry.derived.clone())
            .or_insert_with(|| entry.premises.clone());
    }
    index
}

/// How the interpreter derived `relation(row)`, as it recorded it.
/// `visited` holds the facts being explained further up this branch, so a
/// recursive rule stops at [`Derivation::Cycle`] instead of looping.
fn recorded_derivation(
    index: &RecordedDerivations,
    relation: &str,
    row: &[Value],
    depth: usize,
    visited: &mut Vec<(String, Vec<Value>)>,
) -> Derivation {
    if depth > PROVENANCE_MAX_DEPTH {
        return Derivation::DepthLimit;
    }
    let key = (relation.to_string(), row.to_vec());
    if visited.contains(&key) {
        return Derivation::Cycle;
    }
    let Some(premises) = index.get(&key) else {
        return Derivation::Input;
    };
    visited.push(key);
    let premises = premises
        .iter()
        .map(|(premise_relation, premise_row)| ProvenanceTree {
            relation: premise_relation.clone(),
            row: premise_row.clone(),
            derivation: recorded_derivation(
                index,
                premise_relation,
                premise_row,
                depth + 1,
                visited,
            ),
        })
        .collect();
    visited.pop();
    Derivation::Rule(RuleApplication {
        premises,
        absent: Vec::new(),
    })
}

/// Map a reconstructed [`ProofTree`] to the API's [`ProvenanceTree`]. Pure: the
/// dd layer already built the whole tree in one pass, so this just converts
/// types (no further provenance queries).
fn proof_tree_to_provenance(tree: ProofTree) -> ProvenanceTree {
    ProvenanceTree {
        relation: tree.rel,
        row: tree.row.into_values(),
        derivation: proof_node_to_derivation(tree.node),
    }
}

/// Map a [`ProofNode`] to the API's [`Derivation`].
fn proof_node_to_derivation(node: ProofNode) -> Derivation {
    match node {
        ProofNode::Input => Derivation::Input,
        ProofNode::NoPremises => Derivation::NoPremises,
        ProofNode::DepthLimit => Derivation::DepthLimit,
        ProofNode::NoAnnotation => Derivation::Unexplained(Unexplained::NoAnnotation),
        ProofNode::NoGrounding => Derivation::Unexplained(Unexplained::NoGrounding),
        ProofNode::Rule { premises, negated } => Derivation::Rule(RuleApplication {
            premises: premises.into_iter().map(proof_tree_to_provenance).collect(),
            absent: negated.into_iter().map(absent_fact).collect(),
        }),
    }
}

/// Map a reconstructed negated premise to the API's [`AbsentFact`].
fn absent_fact(negated: NegatedFact) -> AbsentFact {
    AbsentFact {
        relation: negated.rel,
        args: negated
            .args
            .into_iter()
            .map(|a| a.map(Value::from))
            .collect(),
    }
}

/// Lock `mutex`, treating a poisoned lock (a panic while it was held) as
/// fatal.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().expect("lock poisoned")
}

/// The declared column names for a relation, in order, for use as NDJSON keys.
/// Empty when the relation has no `Decl` (callers fall back to positional keys).
fn column_keys(engine: &Engine, relation: &str) -> Vec<String> {
    engine
        .relation_docs()
        .ok()
        .and_then(|docs| {
            docs.get(relation)
                .map(|d| d.columns.iter().map(|c| c.name.clone()).collect())
        })
        .unwrap_or_default()
}

/// Column count of `rel`: from a stored row, else from its Decl.
fn relation_arity(store: &EvalStore, rel: &str, cols: &[String]) -> Option<usize> {
    store
        .scan(rel)
        .first()
        .map(|t| t.len())
        .or_else(|| (!cols.is_empty()).then_some(cols.len()))
}

/// Relation names a `?-` query may reference under `use <name>`: every
/// relation the frozen store actually holds rows or keys for, plus any
/// relation with a `Decl` (covers one with no rows at snapshot time). Unlike
/// `Engine::known_relations`, this leaves out a relation `define` added
/// after the snapshot was taken: it did not exist in the frozen state, so a
/// query against it is unknown, not merely empty.
fn known_relations_in_use(engine: &Engine, active: &EvalStore) -> HashSet<String> {
    let mut known: HashSet<String> = engine
        .relation_docs()
        .map(|docs| docs.into_keys().collect())
        .unwrap_or_default();
    known.extend(active.relation_names().map(str::to_string));
    known
}

/// If `body` is a single atom with named variables but fewer arguments than the
/// relation has columns, pad the rest with `_` so Mangle sees the right arity.
/// Returns (new_body, extra_vars) or None if no padding is needed or the arity
/// is unknown.
fn auto_complete_partial(
    body: &str,
    store: &EvalStore,
    cols: &[String],
) -> Option<(String, Vec<String>)> {
    let (rel, inner) = split_atom(body)?;
    let arity = relation_arity(store, rel, cols)?;
    let given = count_top_level_args(inner);
    if given == 0 || given >= arity {
        return None;
    }
    let padding = std::iter::repeat_n("_", arity - given)
        .collect::<Vec<_>>()
        .join(", ");
    Some((format!("{rel}({inner}, {padding})"), vec![]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Backend, DdBackend, InterpreterBackend};
    use std::collections::BTreeSet;

    fn s(text: &str) -> Value {
        Value::String(text.to_string())
    }

    /// `edge` facts a→b→c and `path` as their transitive closure, on each
    /// backend.
    fn cores() -> Vec<LocalCore> {
        let edb = vec![
            ("edge".to_string(), vec![s("a"), s("b")]),
            ("edge".to_string(), vec![s("b"), s("c")]),
        ];
        let rules = vec![
            "Decl edge(Src, Dst).\nDecl path(Src, Dst).\n\
             path(X, Y) :- edge(X, Y).\n\
             path(X, Z) :- path(X, Y), edge(Y, Z)."
                .to_string(),
        ];
        let backends: [Box<dyn Backend>; 2] = [
            Box::new(InterpreterBackend),
            Box::new(DdBackend { provenance: false }),
        ];
        backends
            .into_iter()
            .map(|backend| {
                let engine = Engine::from_parts(edb.clone(), rules.clone(), backend).unwrap();
                let live = engine.evaluate().unwrap();
                LocalCore::new(Arc::new(Mutex::new(engine)), live)
            })
            .collect()
    }

    fn sorted(mut rows: Rows) -> Rows {
        rows.rows.sort();
        rows
    }

    #[test]
    fn query_returns_bindings_and_tuples() {
        for core in cores() {
            let bindings = sorted(core.query(&At::Live, "path(\"a\", Y)").unwrap());
            assert_eq!(bindings.columns, ["Y"]);
            assert_eq!(bindings.rows, [vec![s("b")], vec![s("c")]]);
            assert_eq!(bindings.relation, None);

            let tuples = sorted(core.query(&At::Live, "path(\"a\")").unwrap());
            assert_eq!(tuples.columns, ["Src", "Dst"], "named from the Decl");
            assert_eq!(tuples.rows, [vec![s("a"), s("b")], vec![s("a"), s("c")]]);
            assert_eq!(tuples.relation.as_deref(), Some("path"));

            let projected = sorted(core.query(&At::Live, "_(X) :- path(X, \"c\")").unwrap());
            assert_eq!(projected.columns, ["X"]);
            assert_eq!(projected.rows, [vec![s("a")], vec![s("b")]]);
        }
    }

    #[test]
    fn query_refusals_name_the_problem() {
        for core in cores() {
            let error = |query: &str| core.query(&At::Live, query).unwrap_err().to_string();
            assert_eq!(
                error("paht(X, Y)"),
                "Unknown relation 'paht'. Did you mean: path?"
            );
            assert_eq!(
                error("path(A, B, C)"),
                "path has 2 columns, got 3 arguments."
            );
            assert_eq!(
                error("path(\"a\", \"b\"), edge(\"a\", \"b\")"),
                "No variables to bind. Name one (e.g. X)."
            );
            assert_eq!(
                error("_(Z) :- path(X, Y)"),
                "Projection variable(s) not bound by the body: Z."
            );
            assert_eq!(
                core.query(&At::Snapshot("nope".to_string()), "path(X, Y)")
                    .unwrap_err()
                    .to_string(),
                "No snapshot named 'nope'."
            );
        }
    }

    /// A read at a snapshot sees the facts as they were when it was taken,
    /// and a read at the live state picks up a change on its own: the live
    /// state is evaluated again once the engine's version moves.
    #[test]
    fn snapshot_reads_stay_frozen_while_live_follows_the_engine() {
        for core in cores() {
            {
                let engine = core.engine();
                let frozen = core.live_store(&engine).unwrap().frozen_copy();
                core.snapshots().insert(
                    "before".to_string(),
                    FrozenState {
                        store: frozen,
                        lazy_provenance: None,
                        inputs: engine.save_inputs(),
                    },
                );
            }
            core.engine()
                .add_fact("edge".to_string(), vec![s("c"), s("d")]);

            let query = "path(\"a\", Y)";
            let live = sorted(core.query(&At::Live, query).unwrap());
            assert_eq!(live.rows, [vec![s("b")], vec![s("c")], vec![s("d")]]);
            let before = sorted(
                core.query(&At::Snapshot("before".to_string()), query)
                    .unwrap(),
            );
            assert_eq!(before.rows, [vec![s("b")], vec![s("c")]]);
        }
    }

    /// A diamond, a→b→d and a→c→d, so `path("a", "d")` has two derivations,
    /// plus `lonely` facts derived through a negated premise.
    fn provenance_core(backend: Box<dyn Backend>) -> LocalCore {
        let edb = vec![
            ("edge".to_string(), vec![s("a"), s("b")]),
            ("edge".to_string(), vec![s("a"), s("c")]),
            ("edge".to_string(), vec![s("b"), s("d")]),
            ("edge".to_string(), vec![s("c"), s("d")]),
            ("node".to_string(), vec![s("d")]),
        ];
        let rules = vec![
            "Decl edge(Src, Dst).\nDecl node(N).\nDecl path(Src, Dst).\nDecl lonely(N).\n\
             path(X, Y) :- edge(X, Y).\n\
             path(X, Z) :- path(X, Y), edge(Y, Z).\n\
             has_out(N) :- edge(N, _).\n\
             lonely(N) :- node(N), !has_out(N)."
                .to_string(),
        ];
        let engine = Engine::from_parts(edb, rules, backend).unwrap();
        let live = engine.evaluate().unwrap();
        LocalCore::new(Arc::new(Mutex::new(engine)), live)
    }

    fn only_tree(core: &LocalCore, at: &At, fact: &str) -> ProvenanceTree {
        let mut trees = core.provenance(at, fact).unwrap();
        assert_eq!(trees.len(), 1, "{fact}");
        trees.remove(0)
    }

    fn application(tree: &ProvenanceTree) -> &RuleApplication {
        match &tree.derivation {
            Derivation::Rule(application) => application,
            other => panic!("{}: {other:?}", tree.relation),
        }
    }

    /// One proof per fact, even for `path("a", "d")`, which the diamond
    /// derives two ways; each premise bottoms out at an input fact.
    #[test]
    fn provenance_explains_down_to_inputs() {
        let backends: [Box<dyn Backend>; 2] = [
            Box::new(InterpreterBackend),
            Box::new(DdBackend { provenance: true }),
        ];
        for backend in backends {
            let core = provenance_core(backend);
            let tree = only_tree(&core, &At::Live, "path(\"a\", \"d\")");
            assert_eq!(tree.row, [s("a"), s("d")]);
            let [path, edge] = &application(&tree).premises[..] else {
                panic!("{tree:?}")
            };
            assert_eq!(path.relation, "path");
            assert_eq!(edge.relation, "edge");
            assert_eq!(edge.derivation, Derivation::Input);
            let [path_edge] = &application(path).premises[..] else {
                panic!("{path:?}")
            };
            assert_eq!(path_edge.derivation, Derivation::Input);

            assert!(
                core.provenance(&At::Live, "path(\"d\", _)")
                    .unwrap()
                    .is_empty()
            );
        }
    }

    /// DD names the negated premise that held.
    #[test]
    fn dd_provenance_names_absent_premises() {
        let core = provenance_core(Box::new(DdBackend { provenance: true }));
        let tree = only_tree(&core, &At::Live, "lonely(\"d\")");
        let application = application(&tree);
        assert_eq!(application.premises[0].relation, "node");
        assert_eq!(
            application.absent,
            [AbsentFact {
                relation: "has_out".to_string(),
                args: vec![Some(s("d"))],
            }]
        );
    }

    #[test]
    fn provenance_refusals_and_unexplained_facts() {
        let core = provenance_core(Box::new(DdBackend { provenance: false }));
        assert_eq!(
            core.provenance(&At::Live, "path(_, _)")
                .unwrap_err()
                .to_string(),
            "why needs provenance, which is off for this session. Re-run with \
             `--backend dd --provenance`, or use `--backend interpreter`."
        );

        let core = provenance_core(Box::new(DdBackend { provenance: true }));
        let unknown = At::Snapshot("nope".to_string());
        assert_eq!(
            core.provenance(&unknown, "path(_, _)")
                .unwrap_err()
                .to_string(),
            "No snapshot named 'nope'."
        );
        // A snapshot frozen without its provenance can't explain anything.
        {
            let engine = core.engine();
            let frozen = core.live_store(&engine).unwrap().frozen_copy();
            core.snapshots().insert(
                "bare".to_string(),
                FrozenState {
                    store: frozen,
                    lazy_provenance: None,
                    inputs: engine.save_inputs(),
                },
            );
        }
        let tree = only_tree(
            &core,
            &At::Snapshot("bare".to_string()),
            "path(\"a\", \"b\")",
        );
        assert_eq!(
            tree.derivation,
            Derivation::Unexplained(Unexplained::NotCaptured)
        );
    }

    #[test]
    fn snapshot_names_must_be_new_and_single_words() {
        for core in cores() {
            let info = core.snapshot("before").unwrap();
            // edge a→b→c: two edges, three paths.
            assert_eq!((info.relations, info.facts), (2, 5));
            assert!(core.has_snapshot("before"));
            assert!(!core.has_snapshot("after"));
            for (name, message) in [
                ("", "Snapshot names cannot be empty or contain spaces."),
                (
                    "two words",
                    "Snapshot names cannot be empty or contain spaces.",
                ),
                ("before", "Snapshot 'before' already exists."),
            ] {
                assert_eq!(core.snapshot(name).unwrap_err().to_string(), message);
            }
        }
    }

    /// A diff names what changed between two states, and only in one
    /// relation when asked.
    #[test]
    fn diff_between_snapshot_and_live() {
        for core in cores() {
            core.snapshot("before").unwrap();
            {
                let mut engine = core.engine();
                engine.retract_fact("edge", &[s("b"), s("c")]);
                engine.add_fact("edge".to_string(), vec![s("c"), s("d")]);
            }
            let before = At::Snapshot("before".to_string());

            let diff = core.diff(&before, &At::Live, None).unwrap();
            let edge = |a: &str, b: &str| BTreeSet::from([vec![s(a), s(b)]]);
            assert_eq!(diff.added["edge"], edge("c", "d"));
            assert_eq!(diff.removed["edge"], edge("b", "c"));
            assert!(diff.removed.contains_key("path"));

            let only_edge = core.diff(&before, &At::Live, Some("edge")).unwrap();
            assert_eq!(only_edge.added.keys().collect::<Vec<_>>(), ["edge"]);
            assert_eq!(only_edge.removed.keys().collect::<Vec<_>>(), ["edge"]);

            assert!(core.diff(&before, &before, None).unwrap().added.is_empty());
            assert_eq!(
                core.diff(&before, &At::Live, Some("egde"))
                    .unwrap_err()
                    .to_string(),
                "Unknown relation 'egde'."
            );
            let missing = At::Snapshot("nope".to_string());
            assert_eq!(
                core.diff(&missing, &At::Live, None)
                    .unwrap_err()
                    .to_string(),
                "No snapshot named 'nope'."
            );
        }
    }

    fn fact(relation: &str, row: &[&str]) -> Fact {
        Fact {
            relation: relation.to_string(),
            row: row.iter().map(|value| s(value)).collect(),
        }
    }

    #[test]
    fn relations_lists_what_the_state_holds_or_names_asked_for() {
        for core in cores() {
            let listed = core.relations(&At::Live, &[]).unwrap();
            let names: Vec<&str> = listed.iter().map(|r| r.name.as_str()).collect();
            // Sorted. DD also lists the prelude's declared input relations
            // while they're empty; the interpreter only lists ones with facts.
            assert!(names.is_sorted(), "{names:?}");
            let edge = listed.iter().find(|r| r.name == "edge").unwrap();
            assert_eq!(edge.arity, Some(2));
            assert!(names.contains(&"path"), "{names:?}");
            let columns: Vec<&str> = edge
                .doc
                .as_ref()
                .unwrap()
                .columns
                .iter()
                .map(|c| c.name.as_str())
                .collect();
            assert_eq!(columns, ["Src", "Dst"]);

            let asked = core.relations(&At::Live, &["path", "nosuch"]).unwrap();
            assert_eq!(asked[1].name, "nosuch");
            assert_eq!((asked[1].arity, asked[1].doc.is_none()), (None, true));
        }
    }

    /// Each write shows up in the next read, on both backends (DD reads it
    /// from the session, the interpreter evaluates on the write).
    #[test]
    fn writes_show_up_in_the_next_read() {
        let paths_from_c =
            |core: &LocalCore| sorted(core.query(&At::Live, "path(\"c\", Y)").unwrap()).rows;
        for core in cores() {
            assert!(core.assert_fact(fact("edge", &["c", "d"])).unwrap());
            assert!(!core.assert_fact(fact("edge", &["c", "d"])).unwrap());
            assert_eq!(paths_from_c(&core), [vec![s("d")]]);

            assert!(
                core.replace_fact(&fact("edge", &["c", "d"]), fact("edge", &["c", "e"]))
                    .unwrap()
            );
            assert!(
                !core
                    .replace_fact(&fact("edge", &["c", "x"]), fact("edge", &["c", "f"]))
                    .unwrap()
            );
            assert_eq!(paths_from_c(&core), [vec![s("e")], vec![s("f")]]);

            assert!(core.retract_fact(&fact("edge", &["c", "e"])).unwrap());
            assert!(!core.retract_fact(&fact("edge", &["c", "e"])).unwrap());
            assert_eq!(paths_from_c(&core), [vec![s("f")]]);

            assert_eq!(
                core.assert_fact(fact("edge", &["c"]))
                    .unwrap_err()
                    .to_string(),
                "arity mismatch: edge/2 expects 2 arg(s), got 1"
            );
        }
    }

    /// A rule that doesn't compile is rejected and leaves the rules as they
    /// were; a good one is queryable straight away.
    #[test]
    fn define_adds_good_rules_and_rejects_bad_ones() {
        for core in cores() {
            let rules = core.engine().rules_len();
            assert!(core.define("reach_c(X) :- path(X, ").is_err());
            assert_eq!(core.engine().rules_len(), rules);

            core.define("reach_c(X) :- path(X, \"c\").").unwrap();
            let reach = sorted(core.query(&At::Live, "reach_c(X)").unwrap());
            assert_eq!(reach.rows, [vec![s("a")], vec![s("b")]]);
        }
    }

    /// A sourced program adds its facts and rules together, or nothing.
    #[test]
    fn source_is_all_or_nothing() {
        for core in cores() {
            core.source("edge(\"c\", \"d\").\nreach_d(X) :- path(X, \"d\").\n")
                .unwrap();
            let reach = sorted(core.query(&At::Live, "reach_d(X)").unwrap());
            assert_eq!(reach.rows, [vec![s("a")], vec![s("b")], vec![s("c")]]);

            let rules = core.engine().rules_len();
            assert!(
                core.source("edge(\"d\", \"e\").\nbroken(X) :- nosuch(X\n")
                    .is_err()
            );
            assert_eq!(core.engine().rules_len(), rules);
            assert!(
                core.query(&At::Live, "path(\"d\", Y)")
                    .unwrap()
                    .rows
                    .is_empty()
            );
        }
    }

    #[test]
    fn load_facts_checks_widths_before_adding_any() {
        for core in cores() {
            let rows = vec![
                vec![s("c"), s("d")],
                vec![s("c"), s("d")],
                vec![s("d"), s("e")],
            ];
            assert_eq!(core.load_facts("edge", rows).unwrap(), 2);
            let error = core
                .load_facts("edge", vec![vec![s("e"), s("f")], vec![s("x")]])
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "Load error: arity mismatch: edge/2 expects 2 column(s), but tuple 1 has 1 \
                 — check your query or source"
            );
            assert!(
                core.query(&At::Live, "edge(\"e\", Y)")
                    .unwrap()
                    .rows
                    .is_empty()
            );
        }
    }

    fn config_map(name: &str, tier: &str) -> KubeObject {
        let object = serde_json::from_value(serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": name, "namespace": "default"},
            "data": {"tier": tier},
        }))
        .unwrap();
        (object, None)
    }

    /// Objects become facts in the core: loading again replaces, and a delta
    /// adds, updates and removes against the live objects.
    #[test]
    fn objects_load_and_apply_as_deltas() {
        for core in cores() {
            let loaded = core
                .load_objects(vec![config_map("web", "a"), config_map("db", "a")])
                .unwrap();
            assert_eq!((loaded.added, loaded.updated), (2, 0));
            let reloaded = core.load_objects(vec![config_map("web", "b")]).unwrap();
            assert_eq!((reloaded.added, reloaded.updated), (0, 1));

            let delta = core
                .apply_delta(
                    vec![
                        config_map("web", "b"),
                        config_map("db", "a"),
                        config_map("old", "a"),
                    ],
                    vec![
                        config_map("web", "c"),
                        config_map("db", "a"),
                        config_map("new", "a"),
                    ],
                )
                .unwrap();
            assert_eq!(
                delta,
                DeltaSummary {
                    added: 1,
                    updated: 1,
                    removed: 1,
                    unchanged: 1,
                    // `old` was never loaded.
                    removed_absent: 1,
                }
            );
            let names = sorted(
                core.query(&At::Live, "k8s(_, \"ConfigMap\", _, N, _)")
                    .unwrap(),
            );
            assert_eq!(names.rows, [vec![s("db")], vec![s("new")], vec![s("web")]]);
        }
    }

    /// A selector match reads: the live state is unchanged after it.
    #[test]
    fn match_selector_reads_without_writing() {
        for core in cores() {
            let version = core.version();
            let error = |at: &At, selector: &str| {
                core.match_selector(at, None, "default", selector)
                    .unwrap_err()
                    .to_string()
            };
            assert!(error(&At::Live, "app in (").starts_with("Selector parse error:"));
            assert_eq!(
                error(&At::Snapshot("nope".to_string()), "app=web"),
                "No snapshot named 'nope'."
            );
            let none = core
                .match_selector(&At::Live, Some("Pod"), "default", "app=web")
                .unwrap();
            assert!(none.rows.is_empty());
            assert_eq!(none.columns, ["apiVersion", "kind", "namespace", "name"]);
            assert_eq!(core.version(), version);
        }
    }
}
