// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! What a client asks of the core: the engine, its rules and facts, and the
//! named snapshots. The REPL is the only client today, through
//! [`LocalCore`], which answers in-process; a remote client would implement
//! [`Core`] over the wire instead.
//!
//! Commands move onto the [`Core`] trait one at a time. Until one has, the
//! REPL reaches the engine and snapshots through [`LocalCore`]'s own methods.

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::Result;
use mangle_common::Value;

use crate::engine::{Engine, EvalStore};
use crate::query::{
    self, body_relations, count_top_level_args, extract_vars, single_atom, split_atom,
    split_projection, suggest,
};
use crate::snapshot::FrozenState;

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

    /// The live state as last evaluated, which may be behind the engine.
    /// For tab completion, where an older list of relations is fine.
    pub fn last_live(&self) -> Arc<EvalStore> {
        Arc::clone(&lock(&self.live).store)
    }

    /// The engine moved from version `from` to `to` without changing its
    /// facts or rules (`k8s::match` asserts selector facts and retracts them
    /// again), so a live state evaluated at `from` still holds at `to`.
    pub fn carry_live(&self, from: u64, to: u64) {
        let mut live = lock(&self.live);
        if live.version == from {
            live.version = to;
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
        let live_store;
        let store: &EvalStore = match at {
            At::Live => {
                live_store = self.live_store(&engine).map_err(QueryError::Evaluation)?;
                &live_store
            }
            At::Snapshot(name) => {
                &snapshots
                    .get(name)
                    .ok_or_else(|| QueryError::UnknownSnapshot(name.clone()))?
                    .store
            }
        };

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

    /// `carry_live` keeps a live state across a version change that left
    /// the facts alone, and only from the version it was evaluated at.
    #[test]
    fn carry_live_keeps_the_live_state_only_from_its_version() {
        for core in cores() {
            let evaluated = core.last_live();
            let from = core.version();
            core.carry_live(from + 7, from + 8);
            core.carry_live(from, from + 1);
            assert_eq!(lock(&core.live).version, from + 1);
            assert!(Arc::ptr_eq(&core.last_live(), &evaluated));
        }
    }
}
