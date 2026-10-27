// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use mangle_common::Value;

use crate::dd::session::FrozenLazyProvenance;
use crate::engine::{EngineInputs, EvalStore, is_scratch_relation};

/// A `\snapshot`'s saved state: a frozen copy of the eval store at the
/// moment `\snapshot` ran, so later mutations to the live engine (`+`, `-`,
/// `~`, `\rollback`) never change it, plus a copy of the engine's inputs
/// (facts and rules) that `\rollback` restores.
///
/// `\why` under `\use` explains facts from the frozen state's own
/// provenance: `store.provenance` on the interpreter, or `lazy_provenance`
/// on the DD backend. `lazy_provenance` is `None` when the snapshot was
/// taken without a DD provenance session.
pub struct FrozenState {
    pub store: EvalStore,
    pub lazy_provenance: Option<FrozenLazyProvenance>,
    pub inputs: EngineInputs,
}

pub struct Diff {
    pub added: BTreeMap<String, BTreeSet<Vec<Value>>>,
    pub removed: BTreeMap<String, BTreeSet<Vec<Value>>>,
}

impl Diff {
    pub fn between(before: &EvalStore, after: &EvalStore) -> Self {
        let mut added: BTreeMap<String, BTreeSet<Vec<Value>>> = BTreeMap::new();
        let mut removed: BTreeMap<String, BTreeSet<Vec<Value>>> = BTreeMap::new();

        let all_relations: BTreeSet<&str> = before
            .relation_names()
            .chain(after.relation_names())
            .filter(|name| !is_scratch_relation(name))
            .collect();

        for rel in all_relations {
            let before_set: BTreeSet<Vec<Value>> = before.scan(rel).iter().cloned().collect();
            let after_set: BTreeSet<Vec<Value>> = after.scan(rel).iter().cloned().collect();

            let add: BTreeSet<Vec<Value>> = after_set.difference(&before_set).cloned().collect();
            let rem: BTreeSet<Vec<Value>> = before_set.difference(&after_set).cloned().collect();

            if !add.is_empty() {
                added.insert(rel.to_string(), add);
            }
            if !rem.is_empty() {
                removed.insert(rel.to_string(), rem);
            }
        }

        Self { added, removed }
    }

    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }

    /// Summary iterator: (relation, added_count, removed_count) for changed relations.
    pub fn relation_changes(&self) -> impl Iterator<Item = (&str, usize, usize)> {
        let all: BTreeSet<&String> = self.added.keys().chain(self.removed.keys()).collect();
        all.into_iter().map(|rel| {
            let a = self.added.get(rel).map(|s| s.len()).unwrap_or(0);
            let r = self.removed.get(rel).map(|s| s.len()).unwrap_or(0);
            (rel.as_str(), a, r)
        })
    }
}

impl fmt::Display for Diff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return writeln!(f, "(no changes)");
        }
        for (rel, added_count, removed_count) in self.relation_changes() {
            writeln!(f, "  {rel}  (+{added_count} -{removed_count})")?;
            if let Some(tuples) = self.added.get(rel) {
                for t in tuples {
                    writeln!(f, "    + {}", format_tuple(t))?;
                }
            }
            if let Some(tuples) = self.removed.get(rel) {
                for t in tuples {
                    writeln!(f, "    - {}", format_tuple(t))?;
                }
            }
        }
        Ok(())
    }
}

fn format_tuple(tuple: &[Value]) -> String {
    let parts: Vec<String> = tuple.iter().map(|v| format!("{v:?}")).collect();
    parts.join(", ")
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use mangle_common::Store;
    use mangle_interpreter::MemStore;

    use super::*;
    use crate::edb;

    fn load_testdata() -> MemStore {
        let mut store = MemStore::new();
        edb::load_from_manifests(&mut store, vec!["fixtures/testdata/small".to_string()])
            .expect("load testdata");
        store
    }

    /// Build an `EvalStore` holding only the `can` relation's rows, mirroring
    /// what a `\snapshot` scoped to one relation would freeze.
    fn eval_with_can(can_facts: Vec<Vec<Value>>) -> EvalStore {
        let mut facts = HashMap::new();
        facts.insert("can".to_string(), can_facts);
        EvalStore::from_facts(facts)
    }

    /// Build an `EvalStore` from every relation a `MemStore` holds.
    fn eval_from_store(store: &MemStore) -> EvalStore {
        let mut facts = HashMap::new();
        for rel in store.relation_names() {
            facts.insert(rel.clone(), store.get_facts(&rel));
        }
        EvalStore::from_facts(facts)
    }

    fn intern_tuple() -> Vec<Value> {
        vec![
            Value::String("intern@example.com".into()),
            Value::String("default".into()),
            Value::String("".into()),
            Value::String("pods".into()),
            Value::String("get".into()),
        ]
    }

    #[test]
    fn diff_detects_added_fact() {
        let store_a = load_testdata();
        let can_before = store_a.get_facts("can");
        let mut can_after = can_before.clone();
        can_after.push(intern_tuple());

        let diff = Diff::between(&eval_with_can(can_before), &eval_with_can(can_after));

        assert!(!diff.is_empty());
        let added = diff.added.get("can").expect("can relation has additions");
        assert_eq!(added.len(), 1);
        let added_tuple = added.iter().next().unwrap();
        assert_eq!(added_tuple[0], Value::String("intern@example.com".into()));
        assert!(
            diff.removed
                .get("can")
                .map(|s| s.is_empty())
                .unwrap_or(true),
            "no can facts should be removed"
        );
    }

    #[test]
    fn diff_symmetric_inverse() {
        let can_before = load_testdata().get_facts("can");
        let mut can_after = can_before.clone();
        can_after.push(intern_tuple());

        let store_a = eval_with_can(can_before);
        let store_b = eval_with_can(can_after);

        let diff_ab = Diff::between(&store_a, &store_b);
        let diff_ba = Diff::between(&store_b, &store_a);

        assert_eq!(diff_ab.added.get("can"), diff_ba.removed.get("can"));
        assert_eq!(diff_ab.removed.get("can"), diff_ba.added.get("can"));
    }

    #[test]
    fn diff_empty_when_identical() {
        let store_a = load_testdata();
        let store_b = load_testdata();

        let diff = Diff::between(&eval_from_store(&store_a), &eval_from_store(&store_b));

        assert!(
            diff.is_empty(),
            "identical stores should produce empty diff"
        );
    }
}
