use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use mangle_common::{Store, Value};
use mangle_interpreter::MemStore;

use crate::engine::EvalStore;

pub enum Scope {
    All,
    Only(Vec<String>),
}

pub struct Snapshot {
    relations: BTreeMap<String, BTreeSet<Vec<Value>>>,
}

impl Snapshot {
    pub fn from_eval(eval: &EvalStore, scope: Scope) -> Self {
        let mut relations = BTreeMap::new();
        let names: Vec<String> = match scope {
            Scope::All => eval.relation_names().map(String::from).collect(),
            Scope::Only(names) => names,
        };
        for name in names {
            let tuples: BTreeSet<Vec<Value>> = eval.scan(&name).iter().cloned().collect();
            if !tuples.is_empty() {
                relations.insert(name, tuples);
            }
        }
        Self { relations }
    }

    /// Iterate over (relation_name, tuples) pairs in this snapshot.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &BTreeSet<Vec<Value>>)> {
        self.relations.iter().map(|(k, v)| (k.as_str(), v))
    }

    pub fn relation_count(&self) -> usize {
        self.relations.len()
    }

    pub fn fact_count(&self) -> usize {
        self.relations.values().map(|s| s.len()).sum()
    }

    pub fn scan_rel(&self, rel: &str) -> Vec<Vec<Value>> {
        self.relations
            .get(rel)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn from_store(store: &MemStore, scope: Scope) -> Self {
        let mut relations = BTreeMap::new();
        let names: Vec<String> = match scope {
            Scope::All => store.relation_names(),
            Scope::Only(names) => names,
        };
        for name in names {
            let tuples: BTreeSet<Vec<Value>> = store.get_facts(&name).into_iter().collect();
            if !tuples.is_empty() {
                relations.insert(name, tuples);
            }
        }
        Self { relations }
    }
}

pub struct Diff {
    pub added: BTreeMap<String, BTreeSet<Vec<Value>>>,
    pub removed: BTreeMap<String, BTreeSet<Vec<Value>>>,
}

impl Diff {
    pub fn between(before: &Snapshot, after: &Snapshot) -> Self {
        let mut added: BTreeMap<String, BTreeSet<Vec<Value>>> = BTreeMap::new();
        let mut removed: BTreeMap<String, BTreeSet<Vec<Value>>> = BTreeMap::new();

        let all_relations: BTreeSet<&String> = before
            .relations
            .keys()
            .chain(after.relations.keys())
            .collect();

        for rel in all_relations {
            let empty = BTreeSet::new();
            let before_set = before.relations.get(rel).unwrap_or(&empty);
            let after_set = after.relations.get(rel).unwrap_or(&empty);

            let add: BTreeSet<Vec<Value>> =
                after_set.difference(before_set).cloned().collect();
            let rem: BTreeSet<Vec<Value>> =
                before_set.difference(after_set).cloned().collect();

            if !add.is_empty() {
                added.insert(rel.clone(), add);
            }
            if !rem.is_empty() {
                removed.insert(rel.clone(), rem);
            }
        }

        Self { added, removed }
    }

    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }

    /// Summary iterator: (relation, added_count, removed_count) for changed relations.
    pub fn relation_changes(&self) -> impl Iterator<Item = (&str, usize, usize)> {
        let all: BTreeSet<&String> = self
            .added
            .keys()
            .chain(self.removed.keys())
            .collect();
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
    use std::path::Path;

    use mangle_interpreter::MemStore;

    use super::*;
    use crate::edb;

    fn load_testdata() -> MemStore {
        let mut store = MemStore::new();
        edb::load_from_manifests(&mut store, vec!["testdata".to_string()]).expect("load testdata");
        store
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
        let mut store_b = load_testdata();
        store_b.add_fact("can", intern_tuple());

        let snap_a = Snapshot::from_store(&store_a, Scope::Only(vec!["can".into()]));
        let snap_b = Snapshot::from_store(&store_b, Scope::Only(vec!["can".into()]));
        let diff = Diff::between(&snap_a, &snap_b);

        assert!(!diff.is_empty());
        let added = diff.added.get("can").expect("can relation has additions");
        assert_eq!(added.len(), 1);
        let added_tuple = added.iter().next().unwrap();
        assert_eq!(added_tuple[0], Value::String("intern@example.com".into()));
        assert!(
            diff.removed.get("can").map(|s| s.is_empty()).unwrap_or(true),
            "no can facts should be removed"
        );
    }

    #[test]
    fn diff_symmetric_inverse() {
        let store_a = load_testdata();
        let mut store_b = load_testdata();
        store_b.add_fact("can", intern_tuple());

        let snap_a = Snapshot::from_store(&store_a, Scope::Only(vec!["can".into()]));
        let snap_b = Snapshot::from_store(&store_b, Scope::Only(vec!["can".into()]));

        let diff_ab = Diff::between(&snap_a, &snap_b);
        let diff_ba = Diff::between(&snap_b, &snap_a);

        assert_eq!(diff_ab.added.get("can"), diff_ba.removed.get("can"));
        assert_eq!(diff_ab.removed.get("can"), diff_ba.added.get("can"));
    }

    #[test]
    fn diff_empty_when_identical() {
        let store_a = load_testdata();
        let store_b = load_testdata();

        let snap_a = Snapshot::from_store(&store_a, Scope::All);
        let snap_b = Snapshot::from_store(&store_b, Scope::All);
        let diff = Diff::between(&snap_a, &snap_b);

        assert!(diff.is_empty(), "identical stores should produce empty diff");
    }
}
