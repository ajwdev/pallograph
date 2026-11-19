// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The changes a GitOps-style delta (`k8s::apply-delta`) makes to the live
//! cluster's objects.

use std::collections::HashMap;

use mangle_common::Value;

use crate::edb::{ObjectFacts, ObjectKey};
use crate::engine::Change;

/// The `k8s/5` row an object emitted, which carries its whole body and so
/// stands in for its content. Compared between base and head to tell an
/// unchanged object from a changed one.
fn k8s_row(object: &ObjectFacts) -> Option<&Vec<Value>> {
    object
        .facts
        .iter()
        .find(|(relation, _)| relation == "k8s")
        .map(|(_, tuple)| tuple)
}

/// Diff two rendered object sets (base and head) into the changes a 3-way
/// merge applies to the live cluster, treating live as "ours": head-only
/// keys are adds, keys in both whose content differs are updates, base-only
/// keys are retracts (what Argo would prune), and keys in both with
/// identical content are left alone so live drift survives. Returns the
/// changes plus the added, updated and unchanged counts for the summary;
/// the retract count is read off the changes, and how many retracts were
/// not live comes back from the engine.
pub fn diff_object_sides(
    base: Vec<ObjectFacts>,
    head: Vec<ObjectFacts>,
) -> (Vec<Change>, usize, usize, usize) {
    // Last copy of a repeated key wins, matching how a load collapses an
    // object listed twice across files.
    let base: HashMap<ObjectKey, ObjectFacts> =
        base.into_iter().map(|o| (o.key.clone(), o)).collect();
    let head: HashMap<ObjectKey, ObjectFacts> =
        head.into_iter().map(|o| (o.key.clone(), o)).collect();

    let mut changes = Vec::new();
    let (mut added, mut updated, mut unchanged) = (0, 0, 0);
    for (key, head_object) in &head {
        match base.get(key) {
            None => {
                added += 1;
                changes.push(Change::Upsert(head_object.clone()));
            }
            Some(base_object) if k8s_row(base_object) != k8s_row(head_object) => {
                updated += 1;
                changes.push(Change::Upsert(head_object.clone()));
            }
            Some(_) => unchanged += 1,
        }
    }
    for key in base.keys() {
        if !head.contains_key(key) {
            changes.push(Change::Retract(key.clone()));
        }
    }
    (changes, added, updated, unchanged)
}

#[cfg(test)]
mod tests {
    use super::diff_object_sides;
    use crate::edb::ObjectFacts;
    use crate::engine::Change;

    /// Turn JSON objects into the rendered `ObjectFacts` a delta side yields.
    fn side(json: Vec<serde_json::Value>) -> Vec<ObjectFacts> {
        struct Objects(Vec<serde_json::Value>);
        impl crate::edb::FactSource for Objects {
            fn k8s_objects(
                &mut self,
            ) -> anyhow::Result<Vec<(kube::api::DynamicObject, Option<(String, String)>)>>
            {
                self.0
                    .drain(..)
                    .map(|json| Ok((serde_json::from_value(json)?, None)))
                    .collect()
            }
        }
        crate::edb::object_facts(&mut Objects(json)).unwrap()
    }

    fn config_map(name: &str, tier: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": name, "namespace": "default"},
            "data": {"tier": tier},
        })
    }

    /// One row of the 3-way table at a time: head-only is an add, a content
    /// change is an update, base-only is a retract, and identical content on
    /// both sides emits nothing, so live (whatever its drift) is left alone.
    #[test]
    fn diff_classifies_each_table_row() {
        let base = side(vec![
            config_map("same", "web"),
            config_map("changed", "web"),
            config_map("removed", "web"),
        ]);
        let head = side(vec![
            config_map("same", "web"),
            config_map("changed", "db"),
            config_map("added", "web"),
        ]);
        let (changes, added, updated, unchanged) = diff_object_sides(base, head);
        assert_eq!((added, updated, unchanged), (1, 1, 1));
        let retracts = changes
            .iter()
            .filter(|c| matches!(c, Change::Retract(_)))
            .count();
        let upserts = changes.len() - retracts;
        assert_eq!(
            (upserts, retracts),
            (2, 1),
            "add + update upsert, remove retracts"
        );
    }

    /// An empty base (a brand-new chart) makes every head object an add.
    #[test]
    fn diff_with_empty_base_is_all_adds() {
        let head = side(vec![config_map("a", "web"), config_map("b", "db")]);
        let (changes, added, updated, unchanged) = diff_object_sides(Vec::new(), head);
        assert_eq!((added, updated, unchanged), (2, 0, 0));
        assert!(changes.iter().all(|c| matches!(c, Change::Upsert(_))));
    }
}
