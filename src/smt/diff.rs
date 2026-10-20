// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Access diff between two snapshots of RBAC grants (`\access-diff`),
//! computed in Rust on the `PermissionTables` of each.

use std::collections::HashMap;

use super::SmtEncoder;
use crate::rbac::facts::{ns_covers, value_covers};
use crate::rbac::{PermissionEntry, Subject};

pub struct CanDiff {
    pub principal: Subject,
    pub namespace: String,
    pub apigroup: String,
    pub resource: String,
    pub verb: String,
}

pub struct EffDiff {
    pub principal: Subject,
    pub namespace: String,
    pub apigroup: String,
    pub resource: String,
    pub verb: String,
}

impl<'ctx> SmtEncoder<'ctx> {
    /// Every (principal, permission) entry `after` grants directly that no
    /// direct grant in `before` covers.
    ///
    /// Both suffixes must have been loaded via `load_rbac_tables_as` or
    /// `load_rbac_tables_from_snapshot_as` before calling this.
    pub fn check_permission_expansion(&self, before: &str, after: &str) -> Vec<CanDiff> {
        self.can_diff_witnesses(after, before)
    }

    /// Every entry `before` grants directly that no direct grant in `after`
    /// covers.
    pub fn check_permission_contraction(&self, before: &str, after: &str) -> Vec<CanDiff> {
        self.can_diff_witnesses(before, after)
    }

    /// Like `check_permission_expansion`, counting what escalation reaches
    /// on both sides.
    pub fn check_effective_can_expansion(&self, before: &str, after: &str) -> Vec<EffDiff> {
        self.eff_diff_witnesses(after, before)
    }

    /// Like `check_permission_contraction`, counting what escalation reaches
    /// on both sides.
    pub fn check_effective_can_contraction(&self, before: &str, after: &str) -> Vec<EffDiff> {
        self.eff_diff_witnesses(before, after)
    }

    /// Every (principal, permission) entry `have` holds literally and
    /// `not_have` does not, unless a wildcard or cluster-wide grant in
    /// `not_have` already covers it. `effective` counts what escalation
    /// reaches rather than direct grants alone.
    ///
    /// Each snapshot's entries are expanded once and kept on its tables, so
    /// the four checks of one `\access-diff` share them, and each principal's
    /// grants in `not_have` are gathered once for all of its entries.
    fn diff_witnesses(&self, have: &str, not_have: &str, effective: bool) -> Vec<PermissionEntry> {
        let (Some(have_tables), Some(not_have_tables)) = (
            self.permission_tables.get(have),
            self.permission_tables.get(not_have),
        ) else {
            return vec![];
        };
        let (have_entries, not_have_entries) = if effective {
            (
                have_tables.effective_entries(),
                not_have_tables.effective_entries(),
            )
        } else {
            (
                have_tables.direct_entries(),
                not_have_tables.direct_entries(),
            )
        };

        let mut by_principal: HashMap<&Subject, Vec<&PermissionEntry>> = HashMap::new();
        for entry in have_entries.difference(not_have_entries) {
            by_principal.entry(&entry.0).or_default().push(entry);
        }

        let mut witnesses = Vec::new();
        for (principal, entries) in by_principal {
            let held = not_have_tables.held_grants(principal, effective);
            witnesses.extend(
                entries
                    .into_iter()
                    .filter(|(_, namespace, api_group, resource, verb)| {
                        !held.iter().any(|granted| {
                            ns_covers(&granted.0, namespace)
                                && value_covers(&granted.1, api_group)
                                && value_covers(&granted.2, resource)
                                && value_covers(&granted.3, verb)
                        })
                    })
                    .cloned(),
            );
        }
        witnesses
    }

    fn can_diff_witnesses(&self, have: &str, not_have: &str) -> Vec<CanDiff> {
        self.diff_witnesses(have, not_have, false)
            .into_iter()
            .map(|(principal, namespace, apigroup, resource, verb)| CanDiff {
                principal,
                namespace,
                apigroup,
                resource,
                verb,
            })
            .collect()
    }

    fn eff_diff_witnesses(&self, have: &str, not_have: &str) -> Vec<EffDiff> {
        self.diff_witnesses(have, not_have, true)
            .into_iter()
            .map(|(principal, namespace, apigroup, resource, verb)| EffDiff {
                principal,
                namespace,
                apigroup,
                resource,
                verb,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use mangle_common::Value;
    use mangle_interpreter::MemStore;

    use super::super::SmtEncoder;
    use crate::edb;
    use crate::engine::{Engine, InterpreterBackend};
    use crate::rbac::Subject;
    use crate::snapshot::{Scope, Snapshot};

    /// A `direct_perm` row granting a User subject, for any object name.
    fn user_grant(user: &str, ns: &str, apigroup: &str, resource: &str, verb: &str) -> Vec<Value> {
        vec![
            Value::String(user.into()),
            Value::Name("/user".into()),
            Value::String(ns.into()),
            Value::String(apigroup.into()),
            Value::String(resource.into()),
            Value::Name("/any".into()),
            Value::String(verb.into()),
        ]
    }

    fn load_engine() -> Engine {
        let mut edb = MemStore::new();
        edb::load_from_manifests(&mut edb, vec!["fixtures/testdata/small".to_string()])
            .expect("load testdata");
        Engine::new(edb, Path::new("rules"), Box::new(InterpreterBackend)).expect("engine")
    }

    #[test]
    fn no_expansion_when_before_and_after_identical() {
        let engine = load_engine();
        let eval = engine.evaluate().expect("evaluate");

        let cfg = z3::Config::new();
        let ctx = z3::Context::new(&cfg);
        let mut enc = SmtEncoder::new(&ctx);
        enc.load_rbac_tables_as(&eval, "before");
        enc.load_rbac_tables_as(&eval, "after");

        let gained = enc.check_permission_expansion("before", "after");
        let lost = enc.check_permission_contraction("before", "after");
        assert!(
            gained.is_empty(),
            "identical before/after must have no expansion"
        );
        assert!(
            lost.is_empty(),
            "identical before/after must have no contraction"
        );
    }

    #[test]
    fn expansion_detects_new_binding() {
        let empty_snap = {
            let store = MemStore::new();
            Snapshot::from_store(&store, Scope::All)
        };

        let after_snap = {
            let mut store = MemStore::new();
            store.add_fact(
                "direct_perm",
                user_grant("alice", "default", "", "pods", "get"),
            );
            Snapshot::from_store(&store, Scope::All)
        };

        let cfg = z3::Config::new();
        let ctx = z3::Context::new(&cfg);
        let mut enc = SmtEncoder::new(&ctx);
        enc.load_rbac_tables_from_snapshot_as(&empty_snap, "before");
        enc.load_rbac_tables_from_snapshot_as(&after_snap, "after");

        let gained = enc.check_permission_expansion("before", "after");
        assert_eq!(gained.len(), 1, "alice should be the only new principal");
        assert_eq!(gained[0].principal, Subject::username("alice"));
        assert_eq!(gained[0].namespace, "default");
        assert_eq!(gained[0].resource, "pods");
        assert_eq!(gained[0].verb, "get");

        // No contraction — nothing was removed.
        let lost = enc.check_permission_contraction("before", "after");
        assert!(lost.is_empty(), "no contraction expected");
    }

    #[test]
    fn wildcard_subsumption_is_not_expansion() {
        // "before" grants alice wildcard verb access on pods.
        // "after" keeps the wildcard AND adds an explicit narrow grant.
        // Tuple-level diff would falsely report GAINED pods/get.
        // The coverage check must return empty (the narrow grant is subsumed).
        let before_snap = {
            let mut store = MemStore::new();
            store.add_fact(
                "direct_perm",
                user_grant("alice", "default", "", "pods", "*"),
            );
            Snapshot::from_store(&store, Scope::All)
        };

        let after_snap = {
            let mut store = MemStore::new();
            // Same wildcard grant as before.
            store.add_fact(
                "direct_perm",
                user_grant("alice", "default", "", "pods", "*"),
            );
            // Additionally: an explicit narrow grant (subsumed by the wildcard above).
            store.add_fact(
                "direct_perm",
                user_grant("alice", "default", "", "pods", "get"),
            );
            Snapshot::from_store(&store, Scope::All)
        };

        let cfg = z3::Config::new();
        let ctx = z3::Context::new(&cfg);
        let mut enc = SmtEncoder::new(&ctx);
        enc.load_rbac_tables_from_snapshot_as(&before_snap, "before");
        enc.load_rbac_tables_from_snapshot_as(&after_snap, "after");

        // The narrow get grant is subsumed by the existing wildcard verb.
        // No expansion: alice already holds pods get in default in "before",
        // through the verb=* wildcard.
        let gained = enc.check_permission_expansion("before", "after");
        assert!(
            gained.is_empty(),
            "narrow grant subsumed by wildcard must not be reported as expansion; got: {:?}",
            gained
                .iter()
                .map(|d| format!(
                    "{}/{}/{}/{}/{}",
                    d.principal, d.namespace, d.apigroup, d.resource, d.verb
                ))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn rbac_tables_read_the_small_fixture() {
        // The permission tables behind \access-diff are built from relations
        // scanned by name; an empty result means a rename or
        // reshape went unnoticed.
        let engine = load_engine();
        let eval = engine.evaluate().expect("evaluate");

        let cfg = z3::Config::new();
        let ctx = z3::Context::new(&cfg);
        let mut enc = SmtEncoder::new(&ctx);
        enc.load_rbac_tables(&eval);

        let tables = &enc.permission_tables[""];
        let direct = tables.direct_entries();
        let effective = tables.effective_entries();
        assert!(!direct.is_empty(), "no direct entries");
        assert!(
            effective.len() > direct.len(),
            "escalation added nothing to the effective entries"
        );
        assert!(
            !tables.escalation_targets.is_empty(),
            "no escalation targets recorded"
        );
        // Only the tables are built; nothing goes into the solver.
        assert!(enc.facts.is_empty(), "{:?}", enc.facts.keys());
        assert!(enc.solver.get_assertions().is_empty());
    }

    #[test]
    fn user_and_group_with_the_same_name_stay_apart() {
        // User twin may read secrets; group twin may delete pods.
        let grant = |kind: &str, resource: &str, verb: &str| {
            vec![
                Value::String("twin".into()),
                Value::Name(kind.into()),
                Value::String("".into()),
                Value::String("".into()),
                Value::String(resource.into()),
                Value::Name("/any".into()),
                Value::String(verb.into()),
            ]
        };
        let empty_snap = Snapshot::from_store(&MemStore::new(), Scope::All);
        let twins_snap = {
            let mut store = MemStore::new();
            store.add_fact("direct_perm", grant("/user", "secrets", "get"));
            store.add_fact("direct_perm", grant("/group", "pods", "delete"));
            Snapshot::from_store(&store, Scope::All)
        };

        let cfg = z3::Config::new();
        let ctx = z3::Context::new(&cfg);
        let mut enc = SmtEncoder::new(&ctx);
        enc.load_rbac_tables_from_snapshot_as(&empty_snap, "before");
        enc.load_rbac_tables_from_snapshot_as(&twins_snap, "after");

        // The principal may do verb on resource in namespace "default".
        let can = |principal: &Subject, resource: &str, verb: &str| -> bool {
            let query = (
                "default".to_string(),
                String::new(),
                resource.to_string(),
                verb.to_string(),
            );
            enc.permission_tables["after"].covers(principal, &query, false)
        };
        let user = Subject::username("twin");
        let group = Subject::group("twin");
        assert!(can(&user, "secrets", "get"));
        assert!(!can(&user, "pods", "delete"));
        assert!(can(&group, "pods", "delete"));
        assert!(!can(&group, "secrets", "get"));

        let mut gained: Vec<(Subject, String)> = enc
            .check_permission_expansion("before", "after")
            .into_iter()
            .map(|d| (d.principal, d.resource))
            .collect();
        gained.sort();
        assert_eq!(
            gained,
            [(user, "secrets".to_string()), (group, "pods".to_string())]
        );
    }

    /// Evaluate the rules over NDJSON manifests alone.
    fn evaluate_manifests(manifests: &[&str]) -> crate::engine::EvalStore {
        // Unique per call: tests run in parallel threads of one process.
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("pallograph-access-diff-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        std::fs::write(dir.join("manifests.json"), manifests.join("\n")).expect("write manifests");
        let mut edb = MemStore::new();
        let loaded = edb::load_from_manifests(&mut edb, vec![dir.to_string_lossy().into_owned()]);
        let _ = std::fs::remove_dir_all(&dir);
        loaded.expect("load manifests");
        Engine::new(edb, Path::new("rules"), Box::new(InterpreterBackend))
            .expect("engine")
            .evaluate()
            .expect("evaluate")
    }

    #[test]
    fn a_principal_known_in_one_snapshot_keeps_its_implicit_groups() {
        // Every authenticated user may create selfsubjectreviews. The second
        // snapshot adds bob's first binding, so only it knows bob; the first
        // must still count bob as authenticated rather than report the
        // system:authenticated grant as gained.
        let shared = [
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"self-review"},"rules":[{"apiGroups":["authentication.k8s.io"],"resources":["selfsubjectreviews"],"verbs":["create"]}]}"#,
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"self-review"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"self-review"},"subjects":[{"kind":"Group","name":"system:authenticated"}]}"#,
        ];
        let bob = [
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"pod-reader","namespace":"demo"},"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["get"]}]}"#,
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"bob","namespace":"demo"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"pod-reader"},"subjects":[{"kind":"User","name":"bob"}]}"#,
        ];
        let without_bob = evaluate_manifests(&shared);
        let with_bob = evaluate_manifests(&[&shared[..], &bob[..]].concat());

        let cfg = z3::Config::new();
        let ctx = z3::Context::new(&cfg);
        let mut enc = SmtEncoder::new(&ctx);
        enc.load_rbac_tables_as(&without_bob, "without");
        enc.load_rbac_tables_as(&with_bob, "with");

        let bob_reads_pods = || {
            (
                Subject::username("bob"),
                "demo".to_string(),
                "pods".to_string(),
            )
        };
        let can = |diffs: Vec<super::CanDiff>| -> Vec<(Subject, String, String)> {
            diffs
                .into_iter()
                .map(|d| (d.principal, d.namespace, d.resource))
                .collect()
        };
        let effective = |diffs: Vec<super::EffDiff>| -> Vec<(Subject, String, String)> {
            diffs
                .into_iter()
                .map(|d| (d.principal, d.namespace, d.resource))
                .collect()
        };

        // Adding the binding gains bob's pod read and nothing else.
        assert_eq!(
            can(enc.check_permission_expansion("without", "with")),
            [bob_reads_pods()]
        );
        assert_eq!(
            effective(enc.check_effective_can_expansion("without", "with")),
            [bob_reads_pods()]
        );
        assert!(can(enc.check_permission_contraction("without", "with")).is_empty());
        assert!(effective(enc.check_effective_can_contraction("without", "with")).is_empty());

        // Deleting bob's last binding loses only that read.
        assert_eq!(
            can(enc.check_permission_contraction("with", "without")),
            [bob_reads_pods()]
        );
        assert_eq!(
            effective(enc.check_effective_can_contraction("with", "without")),
            [bob_reads_pods()]
        );
        assert!(can(enc.check_permission_expansion("with", "without")).is_empty());
        assert!(effective(enc.check_effective_can_expansion("with", "without")).is_empty());
    }
}
