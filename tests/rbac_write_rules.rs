// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Escalation by writing RBAC objects (rules/rbac_write.mg) over small
//! hand-written clusters, checked on both backends. Like
//! tests/escalation_rules.rs, each test reads the derived relations
//! directly.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use mangle_common::Value;
use mangle_interpreter::MemStore;
use pallograph::edb;
use pallograph::engine::{Backend, DdBackend, Engine, EvalStore, InterpreterBackend};

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// Load `manifests` (NDJSON) and evaluate the production rules on each
/// backend.
fn evaluate(manifests: &[String]) -> Vec<(&'static str, EvalStore)> {
    // Unique per call: tests run in parallel threads of one process.
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("pallograph-rbac-write-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    std::fs::write(dir.join("cluster.json"), manifests.join("\n")).expect("write manifests");

    let backends: Vec<(&'static str, Box<dyn Backend>)> = vec![
        ("interpreter", Box::new(InterpreterBackend)),
        ("dd", Box::new(DdBackend { provenance: false })),
    ];
    let results = backends
        .into_iter()
        .map(|(name, backend)| {
            let mut store = MemStore::new();
            edb::load_from_manifests(&mut store, vec![dir.to_string_lossy().into_owned()])
                .expect("load manifests");
            let engine = Engine::new(store, Path::new("rules"), backend).expect("engine");
            (name, engine.evaluate().expect("evaluate"))
        })
        .collect();
    let _ = std::fs::remove_dir_all(&dir);
    results
}

/// The `rbac_write_role` rows of `writer`, as (mechanism, binding, role).
fn write_roles(result: &EvalStore, writer: &str) -> Vec<(String, String, String)> {
    let mut rows: Vec<(String, String, String)> = result
        .scan("rbac_write_role")
        .iter()
        .filter(|row| row[0] == Value::String(writer.into()))
        .map(|row| {
            let text = |value: &Value| match value {
                Value::String(s) => s.clone(),
                other => panic!("unexpected value {other:?}"),
            };
            (text(&row[2]), text(&row[3]), text(&row[4]))
        })
        .collect();
    rows.sort();
    rows
}

fn write_role(mechanism: &str, binding: &str, role: &str) -> (String, String, String) {
    (mechanism.into(), binding.into(), role.into())
}

/// Whether `writer` (a user or ServiceAccount) can grant itself
/// apigroup/resource/verb `*` cluster-wide.
fn grants_itself_everything(result: &EvalStore, writer: &str) -> bool {
    result.scan("rbac_write_perm").iter().any(|row| {
        row[0] == Value::String(writer.into())
            && row[1] == Value::Name("/principal".into())
            && row[5..] == ["*", "*", "*"].map(|s| Value::String(s.into()))
    })
}

fn cluster_role(name: &str, rules: &str) -> String {
    format!(
        r#"{{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{{"name":"{name}"}},"rules":{rules}}}"#
    )
}

/// A ClusterRoleBinding of `role` to one subject, given as JSON.
fn cluster_role_binding(name: &str, role: &str, subject: &str) -> String {
    format!(
        r#"{{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{{"name":"{name}"}},"roleRef":{{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"{role}"}},"subjects":[{subject}]}}"#
    )
}

fn service_account_subject(name: &str) -> String {
    format!(r#"{{"kind":"ServiceAccount","name":"{name}","namespace":"ns1"}}"#)
}

const SA_A: &str = "system:serviceaccount:ns1:sa-a";
const SA_B: &str = "system:serviceaccount:ns1:sa-b";

/// A cluster with cluster-admin and a read-only view ClusterRole, and two
/// ServiceAccounts in ns1.
fn base_cluster() -> Vec<String> {
    vec![
        cluster_role(
            "cluster-admin",
            r#"[{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}]"#,
        ),
        cluster_role(
            "view",
            r#"[{"apiGroups":[""],"resources":["pods"],"verbs":["get","list"]}]"#,
        ),
        r#"{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"sa-a","namespace":"ns1"}}"#.into(),
        r#"{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"sa-b","namespace":"ns1"}}"#.into(),
    ]
}

/// Bind ClusterRole `role` with `rules` to ServiceAccount ns1/`name`.
fn grant(manifests: &mut Vec<String>, name: &str, role: &str, rules: &str) {
    manifests.push(cluster_role(role, rules));
    manifests.push(cluster_role_binding(
        role,
        role,
        &service_account_subject(name),
    ));
}

// sa-a may bind and escalate clusterroles and create clusterrolebindings,
// but holds no */*/* grant. Binding cluster-admin to itself makes it
// cluster-admin-equivalent. sa-b may only create clusterrolebindings: the
// apiserver lets it bind only roles whose permissions it already holds, so
// it gains nothing.
#[test]
fn bind_and_create_bindings_reach_cluster_admin() {
    let mut manifests = base_cluster();
    grant(
        &mut manifests,
        "sa-a",
        "rbac-manager",
        r#"[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"verbs":["bind","escalate"]},
            {"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterrolebindings"],"verbs":["create"]}]"#,
    );
    grant(
        &mut manifests,
        "sa-b",
        "binding-creator",
        r#"[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterrolebindings"],"verbs":["create"]}]"#,
    );

    for (backend, result) in evaluate(&manifests) {
        let roles = write_roles(&result, SA_A);
        assert!(
            roles.contains(&write_role("bind", "", "cluster-admin")),
            "{backend}: sa-a can bind cluster-admin, got {roles:?}"
        );
        assert!(
            grants_itself_everything(&result, SA_A),
            "{backend}: sa-a reaches */*/*"
        );
        assert_eq!(
            write_roles(&result, SA_B),
            [],
            "{backend}: create clusterrolebindings alone grants nothing"
        );
        assert!(!grants_itself_everything(&result, SA_B), "{backend}");
    }
}

// bind limited by resourceNames to view: sa-a can bind view but not
// cluster-admin.
#[test]
fn bind_limited_to_resource_names() {
    let mut manifests = base_cluster();
    grant(
        &mut manifests,
        "sa-a",
        "view-binder",
        r#"[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"resourceNames":["view"],"verbs":["bind"]},
            {"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterrolebindings"],"verbs":["create"]}]"#,
    );

    for (backend, result) in evaluate(&manifests) {
        assert_eq!(
            write_roles(&result, SA_A),
            [write_role("bind", "", "view")],
            "{backend}"
        );
        assert!(!grants_itself_everything(&result, SA_A), "{backend}");
    }
}

// sa-a may escalate and update clusterroles, and is bound to
// self-editor: it can write */*/* into that role. sa-b may update
// clusterroles it is bound to, but not escalate, so it gains nothing.
#[test]
fn escalate_rewrites_a_bound_role() {
    let mut manifests = base_cluster();
    grant(
        &mut manifests,
        "sa-a",
        "self-editor",
        r#"[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"verbs":["update","escalate"]}]"#,
    );
    grant(
        &mut manifests,
        "sa-b",
        "role-updater",
        r#"[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"verbs":["update"]}]"#,
    );

    for (backend, result) in evaluate(&manifests) {
        assert_eq!(
            write_roles(&result, SA_A),
            [write_role("escalate", "self-editor", "self-editor")],
            "{backend}"
        );
        assert!(grants_itself_everything(&result, SA_A), "{backend}");
        assert_eq!(write_roles(&result, SA_B), [], "{backend}");
    }
}

// Wildcards: every verb on every resource of the RBAC API group is enough
// to write a new role with any rules and bind it.
#[test]
fn rbac_wildcards_write_and_bind_a_new_role() {
    let mut manifests = vec![
        r#"{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"sa-a","namespace":"ns1"}}"#.into(),
    ];
    grant(
        &mut manifests,
        "sa-a",
        "rbac-all",
        r#"[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["*"],"verbs":["*"]}]"#,
    );

    for (backend, result) in evaluate(&manifests) {
        let roles = write_roles(&result, SA_A);
        assert!(
            roles.contains(&write_role("escalate", "", "")),
            "{backend}: sa-a can write and bind a new role, got {roles:?}"
        );
        assert!(grants_itself_everything(&result, SA_A), "{backend}");
    }
}

// The permissions can come from a group: members of rbac-admins, known or
// not, can bind cluster-admin, so the group itself is a writer.
#[test]
fn group_grants_start_a_path() {
    let mut manifests = base_cluster();
    manifests.push(cluster_role(
        "rbac-manager",
        r#"[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"verbs":["bind"]},
            {"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterrolebindings"],"verbs":["create"]}]"#,
    ));
    manifests.push(cluster_role_binding(
        "rbac-admins",
        "rbac-manager",
        r#"{"kind":"Group","name":"rbac-admins"}"#,
    ));

    for (backend, result) in evaluate(&manifests) {
        let group_binds_admin = result.scan("rbac_write_role").contains(&vec![
            Value::String("rbac-admins".into()),
            Value::Name("/group".into()),
            Value::String("bind".into()),
            Value::String("".into()),
            Value::String("cluster-admin".into()),
        ]);
        assert!(
            group_binds_admin,
            "{backend}: rbac-admins can bind cluster-admin"
        );
    }
}
