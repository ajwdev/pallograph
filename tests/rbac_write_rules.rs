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

/// Load `manifests` (NDJSON) plus `user_groups` memberships and evaluate the
/// production rules on each backend.
fn evaluate(manifests: &[String], user_groups: &[(&str, &str)]) -> Vec<(&'static str, EvalStore)> {
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
            for (user, group) in user_groups {
                store.add_fact(
                    "user_groups",
                    vec![
                        Value::String((*user).into()),
                        Value::String((*group).into()),
                    ],
                );
            }
            let engine = Engine::new(store, Path::new("rules"), backend).expect("engine");
            (name, engine.evaluate().expect("evaluate"))
        })
        .collect();
    let _ = std::fs::remove_dir_all(&dir);
    results
}

/// (mechanism, namespace, binding, role kind, role) of one write.
type Write = (String, String, String, String, String);

fn write(mechanism: &str, namespace: &str, binding: &str, role_kind: &str, role: &str) -> Write {
    (
        mechanism.into(),
        namespace.into(),
        binding.into(),
        role_kind.into(),
        role.into(),
    )
}

/// The rows of `relation` (rbac_write_binding or rbac_write_binding_direct) for
/// binding subject `name`, sorted.
fn writes(result: &EvalStore, relation: &str, name: &str) -> Vec<Write> {
    let text = |value: &Value| match value {
        Value::String(s) => s.clone(),
        other => panic!("unexpected value {other:?}"),
    };
    let mut rows: Vec<Write> = result
        .scan(relation)
        .iter()
        .filter(|row| row[0] == Value::String(name.into()))
        .map(|row| {
            (
                text(&row[2]),
                text(&row[3]),
                text(&row[4]),
                text(&row[5]),
                text(&row[6]),
            )
        })
        .collect();
    rows.sort();
    rows
}

fn has_row(result: &EvalStore, relation: &str, row: &[&str]) -> bool {
    let row: Vec<Value> = row.iter().map(|s| Value::String((*s).into())).collect();
    result.scan(relation).contains(&row)
}

fn cluster_role(name: &str, rules: &str) -> String {
    format!(
        r#"{{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{{"name":"{name}"}},"rules":{rules}}}"#
    )
}

fn role(namespace: &str, name: &str, rules: &str) -> String {
    format!(
        r#"{{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{{"name":"{name}","namespace":"{namespace}"}},"rules":{rules}}}"#
    )
}

/// A ClusterRoleBinding of `role` to one subject, given as JSON.
fn cluster_role_binding(name: &str, role: &str, subject: &str) -> String {
    format!(
        r#"{{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{{"name":"{name}"}},"roleRef":{{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"{role}"}},"subjects":[{subject}]}}"#
    )
}

/// A RoleBinding in `namespace` of a `role_kind` to one subject.
fn role_binding(namespace: &str, name: &str, role_kind: &str, role: &str, subject: &str) -> String {
    format!(
        r#"{{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{{"name":"{name}","namespace":"{namespace}"}},"roleRef":{{"apiGroup":"rbac.authorization.k8s.io","kind":"{role_kind}","name":"{role}"}},"subjects":[{subject}]}}"#
    )
}

fn service_account_subject(name: &str) -> String {
    format!(r#"{{"kind":"ServiceAccount","name":"{name}","namespace":"ns1"}}"#)
}

const SA_A: &str = "system:serviceaccount:ns1:sa-a";
const SA_B: &str = "system:serviceaccount:ns1:sa-b";
const ADMIN_SA: &str = "system:serviceaccount:ns1:admin";

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

/// Bind ClusterRole `role` with `rules` to ServiceAccount ns1/`name`
/// cluster-wide.
fn grant(manifests: &mut Vec<String>, name: &str, role: &str, rules: &str) {
    manifests.push(cluster_role(role, rules));
    manifests.push(cluster_role_binding(
        role,
        role,
        &service_account_subject(name),
    ));
}

/// Bind a Role `role` with `rules` in ns1 to ServiceAccount ns1/`name`.
fn grant_in_ns1(manifests: &mut Vec<String>, name: &str, role_name: &str, rules: &str) {
    manifests.push(role("ns1", role_name, rules));
    manifests.push(role_binding(
        "ns1",
        role_name,
        "Role",
        role_name,
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

    for (backend, result) in evaluate(&manifests, &[]) {
        let direct = writes(&result, "rbac_write_binding", SA_A);
        assert!(
            direct.contains(&write("bind", "", "", "ClusterRole", "cluster-admin")),
            "{backend}: sa-a can bind cluster-admin, got {direct:?}"
        );
        assert_eq!(
            writes(&result, "rbac_write_binding", SA_B),
            [],
            "{backend}: create clusterrolebindings alone grants nothing"
        );
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

    for (backend, result) in evaluate(&manifests, &[]) {
        assert_eq!(
            writes(&result, "rbac_write_binding", SA_A),
            [write("bind", "", "", "ClusterRole", "view")],
            "{backend}"
        );
    }
}

// Two writes: sa-a may create clusterrolebindings and bind only
// rbac-admin, which allows binding any ClusterRole. In one request it can
// bind rbac-admin; having it, it can bind cluster-admin.
#[test]
fn a_chain_of_two_rbac_writes_is_followed() {
    let mut manifests = base_cluster();
    manifests.push(cluster_role(
        "rbac-admin",
        r#"[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"verbs":["bind"]}]"#,
    ));
    grant(
        &mut manifests,
        "sa-a",
        "rbac-admin-binder",
        r#"[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"resourceNames":["rbac-admin"],"verbs":["bind"]},
            {"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterrolebindings"],"verbs":["create"]}]"#,
    );

    for (backend, result) in evaluate(&manifests, &[]) {
        assert_eq!(
            writes(&result, "rbac_write_binding_direct", SA_A),
            [write("bind", "", "", "ClusterRole", "rbac-admin")],
            "{backend}"
        );
        let all = writes(&result, "rbac_write_binding", SA_A);
        assert!(
            all.contains(&write("bind", "", "", "ClusterRole", "cluster-admin")),
            "{backend}: got {all:?}"
        );
    }
}

// Three writes, the last in a namespace: sa-a may create RoleBindings in
// ns1 and bind only step-1 there. step-1 allows binding step-2, and
// step-2 allows binding any ClusterRole, so sa-a ends up with
// cluster-admin in ns1, and not cluster-wide.
#[test]
fn a_chain_of_three_rbac_writes_is_followed() {
    let mut manifests = base_cluster();
    manifests.push(cluster_role(
        "step-1",
        r#"[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"resourceNames":["step-2"],"verbs":["bind"]}]"#,
    ));
    manifests.push(cluster_role(
        "step-2",
        r#"[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"verbs":["bind"]}]"#,
    ));
    grant_in_ns1(
        &mut manifests,
        "sa-a",
        "step-0",
        r#"[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"resourceNames":["step-1"],"verbs":["bind"]},
            {"apiGroups":["rbac.authorization.k8s.io"],"resources":["rolebindings"],"verbs":["create"]}]"#,
    );

    for (backend, result) in evaluate(&manifests, &[]) {
        let direct = writes(&result, "rbac_write_binding_direct", SA_A);
        assert_eq!(
            direct,
            [write("bind", "ns1", "", "ClusterRole", "step-1")],
            "{backend}"
        );
        let all = writes(&result, "rbac_write_binding", SA_A);
        for role in ["step-2", "cluster-admin"] {
            assert!(
                all.contains(&write("bind", "ns1", "", "ClusterRole", role)),
                "{backend}: {role} in ns1, got {all:?}"
            );
        }
        assert!(
            all.iter().all(|(_, namespace, ..)| namespace == "ns1"),
            "{backend}: nothing outside ns1, got {all:?}"
        );
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

    for (backend, result) in evaluate(&manifests, &[]) {
        assert_eq!(
            writes(&result, "rbac_write_binding", SA_A),
            [write(
                "escalate",
                "",
                "self-editor",
                "ClusterRole",
                "self-editor"
            )],
            "{backend}"
        );
        assert_eq!(writes(&result, "rbac_write_binding", SA_B), [], "{backend}");
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

    for (backend, result) in evaluate(&manifests, &[]) {
        let direct = writes(&result, "rbac_write_binding", SA_A);
        assert!(
            direct.contains(&write("escalate", "", "", "ClusterRole", "")),
            "{backend}: sa-a can write and bind a new role, got {direct:?}"
        );
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

    for (backend, result) in evaluate(&manifests, &[]) {
        let group_binds_admin = result.scan("rbac_write_binding").contains(&vec![
            Value::String("rbac-admins".into()),
            Value::Name("/group".into()),
            Value::String("bind".into()),
            Value::String("".into()),
            Value::String("".into()),
            Value::String("ClusterRole".into()),
            Value::String("cluster-admin".into()),
        ]);
        assert!(
            group_binds_admin,
            "{backend}: rbac-admins can bind cluster-admin"
        );
    }
}

// In ns1, sa-a may create RoleBindings and bind ClusterRoles (both from a
// RoleBinding there). It gains cluster-admin in ns1 only, through a
// RoleBinding, and nothing cluster-wide.
#[test]
fn rolebinding_of_a_clusterrole_applies_in_its_namespace() {
    let mut manifests = base_cluster();
    grant_in_ns1(
        &mut manifests,
        "sa-a",
        "ns-binder",
        r#"[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"verbs":["bind"]},
            {"apiGroups":["rbac.authorization.k8s.io"],"resources":["rolebindings"],"verbs":["create"]}]"#,
    );

    for (backend, result) in evaluate(&manifests, &[]) {
        let all = writes(&result, "rbac_write_binding", SA_A);
        assert!(
            all.contains(&write("bind", "ns1", "", "ClusterRole", "cluster-admin")),
            "{backend}: got {all:?}"
        );
        assert!(
            all.iter().all(|(_, namespace, ..)| namespace == "ns1"),
            "{backend}: nothing outside ns1, got {all:?}"
        );
    }
}

// sa-a may create RoleBindings anywhere (cluster-wide) and bind Roles only
// in ns1 (a RoleBinding there): it can bind ns1's Roles, in ns1.
// Permissions held in two ways meet in ns1.
#[test]
fn rolebinding_of_a_role_in_its_namespace() {
    let mut manifests = base_cluster();
    manifests.push(role(
        "ns1",
        "secret-reader",
        r#"[{"apiGroups":[""],"resources":["secrets"],"verbs":["get"]}]"#,
    ));
    manifests.push(role(
        "ns2",
        "secret-reader",
        r#"[{"apiGroups":[""],"resources":["secrets"],"verbs":["get"]}]"#,
    ));
    grant(
        &mut manifests,
        "sa-a",
        "rolebinding-creator",
        r#"[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["rolebindings"],"verbs":["create"]}]"#,
    );
    grant_in_ns1(
        &mut manifests,
        "sa-a",
        "role-binder",
        r#"[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["roles"],"verbs":["bind"]}]"#,
    );

    for (backend, result) in evaluate(&manifests, &[]) {
        let all = writes(&result, "rbac_write_binding", SA_A);
        assert!(
            all.contains(&write("bind", "ns1", "", "Role", "secret-reader")),
            "{backend}: got {all:?}"
        );
        assert!(
            !all.contains(&write("bind", "ns2", "", "Role", "secret-reader")),
            "{backend}: bind is only allowed in ns1, got {all:?}"
        );
    }
}

// sa-a may escalate and update Roles in ns1 and is bound to one there: it
// can write */*/* into it, in ns1.
#[test]
fn escalate_rewrites_a_bound_role_in_a_namespace() {
    let mut manifests = base_cluster();
    grant_in_ns1(
        &mut manifests,
        "sa-a",
        "ns-self-editor",
        r#"[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["roles"],"verbs":["update","escalate"]}]"#,
    );

    for (backend, result) in evaluate(&manifests, &[]) {
        assert_eq!(
            writes(&result, "rbac_write_binding", SA_A),
            [write(
                "escalate",
                "ns1",
                "ns-self-editor",
                "Role",
                "ns-self-editor"
            )],
            "{backend}"
        );
    }
}

// sa-a may escalate and create ClusterRoles, but not update them, and is
// bound to an aggregating ClusterRole: a new ClusterRole with matching
// labels extends it.
#[test]
fn creating_an_aggregated_role_extends_a_bound_role() {
    let mut manifests = base_cluster();
    manifests.push(
        r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"aggregate"},"aggregationRule":{"clusterRoleSelectors":[{"matchLabels":{"example.com/aggregate-to":"aggregate"}}]},"rules":[]}"#.into(),
    );
    manifests.push(cluster_role_binding(
        "sa-a-aggregate",
        "aggregate",
        &service_account_subject("sa-a"),
    ));
    grant(
        &mut manifests,
        "sa-a",
        "role-creator",
        r#"[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"verbs":["create","escalate"]}]"#,
    );

    for (backend, result) in evaluate(&manifests, &[]) {
        assert_eq!(
            writes(&result, "rbac_write_binding", SA_A),
            [write(
                "escalate",
                "",
                "sa-a-aggregate",
                "ClusterRole",
                "aggregate"
            )],
            "{backend}"
        );
    }
}

// Members of system:masters bypass the escalation checks, so the group can
// write and bind any role.
#[test]
fn system_masters_can_write_any_role() {
    for (backend, result) in evaluate(&base_cluster(), &[("root", "system:masters")]) {
        let masters = writes(&result, "rbac_write_binding", "system:masters");
        assert!(
            masters.contains(&write("escalate", "", "", "ClusterRole", "")),
            "{backend}: got {masters:?}"
        );
    }
}

/// ns1/admin holds cluster-admin and runs a pod.
fn admin_pod() -> Vec<String> {
    vec![
        r#"{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"admin","namespace":"ns1"}}"#.into(),
        r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p","namespace":"ns1"},"spec":{"serviceAccountName":"admin","containers":[{"name":"c","image":"busybox"}]}}"#.into(),
        cluster_role_binding("admin", "cluster-admin", &service_account_subject("admin")),
    ]
}

// A gained role feeds escalation.mg: sa-a may only bind ns1's pod-creator
// Role and create RoleBindings in ns1. Binding it lets sa-a create pods in
// ns1, which run as ns1/admin.
#[test]
fn a_gained_role_reaches_identities() {
    let mut manifests = base_cluster();
    manifests.extend(admin_pod());
    manifests.push(role(
        "ns1",
        "pod-creator",
        r#"[{"apiGroups":[""],"resources":["pods"],"verbs":["create"]}]"#,
    ));
    grant_in_ns1(
        &mut manifests,
        "sa-a",
        "ns-binder",
        r#"[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["roles"],"resourceNames":["pod-creator"],"verbs":["bind"]},
            {"apiGroups":["rbac.authorization.k8s.io"],"resources":["rolebindings"],"verbs":["create"]}]"#,
    );

    for (backend, result) in evaluate(&manifests, &[]) {
        assert!(
            has_row(&result, "controls_identity", &[SA_A, ADMIN_SA]),
            "{backend}: sa-a reaches ns1/admin, got {:?}",
            result.scan("controls_identity")
        );
    }
}

// An identity reached through escalation brings its RBAC writes: deployer
// may create pods in ns1, which can run as ns1/sa-a, and sa-a can bind
// cluster-admin. deployer controls sa-a, and sa-a's own binding subject
// can grant itself cluster-admin.
#[test]
fn an_identity_reached_brings_its_rbac_writes() {
    let mut manifests = base_cluster();
    grant(
        &mut manifests,
        "sa-a",
        "binder",
        r#"[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"verbs":["bind"]},
            {"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterrolebindings"],"verbs":["create"]}]"#,
    );
    manifests.push(role(
        "ns1",
        "pod-creator",
        r#"[{"apiGroups":[""],"resources":["pods"],"verbs":["create"]}]"#,
    ));
    manifests.push(role_binding(
        "ns1",
        "deployer",
        "Role",
        "pod-creator",
        r#"{"kind":"User","name":"deployer"}"#,
    ));

    for (backend, result) in evaluate(&manifests, &[]) {
        assert!(
            has_row(&result, "controls_identity", &["deployer", SA_A]),
            "{backend}: deployer controls sa-a"
        );
        assert!(
            writes(&result, "rbac_write_binding", SA_A).contains(&write(
                "bind",
                "",
                "",
                "ClusterRole",
                "cluster-admin"
            )),
            "{backend}"
        );
    }
}

// resourceNames limit update, escalate and create too. sa-a may update and
// escalate only a ClusterRole named "*" (a literal name, not a wildcard),
// so it cannot rewrite self-editor. sa-b may update and escalate
// self-editor by name, so it can. Neither may create a ClusterRole: a create
// names no object, so a rule limited to names never allows it.
#[test]
fn resource_names_limit_update_escalate_and_create() {
    let mut manifests = base_cluster();
    manifests.push(cluster_role(
        "self-editor",
        r#"[{"apiGroups":[""],"resources":["configmaps"],"verbs":["get"]}]"#,
    ));
    for name in ["sa-a", "sa-b"] {
        manifests.push(cluster_role_binding(
            &format!("{name}-self-editor"),
            "self-editor",
            &service_account_subject(name),
        ));
    }
    grant(
        &mut manifests,
        "sa-a",
        "star-editor",
        r#"[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"resourceNames":["*"],"verbs":["create","update","escalate"]}]"#,
    );
    grant(
        &mut manifests,
        "sa-b",
        "named-editor",
        r#"[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"resourceNames":["self-editor"],"verbs":["create","update","escalate"]}]"#,
    );

    for (backend, result) in evaluate(&manifests, &[]) {
        assert_eq!(writes(&result, "rbac_write_binding", SA_A), [], "{backend}");
        assert_eq!(
            writes(&result, "rbac_write_binding", SA_B),
            [write(
                "escalate",
                "",
                "sa-b-self-editor",
                "ClusterRole",
                "self-editor"
            )],
            "{backend}"
        );
    }
}

// alice is in rbac-admins only through user_groups, and the group may bind
// ns1's pod-creator Role and create RoleBindings in ns1. Logged in, alice
// can bind it and create pods running as ns1/admin. imp may impersonate
// users, but an impersonated alice is not in rbac-admins, so imp does not
// reach ns1/admin through alice's writes.
#[test]
fn an_assumed_user_writes_without_its_user_groups() {
    let mut manifests = base_cluster();
    manifests.extend(admin_pod());
    manifests.push(role(
        "ns1",
        "pod-creator",
        r#"[{"apiGroups":[""],"resources":["pods"],"verbs":["create"]}]"#,
    ));
    manifests.push(role(
        "ns1",
        "pod-creator-binder",
        r#"[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["roles"],"resourceNames":["pod-creator"],"verbs":["bind"]},
            {"apiGroups":["rbac.authorization.k8s.io"],"resources":["rolebindings"],"verbs":["create"]}]"#,
    ));
    manifests.push(role_binding(
        "ns1",
        "rbac-admins",
        "Role",
        "pod-creator-binder",
        r#"{"kind":"Group","name":"rbac-admins"}"#,
    ));
    manifests.push(cluster_role_binding(
        "alice-view",
        "view",
        r#"{"kind":"User","name":"alice"}"#,
    ));
    manifests.push(cluster_role(
        "user-impersonator",
        r#"[{"apiGroups":[""],"resources":["users"],"verbs":["impersonate"]}]"#,
    ));
    manifests.push(cluster_role_binding(
        "imp",
        "user-impersonator",
        r#"{"kind":"User","name":"imp"}"#,
    ));

    for (backend, result) in evaluate(&manifests, &[("alice", "rbac-admins")]) {
        assert!(
            has_row(&result, "controls_identity", &["alice", ADMIN_SA]),
            "{backend}: alice logged in reaches ns1/admin"
        );
        assert!(
            has_row(&result, "controls_identity", &["imp", "alice"]),
            "{backend}: imp controls alice"
        );
        assert!(
            !has_row(&result, "controls_identity", &["imp", ADMIN_SA]),
            "{backend}: impersonated alice is not in rbac-admins"
        );
    }
}
