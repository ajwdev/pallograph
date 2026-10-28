// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Escalation rules (rules/escalation.mg) over small hand-written clusters,
//! checked on both backends. Each test reads the derived relations
//! directly, so it pins what the rules say independently of the Rust
//! consumers in src/rbac.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use mangle_common::Value;
use mangle_interpreter::MemStore;
use pallograph::edb;
use pallograph::engine::{Backend, DdBackend, Engine, EvalStore, InterpreterBackend};

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// Load `manifests` (NDJSON) plus `user_groups` memberships and evaluate the
/// production rules on each backend.
fn evaluate(manifests: &[&str], user_groups: &[(&str, &str)]) -> Vec<(&'static str, EvalStore)> {
    // Unique per call: tests run in parallel threads of one process.
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "pallograph-escalation-rules-{}-{n}",
        std::process::id()
    ));
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

fn has_row(result: &EvalStore, relation: &str, row: &[&str]) -> bool {
    let row: Vec<Value> = row.iter().map(|s| Value::String((*s).into())).collect();
    result.scan(relation).contains(&row)
}

fn cluster_role(name: &str, rules: &str) -> String {
    format!(
        r#"{{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{{"name":"{name}"}},"rules":{rules}}}"#
    )
}

/// A ClusterRoleBinding of `role` to one User or Group subject.
fn cluster_role_binding(name: &str, role: &str, subject_kind: &str, subject: &str) -> String {
    format!(
        r#"{{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{{"name":"{name}"}},"roleRef":{{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"{role}"}},"subjects":[{{"kind":"{subject_kind}","name":"{subject}"}}]}}"#
    )
}

const TARGET: &str = "system:serviceaccount:demo:target";

/// A pod in demo runs as demo:target, which holds cluster-admin, and the
/// group execs may exec into pods in demo.
fn exec_into_admin_pod() -> Vec<String> {
    vec![
        cluster_role("cluster-admin", r#"[{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}]"#),
        r#"{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"target","namespace":"demo"}}"#.into(),
        r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p","namespace":"demo"},"spec":{"serviceAccountName":"target","containers":[{"name":"c","image":"busybox"}]}}"#.into(),
        r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"target-admin"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},"subjects":[{"kind":"ServiceAccount","name":"target","namespace":"demo"}]}"#.into(),
        r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"exec","namespace":"demo"},"rules":[{"apiGroups":[""],"resources":["pods/exec"],"verbs":["create"]}]}"#.into(),
        r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"exec","namespace":"demo"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"exec"},"subjects":[{"kind":"Group","name":"execs"}]}"#.into(),
    ]
}

// imp may impersonate users and groups. Impersonating execs gives imp the
// group's pods/exec grant, which reaches demo:target, so imp controls
// demo:target: the path continues past the group.
#[test]
fn group_impersonation_continues_the_path() {
    let mut manifests = exec_into_admin_pod();
    manifests.push(cluster_role(
        "impersonator",
        r#"[{"apiGroups":[""],"resources":["users","groups"],"verbs":["impersonate"]}]"#,
    ));
    manifests.push(cluster_role_binding("imp", "impersonator", "User", "imp"));
    let manifests: Vec<&str> = manifests.iter().map(String::as_str).collect();

    for (backend, result) in evaluate(&manifests, &[]) {
        assert!(
            has_row(&result, "controls_group", &["imp", "execs"]),
            "{backend}: imp controls execs"
        );
        assert!(
            has_row(&result, "controls_identity", &["imp", TARGET]),
            "{backend}: imp reaches {TARGET} through execs, got {:?}",
            result.scan("controls_identity")
        );
    }
}

// The same from a group: members of impersonators may impersonate groups,
// so they reach what execs reaches.
#[test]
fn group_to_group_impersonation_continues_the_path() {
    let mut manifests = exec_into_admin_pod();
    manifests.push(cluster_role(
        "group-impersonator",
        r#"[{"apiGroups":[""],"resources":["groups"],"verbs":["impersonate"]}]"#,
    ));
    manifests.push(cluster_role_binding(
        "impersonators",
        "group-impersonator",
        "Group",
        "impersonators",
    ));
    let manifests: Vec<&str> = manifests.iter().map(String::as_str).collect();

    for (backend, result) in evaluate(&manifests, &[]) {
        assert!(
            has_row(&result, "group_controls_group", &["impersonators", "execs"]),
            "{backend}: impersonators controls execs"
        );
        assert!(
            has_row(
                &result,
                "group_controls_identity",
                &["impersonators", TARGET]
            ),
            "{backend}: impersonators reaches {TARGET} through execs, got {:?}",
            result.scan("group_controls_identity")
        );
    }
}

// alice may impersonate users. bob holds a grant of his own and, per
// user_groups, is in execs. Impersonating bob gives alice bob's username
// and system:authenticated, not execs, so alice does not reach
// demo:target, while bob logging in himself does. carol is in execs too but
// holds nothing of her own, so impersonating her gains nothing.
#[test]
fn user_impersonation_does_not_carry_user_groups() {
    let mut manifests = exec_into_admin_pod();
    manifests.push(cluster_role(
        "user-impersonator",
        r#"[{"apiGroups":[""],"resources":["users"],"verbs":["impersonate"]}]"#,
    ));
    manifests.push(cluster_role_binding(
        "alice",
        "user-impersonator",
        "User",
        "alice",
    ));
    manifests.push(cluster_role(
        "node-reader",
        r#"[{"apiGroups":[""],"resources":["nodes"],"verbs":["get"]}]"#,
    ));
    manifests.push(cluster_role_binding("bob", "node-reader", "User", "bob"));
    let manifests: Vec<&str> = manifests.iter().map(String::as_str).collect();

    for (backend, result) in evaluate(&manifests, &[("bob", "execs"), ("carol", "execs")]) {
        assert!(
            has_row(&result, "controls_identity", &["alice", "bob"]),
            "{backend}: alice controls bob"
        );
        assert!(
            !has_row(&result, "controls_identity", &["alice", "carol"]),
            "{backend}: carol holds no grant of her own"
        );
        assert!(
            !has_row(&result, "controls_identity", &["alice", TARGET]),
            "{backend}: impersonating bob does not grant execs"
        );
        assert!(
            has_row(&result, "controls_identity", &["bob", TARGET]),
            "{backend}: bob himself is in execs"
        );
        let assumed_groups: Vec<&Value> = result
            .scan("assumed_subject")
            .iter()
            .filter(|row| {
                row[0] == Value::String("bob".into()) && row[1] == Value::Name("/group".into())
            })
            .map(|row| &row[2])
            .collect();
        assert_eq!(
            assumed_groups,
            [&Value::String("system:authenticated".into())],
            "{backend}: assumed bob is in system:authenticated only"
        );
    }
}

/// A RoleBinding in `namespace` of the ClusterRole `role` to one
/// ServiceAccount of that namespace.
fn role_binding_to_sa(namespace: &str, name: &str, role: &str, service_account: &str) -> String {
    format!(
        r#"{{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{{"name":"{name}","namespace":"{namespace}"}},"roleRef":{{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"{role}"}},"subjects":[{{"kind":"ServiceAccount","name":"{service_account}","namespace":"{namespace}"}}]}}"#
    )
}

fn service_account(namespace: &str, name: &str) -> String {
    format!(
        r#"{{"apiVersion":"v1","kind":"ServiceAccount","metadata":{{"name":"{name}","namespace":"{namespace}"}}}}"#
    )
}

const DEPLOYER: &str = "system:serviceaccount:team-a:deployer";

/// team-a:deployer, the ClusterRole impersonator (impersonate users and
/// groups), and the group platform-admins holding cluster-admin. The
/// caller binds impersonator.
fn user_and_group_impersonation() -> Vec<String> {
    vec![
        cluster_role(
            "cluster-admin",
            r#"[{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}]"#,
        ),
        cluster_role_binding(
            "platform-admins",
            "cluster-admin",
            "Group",
            "platform-admins",
        ),
        cluster_role(
            "impersonator",
            r#"[{"apiGroups":[""],"resources":["users","groups"],"verbs":["impersonate"]}]"#,
        ),
        service_account("team-a", "deployer"),
        cluster_role(
            "node-reader",
            r#"[{"apiGroups":[""],"resources":["nodes"],"verbs":["get"]}]"#,
        ),
        cluster_role_binding("bob", "node-reader", "User", "bob"),
    ]
}

// Kubernetes checks impersonating a user or group as a cluster-scoped
// request, which a RoleBinding never matches. So deployer, granted
// impersonate on users and groups only in team-a, can impersonate neither
// platform-admins nor bob.
#[test]
fn namespaced_user_and_group_impersonation_grants_nothing() {
    let mut manifests = user_and_group_impersonation();
    manifests.push(role_binding_to_sa(
        "team-a",
        "deployer-impersonate",
        "impersonator",
        "deployer",
    ));
    let manifests: Vec<&str> = manifests.iter().map(String::as_str).collect();

    for (backend, result) in evaluate(&manifests, &[]) {
        assert!(
            !has_row(&result, "controls_group", &[DEPLOYER, "platform-admins"]),
            "{backend}: a RoleBinding does not allow impersonating groups, got {:?}",
            result.scan("controls_group")
        );
        assert!(
            !has_row(&result, "controls_identity", &[DEPLOYER, "bob"]),
            "{backend}: a RoleBinding does not allow impersonating users, got {:?}",
            result.scan("controls_identity")
        );
    }
}

// The same grant through a ClusterRoleBinding is cluster-scoped, so
// deployer can impersonate platform-admins and bob.
#[test]
fn cluster_wide_user_and_group_impersonation_escalates() {
    let mut manifests = user_and_group_impersonation();
    manifests.push(r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"deployer-impersonate"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"impersonator"},"subjects":[{"kind":"ServiceAccount","name":"deployer","namespace":"team-a"}]}"#.into());
    let manifests: Vec<&str> = manifests.iter().map(String::as_str).collect();

    for (backend, result) in evaluate(&manifests, &[]) {
        assert!(
            has_row(&result, "controls_group", &[DEPLOYER, "platform-admins"]),
            "{backend}: deployer controls platform-admins"
        );
        assert!(
            has_row(&result, "controls_identity", &[DEPLOYER, "bob"]),
            "{backend}: deployer controls bob"
        );
    }
}

// Impersonating a ServiceAccount is checked in the ServiceAccount's
// namespace, so impersonate on serviceaccounts in team-a reaches
// team-a:admin but not team-b:admin, though both hold cluster-admin.
// Checked one hop at a time (escalation_hop): through team-a:admin,
// deployer reaches everything.
#[test]
fn namespaced_service_account_impersonation_stays_in_its_namespace() {
    let manifests = [
        cluster_role(
            "cluster-admin",
            r#"[{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}]"#,
        ),
        cluster_role(
            "sa-impersonator",
            r#"[{"apiGroups":[""],"resources":["serviceaccounts"],"verbs":["impersonate"]}]"#,
        ),
        service_account("team-a", "deployer"),
        service_account("team-a", "admin"),
        service_account("team-b", "admin"),
        role_binding_to_sa(
            "team-a",
            "deployer-impersonate",
            "sa-impersonator",
            "deployer",
        ),
        r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"admins"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},"subjects":[{"kind":"ServiceAccount","name":"admin","namespace":"team-a"},{"kind":"ServiceAccount","name":"admin","namespace":"team-b"}]}"#.into(),
    ];
    let manifests: Vec<&str> = manifests.iter().map(String::as_str).collect();

    for (backend, result) in evaluate(&manifests, &[]) {
        assert!(
            has_row(
                &result,
                "escalation_hop",
                &[DEPLOYER, "system:serviceaccount:team-a:admin"]
            ),
            "{backend}: deployer can impersonate team-a:admin"
        );
        assert!(
            !has_row(
                &result,
                "escalation_hop",
                &[DEPLOYER, "system:serviceaccount:team-b:admin"]
            ),
            "{backend}: deployer cannot impersonate team-b:admin, got {:?}",
            result.scan("escalation_hop")
        );
    }
}
