// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A second system added through rule files alone: the
//! examples/eks-pod-identity/ adapter, loaded as `--rules` and
//! `json-tuples` would load it, on both backends. If this needs a change
//! outside the example, the closure (rules/closure.mg) has stopped being
//! the place systems plug in.

use std::path::Path;

use mangle_common::Value;
use mangle_interpreter::MemStore;
use pallograph::engine::{self, Backend, DdBackend, Engine, EvalStore, InterpreterBackend};
use pallograph::{edb, load};

const EXAMPLE: &str = "examples/eks-pod-identity";

/// The example's json-tuples datasources (pallograph.toml), as
/// (file, relation).
const TUPLES: [(&str, &str); 5] = [
    (
        "aws/pod-identity-associations.json",
        "aws_pod_identity_association",
    ),
    (
        "aws/pod-identity-trust.json",
        "aws_role_trusts_pod_identity",
    ),
    ("aws/role-can-assume.json", "aws_role_can_assume"),
    ("aws/access-entries.json", "aws_eks_access_entry"),
    ("aws/access-entry-groups.json", "aws_eks_access_entry_group"),
];

const UPLOADER_SA: &str = "system:serviceaccount:app:uploader";
const UPLOADER_ROLE: &str = "arn:aws:iam::111122223333:role/uploader";
const DEPLOY_ROLE: &str = "arn:aws:iam::111122223333:role/deploy";

/// Evaluate the example on each backend, leaving out the tuple files in
/// `skip`.
fn evaluate(skip: &[&str]) -> Vec<(&'static str, EvalStore)> {
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join(EXAMPLE);
    let mut rules = engine::read_rule_sources(&Path::new(env!("CARGO_MANIFEST_DIR")).join("rules"))
        .expect("read rules");
    rules.extend(engine::read_rule_sources(&example.join("eks.mg")).expect("read eks.mg"));

    let backends: Vec<(&'static str, Box<dyn Backend>)> = vec![
        ("interpreter", Box::new(InterpreterBackend)),
        ("dd", Box::new(DdBackend { provenance: false })),
    ];
    backends
        .into_iter()
        .map(|(name, backend)| {
            let mut store = MemStore::new();
            edb::load_from_manifests(
                &mut store,
                vec![example.join("cluster").to_string_lossy().into_owned()],
            )
            .expect("load manifests");
            for (file, relation) in TUPLES {
                if skip.contains(&file) {
                    continue;
                }
                let path = example.join(file).to_string_lossy().into_owned();
                for tuple in load::read_tuples(&path).expect("read tuples") {
                    store.add_fact(relation, tuple);
                }
            }
            let engine = Engine::with_rule_sources(store, Vec::new(), rules.clone(), backend)
                .expect("engine");
            (name, engine.evaluate().expect("evaluate"))
        })
        .collect()
}

fn string(value: &str) -> Value {
    Value::String(value.into())
}

fn name(value: &str) -> Value {
    Value::Name(value.into())
}

fn has_row(result: &EvalStore, relation: &str, row: &[Value]) -> bool {
    result.scan(relation).iter().any(|r| r.as_slice() == row)
}

fn controls(from: &str, to: &str, system: &str, kind: &str) -> [Value; 6] {
    [
        string(from),
        name("/k8s"),
        name("/user"),
        string(to),
        name(system),
        name(kind),
    ]
}

// alice execs into the uploader pod, so holds app:uploader, whose Pod
// Identity association gets the uploader role. That role may assume deploy,
// whose access entry puts it in platform-admins, back in the cluster.
#[test]
fn path_leaves_the_cluster_and_comes_back() {
    for (backend, result) in evaluate(&[]) {
        assert!(
            has_row(
                &result,
                "pivot",
                &[
                    string(UPLOADER_SA),
                    name("/k8s"),
                    name("/serviceaccount"),
                    string(UPLOADER_ROLE),
                    name("/aws"),
                    name("/role"),
                    name("/pod_identity"),
                    name("/grant"),
                ]
            ),
            "{backend}: got {:?}",
            result.scan("pivot")
        );
        for (target, system, kind) in [
            (UPLOADER_SA, "/k8s", "/serviceaccount"),
            (UPLOADER_ROLE, "/aws", "/role"),
            (DEPLOY_ROLE, "/aws", "/role"),
            ("platform-admins", "/k8s", "/group"),
        ] {
            assert!(
                has_row(
                    &result,
                    "controls",
                    &controls("alice", target, system, kind)
                ),
                "{backend}: alice reaches {target}"
            );
        }
        assert!(
            has_row(
                &result,
                "k8s_group_via_aws",
                &[
                    string("alice"),
                    string("platform-admins"),
                    string(DEPLOY_ROLE)
                ]
            ),
            "{backend}: got {:?}",
            result.scan("k8s_group_via_aws")
        );
        // The Kubernetes views see the path too, though it leaves the
        // cluster on the way.
        assert!(
            has_row(
                &result,
                "controls_group",
                &[string("alice"), string("platform-admins")]
            ),
            "{backend}: got {:?}",
            result.scan("controls_group")
        );
    }
}

// Without a trust policy for pods.eks.amazonaws.com the association gets
// nothing, and alice stays in the cluster.
#[test]
fn association_without_trust_is_no_pivot() {
    for (backend, result) in evaluate(&["aws/pod-identity-trust.json"]) {
        assert!(
            !has_row(
                &result,
                "controls",
                &controls("alice", UPLOADER_ROLE, "/aws", "/role")
            ),
            "{backend}: got {:?}",
            result.scan("controls")
        );
        assert!(
            !has_row(
                &result,
                "controls_group",
                &[string("alice"), string("platform-admins")]
            ),
            "{backend}"
        );
    }
}
