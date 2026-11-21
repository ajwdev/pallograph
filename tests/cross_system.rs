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

mod pivot_walk;

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

// The pivots command's walk reaches what controls says, from every node a
// path can start at, and alice's path out of the cluster and back is the
// four pivots of the example's story.
#[test]
fn walk_reaches_what_controls_says() {
    for (backend, result) in evaluate(&[]) {
        assert!(pivot_walk::assert_walk_matches_controls(backend, &result) > 0);

        let graph =
            pallograph::pivots::PivotGraph::from_scan(|relation| result.scan(relation).to_vec());
        let alice = pallograph::api::Node {
            name: "alice".into(),
            system: "/k8s".into(),
            kind: "/user".into(),
        };
        let paths = graph.walk(&alice);
        let to_admins = paths
            .iter()
            .find(|path| path.to.name == "platform-admins" && path.to.kind == "/group")
            .expect("alice reaches platform-admins");
        let mechanisms: Vec<&[String]> = to_admins
            .steps
            .iter()
            .map(|step| step.mechanisms.as_slice())
            .collect();
        assert_eq!(
            mechanisms,
            [
                &["/pod_exec".to_string()][..],
                &["/pod_identity".to_string()][..],
                &["/sts_assume_role".to_string()][..],
                &["/impersonate".to_string()][..],
            ],
            "{backend}"
        );
    }
}

/// Run the binary over the example with its config and eks.mg, on `script`.
fn run_example(script: &str) -> std::process::Output {
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join(EXAMPLE);
    // Unique per call: tests run in parallel threads of one process.
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let script_path = std::env::temp_dir().join(format!(
        "pallograph-cross-system-{}-{n}.pg",
        std::process::id()
    ));
    std::fs::write(&script_path, script).expect("write script");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pallograph"))
        .current_dir(&example)
        .args(["-C", "pallograph.toml", "--rules", "eks.mg", "--script"])
        .arg(&script_path)
        .output()
        .expect("run pallograph");
    let _ = std::fs::remove_file(&script_path);
    output
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn pivots_prints_a_path_out_of_the_cluster_and_back() {
    let output = run_example("pivots alice\n");
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let out = stdout(&output);
    assert!(
        out.contains(
            "/pod_identity [/grant] → arn:aws:iam::111122223333:role/uploader (/aws /role)"
        ),
        "{out}"
    );
    assert!(out.contains("platform-admins (/k8s /group)"), "{out}");
    assert!(
        stderr(&output).contains("Reached 5 node(s)."),
        "{}",
        stderr(&output)
    );

    let output = run_example("pivots platform-admins\n");
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
}

#[test]
fn pivots_ndjson_has_one_object_per_reached_node() {
    let output = run_example("format ndjson\npivots alice\n");
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let out = stdout(&output);
    let rows: Vec<serde_json::Value> = out
        .lines()
        .map(|line| serde_json::from_str(line).expect("json line"))
        .collect();
    assert_eq!(rows.len(), 5, "{out}");
    for row in &rows {
        assert_eq!(row["at"], "", "{row}");
        assert_eq!(row["from"]["name"], "alice", "{row}");
        assert!(!row["steps"].as_array().unwrap().is_empty(), "{row}");
    }
}

#[test]
fn pivots_to_unreachable_node_says_no_path() {
    let output = run_example("pivots system:serviceaccount:app:default alice\n");
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("No path from system:serviceaccount:app:default to alice."),
        "{}",
        stderr(&output)
    );
}

#[test]
fn pivots_unknown_node_fails() {
    let output = run_example("pivots nobody\n");
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr(&output).contains("No node named 'nobody'."),
        "{}",
        stderr(&output)
    );
}

#[test]
fn pivots_to_prints_the_whole_path() {
    let output = run_example("pivots alice platform-admins\n");
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let out = stdout(&output);
    for line in [
        "  /pod_exec [/grant] → system:serviceaccount:app:uploader (/k8s /serviceaccount)",
        "    /pod_identity [/grant] → arn:aws:iam::111122223333:role/uploader (/aws /role)",
        "      /sts_assume_role [/grant] → arn:aws:iam::111122223333:role/deploy (/aws /role)",
        "        as platform-admins (/k8s /group) /impersonate [/grant] → platform-admins (/k8s /group)",
    ] {
        assert!(
            out.lines().any(|printed| printed == line),
            "missing {line:?} in:\n{out}"
        );
    }
    assert!(!out.contains("app:default"), "{out}");
}
