// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Drives the built binary over the small fixture to check the REPL's
//! `?-` query UX: tuple listing, output formats, unknown-relation hints and
//! the hint printed for input that is not a command, and `\source` of the
//! example scenarios on both backends.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// Run a REPL session and return (stdout, stderr).
fn run_session(commands: &str) -> (String, String) {
    run_session_with(&[], commands)
}

/// Like [`run_session`], with extra command-line arguments.
fn run_session_with(args: &[&str], commands: &str) -> (String, String) {
    run_session_loading(&[], args, commands)
}

/// Like [`run_session_with`], with `extra_paths` loaded at startup as k8s
/// manifests after the small fixture.
fn run_session_loading(extra_paths: &[&Path], args: &[&str], commands: &str) -> (String, String) {
    // Unique per call: tests run in parallel threads of one process.
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("pallograph-repl-query-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let config = dir.join("pallograph.toml");
    let mut paths = vec![format!(
        "{}/fixtures/testdata/small",
        env!("CARGO_MANIFEST_DIR")
    )];
    paths.extend(extra_paths.iter().map(|p| p.to_string_lossy().into_owned()));
    std::fs::write(
        &config,
        format!(
            "default_profile = \"dev\"\n\
             [datasources.local]\n\
             source = \"file\"\n\
             paths = {paths:?}\n\
             content = \"k8s-manifests\"\n\
             [profiles.dev]\n\
             sources = [\"local\"]\n"
        ),
    )
    .expect("write config");

    let mut child = Command::new(env!("CARGO_BIN_EXE_pallograph"))
        .arg("-C")
        .arg(&config)
        .args(["--profile", "dev"])
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pallograph");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(commands.as_bytes())
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait");
    let _ = std::fs::remove_dir_all(&dir);
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

const ADMIN: &str = r#"?- direct_perm("admin@example.com")"#;

#[test]
fn default_listing_names_columns() {
    let (stdout, _) = run_session(&format!("{ADMIN}\n::quit\n"));
    assert!(
        stdout.contains(
            r#"Principal = "admin@example.com", Kind = /user, Namespace = "", ApiGroup = "*", Resource = "*", ResourceName = /any, Verb = "*""#
        ),
        "stdout: {stdout}"
    );
}

#[test]
fn compact_format_prints_tuples() {
    let (stdout, _) = run_session(&format!("\\format compact\n{ADMIN}\n::quit\n"));
    assert!(
        stdout.contains(r#"direct_perm("admin@example.com", /user, "", "*", "*", /any, "*")"#),
        "stdout: {stdout}"
    );
    assert!(!stdout.contains("Principal ="), "stdout: {stdout}");
}

#[test]
fn table_format_prints_header_and_rule() {
    let (stdout, _) = run_session(&format!("\\format table\n{ADMIN}\n::quit\n"));
    let lines: Vec<&str> = stdout.lines().filter(|l| l.starts_with("  ")).collect();
    assert!(lines.len() >= 3, "stdout: {stdout}");
    assert!(
        lines[0].contains("Principal") && lines[0].contains("Verb"),
        "header: {}",
        lines[0]
    );
    assert!(
        lines[1].trim().chars().all(|c| c == '-' || c == ' '),
        "rule: {}",
        lines[1]
    );
    assert!(lines[2].contains("admin@example.com"), "row: {}", lines[2]);
}

#[test]
fn unknown_relation_suggests_near_names() {
    let (_, stderr) = run_session("?- direct_permz\n::quit\n");
    assert!(
        stderr.contains("Unknown relation 'direct_permz'. Did you mean: direct_perm"),
        "stderr: {stderr}"
    );
}

#[test]
fn too_many_arguments_is_an_error() {
    let (stdout, stderr) = run_session(
        "?- direct_perm(\"a\", \"b\", \"c\", \"d\", \"e\", \"f\", \"g\", \"h\")\n::quit\n",
    );
    assert!(
        stderr.contains("direct_perm has 7 columns, got 8 arguments."),
        "stderr: {stderr}"
    );
    assert!(!stdout.contains("Principal ="), "stdout: {stdout}");
}

#[test]
fn plain_format_name_is_rejected() {
    let (_, stderr) = run_session("\\format plain\n::quit\n");
    assert!(
        stderr
            .contains("Unknown format 'plain'. Use: default | compact | pretty | table | ndjson."),
        "stderr: {stderr}"
    );
}

#[test]
fn bare_predicate_line_prints_hint() {
    let (stdout, stderr) = run_session("direct_perm(X)\n::quit\n");
    assert!(
        stderr.contains("Not a command. Queries start with ?-, e.g. ?- direct_perm(X)"),
        "stderr: {stderr}"
    );
    assert!(!stdout.contains("direct_perm("), "stdout: {stdout}");
}

/// The example scenarios hold struct-valued `role_rule` facts, which the DD
/// backend could not evaluate as bodiless rules. Sourced as facts, both
/// backends must agree on who alice can become.
#[test]
fn sourced_examples_match_across_backends() {
    let examples = [
        "examples/exec-escalation/alice-exec.mg",
        "examples/token-escalation/alice-sa-token.mg",
        "examples/two-hop-escalation/alice-twohop.mg",
        "examples/hidden-clusterrole/hidden-clusterrole.mg",
    ];
    for example in examples {
        let commands = format!(
            "\\source {example}\n\\format compact\n?- controls_identity(\"alice\", T)\n::quit\n"
        );
        let results = ["interpreter", "dd"].map(|backend| {
            let (stdout, stderr) = run_session_with(&["--backend", backend], &commands);
            assert!(
                stderr.contains("Sourced and evaluated."),
                "{example} on {backend}: {stderr}"
            );
            let mut rows: Vec<String> = stdout
                .lines()
                .filter(|line| line.starts_with("  T = "))
                .map(str::to_string)
                .collect();
            // The backends list rows in different orders.
            rows.sort();
            rows
        });
        assert!(
            results[0].contains(&r#"  T = "system:serviceaccount:kube-system:default""#.into()),
            "{example}: {:?}",
            results[0]
        );
        assert_eq!(results[0], results[1], "{example}");
    }
}

/// Facts asserted and retracted on either side of a `\snapshot` must reach
/// both the snapshot and the current state that `\access-diff` compares
/// against, on both backends.
#[test]
fn access_diff_sees_fact_changes_across_backends() {
    let alice = r#"role_rule("kube-system", "alice-debug", {/apiGroups: [""], /resources: ["pods/exec"], /verbs: ["create"]})"#;
    let bob = r#"role_rule("kube-system", "bob-oncall", {/apiGroups: [""], /resources: ["pods/exec"], /verbs: ["create"]})"#;
    let commands = format!(
        "+binding_subject(\"kube-system\", \"rb-alice\", /user, \"alice@example.com\").\n\
         +binding_roleref(\"kube-system\", \"rb-alice\", \"Role\", \"alice-debug\").\n\
         +{alice}.\n\
         \\snapshot before\n\
         -{alice}.\n\
         +binding_subject(\"kube-system\", \"rb-bob\", /user, \"bob@example.com\").\n\
         +binding_roleref(\"kube-system\", \"rb-bob\", \"Role\", \"bob-oncall\").\n\
         +{bob}.\n\
         \\access-diff before\n\
         ::quit\n"
    );
    let results = ["interpreter", "dd"].map(|backend| {
        let (stdout, _) = run_session_with(&["--backend", backend], &commands);
        let mut verdicts: Vec<String> = stdout
            .lines()
            .filter(|line| line.starts_with("    FAIL  ") || line.starts_with("    PASS  "))
            .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect();
        // The backends list rows in different orders.
        verdicts.sort();
        verdicts
    });
    assert!(
        results[0]
            .iter()
            .any(|line| line.starts_with("FAIL bob@example.com")),
        "{:?}",
        results[0]
    );
    assert!(
        results[0]
            .iter()
            .any(|line| line.starts_with("PASS alice@example.com")),
        "{:?}",
        results[0]
    );
    assert_eq!(results[0], results[1]);
}

/// `\snapshot` freezes a copy of the eval state; it must not inject
/// `<name>__<relation>` facts into the live engine, so querying one is an
/// unknown relation, not a hit.
#[test]
fn snapshot_does_not_add_relations_to_live_state() {
    for backend in ["interpreter", "dd"] {
        let (_, stderr) = run_session_with(
            &["--backend", backend],
            "\\snapshot before\n?- before__direct_perm(N, K, Ns, G, R, Rn, V)\n::quit\n",
        );
        assert!(
            stderr.contains("Unknown relation 'before__direct_perm'"),
            "{backend}: {stderr}"
        );
    }
}

/// A second `\snapshot` under a name already taken is refused, leaving the
/// first snapshot (and the current state) untouched.
#[test]
fn snapshot_refuses_taken_name() {
    for backend in ["interpreter", "dd"] {
        let (stdout, stderr) = run_session_with(
            &["--backend", backend],
            "\\snapshot before\n\\snapshot before\n\\diff before\n::quit\n",
        );
        assert!(
            stderr.contains("Snapshot 'before' already exists."),
            "{backend}: {stderr}"
        );
        assert!(stdout.contains("(no changes)"), "{backend}: {stdout}");
    }
}

/// `\snapshot a b` is a name with a space in it, not a name followed by
/// stray words: it is refused, and no snapshot named `a` is created.
#[test]
fn snapshot_refuses_name_with_space() {
    for backend in ["interpreter", "dd"] {
        let (_, stderr) = run_session_with(
            &["--backend", backend],
            "\\snapshot a b\n\\diff a\n::quit\n",
        );
        assert!(
            stderr.contains("Snapshot names cannot be empty or contain spaces."),
            "{backend}: {stderr}"
        );
        assert!(
            stderr.contains("No snapshot named 'a'."),
            "{backend}: {stderr}"
        );
    }
}

/// Taking a second snapshot must not fold the facts of an earlier one into
/// it: two snapshots of the same, unchanged state report the same counts.
#[test]
fn snapshots_do_not_copy_earlier_snapshots() {
    for backend in ["interpreter", "dd"] {
        let (stdout, _) = run_session_with(
            &["--backend", backend],
            "\\snapshot a\n\\snapshot b\n::quit\n",
        );
        let counts: Vec<&str> = stdout
            .lines()
            .filter_map(|l| l.strip_prefix("Saved snapshot "))
            .map(|l| l.split_once('(').expect("relation/fact counts").1)
            .collect();
        assert_eq!(counts.len(), 2, "{backend}: {stdout}");
        assert_eq!(counts[0], counts[1], "{backend}: {stdout}");
    }
}

/// A `?-` query's result relation (`_0`) is scratch, not eval state a
/// snapshot should freeze.
#[test]
fn snapshot_leaves_out_query_results() {
    for backend in ["interpreter", "dd"] {
        let (stdout, _) = run_session_with(
            &["--backend", backend],
            "?- direct_perm(\"admin@example.com\", K, Ns, G, R, Rn, V)\n\
             \\snapshot before\n\
             \\diff before\n\
             ::quit\n",
        );
        assert!(
            !stdout.lines().any(|l| l.contains("_0")),
            "{backend}: {stdout}"
        );
    }
}

/// `::reset` drops added facts and rules but keeps named snapshots: a diff
/// against one taken before the reset sees no change.
#[test]
fn reset_keeps_snapshots() {
    for backend in ["interpreter", "dd"] {
        let commands = "\\snapshot before\n\
             +binding_subject(\"kube-system\", \"rb-bob\", /user, \"bob@example.com\").\n\
             \\reset\n\
             \\diff before\n\
             ::quit\n";
        let (stdout, _) = run_session_with(&["--backend", backend], commands);
        assert!(stdout.contains("(no changes)"), "{backend}: {stdout}");
    }
}

// -----------------------------------------------------------------------
// `\use`: pointing queries at a snapshot
// -----------------------------------------------------------------------

/// Shared setup for the `\use` tests: alice is granted `pods/exec` on
/// `kube-system`, `\snapshot before` freezes that, then alice is retracted
/// and bob is granted the same permission. `before` keeps alice's grant;
/// the live state has bob's instead.
fn before_bob_setup() -> String {
    let alice = r#"role_rule("kube-system", "alice-debug", {/apiGroups: [""], /resources: ["pods/exec"], /verbs: ["create"]})"#;
    let bob = r#"role_rule("kube-system", "bob-oncall", {/apiGroups: [""], /resources: ["pods/exec"], /verbs: ["create"]})"#;
    format!(
        "+binding_subject(\"kube-system\", \"rb-alice\", /user, \"alice@example.com\").\n\
         +binding_roleref(\"kube-system\", \"rb-alice\", \"Role\", \"alice-debug\").\n\
         +{alice}.\n\
         \\snapshot before\n\
         -{alice}.\n\
         +binding_subject(\"kube-system\", \"rb-bob\", /user, \"bob@example.com\").\n\
         +binding_roleref(\"kube-system\", \"rb-bob\", \"Role\", \"bob-oncall\").\n\
         +{bob}.\n"
    )
}

/// `\use <name>` points `?-` at the frozen facts: alice's grant is visible
/// there, but gone once `\use` returns to the live state.
#[test]
fn use_snapshot_queries_frozen_facts() {
    for backend in ["interpreter", "dd"] {
        let commands = format!(
            "{}\\use before\n\
             ?- direct_perm(\"alice@example.com\", K, Ns, G, R, Rn, V)\n\
             \\use\n\
             ?- direct_perm(\"alice@example.com\", K, Ns, G, R, Rn, V)\n\
             ::quit\n",
            before_bob_setup()
        );
        let (stdout, stderr) = run_session_with(&["--backend", backend], &commands);
        assert!(stdout.contains(r#"R = "pods/exec""#), "{backend}: {stdout}");
        assert!(stderr.contains("No results."), "{backend}: {stderr}");
    }
}

/// `\use <name> <command>` runs one command against the snapshot, then
/// returns to the state that was in use before — here, the live state.
#[test]
fn use_one_shot_returns_to_live() {
    for backend in ["interpreter", "dd"] {
        let commands = format!(
            "{}\\use before ?- direct_perm(\"bob@example.com\", K, Ns, G, R, Rn, V)\n\
             ?- direct_perm(\"bob@example.com\", K, Ns, G, R, Rn, V)\n\
             ::quit\n",
            before_bob_setup()
        );
        let (stdout, stderr) = run_session_with(&["--backend", backend], &commands);
        assert!(stderr.contains("No results."), "{backend}: {stderr}");
        assert!(stdout.contains(r#"R = "pods/exec""#), "{backend}: {stdout}");
    }
}

/// A one-shot command that errors out (unknown relation) must still
/// restore the previous state: a following `+` is not refused.
#[test]
fn use_one_shot_returns_after_failed_command() {
    for backend in ["interpreter", "dd"] {
        let commands = format!(
            "{}\\use before ?- nosuch(X)\n+bar(1).\n::quit\n",
            before_bob_setup()
        );
        let (_, stderr) = run_session_with(&["--backend", backend], &commands);
        assert!(stderr.contains("Asserted."), "{backend}: {stderr}");
    }
}

/// `\use` of an unknown name is refused and changes nothing: a following
/// `+` still runs against the live state.
#[test]
fn use_unknown_snapshot_is_refused() {
    for backend in ["interpreter", "dd"] {
        let (_, stderr) =
            run_session_with(&["--backend", backend], "\\use nosuch\n+bar(1).\n::quit\n");
        assert!(
            stderr.contains("No snapshot named 'nosuch'."),
            "{backend}: {stderr}"
        );
        assert!(stderr.contains("Asserted."), "{backend}: {stderr}");
    }
}

/// While a snapshot is in use, every state-changing command is refused
/// with the same message.
#[test]
fn use_refuses_state_changes() {
    for backend in ["interpreter", "dd"] {
        let commands = format!(
            "{}\\use before\n\
             +bar(1).\n\
             \\define baz(X) :- bar(X).\n\
             \\reset\n\
             \\snapshot again\n\
             \\match Pod kube-system foo=bar\n\
             \\match_all kube-system foo=bar\n\
             ::quit\n",
            before_bob_setup()
        );
        let (_, stderr) = run_session_with(&["--backend", backend], &commands);
        let refusals = stderr
            .matches("Snapshot 'before' is in use; \\use to return to the live state.")
            .count();
        assert_eq!(refusals, 6, "{backend}: {stderr}");
    }
}

/// A `?-` query with named variables under `\use` prints the same
/// `Found <n> result(s).` trailing line as a `(→ _N)` query on the live
/// state, minus the `_N` reference: no query-result relation is kept.
#[test]
fn use_query_keeps_no_results() {
    for backend in ["interpreter", "dd"] {
        let commands = format!(
            "{}\\use before\n\
             ?- direct_perm(\"alice@example.com\", K, Ns, G, R, Rn, V)\n\
             ?- direct_perm(\"alice@example.com\", K, Ns, G, R, Rn, V)\n\
             ::quit\n",
            before_bob_setup()
        );
        let (_, stderr) = run_session_with(&["--backend", backend], &commands);
        let found_lines: Vec<&str> = stderr
            .lines()
            .filter(|l| l.contains("Found") && l.contains("result(s)."))
            .collect();
        assert_eq!(found_lines.len(), 2, "{backend}: {stderr}");
        for line in found_lines {
            assert!(!line.contains("(→ _"), "{backend}: {line}");
        }
    }
}

/// A relation `\define`d after the snapshot was taken did not exist at
/// snapshot time, so querying it under `\use` is unknown, not empty.
#[test]
fn use_query_ignores_relations_added_after_snapshot() {
    for backend in ["interpreter", "dd"] {
        let commands = format!(
            "{}\\define spk(X) :- bar(X).\n\
             \\use before ?- spk(X)\n\
             ::quit\n",
            before_bob_setup()
        );
        let (_, stderr) = run_session_with(&["--backend", backend], &commands);
        assert!(
            stderr.contains("Unknown relation 'spk'"),
            "{backend}: {stderr}"
        );
    }
}

/// `\access-diff <name>` under `\use <other>` diffs the frozen `<name>`
/// against the frozen `<other>`, and names it in the header.
#[test]
fn access_diff_under_use_names_state() {
    for backend in ["interpreter", "dd"] {
        let commands = format!(
            "{}\\snapshot after\n\
             \\use after \\access-diff before\n\
             ::quit\n",
            before_bob_setup()
        );
        let (stdout, _) = run_session_with(&["--backend", backend], &commands);
        assert!(
            stdout.contains("=== Access diff: 'before' → 'after' ==="),
            "{backend}: {stdout}"
        );
        let verdicts: Vec<&str> = stdout
            .lines()
            .filter(|line| line.starts_with("    FAIL  ") || line.starts_with("    PASS  "))
            .collect();
        assert!(
            verdicts.iter().any(|l| l.contains("bob@example.com")),
            "{backend}: {stdout}"
        );
        assert!(
            verdicts.iter().any(|l| l.contains("alice@example.com")),
            "{backend}: {stdout}"
        );
    }
}

/// A snapshot keeps the proof of a fact as it stood when it was taken:
/// after the binding that gave alice `pods/exec` is retracted, `\why` under
/// `\use before` still explains her escalation, on both backends.
#[test]
fn why_on_snapshot_survives_retraction() {
    let why = r#"\why controls_identity("alice", "system:serviceaccount:kube-system:default")"#;
    let commands = format!(
        "\\source examples/exec-escalation/alice-exec.mg\n\
         {why}\n\
         \\snapshot before\n\
         -binding_subject(\"kube-system\", \"rb-alice-exec\", /user, \"alice\").\n\
         \\use before {why}\n\
         ::quit\n"
    );
    for args in [
        &["--backend", "interpreter"][..],
        &["--backend", "dd", "--provenance"][..],
    ] {
        let (stdout, stderr) = run_session_with(args, &commands);
        let (live, frozen) = stdout
            .split_once("Saved snapshot 'before'")
            .unwrap_or_else(|| panic!("{args:?}: no snapshot saved: {stdout}\n{stderr}"));
        assert!(
            live.contains("(EDB fact)"),
            "{args:?}: live: {live}\n{stderr}"
        );
        assert!(
            frozen.contains("(EDB fact)"),
            "{args:?}: frozen: {frozen}\n{stderr}"
        );
        assert!(
            !stdout.contains("no provenance captured"),
            "{args:?}: {stdout}"
        );
    }
}

// -----------------------------------------------------------------------
// `\load-k8s` replacing objects already loaded
// -----------------------------------------------------------------------

/// A ClusterRole `demo` granting `get` on `resources` (comma-separated),
/// bound to `demo@example.com`.
fn demo_role(resources: &str) -> String {
    let resources = resources
        .split(',')
        .map(|r| format!("{r:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "apiVersion: rbac.authorization.k8s.io/v1\n\
         kind: ClusterRole\n\
         metadata: {{name: demo}}\n\
         rules:\n\
         - {{apiGroups: [\"\"], resources: [{resources}], verbs: [\"get\"]}}\n\
         ---\n\
         apiVersion: rbac.authorization.k8s.io/v1\n\
         kind: ClusterRoleBinding\n\
         metadata: {{name: demo}}\n\
         roleRef: {{apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: demo}}\n\
         subjects:\n\
         - {{apiGroup: rbac.authorization.k8s.io, kind: User, name: demo@example.com}}\n"
    )
}

/// Write `demo_role(resources)` into its own fresh temp dir, so a
/// datasource can load it alone. Returns the file's path.
fn write_demo_role(resources: &str) -> PathBuf {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("pallograph-repl-upsert-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("demo.yaml");
    std::fs::write(&path, demo_role(resources)).expect("write manifest");
    path
}

/// Rows of `?- clusterrole_rule("demo", R)`, sorted (the backends list rows
/// in different orders).
fn demo_rules(stdout: &str) -> Vec<String> {
    let mut rows: Vec<String> = stdout
        .lines()
        .filter(|line| line.starts_with("  R = "))
        .map(str::to_string)
        .collect();
    rows.sort();
    rows
}

/// Loading a changed version of an object replaces it: rules see only the
/// new version, not both.
#[test]
fn load_k8s_replaces_object_across_backends() {
    let v1 = write_demo_role("secrets");
    let v2 = write_demo_role("configmaps");
    let commands = format!(
        "\\load-k8s {}\n\\load-k8s {}\n?- clusterrole_rule(\"demo\", R)\n::quit\n",
        v1.display(),
        v2.display()
    );
    for backend in ["interpreter", "dd"] {
        let (stdout, stderr) = run_session_with(&["--backend", backend], &commands);
        assert!(
            stderr.contains("Loaded 2 object(s) (2 replaced) and evaluated."),
            "{backend}: {stderr}"
        );
        assert_eq!(
            demo_rules(&stdout),
            [r#"  R = {/apiGroups: [""], /resources: ["configmaps"], /verbs: ["get"]}"#],
            "{backend}: {stdout}"
        );
    }
    for path in [v1, v2] {
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}

/// An object loaded at startup, then replaced by `\load-k8s` with a
/// narrower version: `\access-diff` reports the permission it lost and
/// none gained.
#[test]
fn load_k8s_over_startup_object_contracts_access() {
    let startup = write_demo_role("secrets,configmaps");
    let narrower = write_demo_role("configmaps");
    let commands = format!(
        "\\snapshot before\n\
         \\load-k8s {}\n\
         \\access-diff before\n\
         ?- clusterrole_rule(\"demo\", R)\n\
         ::quit\n",
        narrower.display()
    );
    for backend in ["interpreter", "dd"] {
        let (stdout, stderr) = run_session_loading(&[&startup], &["--backend", backend], &commands);
        assert!(
            stderr.contains("Loaded 2 object(s) (2 replaced) and evaluated."),
            "{backend}: {stderr}"
        );
        assert!(
            stdout.contains("PASS  2 permission(s) removed, none added"),
            "{backend}: {stdout}"
        );
        let lost = stdout
            .lines()
            .skip_while(|line| !line.starts_with("  CAN LOST"))
            .take_while(|line| !line.starts_with("  EFFECTIVE"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            lost.contains(
                r#"demo@example.com  ns=""  apigroup=""  resource="secrets"  verb="get""#
            ),
            "{backend}: {stdout}"
        );
        assert!(!stdout.contains("CAN GAINED"), "{backend}: {stdout}");
        assert_eq!(
            demo_rules(&stdout),
            [r#"  R = {/apiGroups: [""], /resources: ["configmaps"], /verbs: ["get"]}"#],
            "{backend}: {stdout}"
        );
    }
    for path in [startup, narrower] {
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
