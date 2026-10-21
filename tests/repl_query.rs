// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Drives the built binary over the small fixture to check the REPL's
//! `?-` query UX: tuple listing, output formats, unknown-relation hints and
//! the hint printed for input that is not a command, and `\source` of the
//! example scenarios on both backends.

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// Run a REPL session and return (stdout, stderr).
fn run_session(commands: &str) -> (String, String) {
    run_session_with(&[], commands)
}

/// Like [`run_session`], with extra command-line arguments.
fn run_session_with(args: &[&str], commands: &str) -> (String, String) {
    // Unique per call: tests run in parallel threads of one process.
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("pallograph-repl-query-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let config = dir.join("pallograph.toml");
    let testdata = format!("{}/fixtures/testdata/small", env!("CARGO_MANIFEST_DIR"));
    std::fs::write(
        &config,
        format!(
            "default_profile = \"dev\"\n\
             [datasources.local]\n\
             source = \"file\"\n\
             paths = [{testdata:?}]\n\
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
