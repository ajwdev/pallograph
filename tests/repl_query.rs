// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Drives the built binary over the small fixture to check the REPL's
//! `?-` query UX: tuple listing, output formats, unknown-relation hints and
//! the hint printed for input that is not a command.

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// Run a REPL session and return (stdout, stderr).
fn run_session(commands: &str) -> (String, String) {
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
            r#"Principal = "admin@example.com", Namespace = "", ApiGroup = "*", Resource = "*", Verb = "*""#
        ),
        "stdout: {stdout}"
    );
}

#[test]
fn compact_format_prints_tuples() {
    let (stdout, _) = run_session(&format!("\\format compact\n{ADMIN}\n::quit\n"));
    assert!(
        stdout.contains(r#"direct_perm("admin@example.com", "", "*", "*", "*")"#),
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
    let (stdout, stderr) =
        run_session("?- direct_perm(\"a\", \"b\", \"c\", \"d\", \"e\", \"f\")\n::quit\n");
    assert!(
        stderr.contains("direct_perm has 5 columns, got 6 arguments."),
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
