// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Drives the built binary over the small fixture to check the ndjson
//! output of `::smt` checks and the exit status contract: nonzero when any
//! check fails, zero when all pass.

use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn run_session(commands: &str, format: &str) -> Output {
    // Unique per call: tests run in parallel threads of one process.
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("pallograph-smt-ndjson-{}-{n}", std::process::id()));
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
        .args(["--profile", "dev", "--format", format])
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
    out
}

fn json_lines(out: &Output) -> Vec<serde_json::Value> {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("not JSON ({e}): {l}")))
        .collect()
}

#[test]
fn failing_check_emits_ndjson_and_exits_1() {
    let out = run_session("::smt cluster-admin\n::quit\n", "ndjson");
    let lines = json_lines(&out);
    assert!(!lines.is_empty(), "no stdout lines");
    for l in &lines {
        assert!(l.get("check").is_some(), "missing check: {l}");
        assert_eq!(l["result"], "fail", "unexpected result: {l}");
        assert!(l.get("principal").is_some(), "missing principal: {l}");
        assert!(l["paths"].is_array(), "missing paths: {l}");
    }
    assert!(
        lines
            .iter()
            .any(|l| l["principal"] == "admin@example.com" && l["kind"] == "direct"),
        "admin@example.com not reported as a direct cluster-admin: {lines:?}"
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn passing_check_emits_pass_line_and_exits_0() {
    // Cluster-wide grants reach every namespace, so isolation only holds once
    // the principals holding them are listed as allowed.
    let out = run_session(
        "::smt check_isolation no-such-namespace admin@example.com \
         system:serviceaccount:kube-system:kindnet \
         system:serviceaccount:local-path-storage:local-path-provisioner-service-account \
         system:serviceaccount:kube-system:default \
         system:serviceaccount:kube-system:kube-proxy\n::quit\n",
        "ndjson",
    );
    let lines = json_lines(&out);
    assert_eq!(
        lines.len(),
        1,
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert_eq!(lines[0]["result"], "pass");
    assert_eq!(lines[0]["check"], "check_isolation");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn plain_output_annotates_user_principals_and_exits_1() {
    let out = run_session("::smt cluster-admin\n::quit\n", "default");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("admin@example.com (user)"),
        "no (user) annotation:\n{text}"
    );
    assert_eq!(out.status.code(), Some(1));
}
