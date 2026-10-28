// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Drives the built binary with `--script` over the small fixture to check
//! the exit status contract: 0 when clean, 1 on findings (`rbac::diff`
//! finding new permissions), 2 when a line is not a command or its command
//! fails, with the script stopping at that line.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// A Role granting `pods/exec` in kube-system and a RoleBinding giving it to
/// mallory, as a rendered chart might add.
const EXEC_GRANT: &str = r#"apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: mallory-debug
  namespace: kube-system
rules:
- apiGroups: [""]
  resources: ["pods/exec"]
  verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: mallory-debug
  namespace: kube-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: mallory-debug
subjects:
- kind: User
  apiGroup: rbac.authorization.k8s.io
  name: mallory@example.com
"#;

/// A ClusterRole granting everything and a ClusterRoleBinding handing it to
/// a user, i.e. a fresh cluster-admin, as a PR might mint.
const ADMIN_GRANT: &str = r#"apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pr-admin
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: pr-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: pr-admin
subjects:
- kind: User
  apiGroup: rbac.authorization.k8s.io
  name: eve@example.com
"#;

/// A scratch directory with a config for the small fixture and a
/// `rendered/` directory holding [`EXEC_GRANT`]. Removed on drop.
struct Workspace {
    dir: PathBuf,
}

impl Workspace {
    fn new() -> Self {
        // Unique per call: tests run in parallel threads of one process.
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("pallograph-script-mode-{}-{n}", std::process::id()));
        std::fs::create_dir_all(dir.join("rendered")).expect("create temp dir");
        let testdata = format!("{}/fixtures/testdata/small", env!("CARGO_MANIFEST_DIR"));
        std::fs::write(
            dir.join("pallograph.toml"),
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
        std::fs::write(dir.join("rendered/rbac.yaml"), EXEC_GRANT).expect("write manifests");
        Workspace { dir }
    }

    fn rendered(&self) -> String {
        self.dir.join("rendered").to_string_lossy().into_owned()
    }

    /// Write `yaml` into a fresh subdirectory and return its path, for a
    /// second rendered side.
    fn manifests(&self, subdir: &str, yaml: &str) -> String {
        let dir = self.dir.join(subdir);
        std::fs::create_dir_all(&dir).expect("create manifests dir");
        std::fs::write(dir.join("manifests.yaml"), yaml).expect("write manifests");
        dir.to_string_lossy().into_owned()
    }

    /// Write `script` to a file and run it with `--script <file>`.
    fn run_script(&self, script: &str) -> Output {
        let path = self.dir.join("script.pg");
        std::fs::write(&path, script).expect("write script");
        self.run(&["--script".as_ref(), path.as_os_str()], "")
    }

    /// Run with extra arguments, feeding `stdin`.
    fn run(&self, args: &[&std::ffi::OsStr], stdin: &str) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_pallograph"))
            .arg("-C")
            .arg(self.dir.join("pallograph.toml"))
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
            .write_all(stdin.as_bytes())
            .expect("write stdin");
        child.wait_with_output().expect("wait")
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn clean_script_exits_0() {
    let ws = Workspace::new();
    let out = ws.run_script(
        "# no changes since the snapshot\n\
         \n\
         snapshot base\n\
         rbac::diff base\n",
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains("PASS  no permission changes"),
        "{}",
        stdout(&out)
    );
}

#[test]
fn access_diff_expansion_exits_1() {
    let ws = Workspace::new();
    let out = ws.run_script(&format!(
        "::snapshot base\nk8s::load {}\nrbac::diff base\n",
        ws.rendered()
    ));
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
    let stdout = stdout(&out);
    assert!(stdout.contains("FAIL  "), "{stdout}");
    assert!(stdout.contains("mallory@example.com"), "{stdout}");
}

#[test]
fn access_diff_contraction_only_exits_0() {
    // Load the grant, then diff in reverse: from `head` (with mallory's
    // grant) back to `base` (without), so permissions are only removed.
    let ws = Workspace::new();
    let out = ws.run_script(&format!(
        "::snapshot base\nk8s::load {}\n::snapshot head\nrbac::diff head base\n",
        ws.rendered()
    ));
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert!(stdout(&out).contains("none added"), "{}", stdout(&out));
}

#[test]
fn unknown_line_exits_2_and_stops() {
    let ws = Workspace::new();
    let out = ws.run_script("bogus line\n::snapshot base\n");
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("Unknown command"), "{}", stderr(&out));
    assert!(
        !stdout(&out).contains("Saved snapshot"),
        "ran past the failed line: {}",
        stdout(&out)
    );
}

#[test]
fn rollback_to_unknown_snapshot_exits_2() {
    let ws = Workspace::new();
    let out = ws.run_script("rollback nosuch\nsnapshot base\n");
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("No snapshot named 'nosuch'."),
        "{}",
        stderr(&out)
    );
    assert!(
        !stdout(&out).contains("Saved snapshot"),
        "ran past the failed line: {}",
        stdout(&out)
    );
}

#[test]
fn load_of_nonexistent_path_exits_2() {
    let ws = Workspace::new();
    let missing = ws.dir.join("nonexistent.yaml");
    let out = ws.run_script(&format!(
        "::snapshot base\nk8s::load {}\nrbac::diff base\n",
        missing.display()
    ));
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("Load error"), "{}", stderr(&out));
    assert!(
        !stdout(&out).contains("PASS"),
        "ran past the failed line: {}",
        stdout(&out)
    );
}

#[test]
fn error_after_findings_exits_2() {
    // A finding followed by a broken line is still a broken run.
    let ws = Workspace::new();
    let out = ws.run_script(&format!(
        "::snapshot base\nk8s::load {}\nrbac::diff base\nrbac::diff nope\n",
        ws.rendered()
    ));
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("No snapshot named 'nope'"));
}

#[test]
fn smt_usage_error_exits_2() {
    let ws = Workspace::new();
    let out = ws.run_script("rbac::access\n");
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn script_from_stdin() {
    let ws = Workspace::new();
    let script = format!(
        "::snapshot base\nk8s::load {}\nrbac::diff base\n",
        ws.rendered()
    );
    let out = ws.run(&["--script".as_ref(), "-".as_ref()], &script);
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
    let out = ws.run(&["--script".as_ref(), "-".as_ref()], "bogus line\n");
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn missing_script_file_exits_2() {
    let ws = Workspace::new();
    let missing = ws.dir.join("missing.pg");
    let out = ws.run(&["--script".as_ref(), missing.as_os_str()], "");
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("opening script"), "{}", stderr(&out));
}

#[test]
fn startup_path_matching_no_files_exits_2() {
    // A profile whose manifest path matches nothing fails before any
    // command runs, in the REPL as well as under --script.
    let ws = Workspace::new();
    let missing = ws.dir.join("nonexistent");
    let config = std::fs::read_to_string(ws.dir.join("pallograph.toml")).expect("read config");
    let testdata = format!("{}/fixtures/testdata/small", env!("CARGO_MANIFEST_DIR"));
    let config = config.replace(
        &format!("{testdata:?}"),
        &format!("{:?}", missing.display().to_string()),
    );
    std::fs::write(ws.dir.join("pallograph.toml"), config).expect("write config");
    for args in [&["--script".as_ref(), "-".as_ref()][..], &[]] {
        let out = ws.run(args, "snapshot base\n");
        assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr(&out));
        assert!(
            stderr(&out).contains("no .json, .yaml or .yml files match"),
            "{}",
            stderr(&out)
        );
    }
}

#[test]
fn piped_repl_stays_forgiving() {
    // Without --script, a bad line is reported and the session carries on.
    let ws = Workspace::new();
    let out = ws.run(&[], "bogus line\n::snapshot base\n");
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout(&out).contains("Saved snapshot 'base'"));
}

#[test]
fn apply_delta_add_then_access_diff_expands_exits_1() {
    // Empty base, head adds mallory's grant: apply-delta onto live, then the
    // access-diff against the pre-delta snapshot finds the new permission.
    let ws = Workspace::new();
    let out = ws.run_script(&format!(
        "::snapshot base\n::apply-delta - {}\nrbac::diff base\n",
        ws.rendered()
    ));
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
    let stdout = stdout(&out);
    assert!(stdout.contains("FAIL  "), "{stdout}");
    assert!(stdout.contains("mallory@example.com"), "{stdout}");
    assert!(
        stderr(&out).contains("Applied delta: +2 ~0 -0"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn apply_delta_retracts_base_only_object_exits_0() {
    // The motivating case: the grant is live (loaded as if from the cluster)
    // and in the base render, but head drops it. The delta retracts it, so
    // the access-diff against the pre-delta snapshot only loses permissions.
    let ws = Workspace::new();
    let out = ws.run_script(&format!(
        "k8s::load {rendered}\n\
         ::snapshot base\n\
         ::apply-delta {rendered} -\n\
         rbac::diff base\n",
        rendered = ws.rendered()
    ));
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert!(stdout(&out).contains("none added"), "{}", stdout(&out));
    assert!(
        stderr(&out).contains("Applied delta: +0 ~0 -2"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn apply_delta_wrong_arity_exits_2() {
    let ws = Workspace::new();
    let out = ws.run_script("::snapshot base\n::apply-delta onlyone\n");
    assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("Usage: apply-delta"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn apply_delta_missing_side_exits_2() {
    let ws = Workspace::new();
    let missing = ws.dir.join("nonexistent");
    let out = ws.run_script(&format!(
        "::snapshot base\n::apply-delta {} {}\n",
        ws.rendered(),
        missing.display()
    ));
    assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("Delta error"), "{}", stderr(&out));
}

#[test]
fn diff_relation_shows_added_row() {
    // diff-relation is a diagnostic diff, not a gate: it shows the row the
    // delta added to user_is_cluster_admin and exits 0 either way.
    let ws = Workspace::new();
    let admin = ws.manifests("admin", ADMIN_GRANT);
    let out = ws.run_script(&format!(
        "::snapshot base\n\
         ::apply-delta - {admin}\n\
         ::diff-relation base user_is_cluster_admin\n"
    ));
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let stdout = stdout(&out);
    assert!(stdout.contains("user_is_cluster_admin  (+1"), "{stdout}");
    assert!(stdout.contains("+ String(\"eve@example.com\")"), "{stdout}");
}

#[test]
fn diff_relation_no_change_reports_no_changes() {
    // The delta leaves sa_is_cluster_admin untouched, so the relation diff is
    // empty and prints (no changes). Still exit 0.
    let ws = Workspace::new();
    let admin = ws.manifests("admin", ADMIN_GRANT);
    let out = ws.run_script(&format!(
        "::snapshot base\n\
         ::apply-delta - {admin}\n\
         ::diff-relation base sa_is_cluster_admin\n"
    ));
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert!(stdout(&out).contains("(no changes)"), "{}", stdout(&out));
}

#[test]
fn diff_relation_unknown_relation_exits_2() {
    // An unknown relation is a usage error (exit 2), not a silent empty diff.
    let ws = Workspace::new();
    let out = ws.run_script("::snapshot base\n::diff-relation base user_is_clustr_admin\n");
    assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("Unknown relation 'user_is_clustr_admin'"),
        "{}",
        stderr(&out)
    );
}

// The cluster-admin approval view is not shipped; it is the
// examples/cluster-admin-approved/ recipe, sourced here (relative to the
// crate root, which is the script's working directory).
const CA_VIEW: &str = "examples/cluster-admin-approved/cluster-admin-approved.mg";

#[test]
fn diff_relation_shows_unexpected_cluster_admin() {
    // With an empty approval closure, the delta's new cluster-admin shows as
    // an added row in the example's unexpected_cluster_admin view.
    let ws = Workspace::new();
    let admin = ws.manifests("admin", ADMIN_GRANT);
    let out = ws.run_script(&format!(
        "::source {CA_VIEW}\n\
         ::snapshot base\n\
         ::apply-delta - {admin}\n\
         ::diff-relation base unexpected_cluster_admin\n"
    ));
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains("+ String(\"eve@example.com\")"),
        "{}",
        stdout(&out)
    );
}

#[test]
fn diff_relation_approved_admin_absent() {
    // Approving the principal in the closure keeps it out of
    // unexpected_cluster_admin, so the relation diff shows no change.
    let ws = Workspace::new();
    let admin = ws.manifests("admin", ADMIN_GRANT);
    let out = ws.run_script(&format!(
        "+cluster_admin_allowed(\"eve@example.com\")\n\
         ::source {CA_VIEW}\n\
         ::snapshot base\n\
         ::apply-delta - {admin}\n\
         ::diff-relation base unexpected_cluster_admin\n"
    ));
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let stdout = stdout(&out);
    assert!(stdout.contains("(no changes)"), "{stdout}");
    assert!(!stdout.contains("eve@example.com"), "{stdout}");
}
