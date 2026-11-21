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

    /// Like [`run_script`], but with rc enabled: write `rc` to a file passed as
    /// `--rcfile` (so it runs before the script) instead of `--no-rc`.
    fn run_script_with_rcfile(&self, rc: &str, script: &str) -> Output {
        let rc_path = self.dir.join("pallographrc");
        std::fs::write(&rc_path, rc).expect("write rc");
        let script_path = self.dir.join("script.pg");
        std::fs::write(&script_path, script).expect("write script");
        let child = Command::new(env!("CARGO_BIN_EXE_pallograph"))
            .arg("-C")
            .arg(self.dir.join("pallograph.toml"))
            .args(["--profile", "dev"])
            .arg("--rcfile")
            .arg(&rc_path)
            .arg("--script")
            .arg(&script_path)
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn pallograph");
        child.wait_with_output().expect("wait")
    }

    /// Run with extra arguments, feeding `stdin`.
    fn run(&self, args: &[&std::ffi::OsStr], stdin: &str) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_pallograph"))
            .arg("-C")
            .arg(self.dir.join("pallograph.toml"))
            .args(["--profile", "dev", "--no-rc"])
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
        !stderr(&out).contains("Saved snapshot"),
        "ran past the failed line: {}",
        stderr(&out)
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
        !stderr(&out).contains("Saved snapshot"),
        "ran past the failed line: {}",
        stderr(&out)
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
    assert!(stderr(&out).contains("Saved snapshot 'base'"));
}

#[test]
fn apply_delta_add_then_access_diff_expands_exits_1() {
    // Empty base, head adds mallory's grant: k8s::apply-delta onto live, then the
    // access-diff against the pre-delta snapshot finds the new permission.
    let ws = Workspace::new();
    let out = ws.run_script(&format!(
        "::snapshot base\nk8s::apply-delta - {}\nrbac::diff base\n",
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
         k8s::apply-delta {rendered} -\n\
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

/// The live side of the not-live test: only mallory-debug Role from
/// [`EXEC_GRANT`], as if the RoleBinding had drifted away.
const LIVE_ROLE_ONLY: &str = r#"apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: mallory-debug
  namespace: kube-system
rules:
- apiGroups: [""]
  resources: ["pods/exec"]
  verbs: ["create"]
"#;

/// Run the delta script for the not-live tests, with `before` and `after`
/// around the delta: live holds only the Role; base renders the Role, its
/// RoleBinding and [`ADMIN_GRANT`]; head keeps the Role and ClusterRole,
/// rebinds the RoleBinding to eve and drops the ClusterRoleBinding.
fn not_live_delta(ws: &Workspace, before: &str, after: &str) -> Output {
    let live = ws.manifests("live", LIVE_ROLE_ONLY);
    let base = ws.manifests("base", &format!("{EXEC_GRANT}---\n{ADMIN_GRANT}"));
    let (cluster_role, _) = ADMIN_GRANT.split_once("---").unwrap();
    let head = ws.manifests(
        "head",
        &format!(
            "{}---\n{cluster_role}",
            EXEC_GRANT.replace("mallory@example.com", "eve@example.com")
        ),
    );
    ws.run_script(&format!(
        "k8s::load {live}\n{before}k8s::apply-delta {base} {head}\n{after}"
    ))
}

#[test]
fn apply_delta_ndjson_lists_base_objects_not_live() {
    let ws = Workspace::new();
    let out = not_live_delta(&ws, "format ndjson\n", "");
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let stdout = stdout(&out);
    let rows: Vec<serde_json::Value> = stdout
        .lines()
        .filter(|line| line.starts_with('{'))
        .map(|line| serde_json::from_str(line).expect("ndjson row"))
        .collect();
    let [row] = rows.as_slice() else {
        panic!("want one row: {stdout}");
    };
    let rbac = "rbac.authorization.k8s.io";
    assert_eq!(
        *row,
        serde_json::json!({
            "check": "apply-delta",
            "added": 0,
            "updated": 1,
            "removed": 1,
            "unchanged": 2,
            "removed_not_live": 1,
            // Sorted by kind, namespace, name. The live Role is left out.
            "not_live": [
                {"group": rbac, "kind": "ClusterRole", "namespace": "", "name": "pr-admin",
                 "change": "unchanged"},
                {"group": rbac, "kind": "ClusterRoleBinding", "namespace": "", "name": "pr-admin",
                 "change": "removed"},
                {"group": rbac, "kind": "RoleBinding", "namespace": "kube-system",
                 "name": "mallory-debug", "change": "updated"},
            ],
        })
    );
    // The sentence for people stays on stderr.
    assert!(
        stderr(&out).contains("Applied delta: +0 ~1 -1 (2 unchanged, 1 removed but not live)"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn apply_delta_text_mode_prints_no_row() {
    // `format ndjson` after the delta does not apply to it retroactively.
    let ws = Workspace::new();
    let out = not_live_delta(&ws, "", "format ndjson\n");
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert!(!stdout(&out).contains("apply-delta"), "{}", stdout(&out));
    assert!(
        stderr(&out).contains("Applied delta: +0 ~1 -1"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn apply_delta_wrong_arity_exits_2() {
    let ws = Workspace::new();
    let out = ws.run_script("::snapshot base\nk8s::apply-delta onlyone\n");
    assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("Usage: k8s::apply-delta"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn apply_delta_missing_side_exits_2() {
    let ws = Workspace::new();
    let missing = ws.dir.join("nonexistent");
    let out = ws.run_script(&format!(
        "::snapshot base\nk8s::apply-delta {} {}\n",
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
         k8s::apply-delta - {admin}\n\
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
         k8s::apply-delta - {admin}\n\
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
         k8s::apply-delta - {admin}\n\
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
         k8s::apply-delta - {admin}\n\
         ::diff-relation base unexpected_cluster_admin\n"
    ));
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let stdout = stdout(&out);
    assert!(stdout.contains("(no changes)"), "{stdout}");
    assert!(!stdout.contains("eve@example.com"), "{stdout}");
}

#[test]
fn alias_expands_on_bare_command() {
    // `alias` defines a shorthand; typing it runs the expansion (here the
    // escalation-aware cluster-admin check), not an "unknown command".
    let ws = Workspace::new();
    let out = ws.run_script("alias ca rbac::cluster-admin\nca\n");
    let combined = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        !combined.contains("Unknown command"),
        "alias did not expand: {combined}"
    );
    assert!(
        combined.contains("can reach") || combined.contains("effective_can"),
        "{combined}"
    );
}

#[test]
fn unalias_removes_the_alias() {
    let ws = Workspace::new();
    let out = ws.run_script("alias ca rbac::cluster-admin\nunalias ca\nca\n");
    assert!(
        stderr(&out).contains("Unknown command: ca"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn qualified_form_bypasses_an_alias() {
    // Shadow a builtin with an alias, then confirm the `::`-qualified form still
    // runs the real command rather than the alias.
    let ws = Workspace::new();
    let out = ws.run_script("alias show rbac::cluster-admin\n::show\n");
    let combined = format!("{}{}", stdout(&out), stderr(&out));
    // `::show` lists relations (the fixture has `pod`), not a reachability check.
    assert!(
        !combined.contains("can reach"),
        "alias was not bypassed: {combined}"
    );
}

#[test]
fn rcfile_runs_before_the_script() {
    // An alias defined in the rc file is available to the script that follows.
    let ws = Workspace::new();
    let out = ws.run_script_with_rcfile("alias ca rbac::cluster-admin\n", "ca\n");
    let combined = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        !combined.contains("Unknown command"),
        "rc alias not applied: {combined}"
    );
    assert!(
        combined.contains("can reach") || combined.contains("effective_can"),
        "{combined}"
    );
}

#[test]
fn bare_command_missing_args_shows_usage() {
    // A known command invoked with no arguments is not "unknown": show its usage.
    let ws = Workspace::new();
    let out = ws.run_script("diff\n");
    let combined = format!("{}{}", stdout(&out), stderr(&out));
    assert!(combined.contains("Usage: diff"), "{combined}");
    assert!(!combined.contains("Unknown command: diff"), "{combined}");
}

#[test]
fn bare_k8s_subcommand_missing_args_shows_usage() {
    let ws = Workspace::new();
    let out = ws.run_script("k8s::match\n");
    let combined = format!("{}{}", stdout(&out), stderr(&out));
    assert!(combined.contains("Usage: k8s::match"), "{combined}");
}

#[test]
fn rcfile_error_warns_but_session_continues() {
    // A broken rc line must warn and not abort: the clean script that follows
    // still runs and the session exits 0.
    let ws = Workspace::new();
    let out = ws.run_script_with_rcfile("bogus-rc-command\n", "snapshot base\nrbac::diff base\n");
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("Unknown command: bogus-rc-command"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn ndjson_stdout_is_only_json() {
    // Results go to stdout and status lines (snapshot, load, rollback) to
    // stderr, so `--script ... | jq` reads rows without `2>&1` or filtering.
    let ws = Workspace::new();
    let out = ws.run_script(&format!(
        "format ndjson\n\
         snapshot base\n\
         k8s::load {}\n\
         ?- pod\n\
         rbac::cluster-admin\n\
         rollback base\n",
        ws.rendered()
    ));
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
    let stdout = stdout(&out);
    let rows: Vec<serde_json::Value> = stdout
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("not JSON ({e}): {l}")))
        .collect();
    assert!(
        rows.iter().any(|r| r["check"] == "cluster-admin"),
        "no check row: {stdout}"
    );
    let stderr = stderr(&out);
    assert!(stderr.contains("Saved snapshot 'base'"), "{stderr}");
    assert!(
        stderr.contains("Rolled back to snapshot 'base'."),
        "{stderr}"
    );
}

#[test]
fn text_answers_stay_on_stdout() {
    // A command's answer is output whatever the format; only status moves.
    let ws = Workspace::new();
    let out = ws.run_script("snapshot base\nshow k8s\n");
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert!(stdout(&out).contains("k8s/6"), "{}", stdout(&out));
    assert!(!stdout(&out).contains("Saved snapshot"), "{}", stdout(&out));
}

/// mid's `pods/exec` in kube-system, which reaches cluster-admin through the
/// control-plane pods' ServiceAccount, and alice's right to impersonate mid,
/// which reaches the same only through mid. Dropping mid's grant leaves alice
/// with nothing changed but an escalation loss.
const MID_EXEC_GRANT: &str = r#"apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: mid-debug
  namespace: kube-system
rules:
- apiGroups: [""]
  resources: ["pods/exec"]
  verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: mid-debug
  namespace: kube-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: mid-debug
subjects:
- kind: User
  apiGroup: rbac.authorization.k8s.io
  name: mid@example.com
"#;

const ALICE_IMPERSONATES_MID: &str = r#"apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: alice-impersonate
rules:
- apiGroups: [""]
  resources: ["users"]
  verbs: ["impersonate"]
  resourceNames: ["mid@example.com"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: alice-impersonate
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: alice-impersonate
subjects:
- kind: User
  apiGroup: rbac.authorization.k8s.io
  name: alice@example.com
"#;

/// A script whose `rbac::diff base head` (with `diff_args` appended) sees
/// mallory gain `pods/exec` directly and cluster-admin by escalation, mid
/// lose both, and alice lose cluster-admin by escalation only.
fn mixed_diff_script(ws: &Workspace, preamble: &str, diff_args: &str) -> String {
    let base = ws.manifests(
        "base",
        &format!("{MID_EXEC_GRANT}---\n{ALICE_IMPERSONATES_MID}"),
    );
    let head = ws.manifests(
        "head",
        &format!("{EXEC_GRANT}---\n{ALICE_IMPERSONATES_MID}"),
    );
    format!(
        "{preamble}k8s::apply-delta - {base}\n\
         ::snapshot base\n\
         k8s::apply-delta {base} {head}\n\
         ::snapshot head\n\
         rbac::diff base head{diff_args}\n"
    )
}

/// The `rbac::diff` rows on stdout, skipping status lines like `Saved
/// snapshot` and rows from other commands (`k8s::apply-delta`).
fn diff_json_rows(out: &Output) -> Vec<serde_json::Value> {
    stdout(out)
        .lines()
        .filter(|l| l.starts_with('{'))
        .map(|l| -> serde_json::Value {
            serde_json::from_str(l).unwrap_or_else(|e| panic!("not JSON ({e}): {l}"))
        })
        .filter(|row| row["check"] == "diff")
        .collect()
}

/// The change rows as (principal, section, change, namespace, resource),
/// sorted.
fn diff_change_keys(rows: &[serde_json::Value]) -> Vec<(String, String, String, String, String)> {
    let mut keys: Vec<_> = rows
        .iter()
        .filter(|r| r.get("change").is_some())
        .map(|r| {
            let field = |k: &str| r[k].as_str().unwrap_or_default().to_string();
            (
                field("principal"),
                field("section"),
                field("change"),
                field("namespace"),
                field("resource"),
            )
        })
        .collect();
    keys.sort();
    keys
}

#[test]
fn access_diff_ndjson_emits_verdict_and_change_rows() {
    let ws = Workspace::new();
    let out = ws.run_script(&mixed_diff_script(&ws, "format ndjson\n", ""));
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
    let rows = diff_json_rows(&out);
    assert!(rows.iter().all(|r| r["check"] == "diff"), "{rows:?}");
    assert!(
        rows.iter()
            .all(|r| r["before"] == "base" && r["after"] == "head"),
        "{rows:?}"
    );

    let verdict = &rows[0];
    assert_eq!(verdict["result"], "fail", "{verdict}");
    assert_eq!(verdict["gained"], 2, "{verdict}");
    assert_eq!(verdict["lost"], 3, "{verdict}");
    let principals = verdict["principals"].as_array().expect("principals");
    let mallory = principals
        .iter()
        .find(|p| p["principal"] == "mallory@example.com")
        .expect("mallory verdict");
    assert_eq!(mallory["principal_kind"], "user");
    assert_eq!(mallory["result"], "fail");
    assert_eq!(
        (mallory["gained"].as_u64(), mallory["lost"].as_u64()),
        (Some(2), Some(0))
    );
    let alice = principals
        .iter()
        .find(|p| p["principal"] == "alice@example.com")
        .expect("alice verdict");
    assert_eq!(alice["result"], "pass");
    assert_eq!(
        (alice["gained"].as_u64(), alice["lost"].as_u64()),
        (Some(0), Some(1))
    );
    assert_eq!(
        rows.iter().filter(|r| r.get("result").is_some()).count(),
        1,
        "one verdict row: {rows:?}"
    );

    let key = |p: &str, s: &str, c: &str, ns: &str, r: &str| {
        (p.into(), s.into(), c.into(), ns.into(), r.into())
    };
    assert_eq!(
        diff_change_keys(&rows),
        vec![
            key("alice@example.com", "escalation", "lost", "", "*"),
            key(
                "mallory@example.com",
                "direct",
                "gained",
                "kube-system",
                "pods/exec"
            ),
            key("mallory@example.com", "escalation", "gained", "", "*"),
            key(
                "mid@example.com",
                "direct",
                "lost",
                "kube-system",
                "pods/exec"
            ),
            key("mid@example.com", "escalation", "lost", "", "*"),
        ]
    );

    // Escalation rows name the identities they pass through; direct rows
    // have none.
    let row = |p: &str, s: &str| {
        rows.iter()
            .find(|r| r["principal"] == p && r["section"] == s)
            .unwrap_or_else(|| panic!("no {p} {s} row: {rows:?}"))
    };
    let escalation = row("mallory@example.com", "escalation");
    assert_eq!(escalation["principal_kind"], "user");
    assert_eq!(
        (&escalation["apigroup"], &escalation["verb"]),
        (&serde_json::json!("*"), &serde_json::json!("*"))
    );
    let via = escalation["via"].as_array().expect("via");
    assert!(
        via.iter().any(
            |v| v["identity"] == "system:serviceaccount:kube-system:default"
                && v["identity_kind"] == "serviceaccount"
        ),
        "{escalation}"
    );
    let direct = row("mallory@example.com", "direct");
    assert_eq!(direct["verb"], "create");
    assert_eq!(direct["via"], serde_json::json!([]));
}

#[test]
fn access_diff_ndjson_no_changes_passes() {
    let ws = Workspace::new();
    let out = ws.run_script("format ndjson\nsnapshot base\nrbac::diff base\n");
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert!(!stdout(&out).contains("PASS"), "{}", stdout(&out));
    let rows = diff_json_rows(&out);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(
        rows[0],
        serde_json::json!({
            "check": "diff",
            "before": "base",
            "after": "",
            "result": "pass",
            "gained": 0,
            "lost": 0,
            "principals": [],
        })
    );
}

#[test]
fn access_diff_hide_escalation_lost_trims_text_only() {
    let ws = Workspace::new();
    let out = ws.run_script(&mixed_diff_script(&ws, "", " --hide-escalation-lost"));
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
    let stdout = stdout(&out);
    // The verdicts still count every change.
    assert!(
        stdout.contains("FAIL  2 new permission(s) granted, 3 removed"),
        "{stdout}"
    );
    assert!(
        stdout.contains("PASS  alice@example.com (user)"),
        "{stdout}"
    );
    assert!(stdout.contains("PASS  mid@example.com (user)"), "{stdout}");
    // Gains via escalation and direct losses stay.
    assert!(
        stdout.contains("+ (namespace \"\", apiGroup \"*\", resource \"*\", verb \"*\")   via "),
        "{stdout}"
    );
    assert!(
        stdout.contains("- (namespace \"kube-system\", apiGroup \"\", resource \"pods/exec\""),
        "{stdout}"
    );
    // Escalation losses go, and with them alice's whole block and mid's
    // escalation header.
    assert!(
        !stdout.contains("- (namespace \"\", apiGroup \"*\""),
        "{stdout}"
    );
    assert!(!stdout.contains("\n  alice@example.com"), "{stdout}");
    assert!(stdout.contains("\n  mid@example.com (user)\n"), "{stdout}");
    assert_eq!(stdout.matches("» via escalation").count(), 1, "{stdout}");

    // Without the flag, the same diff shows them.
    let full = ws.run_script(&mixed_diff_script(&ws, "", ""));
    let full = String::from_utf8_lossy(&full.stdout);
    assert!(full.contains("\n  alice@example.com (user)\n"), "{full}");
    assert_eq!(full.matches("» via escalation").count(), 3, "{full}");

    // ndjson ignores the flag and keeps every row.
    let flagged = ws.run_script(&mixed_diff_script(
        &ws,
        "format ndjson\n",
        " --hide-escalation-lost",
    ));
    let plain = ws.run_script(&mixed_diff_script(&ws, "format ndjson\n", ""));
    assert_eq!(
        diff_change_keys(&diff_json_rows(&flagged)),
        diff_change_keys(&diff_json_rows(&plain))
    );
}
