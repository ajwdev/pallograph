// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Drives the built binary with `--script` over the small fixture to check
//! the exit status contract: 0 when clean, 1 on findings (`::access-diff`
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
         \\snapshot base\n\
         \\access-diff base\n",
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
        "::snapshot base\n::load-k8s {}\n::access-diff base\n",
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
        "::snapshot base\n::load-k8s {}\n::snapshot head\n::access-diff head base\n",
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
    assert!(stderr(&out).contains("Not a command"), "{}", stderr(&out));
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
        "::snapshot base\n::load-k8s {}\n::access-diff base\n",
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
        "::snapshot base\n::load-k8s {}\n::access-diff base\n::access-diff nope\n",
        ws.rendered()
    ));
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("No snapshot named 'nope'"));
}

#[test]
fn smt_usage_error_exits_2() {
    let ws = Workspace::new();
    let out = ws.run_script("::smt check_access\n");
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn script_from_stdin() {
    let ws = Workspace::new();
    let script = format!(
        "::snapshot base\n::load-k8s {}\n::access-diff base\n",
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
        let out = ws.run(args, "\\snapshot base\n");
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
