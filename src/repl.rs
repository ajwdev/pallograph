// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;
use std::io::IsTerminal;

use anyhow::{Context as _, Result};
use mangle_common::Value;
use rustyline::completion::{Completer, FilenameCompleter, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Helper};

use crate::api::{
    At, Core, Derivation, Fact, KubeObject, LocalCore, ProvenanceTree, ReachesQuery, RelationInfo,
    Rows,
};
use crate::edb::{FactSource, K8sManifestsSource, ShellSource};
use crate::engine::{ApplySummary, EvalStore, RelationDoc};
use crate::load;
use crate::rbac;
use crate::rbac::diff::AccessDiff;
use crate::smt;
use crate::snapshot::FrozenState;
use crate::source::{parse_ground_tuple, split_two_atoms};
use crate::watch::WatchStatus;

struct ReplHelper {
    path_completer: FilenameCompleter,
    /// Alias names, refreshed before each prompt (see `Input::set_completions`).
    aliases: Vec<String>,
    /// Relation names in the active state, for `?-`/`show`/`why`/`+` completion.
    relations: Vec<String>,
}

/// Completable command paths: root verbs, subsystem namespaces, and their
/// subcommands. Kept in step with the dispatcher by hand; see `print_help`.
fn command_completions() -> &'static [&'static str] {
    &[
        // Root verbs.
        "show",
        "why",
        "query",
        "explain",
        "define",
        "source",
        "load",
        "snapshot",
        "rollback",
        "diff",
        "diff-relation",
        "use",
        "format",
        "pretty",
        "smtlib",
        "alias",
        "unalias",
        "help",
        "quit",
        // Subsystem namespaces (a bare `rbac` completes to `rbac::`).
        "rbac::",
        "sched::",
        "k8s::",
        // Subsystem subcommands.
        "rbac::access",
        "rbac::reaches",
        "rbac::cluster-admin",
        "rbac::isolation",
        "rbac::diff",
        "sched::node-selector",
        "sched::anti-affinity",
        "sched::karpenter",
        "k8s::load",
        "k8s::match",
        "k8s::match-all",
        "k8s::apply-delta",
    ]
}

/// Usage text for commands that take arguments, shown when one is invoked with
/// no arguments (so a bare `diff` prints how to use it instead of "unknown
/// command"). Subsystem rbac::/sched:: commands print their own usage via
/// `rbac_command` / `sched_command`, so they are not listed here.
fn command_usage(head: &str) -> Option<&'static str> {
    Some(match head {
        "why" => "why <pred>(<args>...)",
        "query" => "query <body>   (or ?- <body>)",
        "explain" => "explain <body>   (plan a query without running it)",
        "define" => "define <rule>.",
        "source" => "source <src>",
        "load" => "load <relation> <source>   (source is a file path or ! <cmd>)",
        "snapshot" => "snapshot <name>",
        "diff" => "diff <name>   or   diff <name1> <name2>",
        "diff-relation" => "diff-relation <name> [name2] <relation>",
        "smtlib" => "smtlib <relation> [relation ...]",
        "k8s::load" => "k8s::load <src>   (a dir, .json file, or ! <kubectl args>)",
        "k8s::match" => "k8s::match <Kind> <namespace> <selector>",
        "k8s::match-all" => "k8s::match-all <namespace> <selector>",
        "k8s::apply-delta" => {
            "k8s::apply-delta <base> <head>   (a dir, .json file, or - for an empty side)"
        }
        _ => return None,
    })
}

fn completion_pair(s: String) -> Pair {
    Pair {
        display: s.clone(),
        replacement: s,
    }
}

/// What to complete for the text before the cursor. The file cases need
/// rustyline's `Context`, so they are returned as `Files` for [`Completer`] to
/// run; the rest are resolved here (and unit-tested) as concrete candidates.
#[derive(Debug, PartialEq)]
enum CompletionPlan {
    /// Replace from this byte offset with these candidate strings.
    Words(usize, Vec<String>),
    /// Defer to the file-path completer.
    Files,
    /// Nothing to complete.
    Nothing,
}

/// Plan completion for `before` (the text left of the cursor), given the current
/// `aliases` and `relations`. Pure, so it can be tested without a terminal.
fn plan_completion(before: &str, aliases: &[String], relations: &[String]) -> CompletionPlan {
    let word_start = before
        .rfind(char::is_whitespace)
        .map(|i| i + 1)
        .unwrap_or(0);
    let word = &before[word_start..];
    let completing_command = before[..word_start].trim().is_empty();

    if completing_command {
        // Fact mutators take a relation name as their first token.
        if let Some(first) = word.chars().next()
            && matches!(first, '+' | '-' | '~')
        {
            let bare = &word[1..];
            let cands = relations
                .iter()
                .filter(|r| r.starts_with(bare))
                .map(|r| format!("{first}{r}"))
                .collect();
            return CompletionPlan::Words(word_start, cands);
        }
        // Command paths and alias names. A leading `::` (the fully-qualified
        // form) is matched against the same set and preserved in the result.
        let (prefix, bare) = match word.strip_prefix("::") {
            Some(rest) => ("::", rest),
            None => ("", word),
        };
        // Skip a candidate identical to what is already typed (e.g. `sched::`
        // completing to itself alongside its subcommands).
        let mut cands: Vec<String> = command_completions()
            .iter()
            .filter(|c| c.starts_with(bare) && **c != bare)
            .map(|c| format!("{prefix}{c}"))
            .collect();
        if prefix.is_empty() {
            cands.extend(aliases.iter().filter(|a| a.starts_with(bare)).cloned());
        }
        return CompletionPlan::Words(word_start, cands);
    }

    // Completing an argument: route by the command's first token.
    let command = before.split_whitespace().next().unwrap_or("");
    let command = command.strip_prefix("::").unwrap_or(command);
    match command {
        "source" | "k8s::load" => CompletionPlan::Files,
        // `load <rel> <src>`: file-complete the second argument on.
        "load" if before[..word_start].split_whitespace().count() >= 2 => CompletionPlan::Files,
        "show" | "why" | "query" | "explain" | "smtlib" | "?-" => {
            let cands = relations
                .iter()
                .filter(|r| r.starts_with(word))
                .cloned()
                .collect();
            CompletionPlan::Words(word_start, cands)
        }
        _ => CompletionPlan::Nothing,
    }
}

impl Completer for ReplHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        // Shell escape: complete file paths after `!`.
        if line.starts_with('!') && pos >= 1 {
            let (start, candidates) = self.path_completer.complete(&line[1..], pos - 1, ctx)?;
            return Ok((start + 1, candidates));
        }
        match plan_completion(&line[..pos], &self.aliases, &self.relations) {
            CompletionPlan::Words(start, words) => {
                Ok((start, words.into_iter().map(completion_pair).collect()))
            }
            CompletionPlan::Files => self.path_completer.complete(line, pos, ctx),
            CompletionPlan::Nothing => Ok((pos, vec![])),
        }
    }
}

impl Hinter for ReplHelper {
    type Hint = String;
}
impl Highlighter for ReplHelper {}
impl Validator for ReplHelper {}
impl Helper for ReplHelper {}

/// Render a relation's arity: the row width if any rows exist, else the declared
/// column count from its `Decl`, else `?` when the arity is genuinely unknown.
fn arity_display(store_arity: Option<usize>, doc: Option<&RelationDoc>) -> String {
    store_arity
        .or_else(|| doc.map(|d| d.columns.len()).filter(|n| *n > 0))
        .map(|n| n.to_string())
        .unwrap_or_else(|| "?".to_string())
}

/// Print `show`'s list view: one line per relation with its arity and
/// description. Undocumented relations (intermediates, mostly) are only
/// counted unless `show_all`.
fn print_relation_list(relations: &[RelationInfo], show_all: bool) {
    let mut hidden = 0;
    for relation in relations {
        let description = relation.doc.as_ref().and_then(|d| d.description.as_deref());
        if description.is_none() && !show_all {
            hidden += 1;
            continue;
        }
        let description = description.map(|d| format!("  — {d}")).unwrap_or_default();
        let arity = arity_display(relation.arity, relation.doc.as_ref());
        println!("  {}/{arity}{description}", relation.name);
    }
    if hidden > 0 {
        println!("  ({hidden} undocumented relation(s) hidden; show --all to include)");
    }
}

/// Print a psql `\d`-style detail block for one relation: its description and a
/// per-column listing of name, type, and description. Falls back to a bare
/// arity line when the relation has no `Decl` (e.g. derived predicates).
fn print_relation_detail(relation: &RelationInfo) {
    let name = &relation.name;
    let doc = relation.doc.as_ref();
    let arity = arity_display(relation.arity, doc);
    println!("{name}/{arity}");
    let Some(doc) = doc else {
        return;
    };
    if let Some(desc) = &doc.description {
        println!("  {desc}");
    }
    if doc.columns.is_empty() {
        return;
    }
    let name_w = doc.columns.iter().map(|c| c.name.len()).max().unwrap_or(0);
    let ty_w = doc
        .columns
        .iter()
        .map(|c| c.ty.as_deref().unwrap_or("").len())
        .max()
        .unwrap_or(0);
    for (i, col) in doc.columns.iter().enumerate() {
        let ty = col.ty.as_deref().unwrap_or("");
        let desc = col
            .description
            .as_deref()
            .map(|d| format!("  — {d}"))
            .unwrap_or_default();
        println!("  {i}. {:name_w$}  {:ty_w$}{desc}", col.name, ty,);
    }
}

/// How result-set tuples are rendered. `Plain`, named `default` on the command
/// line and in `format`, prints `Column = value` pairs, `Compact` prints bare
/// `rel(a, b, ...)` tuples and `Pretty` indents nested values. `Table` prints
/// an aligned table with a header row. `Ndjson` emits one JSON object per
/// tuple on its own line, for piping into `jq`, DuckDB, etc.
#[derive(clap::ValueEnum, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    #[default]
    #[value(name = "default")]
    Plain,
    Compact,
    Pretty,
    Table,
    Ndjson,
}

impl OutputFormat {
    fn label(self) -> &'static str {
        match self {
            OutputFormat::Plain => "default",
            OutputFormat::Compact => "compact",
            OutputFormat::Pretty => "pretty",
            OutputFormat::Table => "table",
            OutputFormat::Ndjson => "ndjson",
        }
    }
}

/// Render one tuple as a single-line NDJSON object. `key` maps a column index to
/// its key (relation column name or query variable); indices it doesn't cover
/// fall back to positional `c0, c1, ...`.
fn ndjson_row(tuple: &[Value], key: impl Fn(usize) -> Option<String>) -> String {
    let mut map = serde_json::Map::with_capacity(tuple.len());
    for (i, val) in tuple.iter().enumerate() {
        let k = key(i).unwrap_or_else(|| format!("c{i}"));
        map.insert(k, crate::value::value_to_json(val));
    }
    serde_json::Value::Object(map).to_string()
}

fn print_help() {
    println!("\n=== Interactive Query Mode ===");
    println!();
    println!("Commands are bare paths (e.g. `show`, `rbac::reaches`). A leading `::` is the");
    println!("fully-qualified form, used to disambiguate (e.g. `::rbac::diff` vs `::diff`).");
    println!("Queries always start with `?-`.");
    println!();
    println!("Querying");
    println!("  ?- <predicate>                         - list all tuples for a relation");
    println!(
        "  ?- <predicate>(arg, _, ...)            - list tuples matching the constants (_ and missing trailing args match any)"
    );
    println!(
        "  ?- <atom>, <atom>, ...                 - conjunctive query; name variables with uppercase (X) to see their bindings"
    );
    println!(
        "  ?- _(<var>, ...) :- <atom>, ...       - project: anonymous head, report only the head variables; the rest are join keys"
    );
    println!("  query <body>                           - long form of ?-");
    println!(
        "  explain <body>                         - show the planner's operator tree for a query (don't run it)"
    );
    println!(
        "  show                                   - list documented relations (arity + description)"
    );
    println!(
        "  show --all                             - also list undocumented intermediate relations"
    );
    println!(
        "  show <rel...>                          - describe relations (columns, types, docs)"
    );
    println!("  why <pred>(<args>...)                  - show derivation tree for a fact");
    println!();
    println!("EDB / Rules");
    println!("  +pred(arg1, arg2, ...).                - insert a ground fact and re-evaluate");
    println!("  -pred(arg1, arg2, ...).                - retract a ground fact and re-evaluate");
    println!(
        "  ~pred(old...). pred(new...).           - atomic replace: retract old, insert new, re-evaluate"
    );
    println!("  define <rule>.                         - add a rule and re-evaluate");
    println!();
    println!("Loading");
    println!(
        "  source <src>                           - load a Mangle file or ! <cmd>: ground facts as facts (retractable), the rest as rules; re-evaluate"
    );
    println!(
        "  load <rel> <src>                       - load flat JSON tuples into <rel>; src is a file or ! <cmd>"
    );
    println!(
        "  apply-delta <base> <head>              - apply a PR's base->head delta onto live: add head-only objects, update changed ones, retract base-only ones (what Argo prunes), leave identical ones (keeping live drift); each side is a dir, .json file, or - for empty"
    );
    println!();
    println!("Kubernetes  (k8s::)");
    println!(
        "  k8s::load <src>                        - load k8s objects through the projection pipeline, replacing any already loaded with the same group, kind, namespace and name; src is a dir, .json file, or ! <kubectl args>"
    );
    println!(
        "  k8s::match <Kind> <ns> <selector>      - objects of <Kind> in <ns> matching a kubectl selector (ns \"\" = cluster-scoped)"
    );
    println!(
        "  k8s::match-all <ns> <selector>         - objects of any Kind in <ns> matching a kubectl selector"
    );
    println!();
    println!("Snapshots");
    println!(
        "  snapshot <name>                        - save current eval state, and the facts and rules it came from, as a named snapshot"
    );
    println!(
        "  rollback <name>                        - restore the facts and rules saved by snapshot <name>, re-evaluate (the snapshot stays; each one holds a copy of the facts; not with --watch)"
    );
    println!(
        "  diff <name>                            - diff the state in use (live, unless `use` points elsewhere) against a named snapshot"
    );
    println!("  diff <name1> <name2>                   - diff two named snapshots (all relations)");
    println!(
        "  diff-relation <name> [name2] <rel>     - like diff but scoped to one relation; a diagnostic view, not a pass/fail check"
    );
    println!(
        "  use <name>                             - point ?-, why, show and friends at a named snapshot (no name: back to the live state)"
    );
    println!(
        "  use <name> <command>                   - run one command against <name>, then return to the previous state"
    );
    println!();
    println!("RBAC access  (rbac::)");
    println!(
        "  rbac::access <ns> <r> <v> [p...]       - find RBAC principals granted (ns,r,v) outside the expected set (ns \"\" for cluster-wide)"
    );
    println!(
        "  rbac::reaches <ns> <ag> <r> <v> [p...] - find RBAC principals that can reach (ns,ag,r,v), counting escalation"
    );
    println!(
        "  rbac::cluster-admin [p...]             - shorthand for reaches \"\" \"*\" \"*\" \"*\""
    );
    println!(
        "  rbac::isolation <ns> [p...]            - check that only the listed principals have any access in <ns>"
    );
    println!(
        "                                           reaches/cluster-admin flags: --direct (also list principals with a direct grant), --all (include built-in k8s/EKS principals, hidden by default)"
    );
    println!(
        "  rbac::diff <name> [name2]              - diff RBAC permissions, direct and through escalation, vs a snapshot (or between two snapshots)"
    );
    println!();
    println!("Scheduling  (sched::)");
    println!(
        "  sched::node-selector                   - find pods whose nodeSelector no node satisfies"
    );
    println!(
        "  sched::anti-affinity                   - find a valid pod placement or prove none exists"
    );
    println!(
        "  sched::karpenter                       - find nodeSelector gaps in Karpenter NodePool coverage"
    );
    println!(
        "                                           (--format ndjson: one JSON object per result/violation; exit status 1 if any check FAILs)"
    );
    println!();
    println!("Engine / debug");
    println!("  smtlib <rel> [rel...]                  - dump SMT-LIB 2 encoding of relations");
    println!();
    println!("Session");
    println!("  pretty                                 - toggle default/pretty tuple display");
    println!(
        "  format default|compact|pretty|table|ndjson - set output format (compact = bare tuples, table = aligned columns, ndjson = one JSON object per row)"
    );
    println!(
        "  alias [<name> [<command...>]]          - list, show, or define a command alias (expanded on a bare command's first token)"
    );
    println!("  unalias <name>                         - remove an alias");
    println!("  !<cmd>                                 - run a shell command");
    println!(
        "  # <text>                               - comment, ignored (handy in --script files)"
    );
    println!("  help                                   - show this help");
    println!("  quit                                   - exit");
    println!();
    println!(
        "Startup: commands in $XDG_CONFIG_HOME/pallograph/pallographrc (then ./.pallographrc)"
    );
    println!("run first; put `alias` and `format` lines there. --rcfile <f> / --no-rc override.");
    println!();
}

/// Print the subcommands of a subsystem container-command (`rbac`, `sched`,
/// `k8s`), shown when a bare namespace is entered with no subcommand.
fn print_subsystem_help(ns: &str) {
    match ns {
        "rbac" => {
            println!("rbac:: - RBAC access analysis");
            println!(
                "  rbac::access <ns> <r> <v> [p...]       - principals granted (ns,r,v) beyond the expected set"
            );
            println!(
                "  rbac::reaches <ns> <ag> <r> <v> [p...] - principals that can reach (ns,ag,r,v), counting escalation"
            );
            println!(
                "  rbac::cluster-admin [p...]             - shorthand for reaches \"\" \"*\" \"*\" \"*\""
            );
            println!(
                "  rbac::isolation <ns> [p...]            - check only the listed principals have access in <ns>"
            );
            println!(
                "  rbac::diff <name> [name2]              - diff RBAC permissions vs a snapshot, or between two snapshots"
            );
        }
        "sched" => {
            println!("sched:: - scheduling / placement analysis");
            println!(
                "  sched::node-selector                   - pods whose nodeSelector no node satisfies"
            );
            println!(
                "  sched::anti-affinity                   - a valid pod placement, or proof none exists"
            );
            println!(
                "  sched::karpenter                       - nodeSelector gaps in Karpenter NodePool coverage"
            );
        }
        "k8s" => {
            println!("k8s:: - Kubernetes object graph");
            println!(
                "  k8s::load <src>                        - load k8s objects through the projection pipeline"
            );
            println!(
                "  k8s::match <Kind> <ns> <selector>      - objects of <Kind> matching a kubectl selector"
            );
            println!(
                "  k8s::match-all <ns> <selector>         - objects of any Kind matching a kubectl selector"
            );
            println!(
                "  k8s::apply-delta <base> <head>         - apply a PR's base->head object delta onto live"
            );
        }
        _ => {}
    }
}

/// The line printed before a command when the cluster watcher changed the
/// live state since the last one, e.g. `live: 2 updated, 1 removed`. None
/// when nothing changed.
fn live_changes_line(summary: ApplySummary) -> Option<String> {
    let parts: Vec<String> = [
        (summary.added, "added"),
        (summary.updated, "updated"),
        (summary.retracted, "removed"),
    ]
    .into_iter()
    .filter(|(count, _)| *count > 0)
    .map(|(count, what)| format!("{count} {what}"))
    .collect();
    (!parts.is_empty()).then(|| format!("live: {}", parts.join(", ")))
}

/// Print the objects a selector matched, one `apiVersion/kind/namespace/name`
/// per line, or one NDJSON object each.
fn print_matches(format: OutputFormat, rows: &Rows) {
    if rows.rows.is_empty() {
        eprintln!("No matches.");
        return;
    }
    for object in &rows.rows {
        if format == OutputFormat::Ndjson {
            println!("{}", ndjson_row(object, |i| rows.columns.get(i).cloned()));
        } else {
            let parts: Vec<String> = object
                .iter()
                .map(|value| {
                    if format == OutputFormat::Pretty {
                        format_pretty(value)
                    } else {
                        value.to_string()
                    }
                })
                .collect();
            println!("  {}", parts.join("/"));
        }
    }
    eprintln!("Found {} match(es).", rows.rows.len());
}

/// The interactive prompt, red like the rest of the REPL's chrome. `use`
/// with no snapshot (`None`) points it back at the plain prompt; `use
/// <name>` names the snapshot queries are pointed at.
fn prompt(in_use: Option<&str>) -> String {
    match in_use {
        None => "\x1b[1;31mpallograph>\x1b[0m ".to_string(),
        Some(name) => format!("\x1b[1;31mpallograph ({name})>\x1b[0m "),
    }
}

/// The state read-only commands run against: the named snapshot's frozen
/// store under `use <name>`, or the live `current_store` otherwise.
fn active_store<'a>(
    current_store: &'a EvalStore,
    snapshots: &'a BTreeMap<String, FrozenState>,
    in_use: &Option<String>,
) -> &'a EvalStore {
    match in_use {
        Some(name) => {
            &snapshots
                .get(name)
                .expect("in_use always names an existing snapshot")
                .store
        }
        None => current_store,
    }
}

/// Where reads go: the snapshot `use` points at, or the live state.
fn current_at(in_use: &Option<String>) -> At {
    match in_use {
        Some(name) => At::Snapshot(name.clone()),
        None => At::Live,
    }
}

/// Return `true` and refuse a state-changing command (`+`, `-`, `~`,
/// `define`, `load`, `k8s::load`, `apply-delta`, `source`,
/// `snapshot`, `rollback`) while a snapshot is in use: a frozen state never changes, so there is
/// nothing for the command to act on. A refusal marks the line as failed.
fn refuse_if_in_use(in_use: &Option<String>, command_failed: &mut bool) -> bool {
    if let Some(name) = in_use {
        eprintln!("Snapshot '{name}' is in use; use to return to the live state.");
        *command_failed = true;
        true
    } else {
        false
    }
}

/// Print a `?-` query's result rows in the current output format, shared by
/// the live and `use` paths.
fn print_query_rows(format: OutputFormat, vars: &[String], tuples: &[Vec<Value>]) {
    if format == OutputFormat::Table {
        let rows: Vec<Vec<String>> = tuples
            .iter()
            .map(|t| t.iter().map(|v| v.to_string()).collect())
            .collect();
        print!("{}", render_table(vars, &rows));
        return;
    }
    for tuple in tuples {
        if format == OutputFormat::Ndjson {
            println!("{}", ndjson_row(tuple, |i| vars.get(i).cloned()));
        } else {
            let parts: Vec<String> = vars
                .iter()
                .zip(tuple.iter())
                .map(|(name, val)| format!("{name} = {val}"))
                .collect();
            println!("  {}", parts.join(", "));
        }
    }
}

/// How a session ended, which the binary turns into its exit status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionStatus {
    /// Every command ran and no check failed: exit 0.
    Clean,
    /// An `rbac::`/`sched::` check failed or `rbac::diff` found new permissions: exit 1.
    Findings,
    /// A `--script` line was not a command, or its command failed: exit 2.
    Error,
}

impl SessionStatus {
    pub fn exit_code(self) -> u8 {
        match self {
            SessionStatus::Clean => 0,
            SessionStatus::Findings => 1,
            SessionStatus::Error => 2,
        }
    }
}

/// Where a session reads its lines from.
enum Input {
    /// The REPL: rustyline, with completion and `~/.pallograph_history`.
    Editor {
        rl: Box<rustyline::Editor<ReplHelper, rustyline::history::DefaultHistory>>,
        history_path: std::path::PathBuf,
    },
    /// `--script`: one command per line from a file or stdin, no history.
    Script(Box<dyn std::io::BufRead>),
}

impl Input {
    fn readline(&mut self, prompt: &str) -> rustyline::Result<String> {
        match self {
            Input::Editor { rl, .. } => rl.readline(prompt),
            Input::Script(reader) => {
                let mut line = String::new();
                match reader.read_line(&mut line)? {
                    0 => Err(ReadlineError::Eof),
                    _ => Ok(line),
                }
            }
        }
    }

    fn add_history_entry(&mut self, line: &str) -> rustyline::Result<()> {
        if let Input::Editor { rl, .. } = self {
            rl.add_history_entry(line)?;
        }
        Ok(())
    }

    fn save_history(&mut self) {
        if let Input::Editor { rl, history_path } = self {
            let _ = rl.save_history(history_path);
        }
    }

    /// Refresh the tab-completion data (alias and relation names) shown at the
    /// next prompt. A no-op for `--script` input.
    fn set_completions(&mut self, aliases: Vec<String>, relations: Vec<String>) {
        if let Input::Editor { rl, .. } = self
            && let Some(helper) = rl.helper_mut()
        {
            helper.aliases = aliases;
            helper.relations = relations;
        }
    }
}

/// Run the REPL until EOF or `quit`. A command that fails prints an error
/// and the session carries on, so this returns `Findings` if any `rbac::`/
/// `sched::` check failed or `rbac::diff` found new permissions, else `Clean`.
pub fn run(
    core: &LocalCore,
    format: OutputFormat,
    rc: Vec<String>,
    watch: Option<&WatchStatus>,
) -> Result<SessionStatus> {
    // Banner is interactive chrome: skip it when stdout is redirected so a
    // piped session (e.g. `... | pallograph --format ndjson > out.json`) yields
    // clean data. Status/diagnostic lines go to stderr for the same reason.
    let interactive = std::io::stdout().is_terminal();
    if interactive {
        print_help();
    }

    let history_path = dirs_home().join(".pallograph_history");
    let config = rustyline::Config::builder()
        .completion_type(rustyline::config::CompletionType::List)
        .build();
    let mut rl =
        rustyline::Editor::<ReplHelper, rustyline::history::DefaultHistory>::with_config(config)?;
    rl.set_helper(Some(ReplHelper {
        path_completer: FilenameCompleter::new(),
        aliases: Vec::new(),
        relations: Vec::new(),
    }));
    let _ = rl.load_history(&history_path);
    let rl = Box::new(rl);
    session(core, format, rc, watch, Input::Editor { rl, history_path })
}

/// Run the commands in `path` (`-` for stdin), one per line, through the
/// same dispatcher as the REPL. Stops with `Error` at the first line that is
/// not a command or whose command fails; otherwise like [`run`].
pub fn run_script(
    core: &LocalCore,
    format: OutputFormat,
    path: &std::path::Path,
    rc: Vec<String>,
    watch: Option<&WatchStatus>,
) -> Result<SessionStatus> {
    let reader: Box<dyn std::io::BufRead> = if path == std::path::Path::new("-") {
        Box::new(std::io::stdin().lock())
    } else {
        let file = std::fs::File::open(path)
            .with_context(|| format!("opening script {}", path.display()))?;
        Box::new(std::io::BufReader::new(file))
    };
    session(core, format, rc, watch, Input::Script(reader))
}

fn session(
    core: &LocalCore,
    format: OutputFormat,
    rc: Vec<String>,
    watch: Option<&WatchStatus>,
    mut input: Input,
) -> Result<SessionStatus> {
    // A script stops at its first failed line; the REPL carries on.
    let stop_on_error = matches!(input, Input::Script(_));
    let mut command_failed = false;
    // Print a command's error and mark the line as failed.
    macro_rules! command_error {
        ($($arg:tt)*) => {{
            eprintln!($($arg)*);
            command_failed = true;
        }};
    }

    let mut format = format;
    let mut had_failure = false;
    // User-defined command aliases (see the `alias` command and the rc file).
    // A bare command's first token is expanded textually before dispatch; a
    // `::`-qualified command bypasses them.
    let mut aliases: BTreeMap<String, String> = BTreeMap::new();
    // The `bool` is whether the line belongs in rustyline history: `true` for
    // a pasted multi-line command split apart below, `false` for the inner
    // command and restore sentinel a `use <name> <command>` one-shot queues,
    // so up-arrow recalls the one-shot line as typed rather than its parts.
    let mut pending: std::collections::VecDeque<(String, bool)> = std::collections::VecDeque::new();
    // `None` = live state; `Some(name)` = `use <name>` is pointing read-only
    // commands at that frozen snapshot.
    let mut in_use: Option<String> = None;
    // `use <name> <command>` queues `<command>` and this sentinel onto the
    // front of `pending`, so the command runs with `<name>` in use and the
    // sentinel then restores whatever was in use before — on every `continue`
    // path, since it is just another queued line. The null byte keeps it out
    // of reach of anything a person could type.
    const USE_RESTORE_PREFIX: &str = "\0use-restore:";

    // rc (startup) lines run first, through the same dispatcher, followed by a
    // sentinel marking the end of the startup phase. rc errors warn and
    // continue: they must not stop a `--script` run or set the exit status, so
    // the sentinel clears any findings/errors the rc lines produced.
    const RC_END: &str = "\0rc-end";
    let mut in_rc = false;
    if !rc.is_empty() {
        in_rc = true;
        for line in rc {
            pending.push_back((line, false));
        }
        pending.push_back((RC_END.to_string(), false));
    }

    loop {
        if stop_on_error && command_failed && !in_rc {
            break;
        }
        let (raw, to_history) = if let Some((queued, to_history)) = pending.pop_front() {
            (Ok(queued), to_history)
        } else {
            // Refresh tab-completion data from the current state before
            // prompting. The live state as last evaluated is close enough.
            let relations: Vec<String> = {
                let live = core.last_live();
                let snapshots = core.snapshots();
                active_store(&live, &snapshots, &in_use)
                    .relation_names()
                    .filter(|n| !n.starts_with(':') && !n.starts_with('_'))
                    .map(str::to_string)
                    .collect()
            };
            input.set_completions(aliases.keys().cloned().collect(), relations);
            (input.readline(&prompt(in_use.as_deref())), true)
        };
        match raw {
            Ok(line) => {
                if line == RC_END {
                    // Startup phase done: discard any findings/errors the rc
                    // lines produced so they do not affect the exit status.
                    in_rc = false;
                    command_failed = false;
                    had_failure = false;
                    continue;
                }
                if let Some(prev) = line.strip_prefix(USE_RESTORE_PREFIX) {
                    in_use = (!prev.is_empty()).then(|| prev.to_string());
                    continue;
                }
                let line = line.trim().to_string();
                // `#` starts a comment line, as in Mangle files.
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                // Commands are bare paths (e.g. `show`, `rbac::reaches`). Internally
                // they are canonicalized to the `::`-qualified form, which is also
                // what a user types to disambiguate (e.g. `::rbac::diff` vs `::diff`).
                // Queries (`?-`), fact mutations (`+ - ~`), shell (`!`) and comments
                // (`#`, handled above) are not commands and are left untouched.
                let line = if line.starts_with("::") || line.starts_with(['?', '!', '+', '-', '~'])
                {
                    // `::` is the fully-qualified form and bypasses aliases.
                    line
                } else {
                    // A bare command: expand a user alias on its first token (if
                    // any), then canonicalize to the `::` form.
                    let expanded = expand_aliases(&line, &aliases);
                    if expanded.starts_with("::") {
                        expanded
                    } else {
                        format!("::{expanded}")
                    }
                };
                // Split pasted multi-line input into individual commands.
                // Only split at newlines where parentheses are balanced and we're
                // not inside a string, so that multi-line expressions (e.g. a fact
                // argument that wraps across lines) are kept together.
                // Only enter this branch when we have multiple commands to split;
                // a single command with embedded newlines (e.g. a string that wraps
                // across terminal lines) would loop forever here.
                if line.contains('\n') {
                    let cmds = split_commands(&line);
                    if cmds.len() > 1 {
                        pending.extend(cmds.into_iter().map(|cmd| (cmd, true)));
                        continue;
                    }
                    // Single command whose newlines are all inside strings
                    // (e.g. terminal line-wrap during paste). Collapse them.
                }
                let line = collapse_string_newlines(&line);
                if to_history {
                    input.add_history_entry(&line)?;
                }

                if let Some(line) = watch.and_then(|w| live_changes_line(w.take())) {
                    eprintln!("{line}");
                }

                if let Some(body) = line
                    .strip_prefix("::query ")
                    .or_else(|| line.strip_prefix("?- "))
                {
                    let at = current_at(&in_use);
                    match core.query(&at, body) {
                        Ok(rows) => print_rows(format, &rows),
                        Err(e) => command_error!("{e}"),
                    }
                    continue;
                }

                if let Some(fact) = line.strip_prefix("::why ") {
                    let at = current_at(&in_use);
                    match core.provenance(&at, fact) {
                        Ok(trees) if trees.is_empty() => {
                            eprintln!("No matching facts for '{}'.", fact.trim());
                        }
                        Ok(trees) => trees.iter().for_each(print_provenance),
                        Err(e) => command_error!("{e}"),
                    }
                    continue;
                }

                if line == "::use" || line.starts_with("::use ") {
                    let rest = line.strip_prefix("::use").unwrap_or("").trim();
                    if rest.is_empty() {
                        in_use = None;
                        eprintln!("Using live state.");
                        continue;
                    }
                    let (name, command) = match rest.split_once(char::is_whitespace) {
                        Some((n, c)) => (n.to_string(), Some(c.trim().to_string())),
                        None => (rest.to_string(), None),
                    };
                    if !core.has_snapshot(&name) {
                        command_error!("No snapshot named '{name}'.");
                        continue;
                    }
                    match command {
                        None => {
                            eprintln!("Using snapshot '{name}'.");
                            in_use = Some(name);
                        }
                        Some(command) => {
                            // One-shot: queue the command to run with `name`
                            // in use, then a sentinel to restore whatever was
                            // in use before — on every `continue` path, since
                            // it is just the next queued line.
                            let prev = in_use.clone().unwrap_or_default();
                            pending.push_front((format!("{USE_RESTORE_PREFIX}{prev}"), false));
                            pending.push_front((command, false));
                            in_use = Some(name);
                        }
                    }
                    continue;
                }

                if let Some(name) = line.strip_prefix("::snapshot ") {
                    if refuse_if_in_use(&in_use, &mut command_failed) {
                        continue;
                    }
                    match core.snapshot(name.trim()) {
                        Ok(info) => println!(
                            "Saved snapshot '{}' ({} relations, {} facts).",
                            info.name, info.relations, info.facts
                        ),
                        Err(e) => command_error!("{e}"),
                    }
                    continue;
                }

                // `diff <name> [<name>]` and `diff-relation <name> [<name>]
                // <relation>`: one snapshot diffs against whatever is in use.
                let diff_args = line
                    .strip_prefix("::diff ")
                    .map(|rest| (rest, false))
                    .or_else(|| {
                        line.strip_prefix("::diff-relation ")
                            .map(|rest| (rest, true))
                    });
                if let Some((rest, one_relation)) = diff_args {
                    let mut parts: Vec<&str> = rest.split_whitespace().collect();
                    let relation = if one_relation { parts.pop() } else { None };
                    let current = current_at(&in_use);
                    let (before, after) = match parts.as_slice() {
                        [name] => (At::Snapshot(name.to_string()), current),
                        [name1, name2] => (
                            At::Snapshot(name1.to_string()),
                            At::Snapshot(name2.to_string()),
                        ),
                        _ if one_relation => {
                            command_error!(
                                "Usage: diff-relation <name> <relation>  or  diff-relation <name1> <name2> <relation>"
                            );
                            continue;
                        }
                        _ => {
                            command_error!("Usage: diff <name>  or  diff <name1> <name2>");
                            continue;
                        }
                    };
                    match core.diff(&before, &after, relation) {
                        Ok(diff) => print!("{diff}"),
                        Err(e) => command_error!("{e}"),
                    }
                    continue;
                }

                if line == "::show" || line.starts_with("::show ") {
                    let tokens: Vec<&str> = line
                        .strip_prefix("::show")
                        .unwrap_or("")
                        .split_whitespace()
                        .collect();
                    // `--all`/`*` reveals undocumented intermediate relations in the
                    // list view; remaining tokens are explicit relation names.
                    let show_all = tokens.iter().any(|t| *t == "--all" || *t == "*");
                    let names: Vec<&str> = tokens
                        .into_iter()
                        .filter(|t| *t != "--all" && *t != "*")
                        .collect();
                    match core.relations(&current_at(&in_use), &names) {
                        Ok(relations) if names.is_empty() => {
                            print_relation_list(&relations, show_all);
                        }
                        // Detail view: a psql \d-style block per requested relation.
                        Ok(relations) => relations.iter().for_each(print_relation_detail),
                        Err(e) => command_error!("{e}"),
                    }
                    continue;
                }

                if let Some(rule) = line.strip_prefix("::define ") {
                    if refuse_if_in_use(&in_use, &mut command_failed) {
                        continue;
                    }
                    match core.define(rule) {
                        Ok(()) => eprintln!("Rule added and evaluated."),
                        Err(e) => command_error!("{e}"),
                    }
                    continue;
                }

                // ~pred(old_args). pred(new_args).  — replace one ground fact
                if let Some(rest) = line.strip_prefix('~') {
                    if refuse_if_in_use(&in_use, &mut command_failed) {
                        continue;
                    }
                    let Some((old_atom, new_atom)) = split_two_atoms(rest.trim()) else {
                        command_error!("Usage: ~pred(old_args). pred(new_args).");
                        continue;
                    };
                    let parsed = parse_fact(old_atom)
                        .and_then(|old| parse_fact(new_atom).map(|new| (old, new)));
                    match parsed {
                        Ok((old, new)) => match core.replace_fact(&old, new) {
                            Ok(true) => println!("Replaced."),
                            Ok(false) => {
                                println!("Warning: old fact not found; new fact inserted.")
                            }
                            Err(e) => command_error!("{e}"),
                        },
                        Err(e) => command_error!("Parse error: {e}"),
                    }
                    continue;
                }

                // +pred(args).  — insert ground fact
                if let Some(inner) = line.strip_prefix('+') {
                    if refuse_if_in_use(&in_use, &mut command_failed) {
                        continue;
                    }
                    match parse_fact(inner.trim_end_matches('.').trim()) {
                        Ok(fact) => match core.assert_fact(fact) {
                            Ok(true) => eprintln!("Asserted."),
                            Ok(false) => eprintln!("Fact already exists."),
                            Err(e) => command_error!("{e}"),
                        },
                        Err(e) => command_error!("Parse error: {e}"),
                    }
                    continue;
                }

                // -pred(args).  — retract ground fact
                if let Some(inner) = line.strip_prefix('-') {
                    if refuse_if_in_use(&in_use, &mut command_failed) {
                        continue;
                    }
                    match parse_fact(inner.trim_end_matches('.').trim()) {
                        Ok(fact) => match core.retract_fact(&fact) {
                            Ok(true) => eprintln!("Retracted."),
                            Ok(false) => eprintln!("No matching fact found."),
                            Err(e) => command_error!("{e}"),
                        },
                        Err(e) => command_error!("Parse error: {e}"),
                    }
                    continue;
                }

                // The loading commands read files and run commands here, on
                // the client, and hand the core what they read.
                if let Some(src) = line.strip_prefix("::source ") {
                    if refuse_if_in_use(&in_use, &mut command_failed) {
                        continue;
                    }
                    match load::read_source(src.trim()) {
                        Ok(bytes) => match std::str::from_utf8(&bytes) {
                            Ok(text) => match core.source(text) {
                                Ok(()) => eprintln!("Sourced and evaluated."),
                                Err(e) => command_error!("{e}"),
                            },
                            Err(e) => command_error!("Source error: not valid UTF-8: {e}"),
                        },
                        Err(e) => command_error!("Source error: {e:#}"),
                    }
                    continue;
                }

                if let Some(rest) = line.strip_prefix("::k8s::load ") {
                    if refuse_if_in_use(&in_use, &mut command_failed) {
                        continue;
                    }
                    let rest = rest.trim();
                    let objects = match rest.strip_prefix('!') {
                        Some(command) => ShellSource {
                            command: command.trim().to_string(),
                        }
                        .k8s_objects(),
                        None => K8sManifestsSource {
                            paths: vec![rest.to_string()],
                        }
                        .k8s_objects(),
                    };
                    match objects {
                        Ok(objects) => match core.load_objects(objects) {
                            Ok(summary) => eprintln!(
                                "Loaded {} object(s) ({} replaced) and evaluated.",
                                summary.added + summary.updated,
                                summary.updated
                            ),
                            Err(e) => command_error!("{e}"),
                        },
                        Err(e) => command_error!("Load error: {e:#}"),
                    }
                    continue;
                }

                if let Some(rest) = line.strip_prefix("::k8s::apply-delta ") {
                    if refuse_if_in_use(&in_use, &mut command_failed) {
                        continue;
                    }
                    let args: Vec<&str> = rest.split_whitespace().collect();
                    let [base_arg, head_arg] = args.as_slice() else {
                        command_error!(
                            "Usage: k8s::apply-delta <base> <head> (a dir, .json file, or - for an empty side)"
                        );
                        continue;
                    };
                    let sides = load_delta_side(base_arg)
                        .and_then(|base| Ok((base, load_delta_side(head_arg)?)));
                    match sides {
                        Ok((base, head)) => match core.apply_delta(base, head) {
                            Ok(delta) => eprintln!(
                                "Applied delta: +{} ~{} -{} ({} unchanged, {} removed but not live) and evaluated.",
                                delta.added,
                                delta.updated,
                                delta.removed,
                                delta.unchanged,
                                delta.removed_absent
                            ),
                            Err(e) => command_error!("{e}"),
                        },
                        Err(e) => command_error!("Delta error: {e:#}"),
                    }
                    continue;
                }

                if let Some(rest) = line.strip_prefix("::load ") {
                    if refuse_if_in_use(&in_use, &mut command_failed) {
                        continue;
                    }
                    let rest = rest.trim();
                    // Split on first whitespace: <relation> <source>
                    let Some((relation, source)) = rest.split_once(char::is_whitespace) else {
                        command_error!(
                            "Usage: load <relation> <source>  (source is a file path or ! <cmd>)"
                        );
                        continue;
                    };
                    match load::read_tuples(source.trim()) {
                        Ok(rows) => match core.load_facts(relation, rows) {
                            Ok(n) => {
                                eprintln!("Inserted {n} fact(s) into {relation} and evaluated.");
                            }
                            Err(e) => command_error!("{e}"),
                        },
                        Err(e) => command_error!("Load error: {e:#}"),
                    }
                    continue;
                }

                // k8s::match <Kind> <namespace> <selector> scopes to one Kind;
                // k8s::match-all <namespace> <selector> matches any Kind.
                let match_args = line
                    .strip_prefix("::k8s::match ")
                    .map(|rest| (rest, true))
                    .or_else(|| {
                        line.strip_prefix("::k8s::match-all ")
                            .map(|rest| (rest, false))
                    });
                if let Some((rest, one_kind)) = match_args {
                    let fields = if one_kind { 3 } else { 2 };
                    let parts: Vec<&str> =
                        rest.trim().splitn(fields, char::is_whitespace).collect();
                    let (kind, namespace, selector) = match (one_kind, parts.as_slice()) {
                        (true, [kind, namespace, selector]) => (Some(*kind), *namespace, *selector),
                        (false, [namespace, selector]) => (None, *namespace, *selector),
                        (true, _) => {
                            command_error!(
                                "Usage: k8s::match <Kind> <namespace> <selector>  (namespace \"\" for cluster-scoped)"
                            );
                            continue;
                        }
                        (false, _) => {
                            command_error!("Usage: k8s::match-all <namespace> <selector>");
                            continue;
                        }
                    };
                    // The cluster-scoped namespace is typed as ""; the REPL
                    // doesn't otherwise strip quotes from arguments.
                    let namespace = namespace.trim_matches('"');
                    match core.match_selector(&current_at(&in_use), kind, namespace, selector) {
                        Ok(rows) => print_matches(format, &rows),
                        Err(e) => command_error!("{e}"),
                    }
                    continue;
                }

                if line == "::rbac::diff" {
                    command_error!("Usage: rbac::diff <snap>  or  rbac::diff <snap1> <snap2>");
                    continue;
                }
                if let Some(rest) = line.strip_prefix("::rbac::diff ") {
                    let parts: Vec<&str> = rest.split_whitespace().collect();
                    // One snapshot diffs against whatever is in use, and the
                    // header names it instead of "current".
                    let (before, after, before_label, after_label) = match parts.as_slice() {
                        [name] => (
                            At::Snapshot(name.to_string()),
                            current_at(&in_use),
                            *name,
                            in_use.as_deref().unwrap_or("current"),
                        ),
                        [name1, name2] => (
                            At::Snapshot(name1.to_string()),
                            At::Snapshot(name2.to_string()),
                            *name1,
                            *name2,
                        ),
                        _ => {
                            command_error!(
                                "Usage: rbac::diff <snap>  or  rbac::diff <snap1> <snap2>"
                            );
                            continue;
                        }
                    };
                    match core.rbac_diff(&before, &after) {
                        Ok(diff) => {
                            if !print_access_diff(&diff, before_label, after_label) {
                                had_failure = true;
                            }
                        }
                        Err(e) => command_error!("{e}"),
                    }
                    continue;
                }
                if let Some(rest) = line.strip_prefix("::rbac::") {
                    match rbac_command(rest.trim(), core, &current_at(&in_use), format) {
                        CheckResult::Pass => {}
                        CheckResult::Fail => had_failure = true,
                        CheckResult::Error => command_failed = true,
                    }
                    continue;
                }
                if let Some(rest) = line.strip_prefix("::sched::") {
                    match sched_command(rest.trim(), core, &current_at(&in_use), format) {
                        CheckResult::Pass => {}
                        CheckResult::Fail => had_failure = true,
                        CheckResult::Error => command_failed = true,
                    }
                    continue;
                }

                if let Some(query) = line.strip_prefix("::explain ") {
                    match core.explain(&current_at(&in_use), query) {
                        Ok(plan) => print!("{plan}"),
                        Err(e) => command_error!("{e}"),
                    }
                    continue;
                }

                if let Some(rest) = line.strip_prefix("::smtlib ") {
                    let relations: Vec<&str> = rest.split_whitespace().collect();
                    if relations.is_empty() {
                        command_error!("Usage: smtlib <relation> [relation ...]");
                        continue;
                    }
                    match core.smtlib(&current_at(&in_use), &relations) {
                        Ok(smtlib) => println!("{smtlib}"),
                        Err(e) => command_error!("{e}"),
                    }
                    continue;
                }

                if line == "::rollback" || line.starts_with("::rollback ") {
                    if refuse_if_in_use(&in_use, &mut command_failed) {
                        continue;
                    }
                    if watch.is_some() {
                        // A rollback swaps the whole EDB behind the watcher's back,
                        // so objects deleted since the snapshot would come back.
                        command_error!(
                            "rollback is unavailable while watching a cluster: the watcher owns the live state."
                        );
                        continue;
                    }
                    let name = line.strip_prefix("::rollback").unwrap_or("").trim();
                    if name.is_empty() {
                        command_error!("Usage: rollback <name>");
                        continue;
                    }
                    match core.rollback(name) {
                        Ok(()) => println!("Rolled back to snapshot '{name}'."),
                        Err(e) => command_error!("{e}"),
                    }
                    continue;
                }

                if let Some(cmd) = line.strip_prefix('!') {
                    let cmd = cmd.trim();
                    let shell = std::env::var("SHELL").unwrap_or_else(|_| "sh".to_string());
                    let shell_name = std::path::Path::new(&shell)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("sh")
                        .to_string();
                    let status = if shell_name == "zsh" {
                        std::process::Command::new(&shell)
                            .args(["-i", "-o", "nomonitor", "-c", cmd])
                            .status()
                    } else {
                        std::process::Command::new(&shell)
                            .args(["-ic", cmd])
                            .status()
                    };
                    match status {
                        Ok(status) if !status.success() => {
                            command_error!("Shell command failed: {status}")
                        }
                        Ok(_) => {}
                        Err(e) => command_error!("Shell error: {e}"),
                    }
                    continue;
                }

                if line == "::quit" || line == "::exit" || line == "::q" {
                    break;
                }
                if line == "::help" {
                    print_help();
                    continue;
                }
                // `alias` (no args) lists; `alias <name> <command...>` defines a
                // textual shorthand expanded on a bare command's first token;
                // `alias <name>` shows one. Persist aliases by putting them in
                // the rc file. A `::`-qualified command bypasses aliases.
                if line == "::alias" || line.starts_with("::alias ") {
                    let rest = line.strip_prefix("::alias").unwrap_or("").trim();
                    if rest.is_empty() {
                        if aliases.is_empty() {
                            println!("No aliases defined.");
                        } else {
                            for (name, body) in &aliases {
                                println!("  {name} = {body}");
                            }
                        }
                    } else if let Some((name, body)) = rest.split_once(char::is_whitespace) {
                        let body = body.trim();
                        if body.is_empty() {
                            command_error!("Usage: alias <name> <command...>");
                        } else {
                            aliases.insert(name.to_string(), body.to_string());
                        }
                    } else {
                        match aliases.get(rest) {
                            Some(body) => println!("  {rest} = {body}"),
                            None => command_error!("No alias named '{rest}'."),
                        }
                    }
                    continue;
                }
                if line == "::unalias" || line.starts_with("::unalias ") {
                    let name = line.strip_prefix("::unalias").unwrap_or("").trim();
                    if name.is_empty() {
                        command_error!("Usage: unalias <name>");
                    } else if aliases.remove(name).is_none() {
                        command_error!("No alias named '{name}'.");
                    }
                    continue;
                }
                if line == "::pretty" {
                    // Shortcut: toggle between default and pretty display.
                    format = if format == OutputFormat::Pretty {
                        OutputFormat::Plain
                    } else {
                        OutputFormat::Pretty
                    };
                    eprintln!("Output format: {}.", format.label());
                    continue;
                }
                if line == "::format" || line.starts_with("::format ") {
                    let arg = line.strip_prefix("::format").unwrap_or("").trim();
                    match arg {
                        "default" => format = OutputFormat::Plain,
                        "compact" => format = OutputFormat::Compact,
                        "pretty" => format = OutputFormat::Pretty,
                        "table" => format = OutputFormat::Table,
                        "ndjson" => format = OutputFormat::Ndjson,
                        "" => {} // no arg: just report the current format
                        other => {
                            command_error!(
                                "Unknown format '{other}'. Use: default | compact | pretty | table | ndjson."
                            );
                            continue;
                        }
                    }
                    eprintln!("Output format: {}.", format.label());
                    continue;
                }
                // Subsystem container-commands. A bare namespace lists its
                // subcommands; `ns::sub` runs one. The k8s object commands have
                // their own blocks above, so a leftover `::k8s::` here is an
                // unknown subcommand.
                if line == "::rbac" {
                    print_subsystem_help("rbac");
                    continue;
                }
                if line == "::sched" {
                    print_subsystem_help("sched");
                    continue;
                }
                if line == "::k8s" {
                    print_subsystem_help("k8s");
                    continue;
                }
                if let Some(rest) = line.strip_prefix("::k8s::") {
                    // A known k8s command invoked with no arguments: show usage.
                    let head = format!("k8s::{}", rest.split_whitespace().next().unwrap_or(""));
                    if let Some(usage) = command_usage(&head) {
                        command_error!("Usage: {usage}");
                    } else {
                        command_error!(
                            "Unknown k8s command. Available: k8s::load, k8s::match, k8s::match-all, k8s::apply-delta."
                        );
                    }
                    continue;
                }

                // Not matched above. If the first path token is a known command
                // that takes arguments, it was invoked with none: show its usage.
                // Otherwise it is genuinely unknown.
                let shown = line.strip_prefix("::").unwrap_or(&line);
                let head = shown.split_whitespace().next().unwrap_or(shown);
                if let Some(usage) = command_usage(head) {
                    command_error!("Usage: {usage}");
                } else {
                    command_error!(
                        "Unknown command: {shown}. Type `help` for commands, or `?- {shown}` to run it as a query."
                    );
                }
            }
            Err(ReadlineError::Interrupted) => continue,
            Err(ReadlineError::Eof) => break,
            Err(e) => {
                command_error!("Error: {e}");
                break;
            }
        }
    }

    input.save_history();
    Ok(if stop_on_error && command_failed {
        SessionStatus::Error
    } else if had_failure {
        SessionStatus::Findings
    } else {
        SessionStatus::Clean
    })
}

/// Split a multi-line pasted string into individual commands, keeping lines
/// together when a newline falls inside an unbalanced parenthesis or string.
fn collapse_string_newlines(input: &str) -> String {
    if !input.contains('\n') {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len());
    let mut in_string = false;
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                in_string = !in_string;
                out.push('"');
            }
            '\n' if in_string => {
                while chars
                    .peek()
                    .is_some_and(|c| c.is_ascii_whitespace() && *c != '\n')
                {
                    chars.next();
                }
            }
            _ => out.push(ch),
        }
    }
    out
}

fn split_commands(input: &str) -> Vec<String> {
    let mut commands = Vec::new();
    let mut current = String::new();
    let mut depth: i32 = 0;
    let mut in_string = false;

    for ch in input.chars() {
        match ch {
            '"' => in_string = !in_string,
            '(' if !in_string => depth += 1,
            ')' if !in_string => depth -= 1,
            '\n' if !in_string && depth <= 0 => {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    commands.push(trimmed);
                }
                current = String::new();
                continue;
            }
            _ => {}
        }
        current.push(ch);
    }
    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() {
        commands.push(trimmed);
    }
    commands
}

fn fmt_binding(p: &rbac::AccessPath) -> String {
    let ns = if p.binding_namespace.is_empty() {
        String::new()
    } else {
        format!("{}/", p.binding_namespace)
    };
    format!(
        "{} {}{} → {} {}",
        p.binding_kind, ns, p.binding_name, p.role_kind, p.role_name
    )
}

fn mech_str(mech: &str) -> String {
    if mech.is_empty() {
        String::new()
    } else {
        format!(" [{mech}]")
    }
}

/// Serialize an access path to a stable string key for grouping.
fn path_sig(p: &rbac::AccessPath) -> String {
    let hops: String = p
        .hops
        .iter()
        .map(|(hop, mechanism)| format!("{}#{mechanism}", hop.smt_key()))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{}|{}|{}|{}",
        hops, p.binding_kind, p.binding_namespace, p.binding_name
    )
}

fn print_violation_paths(paths: &[rbac::AccessPath]) {
    // Group paths by identical hop chain: print "via X [mech]" once, then list
    // all bindings of the target underneath it rather than repeating the header.
    let mut by_hops: BTreeMap<&Vec<(rbac::Subject, String)>, Vec<&rbac::AccessPath>> =
        BTreeMap::new();
    for p in paths {
        by_hops.entry(&p.hops).or_default().push(p);
    }
    for (hops, group) in &by_hops {
        if hops.is_empty() {
            for p in group {
                println!("          {}", fmt_binding(p));
            }
        } else {
            let (hop, mechanism) = &hops[0];
            println!("          via {hop}{}", mech_str(mechanism));
            for (hop, mechanism) in hops[1..].iter() {
                println!("            → via {hop}{}", mech_str(mechanism));
            }
            for p in group {
                println!("            → {}", fmt_binding(p));
            }
        }
    }
}

/// Print reaches/cluster-admin violations path-first: show each distinct
/// escalation path once and list the principals that can use it underneath.
/// This avoids repeating the same path for every one of N principals.
/// Users and groups are annotated with their kind, e.g. "(group)".
fn print_reaches_grouped(violations: &[rbac::Violation]) {
    // Preserve first-seen order for paths; use a Vec<key> + BTreeMap for lookup.
    let mut order: Vec<String> = Vec::new();
    let mut groups: BTreeMap<String, (Vec<rbac::AccessPath>, Vec<rbac::Subject>)> = BTreeMap::new();
    for v in violations {
        let sig: String = {
            let mut parts: Vec<String> = v.paths.iter().map(path_sig).collect();
            parts.sort();
            parts.join(";")
        };
        if !groups.contains_key(&sig) {
            order.push(sig.clone());
        }
        let entry = groups
            .entry(sig)
            .or_insert_with(|| (v.paths.clone(), Vec::new()));
        entry.1.push(v.principal.clone());
    }
    for sig in &order {
        let (paths, principals) = &groups[sig];
        print_violation_paths(paths);
        println!("          {} principal(s):", principals.len());
        for principal in principals {
            println!("            {}", principal.with_kind());
        }
    }
}

/// Print what RBAC permissions changed from `before` to `after`. Returns
/// `false` when any permission was gained (the `FAIL` verdict).
fn print_access_diff(diff: &AccessDiff, before_label: &str, after_label: &str) -> bool {
    let total_gained = diff.total_gained();
    let total_lost = diff.total_lost();
    if total_gained > 0 {
        println!("FAIL  {} new permission(s) granted", total_gained);
    } else if total_lost > 0 {
        println!("PASS  {} permission(s) removed, none added", total_lost);
    } else {
        println!("PASS  no permission changes");
        return true;
    }

    println!(
        "=== Access diff: '{}' → '{}' ===",
        before_label, after_label
    );
    if !diff.verdicts.is_empty() {
        println!();
        println!("  Per-principal:");
        let col_w = diff
            .verdicts
            .iter()
            .map(|verdict| verdict.principal.to_string().len())
            .max()
            .unwrap_or(8)
            .min(32);
        for verdict in &diff.verdicts {
            let label = if verdict.gained > 0 { "FAIL" } else { "PASS" };
            let principal = verdict.principal.to_string();
            println!(
                "    {label}  {principal:<col_w$}  +{} gained / -{} lost",
                verdict.gained, verdict.lost
            );
        }
        println!();
    }

    for (heading, changes) in [
        ("CAN GAINED", &diff.can_gained),
        ("CAN LOST", &diff.can_lost),
    ] {
        if changes.is_empty() {
            continue;
        }
        println!("  {heading} ({}):", changes.len());
        let mut sorted: Vec<&rbac::diff::CanDiff> = changes.iter().collect();
        sorted.sort_by(|a, b| a.principal.cmp(&b.principal));
        for d in sorted {
            println!(
                "    {}  ns={:?}  apigroup={:?}  resource={:?}  verb={:?}",
                d.principal, d.namespace, d.apigroup, d.resource, d.verb
            );
        }
    }
    if !diff.effective_gained.is_empty() {
        println!(
            "  EFFECTIVE GAINED ({}) [escalation-aware]:",
            diff.effective_gained.len()
        );
        print_eff_diffs_grouped(&diff.effective_gained);
    }
    if !diff.effective_lost.is_empty() {
        println!(
            "  EFFECTIVE LOST ({}) [escalation-aware]:",
            diff.effective_lost.len()
        );
        print_eff_diffs_grouped(&diff.effective_lost);
    }
    total_gained == 0
}

/// Group effective-can changes by (principal, escalation target) and print.
/// A change reached through no identity or group was gained directly.
fn print_eff_diffs_grouped(changes: &[rbac::diff::EffectiveChange]) {
    // (principal, target) → indices into changes. No target = direct grant.
    let mut groups: BTreeMap<(rbac::Subject, Option<rbac::Subject>), Vec<usize>> = BTreeMap::new();
    for (i, change) in changes.iter().enumerate() {
        let principal = &change.diff.principal;
        if change.via.is_empty() {
            groups.entry((principal.clone(), None)).or_default().push(i);
        } else {
            for target in &change.via {
                groups
                    .entry((principal.clone(), Some(target.clone())))
                    .or_default()
                    .push(i);
            }
        }
    }

    for ((principal, target), indices) in &groups {
        match target {
            None => println!("    {principal}  [direct]:"),
            Some(target) => println!("    {principal}  via {target}:"),
        }
        for &i in indices {
            let d = &changes[i].diff;
            println!(
                "      ns={:?}  apigroup={:?}  resource={:?}  verb={:?}",
                d.namespace, d.apigroup, d.resource, d.verb
            );
        }
    }
}
/// JSON form of a violation's explaining binding paths (ndjson output).
fn paths_json(paths: &[rbac::AccessPath]) -> Vec<serde_json::Value> {
    paths
        .iter()
        .map(|p| {
            serde_json::json!({
                "binding_kind": p.binding_kind,
                "binding_namespace": p.binding_namespace,
                "binding_name": p.binding_name,
                "role_kind": p.role_kind,
                "role_name": p.role_name,
                "via": p.hops.iter()
                    .map(|(hop, mechanism)| serde_json::json!({
                        "identity": hop.name,
                        "identity_kind": hop.kind.as_str(),
                        "mechanism": mechanism,
                    }))
                    .collect::<Vec<_>>(),
            })
        })
        .collect()
}

/// What an `rbac::`/`sched::` check concluded.
enum CheckResult {
    Pass,
    /// A `FAIL` line in plain output, `"result":"fail"` in ndjson.
    Fail,
    /// A usage error or unknown subcommand: no check ran.
    Error,
}

/// Run an `rbac::` RBAC access check. The caller turns a `Fail` into exit
/// status 1 and an `Error` into exit status 2 under `--script`.
fn rbac_command(input: &str, core: &LocalCore, at: &At, format: OutputFormat) -> CheckResult {
    let ndjson = format == OutputFormat::Ndjson;
    let mut tokens = input.splitn(2, ' ');
    let subcommand = tokens.next().unwrap_or("").trim();
    let rest = tokens.next().unwrap_or("").trim();

    match subcommand {
        "access" => {
            let mut args = rest.split_whitespace();
            let (Some(ns_raw), Some(res_raw), Some(verb_raw)) =
                (args.next(), args.next(), args.next())
            else {
                eprintln!(
                    "Usage: rbac::access <namespace> <resource> <verb> [expected_principal ...]"
                );
                eprintln!("       Use \"\" for namespace to check cluster-wide (CRB) grants.");
                return CheckResult::Error;
            };
            let namespace = ns_raw.trim_matches('"');
            let resource = res_raw.trim_matches('"');
            let verb = verb_raw.trim_matches('"');
            // Accept [] as empty-list notation; strip quotes from each principal.
            let expected_owned: Vec<String> = args
                .filter(|s| !matches!(*s, "[]" | "[" | "]"))
                .map(|s| s.trim_matches('"').to_string())
                .collect();
            let expected: Vec<&str> = expected_owned.iter().map(String::as_str).collect();

            let violations = match core.rbac_access(at, namespace, resource, verb, &expected) {
                Ok(violations) => violations,
                Err(e) => {
                    eprintln!("{e}");
                    return CheckResult::Error;
                }
            };
            if violations.is_empty() {
                if ndjson {
                    println!(
                        "{}",
                        serde_json::json!({"result":"pass","check":"access","namespace":namespace,"resource":resource,"verb":verb})
                    );
                } else {
                    println!("PASS  can(_, {namespace:?}, {resource:?}, {verb:?})");
                }
                CheckResult::Pass
            } else {
                if ndjson {
                    for v in &violations {
                        println!(
                            "{}",
                            serde_json::json!({
                                "result": "fail",
                                "check": "access",
                                "principal": v.principal.name,
                                "principal_kind": v.principal.kind.as_str(),
                                "namespace": namespace,
                                "resource": resource,
                                "verb": verb,
                                "paths": paths_json(&v.paths),
                            })
                        );
                    }
                } else {
                    println!(
                        "FAIL  can(_, {namespace:?}, {resource:?}, {verb:?}) — {} unexpected principal(s):",
                        violations.len()
                    );
                    for v in &violations {
                        println!(
                            "        UNEXPECTED can({}, {:?}, {:?}, {:?})",
                            v.principal.quoted(),
                            v.namespace,
                            v.resource,
                            v.verb
                        );
                        print_violation_paths(&v.paths);
                    }
                }
                CheckResult::Fail
            }
        }
        "reaches" | "cluster-admin" => {
            // Parse --direct flag out of the token stream before positional args.
            let tokens: Vec<&str> = rest.split_whitespace().collect();
            let include_direct = tokens.contains(&"--direct");
            let include_builtins = tokens.contains(&"--all");
            let mut token_iter = tokens
                .iter()
                .filter(|t| !matches!(**t, "--direct" | "--all"))
                .copied();

            let (namespace, apigroup, resource, verb, expected) = if subcommand == "cluster-admin" {
                let expected_owned: Vec<String> = token_iter
                    .filter(|s| !matches!(*s, "[]" | "[" | "]"))
                    .map(|s| s.trim_matches('"').to_string())
                    .collect();
                ("", "*", "*", "*", expected_owned)
            } else {
                let (Some(ns_raw), Some(ag_raw), Some(res_raw), Some(verb_raw)) = (
                    token_iter.next(),
                    token_iter.next(),
                    token_iter.next(),
                    token_iter.next(),
                ) else {
                    eprintln!(
                        "Usage: rbac::reaches <namespace> <apigroup> <resource> <verb> [--direct] [--all] [expected ...]"
                    );
                    eprintln!(
                        "       Use rbac::cluster-admin [--direct] [--all] to check for cluster-admin level access."
                    );
                    return CheckResult::Error;
                };
                let expected_owned: Vec<String> = token_iter
                    .filter(|s| !matches!(*s, "[]" | "[" | "]"))
                    .map(|s| s.trim_matches('"').to_string())
                    .collect();
                (
                    ns_raw.trim_matches('"'),
                    ag_raw.trim_matches('"'),
                    res_raw.trim_matches('"'),
                    verb_raw.trim_matches('"'),
                    expected_owned,
                )
            };
            let query = ReachesQuery {
                namespace: namespace.to_string(),
                apigroup: apigroup.to_string(),
                resource: resource.to_string(),
                verb: verb.to_string(),
                expected,
                include_direct,
                include_builtins,
            };
            let (direct, via) = match core.rbac_reaches(at, &query) {
                Ok(reaches) => (reaches.direct, reaches.escalation),
                Err(e) => {
                    eprintln!("{e}");
                    return CheckResult::Error;
                }
            };

            if direct.is_empty() && via.is_empty() {
                if ndjson {
                    println!(
                        "{}",
                        serde_json::json!({"result":"pass","check":subcommand,"namespace":namespace,"apigroup":apigroup,"resource":resource,"verb":verb})
                    );
                } else {
                    println!(
                        "PASS  effective_can(_, {namespace:?}, {apigroup:?}, {resource:?}, {verb:?})"
                    );
                }
                CheckResult::Pass
            } else {
                if ndjson {
                    let emit_violations = |violations: &[rbac::Violation], kind: &str| {
                        for v in violations {
                            println!(
                                "{}",
                                serde_json::json!({
                                    "result": "fail",
                                    "check": subcommand,
                                    "kind": kind,
                                    "principal": v.principal.name,
                                    "principal_kind": v.principal.kind.as_str(),
                                    "namespace": namespace,
                                    "apigroup": apigroup,
                                    "resource": resource,
                                    "verb": verb,
                                    "paths": paths_json(&v.paths),
                                })
                            );
                        }
                    };
                    emit_violations(&direct, "direct");
                    emit_violations(&via, "escalation");
                } else {
                    let total = direct.len() + via.len();
                    println!(
                        "FAIL  {total} principal(s) can reach ({namespace:?}, {apigroup:?}, {resource:?}, {verb:?}):"
                    );
                    if !direct.is_empty() {
                        println!("  direct ({}):", direct.len());
                        print_reaches_grouped(&direct);
                    }
                    if !via.is_empty() {
                        println!();
                        println!("  via escalation ({}):", via.len());
                        print_reaches_grouped(&via);
                    }
                }
                CheckResult::Fail
            }
        }
        "isolation" => {
            let mut args = rest.split_whitespace();
            let Some(ns_raw) = args.next() else {
                eprintln!("Usage: rbac::isolation <namespace> [allowed_principal ...]");
                eprintln!(
                    "       Checks that only the listed principals have any RBAC access in <namespace>."
                );
                return CheckResult::Error;
            };
            let namespace = ns_raw.trim_matches('"');
            let allowed_owned: Vec<String> = args
                .filter(|s| !matches!(*s, "[]" | "[" | "]"))
                .map(|s| s.trim_matches('"').to_string())
                .collect();
            let allowed: Vec<&str> = allowed_owned.iter().map(String::as_str).collect();

            let violations = match core.rbac_isolation(at, namespace, &allowed) {
                Ok(violations) => violations,
                Err(e) => {
                    eprintln!("{e}");
                    return CheckResult::Error;
                }
            };
            if violations.is_empty() {
                if ndjson {
                    println!(
                        "{}",
                        serde_json::json!({"result":"pass","check":"isolation","namespace":namespace})
                    );
                } else {
                    println!(
                        "PASS  namespace {namespace:?} is isolated to the expected principals"
                    );
                }
                CheckResult::Pass
            } else {
                if ndjson {
                    for v in &violations {
                        println!(
                            "{}",
                            serde_json::json!({"result":"fail","check":"isolation","principal":v.principal.name,"principal_kind":v.principal.kind.as_str(),"namespace":v.namespace,"resource":v.resource,"verb":v.verb})
                        );
                    }
                } else {
                    println!(
                        "FAIL  {} unexpected principal(s) have access in {namespace:?}:",
                        violations.len()
                    );
                    for v in &violations {
                        println!(
                            "        UNEXPECTED can({}, {:?}, {:?}, {:?})",
                            v.principal.quoted(),
                            v.namespace,
                            v.resource,
                            v.verb
                        );
                    }
                }
                CheckResult::Fail
            }
        }
        _ => {
            eprintln!("Unknown rbac command: {subcommand:?}");
            eprintln!("Available: access, reaches, cluster-admin, isolation.");
            CheckResult::Error
        }
    }
}

/// Run a `sched::` scheduling/placement check. Same `Pass`/`Fail`/`Error`
/// contract as [`rbac_command`].
fn sched_command(input: &str, core: &LocalCore, at: &At, format: OutputFormat) -> CheckResult {
    let ndjson = format == OutputFormat::Ndjson;
    let subcommand = input.split_whitespace().next().unwrap_or("").trim();

    match subcommand {
        "node-selector" => {
            let unschedulable = match core.sched_node_selector(at) {
                Ok(unschedulable) => unschedulable,
                Err(e) => {
                    eprintln!("{e}");
                    return CheckResult::Error;
                }
            };
            if unschedulable.is_empty() {
                if ndjson {
                    println!(
                        "{}",
                        serde_json::json!({"result":"pass","check":"node-selector"})
                    );
                } else {
                    println!("PASS  all pods with nodeSelectors are schedulable");
                }
                CheckResult::Pass
            } else {
                if ndjson {
                    for p in &unschedulable {
                        println!(
                            "{}",
                            serde_json::json!({"result":"fail","check":"node-selector","namespace":p.namespace,"pod":p.name})
                        );
                    }
                } else {
                    println!("FAIL  {} unschedulable pod(s):", unschedulable.len());
                    for p in &unschedulable {
                        println!("        {}/{}", p.namespace, p.name);
                    }
                }
                CheckResult::Fail
            }
        }
        "anti-affinity" => {
            use smt::scheduling::PlacementResult;
            let placement = match core.sched_anti_affinity(at) {
                Ok(placement) => placement,
                Err(e) => {
                    eprintln!("{e}");
                    return CheckResult::Error;
                }
            };
            match placement {
                PlacementResult::Sat(assignment) if assignment.is_empty() => {
                    if ndjson {
                        println!(
                            "{}",
                            serde_json::json!({"result":"pass","check":"anti-affinity"})
                        );
                    } else {
                        println!("PASS  no anti-affinity conflicts found");
                    }
                    CheckResult::Pass
                }
                PlacementResult::Sat(mut assignment) => {
                    assignment.sort_by(|a, b| a.0.cmp(&b.0));
                    if ndjson {
                        for (pod, node) in &assignment {
                            println!(
                                "{}",
                                serde_json::json!({"result":"pass","check":"anti-affinity","pod":pod,"node":node})
                            );
                        }
                    } else {
                        println!("PASS  valid placement found ({} pods):", assignment.len());
                        for (pod, node) in &assignment {
                            println!("        {pod} → {node}");
                        }
                    }
                    CheckResult::Pass
                }
                PlacementResult::Unsat => {
                    if ndjson {
                        println!(
                            "{}",
                            serde_json::json!({"result":"fail","check":"anti-affinity"})
                        );
                    } else {
                        println!(
                            "FAIL  no valid placement exists — anti-affinity constraints unsatisfiable"
                        );
                    }
                    CheckResult::Fail
                }
            }
        }
        "karpenter" => {
            let gaps = match core.sched_karpenter_gaps(at, 5) {
                Ok(gaps) => gaps,
                Err(e) => {
                    eprintln!("{e}");
                    return CheckResult::Error;
                }
            };
            if gaps.is_empty() {
                if ndjson {
                    println!(
                        "{}",
                        serde_json::json!({"result":"pass","check":"karpenter"})
                    );
                } else {
                    println!("PASS  full coverage — no nodeSelector gap found (Z3 UNSAT)");
                }
                CheckResult::Pass
            } else {
                if ndjson {
                    for gap in &gaps {
                        let labels: serde_json::Map<String, serde_json::Value> = gap
                            .labels
                            .iter()
                            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                            .collect();
                        println!(
                            "{}",
                            serde_json::json!({"result":"fail","check":"karpenter","labels":labels})
                        );
                    }
                } else {
                    println!(
                        "FAIL  {} coverage gap(s) found - nodeSelectors no NodePool can satisfy:",
                        gaps.len()
                    );
                    for (i, gap) in gaps.iter().enumerate() {
                        let labels: Vec<String> =
                            gap.labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
                        println!("  GAP {}  {}", i + 1, labels.join(", "));
                    }
                }
                CheckResult::Fail
            }
        }
        _ => {
            eprintln!("Unknown sched command: {subcommand:?}");
            eprintln!("Available: node-selector, anti-affinity, karpenter.");
            CheckResult::Error
        }
    }
}

fn dirs_home() -> std::path::PathBuf {
    std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
}

/// Directory for user config, following the XDG Base Directory spec on every
/// platform: `$XDG_CONFIG_HOME` if set, else `$HOME/.config`. (Deliberately not
/// `dirs::config_dir()`, which is `~/Library/Application Support` on macOS.)
fn xdg_config_dir() -> Option<std::path::PathBuf> {
    if let Ok(dir) = std::env::var("XDG_CONFIG_HOME")
        && !dir.is_empty()
    {
        return Some(std::path::PathBuf::from(dir));
    }
    std::env::var("HOME")
        .ok()
        .filter(|h| !h.is_empty())
        .map(|h| std::path::PathBuf::from(h).join(".config"))
}

/// Collect startup (rc) command lines, run through the normal dispatcher before
/// the REPL or `--script`. With `--rcfile <path>`, read only that file (and warn
/// if it is missing). Otherwise read `$XDG_CONFIG_HOME/pallograph/pallographrc`
/// (default `~/.config/pallograph/pallographrc`) then `./.pallographrc`, each
/// optional and appended in that order; a missing default file is skipped
/// silently. `--no-rc` skips everything.
pub fn load_rc(rcfile: Option<&std::path::Path>, no_rc: bool) -> Vec<String> {
    if no_rc {
        return Vec::new();
    }
    let explicit = rcfile.is_some();
    let paths: Vec<std::path::PathBuf> = if let Some(path) = rcfile {
        vec![path.to_path_buf()]
    } else {
        let mut paths = Vec::new();
        if let Some(dir) = xdg_config_dir() {
            paths.push(dir.join("pallograph").join("pallographrc"));
        }
        paths.push(std::path::PathBuf::from(".pallographrc"));
        paths
    };

    let mut lines = Vec::new();
    for path in paths {
        match std::fs::read_to_string(&path) {
            Ok(contents) => lines.extend(contents.lines().map(str::to_string)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !explicit => {}
            Err(e) => eprintln!("warning: could not read rc file {}: {e}", path.display()),
        }
    }
    lines
}

/// Expand a user alias on the command's first token, repeatedly, until the first
/// token is not an alias or a depth limit is hit (guarding against cycles). A
/// `::`-qualified command bypasses aliases entirely.
fn expand_aliases(line: &str, aliases: &BTreeMap<String, String>) -> String {
    let mut line = line.to_string();
    for _ in 0..16 {
        if line.starts_with("::") {
            break;
        }
        let (head, rest) = match line.split_once(char::is_whitespace) {
            Some((h, r)) => (h, r),
            None => (line.as_str(), ""),
        };
        let Some(body) = aliases.get(head) else {
            break;
        };
        line = if rest.is_empty() {
            body.clone()
        } else {
            format!("{body} {rest}")
        };
    }
    line
}

/// Pretty-print a Value: expand structs/lists with indentation.
fn format_pretty(v: &mangle_common::Value) -> String {
    let s = v.to_string();
    pretty_format_atom(&s)
}

fn pretty_format_atom(s: &str) -> String {
    let mut b = String::new();
    let mut depth: usize = 0;
    let indent = |d: usize| "  ".repeat(d);
    let mut chars = s.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                b.push(ch);
                loop {
                    match chars.next() {
                        None => break,
                        Some(c) => {
                            b.push(c);
                            if c == '"' {
                                break;
                            }
                            if c == '\\'
                                && let Some(esc) = chars.next()
                            {
                                b.push(esc);
                            }
                        }
                    }
                }
            }
            '{' | '[' => {
                b.push(ch);
                depth += 1;
                b.push('\n');
                b.push_str(&indent(depth));
            }
            '}' | ']' => {
                depth = depth.saturating_sub(1);
                b.push('\n');
                b.push_str(&indent(depth));
                b.push(ch);
            }
            ',' => {
                b.push(ch);
                if depth > 0 {
                    b.push('\n');
                    b.push_str(&indent(depth));
                    // Skip the space that Display puts after commas.
                    if chars.peek() == Some(&' ') {
                        chars.next();
                    }
                }
            }
            c => b.push(c),
        }
    }
    b
}

fn join_values(tuple: &[Value]) -> String {
    tuple
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Print a fact's provenance as `why` shows it: the fact, then how it was
/// derived, one premise per line, indented by depth.
fn print_provenance(tree: &ProvenanceTree) {
    println!("{}({})", tree.relation, join_values(&tree.row));
    print_derivation(tree, 1);
}

fn print_derivation(tree: &ProvenanceTree, depth: usize) {
    let indent = "  ".repeat(depth);
    match &tree.derivation {
        Derivation::Input => println!("{indent}└─ (EDB fact)"),
        Derivation::NoPremises => println!("{indent}└─ (rule with no positive premises)"),
        Derivation::Unexplained(why) => println!("{indent}└─ ({})", why.reason()),
        Derivation::DepthLimit => println!("{indent}... (depth limit)"),
        Derivation::Cycle => println!(
            "{indent}↻ (cycle: {}({}))",
            tree.relation,
            join_values(&tree.row)
        ),
        Derivation::Rule(application) => {
            for premise in &application.premises {
                println!(
                    "{indent}  {}({})",
                    premise.relation,
                    join_values(&premise.row)
                );
                print_derivation(premise, depth + 1);
            }
            for absent in &application.absent {
                let args: Vec<String> = absent
                    .args
                    .iter()
                    .map(|arg| arg.as_ref().map_or("_".to_string(), Value::to_string))
                    .collect();
                println!(
                    "{indent}  !{}({}) (absent)",
                    absent.relation,
                    args.join(", ")
                );
            }
        }
    }
}

/// [`parse_ground_tuple`], as the [`Fact`] the core takes.
fn parse_fact(input: &str) -> anyhow::Result<Fact> {
    let (relation, row) = parse_ground_tuple(input)?;
    Ok(Fact { relation, row })
}

/// Read one side of an `apply-delta` into its objects. A literal
/// `-` is an intentionally empty side (a brand-new chart has no base; a
/// deleted chart has no head), distinct from a path that matches no files,
/// which still errors like any manifest load.
fn load_delta_side(arg: &str) -> Result<Vec<KubeObject>> {
    if arg == "-" {
        return Ok(Vec::new());
    }
    K8sManifestsSource {
        paths: vec![arg.to_string()],
    }
    .k8s_objects()
}

/// Longest cell, in characters, before it is cut with a trailing `…`.
const TABLE_MAX_WIDTH: usize = 64;

/// Render `rows` as a left-aligned table with a header row and a dashed
/// separator. Cells are clipped to `TABLE_MAX_WIDTH` and newlines are escaped
/// so every row stays on one line.
fn render_table(headers: &[String], rows: &[Vec<String>]) -> String {
    let clip = |s: &str| {
        let s = s.replace('\n', "\\n");
        if s.chars().count() > TABLE_MAX_WIDTH {
            let head: String = s.chars().take(TABLE_MAX_WIDTH - 1).collect();
            format!("{head}…")
        } else {
            s
        }
    };
    let headers: Vec<String> = headers.iter().map(|h| clip(h)).collect();
    let rows: Vec<Vec<String>> = rows
        .iter()
        .map(|r| r.iter().map(|c| clip(c)).collect())
        .collect();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            if i >= widths.len() {
                widths.push(0);
            }
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let line = |cells: &[String]| {
        let parts: Vec<String> = widths
            .iter()
            .enumerate()
            .map(|(i, w)| format!("{:<w$}", cells.get(i).map_or("", String::as_str), w = *w))
            .collect();
        format!("  {}\n", parts.join("  ").trim_end())
    };
    let mut out = line(&headers);
    let rule: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
    out.push_str(&line(&rule));
    for row in &rows {
        out.push_str(&line(row));
    }
    out
}

/// Print a query's rows in the current output format, then a count to
/// stderr. Whole tuples of one relation (`Rows::relation`) print as
/// `Column = value, ...`, or `rel(a, b, ...)` in compact format; variable
/// bindings print as `X = value, ...`.
fn print_rows(format: OutputFormat, rows: &Rows) {
    if rows.rows.is_empty() {
        eprintln!("No results.");
        return;
    }
    match &rows.relation {
        Some(relation) => print_tuples(format, relation, &rows.columns, &rows.rows),
        None => print_query_rows(format, &rows.columns, &rows.rows),
    }
    eprintln!("Found {} result(s).", rows.rows.len());
}

/// Print whole tuples of `rel`, one per line, with `cols` naming each column.
fn print_tuples(format: OutputFormat, rel: &str, cols: &[String], tuples: &[Vec<Value>]) {
    if format == OutputFormat::Table {
        let rows: Vec<Vec<String>> = tuples
            .iter()
            .map(|t| t.iter().map(|v| v.to_string()).collect())
            .collect();
        print!("{}", render_table(cols, &rows));
        return;
    }
    let show = |v: &Value| {
        if format == OutputFormat::Pretty {
            format_pretty(v)
        } else {
            v.to_string()
        }
    };
    for tuple in tuples {
        match format {
            OutputFormat::Ndjson => println!("{}", ndjson_row(tuple, |i| cols.get(i).cloned())),
            OutputFormat::Compact => {
                let args: Vec<String> = tuple.iter().map(show).collect();
                println!("  {rel}({})", args.join(", "));
            }
            // Default and Pretty name each column, like a Prolog answer.
            _ => {
                let parts: Vec<String> = tuple
                    .iter()
                    .zip(cols)
                    .map(|(v, name)| format!("{name} = {}", show(v)))
                    .collect();
                println!("  {}", parts.join(", "));
            }
        }
    }
}

#[cfg(test)]
mod completion_tests {
    use super::*;

    fn words(before: &str, aliases: &[&str], relations: &[&str]) -> Vec<String> {
        let aliases: Vec<String> = aliases.iter().map(|s| s.to_string()).collect();
        let relations: Vec<String> = relations.iter().map(|s| s.to_string()).collect();
        match plan_completion(before, &aliases, &relations) {
            CompletionPlan::Words(_, w) => w,
            other => panic!("expected Words, got {other:?}"),
        }
    }

    #[test]
    fn first_token_completes_commands_and_aliases() {
        let got = words("rb", &[], &[]);
        assert_eq!(
            got,
            [
                "rbac::",
                "rbac::access",
                "rbac::reaches",
                "rbac::cluster-admin",
                "rbac::isolation",
                "rbac::diff"
            ]
        );
        // An alias shares the bare command namespace.
        assert_eq!(words("c", &["ca"], &[]), ["ca"]);
    }

    #[test]
    fn subcommands_complete_within_a_namespace() {
        assert_eq!(
            words("sched::", &[], &[]),
            [
                "sched::node-selector",
                "sched::anti-affinity",
                "sched::karpenter"
            ]
        );
    }

    #[test]
    fn qualified_prefix_is_preserved() {
        // `::` bypasses aliases but still completes the command tree, keeping `::`.
        let got = words("::k8s::m", &["match-everything"], &[]);
        assert_eq!(got, ["::k8s::match", "::k8s::match-all"]);
    }

    #[test]
    fn query_and_show_args_complete_relations() {
        let rels = ["direct_perm", "direct_url_perm", "pod"];
        assert_eq!(
            words("?- direct_", &[], &rels),
            ["direct_perm", "direct_url_perm"]
        );
        assert_eq!(words("show po", &[], &rels), ["pod"]);
    }

    #[test]
    fn fact_mutator_completes_relations_keeping_the_sigil() {
        assert_eq!(words("+po", &[], &["pod", "policy"]), ["+pod", "+policy"]);
    }

    #[test]
    fn file_and_nothing_cases() {
        assert_eq!(
            plan_completion("source ./f", &[], &[]),
            CompletionPlan::Files
        );
        assert_eq!(
            plan_completion("k8s::load ./f", &[], &[]),
            CompletionPlan::Files
        );
        // `load <rel> <src>`: first arg is not a file, second is.
        assert_eq!(
            plan_completion("load rel ", &[], &[]),
            CompletionPlan::Files
        );
        assert_eq!(
            plan_completion("load re", &[], &[]),
            CompletionPlan::Nothing
        );
        // A command that takes no completable args.
        assert_eq!(
            plan_completion("snapshot foo", &[], &["pod".to_string()]),
            CompletionPlan::Nothing
        );
    }
}

#[cfg(test)]
mod query_helper_tests {
    use super::*;
    use crate::query::{body_relations, single_atom, split_top_level_args, suggest};

    #[test]
    fn finds_relations_in_bodies() {
        assert_eq!(body_relations("direct_perms"), ["direct_perms"]);
        assert_eq!(body_relations("direct_perms()"), ["direct_perms"]);
        assert_eq!(
            body_relations(
                r#"pkg.hop(R, P, I, Id, M), :string:contains(M, "x(y"), !foo(X), fn:plus(1, 2) = Z"#
            ),
            ["pkg.hop", "foo"]
        );
        assert!(body_relations("X").is_empty());
    }

    #[test]
    fn suggests_near_names_only() {
        let known: std::collections::HashSet<String> =
            ["direct_perm", "indirect_perm", "pod", "_0"]
                .iter()
                .map(|s| s.to_string())
                .collect();
        assert_eq!(
            suggest("direct_perms", &known),
            ["direct_perm", "indirect_perm"]
        );
        assert!(suggest("zzzzzzzz", &known).is_empty());
    }

    #[test]
    fn splits_args_outside_strings_and_brackets() {
        assert_eq!(
            split_top_level_args(r#"_, "a, b", [1, 2], f(x, y)"#).len(),
            4
        );
        assert!(split_top_level_args("  ").is_empty());
    }

    #[test]
    fn table_aligns_clips_and_escapes() {
        let w = TABLE_MAX_WIDTH;
        let headers = vec!["Name".to_string(), "Verb".to_string()];
        let rows = vec![
            vec!["\"a\"".to_string(), "get".to_string()],
            vec!["x".repeat(w + 8), "line\nbreak".to_string()],
        ];
        let out = render_table(&headers, &rows);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], format!("  Name{}  Verb", " ".repeat(w - 4)));
        assert_eq!(lines[1], format!("  {}  {}", "-".repeat(w), "-".repeat(11)));
        assert_eq!(lines[2], format!("  \"a\"{}  get", " ".repeat(w - 3)));
        assert_eq!(lines[3], format!("  {}…  line\\nbreak", "x".repeat(w - 1)));
        assert_eq!(lines.len(), 4);
    }

    #[test]
    fn prompt_names_snapshot_in_use() {
        assert_eq!(prompt(None), "\x1b[1;31mpallograph>\x1b[0m ");
        assert_eq!(
            prompt(Some("before")),
            "\x1b[1;31mpallograph (before)>\x1b[0m "
        );
    }

    /// The watcher's line names only what changed, and nothing at all when
    /// nothing did. A retract of an object already gone changed nothing.
    #[test]
    fn live_changes_line_names_what_changed() {
        assert_eq!(live_changes_line(ApplySummary::default()), None);
        let summary = ApplySummary {
            updated: 2,
            retracted: 1,
            removed_absent: 4,
            ..Default::default()
        };
        assert_eq!(
            live_changes_line(summary).as_deref(),
            Some("live: 2 updated, 1 removed")
        );
    }

    #[test]
    fn single_atom_detection() {
        assert_eq!(single_atom("direct_perm"), Some("direct_perm"));
        assert_eq!(single_atom("direct_perm()"), Some("direct_perm"));
        assert_eq!(single_atom(r#"pkg.hop(_, _, "x")"#), Some("pkg.hop"));
        assert_eq!(single_atom("a(X), b(Y)"), None);
        assert_eq!(single_atom("!a(X)"), None);
        assert_eq!(single_atom(r#":string:contains("a", "b")"#), None);
        assert_eq!(single_atom("X"), None);
    }
}

#[cfg(test)]
mod binding_format_tests {
    use super::fmt_binding;
    use crate::rbac::AccessPath;

    fn path(binding_kind: &'static str, ns: &str, role_kind: &'static str) -> AccessPath {
        AccessPath {
            binding_kind,
            binding_namespace: ns.into(),
            binding_name: "b".into(),
            role_kind,
            role_name: "r".into(),
            hops: vec![],
        }
    }

    #[test]
    fn cluster_scoped_binding_has_no_leading_slash() {
        let p = path("ClusterRoleBinding", "", "ClusterRole");
        assert_eq!(fmt_binding(&p), "ClusterRoleBinding b → ClusterRole r");
    }

    #[test]
    fn namespaced_binding_is_prefixed_with_its_namespace() {
        let p = path("RoleBinding", "kube-system", "Role");
        assert_eq!(fmt_binding(&p), "RoleBinding kube-system/b → Role r");
    }
}

#[cfg(test)]
mod format_tests {
    use super::ndjson_row;
    use mangle_common::Value;

    #[test]
    fn ndjson_row_uses_provided_keys() {
        let tuple = vec![Value::String("alice".into()), Value::Name("/devs".into())];
        let keys = ["Username", "Group"];
        let line = ndjson_row(&tuple, |i| keys.get(i).map(|s| s.to_string()));
        assert_eq!(line, r#"{"Username":"alice","Group":"/devs"}"#);
    }

    #[test]
    fn ndjson_row_falls_back_to_positional_keys() {
        let tuple = vec![Value::Number(1), Value::Number(2)];
        // No keys supplied: positional c0, c1, ...
        let line = ndjson_row(&tuple, |_| None);
        assert_eq!(line, r#"{"c0":1,"c1":2}"#);
    }

    #[test]
    fn ndjson_row_is_single_line() {
        let tuple = vec![Value::String("a".into()), Value::String("b".into())];
        let line = ndjson_row(&tuple, |_| None);
        assert!(!line.contains('\n'));
    }
}

#[cfg(test)]
mod delta_side_tests {
    use super::load_delta_side;

    /// `-` is an intentionally empty side; a real path with no files still
    /// errors, like any manifest load.
    #[test]
    fn empty_side_dash_loads_nothing_but_missing_path_errors() {
        assert!(load_delta_side("-").unwrap().is_empty());
        assert!(load_delta_side("/pallograph/no/such/dir").is_err());
    }
}
