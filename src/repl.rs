// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::IsTerminal;
use std::sync::{Mutex, MutexGuard};

use anyhow::{Context as _, Result};
use mangle_common::Value;
use mangle_interpreter::ProvenanceEntry;
use rustyline::completion::{Completer, FilenameCompleter, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Helper};

use crate::dd::session::LazyProvenance;
use crate::edb::{K8sManifestsSource, ObjectFacts, ObjectKey, ShellSource};
use crate::engine::{ApplySummary, Change, Engine, EvalStore, RelationDoc};
use crate::load;
use crate::query;
use crate::rbac;
use crate::smt;
use crate::snapshot::{Diff, FrozenState};
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

/// Print a psql `\d`-style detail block for one relation: its description and a
/// per-column listing of name, type, and description. Falls back to a bare
/// arity line when the relation has no `Decl` (e.g. derived predicates).
fn print_relation_detail(name: &str, store: &EvalStore, doc: Option<&RelationDoc>) {
    let arity = arity_display(store.scan(name).first().map(|t| t.len()), doc);
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

/// The declared column names for a relation, in order, for use as NDJSON keys.
/// Empty when the relation has no `Decl` (callers fall back to positional keys).
fn column_keys(engine: &Engine, relation: &str) -> Vec<String> {
    engine
        .relation_docs()
        .ok()
        .and_then(|docs| {
            docs.get(relation)
                .map(|d| d.columns.iter().map(|c| c.name.clone()).collect())
        })
        .unwrap_or_default()
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

/// Run a real kubectl-style label selector through the `labels.mg` engine and
/// print the objects it matches. The selector is parsed into kube `Expression`s,
/// asserted as synthetic `selector_*` facts under a query owner, evaluated, then
/// retracted so the engine's EDB is left untouched (the same assert→query→retract
/// path the `+`/`?-`/`-` commands expose). `kind = Some(k)` scopes to one Kind
/// (`k8s::match`); `None` matches any Kind (`k8s::match-all`). `namespace` scopes the
/// owner; "" targets cluster-scoped objects. Returns `false` if the selector
/// did not parse or evaluation failed.
fn run_match(
    engine: &mut Engine,
    kind: Option<&str>,
    namespace: &str,
    selector_str: &str,
    format: OutputFormat,
) -> bool {
    let exprs = match crate::selector::parse_selector(selector_str) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Selector parse error: {e:#}");
            return false;
        }
    };

    // Allow the cluster-scoped namespace to be typed as "" (and "demo" as a
    // convenience); the REPL does not otherwise strip argument quotes.
    let namespace = namespace.trim_matches('"');

    let owner = vec![
        Value::String("pallograph.dev/query".to_string()),
        Value::String("Match".to_string()),
        Value::String(namespace.to_string()),
        Value::String("query".to_string()),
    ];

    // Build the synthetic selector facts and assert them on the engine.
    let mut facts: Vec<(String, Vec<Value>)> = Vec::new();
    for expr in &exprs {
        for (rel, args) in crate::edb::expression_facts(&owner, expr) {
            facts.push((rel.to_string(), args));
        }
    }
    engine.add_facts(facts.iter().cloned());

    // Evaluate, then immediately retract the synthetic facts so the EDB is left
    // exactly as it was (we never touch `current_store`).
    let result = engine.evaluate();
    for (rel, args) in &facts {
        engine.retract_fact(rel, args);
    }
    let store = match result {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: {e:#}");
            return false;
        }
    };

    // selector_matches columns: 0 SelApiVersion, 1 SelKind, 2 SelNamespace,
    // 3 SelName, 4 ObjApiVersion, 5 ObjKind, 6 ObjNamespace, 7 ObjName.
    //
    // Scope results to the requested namespace (ObjNamespace == namespace) so the
    // command behaves like `kubectl -n <ns>`. Without this, labels.mg's Case 2
    // (cluster-scoped pairing) would surface unrelated cluster-scoped objects for
    // a namespaced query — visible with negative selectors, which match by
    // absence. A namespace of "" therefore targets cluster-scoped objects only.
    let ns_val = Value::String(namespace.to_string());
    let mut matched: Vec<&Vec<Value>> = store
        .scan("selector_matches")
        .iter()
        .filter(|row| row.len() == 8 && row[0..4] == owner[..])
        .filter(|row| row[6] == ns_val)
        .filter(|row| kind.is_none_or(|k| row[5] == Value::String(k.to_string())))
        .collect();
    matched.sort();

    if matched.is_empty() {
        eprintln!("No matches.");
        return true;
    }
    for row in &matched {
        let obj = &row[4..8]; // ApiVersion, Kind, Namespace, Name
        if format == OutputFormat::Ndjson {
            let cols = ["apiVersion", "kind", "namespace", "name"];
            println!(
                "{}",
                ndjson_row(obj, |i| cols.get(i).map(|s| s.to_string()))
            );
        } else {
            let parts: Vec<String> = obj
                .iter()
                .map(|v| {
                    if format == OutputFormat::Pretty {
                        format_pretty(v)
                    } else {
                        v.to_string()
                    }
                })
                .collect();
            println!("  {}", parts.join("/"));
        }
    }
    eprintln!("Found {} match(es).", matched.len());
    true
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

/// Relation names a `?-` query may reference under `use <name>`: every
/// relation the frozen store actually holds rows or keys for, plus any
/// relation with a `Decl` (covers one with no rows at snapshot time). Unlike
/// `Engine::known_relations`, this leaves out a relation `define` added
/// after the snapshot was taken: it did not exist in the frozen state, so a
/// query against it is unknown, not merely empty.
fn known_relations_in_use(
    engine: &Engine,
    active: &EvalStore,
) -> std::collections::HashSet<String> {
    let mut known: std::collections::HashSet<String> = engine
        .relation_docs()
        .map(|docs| docs.into_keys().collect())
        .unwrap_or_default();
    known.extend(active.relation_names().map(str::to_string));
    known
}

/// Return `true` and refuse a state-changing command (`+`, `-`, `~`,
/// `define`, `load`, `k8s::load`, `apply-delta`, `source`,
/// `snapshot`, `rollback`) while a snapshot is in use: a frozen state never changes, so there is
/// nothing for the command to act on. `k8s::match` and `k8s::match-all` are refused
/// for the same reason even though they leave the EDB untouched: they
/// re-evaluate the live engine, which a frozen snapshot has none of. A
/// refusal marks the line as failed.
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
    engine: &Mutex<Engine>,
    store: EvalStore,
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
    session(
        engine,
        store,
        format,
        rc,
        watch,
        Input::Editor { rl, history_path },
    )
}

/// Run the commands in `path` (`-` for stdin), one per line, through the
/// same dispatcher as the REPL. Stops with `Error` at the first line that is
/// not a command or whose command fails; otherwise like [`run`].
pub fn run_script(
    engine: &Mutex<Engine>,
    store: EvalStore,
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
    session(engine, store, format, rc, watch, Input::Script(reader))
}

/// Lock the shared engine, treating a poisoned lock (a panic while it was
/// held) as fatal.
fn lock_engine(engine: &Mutex<Engine>) -> MutexGuard<'_, Engine> {
    engine.lock().expect("engine lock poisoned")
}

fn session(
    engine: &Mutex<Engine>,
    store: EvalStore,
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

    let mut current_store = store;
    // The engine version `current_store` was evaluated at. Anything that
    // moves the engine on (a `+`, `-` or `~`, which skip re-evaluating with a
    // live session so a run of them stays fast, or another thread feeding the
    // engine) leaves it behind, and the next other command refreshes
    // `current_store` once.
    let mut store_version = lock_engine(engine).version();
    let mut format = format;
    let mut had_failure = false;
    let mut snapshots: BTreeMap<String, FrozenState> = BTreeMap::new();
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
            // Refresh tab-completion data from the current state before prompting.
            let active = active_store(&current_store, &snapshots, &in_use);
            let relations: Vec<String> = active
                .relation_names()
                .filter(|n| !n.starts_with(':') && !n.starts_with('_'))
                .map(str::to_string)
                .collect();
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

                // Hold the engine for the whole command, so nothing else
                // changes it partway through.
                let mut engine_guard = lock_engine(engine);
                let engine = &mut *engine_guard;
                if let Some(line) = watch.and_then(|w| live_changes_line(w.take())) {
                    eprintln!("{line}");
                }
                let is_mutator = line.starts_with(['+', '-', '~']);
                if engine.version() != store_version && !is_mutator {
                    match engine.evaluate() {
                        Ok(new_store) => {
                            current_store = new_store;
                            store_version = engine.version();
                        }
                        Err(e) => command_error!("Error: {e:#}"),
                    }
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
                    let docs = engine.relation_docs().unwrap_or_default();
                    let active = active_store(&current_store, &snapshots, &in_use);
                    if names.is_empty() {
                        // List view. By default only documented relations are shown;
                        // undocumented intermediates are hidden unless --all is given.
                        let mut names: Vec<&str> = active
                            .relation_names()
                            .filter(|n| !n.starts_with(':'))
                            .collect();
                        names.sort_unstable();
                        let mut hidden = 0;
                        for n in names {
                            let documented = docs
                                .get(n)
                                .map(|d| d.description.is_some())
                                .unwrap_or(false);
                            if !documented && !show_all {
                                hidden += 1;
                                continue;
                            }
                            let desc = docs
                                .get(n)
                                .and_then(|d| d.description.as_deref())
                                .map(|d| format!("  — {d}"))
                                .unwrap_or_default();
                            let arity =
                                arity_display(active.scan(n).first().map(|t| t.len()), docs.get(n));
                            println!("  {n}/{arity}{desc}");
                        }
                        if hidden > 0 {
                            println!(
                                "  ({hidden} undocumented relation(s) hidden; show --all to include)"
                            );
                        }
                    } else {
                        // Detail view: a psql \d-style block per requested relation.
                        for n in names {
                            print_relation_detail(n, active, docs.get(n));
                        }
                    }
                    continue;
                }
                if let Some(raw) = line.strip_prefix("::explain ") {
                    let raw = raw.trim();
                    // Same body grammar as `?-`, projection included: an
                    // anonymous head `_(R) :- ...` just sets the query rule's
                    // head columns. This only compiles and plans, never runs.
                    let (projection, body) = split_projection(raw);
                    let vars = projection.unwrap_or_else(|| extract_vars(body));
                    if vars.is_empty() {
                        command_error!("No variables to bind. Name one (e.g. X).");
                        continue;
                    }
                    let rule = format!("__query({}) :- {body}.", vars.join(", "));
                    // The active store backs the cost estimate's row counts.
                    let active = active_store(&current_store, &snapshots, &in_use);
                    if let Err(e) = engine.explain_query(&rule, active) {
                        command_error!("Error: {e:#}");
                    }
                    continue;
                }
                if let Some(raw_body) = line
                    .strip_prefix("::query ")
                    .or_else(|| line.strip_prefix("?- "))
                {
                    let raw_body = raw_body.trim();
                    // Optional projection via an anonymous head: `_(R, N) :-
                    // atom, atom` reports only the head variables; the rest act
                    // as join keys. Without a head, every named variable in the
                    // body is reported (the original behaviour).
                    let (projection, raw_body) = split_projection(raw_body);
                    let active = active_store(&current_store, &snapshots, &in_use);
                    // A typo'd relation is an empty result on the interpreter and
                    // an opaque error on DD; catch it up front either way.
                    let known = if in_use.is_some() {
                        known_relations_in_use(engine, active)
                    } else {
                        let mut known = engine.known_relations();
                        known.extend(current_store.relation_names().map(str::to_string));
                        known
                    };
                    let unknown: Vec<String> = body_relations(raw_body)
                        .into_iter()
                        .filter(|r| !known.contains(r))
                        .collect();
                    if !unknown.is_empty() {
                        for r in &unknown {
                            match suggest(r, &known) {
                                s if s.is_empty() => command_error!("Unknown relation '{r}'."),
                                s => command_error!(
                                    "Unknown relation '{r}'. Did you mean: {}?",
                                    s.join(", ")
                                ),
                            }
                        }
                        continue;
                    }
                    let existing = extract_vars(raw_body);
                    let single = single_atom(raw_body);
                    let cols = single.map(|r| column_keys(engine, r)).unwrap_or_default();
                    if let Some(rel) = single {
                        let given = split_atom(raw_body)
                            .map_or(0, |(_, inner)| count_top_level_args(inner));
                        if let Some(arity) = relation_arity(active, rel, &cols)
                            && given > arity
                        {
                            command_error!("{rel} has {arity} columns, got {given} arguments.");
                            continue;
                        }
                        // No named variables: list whole tuples, not bindings.
                        if existing.is_empty() {
                            if !list_tuples(
                                engine,
                                active,
                                format,
                                rel,
                                raw_body,
                                &cols,
                                in_use.is_none(),
                            ) {
                                command_failed = true;
                            }
                            continue;
                        }
                    } else if existing.is_empty() {
                        command_error!("No variables to bind. Name one (e.g. X).");
                        continue;
                    }
                    let (body, mut vars) = match auto_complete_partial(raw_body, active, &cols) {
                        Some((new_body, added)) => {
                            let mut all = existing;
                            all.extend(added);
                            (new_body, all)
                        }
                        None => (raw_body.to_string(), existing),
                    };
                    let body = body.as_str();

                    // A projection list narrows the reported columns to the
                    // named variables; each must be bound somewhere in the body.
                    if let Some(proj) = projection {
                        let unbound: Vec<&str> = proj
                            .iter()
                            .filter(|p| !vars.contains(p))
                            .map(String::as_str)
                            .collect();
                        if !unbound.is_empty() {
                            command_error!(
                                "Projection variable(s) not bound by the body: {}.",
                                unbound.join(", ")
                            );
                            continue;
                        }
                        vars = proj;
                    }

                    // A query is a read: evaluate just the query rule over
                    // the active state's facts (live or a `use`d snapshot)
                    // and keep nothing. The engine's rules and facts are
                    // left alone, so name a result with `define` to reuse it.
                    let relations = body_relations(raw_body);
                    let result_name = "__query";
                    let rule = format!("{result_name}({}) :- {body}.", vars.join(", "));
                    match engine.evaluate_query_on(active, &relations, rule) {
                        Ok(result_store) => {
                            let tuples = result_store.scan(result_name);
                            if tuples.is_empty() {
                                eprintln!("No results.");
                            } else {
                                print_query_rows(format, &vars, tuples);
                                eprintln!("Found {} result(s).", tuples.len());
                            }
                        }
                        Err(e) => command_error!("Error: {e:#}"),
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
                    if !snapshots.contains_key(&name) {
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

                if let Some(rest) = line.strip_prefix("::why ") {
                    if !engine.supports_provenance() {
                        command_error!(
                            "why needs provenance, which is off for this session. \
                             Re-run with `--backend dd --provenance`, or use \
                             `--backend interpreter`."
                        );
                        continue;
                    }
                    let rest = rest.trim();
                    let active = active_store(&current_store, &snapshots, &in_use);
                    match query::parse_query(rest) {
                        Ok(q) => {
                            // A live session is the source of truth: mutators
                            // don't refresh `current_store` while one exists.
                            // Under `use`, the frozen store is always read
                            // directly: it has no live session of its own.
                            let live: Vec<Vec<Value>>;
                            let rows: &[Vec<Value>] = if in_use.is_none() && engine.has_session() {
                                live = match engine.query_live(&q.predicate) {
                                    Ok(rows) => rows,
                                    Err(e) => {
                                        command_error!("Error: {e:#}");
                                        continue;
                                    }
                                };
                                &live
                            } else {
                                active.scan(&q.predicate)
                            };
                            let matched = query::filter_tuples(rows, &q);
                            if matched.is_empty() {
                                eprintln!("No matching facts for '{rest}'.");
                            } else if engine.has_session() {
                                // DD backend: lazy provenance, one shortest proof
                                // reconstructed on demand from the live session,
                                // or from the copy `snapshot` froze under `use`.
                                let provenance: Option<&dyn LazyProvenance> = match &in_use {
                                    Some(name) => snapshots
                                        .get(name)
                                        .and_then(|s| s.lazy_provenance.as_ref())
                                        .map(|p| p as &dyn LazyProvenance),
                                    None => engine
                                        .provenance_session()
                                        .map(|s| s as &dyn LazyProvenance),
                                };
                                for tuple in matched {
                                    println!("{}({})", q.predicate, join_values(tuple));
                                    let Some(provenance) = provenance else {
                                        if in_use.is_some() {
                                            println!(
                                                "  └─ (no provenance captured for this snapshot)"
                                            );
                                        } else {
                                            println!("  └─ (no provenance for this session)");
                                        }
                                        continue;
                                    };
                                    if !provenance.has_provenance_for(&q.predicate) {
                                        println!(
                                            "  └─ (no provenance: `?-` query results are not tracked)"
                                        );
                                        continue;
                                    }
                                    let row = crate::dd::value::Row::from(tuple.as_slice());
                                    let annotation = provenance.why_height(&q.predicate, &row);
                                    print_why_lazy(provenance, &row, annotation, 1);
                                }
                            } else {
                                // Interpreter: the active store (frozen under
                                // `use`) carries its own provenance.
                                let index = build_provenance_index(&active.provenance);
                                for tuple in matched {
                                    println!("{}({})", q.predicate, join_values(tuple));
                                    print_why(&index, &q.predicate, tuple, 1, &mut Vec::new());
                                }
                            }
                        }
                        Err(e) => command_error!("Parse error: {e}"),
                    }
                    continue;
                }

                if let Some(rest) = line.strip_prefix("::smtlib ") {
                    let relations: Vec<&str> = rest.split_whitespace().collect();
                    if relations.is_empty() {
                        command_error!("Usage: smtlib <relation> [relation ...]");
                    } else {
                        let active = active_store(&current_store, &snapshots, &in_use);
                        let cfg = z3::Config::new();
                        let ctx = z3::Context::new(&cfg);
                        let mut enc = smt::SmtEncoder::new(&ctx);
                        enc.load(active, &relations);
                        println!("{}", enc.to_smtlib());
                    }
                    continue;
                }

                if let Some(name) = line.strip_prefix("::snapshot ") {
                    if refuse_if_in_use(&in_use, &mut command_failed) {
                        continue;
                    }
                    let name = name.trim().to_string();
                    if name.is_empty() || name.contains(char::is_whitespace) {
                        command_error!("Snapshot names cannot be empty or contain spaces.");
                        continue;
                    }
                    if snapshots.contains_key(&name) {
                        command_error!("Snapshot '{name}' already exists.");
                        continue;
                    }
                    let lazy_provenance = match engine
                        .provenance_session()
                        .map(|s| s.freeze_provenance())
                        .transpose()
                    {
                        Ok(p) => p,
                        Err(e) => {
                            command_error!("Error: {e:#}");
                            continue;
                        }
                    };
                    let frozen_store = current_store.frozen_copy();
                    let rc = frozen_store
                        .relation_names()
                        .filter(|r| !frozen_store.scan(r).is_empty())
                        .count();
                    let fc: usize = frozen_store
                        .relation_names()
                        .map(|r| frozen_store.scan(r).len())
                        .sum();
                    println!("Saved snapshot '{name}' ({rc} relations, {fc} facts).");
                    snapshots.insert(
                        name,
                        FrozenState {
                            store: frozen_store,
                            lazy_provenance,
                            inputs: engine.save_inputs(),
                        },
                    );
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
                    let Some(frozen) = snapshots.get(name) else {
                        command_error!("No snapshot named '{name}'.");
                        continue;
                    };
                    if let Err(e) = engine.restore_inputs(&frozen.inputs) {
                        command_error!("Error: {e:#}");
                        continue;
                    }
                    match engine.evaluate() {
                        Ok(new_store) => {
                            current_store = new_store;
                            store_version = engine.version();
                            println!("Rolled back to snapshot '{name}'.");
                        }
                        Err(e) => command_error!("Error: {e:#}"),
                    }
                    continue;
                }

                if let Some(rest) = line.strip_prefix("::diff ") {
                    let parts: Vec<&str> = rest.trim().splitn(2, ' ').collect();
                    let lookup = |n: &str| -> Option<&FrozenState> { snapshots.get(n) };
                    let (before, after_snap) = match parts.as_slice() {
                        [name] => match lookup(name) {
                            Some(s) => (s, None),
                            None => {
                                command_error!("No snapshot named '{}'.", name);
                                continue;
                            }
                        },
                        [name1, name2] => {
                            let s1 = match lookup(name1) {
                                Some(s) => s,
                                None => {
                                    command_error!("No snapshot named '{}'.", name1);
                                    continue;
                                }
                            };
                            let s2 = match lookup(name2) {
                                Some(s) => s,
                                None => {
                                    command_error!("No snapshot named '{}'.", name2);
                                    continue;
                                }
                            };
                            (s1, Some(s2))
                        }
                        _ => {
                            command_error!("Usage: diff <name>  or  diff <name1> <name2>");
                            continue;
                        }
                    };
                    let after: &EvalStore = match after_snap {
                        Some(s) => &s.store,
                        None => active_store(&current_store, &snapshots, &in_use),
                    };
                    let diff = Diff::between(&before.store, after);
                    print!("{diff}");
                    continue;
                }

                if line == "::rbac::diff" {
                    command_error!("Usage: rbac::diff <snap>  or  rbac::diff <snap1> <snap2>");
                    continue;
                }
                if let Some(rest) = line.strip_prefix("::rbac::diff ") {
                    let parts: Vec<&str> = rest.trim().splitn(2, ' ').collect();
                    let lookup = |n: &str| -> Option<&FrozenState> { snapshots.get(n) };
                    let tables_of = |store: &EvalStore| {
                        rbac::PermissionTables::from_scan(&|rel| store.scan(rel).to_vec())
                    };

                    match parts.as_slice() {
                        [name] => {
                            let Some(before_snap) = lookup(name) else {
                                command_error!("No snapshot named '{}'.", name);
                                continue;
                            };
                            // The implicit "current" side is whatever is in
                            // use; the header names it instead of "current".
                            let after = active_store(&current_store, &snapshots, &in_use);
                            let after_label = in_use.as_deref().unwrap_or("current");
                            let before_tables = tables_of(&before_snap.store);
                            let after_tables = tables_of(after);
                            if !print_access_diff(&before_tables, &after_tables, name, after_label)
                            {
                                had_failure = true;
                            }
                        }
                        [name1, name2] => {
                            let Some(s1) = lookup(name1) else {
                                command_error!("No snapshot named '{}'.", name1);
                                continue;
                            };
                            let Some(s2) = lookup(name2) else {
                                command_error!("No snapshot named '{}'.", name2);
                                continue;
                            };
                            let t1 = tables_of(&s1.store);
                            let t2 = tables_of(&s2.store);
                            if !print_access_diff(&t1, &t2, name1, name2) {
                                had_failure = true;
                            }
                        }
                        _ => command_error!(
                            "Usage: rbac::diff <snap>  or  rbac::diff <snap1> <snap2>"
                        ),
                    }
                    continue;
                }

                if let Some(rest) = line.strip_prefix("::diff-relation ") {
                    // Like ::diff, but scoped to one relation: the trailing
                    // token names the relation, the 1 or 2 before it name the
                    // snapshot operands. Purely diagnostic, same pure-diff
                    // output as ::diff (no verdict, no findings).
                    let parts: Vec<&str> = rest.split_whitespace().collect();
                    let (before_name, after_name, relation) = match parts.as_slice() {
                        [name, relation] => (*name, None, *relation),
                        [name1, name2, relation] => (*name1, Some(*name2), *relation),
                        _ => {
                            command_error!(
                                "Usage: diff-relation <name> <relation>  or  diff-relation <name1> <name2> <relation>"
                            );
                            continue;
                        }
                    };
                    let Some(before) = snapshots.get(before_name) else {
                        command_error!("No snapshot named '{}'.", before_name);
                        continue;
                    };
                    let after: &EvalStore = if let Some(after_name) = after_name {
                        match snapshots.get(after_name) {
                            Some(s) => &s.store,
                            None => {
                                command_error!("No snapshot named '{}'.", after_name);
                                continue;
                            }
                        }
                    } else {
                        active_store(&current_store, &snapshots, &in_use)
                    };
                    // A relation the program never declares or derives would
                    // diff as empty, which is misleading; flag the typo.
                    if !engine.known_relations().contains(relation) {
                        command_error!("Unknown relation '{}'.", relation);
                        continue;
                    }
                    let full = Diff::between(&before.store, after);
                    let mut one = Diff {
                        added: BTreeMap::new(),
                        removed: BTreeMap::new(),
                    };
                    if let Some(a) = full.added.get(relation) {
                        one.added.insert(relation.to_string(), a.clone());
                    }
                    if let Some(r) = full.removed.get(relation) {
                        one.removed.insert(relation.to_string(), r.clone());
                    }
                    print!("{one}");
                    continue;
                }

                if let Some(rule) = line.strip_prefix("::define ") {
                    if refuse_if_in_use(&in_use, &mut command_failed) {
                        continue;
                    }
                    let checkpoint = engine.rules_len();
                    if let Err(e) =
                        engine.add_rule(format!("{}.", rule.trim_end_matches('.').trim()))
                    {
                        engine.truncate_rules(checkpoint);
                        command_error!("Error: {e:#}");
                        continue;
                    }
                    match engine.evaluate() {
                        Ok(new_store) => {
                            current_store = new_store;
                            store_version = engine.version();
                            eprintln!("Rule added and evaluated.");
                        }
                        Err(e) => {
                            engine.truncate_rules(checkpoint);
                            command_error!("Error: {e:#}");
                        }
                    }
                    continue;
                }

                if let Some(rest) = line.strip_prefix("::source ") {
                    if refuse_if_in_use(&in_use, &mut command_failed) {
                        continue;
                    }
                    let src = rest.trim();
                    match load::read_source(src) {
                        Ok(bytes) => match std::str::from_utf8(&bytes) {
                            Ok(text) => match source_program(engine, text) {
                                Ok(new_store) => {
                                    current_store = new_store;
                                    store_version = engine.version();
                                    eprintln!("Sourced and evaluated.");
                                }
                                Err(e) => command_error!("Error: {e:#}"),
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
                    let source_result: anyhow::Result<Box<dyn crate::edb::FactSource>> =
                        if let Some(command) = rest.strip_prefix('!') {
                            let command = command.trim().to_string();
                            Ok(Box::new(ShellSource { command }))
                        } else {
                            Ok(Box::new(K8sManifestsSource {
                                paths: vec![rest.to_string()],
                            }))
                        };
                    match source_result.and_then(|mut src| engine.populate_from(src.as_mut())) {
                        Ok(summary) => match engine.evaluate() {
                            Ok(new_store) => {
                                current_store = new_store;
                                store_version = engine.version();
                                eprintln!(
                                    "Loaded {} object(s) ({} replaced) and evaluated.",
                                    summary.added + summary.updated,
                                    summary.updated
                                );
                            }
                            Err(e) => command_error!("Error: {e:#}"),
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
                    // Load both rendered sides into key-indexed maps. This
                    // is transient per-command state, not a Rust-side view of
                    // the live EDB: the delta is applied straight back.
                    let sides = load_delta_side(base_arg).and_then(|base| {
                        let head = load_delta_side(head_arg)?;
                        Ok((base, head))
                    });
                    let (base, head) = match sides {
                        Ok(sides) => sides,
                        Err(e) => {
                            command_error!("Delta error: {e:#}");
                            continue;
                        }
                    };
                    let (changes, added, updated, unchanged) = diff_object_sides(base, head);
                    let removed = changes
                        .iter()
                        .filter(|c| matches!(c, Change::Retract(_)))
                        .count();
                    let summary = engine.apply_changes(changes);
                    match engine.evaluate() {
                        Ok(new_store) => {
                            current_store = new_store;
                            store_version = engine.version();
                            eprintln!(
                                "Applied delta: +{added} ~{updated} -{removed} \
                                 ({unchanged} unchanged, {} removed but not live) and evaluated.",
                                summary.removed_absent
                            );
                        }
                        Err(e) => command_error!("Error: {e:#}"),
                    }
                    continue;
                }

                if let Some(rest) = line.strip_prefix("::load ") {
                    if refuse_if_in_use(&in_use, &mut command_failed) {
                        continue;
                    }
                    let rest = rest.trim();
                    // Split on first whitespace: <relation> <source>
                    let (relation, source) = match rest.find(|c: char| c.is_whitespace()) {
                        Some(idx) => (&rest[..idx], rest[idx + 1..].trim()),
                        None => {
                            command_error!(
                                "Usage: load <relation> <source>  (source is a file path or ! <cmd>)"
                            );
                            continue;
                        }
                    };
                    match load::load_tuples(engine, relation, source) {
                        Ok(n) => match engine.evaluate() {
                            Ok(new_store) => {
                                current_store = new_store;
                                store_version = engine.version();
                                eprintln!("Inserted {n} fact(s) into {relation} and evaluated.");
                            }
                            Err(e) => command_error!("Error: {e:#}"),
                        },
                        Err(e) => command_error!("Load error: {e:#}"),
                    }
                    continue;
                }

                // ~pred(old...). pred(new...).  — atomic replace (retract + insert, one eval)
                if let Some(rest) = line.strip_prefix('~') {
                    if refuse_if_in_use(&in_use, &mut command_failed) {
                        continue;
                    }
                    let rest = rest.trim();
                    // Split into two atoms at the boundary between "). " and the next predicate.
                    match split_two_atoms(rest) {
                        Some((old_atom, new_atom)) => {
                            let result = parse_ground_tuple(old_atom).and_then(|(rel, tuple)| {
                                parse_ground_tuple(new_atom).map(|n| ((rel, tuple), n))
                            });
                            match result {
                                Ok(((old_rel, old_tuple), (new_rel, new_tuple))) => {
                                    if let Some(arity) = engine.relation_arity(&new_rel)
                                        && new_tuple.len() != arity
                                    {
                                        command_error!(
                                            "arity mismatch: {new_rel}/{arity} expects {arity} arg(s), got {}",
                                            new_tuple.len()
                                        );
                                        continue;
                                    }
                                    let removed = engine.retract_fact(&old_rel, &old_tuple);
                                    engine.add_fact(new_rel, new_tuple);
                                    if engine.has_session() {
                                        if removed {
                                            println!("Replaced.");
                                        } else {
                                            println!(
                                                "Warning: old fact not found; new fact inserted."
                                            );
                                        }
                                    } else {
                                        match engine.evaluate() {
                                            Ok(new_store) => {
                                                current_store = new_store;
                                                store_version = engine.version();
                                                if removed {
                                                    println!("Replaced.");
                                                } else {
                                                    println!(
                                                        "Warning: old fact not found; new fact inserted."
                                                    );
                                                }
                                            }
                                            Err(e) => command_error!("Error: {e:#}"),
                                        }
                                    }
                                }
                                Err(e) => command_error!("Parse error: {e}"),
                            }
                        }
                        None => command_error!("Usage: ~pred(old_args). pred(new_args)."),
                    }
                    continue;
                }

                // +pred(args).  — insert ground fact
                if let Some(inner) = line.strip_prefix('+') {
                    if refuse_if_in_use(&in_use, &mut command_failed) {
                        continue;
                    }
                    let inner = inner.trim_end_matches('.').trim();
                    match parse_ground_tuple(inner) {
                        Ok((rel, tuple)) => {
                            if let Some(arity) = engine.relation_arity(&rel)
                                && tuple.len() != arity
                            {
                                command_error!(
                                    "arity mismatch: {rel}/{arity} expects {arity} arg(s), got {}",
                                    tuple.len()
                                );
                                continue;
                            }
                            if engine.add_fact(rel, tuple) {
                                if engine.has_session() {
                                    eprintln!("Asserted.");
                                } else {
                                    match engine.evaluate() {
                                        Ok(new_store) => {
                                            current_store = new_store;
                                            store_version = engine.version();
                                            eprintln!("Asserted.");
                                        }
                                        Err(e) => command_error!("Error: {e:#}"),
                                    }
                                }
                            } else {
                                eprintln!("Fact already exists.");
                            }
                        }
                        Err(e) => command_error!("Parse error: {e}"),
                    }
                    continue;
                }

                // -pred(args).  — retract ground fact
                if let Some(inner) = line.strip_prefix('-') {
                    if refuse_if_in_use(&in_use, &mut command_failed) {
                        continue;
                    }
                    let inner = inner.trim_end_matches('.').trim();
                    match parse_ground_tuple(inner) {
                        Ok((rel, tuple)) => {
                            if engine.retract_fact(&rel, &tuple) {
                                if engine.has_session() {
                                    eprintln!("Retracted.");
                                } else {
                                    match engine.evaluate() {
                                        Ok(new_store) => {
                                            current_store = new_store;
                                            store_version = engine.version();
                                            eprintln!("Retracted.");
                                        }
                                        Err(e) => command_error!("Error: {e:#}"),
                                    }
                                }
                            } else {
                                eprintln!("No matching fact found.");
                            }
                        }
                        Err(e) => command_error!("Parse error: {e}"),
                    }
                    continue;
                }

                // k8s::match <Kind> <namespace> <selector>  - scoped to one Kind
                if let Some(rest) = line.strip_prefix("::k8s::match ") {
                    if refuse_if_in_use(&in_use, &mut command_failed) {
                        continue;
                    }
                    let parts: Vec<&str> = rest.trim().splitn(3, char::is_whitespace).collect();
                    match parts.as_slice() {
                        [kind, namespace, selector] => {
                            // run_match retracts the facts it asserts, so a store that was
                            // current before it still is.
                            let in_sync = engine.version() == store_version;
                            if !run_match(engine, Some(kind), namespace, selector, format) {
                                command_failed = true;
                            }
                            if in_sync {
                                store_version = engine.version();
                            }
                        }
                        _ => command_error!(
                            "Usage: k8s::match <Kind> <namespace> <selector>  (namespace \"\" for cluster-scoped)"
                        ),
                    }
                    continue;
                }

                // k8s::match-all <namespace> <selector>  - any Kind
                if let Some(rest) = line.strip_prefix("::k8s::match-all ") {
                    if refuse_if_in_use(&in_use, &mut command_failed) {
                        continue;
                    }
                    let parts: Vec<&str> = rest.trim().splitn(2, char::is_whitespace).collect();
                    match parts.as_slice() {
                        [namespace, selector] => {
                            // run_match retracts the facts it asserts, so a store that was
                            // current before it still is.
                            let in_sync = engine.version() == store_version;
                            if !run_match(engine, None, namespace, selector, format) {
                                command_failed = true;
                            }
                            if in_sync {
                                store_version = engine.version();
                            }
                        }
                        _ => command_error!("Usage: k8s::match-all <namespace> <selector>"),
                    }
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
                if let Some(rest) = line.strip_prefix("::rbac::") {
                    let active = active_store(&current_store, &snapshots, &in_use);
                    match rbac_command(rest.trim(), active, format) {
                        CheckResult::Pass => {}
                        CheckResult::Fail => had_failure = true,
                        CheckResult::Error => command_failed = true,
                    }
                    continue;
                }
                if let Some(rest) = line.strip_prefix("::sched::") {
                    let active = active_store(&current_store, &snapshots, &in_use);
                    match sched_command(rest.trim(), active, format) {
                        CheckResult::Pass => {}
                        CheckResult::Fail => had_failure = true,
                        CheckResult::Error => command_failed = true,
                    }
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

/// Extract uppercase variable names from a Mangle rule body, in order of first
/// appearance. Skips string literals and single underscores.
/// Parse an optional anonymous-rule head from a `?-`/`query` body. The form
/// `_(R, N) :- atom, atom` (an anonymous head, as in LogiQL) reports only the
/// variables named in the head; the rest act as join keys. Returns
/// `(Some(vars), body)` when the body begins with such a head, otherwise
/// `(None, whole_body)`, keeping the "report every named variable" behaviour.
/// The head name is a bare `_`, and the closing paren is matched outside
/// strings and brackets so a struct or list in the args can't end it early.
fn split_projection(raw: &str) -> (Option<Vec<String>>, &str) {
    let raw = raw.trim_start();
    // The anonymous head is `_` then `(`; anything else is a plain body. A
    // real body atom's predicate starts with a lowercase letter, so a leading
    // `_(` is unambiguous.
    let Some(rest) = raw
        .strip_prefix('_')
        .map(str::trim_start)
        .and_then(|r| r.strip_prefix('('))
    else {
        return (None, raw);
    };
    let mut depth = 1i32;
    let mut in_string = false;
    for (i, ch) in rest.char_indices() {
        match ch {
            '"' => in_string = !in_string,
            _ if in_string => {}
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth == 0 {
                    // Only a head when `:-` follows the arg list; otherwise
                    // treat the whole line as an ordinary body.
                    let Some(body) = rest[i + 1..].trim_start().strip_prefix(":-") else {
                        return (None, raw);
                    };
                    let vars = rest[..i]
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect();
                    return (Some(vars), body.trim_start());
                }
            }
            _ => {}
        }
    }
    (None, raw)
}

fn extract_vars(body: &str) -> Vec<String> {
    let mut vars: Vec<String> = Vec::new();
    let mut in_string = false;
    let mut token = String::new();

    let consider = |tok: &str, vars: &mut Vec<String>| {
        if tok
            .chars()
            .next()
            .map(|c| c.is_uppercase())
            .unwrap_or(false)
            && !vars.contains(&tok.to_string())
        {
            vars.push(tok.to_string());
        }
    };

    for ch in body.chars() {
        match ch {
            '"' => {
                in_string = !in_string;
                token.clear();
            }
            _ if in_string => {}
            c if c.is_alphanumeric() || c == '_' => token.push(c),
            _ => {
                if !token.is_empty() {
                    consider(&token, &mut vars);
                    token.clear();
                }
            }
        }
    }
    if !token.is_empty() {
        consider(&token, &mut vars);
    }

    vars
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
fn print_access_diff(
    before: &rbac::PermissionTables,
    after: &rbac::PermissionTables,
    before_label: &str,
    after_label: &str,
) -> bool {
    let can_gained = rbac::diff::check_permission_expansion(before, after);
    let can_lost = rbac::diff::check_permission_contraction(before, after);
    let eff_gained = rbac::diff::check_effective_can_expansion(before, after);
    let eff_lost = rbac::diff::check_effective_can_contraction(before, after);

    let verdicts = per_principal_verdicts(&can_gained, &can_lost, &eff_gained, &eff_lost);
    let total_gained: usize = verdicts.iter().map(|(_, gained, _)| gained).sum();
    let total_lost: usize = verdicts.iter().map(|(_, _, lost)| lost).sum();

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
    if !verdicts.is_empty() {
        println!();
        println!("  Per-principal:");
        let col_w = verdicts
            .iter()
            .map(|(p, _, _)| p.to_string().len())
            .max()
            .unwrap_or(8)
            .min(32);
        for (principal, gained, lost) in &verdicts {
            let label = if *gained > 0 { "FAIL" } else { "PASS" };
            let principal = principal.to_string();
            println!("    {label}  {principal:<col_w$}  +{gained} gained / -{lost} lost");
        }
        println!();
    }

    if !can_gained.is_empty() {
        println!("  CAN GAINED ({}):", can_gained.len());
        let mut sorted = can_gained;
        sorted.sort_by(|a, b| a.principal.cmp(&b.principal));
        for d in &sorted {
            println!(
                "    {}  ns={:?}  apigroup={:?}  resource={:?}  verb={:?}",
                d.principal, d.namespace, d.apigroup, d.resource, d.verb
            );
        }
    }
    if !can_lost.is_empty() {
        println!("  CAN LOST ({}):", can_lost.len());
        let mut sorted = can_lost;
        sorted.sort_by(|a, b| a.principal.cmp(&b.principal));
        for d in &sorted {
            println!(
                "    {}  ns={:?}  apigroup={:?}  resource={:?}  verb={:?}",
                d.principal, d.namespace, d.apigroup, d.resource, d.verb
            );
        }
    }
    if !eff_gained.is_empty() {
        println!(
            "  EFFECTIVE GAINED ({}) [escalation-aware]:",
            eff_gained.len()
        );
        print_eff_diffs_grouped(&eff_gained, after);
    }
    if !eff_lost.is_empty() {
        println!("  EFFECTIVE LOST ({}) [escalation-aware]:", eff_lost.len());
        print_eff_diffs_grouped(&eff_lost, before);
    }
    total_gained == 0
}

fn per_principal_verdicts(
    can_gained: &[rbac::diff::CanDiff],
    can_lost: &[rbac::diff::CanDiff],
    eff_gained: &[rbac::diff::EffDiff],
    eff_lost: &[rbac::diff::EffDiff],
) -> Vec<(rbac::Subject, usize, usize)> {
    // A permission can be both a direct and an effective change; count it once.
    let key = |p: &rbac::Subject, ns: &str, g: &str, r: &str, v: &str| {
        (
            p.clone(),
            ns.to_string(),
            g.to_string(),
            r.to_string(),
            v.to_string(),
        )
    };
    let gained: BTreeSet<_> = can_gained
        .iter()
        .map(|d| {
            key(
                &d.principal,
                &d.namespace,
                &d.apigroup,
                &d.resource,
                &d.verb,
            )
        })
        .chain(eff_gained.iter().map(|d| {
            key(
                &d.principal,
                &d.namespace,
                &d.apigroup,
                &d.resource,
                &d.verb,
            )
        }))
        .collect();
    let lost: BTreeSet<_> = can_lost
        .iter()
        .map(|d| {
            key(
                &d.principal,
                &d.namespace,
                &d.apigroup,
                &d.resource,
                &d.verb,
            )
        })
        .chain(eff_lost.iter().map(|d| {
            key(
                &d.principal,
                &d.namespace,
                &d.apigroup,
                &d.resource,
                &d.verb,
            )
        }))
        .collect();
    let mut map: BTreeMap<rbac::Subject, (usize, usize)> = BTreeMap::new();
    for (principal, ..) in gained {
        map.entry(principal).or_default().0 += 1;
    }
    for (principal, ..) in lost {
        map.entry(principal).or_default().1 += 1;
    }

    let mut result: Vec<(rbac::Subject, usize, usize)> = map
        .into_iter()
        .map(|(p, (gained, lost))| (p, gained, lost))
        .collect();
    result.sort_by(|a, b| {
        let a_fails = a.1 > 0;
        let b_fails = b.1 > 0;
        b_fails.cmp(&a_fails).then(a.0.cmp(&b.0))
    });
    result
}

/// Group effective-can diffs by (principal, escalation-target) and print.
/// `tables` says which identities and groups each permission was reached
/// through; permissions reached through none were gained directly.
fn print_eff_diffs_grouped(diffs: &[rbac::diff::EffDiff], tables: &rbac::PermissionTables) {
    // (principal, target) → indices into diffs. No target = direct grant.
    let mut groups: BTreeMap<(rbac::Subject, Option<rbac::Subject>), Vec<usize>> = BTreeMap::new();

    for (i, d) in diffs.iter().enumerate() {
        let permission = (
            d.namespace.clone(),
            d.apigroup.clone(),
            d.resource.clone(),
            d.verb.clone(),
        );
        let targets = tables.escalation_via(&d.principal, &permission);
        if targets.is_empty() {
            groups
                .entry((d.principal.clone(), None))
                .or_default()
                .push(i);
        } else {
            for target in targets {
                groups
                    .entry((d.principal.clone(), Some(target.clone())))
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
            let d = &diffs[i];
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
fn rbac_command(input: &str, store: &EvalStore, format: OutputFormat) -> CheckResult {
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

            let model = rbac::RbacAccessModel::from_store(store);

            let violations = model.check_access_invariant(namespace, resource, verb, &expected);
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
            let expected: Vec<&str> = expected.iter().map(String::as_str).collect();

            let mut model = rbac::RbacAccessModel::from_store(store);

            model.include_builtins = include_builtins;
            let direct = model.direct_violations(namespace, apigroup, resource, verb);
            let via = model.check_reaches(
                namespace,
                apigroup,
                resource,
                verb,
                &expected,
                include_direct,
            );

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

            let model = rbac::RbacAccessModel::from_store(store);

            let violations = model.check_namespace_isolation(namespace, &allowed);
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
fn sched_command(input: &str, store: &EvalStore, format: OutputFormat) -> CheckResult {
    let ndjson = format == OutputFormat::Ndjson;
    let subcommand = input.split_whitespace().next().unwrap_or("").trim();

    match subcommand {
        "node-selector" => {
            let unschedulable = smt::scheduling::check_node_selector(store);
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
            match smt::scheduling::check_anti_affinity_placement(store) {
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
            let gaps = smt::scheduling::find_karpenter_coverage_gaps(store, 5);
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

/// If `body` is a single atom with named variables but fewer arguments than the
/// relation has columns, pad the rest with `_` so Mangle sees the right arity.
/// Returns (new_body, extra_vars) or None if no padding is needed or the arity
/// is unknown.
fn auto_complete_partial(
    body: &str,
    store: &EvalStore,
    cols: &[String],
) -> Option<(String, Vec<String>)> {
    let (rel, inner) = split_atom(body)?;
    let arity = relation_arity(store, rel, cols)?;
    let given = count_top_level_args(inner);
    if given == 0 || given >= arity {
        return None;
    }
    let padding = std::iter::repeat_n("_", arity - given)
        .collect::<Vec<_>>()
        .join(", ");
    Some((format!("{rel}({inner}, {padding})"), vec![]))
}

/// Build a map from (relation, tuple) → list of premise-sets that derived it.
/// A single fact may have been derived by multiple rules/paths.
fn build_provenance_index(
    entries: &[ProvenanceEntry],
) -> HashMap<(String, Vec<Value>), Vec<Vec<(String, Vec<Value>)>>> {
    let mut index: HashMap<(String, Vec<Value>), Vec<Vec<(String, Vec<Value>)>>> = HashMap::new();
    for entry in entries {
        index
            .entry(entry.derived.clone())
            .or_default()
            .push(entry.premises.clone());
    }
    index
}

const WHY_MAX_DEPTH: usize = 12;

fn print_why(
    index: &HashMap<(String, Vec<Value>), Vec<Vec<(String, Vec<Value>)>>>,
    rel: &str,
    tuple: &[Value],
    depth: usize,
    visited: &mut Vec<(String, Vec<Value>)>,
) {
    let key = (rel.to_string(), tuple.to_vec());
    if depth > WHY_MAX_DEPTH {
        println!("{}... (depth limit)", "  ".repeat(depth));
        return;
    }
    if visited.contains(&key) {
        println!(
            "{}↻ (cycle: {}({}))",
            "  ".repeat(depth),
            rel,
            tuple
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        return;
    }

    let indent = "  ".repeat(depth);
    match index.get(&key) {
        None => {
            println!("{}└─ (EDB fact)", indent);
        }
        Some(premise_sets) => {
            for (i, premises) in premise_sets.iter().enumerate() {
                if premise_sets.len() > 1 {
                    println!("{}├─ via rule {}:", indent, i + 1);
                }
                visited.push(key.clone());
                for (p_rel, p_tuple) in premises {
                    let args = p_tuple
                        .iter()
                        .map(|v| v.to_string())
                        .collect::<Vec<_>>()
                        .join(", ");
                    println!("{}  {}({})", indent, p_rel, args);
                    print_why(index, p_rel, p_tuple, depth + 1, visited);
                }
                visited.pop();
            }
        }
    }
}

fn join_values(tuple: &[Value]) -> String {
    tuple
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Render one minimal-height proof of `rel(tuple)` by backward-chaining the
/// DD session's lazy provenance annotations. Unlike [`print_why`], this
/// shows a single shortest derivation rather than every derivation, and needs
/// no cycle check: each premise's height is strictly below its parent's.
///
/// `annotation` is the fact's `(rule_id, height)`: looked up once by the
/// caller for the top-level fact, and taken from the `Premise` when recursing,
/// so each node costs one `why_step` and no extra lookup.
fn print_why_lazy(
    provenance: &dyn LazyProvenance,
    row: &crate::dd::value::Row,
    annotation: Option<crate::dd::build::Annotation>,
    depth: usize,
) {
    use crate::dd::value::SENTINEL_EDB;

    let indent = "  ".repeat(depth);
    if depth > WHY_MAX_DEPTH {
        println!("{indent}... (depth limit)");
        return;
    }
    let (rule_id, height) = match annotation {
        Some((SENTINEL_EDB, _)) => {
            println!("{indent}└─ (EDB fact)");
            return;
        }
        Some(annotation) => annotation,
        None => {
            // Every fact in a provenance session has an annotation, so this
            // is a bug; say so rather than pass it off as a base fact.
            println!("{indent}└─ (no annotation: provenance bug)");
            return;
        }
    };
    let Some(grounding) = provenance.why_step(rule_id, row, height) else {
        println!("{indent}└─ (no grounding found)");
        return;
    };
    if grounding.premises.is_empty() && grounding.negated.is_empty() {
        println!("{indent}└─ (rule with no positive premises)");
        return;
    }
    for p in &grounding.premises {
        let values = p.row.clone().into_values();
        println!("{indent}  {}({})", p.rel, join_values(&values));
        print_why_lazy(provenance, &p.row, Some((p.rule_id, p.height)), depth + 1);
    }
    for n in &grounding.negated {
        let args = n
            .args
            .iter()
            .map(|a| match a {
                Some(v) => Value::from(v.clone()).to_string(),
                None => "_".to_string(),
            })
            .collect::<Vec<_>>()
            .join(", ");
        println!("{indent}  !{}({}) (absent)", n.rel, args);
    }
}

/// Split `pred(a, b). pred(c, d).` into `("pred(a, b)", "pred(c, d)")`.
/// Finds the split point at the first `)` followed by `.` at paren-depth 0.
fn split_two_atoms(s: &str) -> Option<(&str, &str)> {
    let mut depth: usize = 0;
    let mut in_string = false;
    let chars: Vec<char> = s.chars().collect();
    for i in 0..chars.len() {
        match chars[i] {
            '"' => in_string = !in_string,
            '(' if !in_string => depth += 1,
            ')' if !in_string => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    // Consume optional '.' and whitespace after the closing paren.
                    let after = s[i + 1..].trim_start_matches('.').trim();
                    if !after.is_empty() {
                        let old = s[..=i].trim_end_matches('.').trim();
                        let new = after.trim_end_matches('.');
                        return Some((old, new));
                    }
                }
            }
            _ => {}
        }
    }
    None
}

/// Parse a ground atom like `pred("a", /b, 42, {/k: ["v"]})` into
/// `(relation, Vec<Value>)`. Rejects any variable (`_` or uppercase-initial),
/// including one nested inside a struct or list.
fn parse_ground_tuple(input: &str) -> anyhow::Result<(String, Vec<Value>)> {
    let arena = mangle_ast::Arena::new_with_global_interner();
    let mut parser = mangle_parse::Parser::new(&arena, input.as_bytes(), "fact");
    parser.next_token().map_err(|e| anyhow::anyhow!(e))?;
    let atom = parser.parse_atom()?;
    let predicate = arena
        .predicate_name(atom.sym)
        .ok_or_else(|| anyhow::anyhow!("cannot resolve predicate name"))?
        .to_string();
    let mut tuple = Vec::with_capacity(atom.args.len());
    for (i, arg) in atom.args.iter().enumerate() {
        let value =
            ground_value(&arena, arg).map_err(|e| anyhow::anyhow!("argument {}: {e}", i + 1))?;
        tuple.push(value);
    }
    Ok((predicate, tuple))
}

/// Convert a ground term to the `Value` the interpreter stores for it.
/// Struct, list, map and pair literals parse as `fn:struct(...)` and friends;
/// they are built with the interpreter's own `eval_function`, so a fact added
/// with `+` equals the same fact loaded with `source`.
fn ground_value(arena: &mangle_ast::Arena, term: &mangle_ast::BaseTerm) -> anyhow::Result<Value> {
    use mangle_ast::{BaseTerm, Const};
    match term {
        BaseTerm::Variable(_) => {
            anyhow::bail!("not ground: variables and `_` are not allowed in a fact")
        }
        BaseTerm::Const(Const::String(s)) => Ok(Value::String(s.to_string())),
        BaseTerm::Const(Const::Name(n)) => {
            let name = arena
                .lookup_name(*n)
                .ok_or_else(|| anyhow::anyhow!("cannot resolve name constant"))?;
            Ok(Value::Name(name.to_string()))
        }
        BaseTerm::Const(Const::Number(n)) => Ok(Value::Number(*n)),
        BaseTerm::Const(Const::Float(f)) => Ok(Value::Float(*f)),
        BaseTerm::Const(Const::Time(t)) => Ok(Value::Time(*t)),
        BaseTerm::Const(Const::Duration(d)) => Ok(Value::Duration(*d)),
        BaseTerm::ApplyFn(function, args) => {
            let name = arena
                .function_name(*function)
                .ok_or_else(|| anyhow::anyhow!("cannot resolve function name"))?;
            if !matches!(name, "fn:list" | "fn:struct" | "fn:map" | "fn:pair") {
                anyhow::bail!(
                    "unsupported term `{name}(...)`: only constants and struct, list, map or pair literals are allowed in a fact"
                );
            }
            let values = args
                .iter()
                .map(|arg| ground_value(arena, arg))
                .collect::<anyhow::Result<Vec<_>>>()?;
            mangle_interpreter::eval_function(name, &values)
        }
        BaseTerm::Const(other) => {
            anyhow::bail!("unsupported constant {other:?} in a fact")
        }
    }
}

/// A `source`d file split into ground facts and the rest of its text.
#[derive(Debug, Default, PartialEq)]
struct SourcedProgram {
    /// Ground facts (an atom with no body and only constant arguments), to be
    /// inserted as facts loaded from the cluster (EDB).
    facts: Vec<(String, Vec<Value>)>,
    /// Everything else, in file order: declarations, rules, and facts with a
    /// variable. Empty when the file holds only ground facts.
    rules: String,
}

/// Split a Mangle file into ground facts and rule text. The DD backend cannot
/// build a bodiless rule whose head holds a struct or list literal, but it can
/// take the same fact as EDB, which `-` and `~` can then also retract.
///
/// A file that does not parse, or that uses `package` or `use`, is left whole
/// as rule text, so `add_rule` reports the error or handles it as before.
fn split_sourced_program(text: &str) -> SourcedProgram {
    let whole = SourcedProgram {
        facts: Vec::new(),
        rules: text.to_string(),
    };
    let arena = mangle_ast::Arena::new_with_global_interner();
    let mut parser = mangle_parse::Parser::new(&arena, text.as_bytes(), "source");
    let Ok(unit) = parser.next_token().and_then(|()| parser.parse_unit()) else {
        return whole;
    };
    if !unit.decls.iter().all(|decl| is_plain_decl(&arena, decl)) {
        return whole;
    }

    let mut program = SourcedProgram::default();
    let mut has_rules = false;
    // Text after the last `.` is only comments and whitespace, since the
    // whole file parsed, so it is dropped.
    for statement in split_statements(text).0 {
        match parse_ground_fact(statement) {
            Some(fact) => {
                program.facts.push(fact);
                // Keep line numbers in rule errors matching the file.
                let newlines = statement.matches('\n').count();
                program.rules.extend(std::iter::repeat_n('\n', newlines));
            }
            None => {
                program.rules.push_str(statement);
                has_rules = true;
            }
        }
    }
    if !has_rules {
        program.rules.clear();
    }
    program
}

/// True for a `Decl`, and for the default package declaration every unit
/// carries. False for `package foo!` and `use foo!`, which would change how
/// later statements are read if split off on their own.
fn is_plain_decl(arena: &mangle_ast::Arena, decl: &mangle_ast::Decl) -> bool {
    use mangle_ast::{BaseTerm, Const};
    match arena.predicate_name(decl.atom.sym) {
        Some("Use") => false,
        Some("Package") => decl.descr.iter().all(|atom| {
            atom.args
                .iter()
                .all(|arg| matches!(arg, BaseTerm::Const(Const::String(""))))
        }),
        _ => true,
    }
}

/// Parse one statement as a ground fact, or `None` if it is anything else.
fn parse_ground_fact(statement: &str) -> Option<(String, Vec<Value>)> {
    let arena = mangle_ast::Arena::new_with_global_interner();
    let mut parser = mangle_parse::Parser::new(&arena, statement.as_bytes(), "statement");
    parser.next_token().ok()?;
    let unit = parser.parse_unit().ok()?;
    let [clause] = unit.clauses else {
        return None;
    };
    if unit.decls.len() != 1
        || !clause.premises.is_empty()
        || !clause.transform.is_empty()
        || clause.head_time.is_some()
    {
        return None;
    }
    let predicate = arena.predicate_name(clause.head.sym)?.to_string();
    let tuple = clause
        .head
        .args
        .iter()
        .map(|arg| ground_value(&arena, arg).ok())
        .collect::<Option<Vec<_>>>()?;
    Some((predicate, tuple))
}

/// Split Mangle source into statements, each ending just after its
/// terminating `.`, plus the text after the last one. The pieces cover the
/// whole input, so concatenating them gives it back.
///
/// A `.` ends a statement when it is outside brackets, strings, comments and
/// `/names` (which may contain `.`, as in `/k8s.io`), and is not followed by a
/// digit (`1.5`) or an uppercase letter (`.Struct` in a type bound). That is
/// the rule Mangle's own scanner uses. Like that scanner, a string ends at the
/// next matching quote: Mangle has no escaped quote inside a string.
fn split_statements(text: &str) -> (Vec<&str>, &str) {
    let mut statements = Vec::new();
    let mut start = 0;
    let mut depth: usize = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        match c {
            '#' => {
                for (_, c) in chars.by_ref() {
                    if c == '\n' {
                        break;
                    }
                }
            }
            '"' | '\'' | '`' => {
                for (_, next) in chars.by_ref() {
                    if next == c {
                        break;
                    }
                }
            }
            '/' => while chars.next_if(|&(_, c)| is_name_char(c)).is_some() {},
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            '.' if depth == 0 => {
                let continues = chars
                    .peek()
                    .is_some_and(|&(_, c)| c.is_ascii_digit() || c.is_ascii_uppercase());
                if !continues {
                    statements.push(&text[start..=i]);
                    start = i + 1;
                }
            }
            _ => {}
        }
    }
    (statements, &text[start..])
}

/// Characters that may follow the `/` of a name constant, as Mangle scans it.
fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '~' | '.' | '%' | '/')
}

/// Load one side of a `apply-delta` into its rendered objects. A literal
/// `-` is an intentionally empty side (a brand-new chart has no base; a
/// deleted chart has no head), distinct from a path that matches no files,
/// which still errors like any manifest load.
fn load_delta_side(arg: &str) -> Result<Vec<ObjectFacts>> {
    if arg == "-" {
        return Ok(Vec::new());
    }
    let mut source = K8sManifestsSource {
        paths: vec![arg.to_string()],
    };
    crate::edb::object_facts(&mut source)
}

/// The `k8s/5` row an object emitted, which carries its whole body and so
/// stands in for its content. Compared between base and head to tell an
/// unchanged object from a changed one.
fn k8s_row(object: &ObjectFacts) -> Option<&Vec<Value>> {
    object
        .facts
        .iter()
        .find(|(relation, _)| relation == "k8s")
        .map(|(_, tuple)| tuple)
}

/// Diff two rendered object sets (base and head) into the changes a 3-way
/// merge applies to the live cluster, treating live as "ours": head-only
/// keys are adds, keys in both whose content differs are updates, base-only
/// keys are retracts (what Argo would prune), and keys in both with
/// identical content are left alone so live drift survives. Returns the
/// changes plus the added, updated and unchanged counts for the summary;
/// the retract count is read off the changes, and how many retracts were
/// not live comes back from the engine.
fn diff_object_sides(
    base: Vec<ObjectFacts>,
    head: Vec<ObjectFacts>,
) -> (Vec<Change>, usize, usize, usize) {
    // Last copy of a repeated key wins, matching how a load collapses an
    // object listed twice across files.
    let base: HashMap<ObjectKey, ObjectFacts> =
        base.into_iter().map(|o| (o.key.clone(), o)).collect();
    let head: HashMap<ObjectKey, ObjectFacts> =
        head.into_iter().map(|o| (o.key.clone(), o)).collect();

    let mut changes = Vec::new();
    let (mut added, mut updated, mut unchanged) = (0, 0, 0);
    for (key, head_object) in &head {
        match base.get(key) {
            None => {
                added += 1;
                changes.push(Change::Upsert(head_object.clone()));
            }
            Some(base_object) if k8s_row(base_object) != k8s_row(head_object) => {
                updated += 1;
                changes.push(Change::Upsert(head_object.clone()));
            }
            Some(_) => unchanged += 1,
        }
    }
    for key in base.keys() {
        if !head.contains_key(key) {
            changes.push(Change::Retract(key.clone()));
        }
    }
    (changes, added, updated, unchanged)
}

/// Load a sourced file: ground facts as EDB, then the rules, then evaluate.
/// All or nothing: on any error, the rules and the facts this call inserted
/// are removed again. A fact that was already present is left alone.
fn source_program(engine: &mut Engine, text: &str) -> Result<EvalStore> {
    let program = split_sourced_program(text);
    let checkpoint = engine.rules_len();
    let mut inserted = Vec::new();
    let result = insert_sourced_program(engine, program, &mut inserted);
    if result.is_err() {
        for (relation, tuple) in &inserted {
            engine.retract_fact(relation, tuple);
        }
        engine.truncate_rules(checkpoint);
    }
    result
}

fn insert_sourced_program(
    engine: &mut Engine,
    program: SourcedProgram,
    inserted: &mut Vec<(String, Vec<Value>)>,
) -> Result<EvalStore> {
    // Facts go in before rules: on the DD backend a rule that reads a relation
    // with no input yet fails to build ("relation not found").
    //
    // One `add_fact` per fact: on the DD backend each brand-new relation
    // rebuilds the session. Fine for small files; switch to the batch
    // `add_facts` once it lands (PR #36).
    for (relation, tuple) in program.facts {
        if let Some(arity) = engine.relation_arity(&relation)
            && tuple.len() != arity
        {
            anyhow::bail!(
                "arity mismatch: {relation}/{arity} expects {arity} arg(s), got {}",
                tuple.len()
            );
        }
        if engine.add_fact(relation.clone(), tuple.clone()) {
            inserted.push((relation, tuple));
        }
    }
    if !program.rules.is_empty() {
        engine.add_rule(program.rules)?;
    }
    engine.evaluate()
}

fn count_top_level_args(s: &str) -> usize {
    split_top_level_args(s).len()
}

/// Split an argument list on top-level commas (not inside strings or brackets).
fn split_top_level_args(s: &str) -> Vec<&str> {
    if s.trim().is_empty() {
        return Vec::new();
    }
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut start = 0;
    let mut out = Vec::new();
    for (i, ch) in s.char_indices() {
        match ch {
            '"' => in_string = !in_string,
            '(' | '[' | '{' if !in_string => depth += 1,
            ')' | ']' | '}' if !in_string => depth = depth.saturating_sub(1),
            ',' if !in_string && depth == 0 => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}

/// Split `rel(args)` into the relation name and the text between the outer
/// parentheses. None unless the body is a single atom.
fn split_atom(body: &str) -> Option<(&str, &str)> {
    let body = body.trim();
    let open = body.find('(')?;
    // The paren opened here must close at the very end, or this is a conjunction.
    let mut depth = 0usize;
    let mut in_string = false;
    for (i, ch) in body[open..].char_indices() {
        match ch {
            '"' => in_string = !in_string,
            '(' if !in_string => depth += 1,
            ')' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    return (open + i + 1 == body.len())
                        .then(|| (body[..open].trim(), &body[open + 1..open + i]));
                }
            }
            _ => {}
        }
    }
    None
}

/// The relation name when `body` is exactly one plain atom (`rel`, `rel()` or
/// `rel(args)`), not a conjunction, negation or builtin call.
fn single_atom(body: &str) -> Option<&str> {
    let body = body.trim();
    let rel = if body.contains('(') {
        split_atom(body)?.0
    } else {
        body
    };
    (body_relations(body) == [rel]).then_some(rel)
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

/// Print the tuples of `rel` matching the constants in `body`, one row per
/// line (`Column = value, ...`, or `rel(a, b, ...)` in compact format). `_` and
/// missing trailing arguments match anything. `live` is false under `use`: a
/// frozen snapshot has no live session of its own, so `store` is read directly
/// even when the live engine has one. Returns `false` if the query failed.
fn list_tuples(
    engine: &Engine,
    store: &EvalStore,
    format: OutputFormat,
    rel: &str,
    body: &str,
    cols: &[String],
    live: bool,
) -> bool {
    let live_rows: Vec<Vec<Value>>;
    let rows: &[Vec<Value>] = if live && engine.has_session() {
        live_rows = match engine.query_live(rel) {
            Ok(rows) => rows,
            Err(e) => {
                eprintln!("Error: {e:#}");
                return false;
            }
        };
        &live_rows
    } else {
        store.scan(rel)
    };
    let q = match split_atom(body) {
        Some((_, inner)) if !inner.trim().is_empty() => match query::parse_query(body) {
            Ok(q) => q,
            Err(e) => {
                eprintln!("Parse error: {e}");
                return false;
            }
        },
        _ => query::ParsedQuery {
            predicate: rel.to_string(),
            args: vec![],
        },
    };
    let matched = query::filter_tuples(rows, &q);
    if matched.is_empty() {
        eprintln!("No results.");
        return true;
    }
    if format == OutputFormat::Table {
        let width = matched.iter().map(|t| t.len()).max().unwrap_or(0);
        let headers: Vec<String> = (0..width)
            .map(|i| cols.get(i).cloned().unwrap_or_else(|| format!("c{i}")))
            .collect();
        let rows: Vec<Vec<String>> = matched
            .iter()
            .map(|t| t.iter().map(|v| v.to_string()).collect())
            .collect();
        print!("{}", render_table(&headers, &rows));
        eprintln!("Found {} result(s).", matched.len());
        return true;
    }
    let show = |v: &Value| {
        if format == OutputFormat::Pretty {
            format_pretty(v)
        } else {
            v.to_string()
        }
    };
    for tuple in &matched {
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
                    .enumerate()
                    .map(|(i, v)| {
                        let name = cols.get(i).cloned().unwrap_or_else(|| format!("c{i}"));
                        format!("{name} = {}", show(v))
                    })
                    .collect();
                println!("  {}", parts.join(", "));
            }
        }
    }
    eprintln!("Found {} result(s).", matched.len());
    true
}

/// Column count of `rel`: from a stored row, else from its Decl.
fn relation_arity(store: &EvalStore, rel: &str, cols: &[String]) -> Option<usize> {
    store
        .scan(rel)
        .first()
        .map(|t| t.len())
        .or_else(|| (!cols.is_empty()).then_some(cols.len()))
}

/// Relation names a query body refers to: identifiers directly followed by `(`,
/// or the whole body when it is a bare name. Builtins (`:string:contains`) and
/// functions (`fn:plus`) contain `:` and are skipped, as are variables.
fn body_relations(body: &str) -> Vec<String> {
    let body = body.trim();
    let name_char = |c: char| c.is_alphanumeric() || matches!(c, '_' | '.' | ':');
    let is_relation = |t: &str| {
        !t.contains(':')
            && t.chars()
                .next()
                .is_some_and(|c| c.is_lowercase() || c == '_')
    };
    let mut out: Vec<String> = Vec::new();
    let push = |t: &str, out: &mut Vec<String>| {
        if is_relation(t) && !out.iter().any(|o| o == t) {
            out.push(t.to_string());
        }
    };
    if body.chars().all(name_char) {
        push(body, &mut out);
        return out;
    }
    let mut in_string = false;
    let mut token = String::new();
    for ch in body.chars() {
        match ch {
            '"' => {
                in_string = !in_string;
                token.clear();
            }
            _ if in_string => {}
            '(' => {
                push(&token, &mut out);
                token.clear();
            }
            c if name_char(c) => token.push(c),
            _ => token.clear(),
        }
    }
    out
}

fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            let sub = prev[j] + usize::from(ca != *cb);
            cur.push(sub.min(prev[j + 1] + 1).min(cur[j] + 1));
        }
        prev = cur;
    }
    prev[b.len()]
}

/// Up to three known relations close to `name`, nearest first. Internal
/// relations (leading `_`) are not suggested.
fn suggest(name: &str, known: &std::collections::HashSet<String>) -> Vec<String> {
    let mut scored: Vec<(usize, &String)> = known
        .iter()
        .filter(|k| !k.starts_with('_'))
        .map(|k| (edit_distance(name, k), k))
        .filter(|(d, _)| *d <= 2.max(name.len() / 4))
        .collect();
    scored.sort();
    scored.into_iter().take(3).map(|(_, k)| k.clone()).collect()
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
mod ground_fact_tests {
    use super::parse_ground_tuple;
    use crate::engine::{Backend, DdBackend, Engine, InterpreterBackend};
    use mangle_common::Value;

    const EXEC_RULE: &str = r#"role_rule("ns", "r", {/apiGroups: [""], /resources: ["pods/exec"], /verbs: ["create"]})"#;
    const LOG_RULE: &str =
        r#"role_rule("ns", "r", {/apiGroups: [""], /resources: ["pods/log"], /verbs: ["get"]})"#;

    fn backends() -> Vec<(&'static str, fn() -> Box<dyn Backend>)> {
        vec![
            ("interpreter", || Box::new(InterpreterBackend)),
            ("dd", || Box::new(DdBackend { provenance: false })),
        ]
    }

    /// An engine with the shipped rules and no facts loaded from a cluster.
    fn engine(backend: Box<dyn Backend>) -> Engine {
        let mut rules: Vec<String> = glob::glob("rules/*.mg")
            .unwrap()
            .map(|p| std::fs::read_to_string(p.unwrap()).unwrap())
            .collect();
        rules.sort();
        Engine::from_parts(vec![], rules, backend).unwrap()
    }

    fn sorted_scan(engine: &Engine, relation: &str) -> Vec<Vec<Value>> {
        let mut rows = engine.evaluate().unwrap().scan(relation).to_vec();
        rows.sort();
        rows
    }

    /// policy_rule_perm rows derived from the rule role "r" holds.
    fn perms(engine: &Engine) -> Vec<Vec<Value>> {
        let held: Vec<Value> = sorted_scan(engine, "role_rule")
            .into_iter()
            .filter(|t| t[1] == Value::String("r".into()))
            .map(|t| t[2].clone())
            .collect();
        sorted_scan(engine, "policy_rule_perm")
            .into_iter()
            .filter(|t| held.contains(&t[0]))
            .collect()
    }

    fn perm(resource: &str, verb: &str) -> Vec<Value> {
        vec![
            Value::String(String::new()),
            Value::String(resource.into()),
            Value::Name("/any".into()),
            Value::String(verb.into()),
        ]
    }

    #[test]
    fn struct_fact_round_trips_on_both_backends() {
        for (name, backend) in backends() {
            let mut engine = engine(backend());
            let (relation, tuple) = parse_ground_tuple(EXEC_RULE).unwrap();
            assert!(engine.add_fact(relation.clone(), tuple.clone()), "{name}");
            let rows: Vec<Vec<Value>> = perms(&engine)
                .into_iter()
                .map(|t| t[1..].to_vec())
                .collect();
            assert_eq!(rows, vec![perm("pods/exec", "create")], "{name}");

            let (relation, tuple) = parse_ground_tuple(EXEC_RULE).unwrap();
            assert!(engine.retract_fact(&relation, &tuple), "{name}");
            assert!(perms(&engine).is_empty(), "{name}");
        }
    }

    #[test]
    fn struct_fact_replace_on_both_backends() {
        for (name, backend) in backends() {
            let mut engine = engine(backend());
            let (relation, tuple) = parse_ground_tuple(EXEC_RULE).unwrap();
            engine.add_fact(relation, tuple);
            // What `~old. new.` does: retract the old fact, insert the new one.
            let line = format!("{EXEC_RULE}. {LOG_RULE}.");
            let (old_atom, new_atom) = super::split_two_atoms(&line).unwrap();
            let (old_relation, old_tuple) = parse_ground_tuple(old_atom).unwrap();
            let (new_relation, new_tuple) = parse_ground_tuple(new_atom).unwrap();
            assert!(engine.retract_fact(&old_relation, &old_tuple), "{name}");
            engine.add_fact(new_relation, new_tuple);
            let rows: Vec<Vec<Value>> = perms(&engine)
                .into_iter()
                .map(|t| t[1..].to_vec())
                .collect();
            assert_eq!(rows, vec![perm("pods/log", "get")], "{name}");
        }
    }

    /// A struct added with `+` must be the same Value the interpreter builds
    /// for the literal in a fact written as a bodiless rule, or joins and
    /// `:match_field` on it would miss. The DD backend cannot evaluate such a
    /// rule ("Let before Scan"), so both backends compare against the
    /// interpreter.
    #[test]
    fn parsed_struct_equals_sourced_struct() {
        let literal = r#"role_rule("ns", "r", {/apiGroups: [""], /resources: ["pods", "pods/exec"], /verbs: ["get", "create"], /resourceNames: [], /n: 3, /nested: {/k: [/v, 1.5]}})"#;
        let mut sourced = engine(Box::new(InterpreterBackend));
        sourced.add_rule(format!("{literal}.")).unwrap();
        assert_eq!(perms(&sourced).len(), 4);
        for (name, backend) in backends() {
            let mut added = engine(backend());
            let (relation, tuple) = parse_ground_tuple(literal).unwrap();
            added.add_fact(relation, tuple);
            assert_eq!(
                sorted_scan(&added, "role_rule"),
                sorted_scan(&sourced, "role_rule"),
                "{name}"
            );
            assert_eq!(perms(&added), perms(&sourced), "{name}");
        }
    }

    #[test]
    fn variables_are_rejected_at_any_depth() {
        for input in ["foo(_)", "foo(X)", "foo({/k: X})", r#"foo("a", [1, _])"#] {
            let error = parse_ground_tuple(input).unwrap_err().to_string();
            assert!(error.contains("not ground"), "{input}: {error}");
        }
        let error = parse_ground_tuple(r#"foo("a", [1, _])"#)
            .unwrap_err()
            .to_string();
        assert!(error.starts_with("argument 2:"), "{error}");
    }

    #[test]
    fn function_calls_are_unsupported() {
        let error = parse_ground_tuple("foo(fn:plus(1, 2))")
            .unwrap_err()
            .to_string();
        assert!(error.contains("unsupported term `fn:plus(...)`"), "{error}");
    }
}

#[cfg(test)]
mod source_tests {
    use super::split_statements;
    use super::{SourcedProgram, parse_ground_tuple, source_program, split_sourced_program};
    use crate::engine::{Backend, DdBackend, Engine, InterpreterBackend};
    use mangle_common::Value;

    fn backends() -> Vec<(&'static str, fn() -> Box<dyn Backend>)> {
        vec![
            ("interpreter", || Box::new(InterpreterBackend)),
            ("dd", || Box::new(DdBackend { provenance: false })),
        ]
    }

    /// An engine with the shipped rules and no facts loaded from a cluster.
    fn engine(backend: Box<dyn Backend>) -> Engine {
        let mut rules: Vec<String> = glob::glob("rules/*.mg")
            .unwrap()
            .map(|p| std::fs::read_to_string(p.unwrap()).unwrap())
            .collect();
        rules.sort();
        Engine::from_parts(vec![], rules, backend).unwrap()
    }

    fn rows(engine: &Engine, relation: &str) -> Vec<Vec<Value>> {
        let mut rows = engine.evaluate().unwrap().scan(relation).to_vec();
        rows.sort();
        rows
    }

    fn s(text: &str) -> Value {
        Value::String(text.into())
    }

    const STRUCT_FACT: &str = r#"role_rule("ns", "r", {/apiGroups: [""], /resources: ["pods/exec"], /verbs: ["create"]})"#;

    #[test]
    fn statements_end_at_top_level_dots() {
        let text = concat!(
            "# a comment. with dots. and \"quotes\n",
            "a(\"x. y # not a comment\", 'it''s. ok', `raw.\nstring`).\n",
            "b(/k8s.io/v1.beta, \"https://example.com/a.b\", 1.5, -0.25, 2.).\n",
            "c({/k: [{/n: 1.0}, [/a.b]]}, 3). d(4).# trailing. comment\n",
            "Decl e(X) bound [.Struct<>].\n",
            "f(X) :- g(X), X = 1.\n",
            "  # tail. comment\n",
        );
        let (statements, rest) = split_statements(text);
        let trimmed: Vec<&str> = statements.iter().map(|s| s.trim()).collect();
        assert_eq!(
            trimmed,
            vec![
                "# a comment. with dots. and \"quotes\na(\"x. y # not a comment\", 'it''s. ok', `raw.\nstring`).",
                "b(/k8s.io/v1.beta, \"https://example.com/a.b\", 1.5, -0.25, 2.).",
                "c({/k: [{/n: 1.0}, [/a.b]]}, 3).",
                "d(4).",
                "# trailing. comment\nDecl e(X) bound [.Struct<>].",
                "f(X) :- g(X), X = 1.",
            ]
        );
        assert_eq!(rest, "\n  # tail. comment\n");
        assert_eq!(statements.concat() + rest, text);
    }

    #[test]
    fn statements_without_trailing_whitespace() {
        let (statements, rest) = split_statements("a(1).b(2).");
        assert_eq!(statements, vec!["a(1).", "b(2)."]);
        assert_eq!(rest, "");
    }

    /// Decls, rules, transforms and non-ground facts stay rule text, in file
    /// order; scalar and struct ground facts are pulled out as facts.
    #[test]
    fn mixed_file_splits_facts_from_rules() {
        let text = concat!(
            "Decl thing(Name) descr [doc(\"a thing\")].\n",
            "scalar(\"a\", /b, 3).\n",
            "derived(X) :- scalar(X, _, _).\n",
            "counted(N) :- scalar(X, _, _) |> do fn:group_by(), let N = fn:count().\n",
            "role_rule(\"ns\", \"r\", {/apiGroups: [\"\"], /resources: [\"pods\"], /verbs: [\"get\"]}).\n",
            "with_var(X).\n",
            "computed(fn:plus(1, 2)).\n",
        );
        let program = split_sourced_program(text);
        let struct_tuple = parse_ground_tuple(
            r#"role_rule("ns", "r", {/apiGroups: [""], /resources: ["pods"], /verbs: ["get"]})"#,
        )
        .unwrap();
        assert_eq!(
            program.facts,
            vec![
                (
                    "scalar".to_string(),
                    vec![s("a"), Value::Name("/b".into()), Value::Number(3)]
                ),
                struct_tuple,
            ]
        );
        assert_eq!(
            program.rules,
            concat!(
                "Decl thing(Name) descr [doc(\"a thing\")].",
                "\n",
                "\nderived(X) :- scalar(X, _, _).",
                "\ncounted(N) :- scalar(X, _, _) |> do fn:group_by(), let N = fn:count().",
                "\n",
                "\nwith_var(X).",
                "\ncomputed(fn:plus(1, 2)).",
            )
        );
    }

    #[test]
    fn facts_only_file_has_no_rule_text() {
        let program = split_sourced_program("# header\na(1).\nb(\"x\").\n# end\n");
        assert_eq!(program.facts.len(), 2);
        assert_eq!(program.rules, "");
    }

    #[test]
    fn unparsable_or_packaged_file_stays_whole() {
        for text in ["a(1).\nb(", "package p!\na(1).\n"] {
            assert_eq!(
                split_sourced_program(text),
                SourcedProgram {
                    facts: vec![],
                    rules: text.to_string()
                },
                "{text}"
            );
        }
    }

    /// A bodiless atom with a variable stays a rule, as before `source` split
    /// out facts, so it fails the same way: an unbound head variable.
    #[test]
    fn non_ground_fact_stays_a_rule() {
        for (name, backend) in backends() {
            let mut engine = engine(backend());
            let checkpoint = engine.rules_len();
            let error = source_program(&mut engine, "with_var(X).\n")
                .map(|_| ())
                .unwrap_err();
            assert_eq!(engine.rules_len(), checkpoint, "{name}");
            let mut today = self::engine(backend());
            let error_today = today
                .add_rule("with_var(X).\n".into())
                .and_then(|()| today.evaluate().map(|_| ()))
                .unwrap_err();
            assert_eq!(format!("{error:#}"), format!("{error_today:#}"), "{name}");
        }
    }

    /// The bug this fixes: a struct fact sourced on the DD backend failed with
    /// "Let before Scan". Now it is a fact `-` can retract.
    #[test]
    fn sourced_struct_fact_is_retractable() {
        for (name, backend) in backends() {
            let mut engine = engine(backend());
            let rules_before = engine.rules_len();
            source_program(&mut engine, &format!("{STRUCT_FACT}.\n")).unwrap();
            assert_eq!(engine.rules_len(), rules_before, "{name}");
            let (relation, tuple) = parse_ground_tuple(STRUCT_FACT).unwrap();
            assert_eq!(rows(&engine, "role_rule"), vec![tuple.clone()], "{name}");

            // What `-role_rule(...)` does.
            assert!(engine.retract_fact(&relation, &tuple), "{name}");
            assert!(rows(&engine, "role_rule").is_empty(), "{name}");
        }
    }

    /// `thing_twice` reads `thing`, which only this file's facts define, so the
    /// facts must be in before the rules on the DD backend.
    #[test]
    fn mixed_file_lands_facts_and_rules_on_both_backends() {
        let text = concat!(
            "Decl thing(Name) descr [doc(\"a thing\")].\n",
            "thing(\"a\").\n",
            "role_rule(\"ns\", \"r\", {/apiGroups: [\"\"], /resources: [\"pods\"], /verbs: [\"get\"]}).\n",
            "role_count(N) :- role_rule(Ns, _, _) |> do fn:group_by(), let N = fn:count(Ns).\n",
            "thing_twice(X, X) :- thing(X).\n",
        );
        for (name, backend) in backends() {
            let mut engine = engine(backend());
            let rules_before = engine.rules_len();
            source_program(&mut engine, text).unwrap();
            assert_eq!(engine.rules_len(), rules_before + 1, "{name}");
            assert_eq!(engine.relation_arity("thing"), Some(1), "{name}");
            assert_eq!(engine.relation_arity("role_rule"), Some(3), "{name}");
            assert_eq!(rows(&engine, "role_count"), vec![vec![Value::Number(1)]]);
            assert_eq!(rows(&engine, "thing_twice"), vec![vec![s("a"), s("a")]]);
        }
    }

    /// A broken rule rolls back the whole file: its rules and the facts it
    /// inserted. A fact that was already there before stays.
    #[test]
    fn failed_source_leaves_no_trace() {
        let text = concat!(
            "already(\"x\").\n",
            "brand_new(\"y\").\n",
            "role_rule(\"ns\", \"r\", {/apiGroups: [\"\"], /resources: [\"pods\"], /verbs: [\"get\"]}).\n",
            "broken(X, Y) :- brand_new(X).\n",
        );
        for (name, backend) in backends() {
            let mut engine = engine(backend());
            engine.add_fact("already".into(), vec![s("x")]);
            let rules_before = engine.rules_len();
            assert!(source_program(&mut engine, text).is_err(), "{name}");
            assert_eq!(engine.rules_len(), rules_before, "{name}");
            assert_eq!(engine.relation_arity("brand_new"), None, "{name}");
            assert_eq!(engine.relation_arity("role_rule"), None, "{name}");
            assert_eq!(rows(&engine, "already"), vec![vec![s("x")]], "{name}");
            assert!(rows(&engine, "role_rule").is_empty(), "{name}");
        }
    }

    #[test]
    fn arity_mismatch_rolls_back() {
        for (name, backend) in backends() {
            let mut engine = engine(backend());
            engine.add_fact("pair".into(), vec![s("a"), s("b")]);
            let error = source_program(&mut engine, "single(\"z\").\npair(\"c\").\n")
                .map(|_| ())
                .unwrap_err();
            assert!(
                error.to_string().contains("arity mismatch"),
                "{name}: {error}"
            );
            assert_eq!(engine.relation_arity("single"), None, "{name}");
            assert_eq!(rows(&engine, "pair"), vec![vec![s("a"), s("b")]], "{name}");
        }
    }
}

#[cfg(test)]
mod delta_tests {
    use super::{diff_object_sides, load_delta_side};
    use crate::edb::ObjectFacts;
    use crate::engine::Change;

    /// Turn JSON objects into the rendered `ObjectFacts` a delta side yields.
    fn side(json: Vec<serde_json::Value>) -> Vec<ObjectFacts> {
        struct Objects(Vec<serde_json::Value>);
        impl crate::edb::FactSource for Objects {
            fn k8s_objects(
                &mut self,
            ) -> anyhow::Result<Vec<(kube::api::DynamicObject, Option<(String, String)>)>>
            {
                self.0
                    .drain(..)
                    .map(|json| Ok((serde_json::from_value(json)?, None)))
                    .collect()
            }
        }
        crate::edb::object_facts(&mut Objects(json)).unwrap()
    }

    fn config_map(name: &str, tier: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": name, "namespace": "default"},
            "data": {"tier": tier},
        })
    }

    /// One row of the 3-way table at a time: head-only is an add, a content
    /// change is an update, base-only is a retract, and identical content on
    /// both sides emits nothing, so live (whatever its drift) is left alone.
    #[test]
    fn diff_classifies_each_table_row() {
        let base = side(vec![
            config_map("same", "web"),
            config_map("changed", "web"),
            config_map("removed", "web"),
        ]);
        let head = side(vec![
            config_map("same", "web"),
            config_map("changed", "db"),
            config_map("added", "web"),
        ]);
        let (changes, added, updated, unchanged) = diff_object_sides(base, head);
        assert_eq!((added, updated, unchanged), (1, 1, 1));
        let retracts = changes
            .iter()
            .filter(|c| matches!(c, Change::Retract(_)))
            .count();
        let upserts = changes.len() - retracts;
        assert_eq!(
            (upserts, retracts),
            (2, 1),
            "add + update upsert, remove retracts"
        );
    }

    /// An empty base (a brand-new chart) makes every head object an add.
    #[test]
    fn diff_with_empty_base_is_all_adds() {
        let head = side(vec![config_map("a", "web"), config_map("b", "db")]);
        let (changes, added, updated, unchanged) = diff_object_sides(Vec::new(), head);
        assert_eq!((added, updated, unchanged), (2, 0, 0));
        assert!(changes.iter().all(|c| matches!(c, Change::Upsert(_))));
    }

    /// `-` is an intentionally empty side; a real path with no files still
    /// errors, like any manifest load.
    #[test]
    fn empty_side_dash_loads_nothing_but_missing_path_errors() {
        assert!(load_delta_side("-").unwrap().is_empty());
        assert!(load_delta_side("/pallograph/no/such/dir").is_err());
    }
}
