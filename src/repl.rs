// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::{BTreeMap, HashMap};
use std::io::IsTerminal;

use anyhow::Result;
use mangle_common::Value;
use mangle_interpreter::ProvenanceEntry;
use rustyline::completion::{Completer, FilenameCompleter, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Helper};

use crate::edb::{K8sManifestsSource, ShellSource};
use crate::engine::{Engine, EvalStore, RelationDoc};
use crate::load;
use crate::query;
use crate::smt;
use crate::snapshot::{Diff, Scope, Snapshot};

struct ReplHelper {
    path_completer: FilenameCompleter,
}

impl Completer for ReplHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        if line.starts_with('!') && pos >= 1 {
            let (start, candidates) = self.path_completer.complete(&line[1..], pos - 1, ctx)?;
            return Ok((start + 1, candidates));
        }
        Ok((pos, vec![]))
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
/// line and in `\format`, prints `Column = value` pairs, `Compact` prints bare
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
    println!("Querying");
    println!("  ?- <predicate>                         - list all tuples for a relation");
    println!(
        "  ?- <predicate>(arg, _, ...)            - list tuples matching the constants (_ and missing trailing args match any)"
    );
    println!(
        "  ?- <atom>, <atom>, ...                 - conjunctive query; name variables with uppercase (X) to see their bindings"
    );
    println!(
        "  \\show                                  — list documented relations (arity + description)"
    );
    println!(
        "  \\show --all                            — also list undocumented intermediate relations"
    );
    println!(
        "  \\show <rel...>                         — describe relations (columns, types, docs)"
    );
    println!("  \\query <body>  / ?- <body>             - same as ?- (\\query is the long form)");
    println!("  \\why <pred>(<args>...)                 — show derivation tree for a fact");
    println!(
        "  \\match <Kind> <ns> <selector>          — objects of <Kind> in <ns> matching a kubectl selector (ns \"\" = cluster-scoped)"
    );
    println!(
        "  \\match_all <ns> <selector>             — objects of any Kind in <ns> matching a kubectl selector"
    );
    println!();
    println!("EDB / Rules");
    println!("  +pred(arg1, arg2, ...).                — insert a ground fact and re-evaluate");
    println!("  -pred(arg1, arg2, ...).                — retract a ground fact and re-evaluate");
    println!(
        "  ~pred(old...). pred(new...).           — atomic replace: retract old, insert new, re-evaluate"
    );
    println!("  \\define <rule>.                        — add a rule and re-evaluate");
    println!();
    println!("Loading");
    println!(
        "  \\source <src>                          — load Mangle rules from a file or ! <cmd> and re-evaluate"
    );
    println!(
        "  \\load <rel> <src>                      — load flat JSON tuples into <rel>; src is a file or ! <cmd>"
    );
    println!(
        "  \\load-k8s <src>                        — load k8s objects through the projection pipeline; src is a dir, .json file, or ! <kubectl args>"
    );
    println!();
    println!("Snapshots");
    println!(
        "  \\snapshot <name>                       — save current eval state as a named snapshot"
    );
    println!(
        "  \\diff <name>                           — diff current state against a named snapshot"
    );
    println!("  \\diff <name1> <name2>                  — diff two named snapshots");
    println!(
        "  \\access-diff <name>                    — diff RBAC can/5 permission closure vs named snapshot"
    );
    println!(
        "  \\access-diff <name1> <name2>           — diff RBAC can/5 between two named snapshots"
    );
    println!();
    println!("SMT / Z3");
    println!(
        "  \\smt check_access <ns> <r> <v> [p...] — find principals in can(_,ns,r,v) outside expected set (ns=\"\" for cluster-wide)"
    );
    println!(
        "  \\smt reaches <ns> <ag> <r> <v> [p...] — find principals that effective_can reach (ag,r,v), escalation-aware"
    );
    println!(
        "  \\smt cluster-admin [p...]              — shorthand for reaches \"\" \"*\" \"*\" \"*\""
    );
    println!(
        "                                           reaches/cluster-admin flags: --direct (also list principals with a direct grant), --all (include built-in k8s/EKS principals, hidden by default)"
    );
    println!(
        "  \\smt node_selector                     — find pods whose nodeSelector no node satisfies"
    );
    println!(
        "  \\smt anti_affinity                     — find a valid pod placement or prove none exists"
    );
    println!(
        "  \\smt karpenter                         — find nodeSelector gaps in Karpenter NodePool coverage"
    );
    println!(
        "                                           (--format ndjson: one JSON object per result/violation; exit status 1 if any check FAILs)"
    );
    println!("  \\smtlib <rel> [rel...]                 — dump SMT-LIB 2 encoding of relations");
    println!();
    println!("Session");
    println!("  \\pretty                                - toggle default/pretty tuple display");
    println!(
        "  \\format default|compact|pretty|table|ndjson - set output format (compact = bare tuples, table = aligned columns, ndjson = one JSON object per row)"
    );
    println!(
        "  \\reset                                 — clear session state (_N results, \\define rules, + facts), re-evaluate"
    );
    println!("  !<cmd>                                 — run a shell command");
    println!("  \\help                                  — show this help");
    println!("  \\quit                                  — exit");
    println!();
    println!("  (legacy: ::cmd also accepted as alias for \\cmd)");
    println!();
}

/// Run a real kubectl-style label selector through the `labels.mg` engine and
/// print the objects it matches. The selector is parsed into kube `Expression`s,
/// asserted as synthetic `selector_*` facts under a query owner, evaluated, then
/// retracted so the engine's EDB is left untouched (the same assert→query→retract
/// path the `+`/`?-`/`-` commands expose). `kind = Some(k)` scopes to one Kind
/// (`::match`); `None` matches any Kind (`::match_all`). `namespace` scopes the
/// owner; "" targets cluster-scoped objects.
fn run_match(
    engine: &mut Engine,
    kind: Option<&str>,
    namespace: &str,
    selector_str: &str,
    format: OutputFormat,
) {
    let exprs = match crate::selector::parse_selector(selector_str) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Selector parse error: {e:#}");
            return;
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
    for (rel, args) in &facts {
        engine.add_fact(rel.clone(), args.clone());
    }

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
            return;
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
        return;
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
}

/// Run the REPL until EOF or `::quit`. Returns `false` if any `::smt` check
/// reported a failure during the session (the binary then exits with status 1).
pub fn run(engine: &mut Engine, store: EvalStore, format: OutputFormat) -> Result<bool> {
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
    }));
    let _ = rl.load_history(&history_path);

    let mut current_store = store;
    let mut format = format;
    let mut had_failure = false;
    let mut query_counter: u32 = 0;
    let mut snapshot_counter: u64 = 0;
    let mut snapshot_names: HashMap<String, u64> = HashMap::new();
    let mut snapshot_data: HashMap<u64, Snapshot> = HashMap::new();
    let mut pending: std::collections::VecDeque<String> = std::collections::VecDeque::new();

    loop {
        let raw = if let Some(queued) = pending.pop_front() {
            Ok(queued)
        } else {
            rl.readline("\x1b[1;31mpallograph>\x1b[0m ")
        };
        match raw {
            Ok(line) => {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                // Normalize \ meta-prefix to :: so all existing dispatch keeps working.
                let line = if let Some(rest) = line.strip_prefix('\\') {
                    format!("::{rest}")
                } else {
                    line
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
                        pending.extend(cmds);
                        continue;
                    }
                    // Single command whose newlines are all inside strings
                    // (e.g. terminal line-wrap during paste). Collapse them.
                }
                let line = collapse_string_newlines(&line);
                rl.add_history_entry(&line)?;
                // Rewrite snapshot->relation references to snapshot__relation before parsing.
                let line = rewrite_snapshot_refs(&line);

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
                    if let Err(e) = status {
                        eprintln!("Shell error: {e}");
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
                            eprintln!(
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
                    if names.is_empty() {
                        // List view. By default only documented relations are shown;
                        // undocumented intermediates are hidden unless --all is given.
                        let mut names: Vec<&str> = current_store
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
                            let arity = arity_display(
                                current_store.scan(n).first().map(|t| t.len()),
                                docs.get(n),
                            );
                            println!("  {n}/{arity}{desc}");
                        }
                        if hidden > 0 {
                            println!(
                                "  ({hidden} undocumented relation(s) hidden; ::show --all to include)"
                            );
                        }
                    } else {
                        // Detail view: a psql \d-style block per requested relation.
                        for n in names {
                            print_relation_detail(n, &current_store, docs.get(n));
                        }
                    }
                    continue;
                }
                if let Some(raw_body) = line
                    .strip_prefix("::query ")
                    .or_else(|| line.strip_prefix("?- "))
                {
                    let raw_body = raw_body.trim();
                    // A typo'd relation is an empty result on the interpreter and
                    // an opaque error on DD; catch it up front either way.
                    let mut known = engine.known_relations();
                    known.extend(current_store.relation_names().map(str::to_string));
                    let unknown: Vec<String> = body_relations(raw_body)
                        .into_iter()
                        .filter(|r| !known.contains(r))
                        .collect();
                    if !unknown.is_empty() {
                        for r in &unknown {
                            match suggest(r, &known) {
                                s if s.is_empty() => eprintln!("Unknown relation '{r}'."),
                                s => eprintln!(
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
                        if let Some(arity) = relation_arity(&current_store, rel, &cols)
                            && given > arity
                        {
                            eprintln!("{rel} has {arity} columns, got {given} arguments.");
                            continue;
                        }
                        // No named variables: list whole tuples, not bindings.
                        if existing.is_empty() {
                            list_tuples(engine, &current_store, format, rel, raw_body, &cols);
                            continue;
                        }
                    } else if existing.is_empty() {
                        eprintln!("No variables to bind. Name one (e.g. X).");
                        continue;
                    }
                    let (body, vars) = match auto_complete_partial(raw_body, &current_store, &cols)
                    {
                        Some((new_body, added)) => {
                            let mut all = existing;
                            all.extend(added);
                            (new_body, all)
                        }
                        None => (raw_body.to_string(), existing),
                    };
                    let body = body.as_str();
                    let result_name = format!("_{query_counter}");
                    let rule = format!("{result_name}({}) :- {body}.", vars.join(", "));
                    if let Err(e) = engine.add_rule(rule) {
                        eprintln!("Error: {e:#}");
                        engine.remove_rules_for(&result_name);
                        continue;
                    }
                    match engine.evaluate() {
                        Ok(new_store) => {
                            current_store = new_store;
                            let tuples = current_store.scan(&result_name).to_vec();
                            if tuples.is_empty() {
                                eprintln!("No results.");
                                engine.remove_rules_for(&result_name);
                            } else {
                                if format == OutputFormat::Table {
                                    let rows: Vec<Vec<String>> = tuples
                                        .iter()
                                        .map(|t| t.iter().map(|v| v.to_string()).collect())
                                        .collect();
                                    print!("{}", render_table(&vars, &rows));
                                }
                                for tuple in &tuples {
                                    if format == OutputFormat::Table {
                                        // Printed above as one table.
                                    } else if format == OutputFormat::Ndjson {
                                        // Keys are the query's variable names.
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
                                eprintln!("Found {} result(s): (→ {result_name})", tuples.len());
                                query_counter += 1;
                            }
                        }
                        Err(e) => {
                            eprintln!("Error: {e:#}");
                            engine.remove_rules_for(&result_name);
                        }
                    }
                    continue;
                }

                if line == "::reset" {
                    engine.reset_session();
                    // Re-materialize named snapshots — they survive ::reset.
                    for (snap_name, version) in &snapshot_names {
                        if let Some(snap) = snapshot_data.get(version) {
                            for (rel, tuples) in snap.iter() {
                                let namespaced = format!("{snap_name}__{rel}");
                                for tuple in tuples {
                                    engine.add_fact(namespaced.clone(), tuple.clone());
                                }
                            }
                        }
                    }
                    query_counter = 0;
                    match engine.evaluate() {
                        Ok(new_store) => {
                            current_store = new_store;
                            println!("Session reset.");
                        }
                        Err(e) => eprintln!("Error: {e:#}"),
                    }
                    continue;
                }

                if let Some(rest) = line.strip_prefix("::why ") {
                    if !engine.supports_provenance() {
                        eprintln!(
                            "::why is unavailable with the experimental DD backend \
                             (no provenance yet). Re-run with --backend interpreter."
                        );
                        continue;
                    }
                    let rest = rest.trim();
                    match query::parse_query(rest) {
                        Ok(q) => {
                            let rows = current_store.scan(&q.predicate);
                            let matched = query::filter_tuples(rows, &q);
                            if matched.is_empty() {
                                eprintln!("No matching facts for '{rest}'.");
                            } else {
                                let index = build_provenance_index(&current_store.provenance);
                                for tuple in matched {
                                    println!(
                                        "{}({})",
                                        q.predicate,
                                        tuple
                                            .iter()
                                            .map(|v| v.to_string())
                                            .collect::<Vec<_>>()
                                            .join(", ")
                                    );
                                    print_why(&index, &q.predicate, tuple, 1, &mut Vec::new());
                                }
                            }
                        }
                        Err(e) => eprintln!("Parse error: {e}"),
                    }
                    continue;
                }

                if let Some(rest) = line.strip_prefix("::smtlib ") {
                    let relations: Vec<&str> = rest.split_whitespace().collect();
                    if relations.is_empty() {
                        eprintln!("Usage: ::smtlib <relation> [relation ...]");
                    } else {
                        let cfg = z3::Config::new();
                        let ctx = z3::Context::new(&cfg);
                        let mut enc = smt::SmtEncoder::new(&ctx);
                        enc.load(&current_store, &relations);
                        println!("{}", enc.to_smtlib());
                    }
                    continue;
                }

                if let Some(rest) = line.strip_prefix("::smt ") {
                    if !smt_command(rest.trim(), &current_store, format) {
                        had_failure = true;
                    }
                    continue;
                }

                if let Some(name) = line.strip_prefix("::snapshot ") {
                    let name = name.trim().to_string();
                    let snap = Snapshot::from_eval(&current_store, Scope::All);
                    let rc = snap.relation_count();
                    let fc = snap.fact_count();
                    for (rel, tuples) in snap.iter() {
                        let namespaced = format!("{name}__{rel}");
                        for tuple in tuples {
                            engine.add_fact(namespaced.clone(), tuple.clone());
                        }
                    }
                    snapshot_counter += 1;
                    let version = snapshot_counter;
                    snapshot_names.insert(name.clone(), version);
                    snapshot_data.insert(version, snap);
                    match engine.evaluate() {
                        Ok(new_store) => {
                            current_store = new_store;
                            println!(
                                "Saved snapshot '{name}' v{version} ({rc} relations, {fc} facts)."
                            );
                        }
                        Err(e) => eprintln!("Error: {e:#}"),
                    }
                    continue;
                }

                if let Some(rest) = line.strip_prefix("::diff ") {
                    let parts: Vec<&str> = rest.trim().splitn(2, ' ').collect();
                    let lookup = |n: &str| -> Option<&Snapshot> {
                        snapshot_names.get(n).and_then(|v| snapshot_data.get(v))
                    };
                    let (before, after_snap) = match parts.as_slice() {
                        [name] => match lookup(name) {
                            Some(s) => (s, None),
                            None => {
                                eprintln!("No snapshot named '{}'.", name);
                                continue;
                            }
                        },
                        [name1, name2] => {
                            let s1 = match lookup(name1) {
                                Some(s) => s,
                                None => {
                                    eprintln!("No snapshot named '{}'.", name1);
                                    continue;
                                }
                            };
                            let s2 = match lookup(name2) {
                                Some(s) => s,
                                None => {
                                    eprintln!("No snapshot named '{}'.", name2);
                                    continue;
                                }
                            };
                            (s1, Some(s2))
                        }
                        _ => {
                            eprintln!("Usage: ::diff <name>  or  ::diff <name1> <name2>");
                            continue;
                        }
                    };
                    let current_snap;
                    let after: &Snapshot = match after_snap {
                        Some(s) => s,
                        None => {
                            current_snap = Snapshot::from_eval(&current_store, Scope::All);
                            &current_snap
                        }
                    };
                    let diff = Diff::between(before, after);
                    print!("{diff}");
                    continue;
                }

                if let Some(rest) = line.strip_prefix("::access-diff ") {
                    let parts: Vec<&str> = rest.trim().splitn(2, ' ').collect();
                    let lookup = |n: &str| -> Option<&Snapshot> {
                        snapshot_names.get(n).and_then(|v| snapshot_data.get(v))
                    };

                    match parts.as_slice() {
                        [name] => {
                            let Some(before_snap) = lookup(name) else {
                                eprintln!("No snapshot named '{}'.", name);
                                continue;
                            };
                            let cfg = z3::Config::new();
                            let ctx = z3::Context::new(&cfg);
                            let mut enc = smt::SmtEncoder::new(&ctx);
                            enc.assert_rbac_axioms_from_snapshot_as(before_snap, name);
                            enc.assert_rbac_axioms_as(&current_store, "current");
                            print_access_diff(&enc, name, "current");
                        }
                        [name1, name2] => {
                            let Some(s1) = lookup(name1) else {
                                eprintln!("No snapshot named '{}'.", name1);
                                continue;
                            };
                            let Some(s2) = lookup(name2) else {
                                eprintln!("No snapshot named '{}'.", name2);
                                continue;
                            };
                            let cfg = z3::Config::new();
                            let ctx = z3::Context::new(&cfg);
                            let mut enc = smt::SmtEncoder::new(&ctx);
                            enc.assert_rbac_axioms_from_snapshot_as(s1, name1);
                            enc.assert_rbac_axioms_from_snapshot_as(s2, name2);
                            print_access_diff(&enc, name1, name2);
                        }
                        _ => eprintln!(
                            "Usage: ::access-diff <snap>  or  ::access-diff <snap1> <snap2>"
                        ),
                    }
                    continue;
                }

                if let Some(rule) = line.strip_prefix("::define ") {
                    let checkpoint = engine.rules_len();
                    if let Err(e) =
                        engine.add_rule(format!("{}.", rule.trim_end_matches('.').trim()))
                    {
                        engine.truncate_rules(checkpoint);
                        eprintln!("Error: {e:#}");
                        continue;
                    }
                    match engine.evaluate() {
                        Ok(new_store) => {
                            current_store = new_store;
                            eprintln!("Rule added and evaluated.");
                        }
                        Err(e) => {
                            engine.truncate_rules(checkpoint);
                            eprintln!("Error: {e:#}");
                        }
                    }
                    continue;
                }

                if let Some(rest) = line.strip_prefix("::source ") {
                    let src = rest.trim();
                    match load::read_source(src) {
                        Ok(bytes) => match std::str::from_utf8(&bytes) {
                            Ok(text) => {
                                let checkpoint = engine.rules_len();
                                if let Err(e) = engine.add_rule(text.to_string()) {
                                    engine.truncate_rules(checkpoint);
                                    eprintln!("Error: {e:#}");
                                    continue;
                                }
                                match engine.evaluate() {
                                    Ok(new_store) => {
                                        current_store = new_store;
                                        eprintln!("Sourced and evaluated.");
                                    }
                                    Err(e) => {
                                        engine.truncate_rules(checkpoint);
                                        eprintln!("Error: {e:#}");
                                    }
                                }
                            }
                            Err(e) => eprintln!("Source error: not valid UTF-8: {e}"),
                        },
                        Err(e) => eprintln!("Source error: {e:#}"),
                    }
                    continue;
                }

                if let Some(rest) = line.strip_prefix("::load-k8s ") {
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
                        Ok(()) => match engine.evaluate() {
                            Ok(new_store) => {
                                current_store = new_store;
                                eprintln!("Loaded and evaluated.");
                            }
                            Err(e) => eprintln!("Error: {e:#}"),
                        },
                        Err(e) => eprintln!("Load error: {e:#}"),
                    }
                    continue;
                }

                if let Some(rest) = line.strip_prefix("::load ") {
                    let rest = rest.trim();
                    // Split on first whitespace: <relation> <source>
                    let (relation, source) = match rest.find(|c: char| c.is_whitespace()) {
                        Some(idx) => (&rest[..idx], rest[idx + 1..].trim()),
                        None => {
                            eprintln!(
                                "Usage: ::load <relation> <source>  (source is a file path or ! <cmd>)"
                            );
                            continue;
                        }
                    };
                    match load::load_tuples(engine, relation, source) {
                        Ok(n) => match engine.evaluate() {
                            Ok(new_store) => {
                                current_store = new_store;
                                eprintln!("Inserted {n} fact(s) into {relation} and evaluated.");
                            }
                            Err(e) => eprintln!("Error: {e:#}"),
                        },
                        Err(e) => eprintln!("Load error: {e:#}"),
                    }
                    continue;
                }

                // ~pred(old...). pred(new...).  — atomic replace (retract + insert, one eval)
                if let Some(rest) = line.strip_prefix('~') {
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
                                        eprintln!(
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
                                                if removed {
                                                    println!("Replaced.");
                                                } else {
                                                    println!(
                                                        "Warning: old fact not found; new fact inserted."
                                                    );
                                                }
                                            }
                                            Err(e) => eprintln!("Error: {e:#}"),
                                        }
                                    }
                                }
                                Err(e) => eprintln!("Parse error: {e}"),
                            }
                        }
                        None => eprintln!("Usage: ~pred(old_args). pred(new_args)."),
                    }
                    continue;
                }

                // +pred(args).  — insert ground fact
                if let Some(inner) = line.strip_prefix('+') {
                    let inner = inner.trim_end_matches('.').trim();
                    match parse_ground_tuple(inner) {
                        Ok((rel, tuple)) => {
                            if let Some(arity) = engine.relation_arity(&rel)
                                && tuple.len() != arity
                            {
                                eprintln!(
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
                                            eprintln!("Asserted.");
                                        }
                                        Err(e) => eprintln!("Error: {e:#}"),
                                    }
                                }
                            } else {
                                eprintln!("Fact already exists.");
                            }
                        }
                        Err(e) => eprintln!("Parse error: {e}"),
                    }
                    continue;
                }

                // -pred(args).  — retract ground fact
                if let Some(inner) = line.strip_prefix('-') {
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
                                            eprintln!("Retracted.");
                                        }
                                        Err(e) => eprintln!("Error: {e:#}"),
                                    }
                                }
                            } else {
                                eprintln!("No matching fact found.");
                            }
                        }
                        Err(e) => eprintln!("Parse error: {e}"),
                    }
                    continue;
                }

                // ::match <Kind> <namespace> <selector>  — scoped to one Kind
                if let Some(rest) = line.strip_prefix("::match ") {
                    let parts: Vec<&str> = rest.trim().splitn(3, char::is_whitespace).collect();
                    match parts.as_slice() {
                        [kind, namespace, selector] => {
                            run_match(engine, Some(kind), namespace, selector, format);
                        }
                        _ => eprintln!(
                            "Usage: ::match <Kind> <namespace> <selector>  (namespace \"\" for cluster-scoped)"
                        ),
                    }
                    continue;
                }

                // ::match_all <namespace> <selector>  — any Kind
                if let Some(rest) = line.strip_prefix("::match_all ") {
                    let parts: Vec<&str> = rest.trim().splitn(2, char::is_whitespace).collect();
                    match parts.as_slice() {
                        [namespace, selector] => {
                            run_match(engine, None, namespace, selector, format);
                        }
                        _ => eprintln!("Usage: ::match_all <namespace> <selector>"),
                    }
                    continue;
                }

                // Everything else is not a command. Queries go through `?-`.
                if line.starts_with("::") {
                    eprintln!("Unknown command: {line} (try \\help)");
                } else {
                    eprintln!("Not a command. Queries start with ?-, e.g. ?- {line}");
                }
            }
            Err(ReadlineError::Interrupted) => continue,
            Err(ReadlineError::Eof) => break,
            Err(e) => {
                eprintln!("Error: {e}");
                break;
            }
        }
    }

    let _ = rl.save_history(&history_path);
    Ok(!had_failure)
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

fn fmt_binding(p: &smt::AccessPath) -> String {
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
fn path_sig(p: &smt::AccessPath) -> String {
    let hops: String = p
        .hops
        .iter()
        .map(|(a, b)| format!("{a}#{b}"))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{}|{}|{}|{}",
        hops, p.binding_kind, p.binding_namespace, p.binding_name
    )
}

fn print_violation_paths(paths: &[smt::AccessPath]) {
    // Group paths by identical hop chain: print "via X [mech]" once, then list
    // all bindings of the target underneath it rather than repeating the header.
    let mut by_hops: BTreeMap<&Vec<(String, String)>, Vec<&smt::AccessPath>> = BTreeMap::new();
    for p in paths {
        by_hops.entry(&p.hops).or_default().push(p);
    }
    for (hops, group) in &by_hops {
        if hops.is_empty() {
            for p in group {
                println!("          {}", fmt_binding(p));
            }
        } else {
            let (id, mech) = &hops[0];
            println!("          via {id}{}", mech_str(mech));
            for (id, mech) in hops[1..].iter() {
                println!("            → via {id}{}", mech_str(mech));
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
/// `kind_of` annotates non-serviceaccount principals with their subject kind.
/// Pass `|_| ""` to suppress annotation.
fn print_reaches_grouped(violations: &[smt::Violation], kind_of: &dyn Fn(&str) -> &'static str) {
    // Preserve first-seen order for paths; use a Vec<key> + BTreeMap for lookup.
    let mut order: Vec<String> = Vec::new();
    let mut groups: BTreeMap<String, (Vec<smt::AccessPath>, Vec<String>)> = BTreeMap::new();
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
        for p in principals {
            let kind = kind_of(p);
            if kind.is_empty() || kind == "serviceaccount" {
                println!("            {p}");
            } else {
                println!("            {p} ({kind})");
            }
        }
    }
}

fn print_access_diff(enc: &smt::SmtEncoder<'_>, before_label: &str, after_label: &str) {
    let can_gained = enc.check_permission_expansion(before_label, after_label);
    let can_lost = enc.check_permission_contraction(before_label, after_label);
    let eff_gained = enc.check_effective_can_expansion(before_label, after_label);
    let eff_lost = enc.check_effective_can_contraction(before_label, after_label);

    let total_gained = can_gained.len() + eff_gained.len();
    let total_lost = can_lost.len() + eff_lost.len();

    if total_gained > 0 {
        println!("FAIL  {} new permission(s) granted", total_gained);
    } else if total_lost > 0 {
        println!("PASS  {} permission(s) removed, none added", total_lost);
    } else {
        println!("PASS  no permission changes");
        return;
    }

    let verdicts = per_principal_verdicts(&can_gained, &can_lost, &eff_gained, &eff_lost);

    println!(
        "=== Access diff: '{}' → '{}' ===",
        before_label, after_label
    );
    if !verdicts.is_empty() {
        println!();
        println!("  Per-principal:");
        let col_w = verdicts
            .iter()
            .map(|(p, _, _)| p.len())
            .max()
            .unwrap_or(8)
            .min(32);
        for (principal, gained, lost) in &verdicts {
            let label = if *gained > 0 { "FAIL" } else { "PASS" };
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
        let via_rel = smt::rbac_model::fn_name("indirect_perm", after_label);
        print_eff_diffs_grouped(&eff_gained, &via_rel, &enc.facts);
    }
    if !eff_lost.is_empty() {
        println!("  EFFECTIVE LOST ({}) [escalation-aware]:", eff_lost.len());
        let via_rel = smt::rbac_model::fn_name("indirect_perm", before_label);
        print_eff_diffs_grouped(&eff_lost, &via_rel, &enc.facts);
    }
}

fn per_principal_verdicts(
    can_gained: &[smt::diff::CanDiff],
    can_lost: &[smt::diff::CanDiff],
    eff_gained: &[smt::diff::EffDiff],
    eff_lost: &[smt::diff::EffDiff],
) -> Vec<(String, usize, usize)> {
    let mut map: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for d in can_gained {
        map.entry(d.principal.clone()).or_default().0 += 1;
    }
    for d in eff_gained {
        map.entry(d.principal.clone()).or_default().0 += 1;
    }
    for d in can_lost {
        map.entry(d.principal.clone()).or_default().1 += 1;
    }
    for d in eff_lost {
        map.entry(d.principal.clone()).or_default().1 += 1;
    }

    let mut result: Vec<(String, usize, usize)> = map
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
/// Looks up `indirect_perm` facts to find which SA each permission came
/// through. Permissions not found there were gained directly.
fn print_eff_diffs_grouped(
    diffs: &[smt::diff::EffDiff],
    via_rel: &str,
    facts: &HashMap<String, Vec<Vec<mangle_common::Value>>>,
) {
    // (principal, target) → indices into diffs. Empty target = direct grant.
    let mut groups: BTreeMap<(String, String), Vec<usize>> = BTreeMap::new();

    for (i, d) in diffs.iter().enumerate() {
        let targets = find_via_targets(
            facts,
            via_rel,
            &d.principal,
            &d.namespace,
            &d.apigroup,
            &d.resource,
            &d.verb,
        );
        if targets.is_empty() {
            groups
                .entry((d.principal.clone(), String::new()))
                .or_default()
                .push(i);
        } else {
            for target in targets {
                groups
                    .entry((d.principal.clone(), target))
                    .or_default()
                    .push(i);
            }
        }
    }

    for ((principal, target), indices) in &groups {
        if target.is_empty() {
            println!("    {}  [direct]:", principal);
        } else {
            println!("    {}  via {}:", principal, target);
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

/// Return all Target values from `indirect_perm` matching the given 5-tuple.
fn find_via_targets(
    facts: &HashMap<String, Vec<Vec<mangle_common::Value>>>,
    rel_name: &str,
    principal: &str,
    namespace: &str,
    apigroup: &str,
    resource: &str,
    verb: &str,
) -> Vec<String> {
    use mangle_common::Value;
    facts
        .get(rel_name)
        .into_iter()
        .flatten()
        .filter_map(|row| {
            if let [
                Value::String(p),
                Value::String(ns),
                Value::String(ag),
                Value::String(r),
                Value::String(v),
                Value::String(target),
            ] = row.as_slice()
            {
                if p == principal && ns == namespace && ag == apigroup && r == resource && v == verb
                {
                    Some(target.clone())
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect()
}

/// JSON form of a violation's explaining binding paths (ndjson output).
fn paths_json(paths: &[smt::AccessPath]) -> Vec<serde_json::Value> {
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
                    .map(|(id, mech)| serde_json::json!({"identity": id, "mechanism": mech}))
                    .collect::<Vec<_>>(),
            })
        })
        .collect()
}

/// Run an `::smt` subcommand. Returns `false` when the check reported a
/// failure (a `FAIL` line in plain output, `"result":"fail"` in ndjson), so the
/// caller can turn it into a nonzero exit status. Usage errors and unknown
/// subcommands return `true`: they are not check results.
fn smt_command(input: &str, store: &EvalStore, format: OutputFormat) -> bool {
    let ndjson = format == OutputFormat::Ndjson;
    let mut tokens = input.splitn(2, ' ');
    let subcommand = tokens.next().unwrap_or("").trim();
    let rest = tokens.next().unwrap_or("").trim();

    match subcommand {
        "check_access" => {
            let mut args = rest.split_whitespace();
            let (Some(ns_raw), Some(res_raw), Some(verb_raw)) =
                (args.next(), args.next(), args.next())
            else {
                eprintln!(
                    "Usage: ::smt check_access <namespace> <resource> <verb> [expected_principal ...]"
                );
                eprintln!("       Use \"\" for namespace to check cluster-wide (CRB) grants.");
                return true;
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

            let cfg = z3::Config::new();
            let ctx = z3::Context::new(&cfg);
            let mut enc = smt::SmtEncoder::new(&ctx);
            enc.assert_rbac_axioms(store);

            let violations = enc.check_access_invariant(namespace, resource, verb, &expected);
            if violations.is_empty() {
                if ndjson {
                    println!(
                        "{}",
                        serde_json::json!({"result":"pass","check":"check_access","namespace":namespace,"resource":resource,"verb":verb})
                    );
                } else {
                    println!("PASS  can(_, {namespace:?}, {resource:?}, {verb:?})");
                }
                true
            } else {
                if ndjson {
                    for v in &violations {
                        println!(
                            "{}",
                            serde_json::json!({
                                "result": "fail",
                                "check": "check_access",
                                "principal": v.principal,
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
                            "        UNEXPECTED can({:?}, {:?}, {:?}, {:?})",
                            v.principal, v.namespace, v.resource, v.verb
                        );
                        print_violation_paths(&v.paths);
                    }
                }
                false
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
                        "Usage: ::smt reaches <namespace> <apigroup> <resource> <verb> [--direct] [--all] [expected ...]"
                    );
                    eprintln!(
                        "       Use ::smt cluster-admin [--direct] [--all] to check for cluster-admin level access."
                    );
                    return true;
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

            let cfg = z3::Config::new();
            let ctx = z3::Context::new(&cfg);
            let mut enc = smt::SmtEncoder::new(&ctx);
            enc.assert_rbac_axioms(store);

            enc.include_builtins = include_builtins;
            let direct = enc.direct_violations(namespace, apigroup, resource, verb);
            let via = enc.check_reaches(
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
                true
            } else {
                if ndjson {
                    let emit_violations = |violations: &[smt::Violation], kind: &str| {
                        for v in violations {
                            println!(
                                "{}",
                                serde_json::json!({
                                    "result": "fail",
                                    "check": subcommand,
                                    "kind": kind,
                                    "principal": v.principal,
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
                    let kind_of = |p: &str| enc.principal_kind(p);
                    if !direct.is_empty() {
                        println!("  direct ({}):", direct.len());
                        print_reaches_grouped(&direct, &kind_of);
                    }
                    if !via.is_empty() {
                        println!();
                        println!("  via escalation ({}):", via.len());
                        print_reaches_grouped(&via, &kind_of);
                    }
                }
                false
            }
        }
        "check_isolation" => {
            let mut args = rest.split_whitespace();
            let Some(ns_raw) = args.next() else {
                eprintln!("Usage: ::smt check_isolation <namespace> [allowed_principal ...]");
                eprintln!(
                    "       Proves that ONLY the listed principals have any access in <namespace>."
                );
                return true;
            };
            let namespace = ns_raw.trim_matches('"');
            let allowed_owned: Vec<String> = args
                .filter(|s| !matches!(*s, "[]" | "[" | "]"))
                .map(|s| s.trim_matches('"').to_string())
                .collect();
            let allowed: Vec<&str> = allowed_owned.iter().map(String::as_str).collect();

            let cfg = z3::Config::new();
            let ctx = z3::Context::new(&cfg);
            let mut enc = smt::SmtEncoder::new(&ctx);
            enc.assert_rbac_axioms(store);

            let violations = enc.check_namespace_isolation(namespace, &allowed);
            if violations.is_empty() {
                if ndjson {
                    println!(
                        "{}",
                        serde_json::json!({"result":"pass","check":"check_isolation","namespace":namespace})
                    );
                } else {
                    println!(
                        "PASS  namespace {namespace:?} is isolated to the expected principals (Z3 UNSAT proof)"
                    );
                }
                true
            } else {
                if ndjson {
                    for v in &violations {
                        println!(
                            "{}",
                            serde_json::json!({"result":"fail","check":"check_isolation","principal":v.principal,"namespace":v.namespace,"resource":v.resource,"verb":v.verb})
                        );
                    }
                } else {
                    println!(
                        "FAIL  {} unexpected principal(s) have access in {namespace:?}:",
                        violations.len()
                    );
                    for v in &violations {
                        println!(
                            "        UNEXPECTED can({:?}, {:?}, {:?}, {:?})",
                            v.principal, v.namespace, v.resource, v.verb
                        );
                    }
                }
                false
            }
        }
        "node_selector" => {
            let unschedulable = smt::scheduling::check_node_selector(store);
            if unschedulable.is_empty() {
                if ndjson {
                    println!(
                        "{}",
                        serde_json::json!({"result":"pass","check":"node_selector"})
                    );
                } else {
                    println!("PASS  all pods with nodeSelectors are schedulable");
                }
                true
            } else {
                if ndjson {
                    for p in &unschedulable {
                        println!(
                            "{}",
                            serde_json::json!({"result":"fail","check":"node_selector","namespace":p.namespace,"pod":p.name})
                        );
                    }
                } else {
                    println!("FAIL  {} unschedulable pod(s):", unschedulable.len());
                    for p in &unschedulable {
                        println!("        {}/{}", p.namespace, p.name);
                    }
                }
                false
            }
        }
        "anti_affinity" => {
            use smt::scheduling::PlacementResult;
            match smt::scheduling::check_anti_affinity_placement(store) {
                PlacementResult::Sat(assignment) if assignment.is_empty() => {
                    if ndjson {
                        println!(
                            "{}",
                            serde_json::json!({"result":"pass","check":"anti_affinity"})
                        );
                    } else {
                        println!("PASS  no anti-affinity conflicts found");
                    }
                    true
                }
                PlacementResult::Sat(mut assignment) => {
                    assignment.sort_by(|a, b| a.0.cmp(&b.0));
                    if ndjson {
                        for (pod, node) in &assignment {
                            println!(
                                "{}",
                                serde_json::json!({"result":"pass","check":"anti_affinity","pod":pod,"node":node})
                            );
                        }
                    } else {
                        println!("PASS  valid placement found ({} pods):", assignment.len());
                        for (pod, node) in &assignment {
                            println!("        {pod} → {node}");
                        }
                    }
                    true
                }
                PlacementResult::Unsat => {
                    if ndjson {
                        println!(
                            "{}",
                            serde_json::json!({"result":"fail","check":"anti_affinity"})
                        );
                    } else {
                        println!(
                            "FAIL  no valid placement exists — anti-affinity constraints unsatisfiable"
                        );
                    }
                    false
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
                true
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
                false
            }
        }
        _ => {
            eprintln!("Unknown SMT subcommand: {subcommand:?}");
            eprintln!(
                "Available: check_access, reaches, cluster-admin, node_selector, anti_affinity, karpenter"
            );
            true
        }
    }
}

fn dirs_home() -> std::path::PathBuf {
    std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
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

/// Parse a ground atom like `pred("a", "b", 42)` into `(relation, Vec<Value>)`.
/// Rejects any variable (`_` or uppercase-initial) — only ground terms allowed.
fn parse_ground_tuple(input: &str) -> anyhow::Result<(String, Vec<mangle_common::Value>)> {
    let q = query::parse_query(input)?;
    let mut tuple = Vec::with_capacity(q.args.len());
    for arg in &q.args {
        match arg {
            query::QueryArg::Variable => {
                anyhow::bail!("all arguments must be ground constants (no variables or `_`)");
            }
            query::QueryArg::StringConst(s) => tuple.push(mangle_common::Value::String(s.clone())),
            query::QueryArg::NameConst(s) => tuple.push(mangle_common::Value::Name(s.clone())),
            query::QueryArg::NumberConst(n) => tuple.push(mangle_common::Value::Number(*n)),
        }
    }
    Ok((q.predicate, tuple))
}

/// Rewrite `snapshot->relation` to the internal `snapshot__relation` form,
/// skipping inside string literals. Applied before any Mangle parsing so that
/// `before->can(P, NS, AG, R, V)` and rule bodies work transparently.
fn rewrite_snapshot_refs(s: &str) -> String {
    if !s.contains("->") {
        return s.to_string();
    }
    let mut result = String::with_capacity(s.len());
    let mut in_string = false;
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '"' => {
                in_string = !in_string;
                result.push('"');
                i += 1;
            }
            '-' if !in_string && i + 1 < chars.len() && chars[i + 1] == '>' => {
                result.push_str("__");
                i += 2;
            }
            c => {
                result.push(c);
                i += 1;
            }
        }
    }
    result
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
/// missing trailing arguments match anything.
fn list_tuples(
    engine: &Engine,
    store: &EvalStore,
    format: OutputFormat,
    rel: &str,
    body: &str,
    cols: &[String],
) {
    let live: Vec<Vec<Value>>;
    let rows: &[Vec<Value>] = if engine.has_session() {
        live = engine.query_live(rel);
        &live
    } else {
        store.scan(rel)
    };
    let q = match split_atom(body) {
        Some((_, inner)) if !inner.trim().is_empty() => match query::parse_query(body) {
            Ok(q) => q,
            Err(e) => {
                eprintln!("Parse error: {e}");
                return;
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
        return;
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
        return;
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

/// Up to three known relations close to `name`, nearest first. Query results
/// (`_N`) and snapshot copies (`x__rel`) are not suggested.
fn suggest(name: &str, known: &std::collections::HashSet<String>) -> Vec<String> {
    let mut scored: Vec<(usize, &String)> = known
        .iter()
        .filter(|k| !k.starts_with('_') && !k.contains("__"))
        .map(|k| (edit_distance(name, k), k))
        .filter(|(d, _)| *d <= 2.max(name.len() / 4))
        .collect();
    scored.sort();
    scored.into_iter().take(3).map(|(_, k)| k.clone()).collect()
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
        let known: std::collections::HashSet<String> = [
            "direct_perm",
            "indirect_perm",
            "pod",
            "_0",
            "a__direct_perm",
        ]
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
    use crate::smt::AccessPath;

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
