use std::collections::HashMap;

use anyhow::Result;
use mangle_common::Value;
use mangle_interpreter::ProvenanceEntry;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;

use crate::edb::{FixtureSource, JsonFileSource, KubectlSource};
use crate::snapshot::{Diff, Scope, Snapshot};
use crate::engine::{Engine, EvalStore};
use crate::load;
use crate::query;
use crate::smt;

pub fn run(engine: &mut Engine, store: EvalStore) -> Result<()> {
    println!("\n=== Interactive Query Mode ===");
    println!("Commands:");
    println!("  <predicate>                        — show all tuples");
    println!("  <predicate>(arg, _, ...)           — filter by constants (_ or uppercase vars match any)");
    println!("  orphaned_sa(\"kube-system\", _)      — example: filter by namespace");
    println!("  ::show all                         — list all known predicates with arity");
    println!("  ::arity <rel>                      — show arity of a single relation");
    println!("  ::define <rule>.                   — add a rule and re-evaluate");
    println!("  ::pretty                           — toggle compact/pretty tuple display");
    println!("  ::query <body>  / ?- <body>         — evaluate a one-shot conjunctive query");
    println!("  ::smt check_access <ns> <r> <v> [p...] — Z3: find principals in can(_,ns,r,v) outside expected set (ns=\"\" for cluster-wide)");
    println!("  ::smt node_selector                — Z3: find pods whose nodeSelector no node satisfies");
    println!("  ::smt anti_affinity                — Z3: find a valid pod placement or prove none exists");
    println!("  can(P, Namespace, ApiGroup, R, V)  — ApiGroup=\"\" for core, \"*\" for wildcard; Namespace scoped to binding");
    println!("  ::smtlib <rel> [rel...]            — dump SMT-LIB 2 encoding of relations");
    println!("  ::why <pred>(<args>...)             — show derivation tree for a fact");
    println!("  +pred(arg1, arg2, ...).             — insert a ground fact into the EDB and re-evaluate");
    println!("  -pred(arg1, arg2, ...).             — retract a ground fact from the EDB and re-evaluate");
    println!("  ~pred(old...). pred(new...).        — atomic replace: retract old, insert new, single re-evaluate");
    println!("  ::source <src>                     — load raw Mangle rules from a file or ! <cmd> and re-evaluate");
    println!("  ::load <rel> <src>                 — load flat JSON tuples into <rel>; src is a file path or ! <cmd>");
    println!("  ::load-k8s <src>                   — load k8s objects through the projection pipeline; src is a dir, .json file, or ! <kubectl args>");
    println!("  ::snapshot <name>                  — save current eval state as a named snapshot");
    println!("  ::diff <name>                      — diff current state against named snapshot");
    println!("  ::diff <name1> <name2>             — diff two named snapshots");
    println!("  ::access-diff <name>               — diff RBAC can/5 permission closure vs named snapshot");
    println!("  ::access-diff <name1> <name2>      — diff RBAC can/5 between two named snapshots");
    println!("  ::reset                            — clear session state (_N results, ::define rules, + facts), re-evaluate");
    println!("  ::quit                             — exit");
    println!();

    let history_path = dirs_home().join(".pallograph_history");
    let mut rl = DefaultEditor::new()?;
    let _ = rl.load_history(&history_path);

    let mut current_store = store;
    let mut pretty = false;
    let mut query_counter: u32 = 0;
    let mut snapshot_counter: u64 = 0;
    let mut snapshot_names: HashMap<String, u64> = HashMap::new();
    let mut snapshot_data: HashMap<u64, Snapshot> = HashMap::new();

    loop {
        let readline = rl.readline("pallograph> ");
        match readline {
            Ok(line) => {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                rl.add_history_entry(&line)?;
                // Rewrite snapshot->relation references to snapshot__relation before parsing.
                let line = rewrite_snapshot_refs(&line);

                if line == "::quit" || line == "::exit" || line == "::q" {
                    break;
                }
                if line == "::pretty" {
                    pretty = !pretty;
                    println!("Pretty printing {}.", if pretty { "enabled" } else { "disabled" });
                    continue;
                }
                if line == "::show all" {
                    let mut names: Vec<&str> = current_store.relation_names()
                        .filter(|n| !n.starts_with(':'))
                        .collect();
                    names.sort_unstable();
                    for n in names {
                        match current_store.scan(n).first().map(|t| t.len()) {
                            Some(arity) => println!("  {n}/{arity}"),
                            None => println!("  {n} (empty)"),
                        }
                    }
                    continue;
                }
                if let Some(rel) = line.strip_prefix("::arity ") {
                    let rel = rel.trim();
                    match current_store.scan(rel).first().map(|t| t.len()) {
                        Some(arity) => println!("{rel}/{arity}"),
                        None => println!("Unknown relation '{rel}'."),
                    }
                    continue;
                }
                if let Some(raw_body) = line.strip_prefix("::query ").or_else(|| line.strip_prefix("?- ")) {
                    let raw_body = raw_body.trim();
                    let (body, vars) = {
                        let existing = extract_vars(raw_body);
                        match auto_complete_partial(raw_body, &current_store) {
                            Some((new_body, added)) => {
                                let mut all_vars = existing;
                                all_vars.extend(added);
                                (new_body, all_vars)
                            }
                            None if existing.is_empty() => {
                                eprintln!("No variables found — use uppercase names for variables.");
                                continue;
                            }
                            None => (raw_body.to_string(), existing),
                        }
                    };
                    let body = body.as_str();
                    let result_name = format!("_{query_counter}");
                    let rule = format!("{result_name}({}) :- {body}.", vars.join(", "));
                    engine.add_rule(rule);
                    match engine.evaluate() {
                        Ok(new_store) => {
                            current_store = new_store;
                            let tuples = current_store.scan(&result_name).to_vec();
                            if tuples.is_empty() {
                                println!("No results.");
                                engine.remove_rules_for(&result_name);
                            } else {
                                for tuple in &tuples {
                                    let parts: Vec<String> = vars
                                        .iter()
                                        .zip(tuple.iter())
                                        .map(|(name, val)| format!("{name} = {val}"))
                                        .collect();
                                    println!("  {}", parts.join(", "));
                                }
                                println!("Found {} result(s): (→ {result_name})", tuples.len());
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
                    let rest = rest.trim();
                    match query::parse_query(rest) {
                        Ok(q) => {
                            let rows = current_store.scan(&q.predicate);
                            let matched = query::filter_tuples(rows, &q);
                            if matched.is_empty() {
                                println!("No matching facts for '{rest}'.");
                            } else {
                                let index = build_provenance_index(&current_store.provenance);
                                for tuple in matched {
                                    println!("{}({})", q.predicate, tuple.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(", "));
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
                    smt_command(rest.trim(), &current_store);
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
                            println!("Saved snapshot '{name}' v{version} ({rc} relations, {fc} facts).");
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
                        [name] => {
                            match lookup(name) {
                                Some(s) => (s, None),
                                None => { eprintln!("No snapshot named '{}'.", name); continue; }
                            }
                        }
                        [name1, name2] => {
                            let s1 = match lookup(name1) {
                                Some(s) => s,
                                None => { eprintln!("No snapshot named '{}'.", name1); continue; }
                            };
                            let s2 = match lookup(name2) {
                                Some(s) => s,
                                None => { eprintln!("No snapshot named '{}'.", name2); continue; }
                            };
                            (s1, Some(s2))
                        }
                        _ => { eprintln!("Usage: ::diff <name>  or  ::diff <name1> <name2>"); continue; }
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
                        _ => eprintln!("Usage: ::access-diff <snap>  or  ::access-diff <snap1> <snap2>"),
                    }
                    continue;
                }

                if let Some(rule) = line.strip_prefix("::define ") {
                    let checkpoint = engine.rules_len();
                    engine.add_rule(rule.trim_end_matches('.').trim().to_string());
                    match engine.evaluate() {
                        Ok(new_store) => {
                            current_store = new_store;
                            println!("Rule added and evaluated.");
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
                                engine.add_rule(text.to_string());
                                match engine.evaluate() {
                                    Ok(new_store) => {
                                        current_store = new_store;
                                        println!("Sourced and evaluated.");
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
                        if rest.starts_with('!') {
                            let args: Vec<String> = rest[1..].split_whitespace().map(String::from).collect();
                            Ok(Box::new(KubectlSource { args }))
                        } else if std::path::Path::new(rest).is_dir() {
                            Ok(Box::new(FixtureSource { dir: rest.into() }))
                        } else {
                            Ok(Box::new(JsonFileSource { path: rest.into() }))
                        };
                    match source_result.and_then(|mut src| engine.populate_from(src.as_mut())) {
                        Ok(()) => match engine.evaluate() {
                            Ok(new_store) => {
                                current_store = new_store;
                                println!("Loaded and evaluated.");
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
                            eprintln!("Usage: ::load <relation> <source>  (source is a file path or ! <cmd>)");
                            continue;
                        }
                    };
                    match load::load_tuples(engine, relation, source) {
                        Ok(n) => match engine.evaluate() {
                            Ok(new_store) => {
                                current_store = new_store;
                                println!("Inserted {n} fact(s) into {relation} and evaluated.");
                            }
                            Err(e) => eprintln!("Error: {e:#}"),
                        },
                        Err(e) => eprintln!("Load error: {e:#}"),
                    }
                    continue;
                }

                // ~pred(old...). pred(new...).  — atomic replace (retract + insert, one eval)
                if line.starts_with('~') {
                    let rest = line[1..].trim();
                    // Split into two atoms at the boundary between "). " and the next predicate.
                    match split_two_atoms(rest) {
                        Some((old_atom, new_atom)) => {
                            let result = parse_ground_tuple(old_atom)
                                .and_then(|(rel, tuple)| {
                                    parse_ground_tuple(new_atom).map(|n| ((rel, tuple), n))
                                });
                            match result {
                                Ok(((old_rel, old_tuple), (new_rel, new_tuple))) => {
                                    if let Some(arity) = engine.relation_arity(&new_rel) {
                                        if new_tuple.len() != arity {
                                            eprintln!("arity mismatch: {new_rel}/{arity} expects {arity} arg(s), got {}", new_tuple.len());
                                            continue;
                                        }
                                    }
                                    let removed = engine.retract_fact(&old_rel, &old_tuple);
                                    engine.add_fact(new_rel, new_tuple);
                                    match engine.evaluate() {
                                        Ok(new_store) => {
                                            current_store = new_store;
                                            if removed {
                                                println!("Replaced.");
                                            } else {
                                                println!("Warning: old fact not found; new fact inserted.");
                                            }
                                        }
                                        Err(e) => eprintln!("Error: {e:#}"),
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
                if line.starts_with('+') {
                    let inner = line[1..].trim_end_matches('.').trim();
                    match parse_ground_tuple(inner) {
                        Ok((rel, tuple)) => {
                            if let Some(arity) = engine.relation_arity(&rel) {
                                if tuple.len() != arity {
                                    eprintln!("arity mismatch: {rel}/{arity} expects {arity} arg(s), got {}", tuple.len());
                                    continue;
                                }
                            }
                            if engine.add_fact(rel, tuple) {
                                match engine.evaluate() {
                                    Ok(new_store) => {
                                        current_store = new_store;
                                        println!("Asserted.");
                                    }
                                    Err(e) => eprintln!("Error: {e:#}"),
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
                if line.starts_with('-') {
                    let inner = line[1..].trim_end_matches('.').trim();
                    match parse_ground_tuple(inner) {
                        Ok((rel, tuple)) => {
                            if engine.retract_fact(&rel, &tuple) {
                                match engine.evaluate() {
                                    Ok(new_store) => {
                                        current_store = new_store;
                                        println!("Retracted.");
                                    }
                                    Err(e) => eprintln!("Error: {e:#}"),
                                }
                            } else {
                                println!("No matching fact found.");
                            }
                        }
                        Err(e) => eprintln!("Parse error: {e}"),
                    }
                    continue;
                }

                if line.contains('(') {
                    match query::parse_query(&line) {
                        Ok(q) => {
                            let rows = current_store.scan(&q.predicate);
                            let matched = query::filter_tuples(rows, &q);
                            let pred = &q.predicate;
                            if matched.is_empty() {
                                println!("No entries for '{pred}'.");
                            } else {
                                let count = matched.len();
                                for tuple in matched {
                                    let args: Vec<String> = tuple.iter().map(|v| {
                                        if pretty { format_pretty(v) } else { v.to_string() }
                                    }).collect();
                                    println!("  {pred}({})", args.join(", "));
                                }
                                println!("Found {} entries:", count);
                            }
                        }
                        Err(e) => eprintln!("Parse error: {e}"),
                    }
                } else {
                    // Bare predicate name (with optional arity like pred/3 stripped)
                    let pred = line.split('/').next().unwrap_or(&line).trim();
                    let tuples = current_store.scan(pred);
                    if tuples.is_empty() {
                        println!("No entries for '{pred}'.");
                    } else {
                        for tuple in tuples {
                            let args: Vec<String> = tuple.iter().map(|v| {
                                if pretty { format_pretty(v) } else { v.to_string() }
                            }).collect();
                            println!("  {pred}({})", args.join(", "));
                        }
                        println!("Found {} entries:", tuples.len());
                    }
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
    Ok(())
}

/// Extract uppercase variable names from a Mangle rule body, in order of first
/// appearance. Skips string literals and single underscores.
fn extract_vars(body: &str) -> Vec<String> {
    let mut vars: Vec<String> = Vec::new();
    let mut in_string = false;
    let mut token = String::new();

    let consider = |tok: &str, vars: &mut Vec<String>| {
        if tok.chars().next().map(|c| c.is_uppercase()).unwrap_or(false)
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

fn print_access_diff(enc: &smt::SmtEncoder<'_>, before_label: &str, after_label: &str) {
    let can_gained = enc.check_permission_expansion(before_label, after_label);
    let can_lost = enc.check_permission_contraction(before_label, after_label);
    let eff_gained = enc.check_effective_can_expansion(before_label, after_label);
    let eff_lost = enc.check_effective_can_contraction(before_label, after_label);

    if can_gained.is_empty() && can_lost.is_empty() && eff_gained.is_empty() && eff_lost.is_empty() {
        println!("(no permission changes)");
        return;
    }

    println!("=== Access diff: '{}' → '{}' ===", before_label, after_label);

    if !can_gained.is_empty() {
        println!("  CAN GAINED ({}):", can_gained.len());
        let mut sorted = can_gained;
        sorted.sort_by(|a, b| a.principal.cmp(&b.principal));
        for d in &sorted {
            println!("    {}  ns={:?}  apigroup={:?}  resource={:?}  verb={:?}",
                d.principal, d.namespace, d.apigroup, d.resource, d.verb);
        }
    }
    if !can_lost.is_empty() {
        println!("  CAN LOST ({}):", can_lost.len());
        let mut sorted = can_lost;
        sorted.sort_by(|a, b| a.principal.cmp(&b.principal));
        for d in &sorted {
            println!("    {}  ns={:?}  apigroup={:?}  resource={:?}  verb={:?}",
                d.principal, d.namespace, d.apigroup, d.resource, d.verb);
        }
    }
    if !eff_gained.is_empty() {
        println!("  EFFECTIVE GAINED ({}) [escalation-aware]:", eff_gained.len());
        let mut sorted = eff_gained;
        sorted.sort_by(|a, b| a.principal.cmp(&b.principal));
        for d in &sorted {
            println!("    {}  ns={:?}  resource={:?}  verb={:?}",
                d.principal, d.namespace, d.resource, d.verb);
        }
    }
    if !eff_lost.is_empty() {
        println!("  EFFECTIVE LOST ({}) [escalation-aware]:", eff_lost.len());
        let mut sorted = eff_lost;
        sorted.sort_by(|a, b| a.principal.cmp(&b.principal));
        for d in &sorted {
            println!("    {}  ns={:?}  resource={:?}  verb={:?}",
                d.principal, d.namespace, d.resource, d.verb);
        }
    }
}

fn smt_command(input: &str, store: &EvalStore) {
    let mut tokens = input.splitn(2, ' ');
    let subcommand = tokens.next().unwrap_or("").trim();
    let rest = tokens.next().unwrap_or("").trim();

    match subcommand {
        "check_access" => {
            let mut args = rest.split_whitespace();
            let (Some(ns_raw), Some(res_raw), Some(verb_raw)) =
                (args.next(), args.next(), args.next())
            else {
                eprintln!("Usage: ::smt check_access <namespace> <resource> <verb> [expected_principal ...]");
                eprintln!("       Use \"\" for namespace to check cluster-wide (CRB) grants.");
                return;
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
                println!("PASS  can(_, {namespace:?}, {resource:?}, {verb:?})");
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
                }
            }
        }
        "check_isolation" => {
            let mut args = rest.split_whitespace();
            let Some(ns_raw) = args.next() else {
                eprintln!("Usage: ::smt check_isolation <namespace> [allowed_principal ...]");
                eprintln!("       Proves that ONLY the listed principals have any access in <namespace>.");
                return;
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
                println!("PASS  namespace {namespace:?} is isolated to the expected principals (Z3 UNSAT proof)");
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
        }
        "node_selector" => {
            let unschedulable = smt::scheduling::check_node_selector(store);
            if unschedulable.is_empty() {
                println!("PASS  all pods with nodeSelectors are schedulable");
            } else {
                println!("FAIL  {} unschedulable pod(s):", unschedulable.len());
                for p in &unschedulable {
                    println!("        {}/{}", p.namespace, p.name);
                }
            }
        }
        "anti_affinity" => {
            use smt::scheduling::PlacementResult;
            match smt::scheduling::check_anti_affinity_placement(store) {
                PlacementResult::Sat(assignment) if assignment.is_empty() => {
                    println!("PASS  no anti-affinity conflicts found");
                }
                PlacementResult::Sat(mut assignment) => {
                    assignment.sort_by(|a, b| a.0.cmp(&b.0));
                    println!("PASS  valid placement found ({} pods):", assignment.len());
                    for (pod, node) in &assignment {
                        println!("        {pod} → {node}");
                    }
                }
                PlacementResult::Unsat => {
                    println!("FAIL  no valid placement exists — anti-affinity constraints unsatisfiable");
                }
            }
        }
        _ => {
            eprintln!("Unknown SMT subcommand: {subcommand:?}");
            eprintln!("Available: check_access, check_isolation, node_selector, anti_affinity");
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
                            if c == '\\' {
                                if let Some(esc) = chars.next() {
                                    b.push(esc);
                                }
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

/// If `body` is a single partial-application atom with no free variables,
/// infer the remaining arity from the store and append generated vars.
/// Returns (new_body, vars) or None if the relation isn't in the store.
fn auto_complete_partial(body: &str, store: &EvalStore) -> Option<(String, Vec<String>)> {
    let (rel, inner) = if let Some(paren) = body.find('(') {
        let inner = body[paren + 1..].trim_end_matches(')').trim();
        (body[..paren].trim(), inner)
    } else {
        (body.trim(), "")
    };

    let arity = store.scan(rel).first().map(|t| t.len())?;
    let given = if inner.is_empty() { 0 } else { count_top_level_args(inner) };

    if given >= arity {
        return None;
    }

    if given == 0 {
        // Bare call — generate named vars for all positions so the head has something to bind.
        let auto_vars: Vec<String> = (0..arity).map(|i| format!("V{i}")).collect();
        let new_body = format!("{}({})", rel, auto_vars.join(", "));
        Some((new_body, auto_vars))
    } else {
        // Partial call — pad trailing positions with _ so Mangle sees the right arity,
        // but keep the head vars exactly as the user specified.
        let padding = std::iter::repeat("_").take(arity - given).collect::<Vec<_>>().join(", ");
        let new_body = format!("{}({}, {})", rel, inner, padding);
        Some((new_body, vec![]))
    }
}

/// Build a map from (relation, tuple) → list of premise-sets that derived it.
/// A single fact may have been derived by multiple rules/paths.
fn build_provenance_index(entries: &[ProvenanceEntry]) -> HashMap<(String, Vec<Value>), Vec<Vec<(String, Vec<Value>)>>> {
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
        println!("{}↻ (cycle: {}({}))", "  ".repeat(depth), rel, tuple.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(", "));
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
                    let args = p_tuple.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(", ");
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
    if s.trim().is_empty() {
        return 0;
    }
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut count = 1usize;
    for ch in s.chars() {
        match ch {
            '"' => in_string = !in_string,
            '(' | '[' | '{' if !in_string => depth += 1,
            ')' | ']' | '}' if !in_string => depth = depth.saturating_sub(1),
            ',' if !in_string && depth == 0 => count += 1,
            _ => {}
        }
    }
    count
}
