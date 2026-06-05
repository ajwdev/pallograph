use std::collections::HashMap;

use anyhow::Result;
use mangle_common::Value;
use mangle_interpreter::ProvenanceEntry;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;

use crate::engine::{Engine, EvalStore};
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
    println!("  ::reset                            — clear session state (_N results, ::define rules), re-evaluate");
    println!("  ::quit                             — exit");
    println!();

    let history_path = dirs_home().join(".pallograph_history");
    let mut rl = DefaultEditor::new()?;
    let _ = rl.load_history(&history_path);

    let mut current_store = store;
    let mut pretty = false;
    let mut query_counter: u32 = 0;

    loop {
        let readline = rl.readline("pallograph> ");
        match readline {
            Ok(line) => {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                rl.add_history_entry(&line)?;

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

                if let Some(rule) = line.strip_prefix("::define ") {
                    engine.add_rule(rule.trim_end_matches('.').trim().to_string());
                    match engine.evaluate() {
                        Ok(new_store) => {
                            current_store = new_store;
                            println!("Rule added and evaluated.");
                        }
                        Err(e) => eprintln!("Error: {e:#}"),
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
