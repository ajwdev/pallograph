use anyhow::Result;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;

use crate::engine::{Engine, EvalStore};

pub fn run(engine: &mut Engine, store: EvalStore) -> Result<()> {
    println!("\n=== Interactive Query Mode ===");
    println!("Commands:");
    println!("  <predicate>          — show all tuples for a predicate");
    println!("  ::show all           — list all known predicates");
    println!("  ::define <rule>.     — add a rule and re-evaluate");
    println!("  ::pretty              — toggle compact/pretty tuple display");
    println!("  ::quit               — exit");
    println!();

    let history_path = dirs_home().join(".pallograph_history");
    let mut rl = DefaultEditor::new()?;
    let _ = rl.load_history(&history_path);

    let mut current_store = store;
    let mut pretty = false;

    loop {
        let readline = rl.readline("mangle> ");
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
                    let mut names: Vec<&str> = current_store.relation_names().collect();
                    names.sort_unstable();
                    for n in names {
                        println!("  {n}");
                    }
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

                // Treat input as a predicate name (with optional arity like pred/3 stripped)
                let pred = line.split('/').next().unwrap_or(&line).trim();
                let tuples = current_store.scan(pred);
                if tuples.is_empty() {
                    println!("No entries for '{pred}'.");
                } else {
                    println!("Found {} entries:", tuples.len());
                    for tuple in tuples {
                        let args: Vec<String> = tuple.iter().map(|v| {
                            if pretty { format_pretty(v) } else { v.to_string() }
                        }).collect();
                        println!("  {pred}({})", args.join(", "));
                    }
                    println!();
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
