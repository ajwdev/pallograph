// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reading Mangle text into the engine: ground facts parsed into rows, and
//! `source`d files split into ground facts (inserted as EDB) and the rules
//! around them, added all or nothing.

use anyhow::Result;
use mangle_common::Value;

use crate::engine::{Engine, EvalStore};

/// Split `pred(a, b). pred(c, d).` into `("pred(a, b)", "pred(c, d)")`.
/// Finds the split point at the first `)` followed by `.` at paren-depth 0.
pub fn split_two_atoms(s: &str) -> Option<(&str, &str)> {
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
pub fn parse_ground_tuple(input: &str) -> anyhow::Result<(String, Vec<Value>)> {
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

/// Load a sourced file: ground facts as EDB, then the rules, then evaluate.
/// All or nothing: on any error, the rules and the facts this call inserted
/// are removed again. A fact that was already present is left alone.
pub fn source_program(engine: &mut Engine, text: &str) -> Result<EvalStore> {
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
    use super::{
        SourcedProgram, parse_ground_tuple, source_program, split_sourced_program, split_statements,
    };
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
