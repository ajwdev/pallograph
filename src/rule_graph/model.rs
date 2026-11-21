// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Builds the [`RuleGraph`] from rule source text.
//!
//! The mangle AST carries no source positions, so statements are located by
//! scanning the text and each one is then parsed on its own for structure.

use std::collections::BTreeMap;

use mangle_ast::{Arena, Term};
use serde::Serialize;

/// How origins of rules added in the session start: `session #1`, ...
pub const SESSION_ORIGIN_PREFIX: &str = "session #";

/// One rule file (or session rule) and where it came from, e.g.
/// `rules/closure.mg` or `session #2`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleSource {
    pub origin: String,
    pub text: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StatementKind {
    /// `Decl name(...) descr [...]`: documentation and types.
    Decl,
    /// A fact written in the rules, such as `identity_kind(/user).`
    Fact,
    /// `head :- body`.
    Rule,
}

/// A statement as written, with the comment block directly above it.
#[derive(Clone, Debug, Serialize)]
pub struct Statement {
    pub kind: StatementKind,
    /// `origin:line` of the statement's first line.
    pub location: String,
    pub text: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PredicateKind {
    /// Has at least one rule.
    Derived,
    /// Facts written in the rules, no rules.
    WrittenFact,
    /// Supplied at runtime (EDB): no rules and no facts in any rule file,
    /// so the rows come from outside the program, such as the Kubernetes
    /// loader, a datasource in pallograph.toml, `+fact`, `source` or a test.
    /// Inferred from the rules alone.
    SuppliedAtRuntime,
}

#[derive(Clone, Debug, Serialize)]
pub struct Predicate {
    pub name: String,
    pub kind: PredicateKind,
    /// The first source that defines it with a rule or fact; None for
    /// predicates supplied at runtime.
    pub origin: Option<String>,
    pub statements: Vec<Statement>,
}

/// A rule's head depends on a predicate in its body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Edge {
    pub head: String,
    pub body: String,
    /// How many rules use this dependency.
    pub count: usize,
    /// Whether any of those rules negates it (`!body(...)`).
    pub negated: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct RuleGraph {
    pub predicates: BTreeMap<String, Predicate>,
    pub edges: Vec<Edge>,
    /// Statements the Mangle parser rejected, so they are not silently lost.
    pub unparsed: Vec<Statement>,
}

impl RuleGraph {
    pub fn build(sources: &[RuleSource]) -> RuleGraph {
        let mut statements: BTreeMap<String, Vec<Statement>> = BTreeMap::new();
        let mut defined_in: BTreeMap<String, String> = BTreeMap::new();
        let mut has_rule: BTreeMap<String, bool> = BTreeMap::new();
        // (head, body) -> index into `edges`, which keeps first-seen order.
        let mut edge_index: BTreeMap<(String, String), usize> = BTreeMap::new();
        let mut edges: Vec<Edge> = Vec::new();
        let mut unparsed: Vec<Statement> = Vec::new();

        for source in sources {
            let lines: Vec<&str> = source.text.lines().collect();
            for chunk in split_statements(&source.text) {
                let location = format!("{}:{}", source.origin, chunk.first_line + 1);
                let text = statement_text(&lines, chunk.first_line, chunk.last_line);
                let Some(parsed_statements) = parse_statement(chunk.text) else {
                    unparsed.push(Statement {
                        kind: StatementKind::Rule,
                        location,
                        text: chunk.text.to_string(),
                    });
                    continue;
                };
                for parsed in parsed_statements {
                    let statement = Statement {
                        kind: parsed.kind,
                        location: location.clone(),
                        text: text.clone(),
                    };
                    if parsed.kind != StatementKind::Decl {
                        defined_in
                            .entry(parsed.head.clone())
                            .or_insert_with(|| source.origin.clone());
                    }
                    let is_rule = parsed.kind == StatementKind::Rule;
                    *has_rule.entry(parsed.head.clone()).or_default() |= is_rule;
                    for (body, negated) in parsed.premises {
                        statements.entry(body.clone()).or_default();
                        let key = (parsed.head.clone(), body.clone());
                        let index = *edge_index.entry(key).or_insert_with(|| {
                            edges.push(Edge {
                                head: parsed.head.clone(),
                                body,
                                count: 0,
                                negated: false,
                            });
                            edges.len() - 1
                        });
                        edges[index].count += 1;
                        edges[index].negated |= negated;
                    }
                    statements.entry(parsed.head).or_default().push(statement);
                }
            }
        }

        let predicates = statements
            .into_iter()
            .map(|(name, statements)| {
                let origin = defined_in.get(&name).cloned();
                let kind = match (has_rule.get(&name), &origin) {
                    (Some(true), _) => PredicateKind::Derived,
                    (_, Some(_)) => PredicateKind::WrittenFact,
                    _ => PredicateKind::SuppliedAtRuntime,
                };
                let predicate = Predicate {
                    name: name.clone(),
                    kind,
                    origin,
                    statements,
                };
                (name, predicate)
            })
            .collect();
        RuleGraph {
            predicates,
            edges,
            unparsed,
        }
    }
}

struct Chunk<'a> {
    text: &'a str,
    /// Zero-based lines of the statement's first and last characters.
    first_line: usize,
    last_line: usize,
}

/// Splits Mangle source into statements. A statement ends at a `.` that is
/// outside a string literal and a `#` comment and is followed by whitespace
/// or the end of the text. Leading blank lines and comments are trimmed.
fn split_statements(text: &str) -> Vec<Chunk<'_>> {
    let bytes = text.as_bytes();
    let mut chunks = Vec::new();
    let mut start: Option<usize> = None;
    let mut line = 0;
    let mut first_line = 0;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        match byte {
            b'\n' => line += 1,
            b'#' => {
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
                continue;
            }
            b'"' | b'\'' | b'`' => {
                if start.is_none() {
                    start = Some(index);
                    first_line = line;
                }
                index += 1;
                while index < bytes.len() && bytes[index] != byte {
                    if bytes[index] == b'\\' {
                        index += 1;
                    }
                    if index < bytes.len() && bytes[index] == b'\n' {
                        line += 1;
                    }
                    index += 1;
                }
            }
            b'.' if start.is_some()
                && bytes
                    .get(index + 1)
                    .is_none_or(|next| next.is_ascii_whitespace() || *next == b'#') =>
            {
                let begin = start.take().unwrap_or(index);
                chunks.push(Chunk {
                    text: &text[begin..=index],
                    first_line,
                    last_line: line,
                });
            }
            _ if byte.is_ascii_whitespace() => {}
            _ => {
                if start.is_none() {
                    start = Some(index);
                    first_line = line;
                }
            }
        }
        index += 1;
    }
    chunks
}

/// Source lines `first..=last`, plus the `#` comment lines directly above
/// (no blank line in between).
fn statement_text(lines: &[&str], first: usize, last: usize) -> String {
    let mut begin = first;
    while begin > 0 && lines[begin - 1].trim_start().starts_with('#') {
        begin -= 1;
    }
    let end = last.min(lines.len().saturating_sub(1));
    lines[begin..=end].join("\n").trim_end().to_string()
}

struct ParsedStatement {
    kind: StatementKind,
    head: String,
    /// Body predicates and whether each use is negated.
    premises: Vec<(String, bool)>,
}

/// Parses one chunk of source. Normally a chunk is one statement, but every
/// clause and declaration in it is returned, so none is lost if the
/// splitter ever joins two. None means the parser rejected the chunk.
fn parse_statement(text: &str) -> Option<Vec<ParsedStatement>> {
    let arena = Arena::new_with_global_interner();
    let mut parser = mangle_parse::Parser::new(&arena, text.as_bytes(), "statement");
    parser.next_token().ok()?;
    let unit = parser.parse_unit().ok()?;

    let mut parsed = Vec::new();
    // The parser adds an implicit Package declaration to every unit.
    for decl in unit.decls {
        match arena.predicate_name(decl.atom.sym) {
            Some(name) if name != "Package" => parsed.push(ParsedStatement {
                kind: StatementKind::Decl,
                head: name.to_string(),
                premises: Vec::new(),
            }),
            _ => {}
        }
    }
    for clause in unit.clauses {
        let Some(head) = arena.predicate_name(clause.head.sym) else {
            continue;
        };
        let mut premises = Vec::new();
        for premise in clause.premises {
            let (atom, negated) = match premise {
                Term::Atom(atom) | Term::TemporalAtom(atom, _) => (atom, false),
                Term::NegAtom(atom) => (atom, true),
                _ => continue,
            };
            // Builtins such as :match_field and :lt are not relations.
            match arena.predicate_name(atom.sym) {
                Some(name) if !name.starts_with(':') => premises.push((name.to_string(), negated)),
                _ => {}
            }
        }
        let kind = if clause.premises.is_empty() && clause.transform.is_empty() {
            StatementKind::Fact
        } else {
            StatementKind::Rule
        };
        parsed.push(ParsedStatement {
            kind,
            head: head.to_string(),
            premises,
        });
    }
    Some(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(text: &str) -> RuleGraph {
        RuleGraph::build(&[RuleSource {
            origin: "f.mg".to_string(),
            text: text.to_string(),
        }])
    }

    fn edge<'g>(graph: &'g RuleGraph, head: &str, body: &str) -> Option<&'g Edge> {
        graph
            .edges
            .iter()
            .find(|edge| edge.head == head && edge.body == body)
    }

    #[test]
    fn edges_from_rule_body() {
        let graph = build("a(X) :- b(X), c(X).\n");
        assert_eq!(graph.edges.len(), 2);
        let ab = edge(&graph, "a", "b").expect("a->b");
        assert_eq!((ab.count, ab.negated), (1, false));
        assert!(edge(&graph, "a", "c").is_some());
        assert_eq!(graph.predicates["a"].kind, PredicateKind::Derived);
    }

    #[test]
    fn edge_count_and_negation() {
        let graph = build("a(X) :- b(X).\na(X) :- c(X), !b(X).\n");
        let ab = edge(&graph, "a", "b").expect("a->b");
        assert_eq!((ab.count, ab.negated), (2, true));
        assert_eq!(graph.predicates["a"].statements.len(), 2);
    }

    #[test]
    fn builtins_and_functions_skipped() {
        let graph = build(
            "a(X, N) :- b(X, D), :match_field(D, /x, X) |> do fn:group_by(X), let N = fn:count().\n",
        );
        let bodies: Vec<&str> = graph.edges.iter().map(|edge| edge.body.as_str()).collect();
        assert_eq!(bodies, ["b"]);
    }

    #[test]
    fn written_fact_attributed() {
        let graph = RuleGraph::build(&[RuleSource {
            origin: "rules/closure.mg".to_string(),
            text: "k(/user).\nk(/serviceaccount).\n".to_string(),
        }]);
        let k = &graph.predicates["k"];
        assert_eq!(k.kind, PredicateKind::WrittenFact);
        assert_eq!(k.origin.as_deref(), Some("rules/closure.mg"));
        assert_eq!(k.statements.len(), 2);
        assert_eq!(k.statements[1].kind, StatementKind::Fact);
    }

    #[test]
    fn loaded_predicate_kind() {
        let graph = build("Decl b(X)\n  descr [doc(\"input\")].\na(X) :- b(X).\n");
        let b = &graph.predicates["b"];
        assert_eq!(b.kind, PredicateKind::SuppliedAtRuntime);
        assert_eq!(b.origin, None);
        assert_eq!(b.statements.len(), 1);
        assert_eq!(b.statements[0].kind, StatementKind::Decl);
        assert!(b.statements[0].text.contains("doc(\"input\")"));
    }

    #[test]
    fn location_and_comment_block() {
        let graph = build("x(1).\n# Why a exists.\na(X) :- b(X).\n");
        let statement = &graph.predicates["a"].statements[0];
        assert_eq!(statement.location, "f.mg:3");
        assert_eq!(statement.text, "# Why a exists.\na(X) :- b(X).");
        // A blank line ends the comment block.
        let graph = build("# Unrelated.\n\na(X) :- b(X).\n");
        assert_eq!(graph.predicates["a"].statements[0].text, "a(X) :- b(X).");
    }

    #[test]
    fn string_literal_with_dot_and_hash() {
        let graph = build("a(X) :- b(X, \"x.\n# not a comment\").\nc(X) :- a(X).\n");
        assert!(edge(&graph, "a", "b").is_some());
        assert!(edge(&graph, "c", "a").is_some());
        assert_eq!(graph.predicates["c"].statements[0].location, "f.mg:3");
    }

    #[test]
    fn multi_line_rule_spans_lines() {
        let graph = build("a(X) :-\n  b(X),\n  c(X).\n");
        let statement = &graph.predicates["a"].statements[0];
        assert_eq!(statement.location, "f.mg:1");
        assert_eq!(statement.text, "a(X) :-\n  b(X),\n  c(X).");
    }

    #[test]
    fn dot_followed_by_comment_ends_statement() {
        let graph = build("a(X) :- b(X).# note\nc(X) :- d(X).\n");
        assert!(edge(&graph, "a", "b").is_some());
        assert!(edge(&graph, "c", "d").is_some(), "{:?}", graph.edges);
        assert_eq!(graph.predicates["c"].kind, PredicateKind::Derived);
    }

    #[test]
    fn unparsable_statement_is_kept() {
        let graph = build("a(X) :- b(X.\nc(X) :- d(X).\n");
        assert_eq!(graph.unparsed.len(), 1);
        assert_eq!(graph.unparsed[0].location, "f.mg:1");
        assert_eq!(graph.unparsed[0].text, "a(X) :- b(X.");
        assert!(edge(&graph, "c", "d").is_some());
    }
}
