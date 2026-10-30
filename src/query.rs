// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{Result, anyhow};
use mangle_ast::{Arena, BaseTerm, Const};
use mangle_common::Value;
use mangle_parse::Parser;

#[derive(Clone)]
pub struct ParsedQuery {
    pub predicate: String,
    pub args: Vec<QueryArg>,
}

#[derive(Clone)]
pub enum QueryArg {
    Variable,
    StringConst(String),
    NameConst(String),
    NumberConst(i64),
}

pub fn parse_query(query: &str) -> Result<ParsedQuery> {
    let arena = Arena::new_with_global_interner();
    let mut parser = Parser::new(&arena, query.as_bytes(), "query");
    parser.next_token().map_err(|e| anyhow!(e))?;
    let atom = parser.parse_atom()?;

    let predicate = arena
        .predicate_name(atom.sym)
        .ok_or_else(|| anyhow!("cannot resolve predicate name"))?
        .to_string();

    let args = atom
        .args
        .iter()
        .map(|arg| match arg {
            BaseTerm::Variable(_) => QueryArg::Variable,
            BaseTerm::Const(Const::String(s)) => QueryArg::StringConst(s.to_string()),
            BaseTerm::Const(Const::Name(n)) => {
                let name = arena.lookup_name(*n).unwrap_or("").to_string();
                QueryArg::NameConst(name)
            }
            BaseTerm::Const(Const::Number(n)) => QueryArg::NumberConst(*n),
            _ => QueryArg::Variable,
        })
        .collect();

    Ok(ParsedQuery { predicate, args })
}

pub fn filter_tuples<'a>(tuples: &'a [Vec<Value>], query: &ParsedQuery) -> Vec<&'a Vec<Value>> {
    tuples
        .iter()
        .filter(|tuple| {
            for (i, arg) in query.args.iter().enumerate() {
                let Some(val) = tuple.get(i) else {
                    return false;
                };
                match arg {
                    QueryArg::Variable => {}
                    QueryArg::StringConst(s) => {
                        if val != &Value::String(s.clone()) {
                            return false;
                        }
                    }
                    QueryArg::NameConst(s) => {
                        if val != &Value::Name(s.clone()) {
                            return false;
                        }
                    }
                    QueryArg::NumberConst(n) => {
                        if val != &Value::Number(*n) {
                            return false;
                        }
                    }
                }
            }
            true
        })
        .collect()
}

/// Parse an optional anonymous-rule head from a `?-`/`query` body. The form
/// `_(R, N) :- atom, atom` (an anonymous head, as in LogiQL) reports only the
/// variables named in the head; the rest act as join keys. Returns
/// `(Some(vars), body)` when the body begins with such a head, otherwise
/// `(None, whole_body)`, keeping the "report every named variable" behaviour.
/// The head name is a bare `_`, and the closing paren is matched outside
/// strings and brackets so a struct or list in the args can't end it early.
pub fn split_projection(raw: &str) -> (Option<Vec<String>>, &str) {
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

/// Extract uppercase variable names from a Mangle rule body, in order of first
/// appearance. Skips string literals and single underscores.
pub fn extract_vars(body: &str) -> Vec<String> {
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

/// Relation names a query body refers to: identifiers directly followed by `(`,
/// or the whole body when it is a bare name. Builtins (`:string:contains`) and
/// functions (`fn:plus`) contain `:` and are skipped, as are variables.
pub fn body_relations(body: &str) -> Vec<String> {
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

/// The relation name when `body` is exactly one plain atom (`rel`, `rel()` or
/// `rel(args)`), not a conjunction, negation or builtin call.
pub fn single_atom(body: &str) -> Option<&str> {
    let body = body.trim();
    let rel = if body.contains('(') {
        split_atom(body)?.0
    } else {
        body
    };
    (body_relations(body) == [rel]).then_some(rel)
}

/// Split `rel(args)` into the relation name and the text between the outer
/// parentheses. None unless the body is a single atom.
pub fn split_atom(body: &str) -> Option<(&str, &str)> {
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

pub fn count_top_level_args(s: &str) -> usize {
    split_top_level_args(s).len()
}

/// Split an argument list on top-level commas (not inside strings or brackets).
pub fn split_top_level_args(s: &str) -> Vec<&str> {
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

/// Up to three known relations close to `name`, nearest first. Internal
/// relations (leading `_`) are not suggested.
pub fn suggest(name: &str, known: &std::collections::HashSet<String>) -> Vec<String> {
    let mut scored: Vec<(usize, &String)> = known
        .iter()
        .filter(|k| !k.starts_with('_'))
        .map(|k| (edit_distance(name, k), k))
        .filter(|(d, _)| *d <= 2.max(name.len() / 4))
        .collect();
    scored.sort();
    scored.into_iter().take(3).map(|(_, k)| k.clone()).collect()
}

pub fn edit_distance(a: &str, b: &str) -> usize {
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
