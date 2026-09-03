// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

// Parses kubectl-style label selector strings into the kube `Expression` AST.
//
// The kube crate provides the `Expression`/`Selector` types and converts the
// structured `LabelSelector` (matchLabels/matchExpressions) into them, but it
// does NOT parse the string form (e.g. "app=web,tier in (a,b)") — that grammar
// only lives in `ListParams` and is shipped to the apiserver. This module fills
// that gap so the REPL can accept selectors written the way an operator would.
//
// Grammar (one comma-separated requirement at a time, commas inside `( )` are
// not separators):
//   !key                  -> DoesNotExist(key)
//   key                   -> Exists(key)
//   key = value           -> Equal(key, value)
//   key == value          -> Equal(key, value)
//   key != value          -> NotEqual(key, value)
//   key in (v1, v2, ...)  -> In(key, {v1, v2, ...})
//   key notin (v1, ...)   -> NotIn(key, {v1, ...})

use std::collections::BTreeSet;

use anyhow::{bail, Result};
use kube::core::labels::Expression;

/// Parse a kubectl-style label selector string into a list of `Expression`s.
/// Errors on malformed input or an empty selector.
pub fn parse_selector(input: &str) -> Result<Vec<Expression>> {
    let mut exprs = Vec::new();
    for req in split_requirements(input) {
        let req = req.trim();
        if req.is_empty() {
            continue;
        }
        exprs.push(parse_requirement(req)?);
    }
    if exprs.is_empty() {
        bail!("empty selector");
    }
    Ok(exprs)
}

/// Split on top-level commas, ignoring commas nested inside parentheses so that
/// the value set in `key in (a, b)` stays intact.
fn split_requirements(input: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for c in input.chars() {
        match c {
            '(' => {
                depth += 1;
                cur.push(c);
            }
            ')' => {
                depth -= 1;
                cur.push(c);
            }
            ',' if depth == 0 => parts.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    parts.push(cur);
    parts
}

fn parse_requirement(req: &str) -> Result<Expression> {
    // DoesNotExist: !key
    if let Some(rest) = req.strip_prefix('!') {
        let key = rest.trim();
        validate_key(key)?;
        return Ok(Expression::DoesNotExist(key.to_string()));
    }

    // Set-based: key in (...) / key notin (...)
    if let Some(open) = req.find('(') {
        let Some(close) = req.rfind(')') else {
            bail!("unterminated '(' in requirement: {req}");
        };
        if close < open {
            bail!("malformed parentheses in requirement: {req}");
        }
        let head = req[..open].trim(); // "key in" or "key notin"
        let mut head_parts = head.split_whitespace();
        let Some(key) = head_parts.next() else {
            bail!("missing key in requirement: {req}");
        };
        let Some(op) = head_parts.next() else {
            bail!("missing set operator in requirement: {req}");
        };
        if head_parts.next().is_some() {
            bail!("unexpected tokens before '(' in requirement: {req}");
        }
        validate_key(key)?;
        let values: BTreeSet<String> = req[open + 1..close]
            .split(',')
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .collect();
        if values.is_empty() {
            bail!("empty value set in requirement: {req}");
        }
        return match op {
            "in" => Ok(Expression::In(key.to_string(), values)),
            "notin" => Ok(Expression::NotIn(key.to_string(), values)),
            other => bail!("unknown set operator '{other}' in requirement: {req}"),
        };
    }

    // Equality (check != and == before bare =).
    if let Some(idx) = req.find("!=") {
        return equality(req, idx, 2, false);
    }
    if let Some(idx) = req.find("==") {
        return equality(req, idx, 2, true);
    }
    if let Some(idx) = req.find('=') {
        return equality(req, idx, 1, true);
    }

    // Bare key -> Exists
    let key = req.trim();
    validate_key(key)?;
    Ok(Expression::Exists(key.to_string()))
}

/// Build an Equal/NotEqual from `req` with the operator at byte `idx` of length
/// `op_len`. `equal` selects Equal vs NotEqual.
fn equality(req: &str, idx: usize, op_len: usize, equal: bool) -> Result<Expression> {
    let key = req[..idx].trim();
    let val = req[idx + op_len..].trim();
    validate_key(key)?;
    Ok(if equal {
        Expression::Equal(key.to_string(), val.to_string())
    } else {
        Expression::NotEqual(key.to_string(), val.to_string())
    })
}

fn validate_key(key: &str) -> Result<()> {
    if key.is_empty() {
        bail!("empty key in selector requirement");
    }
    if key.contains(char::is_whitespace) {
        bail!("invalid key '{key}': contains whitespace");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn equality_operators() {
        assert_eq!(
            parse_selector("app=web").unwrap(),
            vec![Expression::Equal("app".into(), "web".into())]
        );
        assert_eq!(
            parse_selector("app==web").unwrap(),
            vec![Expression::Equal("app".into(), "web".into())]
        );
        assert_eq!(
            parse_selector("app!=web").unwrap(),
            vec![Expression::NotEqual("app".into(), "web".into())]
        );
    }

    #[test]
    fn exists_and_not_exists() {
        assert_eq!(
            parse_selector("tier").unwrap(),
            vec![Expression::Exists("tier".into())]
        );
        assert_eq!(
            parse_selector("!deprecated").unwrap(),
            vec![Expression::DoesNotExist("deprecated".into())]
        );
    }

    #[test]
    fn set_based_in_notin() {
        assert_eq!(
            parse_selector("tier in (a,b)").unwrap(),
            vec![Expression::In("tier".into(), set(&["a", "b"]))]
        );
        assert_eq!(
            parse_selector("tier notin (a,b)").unwrap(),
            vec![Expression::NotIn("tier".into(), set(&["a", "b"]))]
        );
    }

    #[test]
    fn multiple_requirements_and_paren_aware_comma() {
        // The comma inside (a, b) must not split the requirement list.
        let got = parse_selector("tier in (frontend, backend),app=foo,!legacy").unwrap();
        assert_eq!(
            got,
            vec![
                Expression::In("tier".into(), set(&["frontend", "backend"])),
                Expression::Equal("app".into(), "foo".into()),
                Expression::DoesNotExist("legacy".into()),
            ]
        );
    }

    #[test]
    fn whitespace_is_tolerated() {
        let got = parse_selector("  app = web ,  tier in ( a , b ) ").unwrap();
        assert_eq!(
            got,
            vec![
                Expression::Equal("app".into(), "web".into()),
                Expression::In("tier".into(), set(&["a", "b"])),
            ]
        );
    }

    #[test]
    fn errors() {
        assert!(parse_selector("").is_err()); // empty selector
        assert!(parse_selector("   ").is_err()); // only whitespace
        assert!(parse_selector("=web").is_err()); // empty key
        assert!(parse_selector("tier in (a,b").is_err()); // unterminated paren
        assert!(parse_selector("tier badop (a,b)").is_err()); // unknown set operator
        assert!(parse_selector("tier in ()").is_err()); // empty value set
    }
}
