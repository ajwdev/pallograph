// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Helpers shared by the DD-vs-interpreter parity tests
//! (`dd_interp_parity.rs`, `generated_parity.rs`).

// Each test binary compiles this module and uses only some of it.
#![allow(dead_code)]

use std::collections::BTreeSet;

use mangle_common::{CompoundKind, Value};
use pallograph::engine::{Backend, DdBackend, InterpreterBackend};

pub type Edb = Vec<(String, Vec<Value>)>;

pub fn n(x: i64) -> Value {
    Value::Number(x)
}
pub fn s(x: &str) -> Value {
    Value::String(x.to_string())
}
pub fn f(x: f64) -> Value {
    Value::Float(x)
}

pub fn edb(facts: &[(&str, Vec<Value>)]) -> Edb {
    facts
        .iter()
        .map(|(r, t)| (r.to_string(), t.clone()))
        .collect()
}

/// Evaluate `rules` over `edb` on both backends; assert every (non-`$`) relation
/// has an identical fact set. Panics with a diff on mismatch, or with the
/// backend error if either fails to evaluate.
pub fn assert_parity(name: &str, e: &Edb, rules: &str) {
    if let Err(message) = check_parity(name, e, rules, false) {
        panic!("{message}");
    }
}

/// Like [`assert_parity`], but sorts the elements of every `List` value before
/// comparing. Use for aggregates like `fn:collect` whose output-list order is
/// unspecified and may legitimately differ between backends — we want to assert
/// the collected *multiset* matches, not a particular order.
pub fn assert_parity_unordered(name: &str, e: &Edb, rules: &str) {
    if let Err(message) = check_parity(name, e, rules, true) {
        panic!("{message}");
    }
}

/// Recursively sort the elements of any `List` compound, so two lists with the
/// same elements in different order normalize equal. Other value kinds (and
/// non-List compounds like structs/pairs, whose order IS meaningful) are left
/// structurally intact.
fn normalize_value(v: &Value) -> Value {
    match v {
        Value::Compound(CompoundKind::List, elems) => {
            let mut inner: Vec<Value> = elems.iter().map(normalize_value).collect();
            inner.sort();
            Value::Compound(CompoundKind::List, inner)
        }
        Value::Compound(kind, elems) => {
            Value::Compound(*kind, elems.iter().map(normalize_value).collect())
        }
        other => other.clone(),
    }
}

/// Evaluate `rules` over `edb` on both backends and describe any relation
/// whose fact sets differ, or either backend's error. `Ok` means parity.
pub fn check_parity(name: &str, e: &Edb, rules: &str, normalize_lists: bool) -> Result<(), String> {
    let rules = vec![rules.to_string()];
    let interp = InterpreterBackend
        .evaluate(e, &rules)
        .map_err(|err| format!("[{name}] interpreter failed: {err:#}"))?;
    let dd = DdBackend { provenance: false }
        .evaluate(e, &rules)
        .map_err(|err| format!("[{name}] dd failed: {err:#}"))?;

    let rels: BTreeSet<String> = interp
        .relation_names()
        .map(String::from)
        .chain(dd.relation_names().map(String::from))
        .filter(|r| !r.starts_with('$'))
        .collect();

    let prep = |tuples: &[Vec<Value>]| -> Vec<Vec<Value>> {
        let mut v: Vec<Vec<Value>> = tuples
            .iter()
            .map(|t| {
                if normalize_lists {
                    t.iter().map(normalize_value).collect()
                } else {
                    t.clone()
                }
            })
            .collect();
        v.sort();
        v
    };

    let mut failures = Vec::new();
    for rel in &rels {
        let i = prep(interp.scan(rel));
        let d = prep(dd.scan(rel));
        if i != d {
            let missing: Vec<_> = i
                .iter()
                .filter(|t| !d.contains(t))
                .take(3)
                .cloned()
                .collect();
            let extra: Vec<_> = d
                .iter()
                .filter(|t| !i.contains(t))
                .take(3)
                .cloned()
                .collect();
            failures.push(format!(
                "  {rel}: interp={} dd={}\n     missing from dd: {missing:?}\n     extra in dd:     {extra:?}",
                i.len(),
                d.len()
            ));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "[{name}] DD/interpreter parity failures:\n{}",
            failures.join("\n")
        ))
    }
}
