// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{anyhow, bail, Context, Result};
use mangle_common::Value;
use mangle_interpreter::MemStore;
use serde_json::Value as Json;

use crate::engine::Engine;

/// Read bytes from `source`: if it starts with `!`, execute the rest as a shell command and
/// capture stdout; otherwise treat it as a file path.
pub fn read_source(source: &str) -> Result<Vec<u8>> {
    if let Some(cmd) = source.strip_prefix('!') {
        let cmd = cmd.trim();
        let output = std::process::Command::new("sh")
            .args(["-c", cmd])
            .output()
            .with_context(|| format!("running: {cmd}"))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("command exited non-zero: {}", stderr.trim());
        }
        Ok(output.stdout)
    } else if source.trim_start().starts_with('[') {
        Ok(source.as_bytes().to_vec())
    } else {
        std::fs::read(source).with_context(|| format!("reading {source}"))
    }
}

/// Load flat tuples from `source` into `relation` on a raw `MemStore`.
/// Used at startup before the Engine is constructed. Arity is validated
/// within the batch; cross-relation mismatches surface at evaluation time.
pub fn load_tuples_into_store(store: &mut MemStore, relation: &str, source: &str) -> Result<usize> {
    let bytes = read_source(source)?;
    let tuples = parse_tuples(&bytes)?;
    if let Some(arity) = tuples.first().map(|t| t.len()) {
        for (i, tuple) in tuples.iter().enumerate() {
            if tuple.len() != arity {
                bail!(
                    "arity mismatch in {relation}: tuple {i} has {} columns but tuple 0 has {arity}",
                    tuple.len()
                );
            }
        }
    }
    let count = tuples.len();
    for tuple in tuples {
        store.add_fact(relation, tuple);
    }
    Ok(count)
}

/// Load flat tuples from `source` into `relation` on `engine`.
///
/// Accepted formats:
/// - Top-level JSON array of arrays: `[["a","b"], ["c","d"]]`
/// - NDJSON: one JSON array per line
///
/// Returns the number of facts inserted. Arity validation is deferred to the next
/// `engine.evaluate()` call — Mangle will surface a clear error on mismatch.
pub fn load_tuples(engine: &mut Engine, relation: &str, source: &str) -> Result<usize> {
    let bytes = read_source(source)?;
    let tuples = parse_tuples(&bytes)?;
    // Determine expected arity: from existing EDB facts, or from the first tuple in this batch.
    let expected = engine
        .relation_arity(relation)
        .or_else(|| tuples.first().map(|t| t.len()));
    if let Some(arity) = expected {
        for (i, tuple) in tuples.iter().enumerate() {
            if tuple.len() != arity {
                bail!(
                    "arity mismatch: {relation}/{arity} expects {arity} column(s), \
                     but tuple {i} has {} — check your query or source",
                    tuple.len()
                );
            }
        }
    }

    let mut count = 0;
    for tuple in tuples {
        if engine.add_fact(relation.to_string(), tuple) {
            count += 1;
        }
    }
    Ok(count)
}

fn parse_tuples(bytes: &[u8]) -> Result<Vec<Vec<Value>>> {
    let text = std::str::from_utf8(bytes).context("source output is not valid UTF-8")?;

    // Try a top-level JSON value first.
    if let Ok(v) = serde_json::from_str::<Json>(text.trim()) {
        match v {
            Json::Array(rows) => {
                return rows.iter().map(json_row_to_tuple).collect();
            }
            other => bail!(
                "expected a JSON array of tuples at the top level, got {}",
                other.type_name()
            ),
        }
    }

    // Fall back to NDJSON: one JSON value per non-empty line.
    let mut tuples = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let v: Json = serde_json::from_str(line)
            .with_context(|| format!("line {}: not valid JSON", i + 1))?;
        match v {
            Json::Array(_) => tuples.push(json_row_to_tuple(&v)?),
            other => bail!(
                "line {}: expected a JSON array, got {}",
                i + 1,
                other.type_name()
            ),
        }
    }
    Ok(tuples)
}

fn json_row_to_tuple(row: &Json) -> Result<Vec<Value>> {
    let Json::Array(cells) = row else {
        bail!("expected a JSON array for each tuple, got {}", row.type_name());
    };
    cells.iter().map(json_scalar_to_value).collect()
}

fn json_scalar_to_value(v: &Json) -> Result<Value> {
    match v {
        Json::String(s) => Ok(Value::String(s.clone())),
        Json::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(Value::Number(i))
            } else if let Some(f) = n.as_f64() {
                Ok(Value::Float(f))
            } else {
                Err(anyhow!("number out of range: {n}"))
            }
        }
        Json::Bool(b) => Ok(Value::String(b.to_string())),
        Json::Null => Ok(Value::Null),
        Json::Array(_) | Json::Object(_) => bail!(
            "nested arrays/objects are not supported in the generic tuple loader — \
             use \\load-k8s for k8s objects with compound fields"
        ),
    }
}

trait JsonTypeName {
    fn type_name(&self) -> &'static str;
}

impl JsonTypeName for Json {
    fn type_name(&self) -> &'static str {
        match self {
            Json::Null => "null",
            Json::Bool(_) => "bool",
            Json::Number(_) => "number",
            Json::String(_) => "string",
            Json::Array(_) => "array",
            Json::Object(_) => "object",
        }
    }
}

#[cfg(test)]
mod tests {
    use mangle_common::Value;

    use super::*;

    #[test]
    fn parse_top_level_array() {
        let json = r#"[["alice","default","","pods","get"],["bob","default","","pods","list"]]"#;
        let tuples = parse_tuples(json.as_bytes()).expect("parse");
        assert_eq!(tuples.len(), 2);
        assert_eq!(tuples[0][0], Value::String("alice".into()));
        assert_eq!(tuples[1][0], Value::String("bob".into()));
    }

    #[test]
    fn parse_ndjson() {
        let json = "[\"alice\",\"default\",\"\",\"pods\",\"get\"]\n[\"bob\",\"default\",\"\",\"pods\",\"list\"]\n";
        let tuples = parse_tuples(json.as_bytes()).expect("parse");
        assert_eq!(tuples.len(), 2);
        assert_eq!(tuples[0][0], Value::String("alice".into()));
    }

    #[test]
    fn parse_number_and_null() {
        let json = r#"[[42, null, "hello"]]"#;
        let tuples = parse_tuples(json.as_bytes()).expect("parse");
        assert_eq!(tuples[0][0], Value::Number(42));
        assert_eq!(tuples[0][1], Value::Null);
        assert_eq!(tuples[0][2], Value::String("hello".into()));
    }

    #[test]
    fn rejects_nested_object() {
        let json = r#"[["alice", {"nested": "object"}]]"#;
        let err = parse_tuples(json.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("nested"), "got: {err}");
    }

    #[test]
    fn rejects_non_array_toplevel() {
        let json = r#"{"key": "value"}"#;
        let err = parse_tuples(json.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("array"), "got: {err}");
    }

    #[test]
    fn load_via_shell() {
        let store = mangle_interpreter::MemStore::new();
        let mut engine = Engine::new(
            store,
            std::path::Path::new("rules"),
            Box::new(crate::engine::InterpreterBackend),
        )
        .expect("engine");

        let n = load_tuples(
            &mut engine,
            "can",
            r#"! printf '[["alice","default","","pods","get"]]'"#,
        )
        .expect("load via shell");
        assert_eq!(n, 1);
    }
}
