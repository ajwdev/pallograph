use mangle_common::{CompoundKind, Value};
use serde_json::Value as Json;

/// Convert a serde_json Value to a mangle Value.
/// Returns None for JSON null (mirrors the Go POC's removeNulls).
pub fn json_to_value(v: &Json) -> Option<Value> {
    match v {
        Json::Null => None,
        Json::Bool(b) => Some(Value::Name(if *b { "/true" } else { "/false" }.into())),
        Json::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(Value::Number(i))
            } else {
                n.as_f64().map(Value::Float)
            }
        }
        Json::String(s) => Some(Value::String(s.clone())),
        Json::Array(items) => {
            let elems: Vec<Value> = items.iter().filter_map(json_to_value).collect();
            Some(Value::Compound(CompoundKind::List, elems))
        }
        Json::Object(map) => {
            let mut pairs = Vec::with_capacity(map.len() * 2);
            for (k, v) in map {
                if let Some(mv) = json_to_value(v) {
                    pairs.push(Value::Name(format!("/{k}")));
                    pairs.push(mv);
                }
                // Skip null values (removeNulls behavior)
            }
            Some(Value::Compound(CompoundKind::Struct, pairs))
        }
    }
}

#[allow(dead_code)]
/// Look up a field in a Mangle struct value.
pub fn struct_get<'a>(s: &'a Value, field: &str) -> Option<&'a Value> {
    let key = Value::Name(format!("/{field}"));
    if let Value::Compound(_, pairs) = s {
        for chunk in pairs.chunks_exact(2) {
            if chunk[0] == key {
                return Some(&chunk[1]);
            }
        }
    }
    None
}

#[allow(dead_code)]
/// Iterate over elements of a Mangle list value.
pub fn list_iter(v: &Value) -> impl Iterator<Item = &Value> {
    match v {
        Value::Compound(CompoundKind::List, elems) => elems.iter(),
        _ => [].iter(),
    }
}

#[allow(dead_code)]
/// Convert a Value to a display string.
pub fn display(v: &Value) -> String {
    v.to_string()
}
