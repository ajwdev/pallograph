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

/// Convert a mangle Value to a serde_json Value. Inverse of `json_to_value`.
/// Used by `::export`. Struct keys are the `/`-prefixed `Name` values, emitted
/// without the leading slash; everything else is reproduced faithfully.
pub fn value_to_json(v: &Value) -> Json {
    match v {
        Value::String(s) => Json::String(s.clone()),
        Value::Number(i) => Json::Number((*i).into()),
        Value::Float(f) => serde_json::Number::from_f64(*f).map_or(Json::Null, Json::Number),
        Value::Name(s) => Json::String(s.clone()),
        Value::Null => Json::Null,
        // No native JSON representation; emit the canonical display string.
        Value::Time(_) | Value::Duration(_) => Json::String(v.to_string()),
        // Lists and pairs hold elements directly.
        Value::Compound(CompoundKind::List | CompoundKind::Pair, elems) => {
            Json::Array(elems.iter().map(value_to_json).collect())
        }
        // Structs and maps interleave keys and values: [k1, v1, k2, v2, ...].
        Value::Compound(CompoundKind::Struct | CompoundKind::Map, pairs) => {
            let mut map = serde_json::Map::with_capacity(pairs.len() / 2);
            for chunk in pairs.chunks_exact(2) {
                let key = match &chunk[0] {
                    Value::Name(s) => s.strip_prefix('/').unwrap_or(s).to_string(),
                    other => other.to_string(),
                };
                map.insert(key, value_to_json(&chunk[1]));
            }
            Json::Object(map)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_to_json_scalars() {
        assert_eq!(value_to_json(&Value::String("hi".into())), Json::from("hi"));
        assert_eq!(value_to_json(&Value::Number(42)), Json::from(42));
        assert_eq!(value_to_json(&Value::Float(1.5)), Json::from(1.5));
        // Names keep their leading slash so they round-trip faithfully.
        assert_eq!(value_to_json(&Value::Name("/true".into())), Json::from("/true"));
        assert_eq!(value_to_json(&Value::Null), Json::Null);
    }

    #[test]
    fn value_to_json_list() {
        let v = Value::Compound(
            CompoundKind::List,
            vec![Value::Number(1), Value::String("x".into())],
        );
        assert_eq!(value_to_json(&v), serde_json::json!([1, "x"]));
    }

    #[test]
    fn value_to_json_struct_strips_key_slash() {
        let v = Value::Compound(
            CompoundKind::Struct,
            vec![
                Value::Name("/name".into()),
                Value::String("alice".into()),
                Value::Name("/age".into()),
                Value::Number(30),
            ],
        );
        assert_eq!(value_to_json(&v), serde_json::json!({"name": "alice", "age": 30}));
    }
}
