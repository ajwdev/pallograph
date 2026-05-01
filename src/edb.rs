use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result};
use mangle_common::Value;
use mangle_interpreter::MemStore;
use serde_json::Value as Json;

use crate::value::json_to_value;

/// Load all EDB facts from the fixture files into the store.
pub fn load_all(store: &mut MemStore, fixtures_dir: &Path) -> Result<()> {
    for filename in &["allpods.json", "serviceaccounts.json", "rbac.json"] {
        load_k8s_objects(store, &fixtures_dir.join(filename))
            .with_context(|| format!("loading {filename}"))?;
    }
    load_api_resources(store, &fixtures_dir.join("api-resources.txt"))
        .context("loading api-resources.txt")?;
    Ok(())
}

fn load_k8s_objects(store: &mut MemStore, path: &Path) -> Result<()> {
    let file = std::fs::File::open(path)?;
    let reader = BufReader::new(file);

    // Use a streaming deserializer so both pretty-printed and minified
    // multi-document JSON files work (mirrors Go's json.Decoder behaviour).
    for result in serde_json::Deserializer::from_reader(reader)
        .into_iter::<serde_json::Map<String, Json>>()
    {
        let mut m = result?;
        remove_nulls_map(&mut m);
        let obj = Json::Object(m);

        let api_version = get_str(&obj, "apiVersion").unwrap_or_default();
        let kind = get_str(&obj, "kind").unwrap_or_default();
        let namespace = get_nested_str(&obj, &["metadata", "namespace"]).unwrap_or_default();
        let name = get_nested_str(&obj, &["metadata", "name"]).unwrap_or_default();

        let data = json_to_value(&obj)
            .unwrap_or(Value::Compound(mangle_common::CompoundKind::Struct, vec![]));

        store.add_fact(
            "k8s",
            vec![
                Value::String(api_version.clone()),
                Value::String(kind.clone()),
                Value::String(namespace.clone()),
                Value::String(name.clone()),
                data,
            ],
        );

        extract_labels_and_selectors(store, &api_version, &kind, &namespace, &name, &obj);
    }
    Ok(())
}

fn load_api_resources(store: &mut MemStore, path: &Path) -> Result<()> {
    let file = std::fs::File::open(path)?;
    for line in BufReader::new(file).lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (resource, api_group) = line.split_once('.').unwrap_or((line, ""));
        store.add_fact(
            "api_resource",
            vec![
                Value::String(api_group.to_string()),
                Value::String(resource.to_string()),
            ],
        );
    }
    Ok(())
}

/// Port of labels.go: extract object_label/6 and selector_*/5,6 facts.
fn extract_labels_and_selectors(
    store: &mut MemStore,
    api_version: &str,
    kind: &str,
    namespace: &str,
    name: &str,
    obj: &Json,
) {
    let owner = || {
        vec![
            Value::String(api_version.into()),
            Value::String(kind.into()),
            Value::String(namespace.into()),
            Value::String(name.into()),
        ]
    };

    // metadata.labels → object_label/6
    if let Some(labels) = get_map(obj, &["metadata", "labels"]) {
        for (k, v) in labels {
            if let Json::String(vs) = v {
                let mut args = owner();
                args.push(Value::String(k.clone()));
                args.push(Value::String(vs.clone()));
                store.add_fact("object_label", args);
            }
        }
    }

    // .spec.selector
    let selector = match get_json(obj, &["spec", "selector"]) {
        Some(s) => s,
        None => return,
    };

    let match_labels = selector.get("matchLabels").and_then(|v| v.as_object());
    let match_exprs = selector.get("matchExpressions").and_then(|v| v.as_array());

    // matchLabels → selector_match_label/6
    if let Some(ml) = match_labels {
        for (k, v) in ml {
            if let Json::String(vs) = v {
                let mut args = owner();
                args.push(Value::String(k.clone()));
                args.push(Value::String(vs.clone()));
                store.add_fact("selector_match_label", args);
            }
        }
    }

    // matchExpressions
    if let Some(exprs) = match_exprs {
        for expr in exprs {
            let key = match expr.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => continue,
            };
            let op = expr.get("operator").and_then(|v| v.as_str()).unwrap_or("");
            let values = expr.get("values").and_then(|v| v.as_array());
            match op {
                "In" => {
                    for v in values.into_iter().flatten() {
                        if let Json::String(vs) = v {
                            let mut args = owner();
                            args.push(Value::String(key.into()));
                            args.push(Value::String(vs.clone()));
                            store.add_fact("selector_expr_in", args);
                        }
                    }
                }
                "NotIn" => {
                    for v in values.into_iter().flatten() {
                        if let Json::String(vs) = v {
                            let mut args = owner();
                            args.push(Value::String(key.into()));
                            args.push(Value::String(vs.clone()));
                            store.add_fact("selector_expr_notin", args);
                        }
                    }
                }
                "Exists" => {
                    let mut args = owner();
                    args.push(Value::String(key.into()));
                    store.add_fact("selector_expr_exists", args);
                }
                "DoesNotExist" => {
                    let mut args = owner();
                    args.push(Value::String(key.into()));
                    store.add_fact("selector_expr_notexists", args);
                }
                _ => {}
            }
        }
    }

    // Flat .spec.selector (Service-style) → treat as matchLabels
    if match_labels.is_none() && match_exprs.is_none() {
        if let Some(flat) = selector.as_object() {
            for (k, v) in flat {
                if let Json::String(vs) = v {
                    let mut args = owner();
                    args.push(Value::String(k.clone()));
                    args.push(Value::String(vs.clone()));
                    store.add_fact("selector_match_label", args);
                }
            }
        }
    }
}

// ---- JSON helpers ----

fn remove_nulls_map(m: &mut serde_json::Map<String, Json>) {
    m.retain(|_, v| !v.is_null());
    for v in m.values_mut() {
        match v {
            Json::Object(inner) => remove_nulls_map(inner),
            Json::Array(arr) => {
                for item in arr.iter_mut() {
                    if let Json::Object(inner) = item {
                        remove_nulls_map(inner);
                    }
                }
            }
            _ => {}
        }
    }
}

fn get_str<'a>(v: &'a Json, key: &str) -> Option<String> {
    v.get(key)?.as_str().map(str::to_string)
}

fn get_nested_str(v: &Json, path: &[&str]) -> Option<String> {
    get_json(v, path)?.as_str().map(str::to_string)
}

fn get_json<'a>(v: &'a Json, path: &[&str]) -> Option<&'a Json> {
    let mut cur = v;
    for key in path {
        cur = cur.get(key)?;
    }
    Some(cur)
}

fn get_map<'a>(v: &'a Json, path: &[&str]) -> Option<&'a serde_json::Map<String, Json>> {
    get_json(v, path)?.as_object()
}
