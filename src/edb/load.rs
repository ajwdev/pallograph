// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{Context, Result};
use kube::api::DynamicObject;

use serde::Deserialize;

type Objects = Vec<(DynamicObject, Option<(String, String)>)>;

/// Push `value` as objects: unwrap a `List`'s `items`, else a single object.
fn collect_objects(value: serde_json::Value, out: &mut Objects) -> Result<()> {
    match value.get("items").and_then(|i| i.as_array()) {
        Some(items) => {
            for item in items {
                let obj = serde_json::from_value(item.clone()).context("parsing DynamicObject")?;
                out.push((obj, None));
            }
        }
        None => {
            let obj = serde_json::from_value(value).context("parsing DynamicObject")?;
            out.push((obj, None));
        }
    }
    Ok(())
}

/// Parse multi-document YAML (`---` separators) into DynamicObjects, with
/// `List` unwrapping.
pub(super) fn parse_k8s_yaml(bytes: &[u8]) -> Result<Objects> {
    let text = std::str::from_utf8(bytes).context("invalid UTF-8")?;
    let mut objects = Vec::new();
    for document in serde_yaml::Deserializer::from_str(text) {
        let value = serde_json::Value::deserialize(document).context("parsing document")?;
        collect_objects(value, &mut objects)?;
    }
    Ok(objects)
}

/// Parse concatenated top-level JSON objects (streaming) into DynamicObjects,
/// with `List` unwrapping.
pub(super) fn parse_k8s_json(bytes: &[u8]) -> Result<Objects> {
    let mut objects = Vec::new();
    for result in serde_json::Deserializer::from_slice(bytes).into_iter::<serde_json::Value>() {
        collect_objects(result.context("parsing JSON")?, &mut objects)?;
    }
    Ok(objects)
}
