use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result};
use kube::api::{ApiResource, DynamicObject, ListParams};
use kube::{Api, Client, ResourceExt};
use mangle_common::Value;
use mangle_interpreter::MemStore;
use serde_json::Value as Json;

use crate::value::json_to_value;

// TODO: consider switching to concrete k8s-openapi types (Pod, ServiceAccount, etc.)
// for the cluster path once the loading pipeline is stable. DynamicObject avoids the
// typed→JSON→Mangle roundtrip but loses compile-time schema validation.

// Resources to list from the cluster. Fields: (group, version, kind, plural).
const CLUSTER_RESOURCES: &[(&str, &str, &str, &str)] = &[
    ("", "v1", "Pod", "pods"),
    ("", "v1", "ServiceAccount", "serviceaccounts"),
    ("rbac.authorization.k8s.io", "v1", "Role", "roles"),
    (
        "rbac.authorization.k8s.io",
        "v1",
        "RoleBinding",
        "rolebindings",
    ),
    (
        "rbac.authorization.k8s.io",
        "v1",
        "ClusterRole",
        "clusterroles",
    ),
    (
        "rbac.authorization.k8s.io",
        "v1",
        "ClusterRoleBinding",
        "clusterrolebindings",
    ),
];

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

    // Streaming deserializer handles both pretty-printed and minified multi-document JSON.
    // DynamicObject separates apiVersion/kind/metadata into typed fields; spec/status
    // land in obj.data. Nulls in data are dropped by json_to_value.
    for result in serde_json::Deserializer::from_reader(reader).into_iter::<DynamicObject>() {
        add_object(store, &result?, None);
    }
    Ok(())
}

pub async fn load_from_cluster(store: &mut MemStore, client: Client) -> Result<()> {
    for &(group, version, kind, plural) in CLUSTER_RESOURCES {
        let ar = ApiResource {
            group: group.to_string(),
            version: version.to_string(),
            api_version: if group.is_empty() {
                version.to_string()
            } else {
                format!("{group}/{version}")
            },
            kind: kind.to_string(),
            plural: plural.to_string(),
        };
        let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);
        for obj in api
            .list(&ListParams::default())
            .await
            .with_context(|| format!("listing {kind}"))?
        {
            add_object(store, &obj, Some((&ar.api_version, &ar.kind)));
        }
    }
    Ok(())
}

fn add_object(store: &mut MemStore, obj: &DynamicObject, type_hint: Option<(&str, &str)>) {
    let (api_version, kind) = type_hint.unwrap_or_else(|| {
        obj.types
            .as_ref()
            .map(|t| (t.api_version.as_str(), t.kind.as_str()))
            .unwrap_or_default()
    });
    let namespace = obj.namespace().unwrap_or_default();
    let name = obj.name_any();

    // Store spec/status blob as the Data argument of k8s/5. Mangle rules access it
    // via :match_field(Data, /spec, ...). Metadata fields are in the typed fields above
    // and extracted into separate EDB relations below.
    let data = json_to_value(&obj.data)
        .unwrap_or(Value::Compound(mangle_common::CompoundKind::Struct, vec![]));

    store.add_fact(
        "k8s",
        vec![
            Value::String(api_version.to_string()),
            Value::String(kind.to_string()),
            Value::String(namespace.clone()),
            Value::String(name.clone()),
            data,
        ],
    );

    extract_labels_and_selectors(
        store,
        api_version,
        kind,
        &namespace,
        &name,
        obj.metadata.labels.as_ref(),
        &obj.data,
    );
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

fn extract_labels_and_selectors(
    store: &mut MemStore,
    api_version: &str,
    kind: &str,
    namespace: &str,
    name: &str,
    labels: Option<&BTreeMap<String, String>>,
    data: &Json,
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
    if let Some(labels) = labels {
        for (k, v) in labels {
            let mut args = owner();
            args.push(Value::String(k.clone()));
            args.push(Value::String(v.clone()));
            store.add_fact("object_label", args);
        }
    }

    // spec.selector
    let selector = match data.get("spec").and_then(|s| s.get("selector")) {
        Some(s) => s,
        None => return,
    };

    let match_labels = selector.get("matchLabels").and_then(|v| v.as_object());
    let match_exprs = selector.get("matchExpressions").and_then(|v| v.as_array());

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

    // Flat spec.selector (Service-style, no matchLabels/matchExpressions) → matchLabels
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
