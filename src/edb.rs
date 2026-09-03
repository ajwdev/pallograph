// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use kube::api::{ApiResource, DynamicObject, ListParams};
use kube::core::labels::Expression;
use kube::{Api, Client, ResourceExt};
use mangle_common::Value;
use mangle_interpreter::MemStore;
use serde_json::Value as Json;

use serde::Deserialize;

use crate::value::json_to_value;

// TODO: consider switching to concrete k8s-openapi types (Pod, ServiceAccount, etc.)
// for the cluster path once the loading pipeline is stable. DynamicObject avoids the
// typed→JSON→Mangle roundtrip but loses compile-time schema validation.

// Resources to list from the cluster. Fields: (group, version, kind, plural).
const CLUSTER_RESOURCES: &[(&str, &str, &str, &str)] = &[
    ("", "v1", "Pod", "pods"),
    ("", "v1", "Node", "nodes"),
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

// ---- fact source abstraction ----

pub trait FactSource {
    fn k8s_objects(&mut self) -> Result<Vec<(DynamicObject, Option<(String, String)>)>>;
}

/// Loads k8s objects from a list of paths, globs, or directories.
/// - Plain directory: expands to `dir/**/*`, filtered to .json/.yaml/.yml
/// - Glob pattern: expanded as-is (supports **), filtered to .json/.yaml/.yml
/// - Explicit file: parsed directly
pub struct K8sManifestsSource {
    pub paths: Vec<String>,
}

impl FactSource for K8sManifestsSource {
    fn k8s_objects(&mut self) -> Result<Vec<(DynamicObject, Option<(String, String)>)>> {
        let mut objects = Vec::new();
        for pattern in &self.paths {
            let expanded = expand_pattern(pattern);
            for path in expanded {
                let path = path?;
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if !matches!(ext, "json" | "yaml" | "yml") {
                    continue;
                }
                let bytes = std::fs::read(&path)
                    .with_context(|| format!("reading {}", path.display()))?;
                let parsed = match ext {
                    "json" => parse_k8s_json(&bytes),
                    _ => parse_k8s_yaml(&bytes),
                }
                .with_context(|| format!("parsing {}", path.display()))?;
                objects.extend(parsed);
            }
        }
        Ok(objects)
    }
}

fn expand_pattern(pattern: &str) -> Box<dyn Iterator<Item = Result<std::path::PathBuf>>> {
    let path = std::path::Path::new(pattern);
    // Plain directory — expand recursively to all files.
    let glob_pattern = if path.is_dir() && !pattern.contains('*') {
        format!("{pattern}/**/*")
    } else {
        pattern.to_string()
    };
    let opts = glob::MatchOptions { require_literal_separator: false, ..Default::default() };
    match glob::glob_with(&glob_pattern, opts) {
        Ok(paths) => Box::new(paths.filter_map(|e| match e {
            Ok(p) if p.is_file() => Some(Ok(p)),
            Ok(_) => None,
            Err(e) => Some(Err(anyhow::anyhow!(e))),
        })),
        Err(e) => Box::new(std::iter::once(Err(anyhow::anyhow!("invalid glob pattern {pattern:?}: {e}")))),
    }
}

pub struct ClusterSource {
    objects: Vec<(DynamicObject, Option<(String, String)>)>,
}

/// Runs an arbitrary shell command via `sh -c` and parses the output as k8s objects.
pub struct ShellSource {
    pub command: String,
}

impl ClusterSource {
    pub async fn fetch(client: Client) -> Result<Self> {
        let mut objects = Vec::new();
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
                objects.push((obj, Some((ar.api_version.clone(), ar.kind.clone()))));
            }
        }
        Ok(Self { objects })
    }
}

impl FactSource for ClusterSource {
    fn k8s_objects(&mut self) -> Result<Vec<(DynamicObject, Option<(String, String)>)>> {
        Ok(std::mem::take(&mut self.objects))
    }
}

impl FactSource for ShellSource {
    fn k8s_objects(&mut self) -> Result<Vec<(DynamicObject, Option<(String, String)>)>> {
        let output = std::process::Command::new("sh")
            .args(["-c", &self.command])
            .output()
            .with_context(|| format!("running: {}", self.command))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("command exited non-zero: {}", stderr.trim());
        }
        parse_k8s_json(&output.stdout)
    }
}

/// Parse YAML bytes into DynamicObjects.
/// Handles multi-document YAML (--- separators) and List unwrapping.
fn parse_k8s_yaml(bytes: &[u8]) -> Result<Vec<(DynamicObject, Option<(String, String)>)>> {
    let text = std::str::from_utf8(bytes).context("invalid UTF-8")?;
    let mut objects = Vec::new();
    for document in serde_yaml::Deserializer::from_str(text) {
        let value = serde_yaml::Value::deserialize(document).context("parsing document")?;
        if let Some(items) = value.get("items").and_then(|i| i.as_sequence()) {
            for item in items {
                let obj: DynamicObject =
                    serde_yaml::from_value(item.clone()).context("parsing DynamicObject")?;
                objects.push((obj, None));
            }
        } else {
            let obj: DynamicObject =
                serde_yaml::from_value(value).context("parsing DynamicObject")?;
            objects.push((obj, None));
        }
    }
    Ok(objects)
}

/// Parse JSON bytes into DynamicObjects.
/// Handles List unwrapping and concatenated top-level objects (streaming).
fn parse_k8s_json(bytes: &[u8]) -> Result<Vec<(DynamicObject, Option<(String, String)>)>> {
    let mut objects = Vec::new();
    for result in serde_json::Deserializer::from_slice(bytes).into_iter::<serde_json::Value>() {
        let value = result.context("parsing JSON")?;
        if let Some(items) = value.get("items").and_then(|i| i.as_array()) {
            for item in items {
                let obj: DynamicObject =
                    serde_json::from_value(item.clone()).context("parsing DynamicObject")?;
                objects.push((obj, None));
            }
        } else {
            let obj: DynamicObject =
                serde_json::from_value(value).context("parsing DynamicObject")?;
            objects.push((obj, None));
        }
    }
    Ok(objects)
}

pub fn populate(store: &mut MemStore, source: &mut dyn FactSource) -> Result<()> {
    for (obj, type_hint) in source.k8s_objects()? {
        add_object(store, &obj, type_hint.as_ref().map(|(av, k)| (av.as_str(), k.as_str())));
    }
    Ok(())
}

pub fn load_from_manifests(store: &mut MemStore, paths: Vec<String>) -> Result<()> {
    populate(store, &mut K8sManifestsSource { paths })
}

pub async fn load_from_cluster(store: &mut MemStore, client: Client) -> Result<()> {
    let mut source = ClusterSource::fetch(client).await?;
    populate(store, &mut source)
}

pub fn load_k8s_from_command(store: &mut MemStore, command: &str) -> Result<()> {
    populate(store, &mut ShellSource { command: command.to_string() })
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

    if kind == "Node" {
        extract_node_data(store, &name, &obj.data);
    }
    if kind == "Pod" {
        extract_pod_scheduling(store, &namespace, &name, &obj.data);
        extract_pod_anti_affinity(store, &namespace, &name, &obj.data);
    }
    if kind == "ClusterRole" {
        extract_clusterrole_agg_selectors(store, &name, &obj.data);
    }
}

// ---- aggregation selector extraction ----

/// Emit the requirements from one aggregation selector entry as standard selector
/// EDB facts (selector_match_label, selector_expr_in, etc.) under a synthetic owner:
///
///   (ApiVersion="pallograph.dev/agg", Kind="ClusterRoleAggregation",
///    Namespace=<index>, Name=<aggregator ClusterRole name>)
///
/// Using the index in the Namespace slot gives each clusterRoleSelectors[i] its own
/// owner, so requirements within a single selector are AND'd (all must hold) while
/// separate selectors are OR'd (independent owners) — matching K8s semantics.
///
/// The sel_obj_candidate Case 2 rule in labels.mg (Namespace="") then pairs these
/// selectors against all cluster-scoped objects, which includes ClusterRoles.
/// The aggregation rule in rbac.mg pins the object to "rbac.authorization.k8s.io/v1"
/// / "ClusterRole" / "" to extract SourceCR from the matches.
///
/// Note: an empty clusterRoleSelector (no matchLabels, no matchExpressions) produces
/// no requirements, so selector_has_requirements is false and it matches nothing —
/// fail-closed behavior. This is safer for security analysis than the K8s controller
/// behavior (which treats an empty selector as "match all").
fn extract_clusterrole_agg_selectors(store: &mut MemStore, name: &str, data: &Json) {
    let selectors = data
        .get("aggregationRule")
        .and_then(|a| a.get("clusterRoleSelectors"))
        .and_then(|s| s.as_array());
    let Some(selectors) = selectors else { return };

    for (i, selector) in selectors.iter().enumerate() {
        let owner = vec![
            Value::String("pallograph.dev/agg".into()),
            Value::String("ClusterRoleAggregation".into()),
            Value::String(i.to_string()),
            Value::String(name.to_string()),
        ];
        emit_selector_requirements(store, owner, selector);
    }
}

/// Build the EDB fact tuples for one selector requirement (a kube `Expression`)
/// under `owner` (a 4-element [ApiVersion, Kind, Namespace, Name] slice),
/// returning them rather than writing to a store so the caller can add them to a
/// MemStore (load path) or assert/retract them on an Engine (REPL `::match`).
///
/// The fact shapes match those emitted by `emit_selector_requirements`:
///   Equal        -> selector_match_label
///   In           -> selector_expr_in     (one per value)
///   NotIn        -> selector_expr_notin  (one per value)
///   NotEqual     -> selector_expr_notin  (single value; NotEqual(k,v) == NotIn(k,{v}))
///   Exists       -> selector_expr_exists
///   DoesNotExist -> selector_expr_notexists
pub fn expression_facts(owner: &[Value], expr: &Expression) -> Vec<(&'static str, Vec<Value>)> {
    let fact = |rel: &'static str, extra: &[&str]| {
        let mut args = owner.to_vec();
        args.extend(extra.iter().map(|e| Value::String((*e).to_string())));
        (rel, args)
    };
    match expr {
        Expression::Equal(k, v) => vec![fact("selector_match_label", &[k, v])],
        Expression::NotEqual(k, v) => vec![fact("selector_expr_notin", &[k, v])],
        Expression::In(k, set) => set
            .iter()
            .map(|v| fact("selector_expr_in", &[k, v]))
            .collect(),
        Expression::NotIn(k, set) => set
            .iter()
            .map(|v| fact("selector_expr_notin", &[k, v]))
            .collect(),
        Expression::Exists(k) => vec![fact("selector_expr_exists", &[k])],
        Expression::DoesNotExist(k) => vec![fact("selector_expr_notexists", &[k])],
    }
}

// ---- label and selector extraction ----

/// Emit selector requirements (matchLabels and matchExpressions) as EDB facts.
///
/// The `owner` slice must be exactly four Values:
///   [ApiVersion, Kind, Namespace, Name]
/// which identifies the object that "owns" this selector (i.e. the object whose
/// spec.selector or aggregation clusterRoleSelector this is).
///
/// Emits: selector_match_label/6, selector_expr_in/6, selector_expr_notin/6,
///        selector_expr_exists/5, selector_expr_notexists/5.
///
/// These feed the selector_matches/8 engine in labels.mg, which implements
/// AND semantics (all requirements within one selector must hold) via the
/// *_unsatisfied negation pattern.
fn emit_selector_requirements(store: &mut MemStore, owner: Vec<Value>, selector: &Json) {
    let match_labels = selector.get("matchLabels").and_then(|v| v.as_object());
    let match_exprs = selector.get("matchExpressions").and_then(|v| v.as_array());

    if let Some(ml) = match_labels {
        for (k, v) in ml {
            if let Json::String(vs) = v {
                let mut args = owner.clone();
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
                            let mut args = owner.clone();
                            args.push(Value::String(key.into()));
                            args.push(Value::String(vs.clone()));
                            store.add_fact("selector_expr_in", args);
                        }
                    }
                }
                "NotIn" => {
                    for v in values.into_iter().flatten() {
                        if let Json::String(vs) = v {
                            let mut args = owner.clone();
                            args.push(Value::String(key.into()));
                            args.push(Value::String(vs.clone()));
                            store.add_fact("selector_expr_notin", args);
                        }
                    }
                }
                "Exists" => {
                    let mut args = owner.clone();
                    args.push(Value::String(key.into()));
                    store.add_fact("selector_expr_exists", args);
                }
                "DoesNotExist" => {
                    let mut args = owner.clone();
                    args.push(Value::String(key.into()));
                    store.add_fact("selector_expr_notexists", args);
                }
                _ => {}
            }
        }
    }

    // Flat selector (Service-style: no matchLabels/matchExpressions) → matchLabels
    if match_labels.is_none() && match_exprs.is_none() {
        if let Some(flat) = selector.as_object() {
            for (k, v) in flat {
                if let Json::String(vs) = v {
                    let mut args = owner.clone();
                    args.push(Value::String(k.clone()));
                    args.push(Value::String(vs.clone()));
                    store.add_fact("selector_match_label", args);
                }
            }
        }
    }
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
    let owner = vec![
        Value::String(api_version.into()),
        Value::String(kind.into()),
        Value::String(namespace.into()),
        Value::String(name.into()),
    ];

    // metadata.labels → object_label/6
    if let Some(labels) = labels {
        for (k, v) in labels {
            let mut args = owner.clone();
            args.push(Value::String(k.clone()));
            args.push(Value::String(v.clone()));
            store.add_fact("object_label", args);
        }
    }

    // spec.selector → selector_match_label/selector_expr_*/6
    let Some(selector) = data.get("spec").and_then(|s| s.get("selector")) else {
        return;
    };
    emit_selector_requirements(store, owner, selector);
}

fn extract_pod_scheduling(store: &mut MemStore, namespace: &str, name: &str, data: &Json) {
    // spec.nodeSelector → pod_node_selector(Namespace, Name, Key, Value)
    if let Some(sel) = data.get("spec").and_then(|s| s.get("nodeSelector")).and_then(|s| s.as_object()) {
        for (key, val) in sel {
            if let Json::String(v) = val {
                store.add_fact("pod_node_selector", vec![
                    Value::String(namespace.to_string()),
                    Value::String(name.to_string()),
                    Value::String(key.clone()),
                    Value::String(v.clone()),
                ]);
            }
        }
    }
}

fn extract_pod_anti_affinity(store: &mut MemStore, namespace: &str, name: &str, data: &Json) {
    let terms = data
        .get("spec")
        .and_then(|s| s.get("affinity"))
        .and_then(|a| a.get("podAntiAffinity"))
        .and_then(|aa| aa.get("requiredDuringSchedulingIgnoredDuringExecution"))
        .and_then(|r| r.as_array());

    let Some(terms) = terms else { return };

    for term in terms {
        let topology_key = term
            .get("topologyKey")
            .and_then(|v| v.as_str())
            .unwrap_or("kubernetes.io/hostname");

        let Some(match_labels) = term
            .get("labelSelector")
            .and_then(|s| s.get("matchLabels"))
            .and_then(|m| m.as_object())
        else {
            continue;
        };

        for (key, val) in match_labels {
            if let Json::String(v) = val {
                store.add_fact("pod_anti_affinity_req", vec![
                    Value::String(namespace.to_string()),
                    Value::String(name.to_string()),
                    Value::String(key.clone()),
                    Value::String(v.clone()),
                    Value::String(topology_key.to_string()),
                ]);
            }
        }
    }
}

fn extract_node_data(store: &mut MemStore, name: &str, data: &Json) {
    // status.allocatable → node_allocatable(Name, Resource, Quantity)
    // node_taint is derived via Mangle rules in base.mg using :list:member + :match_field.
    if let Some(alloc) = data.get("status").and_then(|s| s.get("allocatable")).and_then(|a| a.as_object()) {
        for (resource, quantity) in alloc {
            let q = match quantity {
                Json::String(s) => s.clone(),
                other => other.to_string(),
            };
            store.add_fact("node_allocatable", vec![
                Value::String(name.to_string()),
                Value::String(resource.clone()),
                Value::String(q),
            ]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Engine, InterpreterBackend};
    use serde_json::json;
    use std::path::Path;

    fn engine_from_store(store: MemStore) -> Engine {
        Engine::new(store, Path::new("rules"), Box::new(InterpreterBackend))
            .expect("engine")
    }

    /// Construct and add a ClusterRole with explicit rules.
    fn add_clusterrole(
        store: &mut MemStore,
        name: &str,
        labels: serde_json::Value,
        rules: serde_json::Value,
    ) {
        let obj: DynamicObject = serde_json::from_value(json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {
                "name": name,
                "labels": labels
            },
            "rules": rules
        }))
        .unwrap();
        add_object(store, &obj, Some(("rbac.authorization.k8s.io/v1", "ClusterRole")));
    }

    /// Construct and add an aggregating ClusterRole (no direct rules, aggregationRule only).
    fn add_aggregating_clusterrole(
        store: &mut MemStore,
        name: &str,
        selectors: serde_json::Value,
    ) {
        let obj: DynamicObject = serde_json::from_value(json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": { "name": name },
            "aggregationRule": {
                "clusterRoleSelectors": selectors
            },
            "rules": []
        }))
        .unwrap();
        add_object(store, &obj, Some(("rbac.authorization.k8s.io/v1", "ClusterRole")));
    }

    fn has_clusterrole_perm(
        result: &crate::engine::EvalStore,
        role: &str,
        apigroup: &str,
        resource: &str,
        verb: &str,
    ) -> bool {
        result.scan("clusterrole_perm").iter().any(|row| {
            row == &vec![
                Value::String(role.into()),
                Value::String(apigroup.into()),
                Value::String(resource.into()),
                Value::String(verb.into()),
            ]
        })
    }

    // AND semantics: all matchLabels within one selector must be satisfied.
    #[test]
    fn aggregation_and_semantics_within_selector() {
        let mut store = MemStore::new();

        // One selector entry with two requirements: key-a=true AND key-b=true.
        add_aggregating_clusterrole(&mut store, "my-agg", json!([
            {"matchLabels": {"key-a": "true", "key-b": "true"}}
        ]));
        // Source CR with only key-a — must NOT be aggregated.
        add_clusterrole(&mut store, "only-a", json!({"key-a": "true"}), json!([
            {"apiGroups": [""], "resources": ["pods"], "verbs": ["list"]}
        ]));
        // Source CR with both keys — MUST be aggregated.
        add_clusterrole(&mut store, "both-ab", json!({"key-a": "true", "key-b": "true"}), json!([
            {"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}
        ]));

        let result = engine_from_store(store).evaluate().unwrap();

        assert!(
            !has_clusterrole_perm(&result, "my-agg", "", "pods", "list"),
            "single-label match (only key-a) should not satisfy a two-label selector"
        );
        assert!(
            has_clusterrole_perm(&result, "my-agg", "", "pods", "get"),
            "both-label match should aggregate"
        );
    }

    // OR semantics: separate selector entries are independent — either matching is enough.
    #[test]
    fn aggregation_or_semantics_across_selectors() {
        let mut store = MemStore::new();

        add_aggregating_clusterrole(&mut store, "my-agg", json!([
            {"matchLabels": {"sel-a": "true"}},
            {"matchLabels": {"sel-b": "true"}}
        ]));
        add_clusterrole(&mut store, "cr-a", json!({"sel-a": "true"}), json!([
            {"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}
        ]));
        add_clusterrole(&mut store, "cr-b", json!({"sel-b": "true"}), json!([
            {"apiGroups": [""], "resources": ["services"], "verbs": ["get"]}
        ]));

        let result = engine_from_store(store).evaluate().unwrap();

        assert!(
            has_clusterrole_perm(&result, "my-agg", "", "pods", "get"),
            "CR matching selector A should be aggregated"
        );
        assert!(
            has_clusterrole_perm(&result, "my-agg", "", "services", "get"),
            "CR matching selector B should be aggregated"
        );
    }

    // matchExpressions / Exists: CR with the key present is aggregated, without is not.
    #[test]
    fn aggregation_match_expressions_exists() {
        let mut store = MemStore::new();

        add_aggregating_clusterrole(&mut store, "my-agg", json!([
            {"matchExpressions": [{"key": "rbac.io/agg", "operator": "Exists"}]}
        ]));
        add_clusterrole(&mut store, "has-key", json!({"rbac.io/agg": "anything"}), json!([
            {"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["get"]}
        ]));
        add_clusterrole(&mut store, "no-key", json!({}), json!([
            {"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["list"]}
        ]));

        let result = engine_from_store(store).evaluate().unwrap();

        assert!(
            has_clusterrole_perm(&result, "my-agg", "apps", "deployments", "get"),
            "Exists should match CR with key present"
        );
        assert!(
            !has_clusterrole_perm(&result, "my-agg", "apps", "deployments", "list"),
            "Exists should not match CR without key"
        );
    }

    // matchExpressions / In: only CRs whose label value is in the allowed set are aggregated.
    #[test]
    fn aggregation_match_expressions_in() {
        let mut store = MemStore::new();

        add_aggregating_clusterrole(&mut store, "my-agg", json!([
            {"matchExpressions": [
                {"key": "tier", "operator": "In", "values": ["admin", "edit"]}
            ]}
        ]));
        add_clusterrole(&mut store, "is-admin", json!({"tier": "admin"}), json!([
            {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}
        ]));
        add_clusterrole(&mut store, "is-view", json!({"tier": "view"}), json!([
            {"apiGroups": [""], "resources": ["secrets"], "verbs": ["list"]}
        ]));

        let result = engine_from_store(store).evaluate().unwrap();

        assert!(
            has_clusterrole_perm(&result, "my-agg", "", "secrets", "get"),
            "tier=admin should match In(admin,edit)"
        );
        assert!(
            !has_clusterrole_perm(&result, "my-agg", "", "secrets", "list"),
            "tier=view should not match In(admin,edit)"
        );
    }

    // Idempotency: a ClusterRole with both a pre-populated .rules AND an aggregationRule
    // pointing at the same source must yield the same permission set as either alone.
    // This guards against double-counting on live clusters where the aggregation controller
    // has already written resolved rules into .rules.
    #[test]
    fn aggregation_idempotency_double_count() {
        let mut store = MemStore::new();

        // Aggregator that also has the rule pre-populated (as on a live cluster).
        let obj: DynamicObject = serde_json::from_value(json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": { "name": "my-agg" },
            "aggregationRule": {
                "clusterRoleSelectors": [{"matchLabels": {"agg-to-me": "true"}}]
            },
            "rules": [
                {"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}
            ]
        }))
        .unwrap();
        add_object(&mut store, &obj, Some(("rbac.authorization.k8s.io/v1", "ClusterRole")));

        // Source CR that contributes the same rule.
        add_clusterrole(&mut store, "src-cr", json!({"agg-to-me": "true"}), json!([
            {"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}
        ]));

        let result = engine_from_store(store).evaluate().unwrap();

        // Datalog relations are sets: duplicate derivations collapse.
        let count = result
            .scan("clusterrole_perm")
            .iter()
            .filter(|row| {
                row.len() == 4
                    && row[0] == Value::String("my-agg".into())
                    && row[3] == Value::String("get".into())
            })
            .count();
        assert_eq!(count, 1, "duplicate derivation paths must collapse to a single fact");
    }

    fn kinds(objects: &[(DynamicObject, Option<(String, String)>)]) -> Vec<&str> {
        objects.iter().map(|(o, _)| o.types.as_ref().unwrap().kind.as_str()).collect()
    }

    #[test]
    fn json_single_object() {
        let input = r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"pod-a"}}"#;
        let result = parse_k8s_json(input.as_bytes()).unwrap();
        assert_eq!(kinds(&result), vec!["Pod"]);
    }

    #[test]
    fn json_concatenated_objects() {
        let input = r#"
            {"apiVersion":"v1","kind":"Pod","metadata":{"name":"pod-a"}}
            {"apiVersion":"v1","kind":"Pod","metadata":{"name":"pod-b"}}
            {"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"sa-a"}}
        "#;
        let result = parse_k8s_json(input.as_bytes()).unwrap();
        assert_eq!(kinds(&result), vec!["Pod", "Pod", "ServiceAccount"]);
    }

    #[test]
    fn json_list_unwrapping() {
        let input = r#"{
            "apiVersion": "v1",
            "kind": "List",
            "items": [
                {"apiVersion":"v1","kind":"Pod","metadata":{"name":"pod-a"}},
                {"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"sa-a"}}
            ]
        }"#;
        let result = parse_k8s_json(input.as_bytes()).unwrap();
        assert_eq!(kinds(&result), vec!["Pod", "ServiceAccount"]);
    }

    #[test]
    fn yaml_single_document() {
        let input = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: pod-a\n";
        let result = parse_k8s_yaml(input.as_bytes()).unwrap();
        assert_eq!(kinds(&result), vec!["Pod"]);
    }

    #[test]
    fn yaml_multi_document() {
        let input = "\
apiVersion: v1
kind: Pod
metadata:
  name: pod-a
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sa-a
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cr-a
rules: []
";
        let result = parse_k8s_yaml(input.as_bytes()).unwrap();
        assert_eq!(kinds(&result), vec!["Pod", "ServiceAccount", "ClusterRole"]);
    }

    #[test]
    fn yaml_list_unwrapping() {
        let input = "\
apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: Pod
    metadata:
      name: pod-a
  - apiVersion: v1
    kind: ServiceAccount
    metadata:
      name: sa-a
";
        let result = parse_k8s_yaml(input.as_bytes()).unwrap();
        assert_eq!(kinds(&result), vec!["Pod", "ServiceAccount"]);
    }
}
