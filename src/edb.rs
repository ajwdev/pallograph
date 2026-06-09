use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

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

// ---- RBAC collection ----
//
// During loading, RBAC objects are parsed into RbacCollector. After all files
// are loaded, emit_can_facts emits can(Principal, Ns, Resource, Verb) EDB facts.
// Wildcards ("*") are preserved as-is — no expansion. Escalation rules in
// escalation.mg handle the 4 wildcard combos explicitly at each usage site.
// CRB grants are expanded to every known concrete namespace (that expansion IS
// enumerable since namespaces are finite and loaded from cluster objects).

#[derive(Default)]
struct RbacCollector {
    // name → [(apiGroup, resource, verb)]
    clusterrole_rules: HashMap<String, Vec<(String, String, String)>>,
    // aggregation: name → [(label_key, label_value)] selector conditions
    clusterrole_agg: HashMap<String, Vec<(String, String)>>,
    // name → labels map (for matching agg selectors)
    clusterrole_labels: HashMap<String, HashMap<String, String>>,
    // (namespace, name) → [(apiGroup, resource, verb)]
    role_rules: HashMap<(String, String), Vec<(String, String, String)>>,
    rolebindings: Vec<RbacBinding>,
    clusterrolebindings: Vec<RbacClusterBinding>,
    // All concrete namespaces seen across any k8s object
    namespaces: HashSet<String>,
}

struct RbacBinding {
    namespace: String,
    subjects: Vec<RbacSubject>,
    roleref_kind: String,
    roleref_name: String,
}

struct RbacClusterBinding {
    subjects: Vec<RbacSubject>,
    roleref_name: String,
}

#[derive(Clone)]
enum RbacSubject {
    ServiceAccount { namespace: String, name: String },
    User(String),
    Group(String),
}

// ---- fact source abstraction ----

pub trait FactSource {
    fn k8s_objects(&mut self) -> Result<Vec<(DynamicObject, Option<(String, String)>)>>;
    fn api_resource_lines(&mut self) -> Result<Vec<String>>;
}

pub struct FixtureSource {
    pub dir: PathBuf,
}

impl FactSource for FixtureSource {
    fn k8s_objects(&mut self) -> Result<Vec<(DynamicObject, Option<(String, String)>)>> {
        let mut objects = Vec::new();
        for filename in &["allpods.json", "nodes.json", "serviceaccounts.json", "rbac.json", "test_scheduling.json"] {
            let path = self.dir.join(filename);
            if !path.exists() {
                continue;
            }
            let file = std::fs::File::open(&path).with_context(|| format!("opening {filename}"))?;
            for result in serde_json::Deserializer::from_reader(BufReader::new(file)).into_iter::<DynamicObject>() {
                objects.push((result.with_context(|| format!("parsing {filename}"))?, None));
            }
        }
        Ok(objects)
    }

    fn api_resource_lines(&mut self) -> Result<Vec<String>> {
        let path = self.dir.join("api-resources.txt");
        if !path.exists() {
            return Ok(vec![]);
        }
        let file = std::fs::File::open(&path).context("opening api-resources.txt")?;
        BufReader::new(file)
            .lines()
            .map(|l| l.context("reading api-resources.txt"))
            .collect()
    }
}

pub struct ClusterSource {
    objects: Vec<(DynamicObject, Option<(String, String)>)>,
}

/// Shells out to `kubectl <args> -o json` and parses the resulting k8s objects.
pub struct KubectlSource {
    pub args: Vec<String>,
}

/// Reads a single JSON file containing k8s objects (DynamicObject, multi-doc, or a List).
pub struct JsonFileSource {
    pub path: PathBuf,
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

    fn api_resource_lines(&mut self) -> Result<Vec<String>> {
        Ok(vec![])
    }
}

impl FactSource for KubectlSource {
    fn k8s_objects(&mut self) -> Result<Vec<(DynamicObject, Option<(String, String)>)>> {
        let mut cmd = std::process::Command::new("kubectl");
        cmd.args(&self.args);
        // Append -o json if the user didn't include it.
        if !self.args.iter().any(|a| a == "-o" || a == "--output") {
            cmd.args(["-o", "json"]);
        }
        let output = cmd.output().context("running kubectl")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("kubectl exited non-zero: {}", stderr.trim());
        }
        parse_k8s_json(&output.stdout)
    }

    fn api_resource_lines(&mut self) -> Result<Vec<String>> {
        Ok(vec![])
    }
}

impl FactSource for JsonFileSource {
    fn k8s_objects(&mut self) -> Result<Vec<(DynamicObject, Option<(String, String)>)>> {
        let bytes = std::fs::read(&self.path)
            .with_context(|| format!("reading {}", self.path.display()))?;
        parse_k8s_json(&bytes)
    }

    fn api_resource_lines(&mut self) -> Result<Vec<String>> {
        Ok(vec![])
    }
}

/// Parse raw JSON bytes into DynamicObjects. Handles:
/// - A top-level `{"kind": "List", "items": [...]}` wrapper (kubectl default)
/// - A single object
/// - Concatenated / multi-doc (streaming deserialization)
fn parse_k8s_json(bytes: &[u8]) -> Result<Vec<(DynamicObject, Option<(String, String)>)>> {
    let mut objects = Vec::new();
    // Try top-level array/List parse first, then fall back to streaming.
    let v: serde_json::Value = serde_json::from_slice(bytes).context("parsing JSON")?;
    if let Some(items) = v.get("items").and_then(|i| i.as_array()) {
        for item in items {
            let obj: DynamicObject =
                serde_json::from_value(item.clone()).context("parsing DynamicObject")?;
            objects.push((obj, None));
        }
    } else {
        // Single object or fall through to streaming.
        for result in serde_json::Deserializer::from_slice(bytes).into_iter::<DynamicObject>() {
            objects.push((result.context("parsing DynamicObject")?, None));
        }
    }
    Ok(objects)
}

pub fn populate(store: &mut MemStore, source: &mut dyn FactSource) -> Result<()> {
    let mut rbac = RbacCollector::default();
    for (obj, type_hint) in source.k8s_objects()? {
        add_object(store, &obj, type_hint.as_ref().map(|(av, k)| (av.as_str(), k.as_str())));
        collect_rbac_object(&mut rbac, &obj);
    }
    for line in source.api_resource_lines()? {
        let line = line.trim().to_string();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (resource, api_group) = line.split_once('.').unwrap_or((&line, ""));
        store.add_fact(
            "api_resource",
            vec![
                Value::String(api_group.to_string()),
                Value::String(resource.to_string()),
            ],
        );
    }
    emit_can_facts(store, &rbac);
    for ns in &rbac.namespaces {
        store.add_fact("namespace", vec![Value::String(ns.clone())]);
    }
    Ok(())
}

pub fn load_all(store: &mut MemStore, fixtures_dir: &Path) -> Result<()> {
    populate(store, &mut FixtureSource { dir: fixtures_dir.to_path_buf() })
}

pub async fn load_from_cluster(store: &mut MemStore, client: Client) -> Result<()> {
    let mut source = ClusterSource::fetch(client).await?;
    populate(store, &mut source)
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

// ---- RBAC collection helpers ----

fn collect_rbac_object(rbac: &mut RbacCollector, obj: &DynamicObject) {
    let kind = obj.types.as_ref().map(|t| t.kind.as_str()).unwrap_or("");
    let namespace = obj.namespace().unwrap_or_default();
    let name = obj.name_any();

    if !namespace.is_empty() {
        rbac.namespaces.insert(namespace.clone());
    }

    match kind {
        "ClusterRole" => {
            let rules = extract_role_rules(&obj.data);
            rbac.clusterrole_rules.insert(name.clone(), rules);

            if let Some(labels) = &obj.metadata.labels {
                rbac.clusterrole_labels.insert(
                    name.clone(),
                    labels.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                );
            }

            if let Some(selectors) = obj
                .data
                .get("aggregationRule")
                .and_then(|a| a.get("clusterRoleSelectors"))
                .and_then(|s| s.as_array())
            {
                let mut agg = Vec::new();
                for sel in selectors {
                    if let Some(ml) = sel.get("matchLabels").and_then(|m| m.as_object()) {
                        for (k, v) in ml {
                            if let Json::String(vs) = v {
                                agg.push((k.clone(), vs.clone()));
                            }
                        }
                    }
                }
                if !agg.is_empty() {
                    rbac.clusterrole_agg.insert(name, agg);
                }
            }
        }
        "Role" => {
            rbac.role_rules.insert((namespace, name), extract_role_rules(&obj.data));
        }
        "RoleBinding" => {
            if let Some((roleref_kind, roleref_name)) = extract_roleref(&obj.data) {
                rbac.rolebindings.push(RbacBinding {
                    namespace,
                    subjects: extract_subjects(&obj.data),
                    roleref_kind,
                    roleref_name,
                });
            }
        }
        "ClusterRoleBinding" => {
            if let Some((_, roleref_name)) = extract_roleref(&obj.data) {
                rbac.clusterrolebindings.push(RbacClusterBinding {
                    subjects: extract_subjects(&obj.data),
                    roleref_name,
                });
            }
        }
        _ => {}
    }
}

fn extract_role_rules(data: &Json) -> Vec<(String, String, String)> {
    let mut result = Vec::new();
    let Some(rules) = data.get("rules").and_then(|r| r.as_array()) else {
        return result;
    };
    for rule in rules {
        let api_groups = json_str_list(rule, "apiGroups");
        let resources = json_str_list(rule, "resources");
        let verbs = json_str_list(rule, "verbs");
        for ag in &api_groups {
            for r in &resources {
                for v in &verbs {
                    result.push((ag.clone(), r.clone(), v.clone()));
                }
            }
        }
    }
    result
}

fn extract_subjects(data: &Json) -> Vec<RbacSubject> {
    let Some(subjects) = data.get("subjects").and_then(|s| s.as_array()) else {
        return vec![];
    };
    subjects
        .iter()
        .filter_map(|subj| {
            let kind = subj.get("kind")?.as_str()?;
            let name = subj.get("name")?.as_str()?.to_string();
            match kind {
                "ServiceAccount" => {
                    let ns = subj
                        .get("namespace")
                        .and_then(|n| n.as_str())
                        .unwrap_or("")
                        .to_string();
                    Some(RbacSubject::ServiceAccount { namespace: ns, name })
                }
                "User" => Some(RbacSubject::User(name)),
                "Group" => Some(RbacSubject::Group(name)),
                _ => None,
            }
        })
        .collect()
}

fn extract_roleref(data: &Json) -> Option<(String, String)> {
    let rr = data.get("roleRef")?;
    let kind = rr.get("kind")?.as_str()?.to_string();
    let name = rr.get("name")?.as_str()?.to_string();
    Some((kind, name))
}

fn json_str_list(val: &Json, key: &str) -> Vec<String> {
    val.get(key)
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

// ---- can fact emission ----

fn emit_can_facts(store: &mut MemStore, rbac: &RbacCollector) {
    let resolved = resolve_clusterrole_perms(rbac);

    // RoleBinding → scoped to the binding's namespace. Wildcards preserved as-is.
    for rb in &rbac.rolebindings {
        let perms = match rb.roleref_kind.as_str() {
            "Role" => rbac
                .role_rules
                .get(&(rb.namespace.clone(), rb.roleref_name.clone()))
                .map(Vec::as_slice)
                .unwrap_or_default(),
            "ClusterRole" => resolved
                .get(&rb.roleref_name)
                .map(Vec::as_slice)
                .unwrap_or_default(),
            _ => continue,
        };
        for subj in &rb.subjects {
            let principal = subject_principal(subj);
            for (apigroup, resource, verb) in perms {
                add_can(store, &principal, &rb.namespace, apigroup, resource, verb);
            }
        }
    }

    // ClusterRoleBinding → one fact per concrete namespace. Wildcards preserved.
    for crb in &rbac.clusterrolebindings {
        let perms = resolved
            .get(&crb.roleref_name)
            .map(Vec::as_slice)
            .unwrap_or_default();
        for subj in &crb.subjects {
            let principal = subject_principal(subj);
            for ns in &rbac.namespaces {
                for (apigroup, resource, verb) in perms {
                    add_can(store, &principal, ns, apigroup, resource, verb);
                }
            }
        }
    }
}

fn resolve_clusterrole_perms(
    rbac: &RbacCollector,
) -> HashMap<String, Vec<(String, String, String)>> {
    let mut resolved = rbac.clusterrole_rules.clone();

    // One pass handles the typical one-level aggregation depth in Kubernetes.
    for (agg_name, selectors) in &rbac.clusterrole_agg {
        let extra: Vec<(String, String, String)> = rbac
            .clusterrole_labels
            .iter()
            .filter(|(_, labels)| {
                selectors
                    .iter()
                    .all(|(k, v)| labels.get(k).map(|lv| lv == v).unwrap_or(false))
            })
            .flat_map(|(source_name, _)| {
                rbac.clusterrole_rules
                    .get(source_name)
                    .cloned()
                    .unwrap_or_default()
            })
            .collect();
        resolved.entry(agg_name.clone()).or_default().extend(extra);
    }

    resolved
}


fn subject_principal(subj: &RbacSubject) -> String {
    match subj {
        RbacSubject::ServiceAccount { namespace, name } => {
            format!("system:serviceaccount:{namespace}:{name}")
        }
        RbacSubject::User(name) | RbacSubject::Group(name) => name.clone(),
    }
}

fn add_can(store: &mut MemStore, principal: &str, ns: &str, apigroup: &str, resource: &str, verb: &str) {
    store.add_fact(
        "can",
        vec![
            Value::String(principal.to_string()),
            Value::String(ns.to_string()),
            Value::String(apigroup.to_string()),
            Value::String(resource.to_string()),
            Value::String(verb.to_string()),
        ],
    );
}

// ---- existing extraction helpers (unchanged) ----

fn extract_clusterrole_agg_selectors(store: &mut MemStore, name: &str, data: &Json) {
    let selectors = data
        .get("aggregationRule")
        .and_then(|a| a.get("clusterRoleSelectors"))
        .and_then(|s| s.as_array());
    let Some(selectors) = selectors else { return };

    for selector in selectors {
        let Some(match_labels) = selector
            .get("matchLabels")
            .and_then(|m| m.as_object())
        else {
            continue;
        };
        for (key, val) in match_labels {
            if let Json::String(v) = val {
                store.add_fact("clusterrole_agg_selector", vec![
                    Value::String(name.to_string()),
                    Value::String(key.clone()),
                    Value::String(v.clone()),
                ]);
            }
        }
    }
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
