// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Label selector compatibility: checks `selector_matches` (rules/k8s_labels.mg)
//! and `k8s::match` against apimachinery's selector code.
//!
//! Each world under `tests/labels_compat/worlds/` is an `objects.yaml`, and
//! optionally a `queries.ndjson` of kubectl-style selectors. What Kubernetes
//! selects is generated, not committed: `hack/compat-gen.sh` runs
//! `k8s-oracle labels eval` (tools/k8s-oracle) to write
//! `selections.ndjson` and `query-results.ndjson` under
//! `target/labels-compat/worlds/<world>/`. Both backends must match the
//! oracle exactly; there is no baseline of known gaps.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};
use mangle_common::Value;
use mangle_interpreter::MemStore;
use pallograph::api::{At, Core, LocalCore};
use pallograph::edb;
use pallograph::engine::{self, Backend, DdBackend, Engine, InterpreterBackend};
use serde_json::Value as Json;

/// An object as (apiVersion, kind, namespace, name).
type ObjectRef = [String; 4];

/// A selector: the object that owns it, and which of its selectors it is
/// (the field path, e.g. spec.selector).
type SelectorRef = (ObjectRef, String);

/// Where hack/compat-gen.sh writes the oracle output:
/// `<target>/labels-compat/worlds`, `<target>/tmp` being
/// `CARGO_TARGET_TMPDIR`.
fn generated_dir() -> PathBuf {
    Path::new(env!("CARGO_TARGET_TMPDIR"))
        .parent()
        .expect("CARGO_TARGET_TMPDIR has a parent")
        .join("labels-compat/worlds")
}

/// The generated world directories, after checking each exists and is
/// newer than its world and the oracle's source.
fn worlds() -> Result<Vec<PathBuf>> {
    let modified = |path: &Path| -> Result<std::time::SystemTime> {
        Ok(std::fs::metadata(path)
            .with_context(|| format!("reading {}", path.display()))?
            .modified()?)
    };
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut oracle_modified = std::time::SystemTime::UNIX_EPOCH;
    for entry in std::fs::read_dir(manifest_dir.join("tools/k8s-oracle"))? {
        oracle_modified = oracle_modified.max(modified(&entry?.path())?);
    }

    let regenerate = "run hack/compat-gen.sh (in nix develop) to regenerate";
    let mut worlds = Vec::new();
    for entry in std::fs::read_dir(manifest_dir.join("tests/labels_compat/worlds"))? {
        let source = entry?.path();
        let world = generated_dir().join(source.file_name().unwrap());
        let selections = world.join("selections.ndjson");
        if !selections.exists() {
            bail!("{} is missing; {regenerate}", selections.display());
        }
        let generated = modified(&selections)?;
        for file in std::fs::read_dir(&source)? {
            if generated < modified(&file?.path())?.max(oracle_modified) {
                bail!(
                    "{} is older than its world or tools/k8s-oracle; {regenerate}",
                    selections.display()
                );
            }
        }
        worlds.push(world);
    }
    worlds.sort();
    Ok(worlds)
}

fn read_ndjson(path: &Path) -> Result<Vec<Json>> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut rows = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line.with_context(|| format!("reading {}", path.display()))?;
        if line.is_empty() {
            continue;
        }
        rows.push(
            serde_json::from_str(&line).with_context(|| format!("parsing {}", path.display()))?,
        );
    }
    Ok(rows)
}

fn json_ref(object: &Json) -> ObjectRef {
    ["apiVersion", "kind", "namespace", "name"]
        .map(|field| object[field].as_str().unwrap_or_default().to_string())
}

fn text(value: &Value) -> Result<String> {
    match value {
        Value::String(text) => Ok(text.clone()),
        other => bail!("expected a string, got {other:?}"),
    }
}

fn value_ref(row: &[Value]) -> Result<ObjectRef> {
    Ok([
        text(&row[0])?,
        text(&row[1])?,
        text(&row[2])?,
        text(&row[3])?,
    ])
}

fn backends() -> Vec<(&'static str, Box<dyn Backend>)> {
    vec![
        ("interpreter", Box::new(InterpreterBackend)),
        ("dd", Box::new(DdBackend { provenance: false })),
    ]
}

/// Every difference between Pallograph and the oracle in `world` on
/// `backend`, one line each.
fn check_world(world: &Path, backend: Box<dyn Backend>) -> Result<Vec<String>> {
    let mut store = MemStore::new();
    let manifest = world.join("objects.yaml");
    edb::load_from_manifests(&mut store, vec![manifest.to_string_lossy().into_owned()])?;
    let rules = Path::new(env!("CARGO_MANIFEST_DIR")).join("rules");
    let engine = Engine::new(store, &rules, backend)?;
    let live = engine.evaluate()?;

    let mut differences = Vec::new();
    let mut compare = |what: &str, got: BTreeSet<ObjectRef>, want: BTreeSet<ObjectRef>| {
        for extra in got.difference(&want) {
            differences.push(format!("{what}: extra {}", extra.join("/")));
        }
        for missing in want.difference(&got) {
            differences.push(format!("{what}: missing {}", missing.join("/")));
        }
    };

    // selector_matches, selector by selector (an owner and which of its
    // selectors), so a difference names the selector.
    let mut got: BTreeSet<(SelectorRef, ObjectRef)> = BTreeSet::new();
    for row in live.scan("selector_matches") {
        let selector = (value_ref(&row[0..4])?, text(&row[4])?);
        got.insert((selector, value_ref(&row[5..9])?));
    }
    let mut want: BTreeSet<(SelectorRef, ObjectRef)> = BTreeSet::new();
    for row in read_ndjson(&world.join("selections.ndjson"))? {
        let selector = (
            json_ref(&row["owner"]),
            row["selector"].as_str().unwrap_or_default().to_string(),
        );
        want.insert((selector, json_ref(&row["object"])));
    }
    let selectors: BTreeSet<&SelectorRef> = got
        .iter()
        .chain(&want)
        .map(|(selector, _)| selector)
        .collect();
    for selector in selectors {
        let objects = |pairs: &BTreeSet<(SelectorRef, ObjectRef)>| {
            pairs
                .iter()
                .filter(|(s, _)| s == selector)
                .map(|(_, object)| object.clone())
                .collect()
        };
        let (owner, field) = selector;
        compare(
            &format!("{} {field}", owner.join("/")),
            objects(&got),
            objects(&want),
        );
    }

    // k8s::match and k8s::match-all, through Core like the REPL.
    let queries_path = world.join("queries.ndjson");
    if queries_path.exists() {
        let queries = read_ndjson(&queries_path)?;
        let results = read_ndjson(&world.join("query-results.ndjson"))?;
        let core = LocalCore::new(Arc::new(Mutex::new(engine)), live);
        for (query, result) in queries.iter().zip(&results) {
            let namespace = query["namespace"].as_str().unwrap_or_default();
            let kind = query["kind"].as_str();
            let selector = query["selector"].as_str().unwrap_or_default();
            let rows = core
                .match_selector(&At::Live, kind, namespace, selector)
                .map_err(|error| anyhow::anyhow!("{error}"))?;
            let got = rows
                .rows
                .iter()
                .map(|row| value_ref(row))
                .collect::<Result<_>>()?;
            let want = result["objects"]
                .as_array()
                .context("query result without objects")?
                .iter()
                .map(json_ref)
                .collect();
            compare(
                &format!("k8s::match {} {namespace} {selector}", kind.unwrap_or("*")),
                got,
                want,
            );
        }
    }
    Ok(differences)
}

#[test]
fn selector_matches_apimachinery() -> Result<()> {
    let worlds = worlds()?;
    assert!(
        !worlds.is_empty(),
        "no worlds under {}",
        generated_dir().display()
    );
    let mut failures = Vec::new();
    for world in &worlds {
        let name = world.file_name().unwrap().to_string_lossy();
        for (backend_name, backend) in backends() {
            for difference in check_world(world, backend)? {
                failures.push(format!("{name} ({backend_name}): {difference}"));
            }
        }
    }
    if !failures.is_empty() {
        bail!(
            "{} differences from the oracle:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
    Ok(())
}

/// examples/selectors-any-kind/ adds cross-kind matches in their own
/// relation and leaves selector_matches as Kubernetes has it, on both
/// backends.
#[test]
fn any_kind_example_matches_every_kind() -> Result<()> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let world = manifest_dir.join("tests/labels_compat/worlds/workloads/objects.yaml");
    let web_service = |row: &Vec<Value>| -> bool {
        row[0..4]
            == [
                Value::String("v1".into()),
                Value::String("Service".into()),
                Value::String("apps".into()),
                Value::String("web".into()),
            ]
    };
    let kinds = |rows: &[Vec<Value>]| -> Result<BTreeSet<String>> {
        rows.iter()
            .filter(|row| web_service(row))
            .map(|row| Ok(value_ref(&row[5..9])?[1].clone()))
            .collect()
    };

    for (backend_name, backend) in backends() {
        let mut store = MemStore::new();
        edb::load_from_manifests(&mut store, vec![world.to_string_lossy().into_owned()])?;
        let mut rules = engine::read_rule_sources(&manifest_dir.join("rules"))?;
        rules.extend(engine::read_rule_sources(
            &manifest_dir.join("examples/selectors-any-kind/any-kind.mg"),
        )?);
        let results = Engine::with_rule_sources(store, Vec::new(), rules, backend)?.evaluate()?;

        assert_eq!(
            kinds(results.scan("selector_matches"))?,
            BTreeSet::from(["Pod".to_string()]),
            "{backend_name}: selector_matches keeps the Service to Pods"
        );
        assert_eq!(
            kinds(results.scan("selector_matches_any_kind"))?,
            BTreeSet::from(["ConfigMap", "Deployment", "Pod", "ReplicaSet"].map(String::from)),
            "{backend_name}: selector_matches_any_kind"
        );
    }
    Ok(())
}
