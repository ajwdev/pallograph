// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RBAC compatibility harness: checks `rbac_allowed` (rules/rbac.mg) against
//! the kube-apiserver RBAC authorizer.
//!
//! Each world under `tests/rbac_compat/worlds/` holds `rbac.yaml` plus the
//! requests and decisions written by `tools/rbac-oracle` (zstd-compressed
//! NDJSON). Every request is decided by both backends, which must agree
//! exactly. Each disagreement with the oracle has a direction (over-grant:
//! Pallograph allows what Kubernetes denies; under-grant: the reverse) and is
//! counted once in the direction's "total" bucket and once per oracle feature
//! tag, e.g. "under-grant: rule-wildcard-subresource".
//!
//! Known gaps are expected, so the counts are compared against
//! `tests/rbac_compat/baseline.json` as a ratchet: the test fails when a
//! bucket grows or a new one appears, and suggests tightening the baseline
//! when one shrinks. `UPDATE_BASELINE=1 cargo test --test rbac_compat`
//! rewrites it. Every mismatch is written to
//! `target/tmp/rbac-compat/<world>.ndjson` for inspection.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use mangle_common::Value;
use mangle_interpreter::MemStore;
use pallograph::edb;
use pallograph::engine::{Backend, DdBackend, Engine, InterpreterBackend};
use serde_json::{Value as Json, json};

/// Per world, bucket name to mismatch count.
type Buckets = BTreeMap<String, BTreeMap<String, usize>>;

fn compat_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/rbac_compat")
}

fn baseline_path() -> PathBuf {
    compat_dir().join("baseline.json")
}

fn report_dir() -> PathBuf {
    Path::new(env!("CARGO_TARGET_TMPDIR")).join("rbac-compat")
}

/// World directories that have oracle decisions, in name order.
fn worlds() -> Result<Vec<PathBuf>> {
    let mut worlds = Vec::new();
    for entry in std::fs::read_dir(compat_dir().join("worlds"))? {
        let path = entry?.path();
        if path.join("oracle.ndjson.zst").exists() {
            worlds.push(path);
        }
    }
    worlds.sort();
    Ok(worlds)
}

fn read_ndjson_zstd(path: &Path) -> Result<Vec<Json>> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut rows = Vec::new();
    for line in BufReader::new(zstd::Decoder::new(file)?).lines() {
        let line = line.with_context(|| format!("reading {}", path.display()))?;
        rows.push(
            serde_json::from_str(&line).with_context(|| format!("parsing {}", path.display()))?,
        );
    }
    Ok(rows)
}

fn string_field(row: &Json, field: &str) -> String {
    row[field].as_str().unwrap_or_default().to_string()
}

fn id_field(row: &Json) -> Result<i64> {
    row["id"].as_i64().context("row without numeric id")
}

/// The `access_request` and `access_request_group` facts for `requests`.
///
/// Service accounts get no `access_request_group` rows: their groups
/// (system:serviceaccounts, system:serviceaccounts:<ns>,
/// system:authenticated) follow from the username, so deriving them is the
/// model's job. Other principals get every group the authenticator attached.
fn request_facts(requests: &[Json]) -> Result<Vec<(&'static str, Vec<Value>)>> {
    let mut facts = Vec::new();
    for request in requests {
        let id = Value::Number(id_field(request)?);
        let user = string_field(request, "user");
        let mut tuple = vec![id.clone()];
        for field in [
            "user",
            "namespace",
            "apiGroup",
            "resource",
            "subresource",
            "name",
            "verb",
            "path",
        ] {
            tuple.push(Value::String(string_field(request, field)));
        }
        facts.push(("access_request", tuple));

        if user.starts_with("system:serviceaccount:") {
            continue;
        }
        for group in request["groups"].as_array().into_iter().flatten() {
            let group = group.as_str().context("non-string group")?;
            facts.push((
                "access_request_group",
                vec![id.clone(), Value::String(group.to_string())],
            ));
        }
    }
    Ok(facts)
}

/// Request ids `rbac_allowed` derives for `world` on `backend`.
fn decide(world: &Path, requests: &[Json], backend: Box<dyn Backend>) -> Result<BTreeSet<i64>> {
    let mut store = MemStore::new();
    let manifest = world.join("rbac.yaml");
    edb::load_from_manifests(&mut store, vec![manifest.to_string_lossy().into_owned()])?;
    for (relation, tuple) in request_facts(requests)? {
        store.add_fact(relation, tuple);
    }

    let rules = Path::new(env!("CARGO_MANIFEST_DIR")).join("rules");
    let results = Engine::new(store, &rules, backend)?.evaluate()?;
    let mut allowed = BTreeSet::new();
    for row in results.scan("rbac_allowed") {
        match row.as_slice() {
            [Value::Number(id)] => {
                allowed.insert(*id);
            }
            other => bail!("unexpected rbac_allowed row {other:?}"),
        }
    }
    Ok(allowed)
}

/// Compares one world against its oracle, writes its mismatch report and
/// returns its bucket counts.
fn check_world(world: &Path) -> Result<BTreeMap<String, usize>> {
    let requests = read_ndjson_zstd(&world.join("requests.ndjson.zst"))?;
    let decisions = read_ndjson_zstd(&world.join("oracle.ndjson.zst"))?;
    if requests.len() != decisions.len() {
        bail!(
            "{}: {} requests but {} decisions; rerun rbac-oracle eval",
            world.display(),
            requests.len(),
            decisions.len()
        );
    }

    let interpreter = decide(world, &requests, Box::new(InterpreterBackend))?;
    let dd = decide(world, &requests, Box::new(DdBackend))?;
    if interpreter != dd {
        let only_interpreter: Vec<_> = interpreter.difference(&dd).take(10).collect();
        let only_dd: Vec<_> = dd.difference(&interpreter).take(10).collect();
        bail!(
            "{}: backends disagree; only interpreter allows {only_interpreter:?}, only dd allows {only_dd:?}",
            world.display()
        );
    }

    let name = world.file_name().unwrap().to_string_lossy().into_owned();
    std::fs::create_dir_all(report_dir())?;
    let report_path = report_dir().join(format!("{name}.ndjson"));
    let mut report = File::create(&report_path)?;

    let mut buckets = BTreeMap::new();
    for (request, decision) in requests.iter().zip(&decisions) {
        let id = id_field(request)?;
        if id_field(decision)? != id {
            bail!(
                "{}: request and decision files are out of order at id {id}",
                world.display()
            );
        }
        let oracle_allowed = decision["allowed"]
            .as_bool()
            .context("decision without allowed")?;
        let pallograph_allowed = interpreter.contains(&id);
        if oracle_allowed == pallograph_allowed {
            continue;
        }

        let direction = if pallograph_allowed {
            "over-grant"
        } else {
            "under-grant"
        };
        *buckets.entry(format!("{direction}: total")).or_insert(0) += 1;
        for tag in decision["tags"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Json::as_str)
        {
            *buckets.entry(format!("{direction}: {tag}")).or_insert(0) += 1;
        }

        let row = json!({
            "world": name,
            "direction": direction,
            "request": request,
            "oracle": decision,
        });
        writeln!(report, "{row}")?;
    }
    Ok(buckets)
}

#[test]
fn rbac_allowed_matches_kube_apiserver() -> Result<()> {
    let mut current: Buckets = BTreeMap::new();
    for world in worlds()? {
        let name = world.file_name().unwrap().to_string_lossy().into_owned();
        current.insert(name, check_world(&world)?);
    }
    assert!(
        !current.is_empty(),
        "no worlds with oracle decisions under {}",
        compat_dir().display()
    );

    if std::env::var_os("UPDATE_BASELINE").is_some() {
        let json = serde_json::to_string_pretty(&current)? + "\n";
        std::fs::write(baseline_path(), json)?;
        eprintln!("wrote {}", baseline_path().display());
        return Ok(());
    }

    let baseline: Buckets = match std::fs::read_to_string(baseline_path()) {
        Ok(text) => serde_json::from_str(&text)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
        Err(error) => return Err(error.into()),
    };

    let mut regressions = Vec::new();
    let mut improvements = Vec::new();
    let empty = BTreeMap::new();
    let world_names: BTreeSet<&String> = current.keys().chain(baseline.keys()).collect();
    for world in world_names {
        let now = current.get(world).unwrap_or(&empty);
        let before = baseline.get(world).unwrap_or(&empty);
        let bucket_names: BTreeSet<&String> = now.keys().chain(before.keys()).collect();
        for bucket in bucket_names {
            let now_count = now.get(bucket).copied().unwrap_or(0);
            let before_count = before.get(bucket).copied().unwrap_or(0);
            let line = format!("{world}: {bucket}: {before_count} -> {now_count}");
            if now_count > before_count {
                regressions.push(line);
            } else if now_count < before_count {
                improvements.push(line);
            }
        }
    }

    if !improvements.is_empty() {
        eprintln!(
            "rbac_compat: fewer mismatches than the baseline; tighten it with \
                   UPDATE_BASELINE=1 cargo test --test rbac_compat\n  {}",
            improvements.join("\n  ")
        );
    }
    if !regressions.is_empty() {
        bail!(
            "rbac_compat: mismatches grew past the baseline (details in {}):\n  {}",
            report_dir().display(),
            regressions.join("\n  ")
        );
    }
    Ok(())
}
