// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RBAC compatibility harness: checks `rbac_allowed` (rules/rbac.mg) against
//! the kube-apiserver RBAC authorizer.
//!
//! Each world under `tests/rbac_compat/worlds/` is an `rbac.yaml`. Its
//! requests and the oracle's decisions are generated, not committed:
//! `hack/rbac-compat-gen.sh` runs `tools/rbac-oracle` (Go) to write them as
//! NDJSON under `target/rbac-compat/worlds/<world>/`, and this test refuses
//! to run on missing or stale output. Every request is decided by both
//! backends, which must agree exactly. Each disagreement with the oracle has a direction (over-grant:
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
//!
//! The ignored `fuzz_worlds` test runs the same checks over randomly
//! generated worlds in `$RBAC_COMPAT_WORLDS` (see hack/rbac-compat.sh). It
//! has no baseline, since every seed makes new worlds: it fails only when
//! the backends disagree, and reports which worlds hit a bucket the curated
//! baseline lacks, as candidates to copy into `tests/rbac_compat/worlds/`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

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

/// Where hack/rbac-compat-gen.sh writes the curated worlds' requests and
/// decisions: `<target>/rbac-compat/worlds`, `<target>/tmp` being
/// `CARGO_TARGET_TMPDIR`.
fn generated_dir() -> PathBuf {
    Path::new(env!("CARGO_TARGET_TMPDIR"))
        .parent()
        .expect("CARGO_TARGET_TMPDIR has a parent")
        .join("rbac-compat/worlds")
}

/// World directories under `dir` that have oracle decisions, in name order.
fn worlds(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut worlds = Vec::new();
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        if path.join("oracle.ndjson").exists() {
            worlds.push(path);
        }
    }
    worlds.sort();
    Ok(worlds)
}

/// The generated directory of every curated world, after checking each one
/// exists and is newer than everything it was generated from: the world's
/// rbac.yaml and the oracle's source.
fn curated_worlds() -> Result<Vec<PathBuf>> {
    let modified = |path: &Path| -> Result<std::time::SystemTime> {
        Ok(std::fs::metadata(path)
            .with_context(|| format!("reading {}", path.display()))?
            .modified()?)
    };
    let oracle_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tools/rbac-oracle");
    let mut oracle_modified = std::time::SystemTime::UNIX_EPOCH;
    for entry in std::fs::read_dir(&oracle_dir)? {
        oracle_modified = oracle_modified.max(modified(&entry?.path())?);
    }

    let regenerate = "run hack/rbac-compat-gen.sh (in nix develop) to regenerate";
    let mut worlds = Vec::new();
    for entry in std::fs::read_dir(compat_dir().join("worlds"))? {
        let source = entry?.path();
        if !source.join("rbac.yaml").exists() {
            continue;
        }
        let world = generated_dir().join(source.file_name().unwrap());
        let decisions = world.join("oracle.ndjson");
        if !decisions.exists() {
            bail!("{} is missing; {regenerate}", decisions.display());
        }
        let generated = modified(&decisions)?;
        if generated < modified(&source.join("rbac.yaml"))? || generated < oracle_modified {
            bail!(
                "{} is older than its world or tools/rbac-oracle; {regenerate}",
                decisions.display()
            );
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

/// Requests are decided in chunks of this size. Requests are independent,
/// so the union of the chunks' answers is the world's answer, and
/// evaluation time grows faster than linearly in the number of requests.
const CHUNK_SIZE: usize = 2000;

/// Applies `function` to every item on all cores, keeping item order.
fn parallel_map<T: Sync, R: Send>(items: &[T], function: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let next = AtomicUsize::new(0);
    let threads = std::thread::available_parallelism().map_or(1, usize::from);
    let mut results: Vec<(usize, R)> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..threads)
            .map(|_| {
                scope.spawn(|| {
                    let mut results = Vec::new();
                    loop {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        let Some(item) = items.get(index) else {
                            break;
                        };
                        results.push((index, function(item)));
                    }
                    results
                })
            })
            .collect();
        workers
            .into_iter()
            .flat_map(|worker| worker.join().unwrap())
            .collect()
    });
    results.sort_by_key(|(index, _)| *index);
    results.into_iter().map(|(_, result)| result).collect()
}

/// A world's requests and the oracle's decisions, in id order.
struct LoadedWorld {
    path: PathBuf,
    requests: Vec<Json>,
    decisions: Vec<Json>,
}

fn load_world(world: &Path) -> Result<LoadedWorld> {
    let requests = read_ndjson(&world.join("requests.ndjson"))?;
    let decisions = read_ndjson(&world.join("oracle.ndjson"))?;
    if requests.len() != decisions.len() {
        bail!(
            "{}: {} requests but {} decisions; rerun rbac-oracle eval",
            world.display(),
            requests.len(),
            decisions.len()
        );
    }
    Ok(LoadedWorld {
        path: world.to_path_buf(),
        requests,
        decisions,
    })
}

/// Checks every world against its oracle and returns each world's bucket
/// counts. All chunks of all worlds are decided in one parallel pass.
fn check_worlds(worlds: &[PathBuf]) -> Vec<(PathBuf, Result<BTreeMap<String, usize>>)> {
    let loaded: Vec<Result<LoadedWorld>> = worlds.iter().map(|world| load_world(world)).collect();

    let mut chunks = Vec::new();
    for (index, world) in loaded.iter().enumerate() {
        if let Ok(world) = world {
            for start in (0..world.requests.len()).step_by(CHUNK_SIZE) {
                chunks.push((index, start..(start + CHUNK_SIZE).min(world.requests.len())));
            }
        }
    }
    let decided = parallel_map(&chunks, |(index, range)| {
        let world = loaded[*index].as_ref().unwrap();
        let requests = &world.requests[range.clone()];
        let interpreter = decide(&world.path, requests, Box::new(InterpreterBackend))?;
        let dd = decide(&world.path, requests, Box::new(DdBackend))?;
        Ok::<_, anyhow::Error>((interpreter, dd))
    });

    let mut allowed: Vec<Result<(BTreeSet<i64>, BTreeSet<i64>)>> =
        (0..loaded.len()).map(|_| Ok(Default::default())).collect();
    for ((index, _), result) in chunks.iter().zip(decided) {
        match (&mut allowed[*index], result) {
            (Ok((interpreter, dd)), Ok((chunk_interpreter, chunk_dd))) => {
                interpreter.extend(chunk_interpreter);
                dd.extend(chunk_dd);
            }
            (slot @ Ok(_), Err(error)) => *slot = Err(error),
            (Err(_), _) => {}
        }
    }

    worlds
        .iter()
        .zip(loaded)
        .zip(allowed)
        .map(|((path, world), allowed)| {
            let result = world.and_then(|world| {
                let (interpreter, dd) = allowed?;
                compare_world(&world, &interpreter, &dd)
            });
            (path.clone(), result)
        })
        .collect()
}

/// Compares one world's decisions against its oracle, writes its mismatch
/// report and returns its bucket counts.
fn compare_world(
    world: &LoadedWorld,
    interpreter: &BTreeSet<i64>,
    dd: &BTreeSet<i64>,
) -> Result<BTreeMap<String, usize>> {
    let LoadedWorld {
        path: world,
        requests,
        decisions,
    } = world;
    if interpreter != dd {
        let only_interpreter: Vec<_> = interpreter.difference(dd).take(10).collect();
        let only_dd: Vec<_> = dd.difference(interpreter).take(10).collect();
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
    for (request, decision) in requests.iter().zip(decisions) {
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
        let tags: Vec<&str> = decision["tags"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Json::as_str)
            .collect();
        for tag in &tags {
            *buckets.entry(format!("{direction}: {tag}")).or_insert(0) += 1;
        }
        // The oracle's denied-by-* tags name the known Kubernetes behavior
        // behind a denial. An over-grant without one is a gap nobody has
        // explained yet.
        if pallograph_allowed && !tags.iter().any(|tag| tag.starts_with("denied-by-")) {
            *buckets
                .entry("over-grant: unexplained".to_string())
                .or_insert(0) += 1;
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
    for (world, result) in check_worlds(&curated_worlds()?) {
        let name = world.file_name().unwrap().to_string_lossy().into_owned();
        current.insert(name, result?);
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

#[test]
#[ignore = "needs generated worlds; run hack/rbac-compat.sh"]
fn fuzz_worlds() -> Result<()> {
    let dir = PathBuf::from(
        std::env::var_os("RBAC_COMPAT_WORLDS")
            .context("set RBAC_COMPAT_WORLDS to a directory of worlds")?,
    );
    let worlds = worlds(&dir)?;
    assert!(
        !worlds.is_empty(),
        "no worlds with oracle decisions under {}",
        dir.display()
    );

    let results = check_worlds(&worlds);

    let baseline: Buckets = serde_json::from_str(&std::fs::read_to_string(baseline_path())?)?;
    let known: BTreeSet<&String> = baseline.values().flat_map(BTreeMap::keys).collect();

    let mut totals: BTreeMap<String, usize> = BTreeMap::new();
    let mut candidates = Vec::new();
    let mut failures = Vec::new();
    for (world, result) in &results {
        let buckets = match result {
            Ok(buckets) => buckets,
            Err(error) => {
                failures.push(format!("{}: {error:#}", world.display()));
                continue;
            }
        };
        for (bucket, count) in buckets {
            *totals.entry(bucket.clone()).or_insert(0) += count;
        }
        // Request and principal tags describe the request's shape, not the
        // behavior behind a mismatch, so new combinations of them are noise.
        let new: Vec<&String> = buckets
            .keys()
            .filter(|bucket| !known.contains(bucket))
            .filter(|bucket| {
                let tag = bucket
                    .split_once(": ")
                    .map_or(bucket.as_str(), |(_, tag)| tag);
                !tag.starts_with("request-") && !tag.starts_with("principal-")
            })
            .collect();
        if !new.is_empty() {
            candidates.push(format!("{}: {new:?}", world.display()));
        }
    }

    eprintln!(
        "rbac_compat fuzz: {} worlds, mismatches per bucket (reports in {}):",
        results.len(),
        report_dir().display()
    );
    for (bucket, count) in &totals {
        eprintln!("  {count:>7}  {bucket}");
    }
    if !candidates.is_empty() {
        candidates.sort();
        eprintln!(
            "worlds with buckets the curated baseline lacks:\n  {}",
            candidates.join("\n  ")
        );
    }
    if !failures.is_empty() {
        failures.sort();
        bail!(
            "rbac_compat fuzz: {} worlds failed:\n  {}",
            failures.len(),
            failures.join("\n  ")
        );
    }
    Ok(())
}
