// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! DD backend with lazy provenance on (`DdBackend { provenance: true }`), on
//! the medium fixture. Compare against the provenance-off benchmarks:
//!
//! - `medium_provenance/dd_bulk_load`    vs `medium_bulk_load/dd`
//! - `medium_provenance/dd_add_fact`     vs `medium_fact_update/dd_add_fact`
//! - `medium_provenance/dd_retract_fact` vs `medium_fact_update/dd_retract_fact`
//!
//! A separate target with its own benchmark names, like the other medium
//! benches. It has no Mangle variant (Mangle tracks provenance eagerly, so the
//! existing medium Mangle numbers already include it), which also means it
//! avoids the 40+ second Mangle runs.
//!
//! Needs the medium fixture: `hack/fetch-fixtures.sh medium`. Panics with that
//! instruction if it is missing or stale, and exits immediately under
//! `cargo test` (no `--bench` argument), like the other medium benches.
//!
//! Run:  cargo bench --bench medium_provenance

use std::time::{Duration, Instant};

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use mangle_common::Value;
use pallograph::engine::{DdBackend, Engine, load_medium_bench_fixtures};

// Unique per-call index so `Engine::add_fact`'s dedup guard never no-ops.
fn bench_fact(i: u64) -> (String, Vec<Value>) {
    (
        "edge".to_string(),
        vec![
            Value::String(format!("bench_src_{i}")),
            Value::String(format!("bench_dst_{i}")),
        ],
    )
}

fn medium_provenance(c: &mut Criterion) {
    // `cargo test --all-targets` runs bench binaries without `--bench`; skip
    // there so CI does not need the dump.
    if !std::env::args().any(|a| a == "--bench") {
        return;
    }
    let (edb, rules) = load_medium_bench_fixtures().unwrap_or_else(|e| panic!("{e:#}"));

    let mut group = c.benchmark_group("medium_provenance");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(3));
    group.measurement_time(Duration::from_secs(60));

    group.bench_function("dd_bulk_load", |b| {
        b.iter_batched(
            || (edb.clone(), rules.clone()),
            |(edb_c, rules_c)| {
                Engine::from_parts(edb_c, rules_c, Box::new(DdBackend { provenance: true }))
                    .expect("engine")
            },
            BatchSize::SmallInput,
        )
    });

    // iter_custom: engine setup is paid once per sample. See
    // small_fact_update.rs for why.
    group.bench_function("dd_add_fact", |b| {
        b.iter_custom(|iters| {
            let mut engine = Engine::from_parts(
                edb.clone(),
                rules.clone(),
                Box::new(DdBackend { provenance: true }),
            )
            .expect("engine");
            let start = Instant::now();
            for i in 0..iters {
                let (rel, tuple) = bench_fact(i);
                engine.add_fact(rel, tuple);
            }
            start.elapsed()
        })
    });

    // Pre-insert the facts during setup (not timed), then retract them.
    group.bench_function("dd_retract_fact", |b| {
        b.iter_custom(|iters| {
            let mut engine = Engine::from_parts(
                edb.clone(),
                rules.clone(),
                Box::new(DdBackend { provenance: true }),
            )
            .expect("engine");
            for i in 0..iters {
                let (rel, tuple) = bench_fact(i);
                engine.add_fact(rel, tuple);
            }
            let start = Instant::now();
            for i in 0..iters {
                let (rel, tuple) = bench_fact(i);
                engine.retract_fact(&rel, &tuple);
            }
            start.elapsed()
        })
    });

    group.finish();
}

criterion_group!(benches, medium_provenance);
criterion_main!(benches);
