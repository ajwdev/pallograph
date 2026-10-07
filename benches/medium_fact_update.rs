// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Same benchmarks as `small_fact_update.rs`, but against the medium fixture:
//! an anonymized cluster dump published as a release asset. `add_fact` is
//! Mangle vs DD; `retract_fact` is DD only. See `medium_bulk_load.rs` for why this is a separate bench target
//! and how to fetch the dump (`hack/fetch-fixtures.sh medium`). Panics with
//! that instruction if the dump is missing or stale.
//!
//! Run:  cargo bench --bench medium_fact_update

use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use mangle_common::Value;
use pallograph::engine::{DdBackend, Engine, InterpreterBackend, load_medium_bench_fixtures};

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

fn medium_fact_update(c: &mut Criterion) {
    // `cargo test --all-targets` runs bench binaries without `--bench`; skip
    // there so CI does not need the dump. `cargo bench` passes it and panics
    // if the dump is missing.
    if !std::env::args().any(|a| a == "--bench") {
        return;
    }
    let (edb, rules) = load_medium_bench_fixtures().unwrap_or_else(|e| panic!("{e:#}"));

    let mut group = c.benchmark_group("medium_fact_update");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(3));
    group.measurement_time(Duration::from_secs(60));

    // iter_custom: engine setup (worker spawn + settle) is paid once per
    // sample, not per iteration. See small_fact_update.rs for why
    // iter_batched(PerIteration) gives degenerate stats here.
    group.bench_function("mangle_add_fact", |b| {
        b.iter_custom(|iters| {
            let mut engine =
                Engine::from_parts(edb.clone(), rules.clone(), Box::new(InterpreterBackend))
                    .expect("engine");
            let start = Instant::now();
            for i in 0..iters {
                let (rel, tuple) = bench_fact(i);
                engine.add_fact(rel, tuple);
                engine.evaluate().unwrap();
            }
            start.elapsed()
        })
    });

    group.bench_function("dd_add_fact", |b| {
        b.iter_custom(|iters| {
            let mut engine = Engine::from_parts(
                edb.clone(),
                rules.clone(),
                Box::new(DdBackend { provenance: false }),
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

    // No Mangle retract: it re-evaluates in full (~45 s each at this scale).
    // Pre-insert the facts during setup (not timed), then retract them.
    group.bench_function("dd_retract_fact", |b| {
        b.iter_custom(|iters| {
            let mut engine = Engine::from_parts(
                edb.clone(),
                rules.clone(),
                Box::new(DdBackend { provenance: false }),
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

criterion_group!(benches, medium_fact_update);
criterion_main!(benches);
