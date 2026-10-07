// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! DD backend with lazy provenance on (`DdBackend { provenance: true }`), on
//! the small fixture. Compare against the matching `provenance: false`
//! benchmarks to see what the `(rule_id, min_height)` annotations cost:
//!
//! - `small_provenance/dd_bulk_load`    vs `small_bulk_load/dd`
//! - `small_provenance/dd_add_fact`     vs `small_fact_update/dd_add_fact`
//! - `small_provenance/dd_retract_fact` vs `small_fact_update/dd_retract_fact`
//!
//! Kept as its own bench target with its own benchmark names so the
//! provenance-off baselines keep their Criterion history. There is no
//! Mangle variant: Mangle always tracks provenance eagerly, so
//! `small_bulk_load/mangle` and `small_fact_update/mangle_*` already include
//! it. See `docs/lazy-provenance.md` section 2.6 for the cost model.
//!
//! Setup mirrors `small_bulk_load.rs` and `small_fact_update.rs`: fixture I/O
//! is excluded, and `iter_custom` pays the engine build once per sample.
//!
//! Run:  cargo bench --bench small_provenance

use std::time::Instant;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use mangle_common::Value;
use pallograph::engine::{DdBackend, Engine, load_bench_fixtures};

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

fn dd_bulk_load(c: &mut Criterion) {
    let (edb, rules) = load_bench_fixtures().expect("load fixtures");
    c.bench_function("small_provenance/dd_bulk_load", |b| {
        b.iter_batched(
            || (edb.clone(), rules.clone()),
            |(edb_c, rules_c)| {
                Engine::from_parts(edb_c, rules_c, Box::new(DdBackend { provenance: true }))
                    .expect("engine")
            },
            BatchSize::SmallInput,
        )
    });
}

fn dd_add_fact(c: &mut Criterion) {
    let (edb, rules) = load_bench_fixtures().expect("load fixtures");
    c.bench_function("small_provenance/dd_add_fact", |b| {
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
}

fn dd_retract_fact(c: &mut Criterion) {
    let (edb, rules) = load_bench_fixtures().expect("load fixtures");
    c.bench_function("small_provenance/dd_retract_fact", |b| {
        b.iter_custom(|iters| {
            // Pre-insert the facts during setup (not timed), then retract them.
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
}

criterion_group!(benches, dd_bulk_load, dd_add_fact, dd_retract_fact);
criterion_main!(benches);
