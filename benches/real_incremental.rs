// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Same benchmarks as `incremental.rs` (add_fact only), but against a real,
//! locally-captured cluster dump instead of the checked-in `testdata/`
//! fixtures. See `real_bulk_load.rs` for why this is a separate bench target.
//!
//! Expected input: a directory of Kubernetes JSON or YAML manifests, by
//! default the gitignored `testdata-real/` (override with
//! `PALLOGRAPH_REAL_FIXTURES`). `real_bulk_load.rs` shows how to produce
//! one. If the directory is missing, the bench prints a message and exits
//! without running anything.
//!
//! Run:  cargo bench --bench real_incremental

use std::path::Path;
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use mangle_common::Value;
use pallograph::engine::{DdBackend, Engine, InterpreterBackend, load_bench_fixtures_from};

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

fn real_incremental(c: &mut Criterion) {
    let dir =
        std::env::var("PALLOGRAPH_REAL_FIXTURES").unwrap_or_else(|_| "testdata-real".to_string());
    if !Path::new(&dir).is_dir() {
        eprintln!(
            "real_incremental: no cluster dump at `{dir}`, skipping. \
             See the header of benches/real_bulk_load.rs for how to create one."
        );
        return;
    }
    let (edb, rules) = load_bench_fixtures_from(&dir).expect("load fixtures");

    let mut group = c.benchmark_group("real_incremental");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(3));
    group.measurement_time(Duration::from_secs(60));

    // iter_custom: engine setup (worker spawn + settle) is paid once per
    // sample, not per iteration. See incremental.rs for why
    // iter_batched(PerIteration) gives degenerate stats here.
    group.bench_function("interpreter_add_fact", |b| {
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

    group.finish();
}

criterion_group!(benches, real_incremental);
criterion_main!(benches);
