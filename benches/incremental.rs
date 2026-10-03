// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Benchmarks for the per-fact-mutation path: how much does each `+fact` or
//! `-fact` REPL operation cost once the initial state is settled?
//!
//! Data source I/O is excluded from all measurements — `load_bench_fixtures()`
//! is called once and cloned into each iteration's setup.
//!
//! Two groups:
//!
//! - `add_fact`    — interpreter (add + full re-evaluate) vs DD (incremental commit)
//! - `retract_fact`— same comparison for fact removal
//!
//! ## Why `iter_custom` instead of `iter_batched(PerIteration)`
//!
//! `iter_batched(PerIteration)` creates one fresh engine *per iteration*.  For
//! the DD benchmarks that means spawning a timely worker and settling the full
//! EDB before each timed call — setup is orders of magnitude heavier than the
//! routine.  Criterion's mean is derived as `total_elapsed / total_iters`; when
//! each sample can hold only ~1 iteration (Criterion's warmup couldn't collect
//! more), `total_iters` collapses and the reported mean degenerates into noise
//! (wide CI, p ~ 0.7).
//!
//! `iter_custom` pays the engine-build cost once per *sample* and runs `iters`
//! back-to-back add/retract calls on the same engine.  This fits Criterion's
//! statistical model (many iterations per sample) and produces tight,
//! trustworthy numbers.
//!
//! Trade-off: the EDB grows by one fact per add-iteration within a sample, so
//! later iterations settle against a marginally larger EDB than earlier ones.
//! For testdata scale this is negligible, but it is worth noting.
//!
//! Run:  cargo bench --bench incremental

use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use mangle_common::Value;
use pallograph::engine::{DdBackend, Engine, InterpreterBackend, load_bench_fixtures};

// Generate a synthetic edge fact absent from testdata.  The index `i` keeps
// each call within a sample unique so `Engine::add_fact`'s dedup guard never
// short-circuits (it no-ops when the fact is already present).
fn bench_fact(i: u64) -> (String, Vec<Value>) {
    (
        "edge".to_string(),
        vec![
            Value::String(format!("bench_src_{i}")),
            Value::String(format!("bench_dst_{i}")),
        ],
    )
}

// ---------------------------------------------------------------------------
// add_fact
// ---------------------------------------------------------------------------

fn interpreter_add_fact(c: &mut Criterion) {
    let (edb, rules) = load_bench_fixtures().expect("load fixtures");
    c.bench_function("incremental/interpreter_add_fact", |b| {
        b.iter_custom(|iters| {
            // Build a fresh engine once per sample — not per iteration.
            let mut engine =
                Engine::from_parts(edb.clone(), rules.clone(), Box::new(InterpreterBackend))
                    .expect("engine");
            let start = Instant::now();
            for i in 0..iters {
                let (rel, tuple) = bench_fact(i);
                engine.add_fact(rel, tuple);
                engine.evaluate().unwrap(); // full recompute
            }
            start.elapsed()
        })
    });
}

fn dd_add_fact(c: &mut Criterion) {
    let (edb, rules) = load_bench_fixtures().expect("load fixtures");
    c.bench_function("incremental/dd_add_fact", |b| {
        b.iter_custom(|iters| {
            // Session startup is setup, not measurement.
            let mut engine = Engine::from_parts(
                edb.clone(),
                rules.clone(),
                Box::new(DdBackend { provenance: false }),
            )
            .expect("engine");
            let start = Instant::now();
            for i in 0..iters {
                let (rel, tuple) = bench_fact(i);
                engine.add_fact(rel, tuple); // incremental insert + commit only
            }
            start.elapsed()
        })
    });
}

// ---------------------------------------------------------------------------
// retract_fact
// ---------------------------------------------------------------------------

fn interpreter_retract_fact(c: &mut Criterion) {
    let (edb, rules) = load_bench_fixtures().expect("load fixtures");
    c.bench_function("incremental/interpreter_retract_fact", |b| {
        b.iter_custom(|iters| {
            // Pre-insert the facts during setup (not timed), then retract them.
            let mut engine =
                Engine::from_parts(edb.clone(), rules.clone(), Box::new(InterpreterBackend))
                    .expect("engine");
            for i in 0..iters {
                let (rel, tuple) = bench_fact(i);
                engine.add_fact(rel, tuple);
            }
            let start = Instant::now();
            for i in 0..iters {
                let (rel, tuple) = bench_fact(i);
                engine.retract_fact(&rel, &tuple);
                engine.evaluate().unwrap();
            }
            start.elapsed()
        })
    });
}

fn dd_retract_fact(c: &mut Criterion) {
    let (edb, rules) = load_bench_fixtures().expect("load fixtures");
    c.bench_function("incremental/dd_retract_fact", |b| {
        b.iter_custom(|iters| {
            // Pre-insert the facts during setup (not timed), then retract them.
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
}

criterion_group! {
    name = benches;
    // These benchmarks involve heavy setup (timely worker spawn + EDB settle).
    // A small sample-size and generous measurement window keeps wall-clock
    // runtime reasonable while still giving Criterion enough data to produce
    // trustworthy statistics.
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_secs(5))
        .measurement_time(Duration::from_secs(60));
    targets = interpreter_add_fact, dd_add_fact, interpreter_retract_fact, dd_retract_fact
}
criterion_main!(benches);
