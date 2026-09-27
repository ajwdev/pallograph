// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Benchmarks for the per-fact-mutation path: how much does each `+fact` or
//! `-fact` REPL operation cost once the initial state is settled?
//!
//! Data source I/O is excluded from all measurements — `load_bench_fixtures()`
//! is called once and cloned into each iteration's setup via `Engine::from_parts`.
//!
//! Two groups:
//!
//! - `add_fact`    — interpreter (add + full re-evaluate) vs DD (incremental commit)
//! - `retract_fact`— same comparison for fact removal
//!
//! `BatchSize::PerIteration` ensures each measurement starts with a fresh engine
//! at the baseline dataset size, so results are stable regardless of how many
//! samples criterion collects.
//!
//! Run:  cargo bench --bench incremental

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use mangle_common::Value;
use pallograph::engine::{DdBackend, Engine, InterpreterBackend, load_bench_fixtures};

// A synthetic edge fact absent from testdata, so add always succeeds and
// retract (after a prior add) always removes exactly one entry.
fn bench_fact() -> (String, Vec<Value>) {
    (
        "edge".to_string(),
        vec![
            Value::String("bench_src".to_string()),
            Value::String("bench_dst".to_string()),
        ],
    )
}

// ---------------------------------------------------------------------------
// add_fact
// ---------------------------------------------------------------------------

fn interpreter_add_fact(c: &mut Criterion) {
    let (edb, rules) = load_bench_fixtures().expect("load fixtures");
    c.bench_function("incremental/interpreter_add_fact", |b| {
        b.iter_batched(
            || Engine::from_parts(edb.clone(), rules.clone(), Box::new(InterpreterBackend)),
            |mut engine| {
                let (rel, tuple) = bench_fact();
                engine.add_fact(rel, tuple);
                engine.evaluate().unwrap() // full recompute
            },
            BatchSize::PerIteration,
        )
    });
}

fn dd_add_fact(c: &mut Criterion) {
    let (edb, rules) = load_bench_fixtures().expect("load fixtures");
    c.bench_function("incremental/dd_add_fact", |b| {
        b.iter_batched(
            || {
                // Session startup is setup, not measurement.
                let mut engine =
                    Engine::from_parts(edb.clone(), rules.clone(), Box::new(DdBackend));
                engine.enable_incremental().expect("enable_incremental");
                engine
            },
            |mut engine| {
                let (rel, tuple) = bench_fact();
                engine.add_fact(rel, tuple) // incremental insert + commit only
            },
            BatchSize::PerIteration,
        )
    });
}

// ---------------------------------------------------------------------------
// retract_fact
// ---------------------------------------------------------------------------

fn interpreter_retract_fact(c: &mut Criterion) {
    let (edb, rules) = load_bench_fixtures().expect("load fixtures");
    c.bench_function("incremental/interpreter_retract_fact", |b| {
        b.iter_batched(
            || {
                let mut engine =
                    Engine::from_parts(edb.clone(), rules.clone(), Box::new(InterpreterBackend));
                let (rel, tuple) = bench_fact();
                engine.add_fact(rel, tuple); // add during setup so retract has something to remove
                engine
            },
            |mut engine| {
                let (rel, tuple) = bench_fact();
                engine.retract_fact(&rel, &tuple);
                engine.evaluate().unwrap()
            },
            BatchSize::PerIteration,
        )
    });
}

fn dd_retract_fact(c: &mut Criterion) {
    let (edb, rules) = load_bench_fixtures().expect("load fixtures");
    c.bench_function("incremental/dd_retract_fact", |b| {
        b.iter_batched(
            || {
                let mut engine =
                    Engine::from_parts(edb.clone(), rules.clone(), Box::new(DdBackend));
                engine.enable_incremental().expect("enable_incremental");
                let (rel, tuple) = bench_fact();
                engine.add_fact(rel, tuple); // add during setup so retract has something to remove
                engine
            },
            |mut engine| {
                let (rel, tuple) = bench_fact();
                engine.retract_fact(&rel, &tuple)
            },
            BatchSize::PerIteration,
        )
    });
}

criterion_group!(
    benches,
    interpreter_add_fact,
    dd_add_fact,
    interpreter_retract_fact,
    dd_retract_fact,
);
criterion_main!(benches);
