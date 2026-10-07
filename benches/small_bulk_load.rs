// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Benchmarks for the initial bulk-load path: how long does it take to go
//! from pre-loaded facts + rules to a fully-derived, query-ready state?
//!
//! Data source I/O is excluded from all measurements — `load_bench_fixtures()`
//! is called once before the benchmark loop and the results are cloned into
//! each iteration's setup.
//!
//! Two variants:
//!
//! - `mangle` — Mangle's `InterpreterBackend::evaluate`, the baseline
//! - `dd`     — `Engine::from_parts` with `DdBackend`, which builds the
//!   dataflow graph, spawns the persistent worker, and feeds +
//!   settles the initial EDB; this is the real DD startup cost
//!
//! (`DdBackend::evaluate` now just spawns + snapshots + drops a session, so a
//! separate batch bench would duplicate `dd`.)
//!
//! Run:  cargo bench --bench small_bulk_load

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use pallograph::engine::{Backend, DdBackend, Engine, InterpreterBackend, load_bench_fixtures};

fn mangle_evaluate(c: &mut Criterion) {
    let (edb, rules) = load_bench_fixtures().expect("load fixtures");
    c.bench_function("small_bulk_load/mangle", |b| {
        b.iter(|| InterpreterBackend.evaluate(&edb, &rules).unwrap())
    });
}

fn dd_spawn(c: &mut Criterion) {
    let (edb, rules) = load_bench_fixtures().expect("load fixtures");
    c.bench_function("small_bulk_load/dd", |b| {
        b.iter_batched(
            // Setup: clone pre-loaded data (no file I/O).
            || (edb.clone(), rules.clone()),
            // Measured: build the dataflow graph, spawn the worker, feed and
            // settle the full initial EDB.  Worker shutdown happens at drop,
            // outside the timed window.
            |(edb_c, rules_c)| {
                Engine::from_parts(edb_c, rules_c, Box::new(DdBackend { provenance: false }))
                    .expect("engine")
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, mangle_evaluate, dd_spawn);
criterion_main!(benches);
