// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Same benchmarks as `small_bulk_load.rs`, but against the medium fixture:
//! an anonymized cluster dump published as a release asset.
//!
//! Kept as a separate bench target (distinct benchmark names, e.g.
//! `medium_bulk_load/mangle`) so each fixture tier has its own
//! Criterion regression history. Criterion compares each benchmark name
//! against its own prior run, and swapping the fixture data behind the
//! same name makes that history meaningless.
//!
//! The dump is not checked in. Fetch it (sha256-verified against the pin
//! in `fixtures/testdata/medium.env`) with:
//!
//!   hack/fetch-fixtures.sh medium
//!
//! The bench panics with that instruction if the dump is missing or stale.
//! Because of that, a bare `cargo bench` fails here until you have fetched
//! it; use `--bench small_bulk_load` to skip the medium tier. (`cargo test`
//! runs these binaries without `--bench` and they exit immediately.)
//!
//! Run:  cargo bench --bench medium_bulk_load

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use pallograph::engine::{
    Backend, DdBackend, Engine, InterpreterBackend, load_medium_bench_fixtures,
};

fn medium_bulk_load(c: &mut Criterion) {
    // `cargo test --all-targets` runs bench binaries without `--bench`; skip
    // there so CI does not need the dump. `cargo bench` passes it and panics
    // if the dump is missing.
    if !std::env::args().any(|a| a == "--bench") {
        return;
    }
    let (edb, rules) = load_medium_bench_fixtures().unwrap_or_else(|e| panic!("{e:#}"));

    let mut group = c.benchmark_group("medium_bulk_load");
    group.sample_size(10);

    group.bench_function("mangle", |b| {
        b.iter(|| InterpreterBackend.evaluate(&edb, &rules).unwrap())
    });

    group.bench_function("dd", |b| {
        b.iter_batched(
            || (edb.clone(), rules.clone()),
            |(edb_c, rules_c)| {
                Engine::from_parts(edb_c, rules_c, Box::new(DdBackend { provenance: false }))
                    .expect("engine")
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group!(benches, medium_bulk_load);
criterion_main!(benches);
