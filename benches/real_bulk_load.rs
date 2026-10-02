// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Same benchmarks as `bulk_load.rs`, but against a real, locally-captured
//! cluster dump instead of the checked-in `testdata/` fixtures.
//!
//! Kept as a separate bench target (distinct benchmark names, e.g.
//! `real_bulk_load/interpreter`) rather than a mode of `bulk_load.rs` so
//! its results never mix into that benchmark's `testdata/`-based
//! regression history. Criterion compares each benchmark name against
//! its own prior run, and silently swapping the fixture data behind the
//! same name makes that history meaningless.
//!
//! Expected input: a directory of Kubernetes JSON or YAML manifests (the
//! same format `testdata/` uses). The default path is `testdata-real/`,
//! which is gitignored; override it with `PALLOGRAPH_REAL_FIXTURES`. To
//! produce a dump from a cluster you have access to:
//!
//!   mkdir -p testdata-real
//!   kubectl get pods,serviceaccounts,roles,rolebindings,clusterroles,\
//!     clusterrolebindings,nodes --all-namespaces -o json \
//!     > testdata-real/dump.json
//!
//! If the directory is missing, the bench prints a message and exits
//! without running anything, so a plain `cargo bench` never depends on
//! real data being present.
//!
//! Run:  cargo bench --bench real_bulk_load

use std::path::Path;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use pallograph::engine::{
    Backend, DdBackend, Engine, InterpreterBackend, load_bench_fixtures_from,
};

fn real_bulk_load(c: &mut Criterion) {
    let dir =
        std::env::var("PALLOGRAPH_REAL_FIXTURES").unwrap_or_else(|_| "testdata-real".to_string());
    if !Path::new(&dir).is_dir() {
        eprintln!(
            "real_bulk_load: no cluster dump at `{dir}`, skipping. \
             See the header of benches/real_bulk_load.rs for how to create one."
        );
        return;
    }
    let (edb, rules) = load_bench_fixtures_from(&dir).expect("load fixtures");

    let mut group = c.benchmark_group("real_bulk_load");
    group.sample_size(10);

    group.bench_function("interpreter", |b| {
        b.iter(|| InterpreterBackend.evaluate(&edb, &rules).unwrap())
    });

    group.bench_function("dd_session", |b| {
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

criterion_group!(benches, real_bulk_load);
criterion_main!(benches);
