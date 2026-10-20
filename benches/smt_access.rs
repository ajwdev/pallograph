// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Benchmarks for SMT/RBAC access checks.
//!
//! These isolate the expensive cluster-admin and namespace-isolation paths from
//! datasource I/O. The small fixture is always checked in. The medium fixture is
//! optional and can be fetched with `hack/fetch-fixtures.sh medium`.
//!
//! Run:
//!   cargo bench --bench smt_access
//!
//! Profile the same code path with samply:
//!   cargo build --release --bin profile_smt_access
//!   samply record target/release/profile_smt_access --scenario cluster-admin --iters 1000

use std::time::Duration;

use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};
use pallograph::engine::{
    Backend, DdBackend, EvalStore, InterpreterBackend, load_bench_fixtures,
    load_medium_bench_fixtures,
};
use pallograph::rbac::RbacAccessModel;
use pallograph::smt::SmtEncoder;

#[derive(Clone, Copy)]
enum AccessBackend {
    Interpreter,
    Dd,
}

impl AccessBackend {
    fn label(self) -> &'static str {
        match self {
            Self::Interpreter => "interpreter",
            Self::Dd => "dd",
        }
    }
}

fn evaluate_with_backend(
    backend: AccessBackend,
    edb: &[(String, Vec<mangle_common::Value>)],
    rules: &[String],
) -> EvalStore {
    match backend {
        AccessBackend::Interpreter => InterpreterBackend.evaluate(edb, rules),
        AccessBackend::Dd => DdBackend { provenance: false }.evaluate(edb, rules),
    }
    .expect("evaluate fixtures")
}

fn evaluated_medium() -> Option<pallograph::engine::EvalStore> {
    if !std::env::args().any(|a| a == "--bench") {
        return None;
    }
    let (edb, rules) = load_medium_bench_fixtures().ok()?;
    Some(
        InterpreterBackend
            .evaluate(&edb, &rules)
            .expect("evaluate medium fixtures"),
    )
}

fn access_model(store: &pallograph::engine::EvalStore) -> RbacAccessModel {
    RbacAccessModel::from_store(store)
}

fn permission_tables<'ctx>(
    ctx: &'ctx z3::Context,
    store: &pallograph::engine::EvalStore,
) -> SmtEncoder<'ctx> {
    let mut enc = SmtEncoder::new(ctx);
    enc.load_rbac_tables(store);
    enc
}

fn bench_store(c: &mut Criterion, name: &str, store: pallograph::engine::EvalStore) {
    let mut group = c.benchmark_group(name);
    group.sample_size(20);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(10));

    group.bench_function("load_access_model", |b| {
        b.iter(|| black_box(access_model(&store)))
    });

    group.bench_function("load_permission_tables", |b| {
        b.iter_batched(
            z3::Config::new,
            |cfg| {
                let ctx = z3::Context::new(&cfg);
                black_box(permission_tables(&ctx, &store));
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("load_access_model_and_cluster_admin", |b| {
        b.iter(|| {
            let enc = access_model(&store);
            black_box(
                enc.direct_violations("", "*", "*", "*").len()
                    + enc.check_reaches("", "*", "*", "*", &[], false).len(),
            );
        })
    });

    group.bench_function("load_access_model_and_namespace_isolation", |b| {
        b.iter(|| {
            let enc = access_model(&store);
            black_box(enc.check_namespace_isolation("default", &[]).len());
        })
    });

    let enc = access_model(&store);

    group.bench_function("direct_cluster_admin", |b| {
        b.iter(|| black_box(enc.direct_violations("", "*", "*", "*")))
    });

    group.bench_function("reaches_cluster_admin", |b| {
        b.iter(|| black_box(enc.check_reaches("", "*", "*", "*", &[], false)))
    });

    group.bench_function("namespace_isolation_default", |b| {
        b.iter(|| black_box(enc.check_namespace_isolation("default", &[])))
    });

    group.finish();
}

fn bench_backend_pipeline(
    c: &mut Criterion,
    fixture: &str,
    edb: &[(String, Vec<mangle_common::Value>)],
    rules: &[String],
) {
    let mut group = c.benchmark_group(format!("{fixture}_smt_access_backend"));
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(10));

    for backend in [AccessBackend::Interpreter, AccessBackend::Dd] {
        group.bench_function(format!("{}/evaluate", backend.label()), |b| {
            b.iter_batched(
                || (edb.to_vec(), rules.to_vec()),
                |(edb_c, rules_c)| {
                    black_box(evaluate_with_backend(backend, &edb_c, &rules_c));
                },
                BatchSize::SmallInput,
            )
        });

        group.bench_function(
            format!("{}/evaluate_and_load_access_model", backend.label()),
            |b| {
                b.iter_batched(
                    || (edb.to_vec(), rules.to_vec()),
                    |(edb_c, rules_c)| {
                        let store = evaluate_with_backend(backend, &edb_c, &rules_c);
                        let enc = access_model(&store);
                        black_box(enc.grant_count());
                    },
                    BatchSize::SmallInput,
                )
            },
        );

        group.bench_function(
            format!("{}/evaluate_and_cluster_admin", backend.label()),
            |b| {
                b.iter_batched(
                    || (edb.to_vec(), rules.to_vec()),
                    |(edb_c, rules_c)| {
                        let store = evaluate_with_backend(backend, &edb_c, &rules_c);
                        let enc = access_model(&store);
                        black_box(
                            enc.direct_violations("", "*", "*", "*").len()
                                + enc.check_reaches("", "*", "*", "*", &[], false).len(),
                        );
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

fn smt_access(c: &mut Criterion) {
    let (small_edb, small_rules) = load_bench_fixtures().expect("load small fixtures");
    bench_backend_pipeline(c, "small", &small_edb, &small_rules);
    bench_store(
        c,
        "small_smt_access",
        evaluate_with_backend(AccessBackend::Interpreter, &small_edb, &small_rules),
    );
    if let Some(store) = evaluated_medium() {
        bench_store(c, "medium_smt_access", store);
    }
}

criterion_group!(benches, smt_access);
criterion_main!(benches);
