// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tight-loop driver for profiling SMT/RBAC access checks with samply.
//!
//! Example:
//!
//! ```text
//! cargo build --release --bin profile_smt_access
//! samply record target/release/profile_smt_access --scenario cluster-admin --iters 1000
//! samply record target/release/profile_smt_access --scenario encode-z3 --iters 100
//! ```

use std::hint::black_box;
use std::time::Instant;

use clap::{Parser, ValueEnum};
use pallograph::engine::{
    Backend, EvalStore, InterpreterBackend, load_bench_fixtures, load_medium_bench_fixtures,
};
use pallograph::smt::SmtEncoder;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Fixture {
    Small,
    Medium,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Scenario {
    /// Build the RBAC access model used by cluster-admin/access checks.
    LoadAccessModel,
    /// Build the full Z3 RecFuncDecl model, for comparison and diff users.
    EncodeZ3,
    /// Enumerate principals with a direct cluster-admin grant.
    DirectClusterAdmin,
    /// Enumerate escalation-aware cluster-admin reachability.
    ClusterAdmin,
    /// Enumerate principals with any access in the default namespace.
    NamespaceIsolation,
}

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, value_enum, default_value_t = Fixture::Small)]
    fixture: Fixture,

    #[arg(long, value_enum, default_value_t = Scenario::ClusterAdmin)]
    scenario: Scenario,

    #[arg(long, default_value_t = 1000)]
    iters: u64,

    #[arg(long)]
    include_builtins: bool,

    #[arg(long)]
    include_direct: bool,
}

fn load_store(fixture: Fixture) -> EvalStore {
    let (edb, rules) = match fixture {
        Fixture::Small => load_bench_fixtures().expect("load small fixtures"),
        Fixture::Medium => load_medium_bench_fixtures().unwrap_or_else(|e| panic!("{e:#}")),
    };
    InterpreterBackend
        .evaluate(&edb, &rules)
        .expect("evaluate fixtures")
}

fn facts_encoder<'ctx>(
    ctx: &'ctx z3::Context,
    store: &EvalStore,
    include_builtins: bool,
) -> SmtEncoder<'ctx> {
    let mut enc = SmtEncoder::new(ctx);
    // Baseline-compatible: the perf patch changes the production command path
    // to skip Z3 encoding, but the benchmark commit should compile before that
    // API exists.
    enc.assert_rbac_axioms(store);
    enc.include_builtins = include_builtins;
    enc
}

fn z3_encoder<'ctx>(
    ctx: &'ctx z3::Context,
    store: &EvalStore,
    include_builtins: bool,
) -> SmtEncoder<'ctx> {
    let mut enc = SmtEncoder::new(ctx);
    enc.assert_rbac_axioms(store);
    enc.include_builtins = include_builtins;
    enc
}

fn main() {
    let args = Args::parse();
    let store = load_store(args.fixture);

    let start = Instant::now();
    let mut total = 0usize;

    match args.scenario {
        Scenario::LoadAccessModel => {
            for _ in 0..args.iters {
                let cfg = z3::Config::new();
                let ctx = z3::Context::new(&cfg);
                let enc = facts_encoder(&ctx, &store, args.include_builtins);
                total += black_box(enc.can_entries.get("").map_or(0, Vec::len));
            }
        }
        Scenario::EncodeZ3 => {
            for _ in 0..args.iters {
                let cfg = z3::Config::new();
                let ctx = z3::Context::new(&cfg);
                let enc = z3_encoder(&ctx, &store, args.include_builtins);
                total += black_box(enc.can_entries.get("").map_or(0, Vec::len));
            }
        }
        Scenario::DirectClusterAdmin => {
            let cfg = z3::Config::new();
            let ctx = z3::Context::new(&cfg);
            let enc = facts_encoder(&ctx, &store, args.include_builtins);
            for _ in 0..args.iters {
                total += black_box(enc.direct_violations("", "*", "*", "*").len());
            }
        }
        Scenario::ClusterAdmin => {
            let cfg = z3::Config::new();
            let ctx = z3::Context::new(&cfg);
            let enc = facts_encoder(&ctx, &store, args.include_builtins);
            for _ in 0..args.iters {
                total += black_box(
                    enc.check_reaches("", "*", "*", "*", &[], args.include_direct)
                        .len(),
                );
            }
        }
        Scenario::NamespaceIsolation => {
            let cfg = z3::Config::new();
            let ctx = z3::Context::new(&cfg);
            let enc = facts_encoder(&ctx, &store, args.include_builtins);
            for _ in 0..args.iters {
                total += black_box(enc.check_namespace_isolation("default", &[]).len());
            }
        }
    }

    let elapsed = start.elapsed();
    println!(
        "scenario={:?} fixture={:?} iters={} total={} elapsed={:?} per_iter={:?}",
        args.scenario,
        args.fixture,
        args.iters,
        total,
        elapsed,
        elapsed / args.iters as u32
    );
}
