// Copyright (c) 2026 Netflix, Inc.
// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Checks that `anonymize` preserved the fact graph: per-relation tuple
//! counts (EDB and derived IDB) must match between a real dump and its
//! anonymized copy.
//!
//!   PALLOGRAPH_REAL_FIXTURES=real PALLOGRAPH_ANON_FIXTURES=anon \
//!     cargo test --release --test anonymize_equiv -- --ignored --nocapture

use pallograph::engine::{Backend, InterpreterBackend, load_bench_fixtures_from};
use std::collections::BTreeMap;

fn counts(dir: &str) -> BTreeMap<String, usize> {
    let (edb, rules) = load_bench_fixtures_from(dir).expect("load fixtures");
    let store = InterpreterBackend.evaluate(&edb, &rules).expect("evaluate");
    store
        .relation_names()
        .map(|r| (r.to_string(), store.scan(r).len()))
        .collect()
}

#[test]
#[ignore = "needs PALLOGRAPH_REAL_FIXTURES and PALLOGRAPH_ANON_FIXTURES"]
fn anonymized_dump_has_identical_relation_counts() {
    let (Ok(real), Ok(anon)) = (
        std::env::var("PALLOGRAPH_REAL_FIXTURES"),
        std::env::var("PALLOGRAPH_ANON_FIXTURES"),
    ) else {
        panic!("set PALLOGRAPH_REAL_FIXTURES and PALLOGRAPH_ANON_FIXTURES");
    };
    let (a, b) = (counts(&real), counts(&anon));
    for (rel, n) in &a {
        println!(
            "{rel:<32} real={n:<8} anon={}",
            b.get(rel).copied().unwrap_or(0)
        );
    }
    assert_eq!(a, b, "relation counts differ");
}
