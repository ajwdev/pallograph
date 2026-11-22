// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A dependency graph of the Mangle rules: which predicates each rule's
//! head depends on, with the rule text behind every predicate. The `graph`
//! REPL command serves it as interactive pages (see `crate::graph_server`).
//!
//! This module reads rule text only. It depends on the mangle crates and
//! std, not on the engine, so it can move with the Datalog code.

pub mod dot;
pub mod model;
pub mod view;

pub use dot::to_dot;
pub use model::{
    Edge, Predicate, PredicateKind, RuleGraph, RuleSource, SESSION_ORIGIN_PREFIX, Statement,
    StatementKind,
};
pub use view::{View, ViewOptions, view};
