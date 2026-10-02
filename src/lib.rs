// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pallograph library crate — exposes the engine and evaluation backend for
//! integration tests and benchmarks.  The binary entry point is `main.rs`.

// TODO(ajw): Revisit type_complexity. Several flagged types would read better
// as aliases or small structs (e.g. the 5-String tuples in smt::SmtEncoder, the
// provenance index in repl). Allowed for now so it doesn't block -D warnings.
#![allow(clippy::type_complexity)]

pub mod config;
pub(crate) mod dd;
pub mod edb;
pub mod engine;
pub mod load;
pub(crate) mod query;
pub mod repl;
pub(crate) mod selector;
pub(crate) mod smt;
pub mod snapshot;
pub(crate) mod value;
