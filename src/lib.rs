// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

#![feature(iter_intersperse)]

//! Pallograph library crate — exposes the engine and evaluation backend for
//! integration tests and benchmarks.  The binary entry point is `main.rs`.

mod config;
pub(crate) mod dd;
pub mod edb;
pub mod engine;
pub(crate) mod load;
pub(crate) mod query;
pub(crate) mod repl;
pub(crate) mod selector;
pub(crate) mod smt;
pub mod snapshot;
pub(crate) mod value;
