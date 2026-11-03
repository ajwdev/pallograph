// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tracing target names, one per subsystem. Tagging each event with a target
//! groups the log output by subsystem and lets the level be tuned per
//! subsystem through `RUST_LOG`, independent of which module the event lives
//! in (ex: cluster listing and object projection both live in `edb`).
//!
//! Example: quiet everything but the fixpoint, in detail:
//!
//! ```text
//! RUST_LOG=pallograph=warn,pallograph::fixpoint=debug
//! ```
//!
//! Each name keeps the `pallograph::` prefix so the crate-wide default filter
//! (`pallograph=info`) still matches every subsystem, and the more specific
//! directive wins when both are present.

/// Listing resources from a live cluster.
pub const CLUSTER: &str = "pallograph::cluster";

/// Loading datasources and projecting k8s objects into facts.
pub const DATASOURCE: &str = "pallograph::datasource";

/// Program evaluation: the initial fixpoint, backend session spawn, snapshots,
/// and derived relation sizes.
pub const FIXPOINT: &str = "pallograph::fixpoint";

/// Ad-hoc `?-` query evaluation.
pub const QUERY: &str = "pallograph::query";

/// Keeping the engine current with a watched cluster.
pub const WATCH: &str = "pallograph::watch";
