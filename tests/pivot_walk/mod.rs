// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Checks that the `pivots` walk (src/pivots.rs) reaches exactly what the
//! rules' `controls` says, so the Rust walk can't drift from the closure.

use std::collections::{BTreeMap, BTreeSet};

use mangle_common::Value;
use pallograph::api::Node;
use pallograph::engine::EvalStore;
use pallograph::pivots::PivotGraph;

fn node(columns: &[Value]) -> Node {
    let text = |value: &Value| match value {
        Value::String(text) | Value::Name(text) => text.to_string(),
        other => panic!("expected a string or name, got {other:?}"),
    };
    Node {
        name: text(&columns[0]),
        system: text(&columns[1]),
        kind: text(&columns[2]),
    }
}

/// For every node a path can start from, the walk's targets equal the
/// union of `controls` over its start grantees, less the node itself.
/// Returns how many start nodes it checked.
pub fn assert_walk_matches_controls(label: &str, result: &EvalStore) -> usize {
    let graph = PivotGraph::from_scan(|relation| result.scan(relation).to_vec());
    let start_modes: BTreeSet<Value> = result
        .scan("start_mode")
        .iter()
        .map(|row| row[0].clone())
        .collect();
    let start_kinds: BTreeSet<(Value, Value)> = result
        .scan("start_kind")
        .iter()
        .map(|row| (row[0].clone(), row[1].clone()))
        .collect();

    let mut starts: BTreeMap<Node, BTreeSet<Node>> = BTreeMap::new();
    for row in result.scan("acts_as") {
        if start_modes.contains(&row[6]) {
            starts
                .entry(node(&row[..3]))
                .or_default()
                .insert(node(&row[3..6]));
        }
    }
    for row in result.scan("pivot") {
        if start_kinds.contains(&(row[1].clone(), row[2].clone())) {
            let from = node(&row[..3]);
            starts.entry(from.clone()).or_default().insert(from);
        }
    }
    let mut controls: BTreeMap<Node, BTreeSet<Node>> = BTreeMap::new();
    for row in result.scan("controls") {
        controls
            .entry(node(&row[..3]))
            .or_default()
            .insert(node(&row[3..6]));
    }

    for (from, grantees) in &starts {
        let mut expected: BTreeSet<Node> = grantees
            .iter()
            .filter_map(|grantee| controls.get(grantee))
            .flatten()
            .cloned()
            .collect();
        expected.remove(from);
        let walked: BTreeSet<Node> = graph.walk(from).into_iter().map(|path| path.to).collect();
        assert_eq!(walked, expected, "{label}: walk from {from:?}");
    }
    starts.len()
}
