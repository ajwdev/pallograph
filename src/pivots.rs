// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A naive forward walk of the generic pivot graph (rules/closure.mg), for
//! systems the REPL has no first-class commands for.
//!
//! The rules decide what is reachable (`controls`). This only picks one
//! shortest path to each node and keeps what a reader needs to follow it,
//! and names no system, kind or mechanism: those all come from the rows.

use std::collections::{BTreeMap, BTreeSet};

use mangle_common::Value;

/// A node of the pivot graph. System and kind are name constants with their
/// leading `/`, as the rules write them (e.g. `/k8s`, `/serviceaccount`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Node {
    pub name: String,
    pub system: String,
    pub kind: String,
}

/// A node as a user names it: a name, and the system and kind when the name
/// alone is ambiguous.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeQuery {
    pub name: String,
    pub system: Option<String>,
    pub kind: Option<String>,
}

/// One pivot along a path: acting with `grantee`'s grants (the previous node
/// itself, or one of its ambient grantees), become `to`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PivotStep {
    pub grantee: Node,
    /// Every mechanism of this pivot from `grantee` to `to` with `source`,
    /// sorted.
    pub mechanisms: Vec<String>,
    pub source: String,
    pub to: Node,
}

/// A shortest path to `to`. The first step starts at the node walked from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PivotPath {
    pub to: Node,
    pub steps: Vec<PivotStep>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ResolveError {
    #[error("No node named '{0}'.")]
    Unknown(String),
    #[error(
        "'{name}' names several nodes; add a system and kind: {}",
        candidates
            .iter()
            .map(|node| format!("{} {} {}", node.name, node.system, node.kind))
            .collect::<Vec<_>>()
            .join(", ")
    )]
    Ambiguous { name: String, candidates: Vec<Node> },
}

/// The pivot graph as the rules derive it. Every map is ordered, so a walk
/// visits the same nodes in the same order on every run.
#[derive(Default)]
pub struct PivotGraph {
    /// Grantee, then source, then each node reached with its mechanisms.
    pivots: BTreeMap<Node, BTreeMap<String, BTreeMap<Node, BTreeSet<String>>>>,
    /// Actor, then mode, then its ambient grantees.
    acts_as: BTreeMap<Node, BTreeMap<String, BTreeSet<Node>>>,
    /// Mode, then the sources it takes pivots from.
    pivot_modes: BTreeMap<String, BTreeSet<String>>,
    start_kinds: BTreeSet<(String, String)>,
    start_modes: BTreeSet<String>,
    /// What a path can stand on: pivot targets, acts_as actors, and pivot
    /// sources whose kind starts a path. Grantee-only kinds (a stand-in such
    /// as Kubernetes's /impersonated_group) are left out, so naming a group
    /// isn't ambiguous with its stand-in.
    nodes: BTreeSet<Node>,
}

/// A candidate step out of a node: (to, grantee, source, mechanisms).
type Edge<'a> = (&'a Node, &'a Node, &'a str, &'a BTreeSet<String>);

impl PivotGraph {
    /// Read the graph from `pivot`, `acts_as`, `pivot_mode`, `start_kind`
    /// and `start_mode`. A row of the wrong shape is skipped with a warning.
    pub fn from_scan<F: Fn(&str) -> Vec<Vec<Value>>>(scan: F) -> Self {
        let mut graph = PivotGraph::default();
        for row in scan("start_kind") {
            match row.as_slice() {
                [system, kind] => match (constant(system), constant(kind)) {
                    (Some(system), Some(kind)) => {
                        graph.start_kinds.insert((system, kind));
                    }
                    _ => unexpected_row("start_kind", &row),
                },
                _ => unexpected_row("start_kind", &row),
            }
        }
        for row in scan("start_mode") {
            match row.as_slice() {
                [mode] => match constant(mode) {
                    Some(mode) => {
                        graph.start_modes.insert(mode);
                    }
                    None => unexpected_row("start_mode", &row),
                },
                _ => unexpected_row("start_mode", &row),
            }
        }
        for row in scan("pivot_mode") {
            match row.as_slice() {
                [mode, source] => match (constant(mode), constant(source)) {
                    (Some(mode), Some(source)) => {
                        graph.pivot_modes.entry(mode).or_default().insert(source);
                    }
                    _ => unexpected_row("pivot_mode", &row),
                },
                _ => unexpected_row("pivot_mode", &row),
            }
        }
        for row in scan("pivot") {
            let parsed = match row.as_slice() {
                [from @ .., mechanism, source] if from.len() == 6 => node(&from[..3])
                    .zip(node(&from[3..]))
                    .zip(constant(mechanism).zip(constant(source))),
                _ => None,
            };
            let Some(((from, to), (mechanism, source))) = parsed else {
                unexpected_row("pivot", &row);
                continue;
            };
            if graph.starts_paths(&from) {
                graph.nodes.insert(from.clone());
            }
            graph.nodes.insert(to.clone());
            graph
                .pivots
                .entry(from)
                .or_default()
                .entry(source)
                .or_default()
                .entry(to)
                .or_default()
                .insert(mechanism);
        }
        for row in scan("acts_as") {
            let parsed = match row.as_slice() {
                [columns @ .., mode] if columns.len() == 6 => node(&columns[..3])
                    .zip(node(&columns[3..]))
                    .zip(constant(mode)),
                _ => None,
            };
            let Some(((actor, grantee), mode)) = parsed else {
                unexpected_row("acts_as", &row);
                continue;
            };
            graph.nodes.insert(actor.clone());
            graph
                .acts_as
                .entry(actor)
                .or_default()
                .entry(mode)
                .or_default()
                .insert(grantee);
        }
        graph
    }

    /// The one node `query` names.
    pub fn resolve(&self, query: &NodeQuery) -> Result<Node, ResolveError> {
        let candidates: Vec<Node> = self
            .nodes
            .iter()
            .filter(|node| node.name == query.name)
            .filter(|node| {
                query
                    .system
                    .as_ref()
                    .is_none_or(|system| &node.system == system)
            })
            .filter(|node| query.kind.as_ref().is_none_or(|kind| &node.kind == kind))
            .cloned()
            .collect();
        match candidates.len() {
            0 => Err(ResolveError::Unknown(query.name.clone())),
            1 => Ok(candidates.into_iter().next().expect("one candidate")),
            _ => Err(ResolveError::Ambiguous {
                name: query.name.clone(),
                candidates,
            }),
        }
    }

    /// One shortest path to every node reachable from `from`, sorted by the
    /// node reached. `from` itself is never listed, even when a cycle leads
    /// back to it.
    pub fn walk(&self, from: &Node) -> Vec<PivotPath> {
        // Breadth first, one parent per node. Within a layer, nodes are
        // expanded in sorted order and their edges taken in sorted order, so
        // the first path found to a node is the same on every run.
        let mut parent: BTreeMap<&Node, (&Node, PivotStep)> = BTreeMap::new();
        let mut layer: Vec<&Node> = vec![from];
        let mut first = true;
        while !layer.is_empty() {
            let mut next: Vec<&Node> = Vec::new();
            for &node in &layer {
                let mut edges = if first {
                    self.start_edges(node)
                } else {
                    self.edges(node)
                };
                edges.sort_by(|a, b| (a.0, a.1, a.2).cmp(&(b.0, b.1, b.2)));
                for (to, grantee, source, mechanisms) in edges {
                    if to == from || parent.contains_key(to) {
                        continue;
                    }
                    let step = PivotStep {
                        grantee: grantee.clone(),
                        mechanisms: mechanisms.iter().cloned().collect(),
                        source: source.to_string(),
                        to: to.clone(),
                    };
                    parent.insert(to, (node, step));
                    next.push(to);
                }
            }
            next.sort();
            layer = next;
            first = false;
        }

        parent
            .keys()
            .map(|&to| {
                let mut steps = Vec::new();
                let mut at = to;
                while let Some((previous, step)) = parent.get(at) {
                    steps.push(step.clone());
                    at = previous;
                }
                steps.reverse();
                PivotPath {
                    to: to.clone(),
                    steps,
                }
            })
            .collect()
    }

    fn starts_paths(&self, node: &Node) -> bool {
        self.start_kinds
            .contains(&(node.system.clone(), node.kind.clone()))
    }

    /// Edges from where a path starts: the node's grantees in each start
    /// mode, and the node itself when its kind starts paths, with pivots of
    /// every source, as in `controls`'s base rule.
    fn start_edges(&self, from: &Node) -> Vec<Edge<'_>> {
        let mut grantees: BTreeSet<&Node> = self
            .acts_as
            .get(from)
            .into_iter()
            .flat_map(|modes| {
                modes
                    .iter()
                    .filter(|(mode, _)| self.start_modes.contains(*mode))
                    .flat_map(|(_, grantees)| grantees)
            })
            .collect();
        if self.starts_paths(from)
            && let Some((node, _)) = self.pivots.get_key_value(from)
        {
            grantees.insert(node);
        }
        grantees
            .into_iter()
            .flat_map(|grantee| {
                self.pivots
                    .get(grantee)
                    .into_iter()
                    .flat_map(move |sources| {
                        sources.iter().flat_map(move |(source, targets)| {
                            targets.iter().map(move |(to, mechanisms)| {
                                (to, grantee, source.as_str(), mechanisms)
                            })
                        })
                    })
            })
            .collect()
    }

    /// Edges from a node reached partway along a path, as `node_pivot`
    /// derives them: its grantees in each mode, with the pivots of the
    /// source that mode uses.
    fn edges(&self, node: &Node) -> Vec<Edge<'_>> {
        let Some(modes) = self.acts_as.get(node) else {
            return Vec::new();
        };
        let mut edges = Vec::new();
        for (mode, grantees) in modes {
            for source in self.pivot_modes.get(mode).into_iter().flatten() {
                for grantee in grantees {
                    let targets = self
                        .pivots
                        .get(grantee)
                        .and_then(|sources| sources.get(source));
                    for (to, mechanisms) in targets.into_iter().flatten() {
                        edges.push((to, grantee, source.as_str(), mechanisms));
                    }
                }
            }
        }
        edges
    }
}

/// A node from three columns: name (a string), system and kind (names).
fn node(columns: &[Value]) -> Option<Node> {
    match columns {
        [Value::String(name), system, kind] => Some(Node {
            name: name.clone(),
            system: constant(system)?,
            kind: constant(kind)?,
        }),
        _ => None,
    }
}

/// A name constant's text, with its leading `/`.
fn constant(value: &Value) -> Option<String> {
    match value {
        Value::Name(name) => Some(name.to_string()),
        _ => None,
    }
}

fn unexpected_row(relation: &str, row: &[Value]) {
    eprintln!("warning: skipping {relation} row with an unexpected shape: {row:?}");
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use mangle_common::Value;

    use super::*;

    fn s(text: &str) -> Value {
        Value::String(text.into())
    }

    fn n(text: &str) -> Value {
        Value::Name(text.into())
    }

    fn node(name: &str, system: &str, kind: &str) -> Node {
        Node {
            name: name.into(),
            system: system.into(),
            kind: kind.into(),
        }
    }

    fn query(name: &str) -> NodeQuery {
        NodeQuery {
            name: name.into(),
            ..NodeQuery::default()
        }
    }

    /// `pivot(From, ..., To, ..., Mechanism, Source)` with nodes as
    /// (name, kind), all in system /s.
    fn pivot(from: (&str, &str), to: (&str, &str), mechanism: &str, source: &str) -> Vec<Value> {
        vec![
            s(from.0),
            n("/s"),
            n(from.1),
            s(to.0),
            n("/s"),
            n(to.1),
            n(mechanism),
            n(source),
        ]
    }

    fn acts_as(actor: (&str, &str), grantee: (&str, &str), mode: &str) -> Vec<Value> {
        vec![
            s(actor.0),
            n("/s"),
            n(actor.1),
            s(grantee.0),
            n("/s"),
            n(grantee.1),
            n(mode),
        ]
    }

    /// A graph with the usual vocabulary: paths start in /login from /u
    /// nodes, and a node reached on the way takes /grant pivots in /assumed.
    fn graph(pivots: Vec<Vec<Value>>, acts: Vec<Vec<Value>>) -> PivotGraph {
        let mut rows: HashMap<&str, Vec<Vec<Value>>> = HashMap::new();
        rows.insert("pivot", pivots);
        rows.insert("acts_as", acts);
        rows.insert("pivot_mode", vec![vec![n("/assumed"), n("/grant")]]);
        rows.insert("start_kind", vec![vec![n("/s"), n("/u")]]);
        rows.insert("start_mode", vec![vec![n("/login")]]);
        PivotGraph::from_scan(|relation| rows.get(relation).cloned().unwrap_or_default())
    }

    /// Each node acting as itself, logged in and assumed.
    fn itself(nodes: &[(&str, &str)]) -> Vec<Vec<Value>> {
        nodes
            .iter()
            .flat_map(|&n| [acts_as(n, n, "/login"), acts_as(n, n, "/assumed")])
            .collect()
    }

    fn targets(paths: &[PivotPath]) -> Vec<&str> {
        paths.iter().map(|path| path.to.name.as_str()).collect()
    }

    #[test]
    fn walk_follows_acts_as_and_pivot_mode() {
        let graph = graph(
            vec![
                pivot(("a", "/u"), ("b", "/i"), "/m1", "/grant"),
                pivot(("b", "/i"), ("c", "/i"), "/m2", "/grant"),
            ],
            itself(&[("a", "/u"), ("b", "/i")]),
        );
        let paths = graph.walk(&node("a", "/s", "/u"));
        assert_eq!(targets(&paths), ["b", "c"]);
        assert_eq!(paths[0].steps.len(), 1);
        assert_eq!(paths[0].steps[0].mechanisms, ["/m1"]);
        assert_eq!(paths[1].steps.len(), 2);
        assert_eq!(paths[1].steps[1].grantee, node("b", "/s", "/i"));
        assert_eq!(paths[1].steps[1].mechanisms, ["/m2"]);
    }

    #[test]
    fn walk_ignores_a_source_its_mode_does_not_use() {
        let graph = graph(
            vec![
                pivot(("a", "/u"), ("b", "/i"), "/m1", "/grant"),
                pivot(("b", "/i"), ("d", "/i"), "/m3", "/other"),
            ],
            itself(&[("a", "/u"), ("b", "/i")]),
        );
        assert_eq!(targets(&graph.walk(&node("a", "/s", "/u"))), ["b"]);
    }

    #[test]
    fn walk_starts_from_a_start_kind_node_itself() {
        // No acts_as /login row: r starts as itself because /u is a
        // start_kind.
        let graph = graph(
            vec![pivot(("r", "/u"), ("t", "/i"), "/m", "/grant")],
            vec![],
        );
        assert_eq!(targets(&graph.walk(&node("r", "/s", "/u"))), ["t"]);
    }

    #[test]
    fn walk_shows_the_grantee_when_it_is_not_the_node() {
        let mut acts = itself(&[("a", "/u"), ("b", "/i")]);
        acts.push(acts_as(("b", "/i"), ("g", "/grp"), "/assumed"));
        let graph = graph(
            vec![
                pivot(("a", "/u"), ("b", "/i"), "/m1", "/grant"),
                pivot(("g", "/grp"), ("e", "/i"), "/m2", "/grant"),
            ],
            acts,
        );
        let paths = graph.walk(&node("a", "/s", "/u"));
        assert_eq!(targets(&paths), ["b", "e"]);
        assert_eq!(paths[1].steps[1].grantee, node("g", "/s", "/grp"));
    }

    #[test]
    fn walk_skips_a_cycle_back_to_from() {
        let graph = graph(
            vec![
                pivot(("a", "/u"), ("b", "/u"), "/m", "/grant"),
                pivot(("b", "/u"), ("a", "/u"), "/m", "/grant"),
            ],
            itself(&[("a", "/u"), ("b", "/u")]),
        );
        assert_eq!(targets(&graph.walk(&node("a", "/s", "/u"))), ["b"]);
    }

    // Ties the walk can only break by sorting. p and q are reached first;
    // p reaches z and q reaches w, so the next layer is discovered as
    // [z, w] and must be sorted for c to come through w. And w takes d
    // through two grantees whose modes list h2 first, so the edges must be
    // sorted for h1 to win.
    #[test]
    fn walk_sorts_layers_and_edges_to_break_ties() {
        let mut rows: HashMap<&str, Vec<Vec<Value>>> = HashMap::new();
        rows.insert(
            "pivot",
            vec![
                pivot(("a", "/u"), ("p", "/i"), "/m", "/grant"),
                pivot(("a", "/u"), ("q", "/i"), "/m", "/grant"),
                pivot(("p", "/i"), ("z", "/i"), "/m", "/grant"),
                pivot(("q", "/i"), ("w", "/i"), "/m", "/grant"),
                pivot(("z", "/i"), ("c", "/i"), "/m", "/grant"),
                pivot(("w", "/i"), ("c", "/i"), "/m", "/grant"),
                pivot(("h1", "/g"), ("d", "/i"), "/m", "/grant"),
                pivot(("h2", "/g"), ("d", "/i"), "/m", "/grant"),
            ],
        );
        let mut acts = itself(&[
            ("a", "/u"),
            ("p", "/i"),
            ("q", "/i"),
            ("z", "/i"),
            ("w", "/i"),
        ]);
        acts.push(acts_as(("w", "/i"), ("h2", "/g"), "/first"));
        acts.push(acts_as(("w", "/i"), ("h1", "/g"), "/second"));
        rows.insert("acts_as", acts);
        rows.insert(
            "pivot_mode",
            vec![
                vec![n("/assumed"), n("/grant")],
                vec![n("/first"), n("/grant")],
                vec![n("/second"), n("/grant")],
            ],
        );
        rows.insert("start_mode", vec![vec![n("/login")]]);
        let graph =
            PivotGraph::from_scan(|relation| rows.get(relation).cloned().unwrap_or_default());
        let paths = graph.walk(&node("a", "/s", "/u"));
        let to = |name: &str| paths.iter().find(|path| path.to.name == name).unwrap();
        assert_eq!(to("c").steps[1].to, node("w", "/s", "/i"));
        assert_eq!(to("d").steps[2].grantee, node("h1", "/s", "/g"));
    }

    #[test]
    fn step_lists_every_mechanism_of_the_chosen_edge() {
        let graph = graph(
            vec![
                pivot(("a", "/u"), ("b", "/i"), "/token", "/grant"),
                pivot(("a", "/u"), ("b", "/i"), "/pod_exec", "/grant"),
            ],
            itself(&[("a", "/u")]),
        );
        let paths = graph.walk(&node("a", "/s", "/u"));
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].steps[0].mechanisms, ["/pod_exec", "/token"]);
    }

    #[test]
    fn resolve_reports_ambiguous_names() {
        let graph = graph(
            vec![
                pivot(("a", "/u"), ("x", "/u"), "/m", "/grant"),
                pivot(("a", "/u"), ("x", "/g"), "/m", "/grant"),
            ],
            vec![],
        );
        assert_eq!(
            graph.resolve(&query("x")),
            Err(ResolveError::Ambiguous {
                name: "x".into(),
                candidates: vec![node("x", "/s", "/g"), node("x", "/s", "/u")],
            })
        );
        let exact = NodeQuery {
            name: "x".into(),
            system: Some("/s".into()),
            kind: Some("/g".into()),
        };
        assert_eq!(graph.resolve(&exact), Ok(node("x", "/s", "/g")));
        assert_eq!(
            graph.resolve(&query("nope")),
            Err(ResolveError::Unknown("nope".into()))
        );
    }

    #[test]
    fn resolve_ignores_grantee_only_kinds() {
        let graph = graph(
            vec![
                pivot(("a", "/u"), ("g", "/grp"), "/m", "/grant"),
                pivot(("g", "/stand_in"), ("e", "/i"), "/m", "/grant"),
            ],
            vec![acts_as(("g", "/grp"), ("g", "/stand_in"), "/assumed")],
        );
        assert_eq!(graph.resolve(&query("g")), Ok(node("g", "/s", "/grp")));
    }
}
