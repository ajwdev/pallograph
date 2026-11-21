// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Renders a [`View`] as Graphviz dot.
//!
//! By default arrows follow the data, top to bottom: from what is supplied
//! at runtime (EDB) down through each rule that uses them, the order the
//! engine derives facts in. `topdown` reverses them to point from a rule's
//! head to what it depends on, like a pprof call graph.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

use super::model::{PredicateKind, RuleGraph, SESSION_ORIGIN_PREFIX};
use super::view::View;

/// Fill for predicates supplied at runtime (EDB), which no rule file defines.
pub const SUPPLIED_AT_RUNTIME_COLOR: &str = "#eeeeee";

/// Fill shared by every rule added in the session (`define`, `source`).
pub const SESSION_COLOR: &str = "#fff3c4";

/// A fill color for every file that defines a predicate, distinct however
/// many files there are (see [`spread_hues`]). Colors follow every file in
/// the graph, not only a view's, so a file keeps its color while walking.
/// Rules added in the session share [`SESSION_COLOR`] and take no hue, so
/// `define` doesn't move the files' colors; adding a rule file does.
pub fn file_colors(graph: &RuleGraph) -> BTreeMap<String, String> {
    let origins: BTreeSet<&str> = graph
        .predicates
        .values()
        .filter_map(|predicate| predicate.origin.as_deref())
        .collect();
    let (session, files): (Vec<&str>, Vec<&str>) = origins
        .into_iter()
        .partition(|origin| origin.starts_with(SESSION_ORIGIN_PREFIX));
    let hues = spread_hues(files.len());
    files
        .into_iter()
        .zip(hues)
        // Pale, so black node labels stay readable.
        .map(|(origin, hue)| (origin.to_string(), hsl_to_hex(hue, 0.55, 0.80)))
        .chain(
            session
                .into_iter()
                .map(|origin| (origin.to_string(), SESSION_COLOR.to_string())),
        )
        .collect()
}

/// `count` hues spaced evenly around the color wheel, so no two are closer
/// than 360/count degrees. They are handed out with a stride of about
/// count/2.6 steps (the golden ratio's share), coprime with `count` so every
/// hue is used once, which puts consecutive entries (files next to each
/// other by name, often drawn together) far apart.
fn spread_hues(count: usize) -> Vec<f64> {
    if count == 0 {
        return Vec::new();
    }
    let target = ((count as f64) * 0.382).round().max(1.0) as usize;
    let coprime = |stride: usize| greatest_common_divisor(stride, count) == 1;
    let stride = (0..count)
        .flat_map(|offset| [target + offset, target.saturating_sub(offset)])
        .find(|stride| *stride > 0 && coprime(*stride))
        .unwrap_or(1);
    (0..count)
        .map(|index| 360.0 * ((index * stride) % count) as f64 / count as f64)
        .collect()
}

fn greatest_common_divisor(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

fn hsl_to_hex(hue: f64, saturation: f64, lightness: f64) -> String {
    let chroma = (1.0 - (2.0 * lightness - 1.0).abs()) * saturation;
    let sector = hue / 60.0;
    let second = chroma * (1.0 - (sector % 2.0 - 1.0).abs());
    let (red, green, blue) = match sector as u32 {
        0 => (chroma, second, 0.0),
        1 => (second, chroma, 0.0),
        2 => (0.0, chroma, second),
        3 => (0.0, second, chroma),
        4 => (second, 0.0, chroma),
        _ => (chroma, 0.0, second),
    };
    let base = lightness - chroma / 2.0;
    let byte = |channel: f64| ((channel + base) * 255.0).round() as u8;
    format!("#{:02x}{:02x}{:02x}", byte(red), byte(green), byte(blue))
}

/// The node for predicates supplied at runtime when collapsed by file.
const SUPPLIED_AT_RUNTIME_FILE_NODE: &str = "supplied at runtime (EDB)";

pub fn to_dot(view: &View) -> String {
    let flow = !view.options.topdown;
    let name = if flow {
        "mangle_flow"
    } else {
        "mangle_topdown"
    };
    let arrow = |head: &str, body: &str| {
        if flow {
            format!("{} -> {}", quote(body), quote(head))
        } else {
            format!("{} -> {}", quote(head), quote(body))
        }
    };

    let colors = file_colors(view.graph);
    let color = |origin: &str| {
        colors
            .get(origin)
            .map_or(SUPPLIED_AT_RUNTIME_COLOR, String::as_str)
    };
    let origin_of = |predicate: &str| {
        view.graph
            .predicates
            .get(predicate)
            .and_then(|predicate| predicate.origin.as_deref())
    };

    let mut out = String::new();
    writeln!(out, "digraph {name} {{").unwrap();
    if view.options.files {
        writeln!(
            out,
            "  rankdir=TB; newrank=true; node [shape=box, style=\"rounded,filled\", fontname=\"Helvetica\"];"
        )
        .unwrap();
        // (from file, to file) -> how many rules use it
        let mut collapsed: BTreeMap<(&str, &str), usize> = BTreeMap::new();
        for edge in &view.edges {
            let head = origin_of(&edge.head).unwrap_or(SUPPLIED_AT_RUNTIME_FILE_NODE);
            let body = origin_of(&edge.body).unwrap_or(SUPPLIED_AT_RUNTIME_FILE_NODE);
            if head != body {
                *collapsed.entry((head, body)).or_default() += edge.count;
            }
        }
        let files: BTreeSet<&str> = collapsed.keys().flat_map(|(a, b)| [*a, *b]).collect();
        for file in files {
            if file == SUPPLIED_AT_RUNTIME_FILE_NODE {
                writeln!(
                    out,
                    "  {} [shape=cylinder, fillcolor=\"{SUPPLIED_AT_RUNTIME_COLOR}\"];",
                    quote(file)
                )
                .unwrap();
            } else {
                writeln!(out, "  {} [fillcolor=\"{}\"];", quote(file), color(file)).unwrap();
            }
        }
        for ((head, body), count) in collapsed {
            writeln!(
                out,
                "  {} [xlabel=\"{count} uses\", penwidth={}];",
                arrow(head, body),
                penwidth(count, 5.0)
            )
            .unwrap();
        }
        out.push_str("}\n");
        return out;
    }

    // newrank avoids the default ranker's "trouble in init_rank" failure
    // when edges cross many clusters, as in the whole graph.
    writeln!(
        out,
        "  rankdir=TB; newrank=true; nodesep=0.15; ranksep=0.6;"
    )
    .unwrap();
    out.push_str(
        "  node [shape=box, style=\"rounded,filled\", fontname=\"Helvetica\", fontsize=10];\n",
    );
    if let Some(focus) = &view.options.focus {
        writeln!(out, "  {} [penwidth=3];", quote(focus)).unwrap();
    }
    let mut by_origin: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for node in &view.nodes {
        let predicate = view.graph.predicates.get(node);
        match predicate.and_then(|predicate| predicate.origin.as_deref()) {
            Some(origin)
                if predicate.map(|predicate| predicate.kind)
                    != Some(PredicateKind::SuppliedAtRuntime) =>
            {
                by_origin.entry(origin).or_default().push(node)
            }
            _ => writeln!(
                out,
                "  {} [shape=cylinder, fillcolor=\"{SUPPLIED_AT_RUNTIME_COLOR}\"];",
                quote(node)
            )
            .unwrap(),
        }
    }
    for (origin, nodes) in by_origin {
        let boxed = view.options.boxes;
        if boxed {
            let label = origin.rsplit('/').next().unwrap_or(origin);
            writeln!(
                out,
                "  subgraph {} {{ label={}; style=dashed;",
                quote(&format!("cluster_{origin}")),
                quote(label)
            )
            .unwrap();
        }
        for node in nodes {
            // Facts written in a rule file are a data source too, so they
            // share the cylinder with predicates supplied at runtime.
            let written_facts = view
                .graph
                .predicates
                .get(node)
                .is_some_and(|predicate| predicate.kind == PredicateKind::WrittenFact);
            let shape = if written_facts {
                "shape=cylinder, "
            } else {
                ""
            };
            writeln!(
                out,
                "    {} [{shape}fillcolor=\"{}\"];",
                quote(node),
                color(origin)
            )
            .unwrap();
        }
        if boxed {
            out.push_str("  }\n");
        }
    }
    for edge in &view.edges {
        let mut attributes = Vec::new();
        if edge.count > 1 {
            attributes.push(format!("xlabel=\"x{}\"", edge.count));
        }
        if edge.negated {
            attributes.push("style=dashed, color=red, arrowhead=tee".to_string());
        }
        attributes.push(format!("penwidth={}", penwidth(edge.count, 4.0)));
        writeln!(
            out,
            "  {} [{}];",
            arrow(&edge.head, &edge.body),
            attributes.join(", ")
        )
        .unwrap();
    }
    out.push_str("}\n");
    out
}

fn penwidth(count: usize, max: f64) -> f64 {
    let width = (1.0 + (count as f64).log2()).min(max);
    (width * 10.0).round() / 10.0
}

fn quote(name: &str) -> String {
    format!("\"{}\"", name.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule_graph::{RuleSource, ViewOptions, view};

    fn graph() -> RuleGraph {
        RuleGraph::build(&[
            RuleSource {
                origin: "rules/a.mg".to_string(),
                text: "a(X) :- b(X), !c(X).\n".to_string(),
            },
            RuleSource {
                origin: "rules/b.mg".to_string(),
                text: "b(X) :- k8s(X).\nc(X) :- k8s(X).\n".to_string(),
            },
        ])
    }

    fn dot(options: ViewOptions) -> String {
        let graph = graph();
        to_dot(&view(&graph, options).unwrap())
    }

    #[test]
    fn dot_direction() {
        // By default data flows from what is supplied at runtime down to
        // what is derived from them.
        let out = dot(ViewOptions::default());
        assert!(out.starts_with("digraph mangle_flow {"), "{out}");
        assert!(out.contains("rankdir=TB"));
        // The default ranker fails ("trouble in init_rank") on the whole
        // graph, where edges cross many file clusters.
        assert!(out.contains("newrank=true"), "{out}");
        assert!(out.contains("\"b\" -> \"a\""));
        assert!(out.contains("\"k8s\" -> \"b\""));
        assert!(out.contains("\"k8s\" [shape=cylinder"));
        assert!(out.contains("\"a\" [fillcolor="), "{out}");

        let out = dot(ViewOptions {
            topdown: true,
            ..ViewOptions::default()
        });
        assert!(out.starts_with("digraph mangle_topdown {"), "{out}");
        assert!(out.contains("rankdir=TB"));
        assert!(out.contains("\"a\" -> \"b\""));
    }

    #[test]
    fn session_rules_do_not_shift_file_colors() {
        let files = vec![
            RuleSource {
                origin: "rules/a.mg".to_string(),
                text: "a(X) :- k8s(X).\n".to_string(),
            },
            RuleSource {
                origin: "rules/b.mg".to_string(),
                text: "b(X) :- a(X).\n".to_string(),
            },
        ];
        let before = file_colors(&RuleGraph::build(&files));
        let mut with_session = files.clone();
        for number in 1..=3 {
            with_session.push(RuleSource {
                origin: format!("session #{number}"),
                text: format!("s{number}(X) :- b(X).\n"),
            });
        }
        let after = file_colors(&RuleGraph::build(&with_session));
        assert_eq!(after["rules/a.mg"], before["rules/a.mg"]);
        assert_eq!(after["rules/b.mg"], before["rules/b.mg"]);
        // Every session rule shares one color.
        assert_eq!(after["session #1"], after["session #3"]);
        assert_ne!(after["session #1"], after["rules/a.mg"]);
    }

    #[test]
    fn file_colors_are_distinct_and_pale_for_many_files() {
        let sources: Vec<RuleSource> = (0..40)
            .map(|index| RuleSource {
                origin: format!("rules/f{index:02}.mg"),
                text: format!("p{index}(X) :- k8s(X).\n"),
            })
            .collect();
        let colors = file_colors(&RuleGraph::build(&sources));
        assert_eq!(colors.len(), 40);
        let distinct: BTreeSet<&String> = colors.values().collect();
        assert_eq!(distinct.len(), 40, "{colors:?}");
        for color in colors.values() {
            assert_eq!(color.len(), 7, "{color}");
            let channels: Vec<u8> = (0..3)
                .map(|channel| {
                    u8::from_str_radix(&color[1 + 2 * channel..3 + 2 * channel], 16).unwrap()
                })
                .collect();
            // Pale enough for black node labels.
            assert!(channels.iter().all(|channel| *channel >= 0xa0), "{color}");
        }
        // Predicates supplied at runtime have no file, so no color here.
        assert!(!colors.contains_key("k8s"));
    }

    #[test]
    fn hues_are_evenly_spaced_and_neighbors_far_apart() {
        let circular = |a: f64, b: f64| {
            let gap = (a - b).abs() % 360.0;
            gap.min(360.0 - gap)
        };
        for count in [1, 2, 5, 12, 13, 40] {
            let hues = spread_hues(count);
            assert_eq!(hues.len(), count);
            // Evenly spaced: sorted, every gap is 360/count.
            let mut sorted = hues.clone();
            sorted.sort_by(f64::total_cmp);
            for pair in sorted.windows(2) {
                let gap = pair[1] - pair[0];
                assert!(
                    (gap - 360.0 / count as f64).abs() < 1e-6,
                    "{count}: {sorted:?}"
                );
            }
            // Files next to each other by name, often drawn together, get
            // hues far apart.
            if count >= 5 {
                for pair in hues.windows(2) {
                    assert!(circular(pair[0], pair[1]) >= 90.0, "{count}: {hues:?}");
                }
            }
        }
    }

    #[test]
    fn dot_uses_file_colors() {
        let graph = graph();
        let colors = file_colors(&graph);
        let out = to_dot(&view(&graph, ViewOptions::default()).unwrap());
        let expected = format!("\"a\" [fillcolor=\"{}\"]", colors["rules/a.mg"]);
        assert!(out.contains(&expected), "{out}");
    }

    #[test]
    fn data_sources_are_cylinders() {
        // Shape says whether a predicate is derived (box) or a data source
        // (cylinder); color says where it is defined.
        let graph = RuleGraph::build(&[RuleSource {
            origin: "rules/t.mg".to_string(),
            text: "table(/x).\nd(X) :- table(X), k8s(X).\n".to_string(),
        }]);
        let color = &file_colors(&graph)["rules/t.mg"];
        let out = to_dot(&view(&graph, ViewOptions::default()).unwrap());
        assert!(
            out.contains(&format!(
                "\"table\" [shape=cylinder, fillcolor=\"{color}\"]"
            )),
            "{out}"
        );
        assert!(out.contains(&format!(
            "\"k8s\" [shape=cylinder, fillcolor=\"{SUPPLIED_AT_RUNTIME_COLOR}\"]"
        )));
        assert!(
            out.contains(&format!("\"d\" [fillcolor=\"{color}\"]")),
            "{out}"
        );
    }

    #[test]
    fn dot_file_boxes_are_opt_in() {
        // Boxing each file's predicates makes dot route edges around the
        // boxes, which bends and loops them; colors already show the file.
        let out = dot(ViewOptions::default());
        assert!(!out.contains("subgraph"), "{out}");
        let out = dot(ViewOptions {
            boxes: true,
            ..ViewOptions::default()
        });
        assert!(out.contains("subgraph \"cluster_rules/a.mg\""), "{out}");
        assert!(out.contains("label=\"a.mg\""));
    }

    #[test]
    fn dot_counts_are_external_labels() {
        // A plain edge label becomes a node in the layout that other edges
        // route around; xlabel is placed afterwards.
        let graph = RuleGraph::build(&[RuleSource {
            origin: "f.mg".to_string(),
            text: "a(X) :- b(X).\na(X) :- c(X), b(X).\n".to_string(),
        }]);
        let out = to_dot(&view(&graph, ViewOptions::default()).unwrap());
        assert!(out.contains("\"b\" -> \"a\" [xlabel=\"x2\""), "{out}");
    }

    #[test]
    fn dot_files_collapse() {
        let out = dot(ViewOptions {
            files: true,
            ..ViewOptions::default()
        });
        assert!(
            out.contains("\"rules/b.mg\" -> \"rules/a.mg\" [xlabel=\"2 uses\""),
            "{out}"
        );
        assert!(
            out.contains("\"supplied at runtime (EDB)\" -> \"rules/b.mg\""),
            "{out}"
        );
        assert!(!out.contains("\"a\""));
    }

    #[test]
    fn dot_negated_edge_style() {
        let out = dot(ViewOptions::default());
        let line = out
            .lines()
            .find(|line| line.contains("\"c\" -> \"a\""))
            .unwrap();
        assert!(
            line.contains("style=dashed, color=red, arrowhead=tee"),
            "{line}"
        );
    }

    #[test]
    fn dot_quotes_names() {
        assert_eq!(quote("a\"b"), "\"a\\\"b\"");
    }
}
