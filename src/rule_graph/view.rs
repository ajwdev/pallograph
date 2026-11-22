// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A view is a slice of the [`RuleGraph`], picked by URL query parameters:
//! the neighborhood of one predicate, or the whole graph.

use std::collections::{BTreeSet, VecDeque};

use super::model::{Edge, RuleGraph};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewOptions {
    /// Center on this predicate. None shows the whole graph.
    pub focus: Option<String>,
    /// With a focus: hops to walk toward what it depends on.
    pub depth: usize,
    /// With a focus: hops to walk toward what uses it.
    pub users: usize,
    /// With a focus: walk only toward users, `users` hops.
    pub down: bool,
    /// Shown, but not walked past.
    pub stop: Vec<String>,
    /// Dropped entirely, e.g. `k8s`.
    pub hide: Vec<String>,
    /// Collapse to one node per source file.
    pub files: bool,
    /// Draw a dashed box around each file's predicates. Off by default:
    /// dot routes edges around the boxes, which bends and loops them.
    pub boxes: bool,
    /// Arrows head -> body, like a pprof call graph, instead of the
    /// default body -> head (data flowing from the facts loaded from the
    /// cluster down to what is derived from them).
    pub topdown: bool,
}

impl Default for ViewOptions {
    fn default() -> Self {
        ViewOptions {
            focus: None,
            depth: 2,
            users: 1,
            down: false,
            stop: Vec::new(),
            hide: Vec::new(),
            files: false,
            boxes: false,
            topdown: false,
        }
    }
}

impl ViewOptions {
    /// Parses `focus=a&depth=3&down&hide=k8s,x`. Unknown keys and bad
    /// numbers are ignored.
    pub fn from_query(query: &str) -> ViewOptions {
        let mut options = ViewOptions::default();
        let list = |value: &str| -> Vec<String> {
            value
                .split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_string)
                .collect()
        };
        for pair in query.split('&').filter(|pair| !pair.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let value = percent_decode(value);
            match key {
                "focus" if !value.is_empty() => options.focus = Some(value),
                "depth" => options.depth = value.parse().unwrap_or(options.depth),
                "users" => options.users = value.parse().unwrap_or(options.users),
                "down" => options.down = true,
                "stop" => options.stop = list(&value),
                "hide" => options.hide = list(&value),
                "files" => options.files = true,
                "boxes" => options.boxes = true,
                "topdown" => options.topdown = true,
                // The old name for what is now the default.
                "flow" => {}
                _ => {}
            }
        }
        options
    }
}

impl ViewOptions {
    /// The inverse of [`Self::from_query`], leaving out defaults.
    pub fn to_query(&self) -> String {
        let defaults = ViewOptions::default();
        let mut pairs = Vec::new();
        if let Some(focus) = &self.focus {
            pairs.push(format!("focus={}", percent_encode(focus)));
        }
        if self.depth != defaults.depth {
            pairs.push(format!("depth={}", self.depth));
        }
        if self.users != defaults.users {
            pairs.push(format!("users={}", self.users));
        }
        for (flag, set) in [
            ("down", self.down),
            ("files", self.files),
            ("boxes", self.boxes),
            ("topdown", self.topdown),
        ] {
            if set {
                pairs.push(flag.to_string());
            }
        }
        for (key, list) in [("stop", &self.stop), ("hide", &self.hide)] {
            if !list.is_empty() {
                pairs.push(format!("{key}={}", percent_encode(&list.join(","))));
            }
        }
        pairs.join("&")
    }
}

/// Encodes everything but unreserved characters and `,` as `%XX`.
pub fn percent_encode(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~,".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Decodes `%XX` escapes and `+` as space. Invalid escapes are kept as-is.
pub fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => out.push(b' '),
            b'%' => {
                let hex = text.get(index + 1..index + 3);
                match hex.and_then(|hex| u8::from_str_radix(hex, 16).ok()) {
                    Some(byte) => {
                        out.push(byte);
                        index += 2;
                    }
                    None => out.push(b'%'),
                }
            }
            byte => out.push(byte),
        }
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub struct View<'g> {
    pub graph: &'g RuleGraph,
    pub options: ViewOptions,
    pub edges: Vec<&'g Edge>,
    pub nodes: BTreeSet<String>,
}

pub fn view(graph: &RuleGraph, options: ViewOptions) -> Result<View<'_>, String> {
    // Focusing a hidden predicate (`focus=k8s&hide=k8s`) means looking at
    // it, so the focus is never hidden.
    let hidden = |name: &str| {
        options.focus.as_deref() != Some(name) && options.hide.iter().any(|hide| hide == name)
    };
    let visible: Vec<&Edge> = graph
        .edges
        .iter()
        .filter(|edge| !hidden(&edge.head) && !hidden(&edge.body))
        .collect();

    let nodes: BTreeSet<String> = match &options.focus {
        None => graph
            .predicates
            .keys()
            .filter(|name| !hidden(name))
            .cloned()
            .collect(),
        Some(focus) => {
            if !graph.predicates.contains_key(focus) {
                return Err(format!("no predicate named {focus}"));
            }
            let (dependency_hops, user_hops) = if options.down {
                (0, options.users)
            } else {
                (options.depth, options.users)
            };
            let mut nodes = walk(&visible, focus, dependency_hops, &options.stop, |edge| {
                (&edge.head, &edge.body)
            });
            nodes.extend(walk(&visible, focus, user_hops, &options.stop, |edge| {
                (&edge.body, &edge.head)
            }));
            nodes
        }
    };

    let edges = visible
        .into_iter()
        .filter(|edge| nodes.contains(&edge.head) && nodes.contains(&edge.body))
        .collect();
    Ok(View {
        graph,
        options,
        edges,
        nodes,
    })
}

/// Breadth-first walk from `start` up to `hops` steps, following edges
/// `from -> to` as given by `direction`. Stop predicates are kept but not
/// expanded (the start always is).
fn walk<'g>(
    edges: &[&'g Edge],
    start: &str,
    hops: usize,
    stop: &[String],
    direction: impl Fn(&'g Edge) -> (&'g String, &'g String),
) -> BTreeSet<String> {
    let mut seen = BTreeSet::from([start.to_string()]);
    let mut queue = VecDeque::from([(start.to_string(), 0)]);
    while let Some((name, distance)) = queue.pop_front() {
        if distance == hops || (name != start && stop.contains(&name)) {
            continue;
        }
        for edge in edges {
            let (from, to) = direction(edge);
            if *from == name && seen.insert(to.clone()) {
                queue.push_back((to.clone(), distance + 1));
            }
        }
    }
    seen
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule_graph::RuleSource;

    fn graph(text: &str) -> RuleGraph {
        RuleGraph::build(&[RuleSource {
            origin: "f.mg".to_string(),
            text: text.to_string(),
        }])
    }

    fn names<'a>(view: &'a View<'a>) -> Vec<&'a str> {
        view.nodes.iter().map(String::as_str).collect()
    }

    fn focused(focus: &str) -> ViewOptions {
        ViewOptions {
            focus: Some(focus.to_string()),
            ..ViewOptions::default()
        }
    }

    const CHAIN: &str = "x(X) :- a(X).\na(X) :- b(X).\nb(X) :- c(X).\nc(X) :- d(X).\n";

    #[test]
    fn focus_depth_limits_dependencies() {
        let graph = graph(CHAIN);
        let options = ViewOptions {
            users: 0,
            ..focused("a")
        };
        let view = view(&graph, options).unwrap();
        assert_eq!(names(&view), ["a", "b", "c"]);
        assert_eq!(view.edges.len(), 2);
    }

    #[test]
    fn focus_includes_users() {
        let graph = graph(CHAIN);
        let options = ViewOptions {
            depth: 0,
            ..focused("a")
        };
        assert_eq!(names(&view(&graph, options).unwrap()), ["a", "x"]);
    }

    #[test]
    fn down_walks_users_only() {
        let graph = graph(CHAIN);
        // `down` walks only toward users, as far as `users` says; `depth`
        // (toward dependencies) does not apply.
        let options = ViewOptions {
            down: true,
            users: 2,
            depth: 5,
            ..focused("c")
        };
        assert_eq!(names(&view(&graph, options).unwrap()), ["a", "b", "c"]);
    }

    #[test]
    fn stop_not_walked_past() {
        let graph = graph(CHAIN);
        let options = ViewOptions {
            depth: 10,
            users: 0,
            stop: vec!["b".to_string()],
            ..focused("a")
        };
        assert_eq!(names(&view(&graph, options).unwrap()), ["a", "b"]);
    }

    #[test]
    fn hide_drops_predicate() {
        let graph = graph(CHAIN);
        let options = ViewOptions {
            hide: vec!["b".to_string()],
            ..ViewOptions::default()
        };
        let view = view(&graph, options).unwrap();
        assert!(!view.nodes.contains("b"));
        assert!(
            view.edges
                .iter()
                .all(|edge| edge.head != "b" && edge.body != "b")
        );
    }

    #[test]
    fn unknown_focus_is_error() {
        let graph = graph(CHAIN);
        let error = view(&graph, focused("nope")).err().unwrap();
        assert!(error.contains("nope"), "{error}");
    }

    #[test]
    fn query_parsing() {
        let options = ViewOptions::from_query("focus=a%5Fb&depth=3&down&hide=k8s,x&users=zz");
        assert_eq!(options.focus.as_deref(), Some("a_b"));
        assert_eq!(options.depth, 3);
        assert_eq!(options.users, 1);
        assert!(options.down);
        assert_eq!(options.hide, ["k8s", "x"]);
        assert!(!options.topdown);
        assert_eq!(percent_decode("100%"), "100%");
    }

    #[test]
    fn query_round_trip() {
        let options = ViewOptions {
            focus: Some("a b".to_string()),
            depth: 4,
            down: true,
            hide: vec!["k8s".to_string(), "x".to_string()],
            ..ViewOptions::default()
        };
        assert_eq!(options.to_query(), "focus=a%20b&depth=4&down&hide=k8s,x");
        assert_eq!(ViewOptions::from_query(&options.to_query()), options);
        assert_eq!(ViewOptions::default().to_query(), "");
    }

    #[test]
    fn focus_overrides_hide() {
        let graph = graph(CHAIN);
        let options = ViewOptions {
            hide: vec!["b".to_string()],
            ..focused("b")
        };
        assert_eq!(names(&view(&graph, options).unwrap()), ["a", "b", "c", "d"]);
    }
}
