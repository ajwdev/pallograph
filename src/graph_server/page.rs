// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Answers one request: the index, a view's page, dot or JSON. Pure apart
//! from running `dot`, so it is tested without sockets.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::Write as _;
use std::process::{Command, Stdio};

use serde::Serialize;

use crate::rule_graph::dot::{SUPPLIED_AT_RUNTIME_COLOR, file_colors};
use crate::rule_graph::view::percent_encode;
use crate::rule_graph::{
    Edge, Predicate, PredicateKind, RuleGraph, RuleSource, View, ViewOptions, to_dot, view,
};

const PAGE: &str = include_str!("assets/page.html");
const SCRIPT: &str = include_str!("assets/page.js");

/// Focused views offered on the index. Ones whose predicate no longer
/// exists are listed as missing.
const BOOKMARKS: &[(&str, &str)] = &[
    (
        "escalation: who can take over which identity",
        "focus=controls_identity",
    ),
    ("escalation hops", "focus=pivot"),
    ("RBAC writes", "focus=rbac_write"),
    ("access requests (rbac_allowed)", "focus=rbac_allowed"),
    ("direct permissions", "focus=direct_perm"),
    (
        "what uses direct permissions",
        "focus=direct_perm&down&users=2",
    ),
];

pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: String,
}

impl Response {
    fn html(status: u16, body: String) -> Response {
        Response {
            status,
            content_type: "text/html; charset=utf-8",
            body,
        }
    }

    fn text(status: u16, content_type: &'static str, body: String) -> Response {
        Response {
            status,
            content_type,
            body,
        }
    }

    fn message(status: u16, title: &str, message: &str) -> Response {
        Response::html(
            status,
            format!(
                "<!doctype html><meta charset=utf-8><title>{title}</title>\
                 <body style=\"font-family:sans-serif\"><p><a href=\"/\">index</a></p>\
                 <h2>{title}</h2><p>{}</p>",
                escape_html(message)
            ),
        )
    }
}

/// Answers a GET for `target` (path and query), building the graph from
/// `sources` and laying it out with `dot_command`.
pub fn handle(target: &str, sources: &[RuleSource], dot_command: &str) -> Response {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let graph = RuleGraph::build(sources);
    if path == "/" {
        return Response::html(200, index(&graph));
    }
    let format = match path {
        "/graph" => Format::Page,
        "/graph.dot" => Format::Dot,
        "/graph.json" => Format::Json,
        _ => return Response::message(404, "Not found", &format!("no page at {path}")),
    };
    let options = ViewOptions::from_query(query);
    let view = match view(&graph, options) {
        Ok(view) => view,
        Err(message) => return Response::message(404, "No such predicate", &message),
    };
    match format {
        Format::Dot => Response::text(200, "text/plain; charset=utf-8", to_dot(&view)),
        Format::Json => Response::text(200, "application/json", view_json(&view)),
        Format::Page => match render_svg(&to_dot(&view), dot_command) {
            Ok(svg) => Response::html(200, page(&view, &svg)),
            Err(message) => Response::message(500, "Graphviz failed", &message),
        },
    }
}

enum Format {
    Page,
    Dot,
    Json,
}

#[derive(Serialize)]
struct ViewJson<'g> {
    predicates: BTreeMap<&'g str, &'g Predicate>,
    edges: &'g [&'g Edge],
}

fn view_json(view: &View) -> String {
    let predicates = view
        .nodes
        .iter()
        .filter_map(|name| {
            let predicate = view.graph.predicates.get(name)?;
            Some((name.as_str(), predicate))
        })
        .collect();
    let json = ViewJson {
        predicates,
        edges: &view.edges,
    };
    serde_json::to_string_pretty(&json).expect("serialize view")
}

/// Runs `dot -Tsvg` on `dot_text`.
pub fn render_svg(dot_text: &str, dot_command: &str) -> Result<String, String> {
    let not_found = |error: std::io::Error| {
        format!(
            "could not run Graphviz '{dot_command}' ({error}). Install Graphviz (it is in \
             the Nix dev shell); /graph.dot and /graph.json still work without it."
        )
    };
    let mut child = Command::new(dot_command)
        .arg("-Tsvg")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(not_found)?;
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(dot_text.as_bytes())
        .map_err(not_found)?;
    let output = child.wait_with_output().map_err(not_found)?;
    if !output.status.success() {
        return Err(format!(
            "Graphviz '{dot_command}' failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let svg = String::from_utf8_lossy(&output.stdout);
    // Drop the XML prologue and doctype; the page embeds the <svg> element.
    Ok(svg
        .find("<svg")
        .map_or(svg.as_ref(), |start| &svg[start..])
        .to_string())
}

fn page(view: &View, svg: &str) -> String {
    let options = &view.options;
    let title = match &options.focus {
        Some(focus) => format!("rule graph: {focus}"),
        None if options.files => "rule graph: files".to_string(),
        None => "rule graph: everything".to_string(),
    };
    let flipped = ViewOptions {
        topdown: !options.topdown,
        ..options.clone()
    };
    let toggled_boxes = ViewOptions {
        boxes: !options.boxes,
        ..options.clone()
    };
    let direction = format!(
        "{} (<a href=\"/graph?{}\">flip</a>) &middot; <a href=\"/graph?{}\">{}</a>",
        if options.topdown {
            "arrows: rule head &rarr; what it depends on"
        } else {
            "arrows: data flowing down from what is supplied at runtime (EDB)"
        },
        escape_html(&flipped.to_query()),
        escape_html(&toggled_boxes.to_query()),
        if options.boxes {
            "hide file boxes"
        } else {
            "box by file"
        }
    );
    page_template(&[
        ("TITLE", &escape_html(&title)),
        ("DIRECTION", &direction),
        ("CONTROLS", &controls(options)),
        ("SVG", svg),
        ("RULES_JSON", &rules_json(view.graph)),
        ("TOPDOWN", if options.topdown { "true" } else { "false" }),
        ("LEGEND", &legend(view)),
        ("ORIGINS_JSON", &origins_json(view)),
        ("SCRIPT", SCRIPT),
    ])
}

/// The file each drawn predicate comes from, for the page's legend
/// highlighting; empty for predicates supplied at runtime.
fn file_of<'g>(view: &'g View, name: &str) -> &'g str {
    match view.graph.predicates.get(name) {
        Some(predicate) if predicate.kind != PredicateKind::SuppliedAtRuntime => {
            predicate.origin.as_deref().unwrap_or("")
        }
        _ => "",
    }
}

/// Colors for the files drawn in this view, then grey for facts loaded from
/// the cluster if any are drawn.
fn legend(view: &View) -> String {
    let colors = file_colors(view.graph);
    let files: BTreeSet<&str> = view.nodes.iter().map(|name| file_of(view, name)).collect();
    let item = |origin: &str, color: &str, label: &str| {
        format!(
            "<span class=\"legend-item\" data-origin=\"{}\"><span class=\"swatch\" \
             style=\"background:{color}\"></span>{}</span>",
            escape_html(origin),
            escape_html(label)
        )
    };
    // Collapsed by default; the page remembers if the viewer opens it.
    let file_count = files.iter().filter(|file| !file.is_empty()).count();
    let mut out = format!(
        "<details class=\"legend\"><summary>colors: {file_count} file{}</summary>",
        if file_count == 1 { "" } else { "s" }
    );
    for file in files.iter().filter(|file| !file.is_empty()) {
        let color = colors
            .get(*file)
            .map_or(SUPPLIED_AT_RUNTIME_COLOR, String::as_str);
        out.push_str(&item(file, color, file));
    }
    if files.contains("") {
        out.push_str(&item(
            "",
            SUPPLIED_AT_RUNTIME_COLOR,
            "supplied at runtime (EDB)",
        ));
    }
    out.push_str("</details>");
    out
}

fn origins_json(view: &View) -> String {
    let map: BTreeMap<&str, &str> = view
        .nodes
        .iter()
        .map(|name| (name.as_str(), file_of(view, name)))
        .collect();
    serde_json::to_string(&map)
        .expect("serialize origins")
        .replace("</", "<\\/")
}

/// Fills `{{NAME}}` markers in the page in one pass, so a value that
/// happens to contain a marker is left alone.
fn page_template(values: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(PAGE.len());
    let mut rest = PAGE;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find("}}").map(|end| (&after[..end], end)) {
            Some((name, end)) if values.iter().any(|(key, _)| *key == name) => {
                let value = values.iter().find(|(key, _)| *key == name).unwrap().1;
                out.push_str(value);
                rest = &after[end + 2..];
            }
            _ => {
                out.push_str("{{");
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Links that change the focused view's depth and direction.
fn controls(options: &ViewOptions) -> String {
    let Some(focus) = &options.focus else {
        return String::new();
    };
    let link = |label: &str, change: &dyn Fn(&mut ViewOptions)| {
        let mut changed = options.clone();
        change(&mut changed);
        format!(
            "<a href=\"/graph?{}\">{label}</a>",
            escape_html(&changed.to_query())
        )
    };
    let mut out = format!(
        "<div class=\"controls\">focused on <b>{}</b> &middot; ",
        escape_html(focus)
    );
    let hops = |count: usize| format!("{count} hop{}", if count == 1 { "" } else { "s" });
    // `down` shows only what uses the focus, so only the users count applies.
    if !options.down {
        write!(
            out,
            "depends on: {} {} {} &middot; ",
            hops(options.depth),
            link("&minus;", &|options| options.depth =
                options.depth.saturating_sub(1)),
            link("+", &|options| options.depth += 1)
        )
        .unwrap();
    }
    write!(
        out,
        "used by: {} {} {}",
        hops(options.users),
        link("&minus;", &|options| options.users =
            options.users.saturating_sub(1)),
        link("+", &|options| options.users += 1)
    )
    .unwrap();
    let toggle = if options.down {
        "both ways"
    } else {
        "users only"
    };
    write!(
        out,
        " &middot; {} &middot; {}</div>",
        link(toggle, &|options| options.down = !options.down),
        link("whole graph", &|options| options.focus = None)
    )
    .unwrap();
    out
}

/// Statements for every predicate, so the panel can show rules for
/// predicates outside the drawn view too.
fn rules_json(graph: &RuleGraph) -> String {
    #[derive(Serialize)]
    struct StatementJson<'g> {
        loc: &'g str,
        text: &'g str,
    }
    let map: BTreeMap<&str, Vec<StatementJson>> = graph
        .predicates
        .iter()
        .map(|(name, predicate)| {
            let statements = predicate
                .statements
                .iter()
                .map(|statement| StatementJson {
                    loc: &statement.location,
                    text: &statement.text,
                })
                .collect();
            (name.as_str(), statements)
        })
        .collect();
    // `</` would end the <script> element early.
    serde_json::to_string(&map)
        .expect("serialize rules")
        .replace("</", "<\\/")
}

fn index(graph: &RuleGraph) -> String {
    let mut out = String::from(
        "<!doctype html><meta charset=utf-8><title>rule graph</title>\
         <body style=\"font-family:sans-serif; max-width: 60em; margin: 1em auto; padding: 0 16px\">\
         <h2>Rule graph</h2><p>Pick a starting point, then double-click a predicate \
         (or use <i>focus here</i> in the rules panel) to walk from it.</p><h3>Bookmarks</h3><ul>",
    );
    out.push_str(
        "<li><a href=\"/graph?files\">overview: how the rule files depend on each other</a></li>",
    );
    out.push_str("<li><a href=\"/graph\">everything</a> (large)</li>");
    for (label, query) in BOOKMARKS {
        let focus = ViewOptions::from_query(query).focus.unwrap_or_default();
        if graph.predicates.contains_key(&focus) {
            write!(out, "<li><a href=\"/graph?{query}\">{label}</a></li>").unwrap();
        } else {
            write!(
                out,
                "<li>{label}: <i>missing, no predicate named {focus}</i></li>"
            )
            .unwrap();
        }
    }
    out.push_str("</ul>");
    if !graph.unparsed.is_empty() {
        out.push_str(
            "<h3>Statements that could not be parsed</h3>\
             <p>These are left out of the graph.</p>",
        );
        for statement in &graph.unparsed {
            write!(
                out,
                "<p><code>{}</code></p><pre>{}</pre>",
                escape_html(&statement.location),
                escape_html(&statement.text)
            )
            .unwrap();
        }
    }
    out.push_str("<h3>All predicates</h3>");

    let mut by_origin: BTreeMap<&str, Vec<&Predicate>> = BTreeMap::new();
    for predicate in graph.predicates.values() {
        let group = match (predicate.kind, &predicate.origin) {
            (PredicateKind::SuppliedAtRuntime, _) | (_, None) => "supplied at runtime (EDB)",
            (_, Some(origin)) => origin.as_str(),
        };
        by_origin.entry(group).or_default().push(predicate);
    }
    for (origin, predicates) in by_origin {
        write!(
            out,
            "<h4>{}</h4><p style=\"line-height:1.7\">",
            escape_html(origin)
        )
        .unwrap();
        let links: Vec<String> = predicates
            .iter()
            .map(|predicate| {
                format!(
                    "<a href=\"/graph?focus={}\"><code>{}</code></a>",
                    percent_encode(&predicate.name),
                    escape_html(&predicate.name)
                )
            })
            .collect();
        out.push_str(&links.join(" &middot; "));
        out.push_str("</p>");
    }
    out
}

pub fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sources() -> Vec<RuleSource> {
        vec![
            RuleSource {
                origin: "rules/a.mg".to_string(),
                text: "a(X) :- b(X).\nb(X) :- k8s(X).\n".to_string(),
            },
            RuleSource {
                origin: "session #1".to_string(),
                text: "s(X) :- a(X).".to_string(),
            },
        ]
    }

    fn get(target: &str) -> Response {
        handle(target, &sources(), "/nonexistent/dot")
    }

    #[test]
    fn json_endpoint_lists_edges() {
        let response = get("/graph.json");
        assert_eq!(response.status, 200);
        let json: serde_json::Value = serde_json::from_str(&response.body).unwrap();
        let edges = json["edges"].as_array().unwrap();
        assert!(
            edges
                .iter()
                .any(|edge| edge["head"] == "a" && edge["body"] == "b")
        );
        assert_eq!(json["predicates"]["s"]["origin"], "session #1");
    }

    #[test]
    fn dot_endpoint_respects_direction() {
        let response = get("/graph.dot?focus=a");
        assert_eq!(response.status, 200);
        assert!(response.body.contains("mangle_flow"), "{}", response.body);
        // Old links that still say `flow` get the default.
        assert!(get("/graph.dot?flow&focus=a").body.contains("mangle_flow"));
        let response = get("/graph.dot?topdown&focus=a");
        assert!(
            response.body.contains("mangle_topdown"),
            "{}",
            response.body
        );
    }

    #[test]
    fn unknown_focus_is_404() {
        let response = get("/graph?focus=nope");
        assert_eq!(response.status, 404);
        assert!(response.body.contains("nope"));
    }

    #[test]
    fn unknown_path_is_404() {
        assert_eq!(get("/favicon.ico").status, 404);
    }

    #[test]
    fn missing_dot_is_500_naming_graphviz() {
        let response = get("/graph?focus=a");
        assert_eq!(response.status, 500);
        assert!(response.body.contains("Graphviz"), "{}", response.body);
    }

    #[test]
    fn page_has_legend_and_help() {
        let graph = RuleGraph::build(&sources());
        let options = ViewOptions::from_query("focus=b");
        let view = view(&graph, options).unwrap();
        let html = page(&view, "<svg/>");
        let colors = crate::rule_graph::dot::file_colors(&graph);

        // The legend lists the files drawn in this view, with their colors.
        // Collapsed by default, with a one-line summary.
        assert!(html.contains("<details class=\"legend\">"), "{html}");
        assert!(html.contains("<summary>colors: 1 file"), "{html}");
        assert!(html.contains("data-origin=\"rules/a.mg\""), "{html}");
        assert!(html.contains(&colors["rules/a.mg"]), "{html}");
        assert!(html.contains("supplied at runtime (EDB)"), "{html}");
        // `s` (session #1) is two hops from `b`, so not drawn or listed.
        assert!(!html.contains("data-origin=\"session #1\""), "{html}");

        // The help explains how to read the drawing.
        assert!(html.contains("id=\"help\""), "{html}");
        for topic in ["Negation", "xN", "Thicker", "Recursion", "Double-click"] {
            assert!(html.contains(topic), "help is missing {topic}");
        }
    }

    #[test]
    fn index_lists_unparsed_statements() {
        let sources = [RuleSource {
            origin: "rules/bad.mg".to_string(),
            text: "a(X) :- b(X.\n".to_string(),
        }];
        let response = handle("/", &sources, "dot");
        assert!(
            response.body.contains("could not be parsed"),
            "{}",
            response.body
        );
        assert!(response.body.contains("rules/bad.mg:1"));
    }

    #[test]
    fn index_marks_missing_bookmarks() {
        let response = get("/");
        assert_eq!(response.status, 200);
        assert!(
            response
                .body
                .contains("no predicate named controls_identity")
        );
        assert!(response.body.contains("href=\"/graph?focus=a\""));
        assert!(!response.body.contains("hide="), "{}", response.body);
    }

    #[test]
    fn template_leaves_markers_in_values_alone() {
        let page = page_template(&[("TITLE", "{{SVG}}"), ("SVG", "<svg/>")]);
        assert!(page.contains("<title>{{SVG}}</title>"));
        assert!(page.contains("<div id=\"graph\"><svg/></div>"));
    }

    #[test]
    fn rules_json_escapes_script_end() {
        let graph = RuleGraph::build(&[RuleSource {
            origin: "f.mg".to_string(),
            text: "# </script>\na(X) :- b(X).\n".to_string(),
        }]);
        assert!(!rules_json(&graph).contains("</script>"));
    }
}
