// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Serves the rule graph (`crate::rule_graph`) as interactive pages over
//! HTTP, for the `graph` REPL command. One server per process, started on
//! first use and running until the process exits. Each request rebuilds the
//! graph from the engine's current rule sources, so rules added with
//! `define` show up without a restart.

pub mod http;
pub mod page;

use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};

use crate::engine::Engine;
use crate::rule_graph::{RuleGraph, RuleSource, SESSION_ORIGIN_PREFIX};

/// Where the server listens unless `--graph-addr` says otherwise.
pub const DEFAULT_ADDRESS: &str = "127.0.0.1:7474";

pub struct GraphServerConfig {
    pub address: SocketAddr,
    pub engine: Arc<Mutex<Engine>>,
    /// The rule files loaded at startup, with their paths, so the engine's
    /// unlabeled sources can be matched back to them.
    pub startup_sources: Vec<RuleSource>,
    /// The Graphviz program, normally `dot`.
    pub dot_command: String,
}

/// Rule sources with their origins, read fresh for every request.
type SourceProvider = Arc<dyn Fn() -> Vec<RuleSource> + Send + Sync>;

struct State {
    config: Option<GraphServerConfig>,
    running: Option<SocketAddr>,
}

static STATE: Mutex<State> = Mutex::new(State {
    config: None,
    running: None,
});

/// Sets what [`ensure_started`] serves. Called once at startup.
pub fn configure(config: GraphServerConfig) {
    STATE.lock().expect("graph server state").config = Some(config);
}

/// Starts the server if it isn't running and returns its address. A failed
/// bind is returned as an error, and the next call tries again.
pub fn ensure_started() -> Result<SocketAddr> {
    let mut state = STATE.lock().expect("graph server state");
    if let Some(address) = state.running {
        return Ok(address);
    }
    let config = state
        .config
        .as_ref()
        .context("the graph server is not configured")?;
    let listener = TcpListener::bind(config.address)
        .with_context(|| format!("listening on {}", config.address))?;
    let address = serve(listener, provider(config), config.dot_command.clone())?;
    state.running = Some(address);
    Ok(address)
}

/// The graph of the engine's current rules, for checking a predicate name
/// before printing a URL for it.
pub fn current_graph() -> Result<RuleGraph> {
    let state = STATE.lock().expect("graph server state");
    let config = state
        .config
        .as_ref()
        .context("the graph server is not configured")?;
    Ok(RuleGraph::build(&provider(config)()))
}

/// Whether the configured Graphviz program runs.
pub fn dot_available() -> bool {
    let state = STATE.lock().expect("graph server state");
    let command = state
        .config
        .as_ref()
        .map_or("dot", |config| config.dot_command.as_str());
    std::process::Command::new(command)
        .arg("-V")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn provider(config: &GraphServerConfig) -> SourceProvider {
    let engine = Arc::clone(&config.engine);
    let startup = config.startup_sources.clone();
    Arc::new(move || {
        let current = engine.lock().expect("engine lock").rule_sources().to_vec();
        labeled_sources(&current, &startup)
    })
}

/// Accepts connections on `listener` in a background thread, one thread
/// per connection.
fn serve(
    listener: TcpListener,
    sources: SourceProvider,
    dot_command: String,
) -> Result<SocketAddr> {
    let address = listener.local_addr()?;
    std::thread::Builder::new()
        .name("graph-server".to_string())
        .spawn(move || {
            for stream in listener.incoming().flatten() {
                let sources = Arc::clone(&sources);
                let dot_command = dot_command.clone();
                std::thread::spawn(move || {
                    http::serve_connection(stream, &|target| {
                        page::handle(target, &sources(), &dot_command)
                    })
                });
            }
        })?;
    Ok(address)
}

/// Labels the engine's rule sources: one equal to a startup source takes
/// its path, and the rest are `session #N` in order. Matching by text keeps
/// labels right after `rollback` swaps the sources out.
pub fn labeled_sources(current: &[String], startup: &[RuleSource]) -> Vec<RuleSource> {
    let mut session = 0;
    current
        .iter()
        .map(|text| {
            let origin = match startup.iter().find(|source| source.text == *text) {
                Some(source) => source.origin.clone(),
                None => {
                    session += 1;
                    format!("{SESSION_ORIGIN_PREFIX}{session}")
                }
            };
            RuleSource {
                origin,
                text: text.clone(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    use super::*;

    fn source(origin: &str, text: &str) -> RuleSource {
        RuleSource {
            origin: origin.to_string(),
            text: text.to_string(),
        }
    }

    #[test]
    fn labels_startup_and_session_sources() {
        let startup = [
            source("rules/a.mg", "a(X) :- b(X)."),
            source("rules/b.mg", "b(X) :- c(X)."),
        ];
        let current = ["a(X) :- b(X).", "b(X) :- c(X).", "d(X) :- a(X)."].map(String::from);
        let origins: Vec<String> = labeled_sources(&current, &startup)
            .into_iter()
            .map(|source| source.origin)
            .collect();
        assert_eq!(origins, ["rules/a.mg", "rules/b.mg", "session #1"]);
    }

    fn request(address: SocketAddr, request: &str) -> String {
        let mut stream = TcpStream::connect(address).unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }

    #[test]
    fn server_serves_over_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let sources: SourceProvider = Arc::new(|| vec![source("f.mg", "a(X) :- b(X).\n")]);
        let address = serve(listener, sources, "/nonexistent/dot".to_string()).unwrap();

        let response = request(address, "GET /graph.json HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(response.contains("\"head\": \"a\""), "{response}");
        // Pages are rebuilt from the engine's current rules on every request,
        // so the browser must not keep a copy.
        assert!(
            response.contains("\r\nCache-Control: no-store\r\n"),
            "{response}"
        );

        let response = request(address, "POST / HTTP/1.1\r\n\r\n");
        assert!(response.starts_with("HTTP/1.1 405"), "{response}");
        assert!(
            response.contains("\r\nCache-Control: no-store\r\n"),
            "{response}"
        );
        let response = request(address, "garbage\r\n\r\n");
        assert!(response.starts_with("HTTP/1.1 400"), "{response}");

        let response = request(address, "GET /graph.dot?focus=a HTTP/1.1\r\n\r\n");
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    }
}
