mod edb;
mod engine;
mod handlers;
mod query;
mod repl;
mod value;

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use mangle_interpreter::MemStore;

use engine::Engine;
use handlers::{DryRunCollector, Handler, LogHandler, Violation};

#[derive(Parser)]
struct Cli {
    /// Start the interactive query REPL after evaluation.
    #[arg(long)]
    repl: bool,

    /// Directory containing .mg rule files. Defaults to ./rules.
    #[arg(long, default_value = "rules")]
    rules: PathBuf,

    /// Directory containing fixture JSON files. Defaults to ./testdata.
    #[arg(long, default_value = "testdata")]
    fixtures: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load EDB facts into a staging MemStore.
    let mut edb = MemStore::new();
    edb::load_all(&mut edb, &cli.fixtures)?;

    // Build the policy engine.
    let mut engine = Engine::new(edb, &cli.rules)?;

    println!("=== Evaluating policies ===");
    let store = engine.evaluate()?;

    // Mirror the Go POC's default policy predicate set.
    // Additional predicates (sa_is_cluster_admin, role_has_wildcard_verb, etc.)
    // are available via --repl.
    let policy_predicates = [
        "orphaned_sa",
        "host_network_pod",
        "privileged_pod",
    ];

    let mut log_handler = LogHandler;
    let mut dry_run = DryRunCollector::new();

    for pred in &policy_predicates {
        for tuple in store.scan(pred) {
            let v = Violation {
                policy: pred.to_string(),
                args: tuple.clone(),
            };
            log_handler.handle(&v);
            dry_run.handle(&v);
        }
    }

    dry_run.print_summary();

    if cli.repl {
        repl::run(&mut engine, store)?;
    }

    Ok(())
}
