#![feature(iter_intersperse)]

mod edb;
mod engine;
mod handlers;
mod load;
// mod op_printer;
mod query;
mod repl;
mod smt;
pub mod snapshot;
mod value;

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use mangle_interpreter::MemStore;

use engine::{Backend, DdBackend, Engine, InterpreterBackend};
use handlers::{DryRunCollector, Handler, LogHandler, Violation};

#[derive(clap::ValueEnum, Clone)]
enum BackendKind {
    Interpreter,
    Dd,
}

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

    /// Load facts from the live Kubernetes cluster (uses KUBECONFIG / in-cluster auth).
    #[arg(long)]
    live: bool,

    #[arg(long)]
    explain: bool,

    /// Run Z3 constraint check on policy violations after evaluation.
    #[arg(long)]
    smt: bool,

    #[arg(long, value_enum, default_value = "interpreter")]
    backend: BackendKind,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load EDB facts into a staging MemStore.
    let mut edb = MemStore::new();
    if cli.live {
        let client = kube::Client::try_default().await?;
        edb::load_from_cluster(&mut edb, client).await?;
    } else {
        edb::load_all(&mut edb, &cli.fixtures)?;
    }

    let backend: Box<dyn Backend> = match cli.backend {
        BackendKind::Interpreter => Box::new(InterpreterBackend),
        BackendKind::Dd => Box::new(DdBackend),
    };

    // Build the policy engine.
    let mut engine = Engine::new(edb, &cli.rules, backend)?;
    if cli.explain {
        let mut cp = engine.compile()?;
        return cp.dump_plan();
    }

    println!("=== Evaluating policies ===");
    let store = engine.evaluate()?;

    // Mirror the Go POC's default policy predicate set.
    // Additional predicates (sa_is_cluster_admin, role_has_wildcard_verb, etc.)
    // are available via --repl.
    let policy_predicates = ["orphaned_sa", "host_network_pod", "privileged_pod"];

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

    if cli.smt {
        let cfg = z3::Config::new();
        let ctx = z3::Context::new(&cfg);
        let mut enc = smt::SmtEncoder::new(&ctx);

        enc.assert_rbac_axioms(&store);

        // Each entry: (namespace, resource, verb, expected_principals)
        // namespace="" checks cluster-wide (CRB) grants only.
        let checks: &[(&str, &str, &str, &[&str])] = &[
            ("", "pods", "delete", &["admin@example.com", "developer@example.com"]),
            ("", "pods", "get",    &["admin@example.com", "developer@example.com"]),
        ];

        println!("\n=== Z3 access invariant checks ===");
        for (namespace, resource, verb, expected) in checks {
            let violations = enc.check_access_invariant(namespace, resource, verb, expected);
            if violations.is_empty() {
                println!("PASS  can(_, {namespace:?}, {resource:?}, {verb:?})");
            } else {
                println!("FAIL  can(_, {namespace:?}, {resource:?}, {verb:?}) — {} unexpected principal(s):", violations.len());
                for v in &violations {
                    println!("        UNEXPECTED can({:?}, {:?}, {:?}, {:?})", v.principal, v.namespace, v.resource, v.verb);
                }
            }
        }
    }

    if cli.repl {
        repl::run(&mut engine, store)?;
    }

    Ok(())
}
