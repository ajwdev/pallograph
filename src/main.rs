#![feature(iter_intersperse)]

mod config;
mod edb;
mod engine;
mod load;
// mod op_printer;
mod query;
mod repl;
mod smt;
pub mod snapshot;
mod value;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use mangle_interpreter::MemStore;

use engine::{Backend, DdBackend, Engine, InterpreterBackend};
use repl::OutputFormat;

#[derive(clap::ValueEnum, Clone)]
enum BackendKind {
    Interpreter,
    Dd,
}

#[derive(Parser)]
struct Cli {
    /// Directory containing .mg rule files. Defaults to ./rules.
    #[arg(long, default_value = "rules")]
    rules: PathBuf,

    /// Path to a config file (overrides default search locations).
    #[arg(short = 'C')]
    config: Option<PathBuf>,

    /// Load facts from a fixture directory (overrides config file).
    #[arg(long)]
    fixtures: Option<PathBuf>,

    /// Select a named profile from the config file.
    #[arg(long)]
    profile: Option<String>,

    #[arg(long)]
    explain: bool,

    /// Run Z3 constraint check on policy violations after evaluation.
    #[arg(long)]
    smt: bool,

    #[arg(long, value_enum, default_value = "interpreter")]
    backend: BackendKind,

    /// Output format for query/relation results. `ndjson` emits one JSON object
    /// per row, suitable for piping into jq, DuckDB, etc.
    #[arg(long, value_enum, default_value = "plain")]
    format: OutputFormat,
}

async fn load_datasource(edb: &mut MemStore, name: &str, ds: &config::Datasource) -> Result<()> {
    use config::{ContentKind, SourceKind};
    match ds.source {
        SourceKind::K8s => {
            eprintln!("  {name}: cluster (live)");
            let client = kube::Client::try_default().await?;
            edb::load_from_cluster(edb, client).await?;
        }
        SourceKind::File => {
            let paths = ds.paths.as_ref()
                .with_context(|| format!("datasource '{name}': source=\"file\" requires paths"))?;
            let content = ds.content.as_ref()
                .with_context(|| format!("datasource '{name}': source=\"file\" requires content"))?;
            match content {
                ContentKind::K8sManifests => {
                    eprintln!("  {name}: file ({}) → k8s-manifests", paths.join(", "));
                    edb::load_from_manifests(edb, paths.clone())?;
                }
                ContentKind::JsonTuples => {
                    let relation = ds.relation.as_deref()
                        .with_context(|| format!("datasource '{name}': content=\"json-tuples\" requires a relation"))?;
                    for path in paths {
                        eprintln!("  {name}: file ({path}) → json-tuples:{relation}");
                        load::load_tuples_into_store(edb, relation, path)?;
                    }
                }
            }
        }
        SourceKind::Shell => {
            let command = ds.command.as_deref()
                .with_context(|| format!("datasource '{name}': source=\"shell\" requires a command"))?;
            let content = ds.content.as_ref()
                .with_context(|| format!("datasource '{name}': source=\"shell\" requires content"))?;
            match content {
                ContentKind::K8sManifests => {
                    eprintln!("  {name}: shell → k8s-manifests");
                    edb::load_k8s_from_command(edb, command)?;
                }
                ContentKind::JsonTuples => {
                    let relation = ds.relation.as_deref()
                        .with_context(|| format!("datasource '{name}': content=\"json-tuples\" requires a relation"))?;
                    eprintln!("  {name}: shell → json-tuples:{relation}");
                    load::load_tuples_into_store(edb, relation, &format!("! {command}"))?;
                }
            }
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load EDB facts into a staging MemStore.
    // Priority: --live / --fixtures flags (explicit overrides) > config file > testdata/ default.
    let mut edb = MemStore::new();
    if let Some(manifests_path) = &cli.fixtures {
        eprintln!("datasource: k8s-manifests ({})", manifests_path.display());
        edb::load_from_manifests(&mut edb, vec![manifests_path.to_string_lossy().into_owned()])?;
    } else {
        match config::load_config(cli.config.as_deref())? {
            Some(cfg) => {
                let profile_name = cli.profile
                    .as_deref()
                    .or(cfg.default_profile.as_deref())
                    .context("no --profile given and no default_profile in config")?;
                let profile = cfg.profiles.get(profile_name)
                    .with_context(|| format!("profile '{profile_name}' not found in config"))?;
                eprintln!("datasource: profile \"{profile_name}\"");
                for name in &profile.sources {
                    let ds = cfg.datasources.get(name.as_str())
                        .with_context(|| format!("datasource '{name}' not found in config"))?;
                    load_datasource(&mut edb, name, ds).await?;
                }
            }
            None => {
                eprintln!("datasource: k8s-manifests (testdata) [default]");
                edb::load_from_manifests(&mut edb, vec!["testdata".to_string()])?;
            }
        }
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

    let store = engine.evaluate()?;

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

    repl::run(&mut engine, store, cli.format)?;

    Ok(())
}
