// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use clap::Parser;
use mangle_interpreter::MemStore;

use pallograph::engine::{self, Backend, DdBackend, Engine, InterpreterBackend};
use pallograph::repl::OutputFormat;
use pallograph::{config, edb, load, repl, watch};

#[derive(clap::ValueEnum, Clone, PartialEq)]
enum BackendKind {
    Interpreter,
    Dd,
}

#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Extra rules to load on top of the built-in ones: a .mg file, or a
    /// directory of them. Repeatable.
    #[arg(long, value_name = "PATH")]
    rules: Vec<PathBuf>,

    /// Directory of .mg files that replaces the rules embedded at build
    /// time. For development, so rule edits take effect without a rebuild.
    #[arg(long, hide = true, value_name = "DIR")]
    builtin_rules: Option<PathBuf>,

    /// Path to a config file (overrides default search locations).
    #[arg(short = 'C')]
    config: Option<PathBuf>,

    /// Select a named profile from the config file.
    #[arg(long)]
    profile: Option<String>,

    #[arg(long)]
    explain: bool,

    #[arg(long, value_enum, default_value = "interpreter")]
    backend: BackendKind,

    /// Enable provenance for the DD backend so `why` works.
    /// Off by default: it adds per-fact annotation operators to every rule and is
    /// only needed for explanation queries. (The interpreter always has it.)
    #[arg(long)]
    provenance: bool,

    /// Output format for query/relation results and `rbac::`/`sched::` checks.
    /// `default` names each column, `compact` prints bare tuples, `table` aligns
    /// columns under a header, and `ndjson` emits one JSON object per row (or per
    /// violation), suitable for piping into jq, DuckDB, etc. The process exits
    /// 1 if any `rbac::`/`sched::` check failed or `rbac::diff` found new
    /// permissions.
    #[arg(long, value_enum, default_value = "default")]
    format: OutputFormat,

    /// Run the commands in this file (`-` for stdin), one per line, instead of
    /// starting the REPL. Blank lines and lines starting with `#` are skipped.
    /// Stops at the first line that is not a command or whose command fails.
    /// Exits 0 when clean, 1 on findings (a failed `rbac::`/`sched::` check, or
    /// `rbac::diff` finding new permissions), 2 on an error.
    #[arg(long, value_name = "FILE")]
    script: Option<PathBuf>,

    /// Read startup commands from this rc file instead of the default search
    /// locations ($XDG_CONFIG_HOME/pallograph/pallographrc, then
    /// ./.pallographrc). Lines run before the REPL or `--script`, same syntax;
    /// a good place for `alias` and `format`.
    #[arg(long, value_name = "FILE")]
    rcfile: Option<PathBuf>,

    /// Skip all rc files.
    #[arg(long)]
    no_rc: bool,

    /// Watch every `k8s` datasource, as if each set `watch = true` in the
    /// config: the live state follows the cluster instead of a list taken at
    /// startup. Mainly for running without a config file. Pairs best with
    /// `--backend dd`, which applies each batch of changes incrementally.
    #[arg(long)]
    watch: bool,
}

/// A client for the cluster in the current kubeconfig context (or the
/// in-cluster service account).
async fn cluster_client() -> Result<kube::Client> {
    let mut config = kube::Config::infer().await?;
    // Profilers (samply) inject DYLD_INSERT_LIBRARIES; keep it out of the
    // exec auth plugin or dyld aborts on arm64e binaries.
    if let Some(exec) = config.auth_info.exec.as_mut() {
        exec.drop_env
            .get_or_insert_with(Vec::new)
            .push("DYLD_INSERT_LIBRARIES".into());
    }
    Ok(kube::Client::try_from(config)?)
}

/// Load one datasource. k8s objects go to `objects` so the engine can track
/// which facts each emitted; flat tuples go straight to `edb`. A watched
/// `k8s` datasource (`watch = true`, or `watch_all` from `--watch`) loads
/// nothing here and leaves its client in `watch_client` instead: the
/// watcher's first list fills the engine.
async fn load_datasource(
    edb: &mut MemStore,
    objects: &mut Vec<edb::ObjectFacts>,
    watch_client: &mut Option<kube::Client>,
    watch_all: bool,
    name: &str,
    ds: &config::Datasource,
) -> Result<()> {
    use config::{ContentKind, SourceKind};
    if ds.watch && ds.source != SourceKind::K8s {
        anyhow::bail!("datasource '{name}': watch = true needs source = \"k8s\"");
    }
    match ds.source {
        SourceKind::K8s => {
            let client = cluster_client().await?;
            if ds.watch || watch_all {
                // Objects are keyed without their cluster, so two watched
                // clusters' objects would collide.
                if watch_client.is_some() {
                    anyhow::bail!(
                        "datasource '{name}': only one watched k8s datasource per profile for now"
                    );
                }
                eprintln!("  {name}: cluster (watched)");
                *watch_client = Some(client);
            } else {
                eprintln!("  {name}: cluster (live)");
                let mut source = edb::ClusterSource::fetch(client).await?;
                objects.extend(edb::object_facts(&mut source)?);
            }
        }
        SourceKind::File => {
            let paths = ds
                .paths
                .as_ref()
                .with_context(|| format!("datasource '{name}': source=\"file\" requires paths"))?;
            let content = ds.content.as_ref().with_context(|| {
                format!("datasource '{name}': source=\"file\" requires content")
            })?;
            match content {
                ContentKind::K8sManifests => {
                    eprintln!("  {name}: file ({}) → k8s-manifests", paths.join(", "));
                    let mut source = edb::K8sManifestsSource {
                        paths: paths.clone(),
                    };
                    objects.extend(edb::object_facts(&mut source)?);
                }
                ContentKind::JsonTuples => {
                    let relation = ds.relation.as_deref().with_context(|| {
                        format!("datasource '{name}': content=\"json-tuples\" requires a relation")
                    })?;
                    for path in paths {
                        eprintln!("  {name}: file ({path}) → json-tuples:{relation}");
                        load::load_tuples_into_store(edb, relation, path)?;
                    }
                }
            }
        }
        SourceKind::Shell => {
            let command = ds.command.as_deref().with_context(|| {
                format!("datasource '{name}': source=\"shell\" requires a command")
            })?;
            let content = ds.content.as_ref().with_context(|| {
                format!("datasource '{name}': source=\"shell\" requires content")
            })?;
            match content {
                ContentKind::K8sManifests => {
                    eprintln!("  {name}: shell → k8s-manifests");
                    let mut source = edb::ShellSource {
                        command: command.to_string(),
                    };
                    objects.extend(edb::object_facts(&mut source)?);
                }
                ContentKind::JsonTuples => {
                    let relation = ds.relation.as_deref().with_context(|| {
                        format!("datasource '{name}': content=\"json-tuples\" requires a relation")
                    })?;
                    eprintln!("  {name}: shell → json-tuples:{relation}");
                    load::load_tuples_into_store(edb, relation, &format!("! {command}"))?;
                }
            }
        }
    }
    Ok(())
}

/// Exits 2 on an error, as `--script` does when a command fails, so it is
/// never mistaken for a finding (exit 1).
#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Error: {e:?}");
            ExitCode::from(repl::SessionStatus::Error.exit_code())
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode> {
    // Load EDB facts into a staging MemStore.
    // Priority: config file > the live cluster in the current kubeconfig context.
    let mut edb = MemStore::new();
    let mut objects = Vec::new();
    let mut watch_client = None;
    match config::load_config(cli.config.as_deref())? {
        Some(cfg) => {
            let profile_name = cli
                .profile
                .as_deref()
                .or(cfg.default_profile.as_deref())
                .context("no --profile given and no default_profile in config")?;
            let profile = cfg
                .profiles
                .get(profile_name)
                .with_context(|| format!("profile '{profile_name}' not found in config"))?;
            eprintln!("datasource: profile \"{profile_name}\"");
            for name in &profile.sources {
                let ds = cfg
                    .datasources
                    .get(name.as_str())
                    .with_context(|| format!("datasource '{name}' not found in config"))?;
                load_datasource(
                    &mut edb,
                    &mut objects,
                    &mut watch_client,
                    cli.watch,
                    name,
                    ds,
                )
                .await?;
            }
        }
        None => {
            eprintln!("datasource: current kubeconfig context [default]");
            let cluster = config::Datasource {
                source: config::SourceKind::K8s,
                paths: None,
                command: None,
                content: None,
                relation: None,
                watch: false,
            };
            load_datasource(
                &mut edb,
                &mut objects,
                &mut watch_client,
                cli.watch,
                "cluster",
                &cluster,
            )
            .await
            .context("no config file found, so connecting to the current kubeconfig context")?;
        }
    }

    // --explain only compiles, so skip starting a DD session for it.
    let backend: Box<dyn Backend> = match cli.backend {
        _ if cli.explain => Box::new(InterpreterBackend),
        BackendKind::Interpreter => Box::new(InterpreterBackend),
        BackendKind::Dd => Box::new(DdBackend {
            provenance: cli.provenance,
        }),
    };

    // Build the policy engine.
    let mut rule_sources = match &cli.builtin_rules {
        Some(dir) => engine::read_rule_sources(dir)?,
        None => engine::builtin_rules(),
    };
    for path in &cli.rules {
        rule_sources.extend(engine::read_rule_sources(path)?);
    }
    let engine = Engine::with_rule_sources(edb, objects, rule_sources, backend)?;
    if cli.explain {
        let mut cp = engine.compile()?;
        cp.dump_plan()?;
        return Ok(ExitCode::SUCCESS);
    }

    let engine = Arc::new(Mutex::new(engine));
    let watch = match watch_client {
        Some(client) => {
            eprintln!("watching cluster: waiting for the initial list...");
            Some(watch::start(client, Arc::clone(&engine)).await?)
        }
        None if cli.watch => anyhow::bail!("--watch needs a k8s datasource"),
        None => None,
    };
    let store = engine.lock().expect("engine lock poisoned").evaluate()?;

    // The REPL blocks on input, so run it off the async runtime's worker
    // threads, which the watcher's tasks need.
    let rc = repl::load_rc(cli.rcfile.as_deref(), cli.no_rc);
    let status = tokio::task::spawn_blocking(move || {
        let watch = watch.as_deref();
        match &cli.script {
            Some(path) => repl::run_script(&engine, store, cli.format, path, rc, watch),
            None => repl::run(&engine, store, cli.format, rc, watch),
        }
    })
    .await??;
    Ok(ExitCode::from(status.exit_code()))
}
