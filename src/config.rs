use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Config {
    pub default_profile: Option<String>,
    #[serde(default)]
    pub datasources: HashMap<String, Datasource>,
    #[serde(default)]
    pub profiles: HashMap<String, Profile>,
}

#[derive(Deserialize)]
pub struct Profile {
    /// Names referencing entries in `Config::datasources`.
    pub sources: Vec<String>,
}

#[derive(Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum SourceKind {
    /// Read from a file or directory.
    File,
    /// Run a shell command via `sh -c` and read its stdout.
    Shell,
    /// Live Kubernetes cluster via KUBECONFIG / in-cluster auth.
    K8s,
}

#[derive(Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ContentKind {
    /// Parse as Kubernetes JSON manifests.
    K8sManifests,
    /// Parse as flat JSON tuples loaded into a named relation.
    JsonTuples,
}

#[derive(Deserialize)]
pub struct Datasource {
    pub source: SourceKind,
    /// Glob patterns, files, or directories to load. Required when source = "file".
    /// Directories are expanded recursively. Supports ** for recursive glob.
    pub paths: Option<Vec<String>>,
    /// Shell command to run. Required when source = "shell".
    pub command: Option<String>,
    /// How to parse the data. Optional for source = "k8s" (always k8s-manifests).
    pub content: Option<ContentKind>,
    /// Target relation name. Required when content = "json-tuples".
    pub relation: Option<String>,
}

/// Find and load the config file. Search order:
///   1. `explicit` path if provided (error if it doesn't exist)
///   2. ./pallograph.toml
///   3. $XDG_CONFIG_HOME/pallograph/config.toml (~/.config/pallograph/config.toml)
///
/// Returns None if no config file is found.
pub fn load_config(explicit: Option<&Path>) -> Result<Option<Config>> {
    if let Some(path) = explicit {
        return read_config(path).map(Some);
    }

    let cwd_path = Path::new("pallograph.toml");
    if cwd_path.exists() {
        return read_config(cwd_path).map(Some);
    }

    if let Some(config_dir) = dirs::config_dir() {
        let xdg_path = config_dir.join("pallograph").join("config.toml");
        if xdg_path.exists() {
            return read_config(&xdg_path).map(Some);
        }
    }

    Ok(None)
}

fn read_config(path: &Path) -> Result<Config> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("reading config from {}", path.display()))?;
    toml::from_str(&contents)
        .with_context(|| format!("parsing config from {}", path.display()))
}
