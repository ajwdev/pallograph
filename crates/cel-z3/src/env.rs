//! Declared type environment: maps dotted CEL paths to their Z3 sort.

use std::collections::HashMap;

/// The Z3 sort a CEL identifier resolves to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CelType {
    Int,
    Real,
    String,
    Bool,
}

/// A caller-declared mapping from dotted CEL paths (e.g. `object.spec.replicas`)
/// to their `CelType`. The crate is Kubernetes-agnostic; consumers declare the
/// types they know about.
#[derive(Clone, Debug, Default)]
pub struct Env {
    vars: HashMap<String, CelType>,
}

impl Env {
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare the type of a dotted CEL path. Returns `&mut self` for chaining.
    pub fn declare(&mut self, path: impl Into<String>, ty: CelType) -> &mut Self {
        self.vars.insert(path.into(), ty);
        self
    }

    /// Look up the declared type of a path, if any.
    pub fn get(&self, path: &str) -> Option<CelType> {
        self.vars.get(path).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declare_and_get_round_trip() {
        let mut env = Env::new();
        env.declare("object.spec.replicas", CelType::Int);
        env.declare("object.metadata.name", CelType::String);

        assert_eq!(env.get("object.spec.replicas"), Some(CelType::Int));
        assert_eq!(env.get("object.metadata.name"), Some(CelType::String));
    }

    #[test]
    fn unknown_path_returns_none() {
        let env = Env::new();
        assert_eq!(env.get("object.spec.replicas"), None);
    }
}
