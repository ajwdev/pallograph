// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Built-in Kubernetes/EKS principal filter.
//!
//! Loads patterns from the embedded `builtins.txt` and exposes `is_builtin`
//! for use by SMT commands to suppress known-platform principals from output.

use std::sync::OnceLock;

static PATTERNS: OnceLock<Vec<String>> = OnceLock::new();

const BUILTIN_DATA: &str = include_str!("builtins.txt");

fn patterns() -> &'static [String] {
    PATTERNS.get_or_init(|| {
        BUILTIN_DATA
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(str::to_owned)
            .collect()
    })
}

pub fn is_builtin(principal: &str) -> bool {
    patterns().iter().any(|pat| {
        if let Some(prefix) = pat.strip_suffix('*') {
            principal.starts_with(prefix)
        } else {
            principal == pat
        }
    })
}

#[cfg(test)]
mod tests {
    use super::is_builtin;

    #[test]
    fn matches_exact_and_prefix_patterns() {
        // Exact match.
        assert!(is_builtin("system:kube-controller-manager"));
        assert!(is_builtin("system:nodes"));
        // Prefix match (`eks:*`).
        assert!(is_builtin("eks:node-manager"));
        // A built-in controller service account.
        assert!(is_builtin(
            "system:serviceaccount:kube-system:job-controller"
        ));
    }

    #[test]
    fn does_not_match_user_principals() {
        assert!(!is_builtin("admin@example.com"));
        assert!(!is_builtin("system:serviceaccount:default:app"));
        // Exact patterns are not prefixes.
        assert!(!is_builtin("system:nodes-extra"));
        assert!(!is_builtin(""));
    }
}
