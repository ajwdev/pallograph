// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Finite RBAC access model.
//!
//! Mangle derives closed-world RBAC facts (`direct_perm`, `indirect_perm`,
//! `controls_identity`, etc.). This module queries those finite relations
//! directly. Z3 remains available under `smt` for analyses that need symbolic
//! search, but normal RBAC access checks should use this model.

use std::collections::{BTreeMap, HashMap, HashSet};

use mangle_common::Value;

use crate::engine::EvalStore;

pub(crate) mod facts;

use facts::{compute_subject_in_crb, compute_subject_in_rb, effective_permission_entries};

pub type PermissionEntry = (String, String, String, String, String);

#[derive(Clone)]
pub struct AccessPath {
    pub binding_kind: &'static str, // "RoleBinding" | "ClusterRoleBinding"
    pub binding_namespace: String,  // "" for ClusterRoleBinding
    pub binding_name: String,
    pub role_kind: &'static str, // "Role" | "ClusterRole"
    pub role_name: String,
    // Escalation chain leading to this binding.
    // Each element is (identity, mechanism_used_to_reach_it).
    // Empty for direct grants (no escalation needed).
    pub hops: Vec<(String, String)>,
}

pub struct Violation {
    pub principal: String,
    pub namespace: String,
    pub resource: String,
    pub verb: String,
    pub paths: Vec<AccessPath>,
}

/// Closed-world RBAC access model derived from Mangle facts.
pub struct RbacAccessModel {
    /// When true, built-in Kubernetes/EKS principals are included in results.
    /// Default false: builtins are filtered out as expected-platform noise.
    pub include_builtins: bool,
    /// Ground/display facts needed for path reconstruction and annotations.
    pub facts: HashMap<String, Vec<Vec<Value>>>,
    /// (principal, namespace, apigroup, resource, verb) direct RBAC entries.
    pub direct_permissions: Vec<PermissionEntry>,
    /// (principal, namespace, apigroup, resource, verb) direct + escalation-aware entries.
    /// Order is unspecified; callers that expose results should dedupe and sort.
    pub effective_permissions: Vec<PermissionEntry>,
}

impl RbacAccessModel {
    pub fn from_store(store: &EvalStore) -> Self {
        Self::from_scan(|rel| store.scan(rel).to_vec())
    }

    pub fn from_scan<F: Fn(&str) -> Vec<Vec<Value>>>(scan: F) -> Self {
        let subject_in_rb = compute_subject_in_rb(&scan);
        let subject_in_crb = compute_subject_in_crb(&scan);
        let direct_perm = scan("direct_perm");
        let indirect_perm = scan("indirect_perm");

        let (can_entries, eff_entries) = effective_permission_entries(&direct_perm, &indirect_perm);

        let mut facts = HashMap::new();
        for rel in ["user_groups", "controls_identity"] {
            facts.insert(rel.to_string(), scan(rel));
        }
        facts.insert("direct_perm".to_string(), direct_perm);
        facts.insert("indirect_perm".to_string(), indirect_perm);
        facts.insert("subject_in_rb".to_string(), subject_in_rb);
        facts.insert("subject_in_crb".to_string(), subject_in_crb);
        facts.insert(
            "rolebinding_roleref".to_string(),
            scan("rolebinding_roleref"),
        );
        facts.insert(
            "clusterrolebinding_roleref".to_string(),
            scan("clusterrolebinding_roleref"),
        );
        for rel in [
            "all_group_perm",
            "all_user_perm",
            "role_perm",
            "clusterrole_perm",
        ] {
            facts.insert(rel.to_string(), scan(rel));
        }
        for rel in [
            "exec_reachable_sa",
            "token_accessible_sa",
            "pod_creatable_sa",
            "impersonatable_sa",
            "escalation_hop",
        ] {
            facts.insert(rel.to_string(), scan(rel));
        }

        Self {
            include_builtins: false,
            facts,
            direct_permissions: can_entries,
            effective_permissions: eff_entries,
        }
    }

    /// Check that every principal with can(_, namespace, resource, verb) is in `expected`.
    /// Pass namespace="" to check cluster-wide grants (ClusterRoleBindings apply to any namespace).
    ///
    /// `direct_permissions` is already the closed-world finite RBAC relation derived by Mangle, so this
    /// scans those entries directly instead of asking Z3 to synthesize string witnesses.
    pub fn check_access_invariant(
        &self,
        namespace: &str,
        resource: &str,
        verb: &str,
        expected: &[&str],
    ) -> Vec<Violation> {
        let expected: HashSet<&str> = expected.iter().copied().collect();
        let mut principals = HashSet::new();

        for (principal, ..) in
            self.direct_permissions
                .iter()
                .filter(|(_, entry_ns, _, entry_resource, entry_verb)| {
                    ns_covers(entry_ns, namespace)
                        && value_covers(entry_resource, resource)
                        && value_covers(entry_verb, verb)
                })
        {
            if expected.contains(principal.as_str()) {
                continue;
            }
            if !self.include_builtins && crate::builtins::is_builtin(principal) {
                continue;
            }
            principals.insert(principal.clone());
        }

        let mut violations: Vec<_> = principals
            .into_iter()
            .map(|principal| {
                let paths = self.paths_for_principal(&principal, None);
                Violation {
                    principal,
                    namespace: namespace.to_string(),
                    resource: resource.to_string(),
                    verb: verb.to_string(),
                    paths,
                }
            })
            .collect();
        violations.sort_by(|a, b| a.principal.cmp(&b.principal));
        violations
    }

    /// Check that only the `allowed` principals have any direct access in `namespace`.
    ///
    /// This is the same closed-world RBAC model used by the Z3 encoding, but it avoids the
    /// expensive free-string witness search by enumerating the finite direct-permission relation.
    pub fn check_namespace_isolation(&self, namespace: &str, allowed: &[&str]) -> Vec<Violation> {
        let allowed: HashSet<&str> = allowed.iter().copied().collect();
        let mut by_principal: BTreeMap<String, (String, String)> = BTreeMap::new();

        for (principal, _, _, entry_resource, entry_verb) in self
            .direct_permissions
            .iter()
            .filter(|(_, entry_ns, _, _, _)| ns_covers(entry_ns, namespace))
        {
            if allowed.contains(principal.as_str()) {
                continue;
            }
            if !self.include_builtins && crate::builtins::is_builtin(principal) {
                continue;
            }
            by_principal
                .entry(principal.clone())
                .or_insert_with(|| (entry_resource.clone(), entry_verb.clone()));
        }

        by_principal
            .into_iter()
            .map(|(principal, (resource, verb))| {
                let paths = self.paths_for_principal(&principal, None);
                Violation {
                    principal,
                    namespace: namespace.to_string(),
                    resource,
                    verb,
                    paths,
                }
            })
            .collect()
    }

    /// Like `check_access_invariant` but queries `effective_can` (escalation-aware).
    /// Enumerates all principals that can reach `(namespace, apigroup, resource, verb)`
    /// via direct RBAC grants *or* via `controls_identity` escalation chains.
    pub fn check_reaches(
        &self,
        namespace: &str,
        apigroup: &str,
        resource: &str,
        verb: &str,
        expected: &[&str],
        include_direct: bool,
    ) -> Vec<Violation> {
        let expected: HashSet<&str> = expected.iter().copied().collect();
        let mut principals = HashSet::new();

        for (principal, ..) in self.effective_permissions.iter().filter(
            |(_, entry_ns, entry_ag, entry_resource, entry_verb)| {
                permission_covers(
                    permission(entry_ns, entry_ag, entry_resource, entry_verb),
                    permission(namespace, apigroup, resource, verb),
                )
            },
        ) {
            if expected.contains(principal.as_str()) {
                continue;
            }
            if !self.include_builtins && crate::builtins::is_builtin(principal) {
                continue;
            }
            if !include_direct
                && self.has_direct_permission(principal, namespace, apigroup, resource, verb)
            {
                continue;
            }
            principals.insert(principal.clone());
        }

        let mut violations: Vec<_> = principals
            .into_iter()
            .map(|principal| {
                let paths = self
                    .paths_for_principal(&principal, Some((namespace, apigroup, resource, verb)));
                Violation {
                    principal,
                    namespace: namespace.to_string(),
                    resource: resource.to_string(),
                    verb: verb.to_string(),
                    paths,
                }
            })
            .collect();
        violations.sort_by(|a, b| a.principal.cmp(&b.principal));
        violations
    }

    /// Return the RBAC subject kind for a principal: "serviceaccount", "group", or "user".
    /// Checks the raw binding subject tables loaded from RBAC facts.
    pub fn principal_kind(&self, p: &str) -> &'static str {
        use mangle_common::Value;
        if p.starts_with("system:serviceaccount:") {
            return "serviceaccount";
        }
        // all_group_perm/all_user_perm are IDB relations with principal as column 0.
        let in_rel = |rel: &str| {
            self.facts.get(rel).is_some_and(|rows| {
                rows.iter()
                    .any(|t| t.first() == Some(&Value::String(p.to_string())))
            })
        };
        if in_rel("all_group_perm") {
            "group"
        } else {
            "user"
        }
    }

    /// Return all principals with a direct `can` entry matching (namespace, apigroup,
    /// resource, verb), along with their relevant binding paths.
    /// Used by `cluster-admin` and `reaches` output to show the direct-grant tier.
    pub fn direct_violations(
        &self,
        namespace: &str,
        apigroup: &str,
        resource: &str,
        verb: &str,
    ) -> Vec<Violation> {
        let matching: Vec<String> = {
            let mut seen = HashSet::new();
            self.direct_permissions
                .iter()
                .filter(|(_, e_ns, e_ag, e_r, e_v)| {
                    permission_covers(
                        permission(e_ns, e_ag, e_r, e_v),
                        permission(namespace, apigroup, resource, verb),
                    )
                })
                .filter_map(|(p, ..)| {
                    if (self.include_builtins || !crate::builtins::is_builtin(p))
                        && seen.insert(p.clone())
                    {
                        Some(p.clone())
                    } else {
                        None
                    }
                })
                .collect()
        };

        matching
            .into_iter()
            .map(|p| {
                // paths_for_principal with perm_filter + has_direct=true returns only
                // the binding(s) that grant the queried permission — no via-chains.
                let paths =
                    self.paths_for_principal(&p, Some((namespace, apigroup, resource, verb)));
                Violation {
                    principal: p,
                    namespace: namespace.to_string(),
                    resource: resource.to_string(),
                    verb: verb.to_string(),
                    paths,
                }
            })
            .collect()
    }

    fn has_direct_permission(
        &self,
        principal: &str,
        namespace: &str,
        apigroup: &str,
        resource: &str,
        verb: &str,
    ) -> bool {
        self.direct_permissions.iter().any(
            |(entry_principal, entry_ns, entry_ag, entry_resource, entry_verb)| {
                entry_principal == principal
                    && permission_covers(
                        permission(entry_ns, entry_ag, entry_resource, entry_verb),
                        permission(namespace, apigroup, resource, verb),
                    )
            },
        )
    }

    /// Return all binding/role paths that grant `principal` access, derived from
    /// the RBAC subject and roleref facts loaded by `assert_rbac_axioms`.
    /// For each `controls_identity(principal, target)` entry, also returns the
    /// target's binding paths annotated with `via: Some(target)`.
    /// Return binding/role paths for `principal`.
    ///
    /// Direct bindings are always included. Escalation via-paths are included only
    /// when `perm_filter` is `Some((ns, ag, r, v))`, and only for targets that
    /// actually satisfy that query (using the same wildcard semantics as the Z3
    /// RecFuncDecl). Self-referential via entries are always excluded.
    ///
    /// Pass `None` for direct-grant queries (`check_access_invariant`) where
    /// escalation paths are out of scope.
    pub fn paths_for_principal(
        &self,
        principal: &str,
        perm_filter: Option<(&str, &str, &str, &str)>,
    ) -> Vec<AccessPath> {
        use mangle_common::Value;

        let rb_key = "subject_in_rb";
        let crb_key = "subject_in_crb";
        let ci_key = "controls_identity";

        let rb_bindings: HashSet<(String, String)> = self
            .facts
            .get(rb_key)
            .map(|rows| {
                rows.iter()
                    .filter_map(|t| {
                        if let [Value::String(p), Value::String(b_ns), Value::String(b_name)] =
                            t.as_slice()
                        {
                            if p == principal {
                                Some((b_ns.clone(), b_name.clone()))
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        let crb_bindings: HashSet<String> = self
            .facts
            .get(crb_key)
            .map(|rows| {
                rows.iter()
                    .filter_map(|t| {
                        if let [Value::String(p), Value::String(b_name)] = t.as_slice() {
                            if p == principal {
                                Some(b_name.clone())
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Without a perm_filter (check_access_invariant mode): always show direct bindings.
        let Some((q_ns, q_ag, q_r, q_v)) = perm_filter else {
            let mut paths = Vec::new();
            self.collect_binding_paths(&rb_bindings, &crb_bindings, vec![], None, &mut paths);
            return paths;
        };

        // Check whether the principal has a direct grant matching the queried permission.
        let has_direct = self
            .direct_permissions
            .iter()
            .any(|(ep, e_ns, e_ag, e_r, e_v)| {
                ep == principal
                    && permission_covers(
                        permission(e_ns, e_ag, e_r, e_v),
                        permission(q_ns, q_ag, q_r, q_v),
                    )
            });

        let mut paths = Vec::new();

        // For principals with direct access, show their binding — it IS the explanation.
        // Via-paths would be redundant noise. Filter to only the binding(s) that grant
        // the queried permission so irrelevant sibling bindings don't appear.
        if has_direct {
            self.collect_binding_paths(
                &rb_bindings,
                &crb_bindings,
                vec![],
                perm_filter,
                &mut paths,
            );
            return paths;
        }

        // Principal only reaches the permission via escalation chains.
        // Collect controls_identity targets, excluding self.
        let via_targets: Vec<String> = self
            .facts
            .get(ci_key)
            .map(|rows| {
                rows.iter()
                    .filter_map(|t| {
                        if let [Value::String(p), Value::String(target)] = t.as_slice() {
                            if p == principal && target != principal {
                                Some(target.clone())
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Filter via-targets by whether they have DIRECT permission matching the query
        // (direct_permissions, not effective_permissions). This breaks mutual-impersonation cycles:
        // a target that only has escalation access won't appear here, so cluster-admin
        // principals don't endlessly list each other as via-paths.
        let relevant_targets: Vec<&String> = via_targets
            .iter()
            .filter(|target| {
                self.direct_permissions
                    .iter()
                    .any(|(ep, e_ns, e_ag, e_r, e_v)| {
                        ep == *target
                            && permission_covers(
                                permission(e_ns, e_ag, e_r, e_v),
                                permission(q_ns, q_ag, q_r, q_v),
                            )
                    })
            })
            .collect();

        // Build hop chains for all relevant targets first.
        let target_chains: Vec<(&String, Vec<(String, String)>)> = relevant_targets
            .iter()
            .map(|t| (*t, self.build_hop_chain(principal, t)))
            .collect();

        // The set of identities that appear as the final hop of some chain.
        let final_hop_ids: HashSet<&str> = target_chains
            .iter()
            .filter_map(|(_, hops)| hops.last().map(|(id, _)| id.as_str()))
            .collect();

        // Suppress redundant longer paths: if a chain's intermediate hops include
        // another final-hop target, the longer chain adds no new information
        // (e.g. A→default→admin@ when A→default is already shown).
        for (target, hops) in &target_chains {
            let intermediates_are_endpoints = hops[..hops.len().saturating_sub(1)]
                .iter()
                .any(|(hop_id, _)| final_hop_ids.contains(hop_id.as_str()));
            if intermediates_are_endpoints {
                continue;
            }

            let target_rb: HashSet<(String, String)> = self
                .facts
                .get(rb_key)
                .map(|rows| {
                    rows.iter()
                        .filter_map(|t| {
                            if let [Value::String(p), Value::String(b_ns), Value::String(b_name)] =
                                t.as_slice()
                            {
                                if p == target.as_str() {
                                    Some((b_ns.clone(), b_name.clone()))
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();

            let target_crb: HashSet<String> = self
                .facts
                .get(crb_key)
                .map(|rows| {
                    rows.iter()
                        .filter_map(|t| {
                            if let [Value::String(p), Value::String(b_name)] = t.as_slice() {
                                if p == target.as_str() {
                                    Some(b_name.clone())
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();

            self.collect_binding_paths(
                &target_rb,
                &target_crb,
                hops.clone(),
                perm_filter,
                &mut paths,
            );
        }

        paths
    }

    /// Reconstruct the escalation hop chain from `principal` to `target`.
    /// Returns `Vec<(identity, mechanism)>` describing each step; the last element
    /// is always `target`. Breadth-first over `escalation_hop` facts, so the chain
    /// has the fewest hops and cycles in mutual-escalation graphs are harmless.
    fn build_hop_chain(&self, principal: &str, target: &str) -> Vec<(String, String)> {
        use mangle_common::Value;
        use std::collections::VecDeque;

        let hops = self.facts.get("escalation_hop");

        // Each queue entry is (node, hops taken from `principal` to reach it).
        let mut queue: VecDeque<(String, Vec<(String, String)>)> = VecDeque::new();
        let mut seen: HashSet<String> = HashSet::new();
        seen.insert(principal.to_string());
        queue.push_back((principal.to_string(), vec![]));

        while let Some((current, path)) = queue.pop_front() {
            let neighbours: Vec<&String> = hops
                .into_iter()
                .flatten()
                .filter_map(|r| {
                    if let [Value::String(p), Value::String(next)] = r.as_slice()
                        && p == &current
                    {
                        Some(next)
                    } else {
                        None
                    }
                })
                .collect();

            for next in neighbours {
                if !seen.insert(next.clone()) {
                    continue;
                }
                let mech = self.mechanism_for(&current, next).unwrap_or_default();
                let mut next_path = path.clone();
                next_path.push((next.clone(), mech));
                if next == target {
                    return next_path;
                }
                queue.push_back((next.clone(), next_path));
            }
        }

        // Fallback: transitive closure says it's reachable but we can't reconstruct the path.
        vec![(target.to_string(), String::new())]
    }

    /// Return the direct escalation mechanism(s) from `principal` to `target` in one hop.
    /// Returns a comma-separated string, e.g. "pod-exec, token". Empty string if unknown.
    fn mechanism_for(&self, principal: &str, target: &str) -> Option<String> {
        use mangle_common::Value;

        let mut mechanisms = Vec::new();

        let sa_prefix = "system:serviceaccount:";
        let (sa_ns, sa_name) = if let Some(rest) = target.strip_prefix(sa_prefix) {
            let mut parts = rest.splitn(2, ':');
            match (parts.next(), parts.next()) {
                (Some(ns), Some(name)) => (Some(ns), Some(name)),
                _ => (None, None),
            }
        } else {
            (None, None)
        };

        let matches_sa = |row: &[Value], rel_ns_idx: usize, rel_name_idx: usize| -> bool {
            if let (Some(target_ns), Some(target_name)) = (sa_ns, sa_name)
                && let (Some(Value::String(p)), Some(Value::String(ns)), Some(Value::String(name))) =
                    (row.first(), row.get(rel_ns_idx), row.get(rel_name_idx))
            {
                return p == principal && ns == target_ns && name == target_name;
            }
            false
        };

        if self
            .facts
            .get("exec_reachable_sa")
            .is_some_and(|r| r.iter().any(|row| matches_sa(row, 1, 2)))
        {
            mechanisms.push("pod-exec");
        }
        if self
            .facts
            .get("token_accessible_sa")
            .is_some_and(|r| r.iter().any(|row| matches_sa(row, 1, 2)))
        {
            mechanisms.push("token");
        }
        if self
            .facts
            .get("pod_creatable_sa")
            .is_some_and(|r| r.iter().any(|row| matches_sa(row, 1, 2)))
        {
            mechanisms.push("pod-create");
        }
        if self
            .facts
            .get("impersonatable_sa")
            .is_some_and(|r| r.iter().any(|row| matches_sa(row, 1, 2)))
        {
            mechanisms.push("impersonate");
        }

        // Non-SA target (user/group): mechanism must be impersonation.
        if sa_ns.is_none()
            && self.facts.get("escalation_hop").is_some_and(|rows| {
                rows.iter().any(|r| {
                    if let [Value::String(p), Value::String(t)] = r.as_slice() {
                        p == principal && t == target
                    } else {
                        false
                    }
                })
            })
        {
            mechanisms.push("impersonate");
        }

        if mechanisms.is_empty() {
            None
        } else {
            mechanisms.dedup();
            Some(mechanisms.join(", "))
        }
    }

    /// Return true when a ClusterRole's permissions include at least one rule
    /// that matches `(q_ag, q_r, q_v)` under wildcard semantics.
    /// Semantics: the entry covers the query when `entry == "*"` (grants all)
    /// or `entry == query` (exact match). A query of `"*"` is only covered by
    /// an entry of `"*"` — a specific entry like `"pods"` does not cover `"*"`.
    fn clusterrole_matches(&self, role_name: &str, q_ag: &str, q_r: &str, q_v: &str) -> bool {
        use mangle_common::Value;
        self.facts.get("clusterrole_perm").is_some_and(|rows| {
            rows.iter().any(|t| {
                if let [
                    Value::String(rn),
                    Value::String(e_ag),
                    Value::String(e_r),
                    Value::String(e_v),
                ] = t.as_slice()
                {
                    rn == role_name
                        && value_covers(e_ag, q_ag)
                        && value_covers(e_r, q_r)
                        && value_covers(e_v, q_v)
                } else {
                    false
                }
            })
        })
    }

    /// Return true when a Role's permissions (scoped to `role_ns`) include at
    /// least one rule that matches `(q_ag, q_r, q_v)` under wildcard semantics.
    fn role_matches(
        &self,
        role_ns: &str,
        role_name: &str,
        q_ag: &str,
        q_r: &str,
        q_v: &str,
    ) -> bool {
        use mangle_common::Value;
        self.facts.get("role_perm").is_some_and(|rows| {
            rows.iter().any(|t| {
                // role_perm: (Namespace, RoleName, ApiGroup, Resource, Verb)
                if let [
                    Value::String(rns),
                    Value::String(rn),
                    Value::String(e_ag),
                    Value::String(e_r),
                    Value::String(e_v),
                ] = t.as_slice()
                {
                    rns == role_ns
                        && rn == role_name
                        && value_covers(e_ag, q_ag)
                        && value_covers(e_r, q_r)
                        && value_covers(e_v, q_v)
                } else {
                    false
                }
            })
        })
    }

    fn collect_binding_paths(
        &self,
        rb_bindings: &HashSet<(String, String)>,
        crb_bindings: &HashSet<String>,
        hops: Vec<(String, String)>,
        // When Some, only bindings whose referenced role grants the queried
        // permission are included. Eliminates irrelevant bindings (e.g.
        // leader-election Roles) from escalation path display.
        perm_filter: Option<(&str, &str, &str, &str)>,
        out: &mut Vec<AccessPath>,
    ) {
        use mangle_common::Value;

        if let Some(rows) = self.facts.get("rolebinding_roleref") {
            for t in rows {
                if let [
                    Value::String(b_ns),
                    Value::String(b_name),
                    Value::String(ref_kind),
                    Value::String(ref_name),
                ] = t.as_slice()
                    && rb_bindings.contains(&(b_ns.clone(), b_name.clone()))
                {
                    if let Some((_, q_ag, q_r, q_v)) = perm_filter {
                        let matches = if ref_kind == "Role" {
                            self.role_matches(b_ns, ref_name, q_ag, q_r, q_v)
                        } else {
                            self.clusterrole_matches(ref_name, q_ag, q_r, q_v)
                        };
                        if !matches {
                            continue;
                        }
                    }
                    out.push(AccessPath {
                        binding_kind: "RoleBinding",
                        binding_namespace: b_ns.clone(),
                        binding_name: b_name.clone(),
                        role_kind: if ref_kind == "Role" {
                            "Role"
                        } else {
                            "ClusterRole"
                        },
                        role_name: ref_name.clone(),
                        hops: hops.clone(),
                    });
                }
            }
        }

        if let Some(rows) = self.facts.get("clusterrolebinding_roleref") {
            for t in rows {
                if let [Value::String(b_name), Value::String(ref_name)] = t.as_slice()
                    && crb_bindings.contains(b_name)
                {
                    if let Some((_, q_ag, q_r, q_v)) = perm_filter
                        && !self.clusterrole_matches(ref_name, q_ag, q_r, q_v)
                    {
                        continue;
                    }
                    out.push(AccessPath {
                        binding_kind: "ClusterRoleBinding",
                        binding_namespace: String::new(),
                        binding_name: b_name.clone(),
                        role_kind: "ClusterRole",
                        role_name: ref_name.clone(),
                        hops: hops.clone(),
                    });
                }
            }
        }
    }
}

/// A permission entry's namespace covers a queried one when it is cluster-wide
/// ("") or equal.
fn ns_covers(entry_ns: &str, query_ns: &str) -> bool {
    entry_ns.is_empty() || entry_ns == query_ns
}

/// A permission field covers a queried value when it is `*` (grants all) or an
/// exact match. A query of `*` is only covered by an entry of `*`; a specific
/// entry like `pods` does not cover the query `*`.
fn value_covers(entry: &str, query: &str) -> bool {
    entry == "*" || entry == query
}

#[derive(Clone, Copy)]
struct PermissionPattern<'a> {
    namespace: &'a str,
    apigroup: &'a str,
    resource: &'a str,
    verb: &'a str,
}

fn permission<'a>(
    namespace: &'a str,
    apigroup: &'a str,
    resource: &'a str,
    verb: &'a str,
) -> PermissionPattern<'a> {
    PermissionPattern {
        namespace,
        apigroup,
        resource,
        verb,
    }
}

fn permission_covers(entry: PermissionPattern<'_>, query: PermissionPattern<'_>) -> bool {
    ns_covers(entry.namespace, query.namespace)
        && value_covers(entry.apigroup, query.apigroup)
        && value_covers(entry.resource, query.resource)
        && value_covers(entry.verb, query.verb)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use mangle_common::Value;
    use mangle_interpreter::MemStore;

    use super::RbacAccessModel;
    use crate::edb;
    use crate::engine::{Engine, InterpreterBackend};

    /// `fixtures/testdata/small/` plus extra NDJSON manifests written to a throwaway directory.
    fn load_engine_with(extra: &str) -> Engine {
        // Unique per call: tests run in parallel threads of one process.
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("pallograph-rbac-access-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        std::fs::write(dir.join("extra.json"), extra).expect("write extra manifests");
        let mut edb = MemStore::new();
        let paths = vec![
            "fixtures/testdata/small".to_string(),
            dir.to_string_lossy().into_owned(),
        ];
        let loaded = edb::load_from_manifests(&mut edb, paths);
        let _ = std::fs::remove_dir_all(&dir);
        loaded.expect("load manifests");
        Engine::new(edb, Path::new("rules"), Box::new(InterpreterBackend)).expect("engine")
    }

    #[test]
    fn direct_violations_show_only_bindings_that_grant_the_permission() {
        // admin@example.com already holds cluster-admin. Give it a second, unrelated
        // binding (like a controller's leader-election Role) that grants nothing
        // close to */*/*; it must not be shown as an explanation.
        let eval = load_engine_with(concat!(
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"leader-election","namespace":"kube-system"},"rules":[{"apiGroups":["coordination.k8s.io"],"resources":["leases"],"verbs":["get","update"]}]}"#,
            "\n",
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"leader-election","namespace":"kube-system"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"leader-election"},"subjects":[{"kind":"User","name":"admin@example.com"}]}"#,
            "\n",
        ))
        .evaluate()
        .expect("evaluate");
        assert!(
            eval.scan("rolebinding_roleref")
                .iter()
                .any(|t| t.contains(&Value::String("leader-election".into()))),
            "fixture binding was not loaded"
        );

        let model = RbacAccessModel::from_store(&eval);
        let direct = model.direct_violations("", "*", "*", "*");
        let admin = direct
            .iter()
            .find(|v| v.principal == "admin@example.com")
            .unwrap_or_else(|| {
                panic!(
                    "admin@example.com missing from {:?}",
                    direct.iter().map(|v| &v.principal).collect::<Vec<_>>()
                )
            });
        assert!(
            admin.paths.iter().all(|p| p.role_name != "leader-election"),
            "non-granting binding shown: {:?}",
            admin
                .paths
                .iter()
                .map(|p| (&p.binding_name, &p.role_name))
                .collect::<Vec<_>>()
        );

        // Every displayed binding, for every principal, references a granting role.
        for v in &direct {
            assert!(
                !v.paths.is_empty(),
                "{} has no explaining binding",
                v.principal
            );
            for p in &v.paths {
                let grants = if p.role_kind == "Role" {
                    model.role_matches(&p.binding_namespace, &p.role_name, "*", "*", "*")
                } else {
                    model.clusterrole_matches(&p.role_name, "*", "*", "*")
                };
                assert!(
                    grants,
                    "{} shown via {} which does not grant */*/*",
                    v.principal, p.role_name
                );
            }
        }
    }

    #[test]
    fn builtin_principals_hidden_by_default_and_shown_with_include_builtins() {
        // A built-in principal granted cluster-admin through a ClusterRoleBinding.
        let eval = load_engine_with(concat!(
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"builtin-admin"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},"subjects":[{"kind":"User","name":"system:kube-controller-manager"}]}"#,
            "\n",
        ))
        .evaluate()
        .expect("evaluate");

        let principals = |include_builtins: bool| -> Vec<String> {
            let mut model = RbacAccessModel::from_store(&eval);
            model.include_builtins = include_builtins;
            model
                .direct_violations("", "*", "*", "*")
                .into_iter()
                .map(|v| v.principal)
                .collect()
        };

        let hidden = principals(false);
        assert!(
            hidden.contains(&"admin@example.com".to_string()),
            "user principal missing: {hidden:?}"
        );
        assert!(
            !hidden.contains(&"system:kube-controller-manager".to_string()),
            "builtin shown by default: {hidden:?}"
        );

        let shown = principals(true);
        assert!(
            shown.contains(&"admin@example.com".to_string()),
            "user principal missing: {shown:?}"
        );
        assert!(
            shown.contains(&"system:kube-controller-manager".to_string()),
            "builtin missing with include_builtins: {shown:?}"
        );
    }

    #[test]
    fn pod_exec_and_pod_create_hops_use_hyphenated_mechanism_labels() {
        // demo:target holds cluster-admin and runs a pod. exec-user can only
        // exec into pods in demo; create-user can only create pods in demo.
        let role = |name: &str, resource: &str| {
            format!(
                r#"{{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{{"name":"{name}","namespace":"demo"}},"rules":[{{"apiGroups":[""],"resources":["{resource}"],"verbs":["create"]}}]}}"#
            )
        };
        let binding = |name: &str, user: &str| {
            format!(
                r#"{{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{{"name":"{name}","namespace":"demo"}},"roleRef":{{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"{name}"}},"subjects":[{{"kind":"User","name":"{user}"}}]}}"#
            )
        };
        let extra = [
            r#"{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"target","namespace":"demo"}}"#.to_string(),
            r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p","namespace":"demo"},"spec":{"serviceAccountName":"target","containers":[{"name":"c","image":"busybox"}]}}"#.to_string(),
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"target-admin"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},"subjects":[{"kind":"ServiceAccount","name":"target","namespace":"demo"}]}"#.to_string(),
            role("exec-role", "pods/exec"),
            binding("exec-role", "exec-user"),
            role("create-role", "pods"),
            binding("create-role", "create-user"),
        ]
        .join("\n");
        let eval = load_engine_with(&extra).evaluate().expect("evaluate");
        let model = RbacAccessModel::from_store(&eval);

        let mechanisms = |user: &str| -> Vec<String> {
            model
                .paths_for_principal(user, Some(("", "*", "*", "*")))
                .into_iter()
                .flat_map(|p| p.hops)
                .filter(|(id, _)| id == "system:serviceaccount:demo:target")
                .map(|(_, mech)| mech)
                .collect()
        };
        assert_eq!(mechanisms("exec-user"), vec!["pod-exec"]);
        assert_eq!(mechanisms("create-user"), vec!["pod-create"]);
    }

    /// One ServiceAccount per namespace (`ns-<name>/<name>`), plus a token-mint
    /// edge `src -> dst` for each pair: a RoleBinding in dst's namespace gives src
    /// `serviceaccounts/token create`, so `escalation_hop(src, dst)` holds.
    /// `holder` additionally gets cluster-wide `secrets get`.
    fn token_graph(names: &[&str], edges: &[(&str, &str)], holder: &str) -> String {
        let mut out = String::new();
        for n in names {
            out += &format!(
                r#"{{"apiVersion":"v1","kind":"ServiceAccount","metadata":{{"name":"{n}","namespace":"ns-{n}"}}}}"#
            );
            out += "\n";
            out += &format!(
                r#"{{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{{"name":"minter","namespace":"ns-{n}"}},"rules":[{{"apiGroups":[""],"resources":["serviceaccounts/token"],"verbs":["create"]}}]}}"#
            );
            out += "\n";
        }
        out += r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"secret-reader"},"rules":[{"apiGroups":[""],"resources":["secrets"],"verbs":["get"]}]}"#;
        out += "\n";
        out += &format!(
            r#"{{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{{"name":"secret-reader"}},"roleRef":{{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"secret-reader"}},"subjects":[{{"kind":"ServiceAccount","name":"{holder}","namespace":"ns-{holder}"}}]}}"#
        );
        out += "\n";
        for (src, dst) in edges {
            out += &format!(
                r#"{{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{{"name":"from-{src}","namespace":"ns-{dst}"}},"roleRef":{{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"minter"}},"subjects":[{{"kind":"ServiceAccount","name":"{src}","namespace":"ns-{src}"}}]}}"#
            );
            out += "\n";
        }
        out
    }

    /// Hop chains `principal` uses to reach cluster-wide `secrets get`,
    /// as `(identity, mechanism)` per hop.
    fn hop_chains(extra: &str, principal: &str) -> Vec<Vec<(String, String)>> {
        let eval = load_engine_with(extra).evaluate().expect("evaluate");
        let model = RbacAccessModel::from_store(&eval);
        let want = format!("system:serviceaccount:ns-{principal}:{principal}");
        let found = model.check_reaches("", "", "secrets", "get", &[], false);
        let v = found
            .iter()
            .find(|v| v.principal == want)
            .unwrap_or_else(|| {
                panic!(
                    "{want} missing from {:?}",
                    found.iter().map(|v| &v.principal).collect::<Vec<_>>()
                )
            });
        v.paths.iter().map(|p| p.hops.clone()).collect()
    }

    fn sa_id(n: &str) -> String {
        format!("system:serviceaccount:ns-{n}:{n}")
    }

    #[test]
    fn hop_chain_is_the_shortest_route() {
        // p -> z -> t (2 hops) and p -> n1 -> n2 -> t (3 hops); no direct p -> t.
        // Both z and n1 control t, so a depth-first walk that tries n1 first
        // returns the 3-hop chain.
        let extra = token_graph(
            &["p", "n1", "n2", "t", "z"],
            &[
                ("p", "n1"),
                ("n1", "n2"),
                ("n2", "t"),
                ("p", "z"),
                ("z", "t"),
            ],
            "t",
        );
        let chains = hop_chains(&extra, "p");
        assert!(!chains.is_empty(), "no path found");
        for hops in chains {
            let ids: Vec<&str> = hops.iter().map(|(id, _)| id.as_str()).collect();
            assert_eq!(ids, [sa_id("z"), sa_id("t")], "not the shortest chain");
            assert!(hops.iter().all(|(_, mech)| mech == "token"), "{hops:?}");
        }
    }

    #[test]
    fn hop_chain_survives_a_cycle_on_the_way() {
        // a <-> b is a cycle; the way out is a -> c -> t. b controls t only
        // through a, so a walk that enters b first has nowhere left to go.
        let extra = token_graph(
            &["a", "b", "c", "t"],
            &[("a", "b"), ("b", "a"), ("a", "c"), ("c", "t")],
            "t",
        );
        let chains = hop_chains(&extra, "a");
        assert!(!chains.is_empty(), "no path found");
        for hops in chains {
            let ids: Vec<&str> = hops.iter().map(|(id, _)| id.as_str()).collect();
            assert_eq!(ids, [sa_id("c"), sa_id("t")]);
            assert!(hops.iter().all(|(_, mech)| mech == "token"), "{hops:?}");
        }

        // b has to go through the cycle member a.
        let chains = hop_chains(&extra, "b");
        for hops in chains {
            let ids: Vec<&str> = hops.iter().map(|(id, _)| id.as_str()).collect();
            assert_eq!(ids, [sa_id("a"), sa_id("c"), sa_id("t")]);
            assert!(hops.iter().all(|(_, mech)| mech == "token"), "{hops:?}");
        }
    }

    #[test]
    fn cluster_wide_grants_reach_every_namespace() {
        // admin@example.com holds cluster-admin via a CRB
        // (stored with ns ""), so it must show up for any namespace query.
        let eval = load_engine_with("").evaluate().expect("evaluate");
        let model = RbacAccessModel::from_store(&eval);

        let iso = model.check_namespace_isolation("default", &[]);
        assert!(
            iso.iter().any(|v| v.principal == "admin@example.com"),
            "isolation: {:?}",
            iso.iter().map(|v| &v.principal).collect::<Vec<_>>()
        );
        let acc = model.check_access_invariant("default", "pods", "get", &[]);
        assert!(
            acc.iter().any(|v| v.principal == "admin@example.com"),
            "check_access missed cluster-wide grant"
        );
        let direct = model.direct_violations("default", "", "pods", "get");
        assert!(
            direct.iter().any(|v| v.principal == "admin@example.com"),
            "direct_violations missed cluster-wide grant"
        );
    }
}
