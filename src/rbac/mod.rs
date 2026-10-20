// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Finite RBAC access model.
//!
//! Mangle derives closed-world RBAC facts (`direct_perm`, `principal_subject`,
//! `controls_identity`, etc.). This module queries those finite relations
//! directly. Z3 remains available under `smt` for analyses that need symbolic
//! search, but normal RBAC access checks should use this model.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use mangle_common::Value;

use crate::engine::EvalStore;

pub(crate) mod facts;

use facts::{Permission, parse_binding_subject, parse_strings, unexpected_row};
pub use facts::{PermissionTables, Subject, SubjectKind};

/// (principal, namespace, apigroup, resource, verb).
pub type PermissionEntry = (Subject, String, String, String, String);

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
    pub principal: Subject,
    pub namespace: String,
    pub resource: String,
    pub verb: String,
    pub paths: Vec<AccessPath>,
}

/// A Role is keyed by (namespace, name); a ClusterRole by ("", name).
type RoleKey = (&'static str, String, String);

/// Relations naming the ServiceAccounts reached by one mechanism, each
/// `(Principal, Namespace, ServiceAccount)`: from a user or ServiceAccount,
/// then from a group, then the mechanism label.
const SERVICE_ACCOUNT_MECHANISMS: [(&str, &str, &str); 4] = [
    ("exec_reachable_sa", "group_exec_reachable_sa", "pod-exec"),
    ("token_accessible_sa", "group_token_accessible_sa", "token"),
    ("pod_creatable_sa", "group_pod_creatable_sa", "pod-create"),
    (
        "impersonatable_sa",
        "group_impersonatable_sa",
        "impersonate",
    ),
];

/// Closed-world RBAC access model derived from Mangle facts.
pub struct RbacAccessModel {
    /// When true, built-in Kubernetes/EKS principals are included in results.
    /// Default false: builtins are filtered out as expected-platform noise.
    pub include_builtins: bool,
    /// Grants per binding subject, group membership and escalation edges,
    /// joined per query. See `PermissionTables` for which principals appear.
    tables: PermissionTables,
    /// `binding_subject`: the (binding namespace, binding name) pairs naming
    /// each subject.
    subject_bindings: HashMap<Subject, Vec<(String, String)>>,
    /// `binding_roleref`: (role kind, role name) per binding.
    binding_roles: HashMap<(String, String), Vec<(String, String)>>,
    /// (apigroup, resource, verb) each role grants, after aggregation.
    role_grants: HashMap<RoleKey, Vec<(String, String, String)>>,
    /// `escalation_hop` and `group_escalation_hop`, by principal.
    escalation_hops: HashMap<Subject, Vec<String>>,
    /// Per mechanism label, the (principal, namespace, ServiceAccount) triples
    /// it reaches.
    service_account_mechanisms: Vec<(&'static str, HashSet<(Subject, String, String)>)>,
}

impl RbacAccessModel {
    pub fn from_store(store: &EvalStore) -> Self {
        Self::from_scan(|rel| store.scan(rel).to_vec())
    }

    pub fn from_scan<F: Fn(&str) -> Vec<Vec<Value>>>(scan: F) -> Self {
        let tables = PermissionTables::from_scan(&scan);

        let mut subject_bindings: HashMap<Subject, Vec<(String, String)>> = HashMap::new();
        for (subject, binding) in parse_binding_subject(&scan("binding_subject")) {
            subject_bindings.entry(subject).or_default().push(binding);
        }

        let mut binding_roles: HashMap<(String, String), Vec<(String, String)>> = HashMap::new();
        for [binding_ns, binding, role_kind, role_name] in
            parse_strings::<4>("binding_roleref", &scan("binding_roleref"))
        {
            binding_roles
                .entry((binding_ns, binding))
                .or_default()
                .push((role_kind, role_name));
        }

        let role_grants = role_grants(&scan);

        // A user and ServiceAccount relation and its group counterpart, keyed
        // by principal.
        let by_principal = |relation: &str, group_relation: &str| {
            let mut map: HashMap<Subject, Vec<String>> = HashMap::new();
            for [from, to] in parse_strings::<2>(relation, &scan(relation)) {
                map.entry(Subject::username(from)).or_default().push(to);
            }
            for [from, to] in parse_strings::<2>(group_relation, &scan(group_relation)) {
                map.entry(Subject::group(from)).or_default().push(to);
            }
            map
        };

        let service_account_mechanisms = SERVICE_ACCOUNT_MECHANISMS
            .iter()
            .map(|(relation, group_relation, label)| {
                let mut reached = HashSet::new();
                for [principal, ns, name] in parse_strings::<3>(relation, &scan(relation)) {
                    reached.insert((Subject::username(principal), ns, name));
                }
                for [group, ns, name] in parse_strings::<3>(group_relation, &scan(group_relation)) {
                    reached.insert((Subject::group(group), ns, name));
                }
                (*label, reached)
            })
            .collect();

        Self {
            include_builtins: false,
            tables,
            subject_bindings,
            binding_roles,
            role_grants,
            escalation_hops: by_principal("escalation_hop", "group_escalation_hop"),
            service_account_mechanisms,
        }
    }

    /// Number of (binding subject, permission) grants the model holds.
    pub fn grant_count(&self) -> usize {
        self.tables.grant_count()
    }

    /// Whether `principal` belongs in a report: not one of the `expected`
    /// names (which match a principal of any kind), and not a built-in
    /// principal unless `include_builtins` is set.
    fn is_reported(&self, principal: &Subject, expected: &HashSet<&str>) -> bool {
        !expected.contains(principal.name.as_str())
            && (self.include_builtins || !crate::builtins::is_builtin(&principal.name))
    }

    /// The identities `principal` controls (`controls_identity`, or
    /// `group_controls_identity` for a group).
    fn controlled_identities<'a>(
        &'a self,
        principal: &Subject,
    ) -> impl Iterator<Item = &'a Subject> + use<'a> {
        self.escalation_targets(principal)
            .filter(|target| target.kind != SubjectKind::Group)
    }

    /// The groups `principal` controls (`controls_group`, or
    /// `group_controls_group` for a group).
    fn controlled_groups<'a>(
        &'a self,
        principal: &Subject,
    ) -> impl Iterator<Item = &'a Subject> + use<'a> {
        self.escalation_targets(principal)
            .filter(|target| target.kind == SubjectKind::Group)
    }

    fn escalation_targets<'a>(
        &'a self,
        principal: &Subject,
    ) -> impl Iterator<Item = &'a Subject> + use<'a> {
        self.tables
            .escalation_targets
            .get(principal)
            .into_iter()
            .flatten()
    }

    /// Check that every principal with can(_, namespace, resource, verb) is in `expected`.
    /// Pass namespace="" to check cluster-wide grants (ClusterRoleBindings apply to any namespace).
    /// `expected` (here and in the other checks) lists names, which match a
    /// principal of any kind.
    ///
    /// `direct_perm` is already the closed-world finite RBAC relation derived by Mangle, so this
    /// scans those entries directly instead of asking Z3 to synthesize string witnesses.
    pub fn check_access_invariant(
        &self,
        namespace: &str,
        resource: &str,
        verb: &str,
        expected: &[&str],
    ) -> Vec<Violation> {
        let expected: HashSet<&str> = expected.iter().copied().collect();
        self.tables
            .principals_with_direct(|(entry_namespace, _, entry_resource, entry_verb)| {
                ns_covers(entry_namespace, namespace)
                    && value_covers(entry_resource, resource)
                    && value_covers(entry_verb, verb)
            })
            .into_iter()
            .filter(|principal| self.is_reported(principal, &expected))
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
            .collect()
    }

    /// Check that only the `allowed` principals have any direct access in `namespace`.
    ///
    /// This is the same closed-world RBAC model used by the Z3 encoding, but it avoids the
    /// expensive free-string witness search by enumerating the finite direct-permission relation.
    pub fn check_namespace_isolation(&self, namespace: &str, allowed: &[&str]) -> Vec<Violation> {
        let allowed: HashSet<&str> = allowed.iter().copied().collect();
        // The smallest (resource, verb) per principal, so the reported example
        // does not depend on hash order.
        let mut by_principal: BTreeMap<Subject, (&str, &str)> = BTreeMap::new();

        for (subject, permissions) in &self.tables.grants {
            let Some(example) = permissions
                .iter()
                .filter(|(entry_namespace, ..)| ns_covers(entry_namespace, namespace))
                .map(|(_, _, resource, verb)| (resource.as_str(), verb.as_str()))
                .min()
            else {
                continue;
            };
            for principal in self.tables.holders(subject) {
                if !self.is_reported(&principal, &allowed) {
                    continue;
                }
                by_principal
                    .entry(principal)
                    .and_modify(|current| *current = example.min(*current))
                    .or_insert(example);
            }
        }

        by_principal
            .into_iter()
            .map(|(principal, (resource, verb))| {
                let paths = self.paths_for_principal(&principal, None);
                Violation {
                    principal,
                    namespace: namespace.to_string(),
                    resource: resource.to_string(),
                    verb: verb.to_string(),
                    paths,
                }
            })
            .collect()
    }

    /// Like `check_access_invariant` but queries `effective_can` (escalation-aware).
    /// Enumerates all principals that can reach `(namespace, apigroup, resource, verb)`
    /// via direct RBAC grants *or* via `controls_identity` and `controls_group`
    /// escalation.
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
        let query = permission(namespace, apigroup, resource, verb);
        self.tables
            .principals_with_effective(|granted| permission_covers(granted, query))
            .into_iter()
            .filter(|principal| self.is_reported(principal, &expected))
            .filter(|principal| include_direct || !self.has_direct_permission(principal, query))
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
            .collect()
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
        let query = permission(namespace, apigroup, resource, verb);
        self.tables
            .principals_with_direct(|granted| permission_covers(granted, query))
            .into_iter()
            .filter(|principal| self.is_reported(principal, &HashSet::new()))
            .map(|principal| {
                // paths_for_principal with perm_filter + has_direct=true returns only
                // the binding(s) that grant the queried permission — no via-chains.
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
            .collect()
    }

    fn has_direct_permission(&self, principal: &Subject, query: PermissionPattern<'_>) -> bool {
        self.tables
            .direct_grants(principal)
            .any(|granted| permission_covers(granted, query))
    }

    /// True when the escalation `target` brings a grant covering `query`.
    fn target_has_permission(&self, target: &Subject, query: PermissionPattern<'_>) -> bool {
        self.tables
            .target_grants(target)
            .any(|granted| permission_covers(granted, query))
    }

    /// May impersonate groups, in any namespace, like
    /// `perm_group_impersonate` in escalation.mg.
    fn impersonates_groups(granted: &Permission) -> bool {
        let (_, api_group, resource, verb) = granted;
        value_covers(api_group, "")
            && value_covers(resource, "groups")
            && value_covers(verb, "impersonate")
    }

    /// Return binding/role paths for `principal`.
    ///
    /// Direct bindings are always included. Escalation via-paths are included only
    /// when `perm_filter` is `Some((namespace, apigroup, resource, verb))`, and only for targets that
    /// actually satisfy that query (using the same wildcard semantics as the Z3
    /// RecFuncDecl). Targets are identities from `controls_identity` and groups
    /// from `controls_group`, or their `group_` counterparts when `principal`
    /// is a group. Self-referential via entries are always excluded.
    ///
    /// Pass `None` for direct-grant queries (`check_access_invariant`) where
    /// escalation paths are out of scope.
    pub fn paths_for_principal(
        &self,
        principal: &Subject,
        perm_filter: Option<(&str, &str, &str, &str)>,
    ) -> Vec<AccessPath> {
        let subjects = self.tables.subjects_of(principal);

        // Without a perm_filter (check_access_invariant mode): always show direct bindings.
        let Some((query_namespace, query_api_group, query_resource, query_verb)) = perm_filter
        else {
            let mut paths = Vec::new();
            self.collect_binding_paths(&subjects, vec![], None, &mut paths);
            return paths;
        };
        let query = permission(query_namespace, query_api_group, query_resource, query_verb);

        let mut paths = Vec::new();

        // For principals with direct access, show their binding — it IS the explanation.
        // Via-paths would be redundant noise. Filter to only the binding(s) that grant
        // the queried permission so irrelevant sibling bindings don't appear.
        if self.has_direct_permission(principal, query) {
            self.collect_binding_paths(&subjects, vec![], perm_filter, &mut paths);
            return paths;
        }

        // Principal only reaches the permission via escalation chains.
        //
        // Identity targets are filtered by whether their own grants (not what
        // they reach through escalation) match the query. This breaks
        // mutual-impersonation cycles: a target that only has escalation
        // access won't appear here, so cluster-admin principals don't
        // endlessly list each other as via-paths.
        let mut target_chains: Vec<(Vec<Subject>, Vec<(String, String)>)> = Vec::new();
        for target in self.controlled_identities(principal) {
            if self.target_has_permission(target, query) {
                target_chains.push((
                    self.tables.target_subjects(target),
                    self.build_hop_chain(principal, &target.name),
                ));
            }
        }

        // Group targets: reached by impersonating the group, from the
        // principal itself or the nearest identity it controls that may.
        let group_targets: Vec<&Subject> = self
            .controlled_groups(principal)
            .filter(|group| self.target_has_permission(group, query))
            .collect();
        if !group_targets.is_empty() {
            let impersonator_chain = self.group_impersonator_chain(principal);
            for group in group_targets {
                let mut hops = impersonator_chain.clone();
                hops.push((group.name.clone(), "impersonate".to_string()));
                target_chains.push((vec![group.clone()], hops));
            }
        }

        // The set of identities that appear as the final hop of some chain.
        let final_hop_ids: HashSet<&str> = target_chains
            .iter()
            .filter_map(|(_, hops)| hops.last().map(|(id, _)| id.as_str()))
            .collect();

        // Suppress redundant longer paths: if a chain's intermediate hops include
        // another final-hop target, the longer chain adds no new information
        // (e.g. A→default→admin@ when A→default is already shown).
        for (target_subjects, hops) in &target_chains {
            let intermediates_are_endpoints = hops[..hops.len().saturating_sub(1)]
                .iter()
                .any(|(hop_id, _)| final_hop_ids.contains(hop_id.as_str()));
            if intermediates_are_endpoints {
                continue;
            }
            self.collect_binding_paths(target_subjects, hops.clone(), perm_filter, &mut paths);
        }

        paths
    }

    /// Hops from `principal` to the nearest identity that may impersonate
    /// groups: empty when `principal` may itself.
    fn group_impersonator_chain(&self, principal: &Subject) -> Vec<(String, String)> {
        if self
            .tables
            .direct_grants(principal)
            .any(Self::impersonates_groups)
        {
            return vec![];
        }
        self.controlled_identities(principal)
            .filter(|target| {
                self.tables
                    .target_grants(target)
                    .any(Self::impersonates_groups)
            })
            .map(|target| self.build_hop_chain(principal, &target.name))
            .min_by(|a, b| a.len().cmp(&b.len()).then_with(|| a.cmp(b)))
            .unwrap_or_default()
    }

    /// Reconstruct the escalation hop chain from `principal` to `target`, a
    /// username. Returns `Vec<(identity, mechanism)>` describing each step;
    /// the last element is always `target`. Breadth-first over
    /// `escalation_hop` facts (`group_escalation_hop` for the first hop from a
    /// group), so the chain has the fewest hops and cycles in
    /// mutual-escalation graphs are harmless.
    fn build_hop_chain(&self, principal: &Subject, target: &str) -> Vec<(String, String)> {
        use std::collections::VecDeque;

        // Each queue entry is (node, hops taken from `principal` to reach it).
        let mut queue: VecDeque<(Subject, Vec<(String, String)>)> = VecDeque::new();
        let mut seen: HashSet<Subject> = HashSet::new();
        seen.insert(principal.clone());
        queue.push_back((principal.clone(), vec![]));

        while let Some((current, path)) = queue.pop_front() {
            // Sorted so ties between equally short chains resolve the same way
            // on every run.
            let mut neighbours: Vec<&String> = self
                .escalation_hops
                .get(&current)
                .into_iter()
                .flatten()
                .collect();
            neighbours.sort();

            for next in neighbours {
                let next_principal = Subject::username(next.as_str());
                if !seen.insert(next_principal.clone()) {
                    continue;
                }
                let mech = self.mechanism_for(&current, next).unwrap_or_default();
                let mut next_path = path.clone();
                next_path.push((next.clone(), mech));
                if next == target {
                    return next_path;
                }
                queue.push_back((next_principal, next_path));
            }
        }

        // Fallback: transitive closure says it's reachable but we can't reconstruct the path.
        vec![(target.to_string(), String::new())]
    }

    /// Return the direct escalation mechanism(s) from `principal` to `target` in one hop.
    /// Returns a comma-separated string, e.g. "pod-exec, token". Empty string if unknown.
    fn mechanism_for(&self, principal: &Subject, target: &str) -> Option<String> {
        let mut mechanisms = Vec::new();

        let service_account = target
            .strip_prefix("system:serviceaccount:")
            .and_then(|rest| rest.split_once(':'));

        if let Some((sa_ns, sa_name)) = service_account {
            let triple = (principal.clone(), sa_ns.to_string(), sa_name.to_string());
            for (label, reached) in &self.service_account_mechanisms {
                if reached.contains(&triple) {
                    mechanisms.push(*label);
                }
            }
        } else if self
            .escalation_hops
            .get(principal)
            .is_some_and(|targets| targets.iter().any(|t| t == target))
        {
            // Non-SA target (a user): mechanism must be impersonation.
            mechanisms.push("impersonate");
        }

        if mechanisms.is_empty() {
            None
        } else {
            mechanisms.dedup();
            Some(mechanisms.join(", "))
        }
    }

    /// Return true when a role's permissions include at least one rule that
    /// matches `(q_ag, q_r, q_v)` under wildcard semantics.
    /// Semantics: the entry covers the query when `entry == "*"` (grants all)
    /// or `entry == query` (exact match). A query of `"*"` is only covered by
    /// an entry of `"*"` — a specific entry like `"pods"` does not cover `"*"`.
    /// Rules limited to some resourceNames count, as they do in
    /// `direct_perm`.
    fn role_key_matches(&self, key: &RoleKey, q_ag: &str, q_r: &str, q_v: &str) -> bool {
        self.role_grants.get(key).is_some_and(|grants| {
            grants.iter().any(|(ag, r, v)| {
                value_covers(ag, q_ag) && value_covers(r, q_r) && value_covers(v, q_v)
            })
        })
    }

    fn clusterrole_matches(&self, role_name: &str, q_ag: &str, q_r: &str, q_v: &str) -> bool {
        let key = ("ClusterRole", String::new(), role_name.to_string());
        self.role_key_matches(&key, q_ag, q_r, q_v)
    }

    fn role_matches(
        &self,
        role_ns: &str,
        role_name: &str,
        q_ag: &str,
        q_r: &str,
        q_v: &str,
    ) -> bool {
        let key = ("Role", role_ns.to_string(), role_name.to_string());
        self.role_key_matches(&key, q_ag, q_r, q_v)
    }

    /// Append the bindings naming any of `subjects`, each once, sorted.
    fn collect_binding_paths(
        &self,
        subjects: &[Subject],
        hops: Vec<(String, String)>,
        // When Some, only bindings whose referenced role grants the queried
        // permission are included. Eliminates irrelevant bindings (e.g.
        // leader-election Roles) from escalation path display.
        perm_filter: Option<(&str, &str, &str, &str)>,
        out: &mut Vec<AccessPath>,
    ) {
        let mut found: BTreeSet<(&str, &str, &'static str, &str)> = BTreeSet::new();
        for subject in subjects {
            for (binding_ns, binding) in self.subject_bindings.get(subject).into_iter().flatten() {
                let roles = self
                    .binding_roles
                    .get(&(binding_ns.clone(), binding.clone()))
                    .into_iter()
                    .flatten();
                for (role_kind, role_name) in roles {
                    let role_kind = match role_kind.as_str() {
                        "Role" => "Role",
                        "ClusterRole" => "ClusterRole",
                        // The API server rejects any other roleRef kind.
                        _ => continue,
                    };
                    if let Some((_, q_ag, q_r, q_v)) = perm_filter {
                        let matches = if role_kind == "Role" {
                            self.role_matches(binding_ns, role_name, q_ag, q_r, q_v)
                        } else {
                            self.clusterrole_matches(role_name, q_ag, q_r, q_v)
                        };
                        if !matches {
                            continue;
                        }
                    }
                    found.insert((binding_ns, binding, role_kind, role_name));
                }
            }
        }

        for (binding_ns, binding, role_kind, role_name) in found {
            out.push(AccessPath {
                binding_kind: if binding_ns.is_empty() {
                    "ClusterRoleBinding"
                } else {
                    "RoleBinding"
                },
                binding_namespace: binding_ns.to_string(),
                binding_name: binding.to_string(),
                role_kind,
                role_name: role_name.to_string(),
                hops: hops.clone(),
            });
        }
    }
}

/// (apigroup, resource, verb) granted by each Role and ClusterRole: role_rule
/// and clusterrole_rule joined with policy_rule_perm on the PolicyRule value.
/// ResourceName is dropped.
fn role_grants(
    scan: &dyn Fn(&str) -> Vec<Vec<Value>>,
) -> HashMap<RoleKey, Vec<(String, String, String)>> {
    let mut rule_grants: HashMap<Value, Vec<(String, String, String)>> = HashMap::new();
    for row in scan("policy_rule_perm") {
        match row.as_slice() {
            [
                rule,
                Value::String(ag),
                Value::String(r),
                Value::Name(_) | Value::String(_),
                Value::String(v),
            ] => rule_grants.entry(rule.clone()).or_default().push((
                ag.clone(),
                r.clone(),
                v.clone(),
            )),
            _ => unexpected_row("policy_rule_perm", &row),
        }
    }

    let mut grants: HashMap<RoleKey, Vec<(String, String, String)>> = HashMap::new();
    let mut add = |key: RoleKey, rule: &Value| {
        if let Some(rule_grants) = rule_grants.get(rule) {
            grants
                .entry(key)
                .or_default()
                .extend(rule_grants.iter().cloned());
        }
    };
    for row in scan("role_rule") {
        match row.as_slice() {
            [Value::String(ns), Value::String(role), rule] => {
                add(("Role", ns.clone(), role.clone()), rule)
            }
            _ => unexpected_row("role_rule", &row),
        }
    }
    for row in scan("clusterrole_rule") {
        match row.as_slice() {
            [Value::String(role), rule] => add(("ClusterRole", String::new(), role.clone()), rule),
            _ => unexpected_row("clusterrole_rule", &row),
        }
    }
    grants
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

/// A granted permission covers a query when every field does.
fn permission_covers(granted: &Permission, query: PermissionPattern<'_>) -> bool {
    let (namespace, api_group, resource, verb) = granted;
    ns_covers(namespace, query.namespace)
        && value_covers(api_group, query.apigroup)
        && value_covers(resource, query.resource)
        && value_covers(verb, query.verb)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use mangle_common::Value;
    use mangle_interpreter::MemStore;

    use super::{RbacAccessModel, Subject, SubjectKind};
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
            eval.scan("binding_roleref")
                .iter()
                .any(|t| t.contains(&Value::String("leader-election".into()))),
            "fixture binding was not loaded"
        );

        let model = RbacAccessModel::from_store(&eval);
        let direct = model.direct_violations("", "*", "*", "*");
        let admin = direct
            .iter()
            .find(|v| v.principal == Subject::username("admin@example.com"))
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
                .map(|v| v.principal.name)
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
                .paths_for_principal(&Subject::username(user), Some(("", "*", "*", "*")))
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
        let want = Subject::username(format!("system:serviceaccount:ns-{principal}:{principal}"));
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
            iso.iter()
                .any(|v| v.principal == Subject::username("admin@example.com")),
            "isolation: {:?}",
            iso.iter().map(|v| &v.principal).collect::<Vec<_>>()
        );
        let acc = model.check_access_invariant("default", "pods", "get", &[]);
        assert!(
            acc.iter()
                .any(|v| v.principal == Subject::username("admin@example.com")),
            "check_access missed cluster-wide grant"
        );
        let direct = model.direct_violations("default", "", "pods", "get");
        assert!(
            direct
                .iter()
                .any(|v| v.principal == Subject::username("admin@example.com")),
            "direct_violations missed cluster-wide grant"
        );
    }

    #[test]
    fn access_model_reads_every_relation_on_the_small_fixture() {
        // Each index below comes from scanning a relation by name. If a rule
        // is renamed or reshaped, the scan comes back empty or every row is
        // rejected; either way the index is empty and this fails.
        let eval = load_engine_with("").evaluate().expect("evaluate");
        let model = RbacAccessModel::from_store(&eval);

        assert!(!model.tables.grants.is_empty(), "direct_perm");
        assert!(
            !model.tables.principal_subjects.is_empty(),
            "principal_subject"
        );
        assert!(!model.subject_bindings.is_empty(), "binding_subject");
        assert!(!model.binding_roles.is_empty(), "binding_roleref");
        assert!(
            model.role_grants.keys().any(|(kind, ..)| *kind == "Role"),
            "role_rule joined with policy_rule_perm"
        );
        assert!(
            model
                .role_grants
                .keys()
                .any(|(kind, ..)| *kind == "ClusterRole"),
            "clusterrole_rule joined with policy_rule_perm"
        );
        assert!(
            model
                .tables
                .escalation_targets
                .values()
                .flatten()
                .any(|target| target.kind != SubjectKind::Group),
            "controls_identity"
        );
        assert!(!model.escalation_hops.is_empty(), "escalation_hop");
        for (label, reached) in &model.service_account_mechanisms {
            assert!(!reached.is_empty(), "{label} relation");
        }
        assert!(
            model.tables.effective_entries().len() > model.tables.direct_entries().len(),
            "escalation added nothing to the effective entries"
        );
        assert!(
            model
                .tables
                .direct_grants(&Subject::username("admin@example.com"))
                .any(|granted| granted == &(String::new(), "*".into(), "*".into(), "*".into())),
            "admin@example.com cluster-admin grant missing"
        );
    }

    #[test]
    fn group_grants_reach_known_members_and_the_group_itself() {
        // A ClusterRoleBinding to the namespace's ServiceAccount group: the
        // group is reported, and so is the ServiceAccount, through its
        // implicit group membership (principal_subject).
        let eval = load_engine_with(concat!(
            r#"{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"app","namespace":"demo"}}"#,
            "\n",
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"pod-reader"},"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["get"]}]}"#,
            "\n",
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"demo-pod-reader"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"pod-reader"},"subjects":[{"kind":"Group","name":"system:serviceaccounts:demo"}]}"#,
            "\n",
        ))
        .evaluate()
        .expect("evaluate");
        let model = RbacAccessModel::from_store(&eval);

        let direct = model.direct_violations("demo", "", "pods", "get");
        for principal in [
            Subject::group("system:serviceaccounts:demo"),
            Subject::username("system:serviceaccount:demo:app"),
        ] {
            let v = direct
                .iter()
                .find(|v| v.principal == principal)
                .unwrap_or_else(|| {
                    panic!(
                        "{principal} missing from {:?}",
                        direct.iter().map(|v| &v.principal).collect::<Vec<_>>()
                    )
                });
            let bindings: Vec<&str> = v.paths.iter().map(|p| p.binding_name.as_str()).collect();
            assert_eq!(bindings, ["demo-pod-reader"], "{principal}");
        }
        assert_eq!(
            Subject::username("system:serviceaccount:demo:app").kind,
            SubjectKind::ServiceAccount
        );
    }

    #[test]
    fn group_impersonation_reaches_the_group_grants() {
        // imp may impersonate groups; the group admins holds cluster-admin.
        // controls_group(imp, admins) makes imp reach cluster-admin, shown as
        // one impersonation hop to the group and the group's binding.
        let eval = load_engine_with(concat!(
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"group-impersonator"},"rules":[{"apiGroups":[""],"resources":["groups"],"verbs":["impersonate"]}]}"#,
            "\n",
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"imp"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"group-impersonator"},"subjects":[{"kind":"User","name":"imp"}]}"#,
            "\n",
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"admins"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},"subjects":[{"kind":"Group","name":"admins"}]}"#,
            "\n",
        ))
        .evaluate()
        .expect("evaluate");
        let model = RbacAccessModel::from_store(&eval);

        let via = model.check_reaches("", "*", "*", "*", &[], false);
        let imp = via
            .iter()
            .find(|v| v.principal == Subject::username("imp"))
            .unwrap_or_else(|| {
                panic!(
                    "imp missing from {:?}",
                    via.iter().map(|v| &v.principal).collect::<Vec<_>>()
                )
            });
        let shown: Vec<(&str, Vec<(String, String)>)> = imp
            .paths
            .iter()
            .map(|p| (p.binding_name.as_str(), p.hops.clone()))
            .collect();
        assert_eq!(
            shown,
            [(
                "admins",
                vec![("admins".to_string(), "impersonate".to_string())]
            )]
        );
    }

    #[test]
    fn group_escalation_starts_from_the_group() {
        // Members of execs, none of them known, may exec into pods in demo.
        // A pod there runs as demo:target, which holds cluster-admin, so the
        // group reaches cluster-admin and is reported as the starting point.
        let eval = load_engine_with(concat!(
            r#"{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"target","namespace":"demo"}}"#,
            "\n",
            r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p","namespace":"demo"},"spec":{"serviceAccountName":"target","containers":[{"name":"c","image":"busybox"}]}}"#,
            "\n",
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"target-admin"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},"subjects":[{"kind":"ServiceAccount","name":"target","namespace":"demo"}]}"#,
            "\n",
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"exec","namespace":"demo"},"rules":[{"apiGroups":[""],"resources":["pods/exec"],"verbs":["create"]}]}"#,
            "\n",
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"exec","namespace":"demo"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"exec"},"subjects":[{"kind":"Group","name":"execs"}]}"#,
            "\n",
        ))
        .evaluate()
        .expect("evaluate");
        let model = RbacAccessModel::from_store(&eval);

        let via = model.check_reaches("", "*", "*", "*", &[], false);
        let execs = via
            .iter()
            .find(|v| v.principal == Subject::group("execs"))
            .unwrap_or_else(|| {
                panic!(
                    "execs (group) missing from {:?}",
                    via.iter()
                        .map(|v| v.principal.to_string())
                        .collect::<Vec<_>>()
                )
            });
        let shown: Vec<(&str, Vec<(String, String)>)> = execs
            .paths
            .iter()
            .map(|p| (p.binding_name.as_str(), p.hops.clone()))
            .collect();
        assert_eq!(
            shown,
            [(
                "target-admin",
                vec![(
                    "system:serviceaccount:demo:target".to_string(),
                    "pod-exec".to_string()
                )]
            )]
        );
    }

    #[test]
    fn user_and_group_with_the_same_name_stay_apart() {
        // User twin may read secrets; group twin may delete pods.
        let eval = load_engine_with(&same_name_user_and_group())
            .evaluate()
            .expect("evaluate");
        let model = RbacAccessModel::from_store(&eval);

        let principals = |resource: &str, verb: &str| -> Vec<Subject> {
            model
                .direct_violations("", "", resource, verb)
                .into_iter()
                .map(|v| v.principal)
                .filter(|p| p.name == "twin")
                .collect()
        };
        assert_eq!(principals("secrets", "get"), [Subject::username("twin")]);
        assert_eq!(principals("pods", "delete"), [Subject::group("twin")]);

        let bindings = |principal: &Subject| -> Vec<String> {
            model
                .paths_for_principal(principal, None)
                .into_iter()
                .map(|p| p.binding_name)
                .collect()
        };
        assert_eq!(bindings(&Subject::username("twin")), ["twin-user"]);
        assert_eq!(bindings(&Subject::group("twin")), ["twin-group"]);
    }

    /// A User and a Group both named twin, bound to different ClusterRoles.
    fn same_name_user_and_group() -> String {
        let role = |name: &str, resource: &str, verb: &str| {
            format!(
                r#"{{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{{"name":"{name}"}},"rules":[{{"apiGroups":[""],"resources":["{resource}"],"verbs":["{verb}"]}}]}}"#
            )
        };
        let binding = |name: &str, kind: &str| {
            format!(
                r#"{{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{{"name":"{name}"}},"roleRef":{{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"{name}"}},"subjects":[{{"kind":"{kind}","name":"twin"}}]}}"#
            )
        };
        [
            role("twin-user", "secrets", "get"),
            binding("twin-user", "User"),
            role("twin-group", "pods", "delete"),
            binding("twin-group", "Group"),
        ]
        .join("\n")
    }
}
