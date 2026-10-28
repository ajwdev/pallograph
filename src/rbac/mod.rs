// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Finite RBAC access model.
//!
//! Mangle derives closed-world RBAC facts (`direct_perm`, `principal_subject`,
//! `controls_identity`, etc.). This module queries those finite relations
//! directly. Z3 remains available under `smt` for analyses that need symbolic
//! search, but normal RBAC access checks should use this model.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use mangle_common::Value;

use crate::engine::EvalStore;

pub mod diff;
pub(crate) mod facts;
mod resource_scope;

use facts::{
    Permission, ns_covers, parse_binding_subject, parse_strings, parse_subject_rows,
    unexpected_row, value_covers,
};
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
    pub hops: Vec<(Subject, String)>,
}

pub struct Violation {
    pub principal: Subject,
    pub namespace: String,
    pub resource: String,
    pub verb: String,
    pub paths: Vec<AccessPath>,
}

/// Shown for a hop the escalation relations cannot explain, which would mean
/// the rules and this module disagree.
const UNKNOWN_MECHANISM: &str = "unknown";

/// A Role is keyed by (namespace, name); a ClusterRole by ("", name).
type RoleKey = (&'static str, String, String);

/// Relations naming the ServiceAccounts one binding subject's grants reach
/// by one mechanism, each `(Name, Kind, Namespace, ServiceAccount)`, with the
/// mechanism label.
const SERVICE_ACCOUNT_MECHANISMS: [(&str, &str); 4] = [
    ("subject_exec_reachable_sa", "pod-exec"),
    ("subject_token_accessible_sa", "token"),
    ("subject_pod_creatable_sa", "pod-create"),
    ("subject_impersonatable_sa", "impersonate"),
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
    /// The rules each role has and the permissions each rule grants.
    role_rules: RoleRules,
    /// `subject_escalation_hop`: the identities (usernames) each binding
    /// subject's grants can assume in one hop.
    subject_hops: HashMap<Subject, BTreeSet<String>>,
    /// Per mechanism label, the (namespace, ServiceAccount) pairs each binding
    /// subject's grants reach.
    service_account_mechanisms: Vec<(&'static str, HashMap<Subject, HashSet<(String, String)>>)>,
    /// Groups holding a grant, which impersonating groups reaches. Sorted.
    granted_groups: Vec<Subject>,
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
        for [binding_namespace, binding, role_kind, role_name] in
            parse_strings::<4>("binding_roleref", &scan("binding_roleref"))
        {
            binding_roles
                .entry((binding_namespace, binding))
                .or_default()
                .push((role_kind, role_name));
        }

        let role_rules = RoleRules::from_scan(&scan);

        let mut subject_hops: HashMap<Subject, BTreeSet<String>> = HashMap::new();
        for (subject, [target]) in
            parse_subject_rows::<1>("subject_escalation_hop", &scan("subject_escalation_hop"))
        {
            subject_hops.entry(subject).or_default().insert(target);
        }

        let service_account_mechanisms = SERVICE_ACCOUNT_MECHANISMS
            .iter()
            .map(|(relation, label)| {
                let mut reached: HashMap<Subject, HashSet<(String, String)>> = HashMap::new();
                for (subject, [namespace, service_account]) in
                    parse_subject_rows::<2>(relation, &scan(relation))
                {
                    reached
                        .entry(subject)
                        .or_default()
                        .insert((namespace, service_account));
                }
                (*label, reached)
            })
            .collect();

        let mut granted_groups: Vec<Subject> = tables
            .grants
            .keys()
            .filter(|subject| subject.kind == SubjectKind::Group)
            .cloned()
            .collect();
        granted_groups.sort();

        Self {
            include_builtins: false,
            tables,
            subject_bindings,
            binding_roles,
            role_rules,
            subject_hops,
            service_account_mechanisms,
            granted_groups,
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

    /// The identities and groups `principal` controls: `controls_identity`
    /// and `controls_group`, or their `group_` counterparts for a group.
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

    /// Check that every principal with a direct grant covering (namespace, resource, verb),
    /// in any apigroup, is in `expected`.
    /// Pass namespace="" to check cluster-wide grants (ClusterRoleBindings apply to any namespace).
    /// `expected` (here and in the other checks) lists names, which match a
    /// principal of any kind.
    ///
    /// In a namespace, a grant on a cluster-scoped resource (see
    /// `resource_scope`) does not count: no request for it carries a namespace.
    ///
    /// `direct_perm` is already the closed-world finite RBAC relation derived by Mangle, so this
    /// scans those entries directly.
    pub fn check_access_invariant(
        &self,
        namespace: &str,
        resource: &str,
        verb: &str,
        expected: &[&str],
    ) -> Vec<Violation> {
        let expected: HashSet<&str> = expected.iter().copied().collect();
        self.tables
            .principals_with_direct(
                |(entry_namespace, entry_api_group, entry_resource, entry_verb)| {
                    ns_covers(entry_namespace, namespace)
                        && (namespace.is_empty()
                            || resource_scope::can_apply_in_namespace(entry_api_group, resource))
                        && value_covers(entry_resource, resource)
                        && value_covers(entry_verb, verb)
                },
            )
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
    /// Access means a grant that can apply to some request in `namespace`: one
    /// made there or cluster-wide, on a resource that is not cluster-scoped
    /// (`resource_scope`). A cluster-wide grant such as `nodes get`, or
    /// `selfsubjectaccessreviews create` for every authenticated user, is not
    /// access to the namespace. Wildcard and unknown resources count.
    pub fn check_namespace_isolation(&self, namespace: &str, allowed: &[&str]) -> Vec<Violation> {
        let allowed: HashSet<&str> = allowed.iter().copied().collect();
        // The smallest (resource, verb) per principal, so the reported example
        // does not depend on hash order.
        let mut by_principal: BTreeMap<Subject, (&str, &str)> = BTreeMap::new();

        for (subject, permissions) in &self.tables.grants {
            let Some(example) = permissions
                .iter()
                .filter(|(entry_namespace, api_group, resource, _)| {
                    ns_covers(entry_namespace, namespace)
                        && resource_scope::can_apply_in_namespace(api_group, resource)
                })
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

    /// Like `check_access_invariant` but escalation-aware.
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

    /// May impersonate groups, like `perm_group_impersonate` in
    /// escalation.mg. Kubernetes checks this as a cluster-scoped request, so
    /// only a cluster-wide grant (namespace "") counts.
    fn impersonates_groups(granted: &Permission) -> bool {
        let (namespace, api_group, resource, verb) = granted;
        namespace.is_empty()
            && value_covers(api_group, "")
            && value_covers(resource, "groups")
            && value_covers(verb, "impersonate")
    }

    /// Return binding/role paths for `principal`.
    ///
    /// Direct bindings are always included. Escalation via-paths are included only
    /// when `perm_filter` is `Some((namespace, apigroup, resource, verb))`, and only for targets that
    /// actually satisfy that query (`permission_covers`). Targets are identities from `controls_identity` and groups
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

        // Principal only reaches the permission via escalation chains, to
        // identities and groups whose own grants (not what they reach through
        // escalation) match the query. This breaks mutual-impersonation
        // cycles: a target that only has escalation access won't appear
        // here, so cluster-admin principals don't endlessly list each other
        // as via-paths.
        let tree = self.escalation_tree(principal);
        let target_chains: Vec<(Vec<Subject>, Vec<(Subject, String)>)> = self
            .escalation_targets(principal)
            .filter(|target| self.target_has_permission(target, query))
            .map(|target| {
                (
                    self.tables.target_subjects(target),
                    hop_chain(&tree, principal, target),
                )
            })
            .collect();

        // The identities and groups that appear as the final hop of some chain.
        let final_hops: HashSet<&Subject> = target_chains
            .iter()
            .filter_map(|(_, hops)| hops.last().map(|(hop, _)| hop))
            .collect();

        // Suppress redundant longer paths: if a chain's intermediate hops include
        // another final-hop target, the longer chain adds no new information
        // (e.g. A→default→admin@ when A→default is already shown).
        for (target_subjects, hops) in &target_chains {
            let intermediates_are_endpoints = hops[..hops.len().saturating_sub(1)]
                .iter()
                .any(|(hop, _)| final_hops.contains(hop));
            if intermediates_are_endpoints {
                continue;
            }
            self.collect_binding_paths(target_subjects, hops.clone(), perm_filter, &mut paths);
        }

        paths
    }

    /// The shortest escalation chains from `principal`, as a tree: for each
    /// identity or group reached, the node it was reached from and the
    /// mechanism of that hop.
    ///
    /// Breadth-first, so each chain has the fewest hops and cycles in
    /// mutual-escalation graphs are harmless. It follows the rules'
    /// closure: `principal` acts with all its subjects (`subjects_of`), an
    /// identity reached on the way only with its `assumed_subject`
    /// subjects, and a group with its own grants. From each, a hop is a
    /// `subject_escalation_hop` of one of those subjects, or impersonating
    /// any group that holds a grant.
    fn escalation_tree(&self, principal: &Subject) -> HashMap<Subject, (Subject, String)> {
        let mut tree: HashMap<Subject, (Subject, String)> = HashMap::new();
        let mut queue = VecDeque::from([principal.clone()]);
        let mut groups_reached = false;

        while let Some(node) = queue.pop_front() {
            let subjects = if node == *principal {
                self.tables.subjects_of(&node)
            } else {
                self.tables.target_subjects(&node)
            };

            // Sorted so ties between equally short chains resolve the same way
            // on every run.
            let identities: BTreeSet<&String> = subjects
                .iter()
                .filter_map(|subject| self.subject_hops.get(subject))
                .flatten()
                .collect();
            let mut next: Vec<(Subject, String)> = identities
                .into_iter()
                .map(|identity| {
                    let identity = Subject::username(identity.as_str());
                    let mechanism = self.mechanism(&subjects, &identity);
                    (identity, mechanism)
                })
                .collect();
            // Every group is one impersonation away from the first node that
            // may impersonate groups, so later nodes add nothing.
            if !groups_reached
                && self
                    .tables
                    .grants_of(subjects.clone())
                    .any(Self::impersonates_groups)
            {
                groups_reached = true;
                next.extend(
                    self.granted_groups
                        .iter()
                        .map(|group| (group.clone(), "impersonate".to_string())),
                );
            }

            for (target, mechanism) in next {
                if target == *principal || tree.contains_key(&target) {
                    continue;
                }
                tree.insert(target.clone(), (node.clone(), mechanism));
                queue.push_back(target);
            }
        }
        tree
    }

    /// The mechanisms by which `subjects` assume `identity` in one hop,
    /// comma-separated, e.g. "pod-exec, token". A ServiceAccount is reached
    /// by the mechanisms whose `subject_*_sa` relation lists it; otherwise
    /// the hop is user impersonation.
    fn mechanism(&self, subjects: &[Subject], identity: &Subject) -> String {
        let service_account = identity
            .name
            .strip_prefix("system:serviceaccount:")
            .and_then(|rest| rest.split_once(':'))
            .map(|(namespace, name)| (namespace.to_string(), name.to_string()));

        let mechanisms: Vec<&str> = service_account
            .map(|service_account| {
                self.service_account_mechanisms
                    .iter()
                    .filter(|(_, reached)| {
                        subjects.iter().any(|subject| {
                            reached
                                .get(subject)
                                .is_some_and(|pairs| pairs.contains(&service_account))
                        })
                    })
                    .map(|(label, _)| *label)
                    .collect()
            })
            .unwrap_or_default();

        if mechanisms.is_empty() {
            "impersonate".to_string()
        } else {
            mechanisms.join(", ")
        }
    }

    /// Return true when a role's permissions include at least one rule that
    /// matches `(query_api_group, query_resource, query_verb)` under wildcard semantics.
    /// Semantics: the entry covers the query when `entry == "*"` (grants all)
    /// or `entry == query` (exact match). A query of `"*"` is only covered by
    /// an entry of `"*"` — a specific entry like `"pods"` does not cover `"*"`.
    /// Rules limited to some resourceNames count, as they do in
    /// `direct_perm`.
    fn role_key_matches(
        &self,
        key: &RoleKey,
        query_api_group: &str,
        query_resource: &str,
        query_verb: &str,
    ) -> bool {
        self.role_rules
            .permissions_of(key)
            .any(|(api_group, resource, verb)| {
                value_covers(api_group, query_api_group)
                    && value_covers(resource, query_resource)
                    && value_covers(verb, query_verb)
            })
    }

    fn clusterrole_matches(
        &self,
        role_name: &str,
        query_api_group: &str,
        query_resource: &str,
        query_verb: &str,
    ) -> bool {
        let key = ("ClusterRole", String::new(), role_name.to_string());
        self.role_key_matches(&key, query_api_group, query_resource, query_verb)
    }

    fn role_matches(
        &self,
        role_namespace: &str,
        role_name: &str,
        query_api_group: &str,
        query_resource: &str,
        query_verb: &str,
    ) -> bool {
        let key = ("Role", role_namespace.to_string(), role_name.to_string());
        self.role_key_matches(&key, query_api_group, query_resource, query_verb)
    }

    /// Append the bindings naming any of `subjects`, each once, sorted.
    fn collect_binding_paths(
        &self,
        subjects: &[Subject],
        hops: Vec<(Subject, String)>,
        // When Some, only bindings that apply in the queried namespace and
        // whose referenced role grants the queried permission are included.
        // Eliminates irrelevant bindings (e.g. leader-election Roles) from
        // escalation path display.
        perm_filter: Option<(&str, &str, &str, &str)>,
        out: &mut Vec<AccessPath>,
    ) {
        let mut found: BTreeSet<(&str, &str, &'static str, &str)> = BTreeSet::new();
        for subject in subjects {
            for (binding_namespace, binding) in
                self.subject_bindings.get(subject).into_iter().flatten()
            {
                // A RoleBinding grants only in its own namespace, so it
                // explains neither a query elsewhere nor a cluster-wide one.
                if perm_filter.is_some_and(|(query_namespace, ..)| {
                    !ns_covers(binding_namespace, query_namespace)
                }) {
                    continue;
                }
                let roles = self
                    .binding_roles
                    .get(&(binding_namespace.clone(), binding.clone()))
                    .into_iter()
                    .flatten();
                for (role_kind, role_name) in roles {
                    let role_kind = match role_kind.as_str() {
                        "Role" => "Role",
                        "ClusterRole" => "ClusterRole",
                        // The API server rejects any other roleRef kind.
                        _ => continue,
                    };
                    if let Some((_, query_api_group, query_resource, query_verb)) = perm_filter {
                        let matches = if role_kind == "Role" {
                            self.role_matches(
                                binding_namespace,
                                role_name,
                                query_api_group,
                                query_resource,
                                query_verb,
                            )
                        } else {
                            self.clusterrole_matches(
                                role_name,
                                query_api_group,
                                query_resource,
                                query_verb,
                            )
                        };
                        if !matches {
                            continue;
                        }
                    }
                    found.insert((binding_namespace, binding, role_kind, role_name));
                }
            }
        }

        for (binding_namespace, binding, role_kind, role_name) in found {
            out.push(AccessPath {
                binding_kind: if binding_namespace.is_empty() {
                    "ClusterRoleBinding"
                } else {
                    "RoleBinding"
                },
                binding_namespace: binding_namespace.to_string(),
                binding_name: binding.to_string(),
                role_kind,
                role_name: role_name.to_string(),
                hops: hops.clone(),
            });
        }
    }
}

/// The rules of each Role and ClusterRole (role_rule and clusterrole_rule),
/// after aggregation, and the (apigroup, resource, verb) each rule grants
/// (policy_rule_perm, ResourceName dropped). As in rbac_roles.mg, a rule's
/// permissions are stored once per distinct PolicyRule value and joined with
/// a role on demand, not copied into every role that has the rule.
#[derive(Default)]
struct RoleRules {
    rules: HashMap<RoleKey, Vec<Value>>,
    permissions: HashMap<Value, Vec<(String, String, String)>>,
}

impl RoleRules {
    fn from_scan(scan: &dyn Fn(&str) -> Vec<Vec<Value>>) -> Self {
        let mut role_rules = Self::default();
        for row in scan("policy_rule_perm") {
            match row.as_slice() {
                [
                    rule,
                    Value::String(api_group),
                    Value::String(resource),
                    Value::Name(_) | Value::String(_),
                    Value::String(verb),
                ] => role_rules
                    .permissions
                    .entry(rule.clone())
                    .or_default()
                    .push((api_group.clone(), resource.clone(), verb.clone())),
                _ => unexpected_row("policy_rule_perm", &row),
            }
        }

        let mut add = |key: RoleKey, rule: &Value| {
            role_rules.rules.entry(key).or_default().push(rule.clone());
        };
        for row in scan("role_rule") {
            match row.as_slice() {
                [Value::String(namespace), Value::String(role), rule] => {
                    add(("Role", namespace.clone(), role.clone()), rule)
                }
                _ => unexpected_row("role_rule", &row),
            }
        }
        for row in scan("clusterrole_rule") {
            match row.as_slice() {
                [Value::String(role), rule] => {
                    add(("ClusterRole", String::new(), role.clone()), rule)
                }
                _ => unexpected_row("clusterrole_rule", &row),
            }
        }
        role_rules
    }

    /// (apigroup, resource, verb) the role `key` grants.
    fn permissions_of<'a>(
        &'a self,
        key: &RoleKey,
    ) -> impl Iterator<Item = &'a (String, String, String)> + use<'a> {
        self.rules
            .get(key)
            .into_iter()
            .flatten()
            .filter_map(|rule| self.permissions.get(rule))
            .flatten()
    }
}

/// The hops from `principal` to `target` in an `escalation_tree`.
fn hop_chain(
    tree: &HashMap<Subject, (Subject, String)>,
    principal: &Subject,
    target: &Subject,
) -> Vec<(Subject, String)> {
    let mut hops = Vec::new();
    let mut node = target;
    while node != principal {
        let Some((previous, mechanism)) = tree.get(node) else {
            // controls_identity or controls_group says the target is
            // reachable, so the tree, which follows the same rules, reaches it,
            // unless a REPL user added such a row by hand.
            if cfg!(test) {
                panic!("no escalation chain from {principal} to {target}");
            }
            eprintln!("warning: no escalation chain from {principal} to {target}");
            return vec![(target.clone(), UNKNOWN_MECHANISM.to_string())];
        };
        hops.push((node.clone(), mechanism.clone()));
        node = previous;
    }
    hops.reverse();
    hops
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

/// A granted permission covers a query when every field does. A query in a
/// namespace for a cluster-scoped resource (see `resource_scope`) is covered
/// by nothing: no such request exists.
fn permission_covers(granted: &Permission, query: PermissionPattern<'_>) -> bool {
    let (namespace, api_group, resource, verb) = granted;
    ns_covers(namespace, query.namespace)
        && (query.namespace.is_empty()
            || resource_scope::can_apply_in_namespace(query.apigroup, query.resource))
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
                .filter(|(hop, _)| hop.name == "system:serviceaccount:demo:target")
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
        v.paths
            .iter()
            .map(|p| {
                p.hops
                    .iter()
                    .map(|(hop, mechanism)| (hop.name.clone(), mechanism.clone()))
                    .collect()
            })
            .collect()
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
    fn isolation_ignores_grants_on_cluster_scoped_resources() {
        // Every authenticated user may read cluster trust bundles and nodes,
        // which live outside namespaces; ns-readers may also list pods
        // everywhere.
        let role = |name: &str, api_group: &str, resource: &str, verb: &str| {
            format!(
                r#"{{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{{"name":"{name}"}},"rules":[{{"apiGroups":["{api_group}"],"resources":["{resource}"],"verbs":["{verb}"]}}]}}"#
            )
        };
        let binding = |name: &str, group: &str| {
            format!(
                r#"{{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{{"name":"{name}"}},"roleRef":{{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"{name}"}},"subjects":[{{"kind":"Group","name":"{group}"}}]}}"#
            )
        };
        let extra = [
            r#"{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"app","namespace":"payments"}}"#.to_string(),
            role("bundles", "certificates.k8s.io", "clustertrustbundles", "get"),
            binding("bundles", "system:authenticated"),
            role("node-reader", "", "nodes", "get"),
            binding("node-reader", "system:authenticated"),
            role("pod-lister", "", "pods", "list"),
            binding("pod-lister", "ns-readers"),
        ]
        .join("\n");
        let eval = load_engine_with(&extra).evaluate().expect("evaluate");
        let model = RbacAccessModel::from_store(&eval);

        let flagged: Vec<Subject> = model
            .check_namespace_isolation("payments", &[])
            .into_iter()
            .map(|v| v.principal)
            .collect();
        assert!(
            flagged.contains(&Subject::group("ns-readers")),
            "{flagged:?}"
        );
        for principal in [
            Subject::group("system:authenticated"),
            Subject::username("system:serviceaccount:payments:app"),
        ] {
            assert!(!flagged.contains(&principal), "{principal}: {flagged:?}");
        }

        // Grants with apigroup "*" (cluster-admin in the fixture) still count:
        // nodes in some other group could be namespaced.
        assert!(
            !model
                .check_access_invariant("payments", "nodes", "get", &[])
                .iter()
                .any(|v| v.principal == Subject::group("system:authenticated")),
            "nodes are cluster-scoped"
        );
        assert!(
            model
                .check_access_invariant("", "nodes", "get", &[])
                .iter()
                .any(|v| v.principal == Subject::group("system:authenticated"))
        );
    }

    #[test]
    fn every_check_ignores_cluster_scoped_grants_in_a_namespace() {
        // Every authenticated user may get nodes, which live outside
        // namespaces, so no check may count it as access in payments.
        let extra = [
            r#"{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"app","namespace":"payments"}}"#,
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"node-reader"},"rules":[{"apiGroups":[""],"resources":["nodes"],"verbs":["get"]}]}"#,
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"node-reader"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"node-reader"},"subjects":[{"kind":"Group","name":"system:authenticated"}]}"#,
        ]
        .join("\n");
        let eval = load_engine_with(&extra).evaluate().expect("evaluate");
        let model = RbacAccessModel::from_store(&eval);
        let authenticated = Subject::group("system:authenticated");
        let flags = |violations: Vec<super::Violation>| {
            violations.iter().any(|v| v.principal == authenticated)
        };

        assert!(!flags(model.check_access_invariant(
            "payments",
            "nodes",
            "get",
            &[]
        )));
        assert!(!flags(model.check_namespace_isolation("payments", &[])));
        assert!(!flags(model.check_reaches(
            "payments",
            "",
            "nodes",
            "get",
            &[],
            true
        )));
        assert!(!flags(
            model.direct_violations("payments", "", "nodes", "get")
        ));
        assert!(
            model
                .paths_for_principal(&authenticated, Some(("payments", "", "nodes", "get")))
                .is_empty()
        );

        // Cluster-wide, the grant counts everywhere.
        assert!(flags(model.check_access_invariant("", "nodes", "get", &[])));
        assert!(flags(model.check_reaches(
            "",
            "",
            "nodes",
            "get",
            &[],
            true
        )));
        assert!(flags(model.direct_violations("", "", "nodes", "get")));
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
            model
                .role_rules
                .rules
                .keys()
                .any(|(kind, ..)| *kind == "Role"),
            "role_rule joined with policy_rule_perm"
        );
        assert!(
            model
                .role_rules
                .rules
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
        assert!(!model.subject_hops.is_empty(), "subject_escalation_hop");
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
        let shown: Vec<(&str, Vec<(Subject, String)>)> = imp
            .paths
            .iter()
            .map(|p| (p.binding_name.as_str(), p.hops.clone()))
            .collect();
        assert_eq!(
            shown,
            [(
                "admins",
                vec![(Subject::group("admins"), "impersonate".to_string())]
            )]
        );
    }

    /// A ClusterRole `name` with one rule, bound by a ClusterRoleBinding of the
    /// same name to one subject.
    fn bound_clusterrole(name: &str, resource: &str, verb: &str, subject: &str) -> String {
        format!(
            concat!(
                r#"{{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{{"name":"{name}"}},"rules":[{{"apiGroups":[""],"resources":["{resource}"],"verbs":["{verb}"]}}]}}"#,
                "\n",
                r#"{{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{{"name":"{name}"}},"roleRef":{{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"{name}"}},"subjects":[{subject}]}}"#,
                "\n",
            ),
            name = name,
            resource = resource,
            verb = verb,
            subject = subject,
        )
    }

    #[test]
    fn hop_chains_continue_through_an_impersonated_group() {
        // imp may only impersonate groups. Group execs may exec into any pod,
        // including one in demo running as demo:target, which holds
        // cluster-admin, as does kube-system:default in the fixture.
        let extra = [
            r#"{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"target","namespace":"demo"}}"#.to_string(),
            r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p","namespace":"demo"},"spec":{"serviceAccountName":"target","containers":[{"name":"c","image":"busybox"}]}}"#.to_string(),
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"target-admin"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},"subjects":[{"kind":"ServiceAccount","name":"target","namespace":"demo"}]}"#.to_string(),
            bound_clusterrole("exec", "pods/exec", "create", r#"{"kind":"Group","name":"execs"}"#),
            bound_clusterrole("imp", "groups", "impersonate", r#"{"kind":"User","name":"imp"}"#),
        ]
        .join("\n");
        let eval = load_engine_with(&extra).evaluate().expect("evaluate");
        let model = RbacAccessModel::from_store(&eval);

        let paths = model.paths_for_principal(&Subject::username("imp"), Some(("", "*", "*", "*")));
        let shown: Vec<(&str, Vec<(Subject, String)>)> = paths
            .iter()
            .map(|p| (p.binding_name.as_str(), p.hops.clone()))
            .collect();
        assert_eq!(
            shown,
            [
                (
                    "target-admin",
                    vec![
                        (Subject::group("execs"), "impersonate".to_string()),
                        (
                            Subject::username("system:serviceaccount:demo:target"),
                            "pod-exec".to_string()
                        ),
                    ]
                ),
                (
                    "cluster-admin",
                    vec![
                        (Subject::group("execs"), "impersonate".to_string()),
                        (
                            Subject::username("system:serviceaccount:kube-system:default"),
                            "pod-exec".to_string()
                        ),
                    ]
                )
            ]
        );
    }

    #[test]
    fn hops_to_a_user_and_a_group_with_the_same_name_stay_apart() {
        // imp may impersonate users and groups; the user twin and the group
        // twin may each read secrets.
        let extra = [
            bound_clusterrole(
                "twin-user",
                "secrets",
                "get",
                r#"{"kind":"User","name":"twin"}"#,
            ),
            bound_clusterrole(
                "twin-group",
                "secrets",
                "get",
                r#"{"kind":"Group","name":"twin"}"#,
            ),
            bound_clusterrole(
                "imp-users",
                "users",
                "impersonate",
                r#"{"kind":"User","name":"imp"}"#,
            ),
            bound_clusterrole(
                "imp-groups",
                "groups",
                "impersonate",
                r#"{"kind":"User","name":"imp"}"#,
            ),
        ]
        .join("\n");
        let eval = load_engine_with(&extra).evaluate().expect("evaluate");
        let model = RbacAccessModel::from_store(&eval);

        let paths =
            model.paths_for_principal(&Subject::username("imp"), Some(("", "", "secrets", "get")));
        let mut twin_hops: Vec<(Subject, &str)> = paths
            .iter()
            .filter(|p| p.binding_name.starts_with("twin-"))
            .map(|p| (p.hops[0].0.clone(), p.binding_name.as_str()))
            .collect();
        twin_hops.sort();
        assert_eq!(
            twin_hops,
            [
                (Subject::username("twin"), "twin-user"),
                (Subject::group("twin"), "twin-group"),
            ]
        );
        assert_eq!(Subject::group("twin").to_string(), "twin (group)");
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
        let shown: Vec<(&str, Vec<(Subject, String)>)> = execs
            .paths
            .iter()
            .map(|p| (p.binding_name.as_str(), p.hops.clone()))
            .collect();
        assert_eq!(
            shown,
            [(
                "target-admin",
                vec![(
                    Subject::username("system:serviceaccount:demo:target"),
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

    /// A RoleBinding in `namespace` naming alice, to ClusterRole `role`.
    fn alice_role_binding(namespace: &str, role: &str) -> String {
        format!(
            r#"{{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{{"name":"alice-{role}","namespace":"{namespace}"}},"roleRef":{{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"{role}"}},"subjects":[{{"kind":"User","name":"alice"}}]}}"#
        )
    }

    /// The (binding namespace, binding name) of each path shown for alice.
    fn alice_bindings(violations: &[super::Violation]) -> Vec<(String, String)> {
        let alice = violations
            .iter()
            .find(|v| v.principal == Subject::username("alice"))
            .expect("alice reported");
        alice
            .paths
            .iter()
            .map(|p| (p.binding_namespace.clone(), p.binding_name.clone()))
            .collect()
    }

    #[test]
    fn paths_show_only_role_bindings_in_the_queried_namespace() {
        // alice may read secrets in dev and in payments, each through its
        // own RoleBinding.
        let extra = [
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"secret-reader"},"rules":[{"apiGroups":[""],"resources":["secrets"],"verbs":["get"]}]}"#.to_string(),
            alice_role_binding("dev", "secret-reader"),
            alice_role_binding("payments", "secret-reader"),
        ]
        .join("\n");
        let eval = load_engine_with(&extra).evaluate().expect("evaluate");
        let model = RbacAccessModel::from_store(&eval);

        let reaches = model.check_reaches("payments", "", "secrets", "get", &[], true);
        assert_eq!(
            alice_bindings(&reaches),
            [("payments".to_string(), "alice-secret-reader".to_string())]
        );
        let direct = model.direct_violations("dev", "", "secrets", "get");
        assert_eq!(
            alice_bindings(&direct),
            [("dev".to_string(), "alice-secret-reader".to_string())]
        );
    }

    #[test]
    fn cluster_wide_paths_show_only_cluster_role_bindings() {
        // alice holds cluster-admin through a ClusterRoleBinding, and in dev
        // also through a RoleBinding, which grants nothing cluster-wide.
        let extra = [
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"alice-admin"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},"subjects":[{"kind":"User","name":"alice"}]}"#.to_string(),
            alice_role_binding("dev", "cluster-admin"),
        ]
        .join("\n");
        let eval = load_engine_with(&extra).evaluate().expect("evaluate");
        let model = RbacAccessModel::from_store(&eval);

        let cluster_admin = [(String::new(), "alice-admin".to_string())];
        assert_eq!(
            alice_bindings(&model.direct_violations("", "*", "*", "*")),
            cluster_admin
        );
        assert_eq!(
            alice_bindings(&model.check_reaches("", "*", "*", "*", &[], true)),
            cluster_admin
        );
    }
}
