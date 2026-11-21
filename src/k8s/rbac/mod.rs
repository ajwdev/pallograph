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
use serde::Serialize;

use crate::engine::EvalStore;

pub mod diff;
pub(crate) mod facts;
mod resource_scope;

use facts::{
    Permission, RbacWrite, RoleKey, Writer, ns_covers, parse_binding_subject, parse_strings,
    value_covers,
};
pub use facts::{PermissionTables, Subject, SubjectKind};

/// One grant a principal holds: a resource permission scoped to a namespace
/// (empty for cluster-wide).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PermissionEntry {
    pub api_group: String,
    pub resource: String,
    pub principal: Subject,
    pub namespace: String,
    pub verb: String,
}

/// Namespace or cluster scoped rolebinding
#[derive(Clone, Copy, Hash, Ord, PartialEq, PartialOrd, Serialize, Eq, Debug)]
pub enum BindingKind {
    RoleBinding,
    ClusterRoleBinding,
}

impl std::fmt::Display for BindingKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindingKind::RoleBinding => write!(f, "RoleBinding"),
            BindingKind::ClusterRoleBinding => write!(f, "ClusterRoleBinding"),
        }
    }
}

/// Namespace or cluster scoped role
#[derive(Clone, Copy, Hash, Ord, PartialEq, PartialOrd, Serialize, Eq, Debug)]
pub enum RoleKind {
    Role,
    ClusterRole,
}

impl std::fmt::Display for RoleKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoleKind::Role => write!(f, "Role"),
            RoleKind::ClusterRole => write!(f, "ClusterRole"),
        }
    }
}

impl RoleKind {
    /// The `roleRef.kind` string from a binding, or `None` for anything the
    /// API server would reject.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "Role" => Some(Self::Role),
            "ClusterRole" => Some(Self::ClusterRole),
            _ => None,
        }
    }
}

/// How one identity is assumed in a single escalation hop. `PodExec`,
/// `PodCreate` and `Token` apply only to ServiceAccounts (a pod running as
/// it, or its token); a principal of any kind can be reached by
/// impersonation. The `Mechanism` column of `pivot` in
/// rules/closure.mg.
#[derive(Clone, Copy, Hash, Ord, PartialEq, PartialOrd, Eq, Debug)]
pub enum ReachMechanism {
    PodExec,
    PodCreate,
    Token,
    Impersonate,
}

impl ReachMechanism {
    /// The order a hop by its own grants lists its mechanisms in.
    const GRANT_ORDER: [Self; 4] = [
        Self::PodExec,
        Self::Token,
        Self::PodCreate,
        Self::Impersonate,
    ];

    /// The label the reports show.
    pub fn label(self) -> &'static str {
        match self {
            ReachMechanism::PodExec => "pod-exec",
            ReachMechanism::PodCreate => "pod-create",
            ReachMechanism::Token => "token",
            ReachMechanism::Impersonate => "impersonate",
        }
    }

    /// The mechanism's name constant in the rules, e.g. "/pod_exec".
    pub fn name_constant(self) -> &'static str {
        match self {
            ReachMechanism::PodExec => "/pod_exec",
            ReachMechanism::PodCreate => "/pod_create",
            ReachMechanism::Token => "/token",
            ReachMechanism::Impersonate => "/impersonate",
        }
    }

    pub fn from_value(value: &Value) -> Option<Self> {
        match value {
            Value::Name(name) => Self::GRANT_ORDER
                .into_iter()
                .find(|mechanism| mechanism.name_constant() == name.as_str()),
            _ => None,
        }
    }
}

impl std::fmt::Display for ReachMechanism {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// The RBAC-write verb class that lets a principal grant itself a role:
/// `bind` an existing role, or `escalate` to a role with more permissions
/// than it already holds. From `rbac_verb_class` in rules/k8s_rbac_write.mg.
#[derive(Clone, Copy, Hash, Ord, PartialEq, PartialOrd, Eq, Debug)]
pub enum WriteMechanism {
    Bind,
    Escalate,
}

impl WriteMechanism {
    /// The verb as the rules and reports spell it.
    pub fn label(self) -> &'static str {
        match self {
            WriteMechanism::Bind => "bind",
            WriteMechanism::Escalate => "escalate",
        }
    }

    /// A write verb the rules emit, or `None` for anything else.
    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "bind" => Some(Self::Bind),
            "escalate" => Some(Self::Escalate),
            _ => None,
        }
    }
}

impl std::fmt::Display for WriteMechanism {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Clone)]
pub struct AccessPath {
    pub binding_kind: BindingKind,
    pub binding_namespace: String, // "" for ClusterRoleBinding
    pub binding_name: String,
    pub role_kind: RoleKind,
    pub role_name: String,
    // Escalation chain leading to this binding.
    // Each element is (identity, mechanism_used_to_reach_it).
    // Empty for direct grants (no escalation needed).
    pub hops: Vec<(Subject, String)>,
}

/// How a principal reaches a permission. Used to group violation output so
/// paths that are already held, reached by assuming another identity, and
/// reached by writing RBAC objects are shown apart rather than interleaved.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PathKind {
    /// A binding the principal already holds grants it; no escalation.
    Direct,
    /// Reached by assuming another identity or group (impersonate, pod-exec,
    /// pod-create, token), ending at a binding that identity holds.
    Escalation,
    /// Reached by writing RBAC objects: with `bind` or `escalate` the
    /// principal can grant itself the permission. The binding, and sometimes
    /// the role, do not exist yet (shown as "(new)").
    RbacWrite,
}

impl AccessPath {
    /// The last hop is a terminal RBAC-write step, pushed by
    /// `collect_rbac_write_paths` with a `WriteMechanism` label. Reach
    /// mechanism labels never parse as one, so the last hop classifies the
    /// path.
    fn ends_in_write(&self) -> bool {
        self.write_action().is_some()
    }

    /// Which tier this path belongs to.
    pub fn kind(&self) -> PathKind {
        if self.ends_in_write() {
            PathKind::RbacWrite
        } else if self.hops.is_empty() {
            PathKind::Direct
        } else {
            PathKind::Escalation
        }
    }

    /// Stable lowercase tag for machine output.
    pub fn kind_str(&self) -> &'static str {
        match self.kind() {
            PathKind::Direct => "direct",
            PathKind::Escalation => "escalation",
            PathKind::RbacWrite => "rbac_write",
        }
    }

    /// True when the path mints a new binding rather than reusing an existing
    /// one.
    pub fn creates_binding(&self) -> bool {
        self.binding_name == NEW_OBJECT
    }

    /// True when the path writes a new role with arbitrary rules rather than
    /// binding an existing one. A new role is equivalent to full access in its
    /// scope, so it subsumes any list of existing roles the writer could bind.
    pub fn creates_role(&self) -> bool {
        self.role_name == NEW_OBJECT
    }

    /// For a write path, the hops before the terminal `bind`/`escalate` hop:
    /// the chain reaching the writer, plus any prerequisite write step. For a
    /// non-write path, all hops.
    pub fn reach_prefix(&self) -> &[(Subject, String)] {
        if self.ends_in_write() {
            &self.hops[..self.hops.len() - 1]
        } else {
            &self.hops
        }
    }

    /// For a write path, the writer and the terminal write mechanism it uses.
    pub fn write_action(&self) -> Option<(&Subject, WriteMechanism)> {
        let (subject, mechanism) = self.hops.last()?;
        Some((subject, WriteMechanism::from_label(mechanism)?))
    }
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

/// Binding or role name shown for one a principal would create by writing
/// RBAC objects.
const NEW_OBJECT: &str = "(new)";

/// A write shown as an earlier step of a path, e.g. "bind ClusterRole
/// rbac-admin" or "bind Role pod-creator in ns1".
fn write_step_label(write: &RbacWrite) -> String {
    let role = if write.role.is_empty() {
        NEW_OBJECT
    } else {
        write.role.as_str()
    };

    let scope = match write.namespace.as_str() {
        "" => String::new(),
        "*" => " in every namespace".to_string(),
        namespace => format!(" in {namespace}"),
    };

    format!("{} {} {role}{scope}", write.mechanism, write.role_kind)
}

/// The path an `RbacWrite` adds after `hops`: the binding it creates or
/// updates and the role, "(new)" where it writes a new one.
fn write_path(write: &RbacWrite, hops: Vec<(Subject, String)>) -> AccessPath {
    let or_new = |name: &str| {
        if name.is_empty() {
            NEW_OBJECT.to_string()
        } else {
            name.to_string()
        }
    };

    AccessPath {
        binding_kind: if write.namespace.is_empty() {
            BindingKind::ClusterRoleBinding
        } else {
            BindingKind::RoleBinding
        },
        binding_namespace: write.namespace.clone(),
        binding_name: or_new(&write.binding),
        role_kind: write.role_kind,
        role_name: or_new(&write.role),
        hops,
    }
}

/// The identities and groups one hop reaches, each with the mechanisms that
/// reach it.
type Hops = BTreeMap<Subject, BTreeSet<ReachMechanism>>;

/// Where a `pivot` row starts: a binding subject's own grants
/// (Source `/grant`), or a role a writer can grant itself (`/rbac_write`).
enum HopStart {
    Grant(Subject),
    RbacWrite(Writer),
}

/// `pivot(Subject, System, Kind, Target, System, TargetKind,
/// Mechanism, Source)` rows, split by source. Targets are principals
/// (`Subject::principal`), so a User subject naming a ServiceAccount's
/// username is that ServiceAccount.
fn parse_subject_hops(rows: &[Vec<Value>]) -> (HashMap<Subject, Hops>, HashMap<Writer, Hops>) {
    let mut grant_hops: HashMap<Subject, Hops> = HashMap::new();
    let mut write_hops: HashMap<Writer, Hops> = HashMap::new();
    for row in rows.iter().filter(|row| is_k8s_rbac_hop(row)) {
        let parsed = match row.as_slice() {
            [
                Value::String(name),
                _,
                kind,
                Value::String(target),
                _,
                target_kind,
                mechanism,
                Value::Name(source),
            ] => (|| {
                let start = match source.as_str() {
                    "/grant" => {
                        HopStart::Grant(Subject::new(SubjectKind::from_value(kind)?, name.clone()))
                    }
                    "/rbac_write" => HopStart::RbacWrite(facts::writer(name, kind)?),
                    _ => return None,
                };
                let target =
                    Subject::new(SubjectKind::from_value(target_kind)?, target.clone()).principal();
                Some((start, target, ReachMechanism::from_value(mechanism)?))
            })(),
            _ => None,
        };
        let Some((start, target, mechanism)) = parsed else {
            facts::unexpected_row("pivot", row);
            continue;
        };
        let hops = match start {
            HopStart::Grant(subject) => grant_hops.entry(subject).or_default(),
            HopStart::RbacWrite(writer) => write_hops.entry(writer).or_default(),
        };
        hops.entry(target).or_default().insert(mechanism);
    }
    (grant_hops, write_hops)
}

/// Whether a `pivot` row is one this model reads: both ends in
/// Kubernetes, from a binding subject or writer. Other systems' hops, and
/// the `/impersonated_group` hops only the closure walks, are left out.
fn is_k8s_rbac_hop(row: &[Value]) -> bool {
    let k8s = |value: &Value| matches!(value, Value::Name(name) if name.as_str() == "/k8s");
    match row {
        [_, system, Value::Name(kind), _, target_system, ..] => {
            k8s(system) && k8s(target_system) && kind.as_str() != "/impersonated_group"
        }
        _ => true,
    }
}

/// The hops of several subjects or writers, as one.
fn merge_hops<'a>(
    all: impl Iterator<Item = &'a Hops>,
) -> BTreeMap<&'a Subject, BTreeSet<ReachMechanism>> {
    let mut merged: BTreeMap<&Subject, BTreeSet<ReachMechanism>> = BTreeMap::new();
    for hops in all {
        for (target, mechanisms) in hops {
            merged.entry(target).or_default().extend(mechanisms);
        }
    }
    merged
}

/// How one hop reaches `target`, e.g. "pod-exec, token": by the
/// mechanisms its own grants allow (`granted`), or, when they allow none,
/// by those of roles gained by writing RBAC objects (`gained`), e.g.
/// "pod-create after RBAC write". A group is always reached by
/// impersonation.
fn mechanism(
    target: &Subject,
    granted: Option<&BTreeSet<ReachMechanism>>,
    gained: Option<&BTreeSet<ReachMechanism>>,
) -> String {
    if target.kind == SubjectKind::Group {
        return ReachMechanism::Impersonate.label().to_string();
    }
    if let Some(granted) = granted {
        let labels: Vec<&str> = ReachMechanism::GRANT_ORDER
            .iter()
            .filter(|mechanism| granted.contains(mechanism))
            .map(|mechanism| mechanism.label())
            .collect();
        return labels.join(", ");
    }
    let mut labels: Vec<&str> = gained.into_iter().flatten().map(|m| m.label()).collect();
    labels.sort_unstable();
    format!("{} after RBAC write", labels.join(", "))
}

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
    /// `pivot` with Source `/grant`: what each binding subject's own
    /// grants reach in one hop.
    grant_hops: HashMap<Subject, Hops>,
    /// `pivot` with Source `/rbac_write`: what each writer reaches in
    /// one hop through a role it can grant itself by writing RBAC objects.
    write_hops: HashMap<Writer, Hops>,
    /// `rbac_write_binding_direct`: the writes each writer can make in one
    /// request, which explain a path best.
    rbac_writes_direct: HashMap<Writer, HashSet<RbacWrite>>,
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

        let (grant_hops, write_hops) = parse_subject_hops(&scan("pivot"));

        let mut rbac_writes_direct: HashMap<Writer, HashSet<RbacWrite>> = HashMap::new();
        for (writer, write) in facts::parse_rbac_write_binding(
            "rbac_write_binding_direct",
            &scan("rbac_write_binding_direct"),
        ) {
            rbac_writes_direct.entry(writer).or_default().insert(write);
        }

        Self {
            include_builtins: false,
            tables,
            subject_bindings,
            binding_roles,
            grant_hops,
            write_hops,
            rbac_writes_direct,
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
            && (self.include_builtins || !crate::k8s::builtins::is_builtin(&principal.name))
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
            .principals_with_direct(|grant| {
                ns_covers(&grant.namespace, namespace)
                    && (namespace.is_empty()
                        || resource_scope::can_apply_in_namespace(&grant.api_group, resource))
                    && value_covers(&grant.resource, resource)
                    && value_covers(&grant.verb, verb)
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
                .filter(|grant| {
                    ns_covers(&grant.namespace, namespace)
                        && resource_scope::can_apply_in_namespace(&grant.api_group, &grant.resource)
                })
                .map(|grant| (grant.resource.as_str(), grant.verb.as_str()))
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
    /// escalation, or by writing RBAC objects (`rbac_write_binding`).
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

    /// Return binding/role paths for `principal`.
    ///
    /// Direct bindings are always included. Escalation via-paths are included only
    /// when `perm_filter` is `Some((namespace, apigroup, resource, verb))`, and only for targets that
    /// actually satisfy that query (`permission_covers`). Targets are identities from `controls_identity` and groups
    /// from `controls_group`, or their `group_` counterparts when `principal`
    /// is a group. Self-referential via entries are always excluded, except
    /// for a role `principal` can grant itself by writing RBAC objects,
    /// shown as one hop from `principal` (`collect_rbac_write_paths`).
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

        // Likewise for a role the principal can grant itself by writing RBAC
        // objects: having it, the principal also reaches every other
        // identity, so chains through them would be noise.
        self.collect_rbac_write_paths(
            &self.tables.login_writers(principal),
            &[],
            query,
            &mut paths,
        );
        if !paths.is_empty() {
            return paths;
        }

        // Principal only reaches the permission via escalation chains, to
        // identities and groups whose own grants (not what they reach through
        // escalation) match the query. This breaks mutual-impersonation
        // cycles: a target that only has escalation access won't appear
        // here, so cluster-admin principals don't endlessly list each other
        // as via-paths.
        let tree = self.escalation_tree(principal);
        let target_chains: Vec<(&Subject, Vec<Subject>, Vec<(Subject, String)>)> = self
            .escalation_targets(principal)
            .filter(|target| self.target_has_permission(target, query))
            .map(|target| {
                (
                    target,
                    self.tables.target_subjects(target),
                    hop_chain(&tree, principal, target),
                )
            })
            .collect();

        // The identities and groups that appear as the final hop of some chain.
        let final_hops: HashSet<&Subject> = target_chains
            .iter()
            .filter_map(|(_, _, hops)| hops.last().map(|(hop, _)| hop))
            .collect();

        // Suppress redundant longer paths: if a chain's intermediate hops include
        // another final-hop target, the longer chain adds no new information
        // (e.g. A→default→admin@ when A→default is already shown). This also tames
        // the path explosion among mutually-reachable cluster-admins; clients add
        // further display-only subsumption on top.
        for (_, target_subjects, hops) in &target_chains {
            let intermediates_are_endpoints = hops[..hops.len().saturating_sub(1)]
                .iter()
                .any(|(hop, _)| final_hops.contains(hop));
            if intermediates_are_endpoints {
                continue;
            }
            self.collect_binding_paths(target_subjects, hops.clone(), perm_filter, &mut paths);
        }

        // Roles a target at the end of a chain can grant itself by writing
        // RBAC objects. A target whose own bindings grant the query is
        // explained by them already.
        for (target, target_subjects, hops) in &target_chains {
            let bindings_cover = self
                .tables
                .grants_of(target_subjects.clone())
                .any(|granted| permission_covers(granted, query));
            if !bindings_cover {
                let writers = self.tables.target_writers(target);
                self.collect_rbac_write_paths(&writers, hops, query, &mut paths);
            }
        }
        paths
    }

    /// Append, for each of `writers` that can grant itself a role covering
    /// `query` by writing RBAC objects (`rbac_write_binding`), the path after
    /// `hops`: a hop to the writer labeled with the verb that lets the write
    /// through (bind or escalate), then the binding it would create or
    /// update and the role.
    ///
    /// A write the writer can make in one request
    /// (`rbac_write_binding_direct`) explains the path best, so those are
    /// shown when any covers `query`. Otherwise the covering writes need
    /// earlier writes that gain more RBAC permissions, and one such first
    /// write is shown as a hop before them: "bind ClusterRole rbac-admin".
    fn collect_rbac_write_paths(
        &self,
        writers: &[Writer],
        hops: &[(Subject, String)],
        query: PermissionPattern<'_>,
        out: &mut Vec<AccessPath>,
    ) {
        for writer in writers {
            let Some(writes) = self.tables.rbac_writes.get(writer) else {
                continue;
            };
            let direct = self.rbac_writes_direct.get(writer);
            let is_direct = |write: &RbacWrite| direct.is_some_and(|set| set.contains(write));
            let covering: Vec<&RbacWrite> = writes
                .iter()
                .filter(|write| self.write_covers(write, query))
                .collect();
            let (shown, first_step): (Vec<&RbacWrite>, Option<&RbacWrite>) =
                if covering.iter().any(|write| is_direct(write)) {
                    let shown = covering
                        .into_iter()
                        .filter(|write| is_direct(write))
                        .collect();
                    (shown, None)
                } else {
                    // A write it can make now whose role grants RBAC
                    // permissions.
                    let first_step = writes.iter().find(|write| {
                        is_direct(write)
                            && write
                                .permissions(&self.tables.role_rules)
                                .iter()
                                .any(|p| value_covers(&p.api_group, "rbac.authorization.k8s.io"))
                    });
                    (covering, first_step)
                };

            for write in shown {
                let mut chain = hops.to_vec();
                if let Some(step) = first_step {
                    chain.push((writer.subject.clone(), write_step_label(step)));
                }
                chain.push((writer.subject.clone(), write.mechanism.to_string()));
                out.push(write_path(write, chain));
            }
        }
    }

    /// The permissions of `write` include one covering `query`.
    fn write_covers(&self, write: &RbacWrite, query: PermissionPattern<'_>) -> bool {
        write
            .permissions(&self.tables.role_rules)
            .iter()
            .any(|granted| permission_covers(granted, query))
    }

    /// The shortest escalation chains from `principal`, as a tree: for each
    /// identity or group reached, the node it was reached from and the
    /// mechanism of that hop.
    ///
    /// Breadth-first, so each chain has the fewest hops and cycles in
    /// mutual-escalation graphs are harmless. It follows the rules'
    /// closure (rules/closure.mg): `principal` acts with all its subjects
    /// (`subjects_of`), an identity reached on the way only with its
    /// `assumed_subject` subjects, and a group with its own grants. From
    /// each, a hop is a `pivot` of one of those subjects (Source
    /// `/grant`) or of one of its writers (`/rbac_write`).
    fn escalation_tree(&self, principal: &Subject) -> HashMap<Subject, (Subject, String)> {
        let mut tree: HashMap<Subject, (Subject, String)> = HashMap::new();
        let mut queue = VecDeque::from([principal.clone()]);

        while let Some(node) = queue.pop_front() {
            let (subjects, writers) = if node == *principal {
                (
                    self.tables.subjects_of(&node),
                    self.tables.login_writers(&node),
                )
            } else {
                (
                    self.tables.target_subjects(&node),
                    self.tables.target_writers(&node),
                )
            };
            let granted = merge_hops(subjects.iter().filter_map(|s| self.grant_hops.get(s)));
            let gained = merge_hops(writers.iter().filter_map(|w| self.write_hops.get(w)));

            // Identities before groups, each sorted by name, so ties between
            // equally short chains resolve the same way on every run.
            let targets: BTreeSet<&Subject> =
                granted.keys().chain(gained.keys()).copied().collect();
            let (groups, identities): (Vec<&Subject>, Vec<&Subject>) = targets
                .into_iter()
                .partition(|target| target.kind == SubjectKind::Group);

            for target in identities.into_iter().chain(groups) {
                if target == principal || tree.contains_key(target) {
                    continue;
                }
                let mechanism = mechanism(target, granted.get(target), gained.get(target));
                tree.insert(target.clone(), (node.clone(), mechanism));
                queue.push_back(target.clone());
            }
        }
        tree
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
        self.tables
            .role_rules
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
        let key = (RoleKind::ClusterRole, String::new(), role_name.to_string());
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
        let key = (
            RoleKind::Role,
            role_namespace.to_string(),
            role_name.to_string(),
        );
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
        let mut found: BTreeSet<(&str, &str, RoleKind, &str)> = BTreeSet::new();
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
                    // The API server rejects any other roleRef kind.
                    let Some(role_kind) = RoleKind::from_name(role_kind) else {
                        continue;
                    };
                    if let Some((_, query_api_group, query_resource, query_verb)) = perm_filter {
                        let matches = if role_kind == RoleKind::Role {
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
                    BindingKind::ClusterRoleBinding
                } else {
                    BindingKind::RoleBinding
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
    let Permission {
        namespace,
        api_group,
        resource,
        verb,
    } = granted;

    ns_covers(namespace, query.namespace)
        && (query.namespace.is_empty()
            || resource_scope::can_apply_in_namespace(query.apigroup, query.resource))
        && value_covers(api_group, query.apigroup)
        && value_covers(resource, query.resource)
        && value_covers(verb, query.verb)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::Path;

    use mangle_common::Value;
    use mangle_interpreter::MemStore;

    use super::{Permission, RbacAccessModel, ReachMechanism, RoleKind, Subject, SubjectKind};
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
                let grants = if p.role_kind == RoleKind::Role {
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
    /// `serviceaccounts/token create`, so `granted_pivot(src, dst)` holds.
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
                .tables
                .role_rules
                .rules
                .keys()
                .any(|(kind, ..)| *kind == RoleKind::Role),
            "role_rule joined with policy_rule_perm"
        );
        assert!(
            model
                .tables
                .role_rules
                .rules
                .keys()
                .any(|(kind, ..)| *kind == RoleKind::ClusterRole),
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
        let mechanisms: BTreeSet<ReachMechanism> = model
            .grant_hops
            .values()
            .flat_map(|hops| hops.values().flatten().copied())
            .collect();
        assert_eq!(
            mechanisms.len(),
            ReachMechanism::GRANT_ORDER.len(),
            "pivot mechanisms: {mechanisms:?}"
        );
        assert!(
            model.tables.effective_entries().len() > model.tables.direct_entries().len(),
            "escalation added nothing to the effective entries"
        );
        assert!(
            model
                .tables
                .direct_grants(&Subject::username("admin@example.com"))
                .any(|granted| {
                    *granted
                        == Permission {
                            namespace: String::new(),
                            api_group: "*".into(),
                            resource: "*".into(),
                            verb: "*".into(),
                        }
                }),
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

    #[test]
    fn rbac_writes_reach_cluster_admin() {
        // ns1:sa-a may bind and escalate clusterroles and create
        // clusterrolebindings, without holding */*/*: binding cluster-admin
        // to itself reaches it, shown as a bind hop from sa-a to a new
        // ClusterRoleBinding. ns1:sa-b may only create clusterrolebindings,
        // which grants nothing it does not already hold.
        let eval = load_engine_with(concat!(
            r#"{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"sa-a","namespace":"ns1"}}"#,
            "\n",
            r#"{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"sa-b","namespace":"ns1"}}"#,
            "\n",
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"rbac-manager"},"rules":[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"verbs":["bind","escalate"]},{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterrolebindings"],"verbs":["create"]}]}"#,
            "\n",
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"sa-a"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"rbac-manager"},"subjects":[{"kind":"ServiceAccount","name":"sa-a","namespace":"ns1"}]}"#,
            "\n",
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"binding-creator"},"rules":[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterrolebindings"],"verbs":["create"]}]}"#,
            "\n",
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"sa-b"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"binding-creator"},"subjects":[{"kind":"ServiceAccount","name":"sa-b","namespace":"ns1"}]}"#,
            "\n",
        ))
        .evaluate()
        .expect("evaluate");
        let model = RbacAccessModel::from_store(&eval);
        let sa_a = Subject::username("system:serviceaccount:ns1:sa-a");
        let sa_b = Subject::username("system:serviceaccount:ns1:sa-b");

        assert!(
            model
                .direct_violations("", "*", "*", "*")
                .iter()
                .all(|v| v.principal != sa_a),
            "sa-a holds no direct */*/* grant"
        );
        let via = model.check_reaches("", "*", "*", "*", &[], false);
        let principals: Vec<&Subject> = via.iter().map(|v| &v.principal).collect();
        assert!(!principals.contains(&&sa_b), "sa-b in {principals:?}");
        let found = via
            .iter()
            .find(|v| v.principal == sa_a)
            .unwrap_or_else(|| panic!("sa-a missing from {principals:?}"));
        let shown: Vec<(&str, &str, Vec<(Subject, String)>)> = found
            .paths
            .iter()
            .map(|p| {
                (
                    p.binding_name.as_str(),
                    p.role_name.as_str(),
                    p.hops.clone(),
                )
            })
            .collect();
        assert_eq!(
            shown,
            [(
                "(new)",
                "cluster-admin",
                vec![(sa_a.clone(), "bind".to_string())]
            )]
        );
    }

    /// The paths shown for `principal` reaching `(namespace, *, *, *)`, as
    /// (binding namespace, binding, role, hops).
    fn shown_paths(
        model: &RbacAccessModel,
        principal: &Subject,
        namespace: &str,
    ) -> Option<Vec<(String, String, String, Vec<(Subject, String)>)>> {
        let via = model.check_reaches(namespace, "*", "*", "*", &[], false);
        let found = via.iter().find(|v| v.principal == *principal)?;
        Some(
            found
                .paths
                .iter()
                .map(|p| {
                    (
                        p.binding_namespace.clone(),
                        p.binding_name.clone(),
                        p.role_name.clone(),
                        p.hops.clone(),
                    )
                })
                .collect(),
        )
    }

    /// The writes binding subject `name` holds through ClusterRole `role`
    /// with `rules`, bound cluster-wide.
    fn sa_grant(name: &str, role: &str, rules: &str) -> String {
        format!(
            concat!(
                r#"{{"apiVersion":"v1","kind":"ServiceAccount","metadata":{{"name":"{name}","namespace":"ns1"}}}}"#,
                "\n",
                r#"{{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{{"name":"{role}"}},"rules":{rules}}}"#,
                "\n",
                r#"{{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{{"name":"{role}"}},"roleRef":{{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"{role}"}},"subjects":[{{"kind":"ServiceAccount","name":"{name}","namespace":"ns1"}}]}}"#,
                "\n",
            ),
            name = name,
            role = role,
            rules = rules,
        )
    }

    #[test]
    fn creating_pods_as_an_rbac_writer_reaches_cluster_admin() {
        // ns1:x can bind cluster-admin to itself. deployer may create pods
        // in ns1, so it can run one as x: deployer reaches cluster-admin
        // through x's bind, shown as a pod-create hop to x and then x's
        // bind.
        let mut extra = sa_grant(
            "x",
            "binder",
            r#"[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"verbs":["bind"]},{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterrolebindings"],"verbs":["create"]}]"#,
        );
        extra.push_str(concat!(
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"pod-creator","namespace":"ns1"},"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["create"]}]}"#,
            "\n",
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"deployer","namespace":"ns1"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"pod-creator"},"subjects":[{"kind":"User","name":"deployer"}]}"#,
            "\n",
        ));
        let eval = load_engine_with(&extra).evaluate().expect("evaluate");
        let model = RbacAccessModel::from_store(&eval);
        let x = Subject::username("system:serviceaccount:ns1:x");

        assert_eq!(
            shown_paths(&model, &Subject::username("deployer"), ""),
            Some(vec![(
                String::new(),
                "(new)".to_string(),
                "cluster-admin".to_string(),
                vec![
                    (x.clone(), "pod-create".to_string()),
                    (x.clone(), "bind".to_string())
                ]
            )])
        );
    }

    #[test]
    fn rbac_writes_in_a_namespace_stay_there() {
        // In ns1, sa-a may create RoleBindings and bind ClusterRoles: it
        // reaches everything in ns1 through a new RoleBinding of
        // cluster-admin, and nothing cluster-wide.
        let extra = concat!(
            r#"{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"sa-a","namespace":"ns1"}}"#,
            "\n",
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"ns-binder","namespace":"ns1"},"rules":[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"verbs":["bind"]},{"apiGroups":["rbac.authorization.k8s.io"],"resources":["rolebindings"],"verbs":["create"]}]}"#,
            "\n",
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"ns-binder","namespace":"ns1"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"ns-binder"},"subjects":[{"kind":"ServiceAccount","name":"sa-a","namespace":"ns1"}]}"#,
            "\n",
        );
        let eval = load_engine_with(extra).evaluate().expect("evaluate");
        let model = RbacAccessModel::from_store(&eval);
        let sa_a = Subject::username("system:serviceaccount:ns1:sa-a");

        assert_eq!(shown_paths(&model, &sa_a, ""), None);
        assert_eq!(shown_paths(&model, &sa_a, "ns2"), None);
        assert_eq!(
            shown_paths(&model, &sa_a, "ns1"),
            Some(vec![(
                "ns1".to_string(),
                "(new)".to_string(),
                "cluster-admin".to_string(),
                vec![(sa_a.clone(), "bind".to_string())]
            )])
        );
    }

    #[test]
    fn chained_rbac_writes_show_the_first_write() {
        // ns1:sa-a may create ClusterRoleBindings and bind only rbac-admin,
        // which allows binding any ClusterRole. The path to cluster-admin
        // shows binding rbac-admin first.
        let mut extra = sa_grant(
            "sa-a",
            "rbac-admin-binder",
            r#"[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"resourceNames":["rbac-admin"],"verbs":["bind"]},{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterrolebindings"],"verbs":["create"]}]"#,
        );
        extra.push_str(concat!(
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"rbac-admin"},"rules":[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"verbs":["bind"]}]}"#,
            "\n",
        ));
        let eval = load_engine_with(&extra).evaluate().expect("evaluate");
        let model = RbacAccessModel::from_store(&eval);
        let sa_a = Subject::username("system:serviceaccount:ns1:sa-a");

        let paths = shown_paths(&model, &sa_a, "").expect("sa-a reaches cluster-admin");
        assert!(
            paths.contains(&(
                String::new(),
                "(new)".to_string(),
                "cluster-admin".to_string(),
                vec![
                    (sa_a.clone(), "bind ClusterRole rbac-admin".to_string()),
                    (sa_a.clone(), "bind".to_string())
                ]
            )),
            "{paths:?}"
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
    fn hop_chains_reach_a_named_group_through_whoever_may_impersonate_it() {
        // imp may impersonate the user bob and the group ops. bob holds a
        // grant of his own: impersonate the group admins, which may read
        // secrets. So imp reaches admins through bob, not directly.
        let extra = [
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"imp"},"rules":[{"apiGroups":[""],"resources":["users"],"resourceNames":["bob"],"verbs":["impersonate"]},{"apiGroups":[""],"resources":["groups"],"resourceNames":["ops"],"verbs":["impersonate"]}]}"#.to_string(),
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"imp"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"imp"},"subjects":[{"kind":"User","name":"imp"}]}"#.to_string(),
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"bob"},"rules":[{"apiGroups":[""],"resources":["groups"],"resourceNames":["admins"],"verbs":["impersonate"]}]}"#.to_string(),
            r#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"bob"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"bob"},"subjects":[{"kind":"User","name":"bob"}]}"#.to_string(),
            bound_clusterrole(
                "admins-secrets",
                "secrets",
                "get",
                r#"{"kind":"Group","name":"admins"}"#,
            ),
            bound_clusterrole("ops-nodes", "nodes", "get", r#"{"kind":"Group","name":"ops"}"#),
        ]
        .join("\n");
        let eval = load_engine_with(&extra).evaluate().expect("evaluate");
        let model = RbacAccessModel::from_store(&eval);

        let paths =
            model.paths_for_principal(&Subject::username("imp"), Some(("", "", "secrets", "get")));
        let shown: Vec<Vec<(Subject, String)>> = paths
            .iter()
            .filter(|p| p.binding_name == "admins-secrets")
            .map(|p| p.hops.clone())
            .collect();
        assert_eq!(
            shown,
            [vec![
                (Subject::username("bob"), "impersonate".to_string()),
                (Subject::group("admins"), "impersonate".to_string()),
            ]]
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
