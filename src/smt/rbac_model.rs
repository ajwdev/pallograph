// RBAC model for Z3 using RecFuncDecl.
//
// Mangle provides the primitive IDB facts: role/binding relations,
// ClusterRole aggregation closure, group memberships, escalation closure.
// This module assembles those facts into two Z3 functions:
//
//   can(principal, namespace, apigroup, resource, verb) → Bool
//     True when the RBAC binding chain grants the permission.
//     Encodes three Kubernetes binding paths:
//       1. RoleBinding → Role
//       2. RoleBinding → ClusterRole (namespace-scoped)
//       3. ClusterRoleBinding → ClusterRole (applies in every namespace)
//     Wildcard matching ("*" in any position) is modeled in Z3 via `matches`.
//
//   effective_can(principal, namespace, resource, verb) → Bool
//     Like can/5 but collapses apiGroup and folds in escalation paths from
//     Mangle's `controls_identity` transitive closure.
//
// Both functions are defined as Z3 RecFuncDecls: finite case analyses with no
// quantifiers. This avoids the quantifier-instantiation overhead of the
// forall-axiom approach, which is prohibitively slow for string theory.
//
// Wildcard semantics live in Z3: `matches(needle, pat)` expresses
// `pat == "*" ∨ needle == pat`. Z3 simplifies `matches(x, "*")` to `true`
// and `matches("pods", "pods")` to `true` at construction time.

use std::collections::{HashMap, HashSet};

use mangle_common::Value;
use z3::ast::{Ast, Bool};
use z3::ast::String as Z3String;
use z3::{RecFuncDecl, Sort};

use crate::engine::EvalStore;
use super::SmtEncoder;

impl<'ctx> SmtEncoder<'ctx> {
    /// Load Mangle RBAC primitives and define `can` and `effective_can` as
    /// closed Z3 functions via RecFuncDecl.
    pub fn assert_rbac_axioms(&mut self, store: &EvalStore) {
        self.assert_rbac_axioms_named(|rel| store.scan(rel).to_vec(), "");
    }

    /// Same as `assert_rbac_axioms` but reads from a saved `Snapshot` instead
    /// of a live eval store. Useful for differential access analysis.
    pub fn assert_rbac_axioms_from_snapshot(&mut self, snap: &crate::snapshot::Snapshot) {
        self.assert_rbac_axioms_named(|rel| snap.scan_rel(rel), "");
    }

    /// Like `assert_rbac_axioms` but registers all predicates under a name suffix.
    /// Defines `can_<suffix>` and `effective_can_<suffix>` instead of bare names.
    /// Enables two snapshots to coexist in one solver for differential queries.
    pub fn assert_rbac_axioms_as(&mut self, store: &EvalStore, suffix: &str) {
        self.assert_rbac_axioms_named(|rel| store.scan(rel).to_vec(), suffix);
    }

    /// Like `assert_rbac_axioms_from_snapshot` but registers predicates under a suffix.
    pub fn assert_rbac_axioms_from_snapshot_as(&mut self, snap: &crate::snapshot::Snapshot, suffix: &str) {
        self.assert_rbac_axioms_named(|rel| snap.scan_rel(rel), suffix);
    }

    fn assert_rbac_axioms_named<F: Fn(&str) -> Vec<Vec<Value>>>(&mut self, scan: F, suffix: &str) {
        let subject_in_rb = compute_subject_in_rb(&scan);
        let subject_in_crb = compute_subject_in_crb(&scan);
        let can_entries = compute_can_entries(&scan, &subject_in_rb, &subject_in_crb);
        let eff_entries = compute_effective_can_entries(&scan, &can_entries);

        // Load the Mangle primitives as ground facts under namespaced names to avoid
        // collisions when multiple snapshots are loaded into the same encoder.
        for rel in &[
            "role_perm",
            "clusterrole_perm",
            "rolebinding_roleref",
            "clusterrolebinding_roleref",
            "user_groups",
            "controls_identity",
        ] {
            self.load_relation(&fn_name(rel, suffix), &scan(rel));
        }
        self.load_relation(&fn_name("subject_in_rb", suffix), &subject_in_rb);
        self.load_relation(&fn_name("subject_in_crb", suffix), &subject_in_crb);

        // Build and register the RecFuncDecl definitions under suffixed names.
        let can_fn = build_can_rec_func(self.ctx, &fn_name("can", suffix), &can_entries);
        let eff_fn = build_effective_can_rec_func(self.ctx, &fn_name("effective_can", suffix), &eff_entries);
        self.rec_decls.insert(fn_name("can", suffix), can_fn);
        self.rec_decls.insert(fn_name("effective_can", suffix), eff_fn);
        self.can_entries.insert(suffix.to_string(), can_entries);
        self.eff_entries.insert(suffix.to_string(), eff_entries);
    }
}

/// Returns `base` when suffix is empty, `base_suffix` otherwise.
pub(crate) fn fn_name(base: &str, suffix: &str) -> String {
    if suffix.is_empty() {
        base.to_string()
    } else {
        format!("{base}_{suffix}")
    }
}

// ---- RecFuncDecl builders ----

/// `can(p, ns, ag, r, v)` — true when the binding chain grants the permission.
/// Body: big OR of `(p == P ∧ ns == NS ∧ matches(ag, AG) ∧ matches(r, R) ∧ matches(v, V))`
/// for each entry derived from the Mangle binding/role join.
fn build_can_rec_func<'ctx>(
    ctx: &'ctx z3::Context,
    name: &str,
    entries: &[(String, String, String, String, String)],
) -> RecFuncDecl<'ctx> {
    let str_sort = Sort::string(ctx);
    let domain = [&str_sort, &str_sort, &str_sort, &str_sort, &str_sort];
    let can_fn = RecFuncDecl::new(ctx, name, &domain, &Sort::bool(ctx));

    // Use name-prefixed formal parameter names to avoid Z3 constant aliasing
    // when two RecFuncDecls with different names are built in the same context.
    let (pn, nsn, agn, rn, vn) = (
        format!("_{name}_p"),
        format!("_{name}_ns"),
        format!("_{name}_ag"),
        format!("_{name}_r"),
        format!("_{name}_v"),
    );
    let p_var = Z3String::new_const(ctx, pn.as_str());
    let ns_var = Z3String::new_const(ctx, nsn.as_str());
    let ag_var = Z3String::new_const(ctx, agn.as_str());
    let r_var = Z3String::new_const(ctx, rn.as_str());
    let v_var = Z3String::new_const(ctx, vn.as_str());

    let wildcard = Z3String::from_str(ctx, "*").unwrap();
    let matches = |needle: &Z3String<'ctx>, pat_str: &str| -> Bool<'ctx> {
        let pat = Z3String::from_str(ctx, pat_str).unwrap();
        // pat == "*"  →  always matches; simplifies to true at construction.
        // Otherwise: needle == pat.
        Bool::or(ctx, &[&pat._eq(&wildcard), &needle._eq(&pat)])
    };

    let clauses: Vec<Bool<'ctx>> = entries
        .iter()
        .map(|(pe, nse, age, re, ve)| {
            let pe_z3 = Z3String::from_str(ctx, pe).unwrap();
            let nse_z3 = Z3String::from_str(ctx, nse).unwrap();
            Bool::and(ctx, &[
                &p_var._eq(&pe_z3),
                &ns_var._eq(&nse_z3),
                &matches(&ag_var, age),
                &matches(&r_var, re),
                &matches(&v_var, ve),
            ])
        })
        .collect();

    let body = if clauses.is_empty() {
        Bool::from_bool(ctx, false)
    } else {
        Bool::or(ctx, &clauses.iter().collect::<Vec<_>>())
    };

    can_fn.add_def(
        &[&p_var as &dyn Ast, &ns_var as &dyn Ast, &ag_var as &dyn Ast, &r_var as &dyn Ast, &v_var as &dyn Ast],
        &body,
    );
    can_fn
}

/// `effective_can(p, ns, r, v)` — like can/5 but apiGroup-collapsed and
/// escalation-aware (includes permissions reachable via controls_identity).
/// Body: big OR of `(p == P ∧ ns == NS ∧ matches(r, R) ∧ matches(v, V))`.
fn build_effective_can_rec_func<'ctx>(
    ctx: &'ctx z3::Context,
    name: &str,
    entries: &[(String, String, String, String)],
) -> RecFuncDecl<'ctx> {
    let str_sort = Sort::string(ctx);
    let domain = [&str_sort, &str_sort, &str_sort, &str_sort];
    let eff_fn = RecFuncDecl::new(ctx, name, &domain, &Sort::bool(ctx));

    let (pn, nsn, rn, vn) = (
        format!("_{name}_p"),
        format!("_{name}_ns"),
        format!("_{name}_r"),
        format!("_{name}_v"),
    );
    let p_var = Z3String::new_const(ctx, pn.as_str());
    let ns_var = Z3String::new_const(ctx, nsn.as_str());
    let r_var = Z3String::new_const(ctx, rn.as_str());
    let v_var = Z3String::new_const(ctx, vn.as_str());

    let wildcard = Z3String::from_str(ctx, "*").unwrap();
    let matches = |needle: &Z3String<'ctx>, pat_str: &str| -> Bool<'ctx> {
        let pat = Z3String::from_str(ctx, pat_str).unwrap();
        Bool::or(ctx, &[&pat._eq(&wildcard), &needle._eq(&pat)])
    };

    let clauses: Vec<Bool<'ctx>> = entries
        .iter()
        .map(|(pe, nse, re, ve)| {
            let pe_z3 = Z3String::from_str(ctx, pe).unwrap();
            let nse_z3 = Z3String::from_str(ctx, nse).unwrap();
            Bool::and(ctx, &[
                &p_var._eq(&pe_z3),
                &ns_var._eq(&nse_z3),
                &matches(&r_var, re),
                &matches(&v_var, ve),
            ])
        })
        .collect();

    let body = if clauses.is_empty() {
        Bool::from_bool(ctx, false)
    } else {
        Bool::or(ctx, &clauses.iter().collect::<Vec<_>>())
    };

    eff_fn.add_def(
        &[&p_var as &dyn Ast, &ns_var as &dyn Ast, &r_var as &dyn Ast, &v_var as &dyn Ast],
        &body,
    );
    eff_fn
}

// ---- Entry computation ----

/// Perform the RBAC binding-join using Mangle IDB facts, producing
/// `(principal, namespace, api_group, resource, verb)` entries where
/// wildcards ("*") are preserved as-is (not expanded).
///
/// Three paths mirror Kubernetes binding semantics:
///   1. subject_in_rb × rolebinding_roleref("Role") × role_perm
///   2. subject_in_rb × rolebinding_roleref("ClusterRole") × clusterrole_perm
///   3. subject_in_crb × clusterrolebinding_roleref × clusterrole_perm
///      expanded over all known namespaces (CRBs grant access in every ns)
fn compute_can_entries(
    scan: &dyn Fn(&str) -> Vec<Vec<Value>>,
    subject_in_rb: &[Vec<Value>],
    subject_in_crb: &[Vec<Value>],
) -> Vec<(String, String, String, String, String)> {
    // Index role_perm by (ns, role_name).
    let mut role_perms: HashMap<(String, String), Vec<(String, String, String)>> = HashMap::new();
    for t in scan("role_perm") {
        if let [Value::String(ns), Value::String(role), Value::String(ag), Value::String(r), Value::String(v)] =
            t.as_slice()
        {
            role_perms
                .entry((ns.clone(), role.clone()))
                .or_default()
                .push((ag.clone(), r.clone(), v.clone()));
        }
    }

    // Index clusterrole_perm by role_name.
    let mut cr_perms: HashMap<String, Vec<(String, String, String)>> = HashMap::new();
    for t in scan("clusterrole_perm") {
        if let [Value::String(role), Value::String(ag), Value::String(r), Value::String(v)] = t.as_slice() {
            cr_perms
                .entry(role.clone())
                .or_default()
                .push((ag.clone(), r.clone(), v.clone()));
        }
    }

    // Index rolebinding_roleref by (binding_ns, binding_name).
    let mut rb_roleref: HashMap<(String, String), Vec<(String, String)>> = HashMap::new();
    for t in scan("rolebinding_roleref") {
        if let [Value::String(b_ns), Value::String(b_name), Value::String(kind), Value::String(role)] =
            t.as_slice()
        {
            rb_roleref
                .entry((b_ns.clone(), b_name.clone()))
                .or_default()
                .push((kind.clone(), role.clone()));
        }
    }

    // Index clusterrolebinding_roleref by binding_name.
    let mut crb_roleref: HashMap<String, String> = HashMap::new();
    for t in scan("clusterrolebinding_roleref") {
        if let [Value::String(b_name), Value::String(role)] = t.as_slice() {
            crb_roleref.insert(b_name.clone(), role.clone());
        }
    }

    // Namespace set for CRB expansion: prefer explicit namespace EDB facts emitted
    // by the EDB loader, which reflect the full cluster namespace list. Fall back
    // to deriving from role/binding entries so interactive ::define sessions still
    // work. Always include "" for cluster-wide checks.
    let mut namespaces: HashSet<String> = HashSet::new();
    namespaces.insert(String::new());
    for t in scan("namespace") {
        if let [Value::String(ns)] = t.as_slice() {
            namespaces.insert(ns.clone());
        }
    }
    if namespaces.len() == 1 {
        // No namespace EDB facts — fall back to deriving from RBAC data.
        for t in scan("role_perm") {
            if let [Value::String(ns), ..] = t.as_slice() {
                namespaces.insert(ns.clone());
            }
        }
        for t in scan("rolebinding_roleref") {
            if let [Value::String(b_ns), ..] = t.as_slice() {
                namespaces.insert(b_ns.clone());
            }
        }
    }

    let mut entries: HashSet<(String, String, String, String, String)> = HashSet::new();

    // Paths 1 & 2: RoleBinding → Role or ClusterRole
    for tuple in subject_in_rb {
        if let [Value::String(p), Value::String(b_ns), Value::String(b_name)] = tuple.as_slice() {
            let key = (b_ns.clone(), b_name.clone());
            if let Some(rollerefs) = rb_roleref.get(&key) {
                for (kind, role_name) in rollerefs {
                    let perms: &[(String, String, String)] = if kind == "Role" {
                        role_perms
                            .get(&(b_ns.clone(), role_name.clone()))
                            .map(Vec::as_slice)
                            .unwrap_or_default()
                    } else {
                        cr_perms
                            .get(role_name)
                            .map(Vec::as_slice)
                            .unwrap_or_default()
                    };
                    for (ag, r, v) in perms {
                        entries.insert((p.clone(), b_ns.clone(), ag.clone(), r.clone(), v.clone()));
                    }
                }
            }
        }
    }

    // Path 3: ClusterRoleBinding → ClusterRole, expanded to each known namespace
    for tuple in subject_in_crb {
        if let [Value::String(p), Value::String(b_name)] = tuple.as_slice() {
            if let Some(role_name) = crb_roleref.get(b_name) {
                if let Some(perms) = cr_perms.get(role_name) {
                    for ns in &namespaces {
                        for (ag, r, v) in perms {
                            entries.insert((p.clone(), ns.clone(), ag.clone(), r.clone(), v.clone()));
                        }
                    }
                }
            }
        }
    }

    entries.into_iter().collect()
}

/// Compute `(principal, namespace, resource, verb)` entries for `effective_can`:
/// direct `can` entries (apiGroup stripped) plus escalation via `controls_identity`.
fn compute_effective_can_entries(
    scan: &dyn Fn(&str) -> Vec<Vec<Value>>,
    can_entries: &[(String, String, String, String, String)],
) -> Vec<(String, String, String, String)> {
    // Project can_entries to (p, ns, r, v), dropping apiGroup.
    let mut result: HashSet<(String, String, String, String)> = HashSet::new();
    for (p, ns, _ag, r, v) in can_entries {
        result.insert((p.clone(), ns.clone(), r.clone(), v.clone()));
    }

    // Build a (target → [(ns, r, v)] index for escalation lookup.
    let mut can_by_principal: HashMap<&str, Vec<(&str, &str, &str)>> = HashMap::new();
    for (p, ns, _ag, r, v) in can_entries {
        can_by_principal
            .entry(p.as_str())
            .or_default()
            .push((ns.as_str(), r.as_str(), v.as_str()));
    }

    // controls_identity(P, Target): P inherits everything Target can do.
    // The closure is already transitively computed by Mangle (escalation.mg).
    for t in scan("controls_identity") {
        if let [Value::String(p), Value::String(target)] = t.as_slice() {
            if let Some(target_can) = can_by_principal.get(target.as_str()) {
                for (ns, r, v) in target_can {
                    result.insert((p.clone(), ns.to_string(), r.to_string(), v.to_string()));
                }
            }
        }
    }

    result.into_iter().collect()
}

// ---- Subject-table helpers (used by assert_rbac_axioms_impl) ----

/// Build `subject_in_rb(principal, binding_ns, binding_name)` tuples.
pub(crate) fn compute_subject_in_rb(scan: &dyn Fn(&str) -> Vec<Vec<Value>>) -> Vec<Vec<Value>> {
    let mut result: HashSet<(String, String, String)> = HashSet::new();

    for t in scan("rolebinding_subject_sa") {
        if let [Value::String(b_ns), Value::String(b_name), Value::String(sa_ns), Value::String(sa_name)] =
            t.as_slice()
        {
            let p = format!("system:serviceaccount:{sa_ns}:{sa_name}");
            result.insert((p, b_ns.clone(), b_name.clone()));
        }
    }

    for t in scan("rolebinding_subject_user") {
        if let [Value::String(b_ns), Value::String(b_name), Value::String(user)] = t.as_slice() {
            result.insert((user.clone(), b_ns.clone(), b_name.clone()));
        }
    }

    let group_bindings: Vec<(String, String, String)> = scan("rolebinding_subject_group")
        .into_iter()
        .filter_map(|t| {
            if let [Value::String(b_ns), Value::String(b_name), Value::String(group)] = t.as_slice() {
                Some((b_ns.clone(), b_name.clone(), group.clone()))
            } else {
                None
            }
        })
        .collect();

    let user_groups: Vec<(String, String)> = scan("user_groups")
        .into_iter()
        .filter_map(|t| {
            if let [Value::String(user), Value::String(group)] = t.as_slice() {
                Some((user.clone(), group.clone()))
            } else {
                None
            }
        })
        .collect();

    for (b_ns, b_name, group) in &group_bindings {
        result.insert((group.clone(), b_ns.clone(), b_name.clone()));
        for (user, g) in &user_groups {
            if g == group {
                result.insert((user.clone(), b_ns.clone(), b_name.clone()));
            }
        }
    }

    result
        .into_iter()
        .map(|(p, b_ns, b_name)| vec![Value::String(p), Value::String(b_ns), Value::String(b_name)])
        .collect()
}

/// Build `subject_in_crb(principal, binding_name)` tuples.
pub(crate) fn compute_subject_in_crb(scan: &dyn Fn(&str) -> Vec<Vec<Value>>) -> Vec<Vec<Value>> {
    let mut result: HashSet<(String, String)> = HashSet::new();

    for t in scan("clusterrolebinding_subject_sa") {
        if let [Value::String(b_name), Value::String(sa_ns), Value::String(sa_name)] = t.as_slice() {
            let p = format!("system:serviceaccount:{sa_ns}:{sa_name}");
            result.insert((p, b_name.clone()));
        }
    }

    for t in scan("clusterrolebinding_subject_user") {
        if let [Value::String(b_name), Value::String(user)] = t.as_slice() {
            result.insert((user.clone(), b_name.clone()));
        }
    }

    let group_crbs: Vec<(String, String)> = scan("clusterrolebinding_subject_group")
        .into_iter()
        .filter_map(|t| {
            if let [Value::String(b_name), Value::String(group)] = t.as_slice() {
                Some((b_name.clone(), group.clone()))
            } else {
                None
            }
        })
        .collect();

    let user_groups: Vec<(String, String)> = scan("user_groups")
        .into_iter()
        .filter_map(|t| {
            if let [Value::String(user), Value::String(group)] = t.as_slice() {
                Some((user.clone(), group.clone()))
            } else {
                None
            }
        })
        .collect();

    for (b_name, group) in &group_crbs {
        result.insert((group.clone(), b_name.clone()));
        for (user, g) in &user_groups {
            if g == group {
                result.insert((user.clone(), b_name.clone()));
            }
        }
    }

    result
        .into_iter()
        .map(|(p, b_name)| vec![Value::String(p), Value::String(b_name)])
        .collect()
}
