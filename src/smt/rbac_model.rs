// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

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

use std::collections::HashSet;

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

        let can_entries = parse_perm_tuples(&scan("direct_perm"));
        let eff_entries: Vec<_> = {
            let mut set: HashSet<(String, String, String, String, String)> = HashSet::new();
            set.extend(parse_perm_tuples(&scan("direct_perm")));
            set.extend(parse_perm_tuples_6(&scan("indirect_perm")));
            set.into_iter().collect()
        };

        for rel in &["user_groups", "controls_identity"] {
            self.load_relation(&fn_name(rel, suffix), &scan(rel));
        }
        self.load_relation(&fn_name("direct_perm", suffix), &scan("direct_perm"));
        self.load_relation(&fn_name("indirect_perm", suffix), &scan("indirect_perm"));
        self.load_relation(&fn_name("subject_in_rb", suffix), &subject_in_rb);
        self.load_relation(&fn_name("subject_in_crb", suffix), &subject_in_crb);
        // Load roleref and escalation-mechanism tables for path reconstruction
        // (display only, not queried by Z3). Stored without suffix so
        // paths_for_principal always finds them regardless of which snapshot is current.
        self.facts.insert("rolebinding_roleref".to_string(), scan("rolebinding_roleref"));
        self.facts.insert("clusterrolebinding_roleref".to_string(), scan("clusterrolebinding_roleref"));
        for rel in &["exec_reachable_sa", "token_accessible_sa", "pod_creatable_sa", "impersonatable_sa", "escalation_hop"] {
            self.facts.insert(rel.to_string(), scan(rel));
        }

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

/// `effective_can(p, ns, ag, r, v)` — like can/5 but escalation-aware (includes
/// permissions reachable via controls_identity). Same arity as can/5.
/// Body: big OR of `(p == P ∧ ns == NS ∧ matches(ag, AG) ∧ matches(r, R) ∧ matches(v, V))`.
fn build_effective_can_rec_func<'ctx>(
    ctx: &'ctx z3::Context,
    name: &str,
    entries: &[(String, String, String, String, String)],
) -> RecFuncDecl<'ctx> {
    let str_sort = Sort::string(ctx);
    let domain = [&str_sort, &str_sort, &str_sort, &str_sort, &str_sort];
    let eff_fn = RecFuncDecl::new(ctx, name, &domain, &Sort::bool(ctx));

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

    eff_fn.add_def(
        &[&p_var as &dyn Ast, &ns_var as &dyn Ast, &ag_var as &dyn Ast, &r_var as &dyn Ast, &v_var as &dyn Ast],
        &body,
    );
    eff_fn
}

// ---- Entry computation ----

fn parse_perm_tuples(rows: &[Vec<Value>]) -> Vec<(String, String, String, String, String)> {
    rows.iter()
        .filter_map(|t| {
            if let [Value::String(p), Value::String(ns), Value::String(ag), Value::String(r), Value::String(v)] =
                t.as_slice()
            {
                Some((p.clone(), ns.clone(), ag.clone(), r.clone(), v.clone()))
            } else {
                None
            }
        })
        .collect()
}

/// Like `parse_perm_tuples` but for 6-column rows (e.g. `indirect_perm/6`);
/// projects away the last column (the via-target).
fn parse_perm_tuples_6(rows: &[Vec<Value>]) -> Vec<(String, String, String, String, String)> {
    rows.iter()
        .filter_map(|t| {
            if let [Value::String(p), Value::String(ns), Value::String(ag), Value::String(r), Value::String(v), _] =
                t.as_slice()
            {
                Some((p.clone(), ns.clone(), ag.clone(), r.clone(), v.clone()))
            } else {
                None
            }
        })
        .collect()
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
