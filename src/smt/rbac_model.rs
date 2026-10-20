// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

// RBAC model for Z3 using RecFuncDecl.
//
// Mangle provides the derived facts (IDB): grants per binding subject
// (direct_perm), the subjects each principal acts as (principal_subject) and
// the escalation closure (controls_identity, controls_group).
// `PermissionTables` joins them, and this module turns the result into two Z3
// functions:
//
//   can(principal, namespace, apigroup, resource, verb) → Bool
//     True when some binding grants the permission to the principal, itself
//     or through one of its groups. Groups named by a binding are principals
//     too (see `PermissionTables`).
//     Wildcard matching ("*" in any position) is modeled in Z3 via `matches`.
//
//   effective_can(principal, namespace, apigroup, resource, verb) → Bool
//     Like can/5 but folds in what escalation reaches through
//     controls_identity and controls_group.
//
// Both functions are defined as Z3 RecFuncDecls: finite case analyses with no
// quantifiers. This avoids the quantifier-instantiation overhead of the
// forall-axiom approach, which is prohibitively slow for string theory.
//
// Wildcard semantics live in Z3: `matches(needle, pat)` expresses
// `pat == "*" ∨ needle == pat`. Z3 simplifies `matches(x, "*")` to `true`
// and `matches("pods", "pods")` to `true` at construction time.

use mangle_common::Value;
use z3::ast::String as Z3String;
use z3::ast::{Ast, Bool};
use z3::{RecFuncDecl, Sort};

use super::SmtEncoder;
use crate::engine::EvalStore;
use crate::rbac::facts::{PermissionTables, relation_name};

impl<'ctx> SmtEncoder<'ctx> {
    /// Load Mangle RBAC primitives and define `can` and `effective_can` as
    /// closed Z3 functions via RecFuncDecl.
    pub fn assert_rbac_axioms(&mut self, store: &EvalStore) {
        self.assert_rbac_axioms_named(|rel| store.scan(rel).to_vec(), "");
    }

    /// Like `assert_rbac_axioms` but registers all predicates under a name suffix.
    /// Defines `can_<suffix>` and `effective_can_<suffix>` instead of bare names.
    /// Enables two snapshots to coexist in one solver for differential queries.
    pub fn assert_rbac_axioms_as(&mut self, store: &EvalStore, suffix: &str) {
        self.assert_rbac_axioms_named(|rel| store.scan(rel).to_vec(), suffix);
    }

    /// Like `assert_rbac_axioms_as` but reads from a saved `Snapshot` instead of a
    /// live eval store. Useful for differential access analysis.
    pub fn assert_rbac_axioms_from_snapshot_as(
        &mut self,
        snap: &crate::snapshot::Snapshot,
        suffix: &str,
    ) {
        self.assert_rbac_axioms_named(|rel| snap.scan_rel(rel), suffix);
    }

    fn assert_rbac_axioms_named<F: Fn(&str) -> Vec<Vec<Value>>>(&mut self, scan: F, suffix: &str) {
        let tables = PermissionTables::from_scan(&scan);

        for rel in [
            "direct_perm",
            "principal_subject",
            "controls_identity",
            "controls_group",
        ] {
            self.load_relation(&relation_name(rel, suffix), &scan(rel));
        }

        let can_fn = build_can_rec_func(self.ctx, &relation_name("can", suffix), &tables.direct);
        let eff_fn = build_effective_can_rec_func(
            self.ctx,
            &relation_name("effective_can", suffix),
            &tables.effective,
        );
        self.rec_decls.insert(relation_name("can", suffix), can_fn);
        self.rec_decls
            .insert(relation_name("effective_can", suffix), eff_fn);
        self.can_entries.insert(suffix.to_string(), tables.direct);
        self.eff_entries
            .insert(suffix.to_string(), tables.effective);
        self.escalation_via
            .insert(suffix.to_string(), tables.escalation_via);
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
    let empty_ns = Z3String::from_str(ctx, "").unwrap();
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
            Bool::and(
                ctx,
                &[
                    &p_var._eq(&pe_z3),
                    // Cluster-wide entries (ns "") apply in every namespace.
                    &Bool::or(ctx, &[&nse_z3._eq(&empty_ns), &ns_var._eq(&nse_z3)]),
                    &matches(&ag_var, age),
                    &matches(&r_var, re),
                    &matches(&v_var, ve),
                ],
            )
        })
        .collect();

    let body = if clauses.is_empty() {
        Bool::from_bool(ctx, false)
    } else {
        Bool::or(ctx, &clauses.iter().collect::<Vec<_>>())
    };

    can_fn.add_def(
        &[
            &p_var as &dyn Ast,
            &ns_var as &dyn Ast,
            &ag_var as &dyn Ast,
            &r_var as &dyn Ast,
            &v_var as &dyn Ast,
        ],
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
    let empty_ns = Z3String::from_str(ctx, "").unwrap();
    let matches = |needle: &Z3String<'ctx>, pat_str: &str| -> Bool<'ctx> {
        let pat = Z3String::from_str(ctx, pat_str).unwrap();
        Bool::or(ctx, &[&pat._eq(&wildcard), &needle._eq(&pat)])
    };

    let clauses: Vec<Bool<'ctx>> = entries
        .iter()
        .map(|(pe, nse, age, re, ve)| {
            let pe_z3 = Z3String::from_str(ctx, pe).unwrap();
            let nse_z3 = Z3String::from_str(ctx, nse).unwrap();
            Bool::and(
                ctx,
                &[
                    &p_var._eq(&pe_z3),
                    // Cluster-wide entries (ns "") apply in every namespace.
                    &Bool::or(ctx, &[&nse_z3._eq(&empty_ns), &ns_var._eq(&nse_z3)]),
                    &matches(&ag_var, age),
                    &matches(&r_var, re),
                    &matches(&v_var, ve),
                ],
            )
        })
        .collect();

    let body = if clauses.is_empty() {
        Bool::from_bool(ctx, false)
    } else {
        Bool::or(ctx, &clauses.iter().collect::<Vec<_>>())
    };

    eff_fn.add_def(
        &[
            &p_var as &dyn Ast,
            &ns_var as &dyn Ast,
            &ag_var as &dyn Ast,
            &r_var as &dyn Ast,
            &v_var as &dyn Ast,
        ],
        &body,
    );
    eff_fn
}
