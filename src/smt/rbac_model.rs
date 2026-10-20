// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

// RBAC model for Z3 using RecFuncDecl.
//
// Mangle provides the derived facts (IDB): grants per binding subject
// (direct_perm), the subjects each principal acts as (principal_subject) and
// the escalation closure (controls_identity, controls_group).
// `PermissionTables` indexes them, and this module turns them into three Z3
// functions. A principal or subject is a string tagged with its kind
// (`Subject::smt_key`), e.g. "/user:alice" or "/group:admins", so a user and
// a group with the same name are different.
//
//   subject_grants(subject, namespace, apigroup, resource, verb) → Bool
//     True when some binding grants the permission to that binding subject
//     itself, before group membership or escalation.
//
//   can(principal, namespace, apigroup, resource, verb) → Bool
//     True when some binding grants the permission to the principal, itself
//     or through one of its groups. Groups named by a binding are principals
//     too (see `PermissionTables`). Wildcard matching ("*" in any position)
//     is modeled in Z3 via `matches`.
//
//   effective_can(principal, namespace, apigroup, resource, verb) → Bool
//     Like can/5 but folds in what escalation reaches through
//     controls_identity and controls_group, and from a group through
//     group_controls_identity and group_controls_group.
//
// can and effective_can join on subjects rather than listing every
// (principal, permission) pair: one clause per binding subject says which
// principals hold its grants and calls subject_grants, and one clause per
// escalation target says which principals control it. A group's grants are
// written once, not once per member.
//
// All three are Z3 RecFuncDecls: finite case analyses with no quantifiers.
// This avoids the quantifier-instantiation overhead of the forall-axiom
// approach, which is prohibitively slow for string theory.
//
// Wildcard semantics live in Z3: `matches(needle, pat)` expresses
// `pat == "*" ∨ needle == pat`. Z3 simplifies `matches(x, "*")` to `true`
// and `matches("pods", "pods")` to `true` at construction time.

use std::collections::{BTreeMap, BTreeSet};

use mangle_common::Value;
use z3::ast::String as Z3String;
use z3::ast::{Ast, Bool};
use z3::{RecFuncDecl, Sort};

use super::SmtEncoder;
use crate::engine::EvalStore;
use crate::rbac::facts::{Permission, relation_name};
use crate::rbac::{PermissionTables, Subject};

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

        let subject_grants =
            build_subject_grants(self.ctx, &relation_name("subject_grants", suffix), &tables);
        let can = build_can(
            self.ctx,
            &relation_name("can", suffix),
            &tables,
            &subject_grants,
        );
        let effective_can = build_effective_can(
            self.ctx,
            &relation_name("effective_can", suffix),
            &tables,
            &can,
            &subject_grants,
        );
        self.rec_decls
            .insert(relation_name("subject_grants", suffix), subject_grants);
        self.rec_decls.insert(relation_name("can", suffix), can);
        self.rec_decls
            .insert(relation_name("effective_can", suffix), effective_can);
        self.permission_tables.insert(suffix.to_string(), tables);
    }
}

// ---- RecFuncDecl builders ----

/// The formal parameters of a (subject or principal, namespace, apigroup,
/// resource, verb) function.
struct Parameters<'ctx> {
    principal: Z3String<'ctx>,
    namespace: Z3String<'ctx>,
    api_group: Z3String<'ctx>,
    resource: Z3String<'ctx>,
    verb: Z3String<'ctx>,
}

impl<'ctx> Parameters<'ctx> {
    /// Parameter names are prefixed with the function name to avoid Z3
    /// constant aliasing when several RecFuncDecls are built in one context.
    fn new(ctx: &'ctx z3::Context, function: &str) -> Self {
        let parameter = |name: &str| Z3String::new_const(ctx, format!("_{function}_{name}"));
        Self {
            principal: parameter("principal"),
            namespace: parameter("namespace"),
            api_group: parameter("api_group"),
            resource: parameter("resource"),
            verb: parameter("verb"),
        }
    }

    fn all(&self) -> [&dyn Ast<'ctx>; 5] {
        [
            &self.principal,
            &self.namespace,
            &self.api_group,
            &self.resource,
            &self.verb,
        ]
    }

    /// `function(first, namespace, apigroup, resource, verb)`, passing this
    /// function's own permission parameters on.
    fn call(&self, function: &RecFuncDecl<'ctx>, first: &Z3String<'ctx>) -> Bool<'ctx> {
        function
            .apply(&[
                first as &dyn Ast,
                &self.namespace,
                &self.api_group,
                &self.resource,
                &self.verb,
            ])
            .as_bool()
            .expect("RBAC functions return Bool")
    }

    /// `principal` is one of `keys`.
    fn principal_in(&self, ctx: &'ctx z3::Context, keys: &[Subject]) -> Bool<'ctx> {
        let equalities: Vec<Bool<'ctx>> = keys
            .iter()
            .map(|key| self.principal._eq(&string(ctx, &key.smt_key())))
            .collect();
        any(ctx, equalities)
    }

    /// The permission parameters are covered by `granted`.
    fn covered_by(&self, ctx: &'ctx z3::Context, granted: &Permission) -> Bool<'ctx> {
        let (namespace, api_group, resource, verb) = granted;
        let wildcard = string(ctx, "*");
        let matches = |needle: &Z3String<'ctx>, pattern: &str| -> Bool<'ctx> {
            let pattern = string(ctx, pattern);
            // pattern == "*" simplifies to true at construction.
            Bool::or(ctx, &[&pattern._eq(&wildcard), &needle._eq(&pattern)])
        };
        let namespace_z3 = string(ctx, namespace);
        Bool::and(
            ctx,
            &[
                // Cluster-wide grants (namespace "") apply in every namespace.
                &Bool::or(
                    ctx,
                    &[
                        &namespace_z3._eq(&string(ctx, "")),
                        &self.namespace._eq(&namespace_z3),
                    ],
                ),
                &matches(&self.api_group, api_group),
                &matches(&self.resource, resource),
                &matches(&self.verb, verb),
            ],
        )
    }
}

fn string<'ctx>(ctx: &'ctx z3::Context, value: &str) -> Z3String<'ctx> {
    Z3String::from_str(ctx, value).expect("RBAC strings contain no NUL")
}

fn any<'ctx>(ctx: &'ctx z3::Context, clauses: Vec<Bool<'ctx>>) -> Bool<'ctx> {
    if clauses.is_empty() {
        Bool::from_bool(ctx, false)
    } else {
        Bool::or(ctx, &clauses.iter().collect::<Vec<_>>())
    }
}

fn define<'ctx>(
    ctx: &'ctx z3::Context,
    name: &str,
    body: impl FnOnce(&Parameters<'ctx>) -> Vec<Bool<'ctx>>,
) -> RecFuncDecl<'ctx> {
    let string_sort = Sort::string(ctx);
    let domain = [&string_sort; 5];
    let function = RecFuncDecl::new(ctx, name, &domain, &Sort::bool(ctx));
    let parameters = Parameters::new(ctx, name);
    let body = any(ctx, body(&parameters));
    function.add_def(&parameters.all(), &body);
    function
}

/// Grant-holding subjects in a stable order, so the encoding does not depend
/// on hash order.
fn sorted_subjects(tables: &PermissionTables) -> Vec<&Subject> {
    let mut subjects: Vec<&Subject> = tables.grants.keys().collect();
    subjects.sort();
    subjects
}

/// `subject_grants(s, ns, ag, r, v)`: per binding subject, `s == S ∧ (one of
/// S's grants covers the permission)`.
fn build_subject_grants<'ctx>(
    ctx: &'ctx z3::Context,
    name: &str,
    tables: &PermissionTables,
) -> RecFuncDecl<'ctx> {
    define(ctx, name, |parameters| {
        sorted_subjects(tables)
            .into_iter()
            .map(|subject| {
                let mut permissions: Vec<&Permission> = tables.grants[subject].iter().collect();
                permissions.sort();
                let covered = any(
                    ctx,
                    permissions
                        .into_iter()
                        .map(|granted| parameters.covered_by(ctx, granted))
                        .collect(),
                );
                Bool::and(
                    ctx,
                    &[
                        &parameters.principal_in(ctx, std::slice::from_ref(subject)),
                        &covered,
                    ],
                )
            })
            .collect()
    })
}

/// `can(p, ns, ag, r, v)`: per binding subject S, `p` is one of S's holders
/// (S itself, and a group's known members) ∧ `subject_grants(S, ns, ag, r, v)`.
fn build_can<'ctx>(
    ctx: &'ctx z3::Context,
    name: &str,
    tables: &PermissionTables,
    subject_grants: &RecFuncDecl<'ctx>,
) -> RecFuncDecl<'ctx> {
    define(ctx, name, |parameters| {
        sorted_subjects(tables)
            .into_iter()
            .map(|subject| {
                Bool::and(
                    ctx,
                    &[
                        &parameters.principal_in(ctx, &tables.holders(subject)),
                        &parameters.call(subject_grants, &string(ctx, &subject.smt_key())),
                    ],
                )
            })
            .collect()
    })
}

/// `effective_can(p, ns, ag, r, v)`: `can(p, ns, ag, r, v)`, or per
/// escalation target T, `p` controls T ∧ one of the subjects T brings
/// (`PermissionTables::target_subjects`) is granted the permission.
fn build_effective_can<'ctx>(
    ctx: &'ctx z3::Context,
    name: &str,
    tables: &PermissionTables,
    can: &RecFuncDecl<'ctx>,
    subject_grants: &RecFuncDecl<'ctx>,
) -> RecFuncDecl<'ctx> {
    let mut controllers: BTreeMap<&Subject, Vec<Subject>> = BTreeMap::new();
    for (principal, targets) in &tables.escalation_targets {
        for target in targets {
            controllers
                .entry(target)
                .or_default()
                .push(principal.clone());
        }
    }

    define(ctx, name, |parameters| {
        let mut clauses = vec![parameters.call(can, &parameters.principal)];
        for (target, controllers) in &mut controllers {
            let granted_subjects: BTreeSet<Subject> = tables
                .target_subjects(target)
                .iter()
                .map(Subject::principal)
                .filter(|subject| tables.grants.contains_key(subject))
                .collect();
            if granted_subjects.is_empty() {
                continue;
            }
            controllers.sort();
            let brings = any(
                ctx,
                granted_subjects
                    .iter()
                    .map(|subject| {
                        parameters.call(subject_grants, &string(ctx, &subject.smt_key()))
                    })
                    .collect(),
            );
            clauses.push(Bool::and(
                ctx,
                &[&parameters.principal_in(ctx, controllers), &brings],
            ));
        }
        clauses
    })
}
