use std::collections::HashSet;

use z3::ast::{Ast, Bool};
use z3::ast::String as Z3String;
use z3::SatResult;

use super::{SmtEncoder, Violation};

impl<'ctx> SmtEncoder<'ctx> {
    /// Check that every principal with can(_, namespace, resource, verb) is in `expected`.
    /// Pass namespace="" to check cluster-wide grants (ClusterRoleBindings apply to any namespace).
    /// Enumerates all unexpected principals via SAT witness exclusion loop.
    ///
    /// Candidate principals are derived from `subject_in_rb`/`subject_in_crb` facts (loaded by
    /// `assert_rbac_axioms`). This bounds Z3's witness search to actual binding subjects, providing
    /// a practical closed-world guarantee even though the intermediate predicates are open-world.
    pub fn check_access_invariant(
        &self,
        namespace: &str,
        resource: &str,
        verb: &str,
        expected: &[&str],
    ) -> Vec<Violation> {
        let Some(can_decl) = self.get_decl("can") else {
            return vec![];
        };

        // Derive candidate principals from the binding subject tables rather than from can/5
        // (which is no longer loaded as ground facts under the axiomatic model).
        // CRB subjects are always candidates regardless of namespace; RB subjects are candidates
        // when their binding namespace matches the queried namespace.
        let mut principal_set: HashSet<String> = HashSet::new();

        if let Some(rb_tuples) = self.facts.get("subject_in_rb") {
            // subject_in_rb: (principal, binding_ns, binding_name)
            for t in rb_tuples {
                if let [mangle_common::Value::String(p), mangle_common::Value::String(b_ns), ..] =
                    t.as_slice()
                {
                    // Include if namespace matches OR if we're checking cluster-wide ("").
                    if namespace.is_empty() || b_ns == namespace {
                        principal_set.insert(p.clone());
                    }
                }
            }
        }

        if let Some(crb_tuples) = self.facts.get("subject_in_crb") {
            // subject_in_crb: (principal, binding_name)
            for t in crb_tuples {
                if let [mangle_common::Value::String(p), ..] = t.as_slice() {
                    principal_set.insert(p.clone());
                }
            }
        }

        let known_principals_owned: Vec<String> = principal_set.into_iter().collect();
        let known_principals: Vec<&str> = known_principals_owned.iter().map(String::as_str).collect();

        if known_principals.is_empty() {
            return vec![];
        }

        let witness = Z3String::new_const(self.ctx, "witness_principal");
        let apigroup_witness = Z3String::new_const(self.ctx, "witness_apigroup");
        let namespace_ast = Z3String::from_str(self.ctx, namespace).unwrap();
        let resource_ast = Z3String::from_str(self.ctx, resource).unwrap();
        let verb_ast = Z3String::from_str(self.ctx, verb).unwrap();

        // can/5: (principal, ns, apigroup, resource, verb)
        // apigroup_witness is a free variable — any apiGroup satisfies the query.
        let witness_has_perm = can_decl
            .apply(&[
                &witness as &dyn Ast,
                &namespace_ast as &dyn Ast,
                &apigroup_witness as &dyn Ast,
                &resource_ast as &dyn Ast,
                &verb_ast as &dyn Ast,
            ])
            .as_bool()
            .unwrap();

        let known_eqs: Vec<Bool> = known_principals
            .iter()
            .map(|p| witness._eq(&Z3String::from_str(self.ctx, p).unwrap()))
            .collect();
        let witness_is_known = Bool::or(self.ctx, &known_eqs.iter().collect::<Vec<_>>());

        let not_expected: Vec<Bool> = expected
            .iter()
            .map(|ep| {
                witness
                    ._eq(&Z3String::from_str(self.ctx, ep).unwrap())
                    .not()
            })
            .collect();

        self.solver.push();
        self.solver.assert(&witness_has_perm);
        self.solver.assert(&witness_is_known);
        if !not_expected.is_empty() {
            self.solver
                .assert(&Bool::and(self.ctx, &not_expected.iter().collect::<Vec<_>>()));
        }

        let mut violations = Vec::new();
        loop {
            if self.solver.check() != SatResult::Sat {
                break;
            }
            let Some(principal) = self
                .solver
                .get_model()
                .and_then(|m| m.eval(&witness, true))
                .and_then(|v| v.as_string())
            else {
                break;
            };

            self.solver.assert(
                &witness
                    ._eq(&Z3String::from_str(self.ctx, &principal).unwrap())
                    .not(),
            );
            violations.push(Violation {
                principal,
                namespace: namespace.to_string(),
                resource: resource.to_string(),
                verb: verb.to_string(),
            });
        }

        self.solver.pop(1);
        violations
    }

    /// Prove that only the `allowed` principals have *any* access in `namespace`.
    ///
    /// Unlike `check_access_invariant`, there is no prefilter: `p` is a free symbolic
    /// string. Z3 evaluates the RecFuncDecl body directly to find satisfying assignments.
    /// When the loop terminates via UNSAT that is a proof — not just "searched and found
    /// nothing" — that no string exists satisfying the constraints.
    pub fn check_namespace_isolation(
        &self,
        namespace: &str,
        allowed: &[&str],
    ) -> Vec<Violation> {
        let Some(can_decl) = self.get_decl("can") else {
            return vec![];
        };

        let p = Z3String::new_const(self.ctx, "p");
        let ag = Z3String::new_const(self.ctx, "ag");
        let r = Z3String::new_const(self.ctx, "r");
        let v = Z3String::new_const(self.ctx, "v");
        let ns_ast = Z3String::from_str(self.ctx, namespace).unwrap();

        let has_access = can_decl
            .apply(&[
                &p as &dyn Ast,
                &ns_ast as &dyn Ast,
                &ag as &dyn Ast,
                &r as &dyn Ast,
                &v as &dyn Ast,
            ])
            .as_bool()
            .unwrap();

        let not_allowed: Vec<Bool> = allowed
            .iter()
            .map(|a| p._eq(&Z3String::from_str(self.ctx, a).unwrap()).not())
            .collect();

        self.solver.push();
        self.solver.assert(&has_access);
        if !not_allowed.is_empty() {
            self.solver
                .assert(&Bool::and(self.ctx, &not_allowed.iter().collect::<Vec<_>>()));
        }

        let mut violations = Vec::new();
        loop {
            if self.solver.check() != SatResult::Sat {
                break;
            }
            let model = self.solver.get_model().unwrap();
            let Some(principal) = model.eval(&p, true).and_then(|ev| ev.as_string()) else {
                break;
            };
            let resource = model
                .eval(&r, true)
                .and_then(|ev| ev.as_string())
                .unwrap_or_default();
            let verb = model
                .eval(&v, true)
                .and_then(|ev| ev.as_string())
                .unwrap_or_default();

            // Exclude this principal and let Z3 find the next one.
            self.solver
                .assert(&p._eq(&Z3String::from_str(self.ctx, &principal).unwrap()).not());

            violations.push(Violation {
                principal,
                namespace: namespace.to_string(),
                resource,
                verb,
            });
        }

        self.solver.pop(1);
        violations
    }
}
