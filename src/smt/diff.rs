use std::collections::HashSet;

use z3::ast::{Ast, Bool};
use z3::ast::String as Z3String;
use z3::SatResult;

use super::SmtEncoder;
use super::rbac_model::fn_name;

pub struct CanDiff {
    pub principal: String,
    pub namespace: String,
    pub apigroup: String,
    pub resource: String,
    pub verb: String,
}

pub struct EffDiff {
    pub principal: String,
    pub namespace: String,
    pub resource: String,
    pub verb: String,
}

impl<'ctx> SmtEncoder<'ctx> {
    /// Returns one representative witness per principal that gained access:
    /// `can_<after>(p,ns,ag,r,v) ∧ ¬can_<before>(p,ns,ag,r,v)`.
    ///
    /// Both suffixes must have been loaded via `assert_rbac_axioms_as` or
    /// `assert_rbac_axioms_from_snapshot_as` before calling this.
    pub fn check_permission_expansion(&self, before: &str, after: &str) -> Vec<CanDiff> {
        self.can_diff_witnesses(after, before)
    }

    /// Returns one representative witness per principal that lost access:
    /// `can_<before>(p,ns,ag,r,v) ∧ ¬can_<after>(p,ns,ag,r,v)`.
    pub fn check_permission_contraction(&self, before: &str, after: &str) -> Vec<CanDiff> {
        self.can_diff_witnesses(before, after)
    }

    /// Returns one representative witness per principal that gained effective access
    /// (escalation-aware): `effective_can_<after> ∧ ¬effective_can_<before>`.
    pub fn check_effective_can_expansion(&self, before: &str, after: &str) -> Vec<EffDiff> {
        self.eff_diff_witnesses(after, before)
    }

    /// Returns one representative witness per principal that lost effective access:
    /// `effective_can_<before> ∧ ¬effective_can_<after>`.
    pub fn check_effective_can_contraction(&self, before: &str, after: &str) -> Vec<EffDiff> {
        self.eff_diff_witnesses(before, after)
    }

    // Finds tuples satisfying have_<have>(p,ns,ag,r,v) ∧ ¬have_<not_have>(p,ns,ag,r,v).
    // Returns one representative witness per principal.
    fn can_diff_witnesses(&self, have: &str, not_have: &str) -> Vec<CanDiff> {
        let have_decl = match self.get_decl(&fn_name("can", have)) {
            Some(d) => d,
            None => return vec![],
        };
        let not_have_decl = match self.get_decl(&fn_name("can", not_have)) {
            Some(d) => d,
            None => return vec![],
        };

        let principals = union_principals_5(
            self.can_entries.get(have).into_iter().flatten(),
            self.can_entries.get(not_have).into_iter().flatten(),
        );
        if principals.is_empty() {
            return vec![];
        }

        let p_var = Z3String::new_const(self.ctx, "cdiff_p");
        let ns_var = Z3String::new_const(self.ctx, "cdiff_ns");
        let ag_var = Z3String::new_const(self.ctx, "cdiff_ag");
        let r_var = Z3String::new_const(self.ctx, "cdiff_r");
        let v_var = Z3String::new_const(self.ctx, "cdiff_v");

        let args: [&dyn Ast; 5] = [&p_var, &ns_var, &ag_var, &r_var, &v_var];
        let has_perm = have_decl.apply(&args).as_bool().unwrap();
        let not_had_perm = not_have_decl.apply(&args).as_bool().unwrap().not();
        let p_is_candidate = candidate_constraint(self.ctx, &p_var, &principals);

        self.solver.push();
        self.solver.assert(&has_perm);
        self.solver.assert(&not_had_perm);
        self.solver.assert(&p_is_candidate);

        let mut results = Vec::new();
        loop {
            if self.solver.check() != SatResult::Sat {
                break;
            }
            let model = self.solver.get_model().unwrap();
            let principal = match model.eval(&p_var, true).and_then(|v| v.as_string()) {
                Some(s) => s,
                None => break,
            };
            let namespace = model.eval(&ns_var, true).and_then(|v| v.as_string()).unwrap_or_default();
            let apigroup = model.eval(&ag_var, true).and_then(|v| v.as_string()).unwrap_or_default();
            let resource = model.eval(&r_var, true).and_then(|v| v.as_string()).unwrap_or_default();
            let verb = model.eval(&v_var, true).and_then(|v| v.as_string()).unwrap_or_default();

            self.solver.assert(
                &p_var._eq(&Z3String::from_str(self.ctx, &principal).unwrap()).not(),
            );
            results.push(CanDiff { principal, namespace, apigroup, resource, verb });
        }

        self.solver.pop(1);
        results
    }

    // Finds tuples satisfying effective_can_<have>(p,ns,r,v) ∧ ¬effective_can_<not_have>(p,ns,r,v).
    fn eff_diff_witnesses(&self, have: &str, not_have: &str) -> Vec<EffDiff> {
        let have_decl = match self.get_decl(&fn_name("effective_can", have)) {
            Some(d) => d,
            None => return vec![],
        };
        let not_have_decl = match self.get_decl(&fn_name("effective_can", not_have)) {
            Some(d) => d,
            None => return vec![],
        };

        let principals = union_principals_4(
            self.eff_entries.get(have).into_iter().flatten(),
            self.eff_entries.get(not_have).into_iter().flatten(),
        );
        if principals.is_empty() {
            return vec![];
        }

        let p_var = Z3String::new_const(self.ctx, "ecdiff_p");
        let ns_var = Z3String::new_const(self.ctx, "ecdiff_ns");
        let r_var = Z3String::new_const(self.ctx, "ecdiff_r");
        let v_var = Z3String::new_const(self.ctx, "ecdiff_v");

        let args: [&dyn Ast; 4] = [&p_var, &ns_var, &r_var, &v_var];
        let has_perm = have_decl.apply(&args).as_bool().unwrap();
        let not_had_perm = not_have_decl.apply(&args).as_bool().unwrap().not();
        let p_is_candidate = candidate_constraint(self.ctx, &p_var, &principals);

        self.solver.push();
        self.solver.assert(&has_perm);
        self.solver.assert(&not_had_perm);
        self.solver.assert(&p_is_candidate);

        let mut results = Vec::new();
        loop {
            if self.solver.check() != SatResult::Sat {
                break;
            }
            let model = self.solver.get_model().unwrap();
            let principal = match model.eval(&p_var, true).and_then(|v| v.as_string()) {
                Some(s) => s,
                None => break,
            };
            let namespace = model.eval(&ns_var, true).and_then(|v| v.as_string()).unwrap_or_default();
            let resource = model.eval(&r_var, true).and_then(|v| v.as_string()).unwrap_or_default();
            let verb = model.eval(&v_var, true).and_then(|v| v.as_string()).unwrap_or_default();

            self.solver.assert(
                &p_var._eq(&Z3String::from_str(self.ctx, &principal).unwrap()).not(),
            );
            results.push(EffDiff { principal, namespace, resource, verb });
        }

        self.solver.pop(1);
        results
    }
}

fn union_principals_5<'a>(
    a: impl Iterator<Item = &'a (String, String, String, String, String)>,
    b: impl Iterator<Item = &'a (String, String, String, String, String)>,
) -> HashSet<String> {
    a.chain(b).map(|(p, ..)| p.clone()).collect()
}

fn union_principals_4<'a>(
    a: impl Iterator<Item = &'a (String, String, String, String)>,
    b: impl Iterator<Item = &'a (String, String, String, String)>,
) -> HashSet<String> {
    a.chain(b).map(|(p, ..)| p.clone()).collect()
}

fn candidate_constraint<'ctx>(
    ctx: &'ctx z3::Context,
    p_var: &Z3String<'ctx>,
    principals: &HashSet<String>,
) -> Bool<'ctx> {
    let eqs: Vec<Bool<'ctx>> = principals
        .iter()
        .map(|p| p_var._eq(&Z3String::from_str(ctx, p).unwrap()))
        .collect();
    Bool::or(ctx, &eqs.iter().collect::<Vec<_>>())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use mangle_common::Value;
    use mangle_interpreter::MemStore;

    use crate::edb;
    use crate::engine::{Engine, InterpreterBackend};
    use crate::snapshot::{Snapshot, Scope};
    use super::super::SmtEncoder;

    fn load_engine() -> Engine {
        let mut edb = MemStore::new();
        edb::load_all(&mut edb, Path::new("testdata")).expect("load testdata");
        Engine::new(edb, Path::new("rules"), Box::new(InterpreterBackend)).expect("engine")
    }

    #[test]
    fn no_expansion_when_before_and_after_identical() {
        let engine = load_engine();
        let eval = engine.evaluate().expect("evaluate");

        let cfg = z3::Config::new();
        let ctx = z3::Context::new(&cfg);
        let mut enc = SmtEncoder::new(&ctx);
        enc.assert_rbac_axioms_as(&eval, "before");
        enc.assert_rbac_axioms_as(&eval, "after");

        let gained = enc.check_permission_expansion("before", "after");
        let lost = enc.check_permission_contraction("before", "after");
        assert!(gained.is_empty(), "identical before/after must have no expansion");
        assert!(lost.is_empty(), "identical before/after must have no contraction");
    }

    #[test]
    fn expansion_detects_new_binding() {
        // Build a minimal "before" with no bindings (empty RBAC state).
        // Build "after" with a single RoleBinding granting alice pods/get.
        //
        // Construct synthetic Snapshots with the IDB relations that
        // assert_rbac_axioms_named reads directly:
        //   rolebinding_subject_user(binding_ns, binding_name, user)
        //   rolebinding_roleref(binding_ns, binding_name, kind, role_name)
        //   role_perm(ns, role_name, apigroup, resource, verb)
        let empty_snap = {
            let store = MemStore::new();
            Snapshot::from_store(&store, Scope::All)
        };

        let after_snap = {
            let mut store = MemStore::new();
            store.add_fact("rolebinding_subject_user", vec![
                Value::String("default".into()),
                Value::String("rb-pod-reader".into()),
                Value::String("alice".into()),
            ]);
            store.add_fact("rolebinding_roleref", vec![
                Value::String("default".into()),
                Value::String("rb-pod-reader".into()),
                Value::String("Role".into()),
                Value::String("pod-reader".into()),
            ]);
            store.add_fact("role_perm", vec![
                Value::String("default".into()),
                Value::String("pod-reader".into()),
                Value::String("".into()),
                Value::String("pods".into()),
                Value::String("get".into()),
            ]);
            Snapshot::from_store(&store, Scope::All)
        };

        let cfg = z3::Config::new();
        let ctx = z3::Context::new(&cfg);
        let mut enc = SmtEncoder::new(&ctx);
        enc.assert_rbac_axioms_from_snapshot_as(&empty_snap, "before");
        enc.assert_rbac_axioms_from_snapshot_as(&after_snap, "after");

        let gained = enc.check_permission_expansion("before", "after");
        assert_eq!(gained.len(), 1, "alice should be the only new principal");
        assert_eq!(gained[0].principal, "alice");
        assert_eq!(gained[0].namespace, "default");
        assert_eq!(gained[0].resource, "pods");
        assert_eq!(gained[0].verb, "get");

        // No contraction — nothing was removed.
        let lost = enc.check_permission_contraction("before", "after");
        assert!(lost.is_empty(), "no contraction expected");
    }

    #[test]
    fn wildcard_subsumption_is_not_expansion() {
        // "before" grants alice wildcard verb access on pods.
        // "after" keeps the wildcard AND adds an explicit narrow grant.
        // Tuple-level diff would falsely report GAINED pods/get.
        // The Z3 semantic check must return empty (the narrow grant is subsumed).
        let before_snap = {
            let mut store = MemStore::new();
            store.add_fact("rolebinding_subject_user", vec![
                Value::String("default".into()),
                Value::String("rb-alice".into()),
                Value::String("alice".into()),
            ]);
            store.add_fact("rolebinding_roleref", vec![
                Value::String("default".into()),
                Value::String("rb-alice".into()),
                Value::String("Role".into()),
                Value::String("wildcard-verbs".into()),
            ]);
            store.add_fact("role_perm", vec![
                Value::String("default".into()),
                Value::String("wildcard-verbs".into()),
                Value::String("".into()),
                Value::String("pods".into()),
                Value::String("*".into()),  // wildcard verb
            ]);
            Snapshot::from_store(&store, Scope::All)
        };

        let after_snap = {
            let mut store = MemStore::new();
            // Same wildcard binding as before.
            store.add_fact("rolebinding_subject_user", vec![
                Value::String("default".into()),
                Value::String("rb-alice".into()),
                Value::String("alice".into()),
            ]);
            store.add_fact("rolebinding_roleref", vec![
                Value::String("default".into()),
                Value::String("rb-alice".into()),
                Value::String("Role".into()),
                Value::String("wildcard-verbs".into()),
            ]);
            store.add_fact("role_perm", vec![
                Value::String("default".into()),
                Value::String("wildcard-verbs".into()),
                Value::String("".into()),
                Value::String("pods".into()),
                Value::String("*".into()),
            ]);
            // Additionally: an explicit narrow grant (subsumed by the wildcard).
            store.add_fact("rolebinding_subject_user", vec![
                Value::String("default".into()),
                Value::String("rb-alice-narrow".into()),
                Value::String("alice".into()),
            ]);
            store.add_fact("rolebinding_roleref", vec![
                Value::String("default".into()),
                Value::String("rb-alice-narrow".into()),
                Value::String("Role".into()),
                Value::String("explicit-get".into()),
            ]);
            store.add_fact("role_perm", vec![
                Value::String("default".into()),
                Value::String("explicit-get".into()),
                Value::String("".into()),
                Value::String("pods".into()),
                Value::String("get".into()),  // explicit, subsumed by *
            ]);
            Snapshot::from_store(&store, Scope::All)
        };

        let cfg = z3::Config::new();
        let ctx = z3::Context::new(&cfg);
        let mut enc = SmtEncoder::new(&ctx);
        enc.assert_rbac_axioms_from_snapshot_as(&before_snap, "before");
        enc.assert_rbac_axioms_from_snapshot_as(&after_snap, "after");

        // The narrow get grant is subsumed by the existing wildcard verb.
        // Z3 must find no expansion because can_before(alice,default,"",pods,get) is already true
        // due to the verb=* wildcard matching "get".
        let gained = enc.check_permission_expansion("before", "after");
        assert!(
            gained.is_empty(),
            "narrow grant subsumed by wildcard must not be reported as expansion; got: {:?}",
            gained.iter().map(|d| format!("{}/{}/{}/{}/{}", d.principal, d.namespace, d.apigroup, d.resource, d.verb)).collect::<Vec<_>>()
        );
    }
}
