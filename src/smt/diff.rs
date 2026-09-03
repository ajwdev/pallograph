// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::HashSet;

use z3::ast::Ast;
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
    pub apigroup: String,
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

    // Iterate over tuples literally in `have_entries` but not `not_have_entries`, then
    // use Z3 to filter out any that are semantically subsumed by a wildcard in not_have.
    // This avoids the infinite-loop that results from asking Z3 to search the full string
    // space when a wildcard entry like ("alice","","","*","*") is present.
    fn can_diff_witnesses(&self, have: &str, not_have: &str) -> Vec<CanDiff> {
        let not_have_decl = match self.get_decl(&fn_name("can", not_have)) {
            Some(d) => d,
            None => return vec![],
        };

        let have_set: HashSet<_> = self.can_entries.get(have).into_iter().flatten().collect();
        let not_have_set: HashSet<_> = self.can_entries.get(not_have).into_iter().flatten().collect();

        let mut results = Vec::new();
        for (principal, namespace, apigroup, resource, verb) in have_set.difference(&not_have_set) {
            let p = Z3String::from_str(self.ctx, principal).unwrap();
            let ns = Z3String::from_str(self.ctx, namespace).unwrap();
            let ag = Z3String::from_str(self.ctx, apigroup).unwrap();
            let r = Z3String::from_str(self.ctx, resource).unwrap();
            let v = Z3String::from_str(self.ctx, verb).unwrap();
            let args: [&dyn Ast; 5] = [&p, &ns, &ag, &r, &v];
            let already_covered = not_have_decl.apply(&args).as_bool().unwrap();

            self.solver.push();
            self.solver.assert(&already_covered);
            let subsumed = self.solver.check() == SatResult::Sat;
            self.solver.pop(1);

            if !subsumed {
                results.push(CanDiff {
                    principal: principal.clone(),
                    namespace: namespace.clone(),
                    apigroup: apigroup.clone(),
                    resource: resource.clone(),
                    verb: verb.clone(),
                });
            }
        }
        results
    }

    // Same approach for effective_can: finite literal diff, Z3 only for subsumption checks.
    fn eff_diff_witnesses(&self, have: &str, not_have: &str) -> Vec<EffDiff> {
        let not_have_decl = match self.get_decl(&fn_name("effective_can", not_have)) {
            Some(d) => d,
            None => return vec![],
        };

        let have_set: HashSet<_> = self.eff_entries.get(have).into_iter().flatten().collect();
        let not_have_set: HashSet<_> = self.eff_entries.get(not_have).into_iter().flatten().collect();

        let mut results = Vec::new();
        for (principal, namespace, apigroup, resource, verb) in have_set.difference(&not_have_set) {
            let p = Z3String::from_str(self.ctx, principal).unwrap();
            let ns = Z3String::from_str(self.ctx, namespace).unwrap();
            let ag = Z3String::from_str(self.ctx, apigroup).unwrap();
            let r = Z3String::from_str(self.ctx, resource).unwrap();
            let v = Z3String::from_str(self.ctx, verb).unwrap();
            let args: [&dyn Ast; 5] = [&p, &ns, &ag, &r, &v];
            let already_covered = not_have_decl.apply(&args).as_bool().unwrap();

            self.solver.push();
            self.solver.assert(&already_covered);
            let subsumed = self.solver.check() == SatResult::Sat;
            self.solver.pop(1);

            if !subsumed {
                results.push(EffDiff {
                    principal: principal.clone(),
                    namespace: namespace.clone(),
                    apigroup: apigroup.clone(),
                    resource: resource.clone(),
                    verb: verb.clone(),
                });
            }
        }
        results
    }
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
        edb::load_from_manifests(&mut edb, vec!["testdata".to_string()]).expect("load testdata");
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
        let empty_snap = {
            let store = MemStore::new();
            Snapshot::from_store(&store, Scope::All)
        };

        let after_snap = {
            let mut store = MemStore::new();
            store.add_fact("direct_perm", vec![
                Value::String("alice".into()),
                Value::String("default".into()),
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
            store.add_fact("direct_perm", vec![
                Value::String("alice".into()),
                Value::String("default".into()),
                Value::String("".into()),
                Value::String("pods".into()),
                Value::String("*".into()),  // wildcard verb
            ]);
            Snapshot::from_store(&store, Scope::All)
        };

        let after_snap = {
            let mut store = MemStore::new();
            // Same wildcard grant as before.
            store.add_fact("direct_perm", vec![
                Value::String("alice".into()),
                Value::String("default".into()),
                Value::String("".into()),
                Value::String("pods".into()),
                Value::String("*".into()),
            ]);
            // Additionally: an explicit narrow grant (subsumed by the wildcard above).
            store.add_fact("direct_perm", vec![
                Value::String("alice".into()),
                Value::String("default".into()),
                Value::String("".into()),
                Value::String("pods".into()),
                Value::String("get".into()),
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
