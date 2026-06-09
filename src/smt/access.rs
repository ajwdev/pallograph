use std::collections::HashSet;

use z3::ast::{Ast, Bool};
use z3::ast::String as Z3String;
use z3::SatResult;

use super::{AccessPath, SmtEncoder, Violation};
use super::rbac_model::fn_name;

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
            let paths = self.paths_for_principal(&principal, "", None);
            violations.push(Violation {
                principal,
                namespace: namespace.to_string(),
                resource: resource.to_string(),
                verb: verb.to_string(),
                paths,
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

            let paths = self.paths_for_principal(&principal, "", None);
            violations.push(Violation {
                principal,
                namespace: namespace.to_string(),
                resource,
                verb,
                paths,
            });
        }

        self.solver.pop(1);
        violations
    }

    /// Like `check_access_invariant` but queries `effective_can` (escalation-aware).
    /// Enumerates all principals that can reach `(namespace, apigroup, resource, verb)`
    /// via direct RBAC grants *or* via `controls_identity` escalation chains.
    pub fn check_reaches(
        &self,
        namespace: &str,
        apigroup: &str,
        resource: &str,
        verb: &str,
        expected: &[&str],
        include_direct: bool,
    ) -> Vec<Violation> {
        let Some(eff_decl) = self.get_decl("effective_can") else {
            return vec![];
        };

        let mut principal_set: HashSet<String> = HashSet::new();
        if let Some(rb_tuples) = self.facts.get("subject_in_rb") {
            for t in rb_tuples {
                if let [mangle_common::Value::String(p), mangle_common::Value::String(b_ns), ..] = t.as_slice() {
                    if namespace.is_empty() || b_ns == namespace {
                        principal_set.insert(p.clone());
                    }
                }
            }
        }
        if let Some(crb_tuples) = self.facts.get("subject_in_crb") {
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

        let witness = Z3String::new_const(self.ctx, "reaches_witness_principal");
        let ns_ast = Z3String::from_str(self.ctx, namespace).unwrap();
        let ag_ast = Z3String::from_str(self.ctx, apigroup).unwrap();
        let resource_ast = Z3String::from_str(self.ctx, resource).unwrap();
        let verb_ast = Z3String::from_str(self.ctx, verb).unwrap();

        // effective_can/5: (principal, ns, apigroup, resource, verb)
        let witness_reaches = eff_decl
            .apply(&[
                &witness as &dyn z3::ast::Ast,
                &ns_ast as &dyn z3::ast::Ast,
                &ag_ast as &dyn z3::ast::Ast,
                &resource_ast as &dyn z3::ast::Ast,
                &verb_ast as &dyn z3::ast::Ast,
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
            .map(|ep| witness._eq(&Z3String::from_str(self.ctx, ep).unwrap()).not())
            .collect();

        self.solver.push();
        self.solver.assert(&witness_reaches);
        self.solver.assert(&witness_is_known);
        if !not_expected.is_empty() {
            self.solver
                .assert(&Bool::and(self.ctx, &not_expected.iter().collect::<Vec<_>>()));
        }

        let mut violations = Vec::new();
        loop {
            if self.solver.check() != z3::SatResult::Sat {
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
            let paths = self.paths_for_principal(&principal, "", Some((namespace, apigroup, resource, verb)));
            violations.push(Violation {
                principal,
                namespace: namespace.to_string(),
                resource: resource.to_string(),
                verb: verb.to_string(),
                paths,
            });
        }

        self.solver.pop(1);

        // When include_direct is false (default), omit principals that have a direct grant
        // matching the query — only escalation paths are interesting.
        if !include_direct {
            let can = self.can_entries.get("").cloned().unwrap_or_default();
            violations.retain(|v| {
                !can.iter().any(|(ep, e_ns, e_ag, e_r, e_v)| {
                    ep == &v.principal
                        && e_ns == namespace
                        && (e_ag == "*" || apigroup == e_ag)
                        && (e_r == "*" || resource == e_r)
                        && (e_v == "*" || verb == e_v)
                })
            });
        }

        violations
    }

    /// Return all binding/role paths that grant `principal` access, derived from
    /// the RBAC subject and roleref facts loaded by `assert_rbac_axioms`.
    /// For each `controls_identity(principal, target)` entry, also returns the
    /// target's binding paths annotated with `via: Some(target)`.
    /// Return binding/role paths for `principal`.
    ///
    /// Direct bindings are always included. Escalation via-paths are included only
    /// when `perm_filter` is `Some((ns, ag, r, v))`, and only for targets that
    /// actually satisfy that query (using the same wildcard semantics as the Z3
    /// RecFuncDecl). Self-referential via entries are always excluded.
    ///
    /// Pass `None` for direct-grant queries (`check_access_invariant`) where
    /// escalation paths are out of scope.
    pub(crate) fn paths_for_principal(
        &self,
        principal: &str,
        suffix: &str,
        perm_filter: Option<(&str, &str, &str, &str)>,
    ) -> Vec<AccessPath> {
        use mangle_common::Value;

        let rb_key = fn_name("subject_in_rb", suffix);
        let crb_key = fn_name("subject_in_crb", suffix);
        let ci_key = fn_name("controls_identity", suffix);

        let rb_bindings: HashSet<(String, String)> = self.facts
            .get(&rb_key)
            .map(|rows| {
                rows.iter()
                    .filter_map(|t| {
                        if let [Value::String(p), Value::String(b_ns), Value::String(b_name)] = t.as_slice() {
                            if p == principal { Some((b_ns.clone(), b_name.clone())) } else { None }
                        } else { None }
                    })
                    .collect()
            })
            .unwrap_or_default();

        let crb_bindings: HashSet<String> = self.facts
            .get(&crb_key)
            .map(|rows| {
                rows.iter()
                    .filter_map(|t| {
                        if let [Value::String(p), Value::String(b_name)] = t.as_slice() {
                            if p == principal { Some(b_name.clone()) } else { None }
                        } else { None }
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Without a perm_filter (check_access_invariant mode): always show direct bindings.
        let Some((q_ns, q_ag, q_r, q_v)) = perm_filter else {
            let mut paths = Vec::new();
            self.collect_binding_paths(&rb_bindings, &crb_bindings, vec![], &mut paths);
            return paths;
        };

        // Check whether the principal has a direct grant matching the queried permission.
        let has_direct = self.can_entries.get(suffix).is_some_and(|entries| {
            entries.iter().any(|(ep, e_ns, e_ag, e_r, e_v)| {
                ep == principal
                    && e_ns == q_ns
                    && (e_ag == "*" || q_ag == e_ag)
                    && (e_r == "*" || q_r == e_r)
                    && (e_v == "*" || q_v == e_v)
            })
        });

        let mut paths = Vec::new();

        // For principals with direct access, show their binding — it IS the explanation.
        // Via-paths would be redundant noise.
        if has_direct {
            self.collect_binding_paths(&rb_bindings, &crb_bindings, vec![], &mut paths);
            return paths;
        }

        // Principal only reaches the permission via escalation chains.
        // Collect controls_identity targets, excluding self.
        let via_targets: Vec<String> = self.facts
            .get(&ci_key)
            .map(|rows| {
                rows.iter()
                    .filter_map(|t| {
                        if let [Value::String(p), Value::String(target)] = t.as_slice() {
                            if p == principal && target != principal {
                                Some(target.clone())
                            } else {
                                None
                            }
                        } else { None }
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Filter via-targets by whether they have DIRECT permission matching the query
        // (can_entries, not eff_entries). This breaks mutual-impersonation cycles:
        // a target that only has escalation access won't appear here, so cluster-admin
        // principals don't endlessly list each other as via-paths.
        let can = self.can_entries.get(suffix);
        let relevant_targets: Vec<&String> = via_targets.iter().filter(|target| {
            can.is_some_and(|entries| {
                entries.iter().any(|(ep, e_ns, e_ag, e_r, e_v)| {
                    ep == *target
                        && e_ns == q_ns
                        && (e_ag == "*" || q_ag == e_ag)
                        && (e_r == "*" || q_r == e_r)
                        && (e_v == "*" || q_v == e_v)
                })
            })
        }).collect();

        // Build hop chains for all relevant targets first.
        let target_chains: Vec<(&String, Vec<(String, String)>)> = relevant_targets
            .iter()
            .map(|t| (*t, self.build_hop_chain(principal, t, &mut HashSet::new())))
            .collect();

        // The set of identities that appear as the final hop of some chain.
        let final_hop_ids: HashSet<&str> = target_chains
            .iter()
            .filter_map(|(_, hops)| hops.last().map(|(id, _)| id.as_str()))
            .collect();

        // Suppress redundant longer paths: if a chain's intermediate hops include
        // another final-hop target, the longer chain adds no new information
        // (e.g. A→default→admin@ when A→default is already shown).
        for (target, hops) in &target_chains {
            let intermediates_are_endpoints = hops[..hops.len().saturating_sub(1)]
                .iter()
                .any(|(hop_id, _)| final_hop_ids.contains(hop_id.as_str()));
            if intermediates_are_endpoints {
                continue;
            }

            let target_rb: HashSet<(String, String)> = self.facts
                .get(&rb_key)
                .map(|rows| {
                    rows.iter()
                        .filter_map(|t| {
                            if let [Value::String(p), Value::String(b_ns), Value::String(b_name)] = t.as_slice() {
                                if p == target.as_str() { Some((b_ns.clone(), b_name.clone())) } else { None }
                            } else { None }
                        })
                        .collect()
                })
                .unwrap_or_default();

            let target_crb: HashSet<String> = self.facts
                .get(&crb_key)
                .map(|rows| {
                    rows.iter()
                        .filter_map(|t| {
                            if let [Value::String(p), Value::String(b_name)] = t.as_slice() {
                                if p == target.as_str() { Some(b_name.clone()) } else { None }
                            } else { None }
                        })
                        .collect()
                })
                .unwrap_or_default();

            self.collect_binding_paths(&target_rb, &target_crb, hops.clone(), &mut paths);
        }

        paths
    }

    /// Reconstruct the escalation hop chain from `principal` to `target`.
    /// Returns `Vec<(identity, mechanism)>` describing each step; the last element
    /// is always `target`. Handles multi-hop chains by walking `escalation_hop` facts.
    /// `visited` guards against cycles in mutual-escalation graphs.
    fn build_hop_chain(
        &self,
        principal: &str,
        target: &str,
        visited: &mut HashSet<String>,
    ) -> Vec<(String, String)> {
        use mangle_common::Value;

        // Check for a direct hop: escalation_hop(principal, target).
        let is_direct_hop = self.facts.get("escalation_hop").is_some_and(|rows| {
            rows.iter().any(|r| {
                if let [Value::String(p), Value::String(t)] = r.as_slice() {
                    p == principal && t == target
                } else {
                    false
                }
            })
        });

        if is_direct_hop {
            let mech = self.mechanism_for(principal, target).unwrap_or_default();
            return vec![(target.to_string(), mech)];
        }

        // Multi-hop: find an intermediate B where escalation_hop(principal, B)
        // and controls_identity(B, target). Guard against cycles with `visited`.
        if !visited.insert(principal.to_string()) {
            return vec![(target.to_string(), String::new())];
        }

        let intermediates: Vec<String> = self.facts
            .get("escalation_hop")
            .map(|rows| {
                rows.iter()
                    .filter_map(|r| {
                        if let [Value::String(p), Value::String(mid)] = r.as_slice() {
                            if p == principal && mid != target && !visited.contains(mid) {
                                Some(mid.clone())
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        for mid in &intermediates {
            let mid_reaches_target = self.facts.get("controls_identity").is_some_and(|rows| {
                rows.iter().any(|r| {
                    if let [Value::String(p), Value::String(t)] = r.as_slice() {
                        p == mid && t == target
                    } else {
                        false
                    }
                })
            });

            if mid_reaches_target {
                let mech_to_mid = self.mechanism_for(principal, mid).unwrap_or_default();
                let mut chain = vec![(mid.clone(), mech_to_mid)];
                chain.extend(self.build_hop_chain(mid, target, visited));
                return chain;
            }
        }

        // Fallback: transitive closure says it's reachable but we can't reconstruct the path.
        vec![(target.to_string(), String::new())]
    }

    /// Return the direct escalation mechanism(s) from `principal` to `target` in one hop.
    /// Returns a comma-separated string, e.g. "pods/exec, token". Empty string if unknown.
    fn mechanism_for(&self, principal: &str, target: &str) -> Option<String> {
        use mangle_common::Value;

        let mut mechanisms = Vec::new();

        let sa_prefix = "system:serviceaccount:";
        let (sa_ns, sa_name) = if let Some(rest) = target.strip_prefix(sa_prefix) {
            let mut parts = rest.splitn(2, ':');
            match (parts.next(), parts.next()) {
                (Some(ns), Some(name)) => (Some(ns), Some(name)),
                _ => (None, None),
            }
        } else {
            (None, None)
        };

        let matches_sa = |row: &[Value], rel_ns_idx: usize, rel_name_idx: usize| -> bool {
            if let (Some(target_ns), Some(target_name)) = (sa_ns, sa_name) {
                if let (Some(Value::String(p)), Some(Value::String(ns)), Some(Value::String(name))) =
                    (row.first(), row.get(rel_ns_idx), row.get(rel_name_idx))
                {
                    return p == principal && ns == target_ns && name == target_name;
                }
            }
            false
        };

        if self.facts.get("exec_reachable_sa").is_some_and(|r| r.iter().any(|row| matches_sa(row, 1, 2))) {
            mechanisms.push("pods/exec");
        }
        if self.facts.get("token_accessible_sa").is_some_and(|r| r.iter().any(|row| matches_sa(row, 1, 2))) {
            mechanisms.push("token");
        }
        if self.facts.get("pod_creatable_sa").is_some_and(|r| r.iter().any(|row| matches_sa(row, 1, 2))) {
            mechanisms.push("pods create");
        }
        if self.facts.get("impersonatable_sa").is_some_and(|r| r.iter().any(|row| matches_sa(row, 1, 2))) {
            mechanisms.push("impersonate");
        }

        // Non-SA target (user/group): mechanism must be impersonation.
        if sa_ns.is_none() && self.facts.get("escalation_hop").is_some_and(|rows| {
            rows.iter().any(|r| {
                if let [Value::String(p), Value::String(t)] = r.as_slice() {
                    p == principal && t == target
                } else {
                    false
                }
            })
        }) {
            mechanisms.push("impersonate");
        }

        if mechanisms.is_empty() {
            None
        } else {
            mechanisms.dedup();
            Some(mechanisms.join(", "))
        }
    }

    fn collect_binding_paths(
        &self,
        rb_bindings: &HashSet<(String, String)>,
        crb_bindings: &HashSet<String>,
        hops: Vec<(String, String)>,
        out: &mut Vec<AccessPath>,
    ) {
        use mangle_common::Value;

        if let Some(rows) = self.facts.get("rolebinding_roleref") {
            for t in rows {
                if let [Value::String(b_ns), Value::String(b_name), Value::String(ref_kind), Value::String(ref_name)] = t.as_slice() {
                    if rb_bindings.contains(&(b_ns.clone(), b_name.clone())) {
                        out.push(AccessPath {
                            binding_kind: "RoleBinding",
                            binding_namespace: b_ns.clone(),
                            binding_name: b_name.clone(),
                            role_kind: if ref_kind == "Role" { "Role" } else { "ClusterRole" },
                            role_name: ref_name.clone(),
                            hops: hops.clone(),
                        });
                    }
                }
            }
        }

        if let Some(rows) = self.facts.get("clusterrolebinding_roleref") {
            for t in rows {
                if let [Value::String(b_name), Value::String(ref_name)] = t.as_slice() {
                    if crb_bindings.contains(b_name) {
                        out.push(AccessPath {
                            binding_kind: "ClusterRoleBinding",
                            binding_namespace: String::new(),
                            binding_name: b_name.clone(),
                            role_kind: "ClusterRole",
                            role_name: ref_name.clone(),
                            hops: hops.clone(),
                        });
                    }
                }
            }
        }
    }
}
