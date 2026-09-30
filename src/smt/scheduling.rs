// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::{HashMap, HashSet};

use mangle_common::Value;
use z3::ast::{Ast, Bool, BV, String as Z3String};
use z3::SatResult;

use crate::engine::EvalStore;

pub struct UnschedulablePod {
    pub namespace: String,
    pub name: String,
}

/// For each pod that has nodeSelector requirements, check whether at least one
/// node satisfies all of them. UNSAT → unschedulable.
pub fn check_node_selector(store: &EvalStore) -> Vec<UnschedulablePod> {
    let mut pod_reqs: HashMap<(String, String), Vec<(String, String)>> = HashMap::new();
    for tuple in store.scan("pod_node_selector") {
        let (ns, name, key, val) = match tuple.as_slice() {
            [Value::String(ns), Value::String(name), Value::String(k), Value::String(v)] => {
                (ns, name, k, v)
            }
            _ => continue,
        };
        pod_reqs
            .entry((ns.clone(), name.clone()))
            .or_default()
            .push((key.clone(), val.clone()));
    }

    if pod_reqs.is_empty() {
        return vec![];
    }

    let mut node_labels: HashMap<String, HashSet<(String, String)>> = HashMap::new();
    for tuple in store.scan("object_label") {
        let (node_name, key, val) = match tuple.as_slice() {
            [Value::String(av), Value::String(k), Value::String(_ns), Value::String(name), Value::String(lk), Value::String(lv)]
                if k == "Node" && av == "v1" =>
            {
                (name, lk, lv)
            }
            _ => continue,
        };
        node_labels
            .entry(node_name.clone())
            .or_default()
            .insert((key.clone(), val.clone()));
    }

    let cfg = z3::Config::new();
    let ctx = z3::Context::new(&cfg);
    let mut unschedulable = Vec::new();

    for ((ns, name), reqs) in &pod_reqs {
        let solver = z3::Solver::new(&ctx);

        let node_vars: Vec<(String, Bool)> = node_labels
            .keys()
            .map(|n| (n.clone(), Bool::new_const(&ctx, n.as_str())))
            .collect();

        if node_vars.is_empty() {
            unschedulable.push(UnschedulablePod { namespace: ns.clone(), name: name.clone() });
            continue;
        }

        let empty = HashSet::new();
        for (node_name, node_var) in &node_vars {
            let labels = node_labels.get(node_name).unwrap_or(&empty);
            for (req_key, req_val) in reqs {
                if !labels.contains(&(req_key.clone(), req_val.clone())) {
                    solver.assert(&node_var.not());
                }
            }
        }

        let node_var_refs: Vec<&Bool> = node_vars.iter().map(|(_, v)| v).collect();
        solver.assert(&Bool::or(&ctx, &node_var_refs));

        if solver.check() != SatResult::Sat {
            unschedulable.push(UnschedulablePod { namespace: ns.clone(), name: name.clone() });
        }
    }

    unschedulable
}

pub enum PlacementResult {
    /// Valid assignment: pod key → node name
    Sat(Vec<(String, String)>),
    /// No valid placement exists
    Unsat,
}

/// Check whether pods with podAntiAffinity hard requirements can all be placed
/// simultaneously on the available nodes.
///
/// Each pod gets a Z3 integer variable representing its assigned node index.
/// Anti-affinity rules become `assign(A) ≠ assign(B)` constraints between
/// pods that conflict. SAT returns a concrete placement; UNSAT proves that no
/// valid placement exists.
pub fn check_anti_affinity_placement(store: &EvalStore) -> PlacementResult {
    // Collect all nodes.
    let nodes: Vec<String> = {
        let mut seen = HashSet::new();
        for tuple in store.scan("object_label") {
            if let [Value::String(av), Value::String(k), Value::String(_ns), Value::String(name), ..] =
                tuple.as_slice()
            {
                if av == "v1" && k == "Node" {
                    seen.insert(name.clone());
                }
            }
        }
        // Fall back to node_allocatable if object_label has no nodes.
        if seen.is_empty() {
            for tuple in store.scan("node_allocatable") {
                if let [Value::String(name), ..] = tuple.as_slice() {
                    seen.insert(name.clone());
                }
            }
        }
        let mut v: Vec<_> = seen.into_iter().collect();
        v.sort();
        v
    };

    let num_nodes = nodes.len() as i64;
    if num_nodes == 0 {
        return PlacementResult::Unsat;
    }

    // Build pod label index: (namespace, name) → set of (key, value).
    let mut pod_labels: HashMap<(String, String), HashSet<(String, String)>> = HashMap::new();
    for tuple in store.scan("object_label") {
        let (ns, name, key, val) = match tuple.as_slice() {
            [Value::String(av), Value::String(k), Value::String(ns), Value::String(name), Value::String(lk), Value::String(lv)]
                if av == "v1" && k == "Pod" =>
            {
                (ns, name, lk, lv)
            }
            _ => continue,
        };
        pod_labels
            .entry((ns.clone(), name.clone()))
            .or_default()
            .insert((key.clone(), val.clone()));
    }

    // Collect conflict pairs from pod_anti_affinity_req.
    // A conflicts with B if A requires no pod matching (key, val) and B has that label.
    // Filter self-conflicts (A != B).
    let mut conflicts: HashSet<(String, String, String, String)> = HashSet::new();
    for tuple in store.scan("pod_anti_affinity_req") {
        let (ns_a, name_a, match_key, match_val) = match tuple.as_slice() {
            [Value::String(ns), Value::String(name), Value::String(k), Value::String(v), Value::String(_topo)] => {
                (ns, name, k, v)
            }
            _ => continue,
        };

        for ((ns_b, name_b), labels) in &pod_labels {
            if (ns_a == ns_b && name_a == name_b)
                || !labels.contains(&(match_key.clone(), match_val.clone()))
            {
                continue;
            }
            // Normalise order so (A,B) and (B,A) don't both appear.
            let (ka, kb) = {
                let a = format!("{ns_a}/{name_a}");
                let b = format!("{ns_b}/{name_b}");
                if a <= b { (a, b) } else { (b, a) }
            };
            conflicts.insert((ka, kb, ns_a.clone(), name_a.clone()));
            let _ = (ns_a, name_a); // suppress move warning
        }
    }

    if conflicts.is_empty() {
        return PlacementResult::Sat(vec![]);
    }

    // Collect all pods involved in at least one conflict.
    let mut pods: HashSet<String> = HashSet::new();
    for (a, b, ..) in &conflicts {
        pods.insert(a.clone());
        pods.insert(b.clone());
    }
    let pods: Vec<String> = { let mut v: Vec<_> = pods.into_iter().collect(); v.sort(); v };

    let cfg = z3::Config::new();
    let ctx = z3::Context::new(&cfg);
    let solver = z3::Solver::new(&ctx);

    // Bitvector variable per pod: assign(pod) ∈ [0, num_nodes).
    // BV reduces to SAT internally — much faster than LIA for bounded UNSAT proofs.
    const BITS: u32 = 8; // supports clusters up to 256 nodes
    let pod_vars: HashMap<String, BV> = pods
        .iter()
        .map(|p| {
            let var = BV::new_const(&ctx, p.as_str(), BITS);
            solver.assert(&var.bvult(&BV::from_u64(&ctx, num_nodes as u64, BITS)));
            (p.clone(), var)
        })
        .collect();

    // Assert assign(A) ≠ assign(B) for each conflicting pair.
    for (a, b, ..) in &conflicts {
        if let (Some(va), Some(vb)) = (pod_vars.get(a), pod_vars.get(b)) {
            solver.assert(&va._eq(vb).not());
        }
    }

    match solver.check() {
        SatResult::Sat => {
            let model = solver.get_model().unwrap();
            let assignment = pods
                .iter()
                .filter_map(|p| {
                    let idx = model
                        .eval(pod_vars.get(p)?, true)
                        .and_then(|v| v.as_u64())? as usize;
                    let node = nodes.get(idx)?.clone();
                    Some((p.clone(), node))
                })
                .collect();
            PlacementResult::Sat(assignment)
        }
        _ => PlacementResult::Unsat,
    }
}

pub struct CoverageGap {
    /// The synthesized nodeSelector that no pool can satisfy.
    pub labels: Vec<(String, String)>,
}

/// Search for gaps in Karpenter NodePool coverage. Z3 synthesizes a concrete
/// nodeSelector (a set of label key=value pairs drawn from the pools' own
/// vocabularies) such that NO NodePool can provision a matching node. Each
/// value individually appears in some pool, but the combination falls through
/// every pool's constraints.
///
/// Returns up to `max_gaps` witnesses. An empty vec means full coverage
/// (Z3 UNSAT proof).
pub fn find_karpenter_coverage_gaps(store: &EvalStore, max_gaps: usize) -> Vec<CoverageGap> {
    struct PoolReq {
        in_values: HashSet<String>,
        notin_values: HashSet<String>,
        exists: bool,
        does_not_exist: bool,
    }

    let mut pool_reqs: HashMap<String, HashMap<String, PoolReq>> = HashMap::new();
    for tuple in store.scan("nodepool_requirement") {
        if let [Value::String(pool), Value::String(key), Value::String(op), Value::String(val)] =
            tuple.as_slice()
        {
            let entry = pool_reqs
                .entry(pool.clone())
                .or_default()
                .entry(key.clone())
                .or_insert_with(|| PoolReq {
                    in_values: HashSet::new(),
                    notin_values: HashSet::new(),
                    exists: false,
                    does_not_exist: false,
                });
            match op.as_str() {
                "In" => { entry.in_values.insert(val.clone()); }
                "NotIn" => { entry.notin_values.insert(val.clone()); }
                "Exists" => { entry.exists = true; }
                "DoesNotExist" => { entry.does_not_exist = true; }
                _ => {}
            }
        }
    }

    let mut pool_labels: HashMap<String, Vec<(String, String)>> = HashMap::new();
    for tuple in store.scan("nodepool_label") {
        if let [Value::String(pool), Value::String(key), Value::String(val)] = tuple.as_slice() {
            pool_labels
                .entry(pool.clone())
                .or_default()
                .push((key.clone(), val.clone()));
        }
    }

    let all_pools: Vec<String> = {
        let mut s: HashSet<String> = pool_reqs.keys().cloned().collect();
        for k in pool_labels.keys() {
            s.insert(k.clone());
        }
        let mut v: Vec<_> = s.into_iter().collect();
        v.sort();
        v
    };

    if all_pools.is_empty() {
        return vec![];
    }

    // Build the universe of values per label key across all pools.
    let mut key_values: HashMap<String, Vec<String>> = HashMap::new();
    for reqs in pool_reqs.values() {
        for (key, req) in reqs {
            let entry = key_values.entry(key.clone()).or_default();
            for v in &req.in_values {
                if !entry.contains(v) {
                    entry.push(v.clone());
                }
            }
        }
    }
    for labels in pool_labels.values() {
        for (key, val) in labels {
            let entry = key_values.entry(key.clone()).or_default();
            if !entry.contains(val) {
                entry.push(val.clone());
            }
        }
    }

    // Only consider keys with at least one known value.
    let keys: Vec<(String, Vec<String>)> = {
        let mut v: Vec<_> = key_values
            .into_iter()
            .filter(|(_, vs)| !vs.is_empty())
            .collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    };

    if keys.is_empty() {
        return vec![];
    }

    let cfg = z3::Config::new();
    let ctx = z3::Context::new(&cfg);
    let solver = z3::Solver::new(&ctx);

    // Per label key: a Z3 string var (the value) and a bool var (is this key
    // part of the synthesized nodeSelector?).
    let vars: Vec<(Z3String, Bool)> = keys
        .iter()
        .map(|(key, _)| {
            (
                Z3String::new_const(&ctx, format!("val_{key}").as_str()),
                Bool::new_const(&ctx, format!("req_{key}").as_str()),
            )
        })
        .collect();

    // Constrain each value to its known universe when selected.
    for (i, (_key, values)) in keys.iter().enumerate() {
        let (ref val_var, ref req_var) = vars[i];
        let in_universe: Vec<Bool> = values
            .iter()
            .map(|v| val_var._eq(&Z3String::from_str(&ctx, v).unwrap()))
            .collect();
        let refs: Vec<&Bool> = in_universe.iter().collect();
        // req_var → val_var ∈ universe
        solver.assert(&Bool::or(&ctx, &[&req_var.not(), &Bool::or(&ctx, &refs)]));
    }

    // At least two keys must be selected so the gap is combinatorial, not
    // trivially "key X only exists in pool A."
    // Fall back to one if there's only one key.
    if keys.len() >= 2 {
        let mut at_least_two: Vec<Bool> = Vec::new();
        for i in 0..vars.len() {
            for j in (i + 1)..vars.len() {
                at_least_two.push(Bool::and(&ctx, &[&vars[i].1, &vars[j].1]));
            }
        }
        let refs: Vec<&Bool> = at_least_two.iter().collect();
        solver.assert(&Bool::or(&ctx, &refs));
    } else {
        let req_refs: Vec<&Bool> = vars.iter().map(|(_, r)| r).collect();
        solver.assert(&Bool::or(&ctx, &req_refs));
    }

    // For each pool: assert the pool is blocked by at least one selected key.
    let empty_reqs = HashMap::new();
    let empty_labels: Vec<(String, String)> = Vec::new();
    for pool_name in &all_pools {
        let p_reqs = pool_reqs.get(pool_name).unwrap_or(&empty_reqs);
        let p_labels = pool_labels.get(pool_name).unwrap_or(&empty_labels);
        let guaranteed: HashMap<&str, &str> = p_labels
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        let mut blocking_clauses: Vec<Bool> = Vec::new();

        for (i, (key, _values)) in keys.iter().enumerate() {
            let (ref val_var, ref req_var) = vars[i];

            // Can this pool provide key=val_var?
            let can_provide = if let Some(req) = p_reqs.get(key) {
                if req.does_not_exist {
                    Bool::from_bool(&ctx, false)
                } else {
                    let mut conditions: Vec<Bool> = Vec::new();
                    if !req.in_values.is_empty() {
                        let clauses: Vec<Bool> = req
                            .in_values
                            .iter()
                            .map(|v| val_var._eq(&Z3String::from_str(&ctx, v).unwrap()))
                            .collect();
                        let refs: Vec<&Bool> = clauses.iter().collect();
                        conditions.push(Bool::or(&ctx, &refs));
                    }
                    for excluded in &req.notin_values {
                        conditions.push(
                            val_var
                                ._eq(&Z3String::from_str(&ctx, excluded).unwrap())
                                .not(),
                        );
                    }
                    if let Some(&gv) = guaranteed.get(key.as_str()) {
                        conditions.push(
                            val_var._eq(&Z3String::from_str(&ctx, gv).unwrap()),
                        );
                    }
                    if conditions.is_empty() {
                        Bool::from_bool(&ctx, true)
                    } else {
                        let refs: Vec<&Bool> = conditions.iter().collect();
                        Bool::and(&ctx, &refs)
                    }
                }
            } else if let Some(&gv) = guaranteed.get(key.as_str()) {
                val_var._eq(&Z3String::from_str(&ctx, gv).unwrap())
            } else {
                // Pool doesn't constrain this key at all - can provide any value.
                Bool::from_bool(&ctx, true)
            };

            // This key blocks the pool if: key is selected AND pool can't provide the value.
            blocking_clauses.push(Bool::and(&ctx, &[req_var, &can_provide.not()]));
        }

        // Pool must be blocked by at least one selected key.
        let refs: Vec<&Bool> = blocking_clauses.iter().collect();
        solver.assert(&Bool::or(&ctx, &refs));
    }

    // Extract witnesses, adding blocking clauses to find distinct gaps.
    let mut gaps = Vec::new();
    while gaps.len() < max_gaps {
        if solver.check() != SatResult::Sat {
            break;
        }
        let model = match solver.get_model() {
            Some(m) => m,
            None => break,
        };

        let mut labels = Vec::new();
        let mut blocking: Vec<Bool> = Vec::new();
        for (i, (key, _)) in keys.iter().enumerate() {
            let (ref val_var, ref req_var) = vars[i];
            let selected = model
                .eval(req_var, true)
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if selected {
                if let Some(val) = model.eval(val_var, true).and_then(|v| v.as_string()) {
                    blocking.push(
                        Bool::and(&ctx, &[
                            req_var,
                            &val_var._eq(&Z3String::from_str(&ctx, &val).unwrap()),
                        ])
                        .not(),
                    );
                    labels.push((key.clone(), val));
                }
            }
        }

        if labels.is_empty() {
            break;
        }

        let refs: Vec<&Bool> = blocking.iter().collect();
        solver.assert(&Bool::or(&ctx, &refs));

        gaps.push(CoverageGap { labels });
    }

    gaps
}
