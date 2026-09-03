// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::{HashMap, HashSet};

use mangle_common::Value;
use z3::ast::{Ast, Bool, BV};
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
