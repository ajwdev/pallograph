// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RBAC fact extraction helpers shared by the finite access model and the
//! optional Z3 encoding.

use std::collections::HashSet;

use mangle_common::Value;

use super::PermissionEntry;

/// Returns `base` when suffix is empty, `base_suffix` otherwise.
pub(crate) fn relation_name(base: &str, suffix: &str) -> String {
    if suffix.is_empty() {
        base.to_string()
    } else {
        format!("{base}_{suffix}")
    }
}

pub(crate) fn parse_perm_tuples(rows: &[Vec<Value>]) -> Vec<PermissionEntry> {
    rows.iter()
        .filter_map(|t| {
            if let [
                Value::String(p),
                Value::String(ns),
                Value::String(ag),
                Value::String(r),
                Value::String(v),
            ] = t.as_slice()
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
pub(crate) fn parse_perm_tuples_6(rows: &[Vec<Value>]) -> Vec<PermissionEntry> {
    rows.iter()
        .filter_map(|t| {
            if let [
                Value::String(p),
                Value::String(ns),
                Value::String(ag),
                Value::String(r),
                Value::String(v),
                _,
            ] = t.as_slice()
            {
                Some((p.clone(), ns.clone(), ag.clone(), r.clone(), v.clone()))
            } else {
                None
            }
        })
        .collect()
}

pub(crate) fn effective_permission_entries(
    direct: &[Vec<Value>],
    indirect: &[Vec<Value>],
) -> (Vec<PermissionEntry>, Vec<PermissionEntry>) {
    let can_entries = parse_perm_tuples(direct);
    let eff_entries = {
        let mut set: HashSet<PermissionEntry> = HashSet::new();
        set.extend(can_entries.iter().cloned());
        set.extend(parse_perm_tuples_6(indirect));
        set.into_iter().collect()
    };
    (can_entries, eff_entries)
}

/// Build `subject_in_rb(principal, binding_ns, binding_name)` tuples.
pub(crate) fn compute_subject_in_rb(scan: &dyn Fn(&str) -> Vec<Vec<Value>>) -> Vec<Vec<Value>> {
    let mut result: HashSet<(String, String, String)> = HashSet::new();

    for t in scan("rolebinding_subject_sa") {
        if let [
            Value::String(b_ns),
            Value::String(b_name),
            Value::String(sa_ns),
            Value::String(sa_name),
        ] = t.as_slice()
        {
            let p = format!("system:serviceaccount:{sa_ns}:{sa_name}");
            result.insert((p, b_ns.clone(), b_name.clone()));
        }
    }

    for t in scan("rolebinding_subject_user") {
        if let [
            Value::String(b_ns),
            Value::String(b_name),
            Value::String(user),
        ] = t.as_slice()
        {
            result.insert((user.clone(), b_ns.clone(), b_name.clone()));
        }
    }

    let group_bindings: Vec<(String, String, String)> = scan("rolebinding_subject_group")
        .into_iter()
        .filter_map(|t| {
            if let [
                Value::String(b_ns),
                Value::String(b_name),
                Value::String(group),
            ] = t.as_slice()
            {
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
        if let [
            Value::String(b_name),
            Value::String(sa_ns),
            Value::String(sa_name),
        ] = t.as_slice()
        {
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
