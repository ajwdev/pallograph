// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RBAC fact extraction helpers shared by the finite access model and the
//! optional Z3 encoding.
//!
//! The rules keep grants per binding subject (`direct_perm`, with a Kind
//! column) and list separately which subjects each user or ServiceAccount
//! acts as (`principal_subject`). This module does the join the rules leave
//! to consumers:
//!
//!   principal_subject(P, Kind, Name), direct_perm(Name, Kind, Ns, G, R, _, V)
//!
//! and adds what escalation reaches through `controls_identity` and
//! `controls_group`, and from a group's own grants through
//! `group_controls_identity` and `group_controls_group`. ResourceName is projected away: these consumers have no
//! object-name dimension, so a grant limited to some names still counts.
//!
//! Rows are matched against fixed shapes. A row that does not fit means the
//! rules and this module disagree, so it panics in debug builds (tests) and
//! is reported on stderr otherwise, rather than being skipped silently.

use std::collections::{BTreeSet, HashMap, HashSet};

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

/// Binding subject kinds, the `/user`, `/group` and `/serviceaccount` name
/// constants in the rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SubjectKind {
    User,
    Group,
    ServiceAccount,
}

impl SubjectKind {
    pub fn from_value(value: &Value) -> Option<Self> {
        match value {
            Value::Name(name) => match name.as_str() {
                "/user" => Some(Self::User),
                "/group" => Some(Self::Group),
                "/serviceaccount" => Some(Self::ServiceAccount),
                _ => None,
            },
            _ => None,
        }
    }

    /// The kind of a principal name with no other information: ServiceAccount
    /// usernames are recognizable, anything else is taken to be a user.
    pub fn of_username(username: &str) -> Self {
        if username.starts_with("system:serviceaccount:") {
            Self::ServiceAccount
        } else {
            Self::User
        }
    }

    /// "user", "group" or "serviceaccount", as in report output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Group => "group",
            Self::ServiceAccount => "serviceaccount",
        }
    }
}

/// A user, group or ServiceAccount, by name (a ServiceAccount by username).
///
/// As a binding subject, the kind is the one the binding names. As a
/// principal in reports, it is `Group` for a group and otherwise follows
/// from the username (`Subject::username`): Kubernetes matches a User
/// subject named `system:serviceaccount:<ns>:<name>` against that
/// ServiceAccount, so the two are one principal. A user and a group with the
/// same name are two.
///
/// Name comes first so that sorting orders by name.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Subject {
    pub name: String,
    pub kind: SubjectKind,
}

impl Subject {
    pub fn new(kind: SubjectKind, name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind,
        }
    }

    pub fn group(name: impl Into<String>) -> Self {
        Self::new(SubjectKind::Group, name)
    }

    /// The principal a user or ServiceAccount username names.
    pub fn username(name: impl Into<String>) -> Self {
        let name = name.into();
        Self::new(SubjectKind::of_username(&name), name)
    }

    /// The principal as one Z3 string: the kind's name constant from the
    /// rules, a colon, then the name, e.g. "/group:admins". The kind tags
    /// contain no colon, so two different subjects never share a key.
    pub fn smt_key(&self) -> String {
        let tag = match self.kind {
            SubjectKind::User => "/user",
            SubjectKind::Group => "/group",
            SubjectKind::ServiceAccount => "/serviceaccount",
        };
        format!("{tag}:{}", self.name)
    }
}

/// The name, with " (group)" after a group so that it reads apart from a user
/// of the same name.
impl std::fmt::Display for Subject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            SubjectKind::Group => write!(f, "{} (group)", self.name),
            SubjectKind::User | SubjectKind::ServiceAccount => f.write_str(&self.name),
        }
    }
}

/// (namespace, apigroup, resource, verb) of one grant, ResourceName dropped.
pub type Permission = (String, String, String, String);

/// Report a row whose shape does not match what the rules declare.
pub(crate) fn unexpected_row(relation: &str, row: &[Value]) {
    if cfg!(debug_assertions) {
        panic!("{relation}: row does not match the declared shape: {row:?}");
    }
    eprintln!("warning: skipping {relation} row with an unexpected shape: {row:?}");
}

fn string(value: &Value) -> Option<&String> {
    match value {
        Value::String(s) => Some(s),
        _ => None,
    }
}

/// `direct_perm(Name, Kind, Ns, ApiGroup, Resource, ResourceName, Verb)` rows
/// as (subject, permission). ResourceName is /any or a string; either way it
/// is dropped.
pub(crate) fn parse_direct_perm(rows: &[Vec<Value>]) -> Vec<(Subject, Permission)> {
    rows.iter()
        .filter_map(|row| {
            let parsed = match row.as_slice() {
                [name, kind, ns, ag, r, Value::Name(_) | Value::String(_), v] => (|| {
                    Some((
                        Subject::new(SubjectKind::from_value(kind)?, string(name)?.clone()),
                        (
                            string(ns)?.clone(),
                            string(ag)?.clone(),
                            string(r)?.clone(),
                            string(v)?.clone(),
                        ),
                    ))
                })(
                ),
                _ => None,
            };
            if parsed.is_none() {
                unexpected_row("direct_perm", row);
            }
            parsed
        })
        .collect()
}

/// `principal_subject(Username, Kind, Name)` rows.
pub(crate) fn parse_principal_subject(rows: &[Vec<Value>]) -> Vec<(String, Subject)> {
    rows.iter()
        .filter_map(|row| {
            let parsed = match row.as_slice() {
                [Value::String(username), kind, Value::String(name)] => {
                    SubjectKind::from_value(kind)
                        .map(|kind| (username.clone(), Subject::new(kind, name.clone())))
                }
                _ => None,
            };
            if parsed.is_none() {
                unexpected_row("principal_subject", row);
            }
            parsed
        })
        .collect()
}

/// `binding_subject(BindingNs, Binding, Kind, Name)` rows as
/// (subject, (binding namespace, binding name)).
pub(crate) fn parse_binding_subject(rows: &[Vec<Value>]) -> Vec<(Subject, (String, String))> {
    rows.iter()
        .filter_map(|row| {
            let parsed = match row.as_slice() {
                [
                    Value::String(binding_ns),
                    Value::String(binding),
                    kind,
                    Value::String(name),
                ] => SubjectKind::from_value(kind).map(|kind| {
                    (
                        Subject::new(kind, name.clone()),
                        (binding_ns.clone(), binding.clone()),
                    )
                }),
                _ => None,
            };
            if parsed.is_none() {
                unexpected_row("binding_subject", row);
            }
            parsed
        })
        .collect()
}

/// Rows of an all-string relation of a fixed width.
pub(crate) fn parse_strings<const N: usize>(
    relation: &str,
    rows: &[Vec<Value>],
) -> Vec<[String; N]> {
    rows.iter()
        .filter_map(|row| {
            let parsed: Option<[String; N]> = (row.len() == N)
                .then(|| {
                    row.iter()
                        .map(|v| string(v).cloned())
                        .collect::<Option<Vec<_>>>()
                })
                .flatten()
                .and_then(|v| v.try_into().ok());
            if parsed.is_none() {
                unexpected_row(relation, row);
            }
            parsed
        })
        .collect()
}

/// Permissions per principal, expanded through group membership, plus what
/// escalation adds.
///
/// A principal here is a user or ServiceAccount username, or a group named by
/// some binding, keyed by `Subject` so that a user and a group with the same
/// name stay apart. Groups are kept as principals of their own because their
/// members are mostly unknown: membership comes from the authenticator, and
/// `user_groups` only lists what the caller supplied. A known member also
/// gets the group's grants under its own name, so a grant to
/// `system:authenticated` appears once for the group and once per known user
/// and ServiceAccount.
#[derive(Default)]
pub struct PermissionTables {
    /// (principal, namespace, apigroup, resource, verb), without escalation.
    pub direct: Vec<PermissionEntry>,
    /// `direct` plus what escalation reaches. Order is unspecified.
    pub effective: Vec<PermissionEntry>,
    /// For entries of `effective` reached through escalation, the identities
    /// and groups they were reached through.
    pub escalation_via: HashMap<PermissionEntry, BTreeSet<Subject>>,
    /// The subjects each known user or ServiceAccount acts as, from
    /// `principal_subject`.
    pub principal_subjects: HashMap<String, Vec<Subject>>,
    /// Grants of each group named by a `direct_perm` row.
    pub group_permissions: HashMap<String, HashSet<Permission>>,
}

impl PermissionTables {
    pub fn from_scan(scan: &dyn Fn(&str) -> Vec<Vec<Value>>) -> Self {
        let grants = parse_direct_perm(&scan("direct_perm"));

        let mut principal_subjects: HashMap<String, Vec<Subject>> = HashMap::new();
        let mut group_members: HashMap<String, Vec<String>> = HashMap::new();
        for (username, subject) in parse_principal_subject(&scan("principal_subject")) {
            if subject.kind == SubjectKind::Group {
                group_members
                    .entry(subject.name.clone())
                    .or_default()
                    .push(username.clone());
            }
            principal_subjects
                .entry(username)
                .or_default()
                .push(subject);
        }

        // Grants under a user or ServiceAccount name: its own and its groups'.
        let mut principal_grants: HashMap<String, HashSet<Permission>> = HashMap::new();
        let mut group_grants: HashMap<String, HashSet<Permission>> = HashMap::new();
        for (subject, permission) in grants {
            match subject.kind {
                SubjectKind::Group => {
                    for member in group_members.get(&subject.name).into_iter().flatten() {
                        principal_grants
                            .entry(member.clone())
                            .or_default()
                            .insert(permission.clone());
                    }
                    group_grants
                        .entry(subject.name)
                        .or_default()
                        .insert(permission);
                }
                SubjectKind::User | SubjectKind::ServiceAccount => {
                    principal_grants
                        .entry(subject.name)
                        .or_default()
                        .insert(permission);
                }
            }
        }

        let entry = |principal: &Subject, (ns, ag, r, v): &Permission| -> PermissionEntry {
            (
                principal.clone(),
                ns.clone(),
                ag.clone(),
                r.clone(),
                v.clone(),
            )
        };

        let mut direct: HashSet<PermissionEntry> = HashSet::new();
        for (username, permissions) in &principal_grants {
            let principal = Subject::username(username.as_str());
            direct.extend(permissions.iter().map(|p| entry(&principal, p)));
        }
        for (group, permissions) in &group_grants {
            let principal = Subject::group(group.as_str());
            direct.extend(permissions.iter().map(|p| entry(&principal, p)));
        }

        // Escalation from a user or ServiceAccount (controls_identity,
        // controls_group) and from a group (group_controls_identity,
        // group_controls_group). Identity targets are usernames.
        let mut escalation_via: HashMap<PermissionEntry, BTreeSet<Subject>> = HashMap::new();
        let mut add_via = |principal: Subject, target: Subject| {
            let permissions = match target.kind {
                SubjectKind::Group => group_grants.get(&target.name),
                SubjectKind::User | SubjectKind::ServiceAccount => {
                    principal_grants.get(&target.name)
                }
            };
            for permission in permissions.into_iter().flatten() {
                escalation_via
                    .entry(entry(&principal, permission))
                    .or_default()
                    .insert(target.clone());
            }
        };
        for [principal, target] in
            parse_strings::<2>("controls_identity", &scan("controls_identity"))
        {
            if principal != target {
                add_via(Subject::username(principal), Subject::username(target));
            }
        }
        for [principal, group] in parse_strings::<2>("controls_group", &scan("controls_group")) {
            add_via(Subject::username(principal), Subject::group(group));
        }
        for [group, target] in
            parse_strings::<2>("group_controls_identity", &scan("group_controls_identity"))
        {
            add_via(Subject::group(group), Subject::username(target));
        }
        for [group, other] in
            parse_strings::<2>("group_controls_group", &scan("group_controls_group"))
        {
            add_via(Subject::group(group), Subject::group(other));
        }

        let mut effective = direct.clone();
        effective.extend(escalation_via.keys().cloned());

        Self {
            direct: direct.into_iter().collect(),
            effective: effective.into_iter().collect(),
            escalation_via,
            principal_subjects,
            group_permissions: group_grants,
        }
    }
}

#[cfg(test)]
mod tests {
    use mangle_common::Value;

    use super::{Subject, SubjectKind, parse_direct_perm};

    #[test]
    fn direct_perm_rows_parse_with_kind_and_any_name() {
        let row = |resource_name: Value| {
            vec![
                Value::String("system:serviceaccount:demo:app".into()),
                Value::Name("/serviceaccount".into()),
                Value::String("demo".into()),
                Value::String("".into()),
                Value::String("secrets".into()),
                resource_name,
                Value::String("get".into()),
            ]
        };
        let parsed = parse_direct_perm(&[
            row(Value::Name("/any".into())),
            row(Value::String("db-password".into())),
        ]);
        assert_eq!(parsed.len(), 2);
        for (subject, permission) in parsed {
            assert_eq!(
                subject,
                Subject::new(
                    SubjectKind::ServiceAccount,
                    "system:serviceaccount:demo:app"
                )
            );
            assert_eq!(
                permission,
                (
                    "demo".to_string(),
                    String::new(),
                    "secrets".to_string(),
                    "get".to_string()
                )
            );
        }
    }

    // The old five-column shape must not be skipped silently.
    #[test]
    #[should_panic(expected = "direct_perm: row does not match the declared shape")]
    fn direct_perm_rows_of_the_old_shape_are_rejected() {
        parse_direct_perm(&[vec![
            Value::String("alice".into()),
            Value::String("default".into()),
            Value::String("".into()),
            Value::String("pods".into()),
            Value::String("get".into()),
        ]]);
    }
}
