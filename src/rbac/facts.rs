// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RBAC fact extraction helpers shared by the finite access model and the
//! optional Z3 encoding.
//!
//! The rules keep grants per binding subject (`direct_perm`, with a Kind
//! column) and list separately which subjects each user or ServiceAccount
//! acts as (`principal_subject`). This module indexes both and does the join
//! the rules leave to consumers, per query rather than up front:
//!
//!   principal_subject(P, Kind, Name), direct_perm(Name, Kind, Ns, G, R, _, V)
//!
//! It also indexes who reaches whom through escalation: `controls_identity`
//! and `controls_group`, and from a group's own grants
//! `group_controls_identity` and `group_controls_group`. ResourceName is
//! projected away: these consumers have no object-name dimension, so a grant
//! limited to some names still counts.
//!
//! Rows are matched against fixed shapes. A row that does not fit means the
//! rules and this module disagree, so it panics in tests and is reported on
//! stderr otherwise, rather than being skipped silently. Outside tests such
//! rows are not always a bug: a REPL user can add an old-shaped row with
//! `+`, `\load` or `\define`.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;

use mangle_common::Value;

use super::PermissionEntry;

/// Returns `base` when suffix is empty, `base_suffix` otherwise.
pub fn relation_name(base: &str, suffix: &str) -> String {
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
    const ALL: [Self; 3] = [Self::User, Self::Group, Self::ServiceAccount];

    /// The kind's name constant in the rules, e.g. "/group".
    pub fn name_constant(self) -> &'static str {
        match self {
            Self::User => "/user",
            Self::Group => "/group",
            Self::ServiceAccount => "/serviceaccount",
        }
    }

    pub fn from_value(value: &Value) -> Option<Self> {
        match value {
            Value::Name(name) => Self::ALL
                .into_iter()
                .find(|kind| kind.name_constant() == name.as_str()),
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
        self.name_constant().trim_start_matches('/')
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

    /// The principal this binding subject is: a group stays a group, and a
    /// User or ServiceAccount subject is the principal its name names.
    pub fn principal(&self) -> Self {
        match self.kind {
            SubjectKind::Group => self.clone(),
            SubjectKind::User | SubjectKind::ServiceAccount => Self::username(self.name.as_str()),
        }
    }

    /// The principal as one Z3 string: the kind's name constant from the
    /// rules, a colon, then the name, e.g. "/group:admins". The kind tags
    /// contain no colon, so two different subjects never share a key.
    pub fn smt_key(&self) -> String {
        format!("{}:{}", self.kind.name_constant(), self.name)
    }

    /// Like `Display`, with the name quoted: `"admins" (group)`.
    pub fn quoted(&self) -> impl fmt::Display + '_ {
        SubjectDisplay {
            subject: self,
            quoted: true,
            annotate_users: false,
        }
    }

    /// Like `Display`, but a user is annotated too: `alice (user)`. A
    /// ServiceAccount username already says what it is.
    pub fn with_kind(&self) -> impl fmt::Display + '_ {
        SubjectDisplay {
            subject: self,
            quoted: false,
            annotate_users: true,
        }
    }
}

/// The name, with " (group)" after a group so that it reads apart from a user
/// of the same name.
impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        SubjectDisplay {
            subject: self,
            quoted: false,
            annotate_users: false,
        }
        .fmt(f)
    }
}

struct SubjectDisplay<'a> {
    subject: &'a Subject,
    quoted: bool,
    annotate_users: bool,
}

impl fmt::Display for SubjectDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Subject { name, kind } = self.subject;
        if self.quoted {
            write!(f, "{name:?}")?;
        } else {
            f.write_str(name)?;
        }
        let annotate = match kind {
            SubjectKind::Group => true,
            SubjectKind::User => self.annotate_users,
            SubjectKind::ServiceAccount => false,
        };
        if annotate {
            write!(f, " ({})", kind.as_str())?;
        }
        Ok(())
    }
}

/// (namespace, apigroup, resource, verb) of one grant, ResourceName dropped.
pub type Permission = (String, String, String, String);

/// Report a row whose shape does not match what the rules declare.
pub fn unexpected_row(relation: &str, row: &[Value]) {
    if cfg!(test) {
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
pub fn parse_direct_perm(rows: &[Vec<Value>]) -> Vec<(Subject, Permission)> {
    rows.iter()
        .filter_map(|row| {
            let parsed = match row.as_slice() {
                [
                    name,
                    kind,
                    namespace,
                    api_group,
                    resource,
                    Value::Name(_) | Value::String(_),
                    verb,
                ] => (|| {
                    Some((
                        Subject::new(SubjectKind::from_value(kind)?, string(name)?.clone()),
                        (
                            string(namespace)?.clone(),
                            string(api_group)?.clone(),
                            string(resource)?.clone(),
                            string(verb)?.clone(),
                        ),
                    ))
                })(),
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
pub fn parse_principal_subject(rows: &[Vec<Value>]) -> Vec<(String, Subject)> {
    parse_principal_subject_rows("principal_subject", rows)
}

/// Rows of a relation shaped like `principal_subject(Username, Kind, Name)`,
/// such as `assumed_subject`.
pub fn parse_principal_subject_rows(relation: &str, rows: &[Vec<Value>]) -> Vec<(String, Subject)> {
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
                unexpected_row(relation, row);
            }
            parsed
        })
        .collect()
}

/// `binding_subject(BindingNamespace, Binding, Kind, Name)` rows as
/// (subject, (binding namespace, binding name)).
pub fn parse_binding_subject(rows: &[Vec<Value>]) -> Vec<(Subject, (String, String))> {
    rows.iter()
        .filter_map(|row| {
            let parsed = match row.as_slice() {
                [
                    Value::String(binding_namespace),
                    Value::String(binding),
                    kind,
                    Value::String(name),
                ] => SubjectKind::from_value(kind).map(|kind| {
                    (
                        Subject::new(kind, name.clone()),
                        (binding_namespace.clone(), binding.clone()),
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

/// Rows of a relation keyed by a binding subject, `(Name, Kind, ...)` with
/// `N` string columns after the kind.
pub fn parse_subject_rows<const N: usize>(
    relation: &str,
    rows: &[Vec<Value>],
) -> Vec<(Subject, [String; N])> {
    rows.iter()
        .filter_map(|row| {
            let parsed = match row.as_slice() {
                [Value::String(name), kind, rest @ ..] if rest.len() == N => (|| {
                    let rest: Vec<String> = rest
                        .iter()
                        .map(|value| string(value).cloned())
                        .collect::<Option<_>>()?;
                    Some((
                        Subject::new(SubjectKind::from_value(kind)?, name.clone()),
                        rest.try_into().ok()?,
                    ))
                })(),
                _ => None,
            };
            if parsed.is_none() {
                unexpected_row(relation, row);
            }
            parsed
        })
        .collect()
}

/// Rows of an all-string relation of a fixed width.
pub fn parse_strings<const N: usize>(relation: &str, rows: &[Vec<Value>]) -> Vec<[String; N]> {
    rows.iter()
        .filter_map(|row| {
            let parsed: Option<[String; N]> = (row.len() == N)
                .then(|| {
                    row.iter()
                        .map(|value| string(value).cloned())
                        .collect::<Option<Vec<_>>>()
                })
                .flatten()
                .and_then(|values| values.try_into().ok());
            if parsed.is_none() {
                unexpected_row(relation, row);
            }
            parsed
        })
        .collect()
}

/// The RBAC relations, indexed for joining on demand.
///
/// A principal is a user or ServiceAccount username, or a group named by
/// some binding, keyed by `Subject` so that a user and a group with the same
/// name stay apart. Groups are principals of their own because their
/// members are mostly unknown: membership comes from the authenticator, and
/// `user_groups` only lists what the caller supplied.
///
/// A principal's direct grants are those of every subject it acts as: a
/// known user or ServiceAccount its own and its groups', a group its own.
/// Its effective grants add the grants of every identity and group it
/// controls through escalation. Neither is materialized per principal: with
/// many clusters, copying each group's grants to every member and each
/// target's grants to every controller multiplies, so the tables keep grants
/// per binding subject and the edges between principals, and consumers
/// expand what a query touches.
#[derive(Default)]
pub struct PermissionTables {
    /// Grants of each binding subject, keyed by `Subject::principal`, so a
    /// User subject naming a ServiceAccount username shares its grants.
    pub grants: HashMap<Subject, HashSet<Permission>>,
    /// The subjects each known user or ServiceAccount acts as, from
    /// `principal_subject`, with the kinds named there.
    pub principal_subjects: HashMap<String, Vec<Subject>>,
    /// The subjects each known user or ServiceAccount acts as when assumed
    /// through escalation, from `assumed_subject`.
    assumed_subjects: HashMap<String, Vec<Subject>>,
    /// Known members of each group, by username.
    group_members: HashMap<String, Vec<String>>,
    /// The identities (by username) and groups each principal controls
    /// through escalation. Never contains the principal itself.
    pub escalation_targets: HashMap<Subject, BTreeSet<Subject>>,
}

impl PermissionTables {
    pub fn from_scan(scan: &dyn Fn(&str) -> Vec<Vec<Value>>) -> Self {
        let mut grants: HashMap<Subject, HashSet<Permission>> = HashMap::new();
        for (subject, permission) in parse_direct_perm(&scan("direct_perm")) {
            grants
                .entry(subject.principal())
                .or_default()
                .insert(permission);
        }

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

        let mut assumed_subjects: HashMap<String, Vec<Subject>> = HashMap::new();
        for (username, subject) in
            parse_principal_subject_rows("assumed_subject", &scan("assumed_subject"))
        {
            assumed_subjects.entry(username).or_default().push(subject);
        }

        // From a user or ServiceAccount (controls_identity, controls_group)
        // and from a group (group_controls_identity, group_controls_group).
        // Identity targets are usernames.
        let mut escalation_targets: HashMap<Subject, BTreeSet<Subject>> = HashMap::new();
        let mut add_target = |principal: Subject, target: Subject| {
            if principal != target {
                escalation_targets
                    .entry(principal)
                    .or_default()
                    .insert(target);
            }
        };
        for [principal, target] in
            parse_strings::<2>("controls_identity", &scan("controls_identity"))
        {
            add_target(Subject::username(principal), Subject::username(target));
        }
        for [principal, group] in parse_strings::<2>("controls_group", &scan("controls_group")) {
            add_target(Subject::username(principal), Subject::group(group));
        }
        for [group, target] in
            parse_strings::<2>("group_controls_identity", &scan("group_controls_identity"))
        {
            add_target(Subject::group(group), Subject::username(target));
        }
        for [group, other] in
            parse_strings::<2>("group_controls_group", &scan("group_controls_group"))
        {
            add_target(Subject::group(group), Subject::group(other));
        }

        Self {
            grants,
            principal_subjects,
            assumed_subjects,
            group_members,
            escalation_targets,
        }
    }

    /// Number of (binding subject, permission) grants.
    pub fn grant_count(&self) -> usize {
        self.grants.values().map(HashSet::len).sum()
    }

    /// The binding subjects `principal` acts as, with the kinds bindings
    /// name: a known user or ServiceAccount's own subject and groups, or the
    /// group itself. A user or ServiceAccount missing from
    /// `principal_subject`, such as one the other snapshot of an access diff
    /// knows, gets the groups any login brings (`login_subjects`).
    pub fn subjects_of(&self, principal: &Subject) -> Vec<Subject> {
        if principal.kind == SubjectKind::Group {
            return vec![principal.clone()];
        }
        self.principal_subjects
            .get(&principal.name)
            .cloned()
            .unwrap_or_else(|| login_subjects(&principal.name))
    }

    /// The binding subjects whose grants an identity or group reached through
    /// escalation brings: a group itself, or an identity as `assumed_subject`
    /// lists it, itself and the groups Kubernetes adds but not its
    /// `user_groups` groups. An impersonated request carries only those, and
    /// a token or a pod gives a ServiceAccount nothing more.
    pub fn target_subjects(&self, target: &Subject) -> Vec<Subject> {
        if target.kind == SubjectKind::Group {
            return vec![target.clone()];
        }
        self.assumed_subjects
            .get(&target.name)
            .cloned()
            .unwrap_or_else(|| vec![target.clone()])
    }

    /// The grants of `subjects`, each subject once.
    pub fn grants_of<'a>(
        &'a self,
        subjects: Vec<Subject>,
    ) -> impl Iterator<Item = &'a Permission> + use<'a> {
        let keys: BTreeSet<Subject> = subjects.iter().map(Subject::principal).collect();
        keys.into_iter()
            .filter_map(|key| self.grants.get(&key))
            .flatten()
    }

    /// `principal`'s grants without escalation.
    pub fn direct_grants<'a>(
        &'a self,
        principal: &Subject,
    ) -> impl Iterator<Item = &'a Permission> + use<'a> {
        self.grants_of(self.subjects_of(principal))
    }

    /// The grants an escalation `target` brings (see `target_subjects`).
    pub fn target_grants<'a>(
        &'a self,
        target: &Subject,
    ) -> impl Iterator<Item = &'a Permission> + use<'a> {
        self.grants_of(self.target_subjects(target))
    }

    /// The principals that hold the grants of binding subject `subject`
    /// (a key of `grants`): a group and its known members, or the user or
    /// ServiceAccount itself.
    pub fn holders(&self, subject: &Subject) -> Vec<Subject> {
        let mut holders = vec![subject.clone()];
        if subject.kind == SubjectKind::Group {
            holders.extend(
                self.group_members
                    .get(&subject.name)
                    .into_iter()
                    .flatten()
                    .map(|member| Subject::username(member.as_str())),
            );
        }
        holders
    }

    /// Every principal with a grant `matches` accepts, without escalation.
    pub fn principals_with_direct(
        &self,
        matches: impl Fn(&Permission) -> bool,
    ) -> BTreeSet<Subject> {
        self.grants
            .iter()
            .filter(|(_, permissions)| permissions.iter().any(&matches))
            .flat_map(|(subject, _)| self.holders(subject))
            .collect()
    }

    /// Every principal with a grant `matches` accepts, directly or through
    /// an identity or group it controls.
    pub fn principals_with_effective(
        &self,
        matches: impl Fn(&Permission) -> bool,
    ) -> BTreeSet<Subject> {
        let mut principals = self.principals_with_direct(&matches);
        let mut target_matches: HashMap<&Subject, bool> = HashMap::new();
        for (principal, targets) in &self.escalation_targets {
            if principals.contains(principal) {
                continue;
            }
            let reaches = targets.iter().any(|target| {
                *target_matches
                    .entry(target)
                    .or_insert_with(|| self.target_grants(target).any(&matches))
            });
            if reaches {
                principals.insert(principal.clone());
            }
        }
        principals
    }

    /// Every principal: groups and users or ServiceAccounts with grants,
    /// known users and ServiceAccounts, and those escalation starts from.
    fn principals(&self) -> BTreeSet<Subject> {
        let mut principals: BTreeSet<Subject> = self.grants.keys().cloned().collect();
        principals.extend(
            self.principal_subjects
                .keys()
                .map(|username| Subject::username(username.as_str())),
        );
        principals.extend(self.escalation_targets.keys().cloned());
        principals
    }

    /// (principal, permission) for every direct grant, expanded through
    /// group membership. Built on demand for the access diff, which compares
    /// two snapshots entry by entry.
    pub fn direct_entries(&self) -> HashSet<PermissionEntry> {
        let mut entries = HashSet::new();
        for principal in self.principals() {
            for permission in self.direct_grants(&principal) {
                entries.insert(entry(&principal, permission));
            }
        }
        entries
    }

    /// `direct_entries` plus what escalation reaches.
    pub fn effective_entries(&self) -> HashSet<PermissionEntry> {
        let mut entries = self.direct_entries();
        for (principal, targets) in &self.escalation_targets {
            for target in targets {
                for permission in self.target_grants(target) {
                    entries.insert(entry(principal, permission));
                }
            }
        }
        entries
    }

    /// The identities and groups `principal` controls whose grants include
    /// `permission` exactly.
    pub fn escalation_via(
        &self,
        principal: &Subject,
        permission: &Permission,
    ) -> BTreeSet<Subject> {
        self.escalation_targets
            .get(principal)
            .into_iter()
            .flatten()
            .filter(|target| {
                self.target_grants(target)
                    .any(|granted| granted == permission)
            })
            .cloned()
            .collect()
    }
}

/// The subjects any login as `username` matches, whether or not the loaded
/// objects mention it: itself, and the groups Kubernetes adds, as
/// `implicit_group` and `principal_group` in rules/rbac_subjects.mg derive
/// them. A ServiceAccount is in system:serviceaccounts and
/// system:serviceaccounts:<ns>; everyone but system:anonymous is in
/// system:authenticated, and system:anonymous is in system:unauthenticated.
/// Groups from `user_groups` are supplied per user by the caller, so for a
/// username the rules do not know they cannot be included.
fn login_subjects(username: &str) -> Vec<Subject> {
    let mut subjects = vec![Subject::username(username)];
    if let Some(namespace) = username
        .strip_prefix("system:serviceaccount:")
        .and_then(|rest| rest.split_once(':'))
        .map(|(namespace, _)| namespace)
    {
        subjects.push(Subject::group("system:serviceaccounts"));
        subjects.push(Subject::group(format!(
            "system:serviceaccounts:{namespace}"
        )));
    }
    subjects.push(Subject::group(if username == "system:anonymous" {
        "system:unauthenticated"
    } else {
        "system:authenticated"
    }));
    subjects
}

fn entry(principal: &Subject, permission: &Permission) -> PermissionEntry {
    let (namespace, api_group, resource, verb) = permission.clone();
    (principal.clone(), namespace, api_group, resource, verb)
}

#[cfg(test)]
mod tests {
    use mangle_common::Value;

    use super::{PermissionTables, Subject, SubjectKind, parse_direct_perm};

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

    #[test]
    fn unknown_principals_get_the_groups_kubernetes_adds() {
        let tables = PermissionTables::default();
        assert_eq!(
            tables.subjects_of(&Subject::username("bob")),
            [
                Subject::username("bob"),
                Subject::group("system:authenticated")
            ]
        );
        assert_eq!(
            tables.subjects_of(&Subject::username("system:anonymous")),
            [
                Subject::username("system:anonymous"),
                Subject::group("system:unauthenticated")
            ]
        );
        let app = "system:serviceaccount:demo:app";
        assert_eq!(
            tables.subjects_of(&Subject::username(app)),
            [
                Subject::username(app),
                Subject::group("system:serviceaccounts"),
                Subject::group("system:serviceaccounts:demo"),
                Subject::group("system:authenticated"),
            ]
        );
    }

    #[test]
    fn kind_text_round_trips() {
        for kind in SubjectKind::ALL {
            let value = Value::Name(kind.name_constant().into());
            assert_eq!(SubjectKind::from_value(&value), Some(kind));
        }
        let admins = Subject::group("admins");
        assert_eq!(admins.smt_key(), "/group:admins");
        assert_eq!(admins.to_string(), "admins (group)");
        assert_eq!(admins.quoted().to_string(), r#""admins" (group)"#);
        let alice = Subject::username("alice");
        assert_eq!(alice.to_string(), "alice");
        assert_eq!(alice.with_kind().to_string(), "alice (user)");
        let app = Subject::username("system:serviceaccount:demo:app");
        assert_eq!(
            app.with_kind().to_string(),
            "system:serviceaccount:demo:app"
        );
    }

    /// `alice` logs in as a member of `devs` (from `user_groups`), which may
    /// read secrets, as may `system:serviceaccounts:demo`. `imp` may
    /// impersonate alice; `owner` controls the ServiceAccount `demo:app`.
    fn impersonation_tables() -> PermissionTables {
        let grant = |name: &str, kind: &str, resource: &str| {
            vec![
                Value::String(name.into()),
                Value::Name(kind.into()),
                Value::String("".into()),
                Value::String("".into()),
                Value::String(resource.into()),
                Value::Name("/any".into()),
                Value::String("get".into()),
            ]
        };
        let member = |username: &str, kind: &str, name: &str| {
            vec![
                Value::String(username.into()),
                Value::Name(kind.into()),
                Value::String(name.into()),
            ]
        };
        let pair =
            |from: &str, to: &str| vec![Value::String(from.into()), Value::String(to.into())];
        let app = "system:serviceaccount:demo:app";
        PermissionTables::from_scan(&|relation| match relation {
            "direct_perm" => vec![
                grant("devs", "/group", "secrets"),
                grant("system:serviceaccounts:demo", "/group", "secrets"),
                grant("system:authenticated", "/group", "selfsubjectreviews"),
                grant("alice", "/user", "configmaps"),
            ],
            "principal_subject" => vec![
                member("alice", "/user", "alice"),
                member("alice", "/group", "devs"),
                member("alice", "/group", "system:authenticated"),
                member(app, "/serviceaccount", app),
                member(app, "/group", "system:serviceaccounts:demo"),
            ],
            "assumed_subject" => vec![
                member("alice", "/user", "alice"),
                member("alice", "/group", "system:authenticated"),
                member(app, "/serviceaccount", app),
                member(app, "/group", "system:serviceaccounts:demo"),
            ],
            "controls_identity" => vec![pair("imp", "alice"), pair("owner", app)],
            _ => vec![],
        })
    }

    #[test]
    fn impersonating_a_user_does_not_bring_its_groups() {
        let tables = impersonation_tables();
        let resources = |grants: Vec<&super::Permission>| -> Vec<String> {
            let mut resources: Vec<String> = grants.into_iter().map(|p| p.2.clone()).collect();
            resources.sort();
            resources
        };
        let alice = Subject::username("alice");
        assert_eq!(
            resources(tables.direct_grants(&alice).collect()),
            ["configmaps", "secrets", "selfsubjectreviews"]
        );
        assert_eq!(
            resources(tables.target_grants(&alice).collect()),
            ["configmaps", "selfsubjectreviews"]
        );

        let reads_secrets = |p: &super::Permission| p.2 == "secrets";
        let principals = tables.principals_with_effective(reads_secrets);
        assert!(
            !principals.contains(&Subject::username("imp")),
            "{principals:?}"
        );
        // A ServiceAccount assumed through a token keeps its implicit groups.
        assert!(
            principals.contains(&Subject::username("owner")),
            "{principals:?}"
        );
    }

    #[test]
    fn group_grants_are_joined_on_query() {
        let tables = impersonation_tables();
        let principals = tables.principals_with_direct(|p| p.2 == "secrets");
        assert_eq!(
            principals.into_iter().collect::<Vec<_>>(),
            [
                Subject::username("alice"),
                Subject::group("devs"),
                Subject::username("system:serviceaccount:demo:app"),
                Subject::group("system:serviceaccounts:demo"),
            ]
        );
        // One grant per binding subject, not per member.
        assert_eq!(tables.grant_count(), 4);
        // imp and owner, missing from principal_subject, still log in as
        // system:authenticated (subjects_of).
        assert_eq!(tables.direct_entries().len(), 9);
    }
}
