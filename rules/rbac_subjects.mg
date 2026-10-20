# RBAC subjects - who each RoleBinding and ClusterRoleBinding applies to.
#
# Facts loaded from the cluster (EDB) used here:
#   k8s/5          - RoleBinding, ClusterRoleBinding and ServiceAccount objects
#   user_groups/2  - (Username, Group) memberships supplied by the caller
#
# Derived relations (IDB):
#   rolebinding/3, clusterrolebinding/2       (type filters)
#   binding_subject/4, binding_roleref/4      (one shape for both binding kinds)
#   service_account_principal/3               (SA namespace/name to username)
#   known_principal/2, principal_group/2      (principals and their groups)
#   principal_subject/3                       (the subjects a principal acts as)
#
# A subject is identified by a kind, one of /user, /group or /serviceaccount,
# and a name. Kinds are kept apart because Kubernetes matches them
# differently: a User subject "x" does not match a request from a member of
# group "x". ServiceAccount subjects are named by the username their tokens
# authenticate as, system:serviceaccount:<namespace>:<name>.

# ---- Type filters ----

rolebinding(Namespace, Name, Data) :-
    k8s("rbac.authorization.k8s.io/v1", "RoleBinding", Namespace, Name, Data).

clusterrolebinding(Name, Data) :-
    k8s("rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "", Name, Data).

# Both binding kinds, ClusterRoleBindings with namespace "".
binding(Namespace, Name, Data) :- rolebinding(Namespace, Name, Data).
binding("", Name, Data) :- clusterrolebinding(Name, Data).

# :match_field cannot compare against a constant, so subject kinds are
# translated through this table.
subject_kind("User", /user).
subject_kind("Group", /group).
subject_kind("ServiceAccount", /serviceaccount).

binding_subject_entry(BindingNamespace, Binding, Kind, Subject) :-
    binding(BindingNamespace, Binding, Data),
    :match_field(Data, /subjects, Subjects),
    :list:member(Subject, Subjects),
    :match_field(Subject, /kind, KindString),
    subject_kind(KindString, Kind).

# ServiceAccount subjects as (namespace, name). In a RoleBinding the
# namespace defaults to the binding's own when left out or empty; in a
# ClusterRoleBinding there is nothing to default to, and the subject matches
# no one (appliesToUser in k8s pkg/registry/rbac/validation/rule.go).

# The namespace a ServiceAccount subject names, when it names a non-empty one.
service_account_subject_namespace(Subject, Namespace) :-
    binding_subject_entry(_, _, /serviceaccount, Subject),
    :match_field(Subject, /namespace, Namespace),
    Namespace != "".

# A field cannot be tested for absence directly (a negated :match_field
# needs every argument bound), so the default goes through this helper.
service_account_subject_has_namespace(Subject) :-
    service_account_subject_namespace(Subject, _).

binding_service_account(BindingNamespace, Binding, Namespace, Name) :-
    binding_subject_entry(BindingNamespace, Binding, /serviceaccount, Subject),
    service_account_subject_namespace(Subject, Namespace),
    :match_field(Subject, /name, Name).

binding_service_account(BindingNamespace, Binding, BindingNamespace, Name) :-
    binding_subject_entry(BindingNamespace, Binding, /serviceaccount, Subject),
    BindingNamespace != "",
    !service_account_subject_has_namespace(Subject),
    :match_field(Subject, /name, Name).

Decl binding_subject(BindingNamespace, Binding, Kind, Name)
  descr [
    doc("Subjects of RoleBindings and ClusterRoleBindings, one row per subject."),
    arg(BindingNamespace, "RoleBinding namespace; empty for a ClusterRoleBinding"),
    arg(Binding, "binding name"),
    arg(Kind, "/user, /group or /serviceaccount"),
    arg(Name, "user or group name, or system:serviceaccount:<ns>:<name>")
  ].

binding_subject(BindingNamespace, Binding, /user, Name) :-
    binding_subject_entry(BindingNamespace, Binding, /user, Subject),
    :match_field(Subject, /name, Name).

binding_subject(BindingNamespace, Binding, /group, Name) :-
    binding_subject_entry(BindingNamespace, Binding, /group, Subject),
    :match_field(Subject, /name, Name).

binding_subject(BindingNamespace, Binding, /serviceaccount, Username) :-
    binding_service_account(BindingNamespace, Binding, Namespace, Name)
    |> let Username = fn:string:concat("system:serviceaccount:", Namespace, ":", Name).

Decl binding_roleref(BindingNamespace, Binding, RoleKind, RoleName)
  descr [
    doc("The role each RoleBinding or ClusterRoleBinding grants."),
    arg(BindingNamespace, "RoleBinding namespace; empty for a ClusterRoleBinding"),
    arg(Binding, "binding name"),
    arg(RoleKind, "Role or ClusterRole; a ClusterRoleBinding always names a ClusterRole"),
    arg(RoleName, "role name; a Role is looked up in the binding namespace")
  ].

binding_roleref(BindingNamespace, Binding, RoleKind, RoleName) :-
    binding(BindingNamespace, Binding, Data),
    :match_field(Data, /roleRef, RoleRef),
    :match_field(RoleRef, /kind, RoleKind),
    :match_field(RoleRef, /name, RoleName).

# ---- Principals ----

Decl service_account_principal(Namespace, Name, Username)
  descr [
    doc("ServiceAccounts that exist or are named by a binding, with their username."),
    arg(Namespace, "serviceaccount namespace"),
    arg(Name, "serviceaccount name"),
    arg(Username, "system:serviceaccount:<ns>:<name>")
  ].

service_account_principal(Namespace, Name, Username) :-
    binding_service_account(_, _, Namespace, Name)
    |> let Username = fn:string:concat("system:serviceaccount:", Namespace, ":", Name).

service_account_principal(Namespace, Name, Username) :-
    serviceaccount(Namespace, Name, _)
    |> let Username = fn:string:concat("system:serviceaccount:", Namespace, ":", Name).

Decl known_principal(Kind, Name)
  descr [
    doc("Principals the loaded objects mention: binding subjects, ServiceAccounts and user_groups users."),
    arg(Kind, "/user, /group or /serviceaccount"),
    arg(Name, "user or group name, or system:serviceaccount:<ns>:<name>")
  ].

known_principal(Kind, Name) :- binding_subject(_, _, Kind, Name).
known_principal(/serviceaccount, Username) :- service_account_principal(_, _, Username).
known_principal(/user, Username) :- user_groups(Username, _).

# The groups the authenticator puts a principal in. user_groups supplies
# them for users. ServiceAccount tokens always carry system:serviceaccounts
# and system:serviceaccounts:<ns>. Everyone except system:anonymous is in
# system:authenticated, and system:anonymous is in system:unauthenticated
# (authenticatedGroups in tools/rbac-oracle/request.go).
Decl principal_group(Username, Group)
  descr [
    doc("Groups a known user or ServiceAccount belongs to, from user_groups plus the groups Kubernetes adds."),
    arg(Username, "user name or system:serviceaccount:<ns>:<name>"),
    arg(Group, "group name")
  ].

principal_group(Username, Group) :- user_groups(Username, Group).

principal_group(Username, "system:serviceaccounts") :-
    service_account_principal(_, _, Username).

principal_group(Username, Group) :-
    service_account_principal(Namespace, _, Username)
    |> let Group = fn:string:concat("system:serviceaccounts:", Namespace).

principal_group(Username, "system:authenticated") :-
    service_account_principal(_, _, Username).

principal_group(Username, "system:authenticated") :-
    known_principal(/user, Username),
    Username != "system:anonymous".

principal_group(Username, "system:unauthenticated") :-
    known_principal(/user, Username),
    Username = "system:anonymous".

# A principal (a user or ServiceAccount username) matches binding subjects
# of two shapes: a User or ServiceAccount subject naming it, and a Group
# subject naming one of its groups. Grants live per subject in direct_perm,
# so this relation is what expands a principal into everything it acts as:
#
#   principal_subject(P, Kind, Name), direct_perm(Name, Kind, ...)
#
# Only the kinds a principal is known by are listed: a direct_perm row for
# (Kind, Name) comes from a binding subject, which makes (Kind, Name) a
# known_principal, so no grant is missed. Groups are subjects but never
# principals: nobody authenticates as a group.
Decl principal_subject(Username, Kind, Name)
  descr [
    doc("Binding subjects a known user or ServiceAccount matches: itself, and each of its groups as /group."),
    arg(Username, "user name or system:serviceaccount:<ns>:<name>"),
    arg(Kind, "/user, /group or /serviceaccount"),
    arg(Name, "Username itself for /user and /serviceaccount, else the group name")
  ].

principal_subject(Username, /user, Username) :-
    known_principal(/user, Username).

principal_subject(Username, /serviceaccount, Username) :-
    known_principal(/serviceaccount, Username).

principal_subject(Username, /group, Group) :-
    principal_group(Username, Group).
