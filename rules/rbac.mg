# RBAC rules - models Kubernetes RBAC objects and derives effective permissions.
#
# Base facts (EDB - Extensional Database, i.e. facts asserted directly, not derived):
#   k8s/5          - Kubernetes objects loaded from the cluster
#   user_groups/2  - (Username, Group) populated at query time from a UserInfo struct
#
# Predicate hierarchy (IDB - Intensional Database, i.e. facts derived by rules):
#   k8s/5
#     → role/3, clusterrole/2, rolebinding/3, clusterrolebinding/2  (type filters)
#     → role_perm/5, clusterrole_perm/4                             (permission flattening)
#     → rolebinding_subject_{sa,user,group}                         (subject extraction)
#     → clusterrolebinding_subject_{sa,user,group}                  (subject extraction)
#     → rolebinding_roleref/4, clusterrolebinding_roleref/2         (roleref extraction)
#     → sa_{role,rb_clusterrole,crb}_perm                          (effective SA perms)
#     → user_{role,rb_clusterrole,crb}_perm                        (effective user perms)
#     → group_{role,rb_clusterrole,crb}_perm                       (effective group perms)
#   user_groups/2
#     → all_{sa,user,group}_perm/N  (union of all binding paths, with Namespace)
#     → all_{sa,user,group}_ns_perm (namespace-scoped paths only)
#     → all_user_cluster_perm       (cluster-wide paths only, for users+groups)
#   all_{sa,user,group}_perm/N
#     → direct_perm/5  (principal, namespace, apigroup, resource, verb; wildcards preserved as-is)
#     → can/5          (alias for direct_perm; for REPL scanning — Z3 builds its own rec-func)

# ---- Type filter predicates ----

role(Namespace, Name, Data) :-
    k8s("rbac.authorization.k8s.io/v1", "Role", Namespace, Name, Data).

clusterrole(Name, Data) :-
    k8s("rbac.authorization.k8s.io/v1", "ClusterRole", "", Name, Data).

rolebinding(Namespace, Name, Data) :-
    k8s("rbac.authorization.k8s.io/v1", "RoleBinding", Namespace, Name, Data).

clusterrolebinding(Name, Data) :-
    k8s("rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "", Name, Data).

# ---- Permission flattening ----
#
# Each Role/ClusterRole has a list of PolicyRules. Each PolicyRule has lists of
# apiGroups, resources, and verbs. We flatten the three nested lists into
# individual (apiGroup, resource, verb) tuples via three :list:member calls.
#
# Note: "*" in any position is a Kubernetes wildcard string. It is stored as the
# Mangle string "*" and matched literally — see policies.mg for wildcard coverage
# predicates used at policy-check time.

role_perm(Namespace, RoleName, ApiGroup, Resource, Verb) :-
    role(Namespace, RoleName, Data),
    :match_field(Data, /rules, Rules),
    :list:member(PolicyRule, Rules),
    :match_field(PolicyRule, /apiGroups, ApiGroups),
    :match_field(PolicyRule, /resources, Resources),
    :match_field(PolicyRule, /verbs, Verbs),
    :list:member(ApiGroup, ApiGroups),
    :list:member(Resource, Resources),
    :list:member(Verb, Verbs).

clusterrole_perm(RoleName, ApiGroup, Resource, Verb) :-
    clusterrole(RoleName, Data),
    :match_field(Data, /rules, Rules),
    :list:member(PolicyRule, Rules),
    :match_field(PolicyRule, /apiGroups, ApiGroups),
    :match_field(PolicyRule, /resources, Resources),
    :match_field(PolicyRule, /verbs, Verbs),
    :list:member(ApiGroup, ApiGroups),
    :list:member(Resource, Resources),
    :list:member(Verb, Verbs).

# ---- Subject kind helpers ----
#
# :match_field requires its output argument to be a free variable — constants
# are not allowed. Use helper predicates for kind matching, the same pattern
# as is_true/1 in policies.mg.
subject_kind_sa("ServiceAccount").
subject_kind_user("User").
subject_kind_group("Group").

# ---- Subject extraction ----
#
# Subjects in bindings are kind-typed: ServiceAccount subjects have a namespace
# field; User and Group subjects do not. We handle each kind with a separate
# predicate so that :match_field on /namespace only runs for ServiceAccounts,
# where the field is guaranteed to exist.

rolebinding_subject_sa(BindingNs, BindingName, SubjectNs, SubjectName) :-
    rolebinding(BindingNs, BindingName, Data),
    :match_field(Data, /subjects, Subjects),
    :list:member(Subject, Subjects),
    :match_field(Subject, /kind, Kind),
    subject_kind_sa(Kind),
    :match_field(Subject, /namespace, SubjectNs),
    :match_field(Subject, /name, SubjectName).

rolebinding_subject_user(BindingNs, BindingName, SubjectName) :-
    rolebinding(BindingNs, BindingName, Data),
    :match_field(Data, /subjects, Subjects),
    :list:member(Subject, Subjects),
    :match_field(Subject, /kind, Kind),
    subject_kind_user(Kind),
    :match_field(Subject, /name, SubjectName).

rolebinding_subject_group(BindingNs, BindingName, GroupName) :-
    rolebinding(BindingNs, BindingName, Data),
    :match_field(Data, /subjects, Subjects),
    :list:member(Subject, Subjects),
    :match_field(Subject, /kind, Kind),
    subject_kind_group(Kind),
    :match_field(Subject, /name, GroupName).

clusterrolebinding_subject_sa(BindingName, SubjectNs, SubjectName) :-
    clusterrolebinding(BindingName, Data),
    :match_field(Data, /subjects, Subjects),
    :list:member(Subject, Subjects),
    :match_field(Subject, /kind, Kind),
    subject_kind_sa(Kind),
    :match_field(Subject, /namespace, SubjectNs),
    :match_field(Subject, /name, SubjectName).

clusterrolebinding_subject_user(BindingName, SubjectName) :-
    clusterrolebinding(BindingName, Data),
    :match_field(Data, /subjects, Subjects),
    :list:member(Subject, Subjects),
    :match_field(Subject, /kind, Kind),
    subject_kind_user(Kind),
    :match_field(Subject, /name, SubjectName).

# ---- RoleRef extraction ----

rolebinding_roleref(BindingNs, BindingName, RefKind, RefName) :-
    rolebinding(BindingNs, BindingName, Data),
    :match_field(Data, /roleRef, RoleRef),
    :match_field(RoleRef, /kind, RefKind),
    :match_field(RoleRef, /name, RefName).

clusterrolebinding_roleref(BindingName, RefName) :-
    clusterrolebinding(BindingName, Data),
    :match_field(Data, /roleRef, RoleRef),
    :match_field(RoleRef, /name, RefName).

# ---- Effective permissions ----
#
# Three join paths for each subject type. Namespace is always preserved:
#   1. Subject → RoleBinding → Role              (Namespace = binding namespace)
#   2. Subject → RoleBinding → ClusterRole       (Namespace = binding namespace)
#   3. Subject → ClusterRoleBinding → ClusterRole (Namespace = "")

# Path 1: RoleBinding → Role
sa_role_perm(SANs, SAName, Namespace, ApiGroup, Resource, Verb) :-
    rolebinding_subject_sa(Namespace, BindingName, SANs, SAName),
    rolebinding_roleref(Namespace, BindingName, "Role", RoleName),
    role_perm(Namespace, RoleName, ApiGroup, Resource, Verb).

# Path 2: RoleBinding → ClusterRole (namespace-scoped effect)
sa_rb_clusterrole_perm(SANs, SAName, BindingNs, ApiGroup, Resource, Verb) :-
    rolebinding_subject_sa(BindingNs, BindingName, SANs, SAName),
    rolebinding_roleref(BindingNs, BindingName, "ClusterRole", ClusterRoleName),
    clusterrole_perm(ClusterRoleName, ApiGroup, Resource, Verb).

# Path 3: ClusterRoleBinding → ClusterRole (cluster-wide)
sa_crb_perm(SANs, SAName, ApiGroup, Resource, Verb) :-
    clusterrolebinding_subject_sa(BindingName, SANs, SAName),
    clusterrolebinding_roleref(BindingName, ClusterRoleName),
    clusterrole_perm(ClusterRoleName, ApiGroup, Resource, Verb).

# User paths (no namespace for the subject)
user_role_perm(UserName, BindingNs, ApiGroup, Resource, Verb) :-
    rolebinding_subject_user(BindingNs, BindingName, UserName),
    rolebinding_roleref(BindingNs, BindingName, "Role", RoleName),
    role_perm(BindingNs, RoleName, ApiGroup, Resource, Verb).

user_rb_clusterrole_perm(UserName, BindingNs, ApiGroup, Resource, Verb) :-
    rolebinding_subject_user(BindingNs, BindingName, UserName),
    rolebinding_roleref(BindingNs, BindingName, "ClusterRole", ClusterRoleName),
    clusterrole_perm(ClusterRoleName, ApiGroup, Resource, Verb).

user_crb_perm(UserName, ApiGroup, Resource, Verb) :-
    clusterrolebinding_subject_user(BindingName, UserName),
    clusterrolebinding_roleref(BindingName, ClusterRoleName),
    clusterrole_perm(ClusterRoleName, ApiGroup, Resource, Verb).

# ---- Group subject extraction ----

clusterrolebinding_subject_group(BindingName, GroupName) :-
    clusterrolebinding(BindingName, Data),
    :match_field(Data, /subjects, Subjects),
    :list:member(Subject, Subjects),
    :match_field(Subject, /kind, Kind),
    subject_kind_group(Kind),
    :match_field(Subject, /name, GroupName).

# ---- Group effective permissions ----
#
# Mirror of the user paths, but keyed on group name. Groups appear as
# subjects in both RoleBindings and ClusterRoleBindings.

# Path 1: RoleBinding → Role (namespace-scoped)
group_role_perm(GroupName, BindingNs, ApiGroup, Resource, Verb) :-
    rolebinding_subject_group(BindingNs, BindingName, GroupName),
    rolebinding_roleref(BindingNs, BindingName, "Role", RoleName),
    role_perm(BindingNs, RoleName, ApiGroup, Resource, Verb).

# Path 2: RoleBinding → ClusterRole (namespace-scoped effect)
group_rb_clusterrole_perm(GroupName, BindingNs, ApiGroup, Resource, Verb) :-
    rolebinding_subject_group(BindingNs, BindingName, GroupName),
    rolebinding_roleref(BindingNs, BindingName, "ClusterRole", ClusterRoleName),
    clusterrole_perm(ClusterRoleName, ApiGroup, Resource, Verb).

# Path 3: ClusterRoleBinding → ClusterRole (cluster-wide)
group_crb_perm(GroupName, ApiGroup, Resource, Verb) :-
    clusterrolebinding_subject_group(BindingName, GroupName),
    clusterrolebinding_roleref(BindingName, ClusterRoleName),
    clusterrole_perm(ClusterRoleName, ApiGroup, Resource, Verb).

# ---- all_sa_perm / all_user_perm / all_group_perm ----
#
# Full union of all binding paths, namespace preserved (CRB emits "").
# Kept for enumeration use cases (e.g. listing all known users/groups in
# escalation rules) and direct policy queries. Not used by can/4 below.

all_sa_perm(SANs, SAName, Namespace, ApiGroup, Resource, Verb) :-
    sa_role_perm(SANs, SAName, Namespace, ApiGroup, Resource, Verb).

all_sa_perm(SANs, SAName, Namespace, ApiGroup, Resource, Verb) :-
    sa_rb_clusterrole_perm(SANs, SAName, Namespace, ApiGroup, Resource, Verb).

all_sa_perm(SANs, SAName, "", ApiGroup, Resource, Verb) :-
    sa_crb_perm(SANs, SAName, ApiGroup, Resource, Verb).

all_group_perm(GroupName, Namespace, ApiGroup, Resource, Verb) :-
    group_role_perm(GroupName, Namespace, ApiGroup, Resource, Verb).

all_group_perm(GroupName, Namespace, ApiGroup, Resource, Verb) :-
    group_rb_clusterrole_perm(GroupName, Namespace, ApiGroup, Resource, Verb).

all_group_perm(GroupName, "", ApiGroup, Resource, Verb) :-
    group_crb_perm(GroupName, ApiGroup, Resource, Verb).

all_user_perm(Username, Namespace, ApiGroup, Resource, Verb) :-
    user_role_perm(Username, Namespace, ApiGroup, Resource, Verb).

all_user_perm(Username, Namespace, ApiGroup, Resource, Verb) :-
    user_rb_clusterrole_perm(Username, Namespace, ApiGroup, Resource, Verb).


all_user_perm(Username, "", ApiGroup, Resource, Verb) :-
    user_crb_perm(Username, ApiGroup, Resource, Verb).

all_user_perm(Username, Namespace, ApiGroup, Resource, Verb) :-
    user_groups(Username, Group),
    group_role_perm(Group, Namespace, ApiGroup, Resource, Verb).

all_user_perm(Username, Namespace, ApiGroup, Resource, Verb) :-
    user_groups(Username, Group),
    group_rb_clusterrole_perm(Group, Namespace, ApiGroup, Resource, Verb).

all_user_perm(Username, "", ApiGroup, Resource, Verb) :-
    user_groups(Username, Group),
    group_crb_perm(Group, ApiGroup, Resource, Verb).

# ---- Aggregated ClusterRoles ----
#
# ClusterRoles can declare an aggregationRule whose clusterRoleSelectors list
# pulls in permissions from any ClusterRole whose labels match. This is how the
# built-in cluster-admin/admin/edit/view roles work.
#
# Each clusterRoleSelectors[i] entry is emitted by edb.rs as a synthetic selector
# owner (ApiVersion="pallograph.dev/agg", Kind="ClusterRoleAggregation",
# Namespace=i, Name=<AggCR>), with its matchLabels and matchExpressions requirements
# stored as standard selector_match_label/selector_expr_*/6 EDB facts. The
# selector_matches/8 engine in labels.mg then provides:
#   - AND semantics within one selector: all requirements must hold.
#   - OR semantics across selectors: each index is a separate owner.
#
# Note: an empty clusterRoleSelector (no matchLabels, no matchExpressions) produces
# no requirements and therefore matches nothing (fail-closed). This differs from the
# K8s aggregation controller, which treats an empty selector as "match all", but is
# safer for security analysis purposes.

clusterrole_aggregates(AggCR, SourceCR) :-
    selector_matches("pallograph.dev/agg", "ClusterRoleAggregation", SelIdx, AggCR,
                     "rbac.authorization.k8s.io/v1", "ClusterRole", "", SourceCR).

clusterrole_perm(AggCR, ApiGroup, Resource, Verb) :-
    clusterrole_aggregates(AggCR, SourceCR),
    clusterrole_perm(SourceCR, ApiGroup, Resource, Verb).

# ---- direct_perm ----
#
# Flat union of all binding paths for every subject type. Wildcards ("*") are
# preserved as-is — no expansion. Namespace="" for cluster-wide grants (CRB path).
# SA principals are formatted as system:serviceaccount:<ns>:<name>.

direct_perm(Principal, Namespace, ApiGroup, Resource, Verb) :-
    all_user_perm(Principal, Namespace, ApiGroup, Resource, Verb).

direct_perm(Principal, Namespace, ApiGroup, Resource, Verb) :-
    all_sa_perm(SANs, SAName, Namespace, ApiGroup, Resource, Verb)
    |> let Principal = fn:string:concat("system:serviceaccount:", SANs, ":", SAName).

direct_perm(Principal, Namespace, ApiGroup, Resource, Verb) :-
    all_group_perm(Principal, Namespace, ApiGroup, Resource, Verb).

# ---- can/5 alias ----
#
# A scannable alias for direct_perm. The Z3 SMT layer builds its own can/effective_can
# recursive functions from direct_perm and indirect_perm directly (see smt/rbac_model.rs);
# this relation exists for interactive querying in the REPL.
#
# Cluster-wide grants (ClusterRoleBinding path) carry Namespace="" here, consistent
# with direct_perm. The old Rust can/5 emitter expanded those to every concrete
# namespace — that was an implementation artifact, not the K8s model.
can(Principal, Namespace, ApiGroup, Resource, Verb) :-
    direct_perm(Principal, Namespace, ApiGroup, Resource, Verb).
