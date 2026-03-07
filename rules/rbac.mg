# RBAC rules - models Kubernetes RBAC objects and derives effective permissions.
#
# Base facts (EDB - Extensional Database, i.e. facts asserted directly, not derived):
#   k8s/5          - Kubernetes objects loaded from the cluster
#   user_groups/2  - (Username, Group) populated at query time from a UserInfo struct
#   api_resource/2 - (ApiGroup, Resource) loaded from `kubectl api-resources -o name`
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
#     → all_user_perm/4   (union of user-direct + group-inherited perms)
#   api_resource/2 + all_user_perm/4
#     → resource_type/1, verb_type/1  (bounding sets for can_i)
#     → can_i/3                       (SubjectAccessReview equivalent, with wildcard expansion)

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
# Three join paths, each producing (SANs, SAName, ApiGroup, Resource, Verb):
#   1. SA → RoleBinding → Role                (namespace-scoped)
#   2. SA → RoleBinding → ClusterRole         (scoped to binding namespace)
#   3. SA → ClusterRoleBinding → ClusterRole  (cluster-wide)
#
# Path 2 includes BindingNs in the output because the ClusterRole's permissions
# are restricted to that namespace when applied via a RoleBinding.

# Path 1: RoleBinding → Role
sa_role_perm(SANs, SAName, ApiGroup, Resource, Verb) :-
    rolebinding_subject_sa(BindingNs, BindingName, SANs, SAName),
    rolebinding_roleref(BindingNs, BindingName, "Role", RoleName),
    role_perm(BindingNs, RoleName, ApiGroup, Resource, Verb).

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

# ---- all_user_perm ----
#
# Union of all effective permissions for a user: direct bindings plus
# permissions inherited through any group membership recorded in user_groups/2.
# user_groups(Username, Group) is populated at query time from a UserInfo struct.

all_user_perm(Username, ApiGroup, Resource, Verb) :-
    user_role_perm(Username, _, ApiGroup, Resource, Verb).

all_user_perm(Username, ApiGroup, Resource, Verb) :-
    user_rb_clusterrole_perm(Username, _, ApiGroup, Resource, Verb).

all_user_perm(Username, ApiGroup, Resource, Verb) :-
    user_crb_perm(Username, ApiGroup, Resource, Verb).

all_user_perm(Username, ApiGroup, Resource, Verb) :-
    user_groups(Username, Group),
    group_role_perm(Group, _, ApiGroup, Resource, Verb).

all_user_perm(Username, ApiGroup, Resource, Verb) :-
    user_groups(Username, Group),
    group_rb_clusterrole_perm(Group, _, ApiGroup, Resource, Verb).

all_user_perm(Username, ApiGroup, Resource, Verb) :-
    user_groups(Username, Group),
    group_crb_perm(Group, ApiGroup, Resource, Verb).

# ---- resource_type / verb_type ----
#
# Bounding sets used by can_i to keep derived facts finite.
#
# resource_type is derived from api_resource (EDB loaded from
# `kubectl api-resources -o name`), giving the canonical set of resource names
# known to the cluster. Additional resource_type facts can be injected directly
# into the store for resources not yet returned by api-resources (e.g. CRDs
# installed after the last load).
#
# verb_type is derived from permissions already present in roles and
# clusterroles, so it automatically covers every verb in use.

resource_type(Resource) :- api_resource(_, Resource).

verb_type(Verb) :- role_perm(_, _, _, _, Verb).
verb_type(Verb) :- clusterrole_perm(_, _, _, Verb).

# ---- can_i ----
#
# SubjectAccessReview equivalent. Returns true if Username has permission
# to perform Verb on Resource, accounting for Kubernetes wildcard semantics:
# a stored "*" in either the resource or verb position grants all values.
#
# resource_type and verb_type bind Resource and Verb so the derived fact set
# stays finite — one row per (username, resource, verb) triple where the user
# has access.

can_i(Username, Resource, Verb) :-
    resource_type(Resource), verb_type(Verb),
    all_user_perm(Username, _, Resource, Verb).

can_i(Username, Resource, Verb) :-
    resource_type(Resource), verb_type(Verb),
    all_user_perm(Username, _, "*", Verb).

can_i(Username, Resource, Verb) :-
    resource_type(Resource), verb_type(Verb),
    all_user_perm(Username, _, Resource, "*").

can_i(Username, Resource, Verb) :-
    resource_type(Resource), verb_type(Verb),
    all_user_perm(Username, _, "*", "*").
