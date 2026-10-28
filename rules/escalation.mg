# Privilege escalation rules.
#
# Models paths by which one principal can acquire the effective permissions of
# another identity. The key predicates:
#
#   controls_identity(P, Target) - P can assume Target's identity via at least
#       one escalation path. Transitively closed: if A->B->C then A controls C,
#       also when a step goes through a group P can impersonate.
#   controls_group(P, Group) - P, or an identity it controls, can impersonate
#       Group, which holds grants.
#
#   group_controls_identity(Group, Target), group_controls_group(Group, Other)
#       - the same, starting from a group's own grants. Any member of Group
#       gains what they reach.
#
# Principals (P, Target) are users and ServiceAccounts, by username. A group
# is never a principal: nobody authenticates as one. Impersonating a group is
# recorded in controls_group, and P then holds the group's grants, so
# whatever the group reaches (group_escalation_hop) P reaches too.
# Kubernetes only accepts Impersonate-Group alongside Impersonate-User; that
# second permission is not required here, which over-approximates. A group
# can also be where a path starts; see "Escalation from groups".
#
# Escalation paths modeled:
#   1. Impersonation  - impersonate verb on users/serviceaccounts/groups
#   2. SA token       - create on serviceaccounts/token subresource
#   3. Pod exec/attach - create on pods/exec or pods/attach exposes mounted token
#   4. Pod creation   - create on pods lets you run as any SA in that namespace
#
# Logging in and being assumed are different. A principal that logs in acts
# as itself and its principal_group groups, user_groups included. An
# identity assumed through escalation acts as itself and only the groups
# Kubernetes adds (implicit_group): an impersonated request carries the
# impersonated username plus system:authenticated (and, for a ServiceAccount,
# its ServiceAccount groups), and other groups only through Impersonate-Group
# headers, which controls_group models. A token or a pod gives a
# ServiceAccount its usual groups. So the first hop of a path uses
# principal_subject, and every later hop uses assumed_subject.
#
# What P can do through escalation is not materialized. Join on demand:
#
#   controls_identity(P, Target), assumed_subject(Target, Kind, Name),
#       direct_perm(Name, Kind, Ns, ApiGroup, Resource, ResourceName, Verb)
#   controls_group(P, Group), direct_perm(Group, /group, Ns, ...)
#   group_controls_identity(G, Target), then as for controls_identity

# ---- Permission guards ----
#
# grant_X(Name, Kind, Ns): the binding subject (Kind, Name) holds permission X
# in Ns. direct_perm stores "*" literals for apiGroup, resource and verb, so
# each guard checks all 8 combinations (2^3) of wildcard vs literal. Grants
# are filtered here, per subject, before principal_subject or
# assumed_subject expands them to the identities that hold them.
#
# The ResourceName column is ignored (_): a grant limited to some object names
# still counts. That over-approximates, the safe side for finding escalation
# paths.
#
# Impersonation is authorized per impersonated identity, as an impersonate
# request on users, groups, uids, userextras or serviceaccounts (see
# buildImpersonationRequests in k8s.io/apiserver's impersonation filter).
# Only a ServiceAccount request carries a namespace, the ServiceAccount's
# own, so subject_impersonatable_sa reaches ServiceAccounts in the grant's
# namespace (every namespace for Ns = ""). The others are cluster-scoped
# requests, which only a ClusterRoleBinding (Ns = "") matches, so the rules
# below use grant_user_impersonate and grant_group_impersonate with Ns = ""
# only. uids and userextras add nothing to a path and are not modeled.

grant_sa_token_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "serviceaccounts/token", _, "create").
grant_sa_token_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "serviceaccounts/token", _, "*").
grant_sa_token_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "*",                     _, "create").
grant_sa_token_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "*",                     _, "*").
grant_sa_token_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "serviceaccounts/token", _, "create").
grant_sa_token_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "serviceaccounts/token", _, "*").
grant_sa_token_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "*",                     _, "create").
grant_sa_token_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "*",                     _, "*").

grant_pods_exec_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "pods/exec", _, "create").
grant_pods_exec_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "pods/exec", _, "*").
grant_pods_exec_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "*",         _, "create").
grant_pods_exec_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "*",         _, "*").
grant_pods_exec_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "pods/exec", _, "create").
grant_pods_exec_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "pods/exec", _, "*").
grant_pods_exec_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "*",         _, "create").
grant_pods_exec_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "*",         _, "*").

grant_pods_attach_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "pods/attach", _, "create").
grant_pods_attach_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "pods/attach", _, "*").
grant_pods_attach_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "*",           _, "create").
grant_pods_attach_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "*",           _, "*").
grant_pods_attach_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "pods/attach", _, "create").
grant_pods_attach_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "pods/attach", _, "*").
grant_pods_attach_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "*",           _, "create").
grant_pods_attach_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "*",           _, "*").

grant_pods_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "pods", _, "create").
grant_pods_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "pods", _, "*").
grant_pods_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "*",    _, "create").
grant_pods_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "*",    _, "*").
grant_pods_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "pods", _, "create").
grant_pods_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "pods", _, "*").
grant_pods_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "*",    _, "create").
grant_pods_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "*",    _, "*").

grant_sa_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "serviceaccounts", _, "impersonate").
grant_sa_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "serviceaccounts", _, "*").
grant_sa_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "*",               _, "impersonate").
grant_sa_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "*",               _, "*").
grant_sa_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "serviceaccounts", _, "impersonate").
grant_sa_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "serviceaccounts", _, "*").
grant_sa_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "*",               _, "impersonate").
grant_sa_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "*",               _, "*").

grant_user_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "users", _, "impersonate").
grant_user_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "users", _, "*").
grant_user_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "*",     _, "impersonate").
grant_user_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "*",     _, "*").
grant_user_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "users", _, "impersonate").
grant_user_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "users", _, "*").
grant_user_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "*",     _, "impersonate").
grant_user_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "*",     _, "*").

grant_group_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "groups", _, "impersonate").
grant_group_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "groups", _, "*").
grant_group_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "*",      _, "impersonate").
grant_group_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "*",      _, "*").
grant_group_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "groups", _, "impersonate").
grant_group_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "groups", _, "*").
grant_group_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "*",      _, "impersonate").
grant_group_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "*",      _, "*").

# ---- Subjects of an assumed identity ----

Decl assumed_subject(Username, Kind, Name)
  descr [
    doc("Binding subjects a user or ServiceAccount matches when assumed through escalation (impersonation, a token or a pod): itself and the groups Kubernetes adds (implicit_group), but not its user_groups groups."),
    arg(Username, "user name or system:serviceaccount:<ns>:<name>"),
    arg(Kind, "/user, /group or /serviceaccount"),
    arg(Name, "Username itself for /user and /serviceaccount, else the group name")
  ].

assumed_subject(Username, /user, Username) :-
    known_principal(/user, Username).

assumed_subject(Username, /serviceaccount, Username) :-
    known_principal(/serviceaccount, Username).

assumed_subject(Username, /group, Group) :-
    implicit_group(Username, Group).

# ---- Escalation from one binding subject ----
#
# subject_X(Name, Kind, ...): what the grants of binding subject (Kind, Name)
# alone reach. Each mechanism has two forms: namespace-scoped (Ns matches
# directly) and cluster-wide (Ns=""). CRBs produce direct_perm with Ns=""
# which means "all namespaces" in K8s, so the cluster-wide variants join
# against all real namespaces where the target resource exists.
#
# Name comes first, the column a principal_subject or assumed_subject join
# binds, because the planner keys a lookup on an atom's first bound column.

subject_token_accessible_sa(Name, Kind, SANs, SAName) :-
    grant_sa_token_create(Name, Kind, SANs),
    serviceaccount(SANs, SAName, _).

subject_token_accessible_sa(Name, Kind, SANs, SAName) :-
    grant_sa_token_create(Name, Kind, ""),
    serviceaccount(SANs, SAName, _).

subject_exec_reachable_sa(Name, Kind, PodNs, SAName) :-
    grant_pods_exec_create(Name, Kind, PodNs),
    pod_sa(PodNs, _, SAName).

subject_exec_reachable_sa(Name, Kind, PodNs, SAName) :-
    grant_pods_exec_create(Name, Kind, ""),
    pod_sa(PodNs, _, SAName).

subject_exec_reachable_sa(Name, Kind, PodNs, SAName) :-
    grant_pods_attach_create(Name, Kind, PodNs),
    pod_sa(PodNs, _, SAName).

subject_exec_reachable_sa(Name, Kind, PodNs, SAName) :-
    grant_pods_attach_create(Name, Kind, ""),
    pod_sa(PodNs, _, SAName).

subject_pod_creatable_sa(Name, Kind, SANs, SAName) :-
    grant_pods_create(Name, Kind, SANs),
    serviceaccount(SANs, SAName, _).

subject_pod_creatable_sa(Name, Kind, SANs, SAName) :-
    grant_pods_create(Name, Kind, ""),
    serviceaccount(SANs, SAName, _).

subject_impersonatable_sa(Name, Kind, SANs, SAName) :-
    grant_sa_impersonate(Name, Kind, SANs),
    serviceaccount(SANs, SAName, _).

subject_impersonatable_sa(Name, Kind, SANs, SAName) :-
    grant_sa_impersonate(Name, Kind, ""),
    serviceaccount(SANs, SAName, _).

# An impersonated user acts as itself plus system:authenticated, and the
# impersonator is already in system:authenticated, so impersonating a user
# only gains something when the user holds grants of its own.
user_has_own_grant(Username) :-
    direct_perm(Username, /user, _, _, _, _, _).

Decl subject_escalation_hop(Name, Kind, Target)
  descr [
    doc("Single-step escalation using only the grants of binding subject (Kind, Name): whoever acts as that subject can assume Target's identity via one mechanism."),
    arg(Name, "subject name: user or group name, or system:serviceaccount:<ns>:<name>"),
    arg(Kind, "/user, /group or /serviceaccount"),
    arg(Target, "the user or ServiceAccount whose identity can be directly assumed")
  ].

subject_escalation_hop(Name, Kind, Target) :-
    subject_impersonatable_sa(Name, Kind, SANs, SAName)
    |> let Target = fn:string:concat("system:serviceaccount:", SANs, ":", SAName).

subject_escalation_hop(Name, Kind, Target) :-
    subject_token_accessible_sa(Name, Kind, SANs, SAName)
    |> let Target = fn:string:concat("system:serviceaccount:", SANs, ":", SAName).

subject_escalation_hop(Name, Kind, Target) :-
    subject_exec_reachable_sa(Name, Kind, PodNs, SAName)
    |> let Target = fn:string:concat("system:serviceaccount:", PodNs, ":", SAName).

subject_escalation_hop(Name, Kind, Target) :-
    subject_pod_creatable_sa(Name, Kind, SANs, SAName)
    |> let Target = fn:string:concat("system:serviceaccount:", SANs, ":", SAName).

# Cluster-wide grants only: impersonating a user is a cluster-scoped request.
subject_escalation_hop(Name, Kind, Target) :-
    grant_user_impersonate(Name, Kind, ""),
    user_has_own_grant(Target).

# ---- Escalation from a principal ----
#
# Single-step escalation: P can directly assume Target's identity via exactly
# one mechanism. Keeping this as a separate predicate (rather than inlining into
# controls_identity) is what makes the transitive closure below BFS-ordered:
# semi-naive evaluation extends controls_identity by one hop per fixpoint
# iteration, so shorter paths are always derived before longer ones. Because
# provenance records only the first (is_new) insertion, why on any
# controls_identity fact will show the shortest path to the target.

Decl escalation_hop(Principal, Target)
  descr [
    doc("Single-step escalation: Principal, logged in with all its groups, can assume Target's identity via one mechanism."),
    arg(Principal, "the user or ServiceAccount performing the escalation"),
    arg(Target, "the user or ServiceAccount whose identity Principal can directly assume")
  ].

escalation_hop(P, Target) :-
    principal_subject(P, Kind, Name),
    subject_escalation_hop(Name, Kind, Target).

Decl assumed_escalation_hop(Identity, Target)
  descr [
    doc("Single-step escalation from an identity assumed through escalation, which acts only as its assumed_subject subjects."),
    arg(Identity, "the user or ServiceAccount reached by an earlier hop"),
    arg(Target, "the user or ServiceAccount whose identity Identity can directly assume")
  ].

assumed_escalation_hop(Identity, Target) :-
    assumed_subject(Identity, Kind, Name),
    subject_escalation_hop(Name, Kind, Target).

# Group impersonation, from a principal as it logs in and from an assumed
# identity. Like user impersonation, only a cluster-wide grant counts: a
# RoleBinding allowing impersonate on groups allows nothing.
perm_group_impersonate(P) :-
    principal_subject(P, Kind, Name),
    grant_group_impersonate(Name, Kind, "").

assumed_group_impersonate(Identity) :-
    assumed_subject(Identity, Kind, Name),
    grant_group_impersonate(Name, Kind, "").

group_has_grant(Group) :-
    direct_perm(Group, /group, _, _, _, _, _).

# ---- controls_identity and controls_group ----
#
# One closure over three kinds of step: a hop from P as it logs in, a hop
# from an identity already assumed, and a hop from a group P can
# impersonate, whose grants P then holds. Each recursive rule extends a path
# by exactly one hop, preserving BFS order. The two relations are mutually
# recursive: impersonating groups can be what an assumed identity is
# allowed to do, and a group's grants can reach the next identity.

Decl controls_identity(Principal, Target)
  descr [
    doc("Principal can assume Target's identity via one or more escalation hops, through identities and impersonated groups (transitively closed)."),
    arg(Principal, "the user or ServiceAccount that gains control"),
    arg(Target, "the user or ServiceAccount Principal ultimately controls")
  ].

controls_identity(P, Target) :- escalation_hop(P, Target), P != Target.

controls_identity(P, Target) :-
    controls_identity(P, Mid),
    assumed_escalation_hop(Mid, Target).

controls_identity(P, Target) :-
    controls_group(P, Group),
    group_escalation_hop(Group, Target),
    P != Target.

# Group impersonation reaches every group that holds a grant.
Decl controls_group(Principal, Group)
  descr [
    doc("Principal, or an identity it controls, can impersonate Group, which holds grants."),
    arg(Principal, "user name or system:serviceaccount:<ns>:<name>"),
    arg(Group, "group whose direct_perm grants Principal can use")
  ].

controls_group(P, Group) :-
    perm_group_impersonate(P),
    group_has_grant(Group).

controls_group(P, Group) :-
    controls_identity(P, Mid),
    assumed_group_impersonate(Mid),
    group_has_grant(Group).

# ---- Escalation from groups ----
#
# A group is never a principal, but a binding can grant a group the
# permissions above. Group members are mostly unknown (membership comes from
# the authenticator, and user_groups only lists what the caller supplied), so
# paths that start from known users and ServiceAccounts would lose such a
# grant. These relations start from the group instead, using only its own
# grants, direct_perm(Group, /group, ...): whatever they reach, any member
# reaches too.

Decl group_escalation_hop(Group, Target)
  descr [
    doc("Single-step escalation from a group: any member of Group can assume Target's identity via one mechanism, using the group's own grants."),
    arg(Group, "group whose direct_perm grants allow the escalation"),
    arg(Target, "the user or ServiceAccount whose identity members of Group can directly assume")
  ].

group_escalation_hop(Group, Target) :-
    subject_escalation_hop(Group, /group, Target).

# The same closure as controls_identity and controls_group, from the
# group's own grants.
Decl group_controls_identity(Group, Target)
  descr [
    doc("Any member of Group can assume Target's identity via one or more escalation hops, starting from the group's own grants."),
    arg(Group, "group whose direct_perm grants start the escalation"),
    arg(Target, "the user or ServiceAccount members of Group ultimately control")
  ].

group_controls_identity(Group, Target) :- group_escalation_hop(Group, Target).

group_controls_identity(Group, Target) :-
    group_controls_identity(Group, Mid),
    assumed_escalation_hop(Mid, Target).

group_controls_identity(Group, Target) :-
    group_controls_group(Group, Other),
    group_escalation_hop(Other, Target).

Decl group_controls_group(Group, Other)
  descr [
    doc("Any member of Group, or an identity the group controls, can impersonate Other, which holds grants."),
    arg(Group, "group whose direct_perm grants start the escalation"),
    arg(Other, "another group whose direct_perm grants members of Group can use")
  ].

group_controls_group(Group, Other) :-
    grant_group_impersonate(Group, /group, ""),
    group_has_grant(Other),
    Group != Other.

group_controls_group(Group, Other) :-
    group_controls_identity(Group, Mid),
    assumed_group_impersonate(Mid),
    group_has_grant(Other),
    Group != Other.
