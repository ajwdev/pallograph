# Privilege escalation rules.
#
# Models paths by which one principal can acquire the effective permissions of
# another identity. The key predicates:
#
#   controls_identity(P, Target) - P can assume Target's identity via at least
#       one escalation path. Transitively closed: if A->B->C then A controls C.
#   controls_group(P, Group) - P, or an identity it controls, can impersonate
#       Group, which holds grants.
#
#   group_controls_identity(Group, Target), group_controls_group(Group, Other)
#       - the same, starting from a group's own grants. Any member of Group
#       gains what they reach.
#
# Principals (P, Target) are users and ServiceAccounts, by username. A group
# is never a principal: nobody authenticates as one, so a group is never
# hopped to. Impersonating a group is recorded in controls_group instead, and
# the group's grants are not followed further: Kubernetes only accepts
# Impersonate-Group alongside Impersonate-User, and impersonating a user is
# modelled as its own hop. A group can be where a path starts, though; see
# "Escalation from groups" at the end of this file.
#
# Escalation paths modeled:
#   1. Impersonation  - impersonate verb on users/serviceaccounts/groups
#   2. SA token       - create on serviceaccounts/token subresource
#   3. Pod exec/attach - create on pods/exec or pods/attach exposes mounted token
#   4. Pod creation   - create on pods lets you run as any SA in that namespace
#
# What P can do through escalation is not materialized. Join on demand:
#
#   controls_identity(P, Target), principal_subject(Target, Kind, Name),
#       direct_perm(Name, Kind, Ns, ApiGroup, Resource, ResourceName, Verb)
#   controls_group(P, Group), direct_perm(Group, /group, Ns, ...)
#   group_controls_identity(G, Target), then as for controls_identity

# ---- Permission guards ----
#
# grant_X(Name, Kind, Ns): the binding subject (Kind, Name) holds permission X
# in Ns. direct_perm stores "*" literals for apiGroup, resource and verb, so
# each guard checks all 8 combinations (2^3) of wildcard vs literal. Grants
# are filtered here, per subject, before principal_subject expands them to
# the principals that hold them: perm_X(P, Ns).
#
# The ResourceName column is ignored (_): a grant limited to some object names
# still counts. That over-approximates, the safe side for finding escalation
# paths.
#
# perm_X looks grant_X up by subject name, its first column, so the join is
# keyed on Name rather than on Kind (see rbac.mg).

grant_sa_token_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "serviceaccounts/token", _, "create").
grant_sa_token_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "serviceaccounts/token", _, "*").
grant_sa_token_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "*",                     _, "create").
grant_sa_token_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "*",                     _, "*").
grant_sa_token_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "serviceaccounts/token", _, "create").
grant_sa_token_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "serviceaccounts/token", _, "*").
grant_sa_token_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "*",                     _, "create").
grant_sa_token_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "*",                     _, "*").

perm_sa_token_create(P, Ns) :-
    principal_subject(P, Kind, Name),
    grant_sa_token_create(Name, Kind, Ns).

grant_pods_exec_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "pods/exec", _, "create").
grant_pods_exec_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "pods/exec", _, "*").
grant_pods_exec_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "*",         _, "create").
grant_pods_exec_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "*",         _, "*").
grant_pods_exec_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "pods/exec", _, "create").
grant_pods_exec_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "pods/exec", _, "*").
grant_pods_exec_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "*",         _, "create").
grant_pods_exec_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "*",         _, "*").

perm_pods_exec_create(P, Ns) :-
    principal_subject(P, Kind, Name),
    grant_pods_exec_create(Name, Kind, Ns).

grant_pods_attach_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "pods/attach", _, "create").
grant_pods_attach_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "pods/attach", _, "*").
grant_pods_attach_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "*",           _, "create").
grant_pods_attach_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "*",           _, "*").
grant_pods_attach_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "pods/attach", _, "create").
grant_pods_attach_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "pods/attach", _, "*").
grant_pods_attach_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "*",           _, "create").
grant_pods_attach_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "*",           _, "*").

perm_pods_attach_create(P, Ns) :-
    principal_subject(P, Kind, Name),
    grant_pods_attach_create(Name, Kind, Ns).

grant_pods_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "pods", _, "create").
grant_pods_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "pods", _, "*").
grant_pods_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "*",    _, "create").
grant_pods_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "*",    _, "*").
grant_pods_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "pods", _, "create").
grant_pods_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "pods", _, "*").
grant_pods_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "*",    _, "create").
grant_pods_create(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "*",    _, "*").

perm_pods_create(P, Ns) :-
    principal_subject(P, Kind, Name),
    grant_pods_create(Name, Kind, Ns).

grant_sa_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "serviceaccounts", _, "impersonate").
grant_sa_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "serviceaccounts", _, "*").
grant_sa_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "*",               _, "impersonate").
grant_sa_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "*",               _, "*").
grant_sa_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "serviceaccounts", _, "impersonate").
grant_sa_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "serviceaccounts", _, "*").
grant_sa_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "*",               _, "impersonate").
grant_sa_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "*",               _, "*").

perm_sa_impersonate(P, Ns) :-
    principal_subject(P, Kind, Name),
    grant_sa_impersonate(Name, Kind, Ns).

grant_user_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "users", _, "impersonate").
grant_user_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "users", _, "*").
grant_user_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "*",     _, "impersonate").
grant_user_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "*",     _, "*").
grant_user_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "users", _, "impersonate").
grant_user_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "users", _, "*").
grant_user_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "*",     _, "impersonate").
grant_user_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "*",     _, "*").

perm_user_impersonate(P, Ns) :-
    principal_subject(P, Kind, Name),
    grant_user_impersonate(Name, Kind, Ns).

grant_group_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "groups", _, "impersonate").
grant_group_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "groups", _, "*").
grant_group_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "*",      _, "impersonate").
grant_group_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "",  "*",      _, "*").
grant_group_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "groups", _, "impersonate").
grant_group_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "groups", _, "*").
grant_group_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "*",      _, "impersonate").
grant_group_impersonate(Name, Kind, Ns) :- direct_perm(Name, Kind, Ns, "*", "*",      _, "*").

perm_group_impersonate(P, Ns) :-
    principal_subject(P, Kind, Name),
    grant_group_impersonate(Name, Kind, Ns).

# ---- Escalation path helpers ----
#
# Each helper has two forms: namespace-scoped (Ns matches directly) and
# cluster-wide (Ns=""). CRBs produce direct_perm with Ns="" which means
# "all namespaces" in K8s, so the cluster-wide variants join against all
# real namespaces where the target resource exists.

token_accessible_sa(P, SANs, SAName) :-
    perm_sa_token_create(P, SANs),
    serviceaccount(SANs, SAName, _).

token_accessible_sa(P, SANs, SAName) :-
    perm_sa_token_create(P, ""),
    serviceaccount(SANs, SAName, _).

exec_reachable_sa(P, PodNs, SAName) :-
    perm_pods_exec_create(P, PodNs),
    pod_sa(PodNs, _, SAName).

exec_reachable_sa(P, PodNs, SAName) :-
    perm_pods_exec_create(P, ""),
    pod_sa(PodNs, _, SAName).

exec_reachable_sa(P, PodNs, SAName) :-
    perm_pods_attach_create(P, PodNs),
    pod_sa(PodNs, _, SAName).

exec_reachable_sa(P, PodNs, SAName) :-
    perm_pods_attach_create(P, ""),
    pod_sa(PodNs, _, SAName).

pod_creatable_sa(P, SANs, SAName) :-
    perm_pods_create(P, SANs),
    serviceaccount(SANs, SAName, _).

pod_creatable_sa(P, SANs, SAName) :-
    perm_pods_create(P, ""),
    serviceaccount(SANs, SAName, _).

impersonatable_sa(P, SANs, SAName) :-
    perm_sa_impersonate(P, SANs),
    serviceaccount(SANs, SAName, _).

impersonatable_sa(P, SANs, SAName) :-
    perm_sa_impersonate(P, ""),
    serviceaccount(SANs, SAName, _).

# A principal holds some grant, directly or through one of its groups.
principal_has_grant(Username) :-
    principal_subject(Username, Kind, Name),
    direct_perm(Name, Kind, _, _, _, _, _).

# ---- escalation_hop ----
#
# Single-step escalation: P can directly assume Target's identity via exactly
# one mechanism. Keeping this as a separate predicate (rather than inlining into
# controls_identity) is what makes the transitive closure below BFS-ordered:
# semi-naive evaluation extends controls_identity by one escalation_hop per
# fixpoint iteration, so shorter paths are always derived before longer ones.
# Because provenance records only the first (is_new) insertion, \why on any
# controls_identity fact will show the shortest path to the target.

Decl escalation_hop(Principal, Target)
  descr [
    doc("Single-step escalation: Principal can assume Target's identity via one mechanism."),
    arg(Principal, "the user or ServiceAccount performing the escalation"),
    arg(Target, "the user or ServiceAccount whose identity Principal can directly assume")
  ].

escalation_hop(P, Target) :-
    impersonatable_sa(P, SANs, SAName)
    |> let Target = fn:string:concat("system:serviceaccount:", SANs, ":", SAName).

escalation_hop(P, Target) :-
    token_accessible_sa(P, SANs, SAName)
    |> let Target = fn:string:concat("system:serviceaccount:", SANs, ":", SAName).

escalation_hop(P, Target) :-
    exec_reachable_sa(P, PodNs, SAName)
    |> let Target = fn:string:concat("system:serviceaccount:", PodNs, ":", SAName).

escalation_hop(P, Target) :-
    pod_creatable_sa(P, SANs, SAName)
    |> let Target = fn:string:concat("system:serviceaccount:", SANs, ":", SAName).

# Impersonating a user is only recorded when the user holds some grant.
escalation_hop(P, Target) :-
    perm_user_impersonate(P, _),
    known_principal(/user, Target),
    principal_has_grant(Target).

# ---- controls_identity ----
#
# Transitive closure over escalation_hop. The recursive rule extends by exactly
# one escalation_hop (not controls_identity on both sides), preserving BFS order.

Decl controls_identity(Principal, Target)
  descr [
    doc("Principal can assume Target's identity via one or more escalation hops (transitively closed)."),
    arg(Principal, "the user or ServiceAccount that gains control"),
    arg(Target, "the user or ServiceAccount Principal ultimately controls")
  ].

controls_identity(P, Target) :- escalation_hop(P, Target), P != Target.

controls_identity(P, Target) :-
    controls_identity(P, Mid),
    escalation_hop(Mid, Target).

# ---- controls_group ----
#
# Group impersonation reaches every group that holds a grant. Like user
# impersonation, the guard ignores the namespace of the impersonate grant.

group_has_grant(Group) :-
    direct_perm(Group, /group, _, _, _, _, _).

Decl controls_group(Principal, Group)
  descr [
    doc("Principal, or an identity it controls, can impersonate Group, which holds grants. Groups do not hop further."),
    arg(Principal, "user name or system:serviceaccount:<ns>:<name>"),
    arg(Group, "group whose direct_perm grants Principal can use")
  ].

controls_group(P, Group) :-
    perm_group_impersonate(P, _),
    group_has_grant(Group).

controls_group(P, Group) :-
    controls_identity(P, Mid),
    perm_group_impersonate(Mid, _),
    group_has_grant(Group).

# ---- Escalation from groups ----
#
# A group is never a principal, but a binding can grant a group the
# permissions above. Group members are mostly unknown (membership comes from
# the authenticator, and user_groups only lists what the caller supplied), so
# the escalation_hop rules, which start from known users and ServiceAccounts,
# would lose such a grant. These relations start from the group instead,
# using only its own grants, direct_perm(Group, /group, ...): whatever they
# reach, any member reaches too.
#
# Each helper looks up its grant_X guard with Kind bound to /group. The guard
# is already filtered on resource and verb, so this is a scan of a small
# relation, not of direct_perm.

group_token_accessible_sa(Group, SANs, SAName) :-
    grant_sa_token_create(Group, /group, SANs),
    serviceaccount(SANs, SAName, _).

group_token_accessible_sa(Group, SANs, SAName) :-
    grant_sa_token_create(Group, /group, ""),
    serviceaccount(SANs, SAName, _).

group_exec_reachable_sa(Group, PodNs, SAName) :-
    grant_pods_exec_create(Group, /group, PodNs),
    pod_sa(PodNs, _, SAName).

group_exec_reachable_sa(Group, PodNs, SAName) :-
    grant_pods_exec_create(Group, /group, ""),
    pod_sa(PodNs, _, SAName).

group_exec_reachable_sa(Group, PodNs, SAName) :-
    grant_pods_attach_create(Group, /group, PodNs),
    pod_sa(PodNs, _, SAName).

group_exec_reachable_sa(Group, PodNs, SAName) :-
    grant_pods_attach_create(Group, /group, ""),
    pod_sa(PodNs, _, SAName).

group_pod_creatable_sa(Group, SANs, SAName) :-
    grant_pods_create(Group, /group, SANs),
    serviceaccount(SANs, SAName, _).

group_pod_creatable_sa(Group, SANs, SAName) :-
    grant_pods_create(Group, /group, ""),
    serviceaccount(SANs, SAName, _).

group_impersonatable_sa(Group, SANs, SAName) :-
    grant_sa_impersonate(Group, /group, SANs),
    serviceaccount(SANs, SAName, _).

group_impersonatable_sa(Group, SANs, SAName) :-
    grant_sa_impersonate(Group, /group, ""),
    serviceaccount(SANs, SAName, _).

Decl group_escalation_hop(Group, Target)
  descr [
    doc("Single-step escalation from a group: any member of Group can assume Target's identity via one mechanism, using the group's own grants."),
    arg(Group, "group whose direct_perm grants allow the escalation"),
    arg(Target, "the user or ServiceAccount whose identity members of Group can directly assume")
  ].

group_escalation_hop(Group, Target) :-
    group_impersonatable_sa(Group, SANs, SAName)
    |> let Target = fn:string:concat("system:serviceaccount:", SANs, ":", SAName).

group_escalation_hop(Group, Target) :-
    group_token_accessible_sa(Group, SANs, SAName)
    |> let Target = fn:string:concat("system:serviceaccount:", SANs, ":", SAName).

group_escalation_hop(Group, Target) :-
    group_exec_reachable_sa(Group, PodNs, SAName)
    |> let Target = fn:string:concat("system:serviceaccount:", PodNs, ":", SAName).

group_escalation_hop(Group, Target) :-
    group_pod_creatable_sa(Group, SANs, SAName)
    |> let Target = fn:string:concat("system:serviceaccount:", SANs, ":", SAName).

group_escalation_hop(Group, Target) :-
    grant_user_impersonate(Group, /group, _),
    known_principal(/user, Target),
    principal_has_grant(Target).

# One group hop, then the user and ServiceAccount closure. Not recursive:
# after the first hop the path continues from an identity, never a group.
Decl group_controls_identity(Group, Target)
  descr [
    doc("Any member of Group can assume Target's identity via one or more escalation hops, starting from the group's own grants."),
    arg(Group, "group whose direct_perm grants start the escalation"),
    arg(Target, "the user or ServiceAccount members of Group ultimately control")
  ].

group_controls_identity(Group, Target) :- group_escalation_hop(Group, Target).

group_controls_identity(Group, Target) :-
    group_escalation_hop(Group, Mid),
    controls_identity(Mid, Target).

Decl group_controls_group(Group, Other)
  descr [
    doc("Any member of Group, or an identity the group controls, can impersonate Other, which holds grants."),
    arg(Group, "group whose direct_perm grants start the escalation"),
    arg(Other, "another group whose direct_perm grants members of Group can use")
  ].

group_controls_group(Group, Other) :-
    grant_group_impersonate(Group, /group, _),
    group_has_grant(Other),
    Group != Other.

group_controls_group(Group, Other) :-
    group_controls_identity(Group, Mid),
    perm_group_impersonate(Mid, _),
    group_has_grant(Other),
    Group != Other.
