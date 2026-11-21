# Privilege escalation rules.
#
# Models the single hops by which one principal can acquire the effective
# permissions of another identity, as subject_hop rows with Source /grant,
# and the subjects an identity acts as (acts_as). closure.mg chains the hops
# into controls_identity, controls_group, group_controls_identity and
# group_controls_group.
#
# Principals are users and ServiceAccounts, by username. A group is never a
# principal: nobody authenticates as one. Impersonating a group is a hop to
# the group, and the impersonator then holds the group's grants, so whatever
# the group's own grants reach the impersonator reaches too. Kubernetes only
# accepts Impersonate-Group alongside Impersonate-User; that second
# permission is not required here, which over-approximates. A group can also
# be where a path starts: its members are mostly unknown (membership comes
# from the authenticator, and user_groups only lists what the caller
# supplied), so closure.mg starts paths from a group's own grants too.
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
# headers, which hops to groups model. A token or a pod gives a
# ServiceAccount its usual groups. So the first hop of a path uses
# principal_subject (acts_as /login), and every later hop uses
# assumed_subject (acts_as /assumed).
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
# Except for impersonation, the ResourceName column is ignored (_): a grant
# limited to some object names still counts. That over-approximates, the
# safe side for finding escalation paths.
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
#
# Each request names the identity: the username, the group, or the
# ServiceAccount's name (without system:serviceaccount:<ns>:). So the
# impersonate guards keep the ResourceName column, grant_X(Name, Kind, Ns,
# ResourceName), and a grant with resourceNames only reaches the identities
# it names. ResourceName /any (no resourceNames) reaches every identity.

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

grant_sa_impersonate(Name, Kind, Ns, ResourceName) :- direct_perm(Name, Kind, Ns, "",  "serviceaccounts", ResourceName, "impersonate").
grant_sa_impersonate(Name, Kind, Ns, ResourceName) :- direct_perm(Name, Kind, Ns, "",  "serviceaccounts", ResourceName, "*").
grant_sa_impersonate(Name, Kind, Ns, ResourceName) :- direct_perm(Name, Kind, Ns, "",  "*",               ResourceName, "impersonate").
grant_sa_impersonate(Name, Kind, Ns, ResourceName) :- direct_perm(Name, Kind, Ns, "",  "*",               ResourceName, "*").
grant_sa_impersonate(Name, Kind, Ns, ResourceName) :- direct_perm(Name, Kind, Ns, "*", "serviceaccounts", ResourceName, "impersonate").
grant_sa_impersonate(Name, Kind, Ns, ResourceName) :- direct_perm(Name, Kind, Ns, "*", "serviceaccounts", ResourceName, "*").
grant_sa_impersonate(Name, Kind, Ns, ResourceName) :- direct_perm(Name, Kind, Ns, "*", "*",               ResourceName, "impersonate").
grant_sa_impersonate(Name, Kind, Ns, ResourceName) :- direct_perm(Name, Kind, Ns, "*", "*",               ResourceName, "*").

grant_user_impersonate(Name, Kind, Ns, ResourceName) :- direct_perm(Name, Kind, Ns, "",  "users", ResourceName, "impersonate").
grant_user_impersonate(Name, Kind, Ns, ResourceName) :- direct_perm(Name, Kind, Ns, "",  "users", ResourceName, "*").
grant_user_impersonate(Name, Kind, Ns, ResourceName) :- direct_perm(Name, Kind, Ns, "",  "*",     ResourceName, "impersonate").
grant_user_impersonate(Name, Kind, Ns, ResourceName) :- direct_perm(Name, Kind, Ns, "",  "*",     ResourceName, "*").
grant_user_impersonate(Name, Kind, Ns, ResourceName) :- direct_perm(Name, Kind, Ns, "*", "users", ResourceName, "impersonate").
grant_user_impersonate(Name, Kind, Ns, ResourceName) :- direct_perm(Name, Kind, Ns, "*", "users", ResourceName, "*").
grant_user_impersonate(Name, Kind, Ns, ResourceName) :- direct_perm(Name, Kind, Ns, "*", "*",     ResourceName, "impersonate").
grant_user_impersonate(Name, Kind, Ns, ResourceName) :- direct_perm(Name, Kind, Ns, "*", "*",     ResourceName, "*").

grant_group_impersonate(Name, Kind, Ns, ResourceName) :- direct_perm(Name, Kind, Ns, "",  "groups", ResourceName, "impersonate").
grant_group_impersonate(Name, Kind, Ns, ResourceName) :- direct_perm(Name, Kind, Ns, "",  "groups", ResourceName, "*").
grant_group_impersonate(Name, Kind, Ns, ResourceName) :- direct_perm(Name, Kind, Ns, "",  "*",      ResourceName, "impersonate").
grant_group_impersonate(Name, Kind, Ns, ResourceName) :- direct_perm(Name, Kind, Ns, "",  "*",      ResourceName, "*").
grant_group_impersonate(Name, Kind, Ns, ResourceName) :- direct_perm(Name, Kind, Ns, "*", "groups", ResourceName, "impersonate").
grant_group_impersonate(Name, Kind, Ns, ResourceName) :- direct_perm(Name, Kind, Ns, "*", "groups", ResourceName, "*").
grant_group_impersonate(Name, Kind, Ns, ResourceName) :- direct_perm(Name, Kind, Ns, "*", "*",      ResourceName, "impersonate").
grant_group_impersonate(Name, Kind, Ns, ResourceName) :- direct_perm(Name, Kind, Ns, "*", "*",      ResourceName, "*").

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

# A named grant reaches only the ServiceAccounts with that name.
subject_impersonatable_sa(Name, Kind, SANs, SAName) :-
    grant_sa_impersonate(Name, Kind, SANs, /any),
    serviceaccount(SANs, SAName, _).

subject_impersonatable_sa(Name, Kind, SANs, SAName) :-
    grant_sa_impersonate(Name, Kind, SANs, SAName),
    serviceaccount(SANs, SAName, _).

subject_impersonatable_sa(Name, Kind, SANs, SAName) :-
    grant_sa_impersonate(Name, Kind, "", /any),
    serviceaccount(SANs, SAName, _).

subject_impersonatable_sa(Name, Kind, SANs, SAName) :-
    grant_sa_impersonate(Name, Kind, "", SAName),
    serviceaccount(SANs, SAName, _).

# An impersonated user acts as itself plus system:authenticated, and the
# impersonator is already in system:authenticated, so impersonating a user
# only gains something when the user holds grants of its own.
user_has_own_grant(Username) :-
    direct_perm(Username, /user, _, _, _, _, _).

group_has_grant(Group) :-
    direct_perm(Group, /group, _, _, _, _, _).

# ---- Hops from one binding subject (subject_hop, Source /grant) ----

subject_hop(Name, /k8s, Kind, Target, /k8s, /serviceaccount, /impersonate, /grant) :-
    subject_impersonatable_sa(Name, Kind, SANs, SAName)
    |> let Target = fn:string:concat("system:serviceaccount:", SANs, ":", SAName).

subject_hop(Name, /k8s, Kind, Target, /k8s, /serviceaccount, /token, /grant) :-
    subject_token_accessible_sa(Name, Kind, SANs, SAName)
    |> let Target = fn:string:concat("system:serviceaccount:", SANs, ":", SAName).

subject_hop(Name, /k8s, Kind, Target, /k8s, /serviceaccount, /pod_exec, /grant) :-
    subject_exec_reachable_sa(Name, Kind, PodNs, SAName)
    |> let Target = fn:string:concat("system:serviceaccount:", PodNs, ":", SAName).

subject_hop(Name, /k8s, Kind, Target, /k8s, /serviceaccount, /pod_create, /grant) :-
    subject_pod_creatable_sa(Name, Kind, SANs, SAName)
    |> let Target = fn:string:concat("system:serviceaccount:", SANs, ":", SAName).

# Cluster-wide grants only: impersonating a user is a cluster-scoped request.
# A named grant reaches only the users it names.
subject_hop(Name, /k8s, Kind, Target, /k8s, /user, /impersonate, /grant) :-
    grant_user_impersonate(Name, Kind, "", /any),
    user_has_own_grant(Target).

subject_hop(Name, /k8s, Kind, Target, /k8s, /user, /impersonate, /grant) :-
    grant_user_impersonate(Name, Kind, "", Target),
    user_has_own_grant(Target).

# Group impersonation. Like user impersonation, only a cluster-wide grant
# counts: a RoleBinding allowing impersonate on groups allows nothing. A
# named grant reaches only the groups it names, and only a group that holds
# a grant gains anything.
subject_hop(Name, /k8s, Kind, Group, /k8s, /group, /impersonate, /grant) :-
    grant_group_impersonate(Name, Kind, "", /any),
    group_has_grant(Group).

subject_hop(Name, /k8s, Kind, Group, /k8s, /group, /impersonate, /grant) :-
    grant_group_impersonate(Name, Kind, "", Group),
    group_has_grant(Group).

# ---- Subjects an identity acts as (acts_as) ----

acts_as(Identity, /k8s, Name, /k8s, Kind, /login) :-
    principal_subject(Identity, Kind, Name).

acts_as(Identity, /k8s, Name, /k8s, Kind, /assumed) :-
    assumed_subject(Identity, Kind, Name).
