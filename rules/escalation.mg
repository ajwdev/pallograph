# Privilege escalation rules.
#
# Models paths by which one principal can acquire the effective permissions of
# another identity. The key predicate:
#
#   controls_identity(P, Target) — P can assume Target's identity via at least
#       one escalation path. Transitively closed: if A→B→C then A controls C.
#
# Escalation paths modeled:
#   1. Impersonation  — impersonate verb on users/serviceaccounts/groups
#   2. SA token       — create on serviceaccounts/token subresource
#   3. Pod exec/attach — create on pods/exec or pods/attach exposes mounted token
#   4. Pod creation   — create on pods lets you run as any SA in that namespace
#
# Wildcard handling: perm/5 stores "*" literals for apiGroup, resource, and verb.
# Permission guards below check all 8 combinations (2^3) of wildcard vs literal
# for each (apiGroup, resource, verb) tuple escalation cares about.
# Each guard rule is safe Datalog: every head variable is bound by the body.

# ---- Permission guards ----
#
# perm_X(P, Ns): P has permission X in Ns under any combination of wildcards.
# Format: can(P, Ns, ApiGroup, Resource, Verb) with "*" matching any value.

perm_sa_token_create(P, Ns) :- direct_perm(P, Ns, "",  "serviceaccounts/token", "create").
perm_sa_token_create(P, Ns) :- direct_perm(P, Ns, "",  "serviceaccounts/token", "*").
perm_sa_token_create(P, Ns) :- direct_perm(P, Ns, "",  "*",                     "create").
perm_sa_token_create(P, Ns) :- direct_perm(P, Ns, "",  "*",                     "*").
perm_sa_token_create(P, Ns) :- direct_perm(P, Ns, "*", "serviceaccounts/token", "create").
perm_sa_token_create(P, Ns) :- direct_perm(P, Ns, "*", "serviceaccounts/token", "*").
perm_sa_token_create(P, Ns) :- direct_perm(P, Ns, "*", "*",                     "create").
perm_sa_token_create(P, Ns) :- direct_perm(P, Ns, "*", "*",                     "*").

perm_pods_exec_create(P, Ns) :- direct_perm(P, Ns, "",  "pods/exec", "create").
perm_pods_exec_create(P, Ns) :- direct_perm(P, Ns, "",  "pods/exec", "*").
perm_pods_exec_create(P, Ns) :- direct_perm(P, Ns, "",  "*",         "create").
perm_pods_exec_create(P, Ns) :- direct_perm(P, Ns, "",  "*",         "*").
perm_pods_exec_create(P, Ns) :- direct_perm(P, Ns, "*", "pods/exec", "create").
perm_pods_exec_create(P, Ns) :- direct_perm(P, Ns, "*", "pods/exec", "*").
perm_pods_exec_create(P, Ns) :- direct_perm(P, Ns, "*", "*",         "create").
perm_pods_exec_create(P, Ns) :- direct_perm(P, Ns, "*", "*",         "*").

perm_pods_attach_create(P, Ns) :- direct_perm(P, Ns, "",  "pods/attach", "create").
perm_pods_attach_create(P, Ns) :- direct_perm(P, Ns, "",  "pods/attach", "*").
perm_pods_attach_create(P, Ns) :- direct_perm(P, Ns, "",  "*",           "create").
perm_pods_attach_create(P, Ns) :- direct_perm(P, Ns, "",  "*",           "*").
perm_pods_attach_create(P, Ns) :- direct_perm(P, Ns, "*", "pods/attach", "create").
perm_pods_attach_create(P, Ns) :- direct_perm(P, Ns, "*", "pods/attach", "*").
perm_pods_attach_create(P, Ns) :- direct_perm(P, Ns, "*", "*",           "create").
perm_pods_attach_create(P, Ns) :- direct_perm(P, Ns, "*", "*",           "*").

perm_pods_create(P, Ns) :- direct_perm(P, Ns, "",  "pods", "create").
perm_pods_create(P, Ns) :- direct_perm(P, Ns, "",  "pods", "*").
perm_pods_create(P, Ns) :- direct_perm(P, Ns, "",  "*",    "create").
perm_pods_create(P, Ns) :- direct_perm(P, Ns, "",  "*",    "*").
perm_pods_create(P, Ns) :- direct_perm(P, Ns, "*", "pods", "create").
perm_pods_create(P, Ns) :- direct_perm(P, Ns, "*", "pods", "*").
perm_pods_create(P, Ns) :- direct_perm(P, Ns, "*", "*",    "create").
perm_pods_create(P, Ns) :- direct_perm(P, Ns, "*", "*",    "*").

perm_sa_impersonate(P, Ns) :- direct_perm(P, Ns, "",  "serviceaccounts", "impersonate").
perm_sa_impersonate(P, Ns) :- direct_perm(P, Ns, "",  "serviceaccounts", "*").
perm_sa_impersonate(P, Ns) :- direct_perm(P, Ns, "",  "*",               "impersonate").
perm_sa_impersonate(P, Ns) :- direct_perm(P, Ns, "",  "*",               "*").
perm_sa_impersonate(P, Ns) :- direct_perm(P, Ns, "*", "serviceaccounts", "impersonate").
perm_sa_impersonate(P, Ns) :- direct_perm(P, Ns, "*", "serviceaccounts", "*").
perm_sa_impersonate(P, Ns) :- direct_perm(P, Ns, "*", "*",               "impersonate").
perm_sa_impersonate(P, Ns) :- direct_perm(P, Ns, "*", "*",               "*").

perm_user_impersonate(P, Ns) :- direct_perm(P, Ns, "",  "users", "impersonate").
perm_user_impersonate(P, Ns) :- direct_perm(P, Ns, "",  "users", "*").
perm_user_impersonate(P, Ns) :- direct_perm(P, Ns, "",  "*",     "impersonate").
perm_user_impersonate(P, Ns) :- direct_perm(P, Ns, "",  "*",     "*").
perm_user_impersonate(P, Ns) :- direct_perm(P, Ns, "*", "users", "impersonate").
perm_user_impersonate(P, Ns) :- direct_perm(P, Ns, "*", "users", "*").
perm_user_impersonate(P, Ns) :- direct_perm(P, Ns, "*", "*",     "impersonate").
perm_user_impersonate(P, Ns) :- direct_perm(P, Ns, "*", "*",     "*").

perm_group_impersonate(P, Ns) :- direct_perm(P, Ns, "",  "groups", "impersonate").
perm_group_impersonate(P, Ns) :- direct_perm(P, Ns, "",  "groups", "*").
perm_group_impersonate(P, Ns) :- direct_perm(P, Ns, "",  "*",      "impersonate").
perm_group_impersonate(P, Ns) :- direct_perm(P, Ns, "",  "*",      "*").
perm_group_impersonate(P, Ns) :- direct_perm(P, Ns, "*", "groups", "impersonate").
perm_group_impersonate(P, Ns) :- direct_perm(P, Ns, "*", "groups", "*").
perm_group_impersonate(P, Ns) :- direct_perm(P, Ns, "*", "*",      "impersonate").
perm_group_impersonate(P, Ns) :- direct_perm(P, Ns, "*", "*",      "*").

# ---- Escalation path helpers ----

token_accessible_sa(P, SANs, SAName) :-
    perm_sa_token_create(P, SANs),
    serviceaccount(SANs, SAName, _).

exec_reachable_sa(P, PodNs, SAName) :-
    perm_pods_exec_create(P, PodNs),
    pod_sa(PodNs, _, SAName).

exec_reachable_sa(P, PodNs, SAName) :-
    perm_pods_attach_create(P, PodNs),
    pod_sa(PodNs, _, SAName).

pod_creatable_sa(P, SANs, SAName) :-
    perm_pods_create(P, SANs),
    serviceaccount(SANs, SAName, _).

impersonatable_sa(P, SANs, SAName) :-
    perm_sa_impersonate(P, SANs),
    serviceaccount(SANs, SAName, _).

# ---- escalation_hop ----
#
# Single-step escalation: P can directly assume Target's identity via exactly
# one mechanism. Keeping this as a separate predicate (rather than inlining into
# controls_identity) is what makes the transitive closure below BFS-ordered:
# semi-naive evaluation extends controls_identity by one escalation_hop per
# fixpoint iteration, so shorter paths are always derived before longer ones.
# Because provenance records only the first (is_new) insertion, ::why on any
# controls_identity fact will show the shortest path to the target.

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

escalation_hop(P, Target) :-
    perm_user_impersonate(P, _),
    all_user_perm(Target, _, _, _, _).

escalation_hop(P, Target) :-
    perm_group_impersonate(P, _),
    all_group_perm(Target, _, _, _, _).

# ---- controls_identity ----
#
# Transitive closure over escalation_hop. The recursive rule extends by exactly
# one escalation_hop (not controls_identity on both sides), preserving BFS order.

controls_identity(P, Target) :- escalation_hop(P, Target), P != Target.

controls_identity(P, Target) :-
    controls_identity(P, Mid),
    escalation_hop(Mid, Target).

# ---- indirect_perm ----
#
# Permissions P gains via escalation, with the intermediate identity recorded.
# Target is the identity P controls that holds the direct_perm. Wildcards
# preserved as-is. Does not include P's own direct_perm.

indirect_perm(P, Ns, ApiGroup, Resource, Verb, Target) :-
    controls_identity(P, Target),
    direct_perm(Target, Ns, ApiGroup, Resource, Verb).

