# User-defined policy rules
# These could come from a CRD

# Helper predicate for checking boolean true
# Mangle equality (X = /val) only works at start of clause body,
# so we use unification through a helper predicate instead
is_true(/true).

# Find pods with hostNetwork enabled
Decl host_network_pod(Namespace, Name)
  descr [
    doc("Pods running with hostNetwork enabled."),
    arg(Namespace, "pod namespace"),
    arg(Name, "pod name")
  ].

host_network_pod(Namespace, Name) :-
    pod(Namespace, Name, Data),
    :match_field(Data, /spec, Spec),
    :match_field(Spec, /hostNetwork, HostNet),
    is_true(HostNet).

# Find pods running as privileged
Decl privileged_pod(Namespace, Name)
  descr [
    doc("Pods with at least one privileged container."),
    arg(Namespace, "pod namespace"),
    arg(Name, "pod name")
  ].

privileged_pod(Namespace, Name) :-
    pod(Namespace, Name, Data),
    :match_field(Data, /spec, Spec),
    :match_field(Spec, /containers, Containers),
    :list:member(Container, Containers),
    :match_field(Container, /securityContext, Sec),
    :match_field(Sec, /privileged, Priv),
    is_true(Priv).

# Service accounts in use (helper)
sa_in_use(Namespace, SAName) :-
    pod_sa(Namespace, _, SAName).

# Orphaned service accounts
Decl orphaned_sa(Namespace, SAName)
  descr [
    doc("ServiceAccounts not used by any pod in their namespace."),
    arg(Namespace, "serviceaccount namespace"),
    arg(SAName, "serviceaccount name")
  ].

orphaned_sa(Namespace, SAName) :-
    serviceaccount(Namespace, SAName, _),
    !sa_in_use(Namespace, SAName).

# ---- RBAC policy predicates ----
#
# Note on Kubernetes RBAC wildcards: the string "*" means "all" in k8s but is
# stored as the literal Mangle string "*". Since Mangle has no glob semantics,
# wildcard cases are handled by writing two rules per policy predicate - one
# matching the literal resource name and one matching "*".
#
# These read direct_perm (rbac.mg), so they consider grants bound to the
# ServiceAccount or user itself, not grants reached through group membership.

# sa_is_cluster_admin(Namespace, SAName)
# A ServiceAccount has cluster-admin level access (literal "*","*","*"
# permissions on every name). Also catches cluster-admin bound via a
# RoleBinding (namespace-scoped but still dangerous).
Decl sa_is_cluster_admin(Namespace, SAName)
  descr [
    doc("ServiceAccounts with cluster-admin level access (*,*,* permissions)."),
    arg(Namespace, "serviceaccount namespace"),
    arg(SAName, "serviceaccount name")
  ].

sa_is_cluster_admin(SANs, SAName) :-
    direct_perm(Username, /serviceaccount, _, "*", "*", /any, "*"),
    service_account_principal(SANs, SAName, Username).

# user_is_cluster_admin(UserName)
Decl user_is_cluster_admin(UserName)
  descr [
    doc("Users with cluster-admin level access (*,*,* via ClusterRoleBinding)."),
    arg(UserName, "user name")
  ].

user_is_cluster_admin(UserName) :-
    direct_perm(UserName, /user, "", "*", "*", /any, "*").

# PolicyRules granting a wildcard verb. The two checks below look this up by
# the Rule struct. The interpreter indexes a struct column by its field count
# alone, so a lookup into all of policy_rule_perm would return nearly every
# row; this relation keeps the candidates to the few wildcard-verb rules.
policy_rule_has_wildcard_verb(Rule) :-
    policy_rule_perm(Rule, _, _, _, "*").

# role_has_wildcard_verb(Namespace, RoleName)
# A namespace-scoped Role grants wildcard verb on some resource.
role_has_wildcard_verb(Namespace, RoleName) :-
    role_rule(Namespace, RoleName, Rule),
    policy_rule_has_wildcard_verb(Rule).

# clusterrole_has_wildcard_verb(RoleName)
# A ClusterRole grants wildcard verb on some resource.
clusterrole_has_wildcard_verb(RoleName) :-
    clusterrole_rule(RoleName, Rule),
    policy_rule_has_wildcard_verb(Rule).

# sa_pod_perm(SANs, SAName, Verb)
# A ServiceAccount has some verb on pods via any binding path, in any
# namespace. Two variants: literal "pods" resource and wildcard "*" resource.
# Callers filter on Verb for the specific action they care about.

sa_pod_perm(SANs, SAName, Verb) :-
    direct_perm(Username, /serviceaccount, _, _, "pods", _, Verb),
    service_account_principal(SANs, SAName, Username).

sa_pod_perm(SANs, SAName, Verb) :-
    direct_perm(Username, /serviceaccount, _, _, "*", _, Verb),
    service_account_principal(SANs, SAName, Username).
