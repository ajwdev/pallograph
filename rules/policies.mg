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

# Pods with existing SAs (join)
pod_with_sa(Namespace, PodName, SAName) :-
    pod_sa(Namespace, PodName, SAName),
    serviceaccount(Namespace, SAName, _).

# ---- RBAC policy predicates ----
#
# Note on Kubernetes RBAC wildcards: the string "*" means "all" in k8s but is
# stored as the literal Mangle string "*". Since Mangle has no glob semantics,
# wildcard cases are handled by writing two rules per policy predicate — one
# matching the literal resource name and one matching "*".

# sa_is_cluster_admin(Namespace, SAName)
# A ServiceAccount has cluster-admin level access (literal "*","*","*" permissions).
Decl sa_is_cluster_admin(Namespace, SAName)
  descr [
    doc("ServiceAccounts with cluster-admin level access (*,*,* permissions)."),
    arg(Namespace, "serviceaccount namespace"),
    arg(SAName, "serviceaccount name")
  ].

sa_is_cluster_admin(SANs, SAName) :-
    sa_crb_perm(SANs, SAName, "*", "*", "*").

# Also catches cluster-admin bound via RoleBinding (namespace-scoped but still dangerous).
sa_is_cluster_admin(SANs, SAName) :-
    sa_rb_clusterrole_perm(SANs, SAName, _, "*", "*", "*").

# user_is_cluster_admin(UserName)
Decl user_is_cluster_admin(UserName)
  descr [
    doc("Users with cluster-admin level access (*,*,* via ClusterRoleBinding)."),
    arg(UserName, "user name")
  ].

user_is_cluster_admin(UserName) :-
    user_crb_perm(UserName, "*", "*", "*").

# role_has_wildcard_verb(Namespace, RoleName)
# A namespace-scoped Role grants wildcard verb on some resource.
role_has_wildcard_verb(Namespace, RoleName) :-
    role_perm(Namespace, RoleName, _, _, "*").

# clusterrole_has_wildcard_verb(RoleName)
# A ClusterRole grants wildcard verb on some resource.
clusterrole_has_wildcard_verb(RoleName) :-
    clusterrole_perm(RoleName, _, _, "*").

# sa_pod_perm(SANs, SAName, Verb)
# A ServiceAccount has some verb on pods via any binding path.
# Two variants per path: literal "pods" resource and wildcard "*" resource.
# Callers filter on Verb for the specific action they care about.

sa_pod_perm(SANs, SAName, Verb) :-
    sa_crb_perm(SANs, SAName, _, "pods", Verb).

sa_pod_perm(SANs, SAName, Verb) :-
    sa_crb_perm(SANs, SAName, _, "*", Verb).

sa_pod_perm(SANs, SAName, Verb) :-
    sa_role_perm(SANs, SAName, _, "pods", Verb).

sa_pod_perm(SANs, SAName, Verb) :-
    sa_role_perm(SANs, SAName, _, "*", Verb).

sa_pod_perm(SANs, SAName, Verb) :-
    sa_rb_clusterrole_perm(SANs, SAName, _, _, "pods", Verb).

sa_pod_perm(SANs, SAName, Verb) :-
    sa_rb_clusterrole_perm(SANs, SAName, _, _, "*", Verb).
