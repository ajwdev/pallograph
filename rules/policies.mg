# User-defined policy rules
# These could come from a CRD

# Helper predicate for checking boolean true
# Mangle equality (X = /val) only works at start of clause body,
# so we use unification through a helper predicate instead
is_true(/true).

# Find pods with hostNetwork enabled
host_network_pod(Namespace, Name) :-
    pod(Namespace, Name, Data),
    :match_field(Data, /spec, Spec),
    :match_field(Spec, /hostNetwork, HostNet),
    is_true(HostNet).

# Find pods running as privileged
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
orphaned_sa(Namespace, SAName) :-
    serviceaccount(Namespace, SAName, _),
    !sa_in_use(Namespace, SAName).

# Pods with existing SAs (join)
pod_with_sa(Namespace, PodName, SAName) :-
    pod_sa(Namespace, PodName, SAName),
    serviceaccount(Namespace, SAName, _).
