# Base rules - convenience predicates over k8s/5
# These would ship with your controller

pod(Namespace, Name, Data) :-
    k8s("v1", "Pod", Namespace, Name, Data).

serviceaccount(Namespace, Name, Data) :-
    k8s("v1", "ServiceAccount", Namespace, Name, Data).

# Extract common fields
pod_sa(Namespace, PodName, SAName) :-
    pod(Namespace, PodName, Data),
    :match_field(Data, /spec, Spec),
    :match_field(Spec, /serviceAccountName, SAName).

# Pods without an explicit serviceAccountName implicitly use "default".
# This is an overapproximation: static control-plane pods also get this
# fact, but they don't actually mount SA tokens.
pod_sa(Namespace, PodName, "default") :-
    pod(Namespace, PodName, _).

pod_image(Namespace, PodName, Image) :-
    pod(Namespace, PodName, Data),
    :match_field(Data, /spec, Spec),
    :match_field(Spec, /containers, Containers),
    :list:member(Container, Containers),
    :match_field(Container, /image, Image).
