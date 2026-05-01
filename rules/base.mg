# Base rules - convenience predicates over k8s/5
# These would ship with your controller

pod(Namespace, Name, Data) :-
    k8s("v1", "Pod", Namespace, Name, Data).

serviceaccount(Namespace, Name, Data) :-
    k8s("v1", "ServiceAccount", Namespace, Name, Data).

deployment(Namespace, Name, Data) :-
    k8s("apps/v1", "Deployment", Namespace, Name, Data).

configmap(Namespace, Name, Data) :-
    k8s("v1", "ConfigMap", Namespace, Name, Data).

secret(Namespace, Name, Data) :-
    k8s("v1", "Secret", Namespace, Name, Data).

# Extract common fields
pod_sa(Namespace, PodName, SAName) :-
    pod(Namespace, PodName, Data),
    :match_field(Data, /spec, Spec),
    :match_field(Spec, /serviceAccountName, SAName).

pod_image(Namespace, PodName, Image) :-
    pod(Namespace, PodName, Data),
    :match_field(Data, /spec, Spec),
    :match_field(Spec, /containers, Containers),
    :list:member(Container, Containers),
    :match_field(Container, /image, Image).

# Helper for namespace queries
objects_in_ns(Namespace, Kind, Name) :-
    k8s(_, Kind, Namespace, Name, _).
