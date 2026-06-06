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

node(Name, Data) :-
    k8s("v1", "Node", "", Name, Data).

node_taint(Name, Key, Value, Effect) :-
    node(Name, Data),
    :match_field(Data, /spec, Spec),
    :match_field(Spec, /taints, Taints),
    :list:member(Taint, Taints),
    :match_field(Taint, /key, Key),
    :match_field(Taint, /value, Value),
    :match_field(Taint, /effect, Effect).

# Helper for namespace queries
objects_in_ns(Namespace, Kind, Name) :-
    k8s(_, Kind, Namespace, Name, _).
