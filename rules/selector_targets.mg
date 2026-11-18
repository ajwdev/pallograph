# What each kind of selector owner selects, as upstream Kubernetes does.
#
# A label selector in Kubernetes is always evaluated against one kind of
# object, in a scope its controller picks: a Service's selector picks Pods in
# the Service's namespace, a PersistentVolumeClaim's picks PersistentVolumes
# (cluster-scoped). labels.mg only pairs a selector with the objects this
# table names, so a Service never matches a ConfigMap that happens to carry
# the same labels.
#
# Workloads follow ownership: a Deployment selects its ReplicaSets, which
# select Pods, so a Deployment reaches its Pods through reachable/8 in
# graph.mg. StatefulSets and DaemonSets also select the ControllerRevisions
# holding their history.
#
# Kinds not listed here (custom resources included) keep their selector_*
# facts but select nothing. To give one a target, add a row from a --rules
# file, e.g. a Prometheus Operator ServiceMonitor:
#
#   selector_target_kind("monitoring.coreos.com/v1", "ServiceMonitor",
#                        "v1", "Service", /same_namespace).
#
# To match selectors against every kind instead, see
# examples/selectors-any-kind/.
#
# Relations:
#   selector_target_kind/5 - (SelApiVersion, SelKind, TargetApiVersion,
#                             TargetKind, Scope)

Decl selector_target_kind(SelApiVersion, SelKind, TargetApiVersion, TargetKind, Scope)
  descr [
    doc("A selector owned by a SelApiVersion/SelKind object selects TargetApiVersion/TargetKind objects in Scope."),
    arg(SelApiVersion, "selector owner apiVersion"),
    arg(SelKind, "selector owner kind"),
    arg(TargetApiVersion, "selected object apiVersion"),
    arg(TargetKind, "selected object kind"),
    arg(Scope, "/same_namespace (the owner's namespace) or /cluster (cluster-scoped objects)")
  ].

selector_target_kind("v1", "Service", "v1", "Pod", /same_namespace).
selector_target_kind("v1", "ReplicationController", "v1", "Pod", /same_namespace).
selector_target_kind("apps/v1", "Deployment", "apps/v1", "ReplicaSet", /same_namespace).
selector_target_kind("apps/v1", "ReplicaSet", "v1", "Pod", /same_namespace).
selector_target_kind("apps/v1", "StatefulSet", "v1", "Pod", /same_namespace).
selector_target_kind("apps/v1", "StatefulSet", "apps/v1", "ControllerRevision", /same_namespace).
selector_target_kind("apps/v1", "DaemonSet", "v1", "Pod", /same_namespace).
selector_target_kind("apps/v1", "DaemonSet", "apps/v1", "ControllerRevision", /same_namespace).
selector_target_kind("batch/v1", "Job", "v1", "Pod", /same_namespace).
selector_target_kind("policy/v1", "PodDisruptionBudget", "v1", "Pod", /same_namespace).
selector_target_kind("policy/v1beta1", "PodDisruptionBudget", "v1", "Pod", /same_namespace).
selector_target_kind("v1", "PersistentVolumeClaim", "v1", "PersistentVolume", /cluster).

# The synthetic owner edb.rs emits for each ClusterRole
# aggregationRule.clusterRoleSelectors entry (see rbac_roles.mg).
selector_target_kind("pallograph.dev/agg", "ClusterRoleAggregation",
                     "rbac.authorization.k8s.io/v1", "ClusterRole", /cluster).
