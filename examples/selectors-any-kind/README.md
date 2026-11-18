# Recipe: match label selectors against every kind

## The idea

Kubernetes evaluates a label selector against one kind of object: a
Service's selector picks Pods, a PersistentVolumeClaim's picks
PersistentVolumes. Pallograph's built-in `selector_matches` does the same,
using the table in `rules/selector_targets.mg`, so a Service does not
"select" the Deployment or ConfigMap that carries the same labels.

Sometimes you want the looser question: which objects of any kind carry
labels this selector would accept? A ConfigMap labelled `app=web` next to a
Service selecting `app=web` is usually meant to go with it, and a custom
resource's selector has no built-in target at all. This recipe answers
that question in its own relation, leaving `selector_matches` alone.

## The pieces

- [`any-kind.mg`](any-kind.mg) - adds a candidate pair for every selector
  and every object in its namespace, whatever the kinds, and defines
  `selector_matches_any_kind/8` as every pair whose requirements hold. The
  built-in matcher in `rules/labels.mg` does the checking.

`selector_matches_any_kind` includes the owner itself when its own labels
satisfy its selector (a Deployment labelled `app=web` selecting `app=web`),
and keeps the built-in cluster-scoped targets (a PersistentVolumeClaim's
PersistentVolumes).

## Use it

Load it at startup with `--rules`, or at runtime with `source`:

```
pallograph --rules examples/selectors-any-kind/any-kind.mg ...
?- selector_matches_any_kind("v1", "Service", "apps", "web", A, K, N, M)
```

## Graph edges

`reachable/8` in `rules/graph.mg` follows `graph_edge`, which only has the
built-in matches. To walk cross-kind matches too, add the edge rule
alongside `any-kind.mg`:

```
graph_edge(SrcApiVersion, SrcKind, SrcNamespace, SrcName,
           DstApiVersion, DstKind, DstNamespace, DstName) :-
    selector_matches_any_kind(SrcApiVersion, SrcKind, SrcNamespace, SrcName,
                              DstApiVersion, DstKind, DstNamespace, DstName).
```

## Selectors of custom resources

To give a custom resource's selector a target kind, rather than matching
every kind, add a row to the built-in table from a `--rules` file. For
example, a Prometheus Operator ServiceMonitor selects Services:

```
selector_target_kind("monitoring.coreos.com/v1", "ServiceMonitor",
                     "v1", "Service", /same_namespace).
```

Its matches then show up in `selector_matches` and `graph_edge` like any
built-in owner's.
