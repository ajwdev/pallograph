# Match every label selector against objects of every kind in its
# namespace, not only the kinds Kubernetes evaluates it against. See
# README.md.
#
# Builds on k8s_labels.mg: it adds candidate pairs, the built-in matcher checks
# their requirements, and selector_matches_any_kind/9 reads every pair that
# passes. selector_matches/9 is unchanged, since it keeps only the kinds
# k8s_selector_targets.mg allows.

Decl selector_matches_any_kind(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                               ObjApiVersion, ObjKind, ObjNamespace, ObjName)
  descr [
    doc("A selector's requirements all hold for Obj, which is in the owner's namespace (any kind) or one of its built-in targets."),
    arg(SelApiVersion, "selector owner apiVersion"),
    arg(SelKind, "selector owner kind"),
    arg(SelNamespace, "selector owner namespace; empty for cluster-scoped"),
    arg(SelName, "selector owner name"),
    arg(Selector, "which of the owner's selectors (its field path)"),
    arg(ObjApiVersion, "matched object apiVersion"),
    arg(ObjKind, "matched object kind"),
    arg(ObjNamespace, "matched object namespace; empty for cluster-scoped"),
    arg(ObjName, "matched object name")
  ].

# Every object in the owner's namespace, whatever the kinds, custom
# resources included. A cluster-scoped owner (a ClusterRole's aggregation
# selectors) is paired with every cluster-scoped object.
selector_candidate(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                   ObjApiVersion, ObjKind, SelNamespace, ObjName) :-
    selector_declared(SelApiVersion, SelKind, SelNamespace, SelName, Selector),
    object_in_namespace(SelNamespace, ObjKind, ObjApiVersion, ObjName).

selector_matches_any_kind(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                          ObjApiVersion, ObjKind, ObjNamespace, ObjName) :-
    selector_pair_matches(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                          ObjApiVersion, ObjKind, ObjNamespace, ObjName).
