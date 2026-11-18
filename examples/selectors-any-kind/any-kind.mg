# Match every label selector against objects of every kind in its
# namespace, not only the kinds Kubernetes evaluates it against. See
# README.md.
#
# Builds on labels.mg: it adds candidate pairs, the built-in matcher checks
# their requirements, and selector_matches_any_kind/8 reads every pair that
# passes. selector_matches/8 is unchanged, since it keeps only the kinds
# selector_targets.mg allows.

Decl selector_matches_any_kind(SelApiVersion, SelKind, SelNamespace, SelName,
                               ObjApiVersion, ObjKind, ObjNamespace, ObjName)
  descr [
    doc("A selector's requirements all hold for Obj, which is in the owner's namespace (any kind) or one of its built-in targets."),
    arg(SelApiVersion, "selector owner apiVersion"),
    arg(SelKind, "selector owner kind"),
    arg(SelNamespace, "selector owner namespace; empty for cluster-scoped"),
    arg(SelName, "selector owner name"),
    arg(ObjApiVersion, "matched object apiVersion"),
    arg(ObjKind, "matched object kind"),
    arg(ObjNamespace, "matched object namespace; empty for cluster-scoped"),
    arg(ObjName, "matched object name")
  ].

# Every object in the owner's namespace, whatever the kinds, custom
# resources included. A ClusterRole aggregation entry keeps its index in the
# Namespace slot, so it is left to its built-in ClusterRole targets.
selector_candidate(SelApiVersion, SelKind, SelNamespace, SelName,
                   ObjApiVersion, ObjKind, SelNamespace, ObjName) :-
    selector_declared(SelApiVersion, SelKind, SelNamespace, SelName),
    SelApiVersion != "pallograph.dev/agg",
    object_in_namespace(SelNamespace, ObjKind, ObjApiVersion, ObjName).

selector_matches_any_kind(SelApiVersion, SelKind, SelNamespace, SelName,
                          ObjApiVersion, ObjKind, ObjNamespace, ObjName) :-
    selector_pair_matches(SelApiVersion, SelKind, SelNamespace, SelName,
                          ObjApiVersion, ObjKind, ObjNamespace, ObjName).
