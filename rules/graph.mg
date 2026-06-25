# Object graph reachability — transitive closure over relationship edges.
#
# A "graph edge" is any directed relationship between two Kubernetes objects.
# Currently the only edge source is label selector matching (selector_matches/8
# from labels.mg). Owner references will be added as a second edge source once
# that EDB is available; no changes to reachable/8 will be required at that point.
#
# Predicate hierarchy:
#   selector_matches/8  (from labels.mg)
#     → graph_edge/8     (union of all edge sources; extend here for new sources)
#     → reachable/8      (transitive closure over graph_edge)
#
# Variable naming follows the same convention as labels.mg:
#   SrcApiVersion, SrcKind, SrcNamespace, SrcName  — the source (parent) object
#   DstApiVersion, DstKind, DstNamespace, DstName  — the destination (child) object
#   MidApiVersion, MidKind, MidNamespace, MidName  — intermediate hop in recursion

# ---- graph_edge ----
#
# A directed edge exists from Src to Dst when Src's label selector matches Dst.
# Add additional rules here for new edge sources (e.g. owner references).

graph_edge(SrcApiVersion, SrcKind, SrcNamespace, SrcName,
           DstApiVersion, DstKind, DstNamespace, DstName) :-
    selector_matches(SrcApiVersion, SrcKind, SrcNamespace, SrcName,
                     DstApiVersion, DstKind, DstNamespace, DstName).

# Future: owner reference edges (child → parent direction inverted to parent → child).
# graph_edge(OwnerApiVersion, OwnerKind, OwnerNamespace, OwnerName,
#            ObjApiVersion, ObjKind, ObjNamespace, ObjName) :-
#     owner_ref(ObjApiVersion, ObjKind, ObjNamespace, ObjName,
#               OwnerApiVersion, OwnerKind, OwnerNamespace, OwnerName).

# ---- reachable ----
#
Decl reachable(SrcApiVersion, SrcKind, SrcNamespace, SrcName,
               DstApiVersion, DstKind, DstNamespace, DstName)
  descr [
    doc("Object graph reachability: Src reaches Dst via one or more relationship edges."),
    arg(SrcApiVersion, "source object apiVersion"),
    arg(SrcKind, "source object kind"),
    arg(SrcNamespace, "source object namespace; empty for cluster-scoped"),
    arg(SrcName, "source object name"),
    arg(DstApiVersion, "destination object apiVersion"),
    arg(DstKind, "destination object kind"),
    arg(DstNamespace, "destination object namespace; empty for cluster-scoped"),
    arg(DstName, "destination object name")
  ].

# Base case: a direct edge is reachable.
reachable(SrcApiVersion, SrcKind, SrcNamespace, SrcName,
          DstApiVersion, DstKind, DstNamespace, DstName) :-
    graph_edge(SrcApiVersion, SrcKind, SrcNamespace, SrcName,
               DstApiVersion, DstKind, DstNamespace, DstName).

# Recursive case: if Src reaches Mid and Mid has an edge to Dst, then Src reaches Dst.
# Mangle's semi-naive fixpoint evaluation handles the recursion; cycles terminate
# naturally when no new facts are produced.
reachable(SrcApiVersion, SrcKind, SrcNamespace, SrcName,
          DstApiVersion, DstKind, DstNamespace, DstName) :-
    reachable(SrcApiVersion, SrcKind, SrcNamespace, SrcName,
              MidApiVersion, MidKind, MidNamespace, MidName),
    graph_edge(MidApiVersion, MidKind, MidNamespace, MidName,
               DstApiVersion, DstKind, DstNamespace, DstName).
