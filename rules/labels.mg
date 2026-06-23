# Label selector rules - evaluates Kubernetes label selectors against any object.
#
# Unlike native Kubernetes, which restricts label selectors to a single Kind,
# these rules match a selector against all objects in the store regardless of
# ApiVersion or Kind. For example, a Deployment's selector can be evaluated
# against Pods, StatefulSets, or any other type simultaneously.
#
# Variable naming convention:
#   ApiVersion  - the apiVersion field from the object (e.g. "apps/v1", "v1").
#                 This is the Kubernetes apiVersion string, which combines group
#                 and version. There is no standard Kubernetes abbreviation for
#                 this combined field, so the full name is used throughout.
#   Kind        - the kind field (e.g. "Pod", "Deployment")
#   Namespace   - the namespace field ("" for cluster-scoped objects)
#   Name        - the metadata.name field
#   LabelKey    - a label key string (e.g. "app", "tier")
#   LabelValue  - a label value string (e.g. "nginx", "frontend")
#
#   Variables referencing the selector-owning object are prefixed "Sel":
#     SelApiVersion, SelKind, SelNamespace, SelName
#   Variables referencing the candidate target object are prefixed "Obj":
#     ObjApiVersion, ObjKind, ObjNamespace, ObjName
#
# Base facts (EDB - Extensional Database, i.e. facts asserted directly, not derived):
#   k8s/5                     - Kubernetes objects loaded from the cluster
#   object_label/6            - (ApiVersion, Kind, Namespace, Name, LabelKey, LabelValue)
#                               One fact per label on any object. Extracted at load time
#                               in Rust because Mangle cannot enumerate struct fields with
#                               a variable key — :match_field requires a constant field name.
#   selector_match_label/6    - (ApiVersion, Kind, Namespace, Name, LabelKey, LabelValue)
#                               One fact per matchLabels entry. Also covers flat
#                               Service-style .spec.selector maps (treated as matchLabels).
#   selector_expr_in/6        - (ApiVersion, Kind, Namespace, Name, LabelKey, AllowedValue)
#                               matchExpressions In operator; one fact per allowed value.
#   selector_expr_notin/6     - (ApiVersion, Kind, Namespace, Name, LabelKey, ExcludedValue)
#                               matchExpressions NotIn operator; one fact per excluded value.
#   selector_expr_exists/5    - (ApiVersion, Kind, Namespace, Name, LabelKey)
#                               matchExpressions Exists operator.
#   selector_expr_notexists/5 - (ApiVersion, Kind, Namespace, Name, LabelKey)
#                               matchExpressions DoesNotExist operator.
#
# Predicate hierarchy (IDB - Intensional Database, i.e. facts derived by rules):
#   k8s/5
#     → object_exists/4              (any object in the store; see TODO below)
#   object_label/6
#     → object_has_label_key/5       (strips LabelValue; needed because Mangle forbids
#                                     unbound wildcards in negated literals — see below)
#   selector_* + object_exists/4
#     → selector_has_requirements/4  (guards the cross-product: only objects that
#                                     actually declare a selector are considered)
#     → sel_obj_candidate/8          (cross-product of selector owners × all objects;
#                                     ensures every variable is bound before negation fires)
#     → matchlabel_unsatisfied/8     (a matchLabels Key=Value requirement is not met)
#     → expr_in_satisfied/9          (an In requirement IS met; a separate named predicate
#                                     is required because Mangle can only negate a named
#                                     predicate — it cannot negate an inline conjunction)
#     → expr_in_unsatisfied/8        (no allowed value in the In set matched)
#     → expr_notin_unsatisfied/8     (an excluded value from NotIn was found)
#     → expr_exists_unsatisfied/8    (the required key is absent)
#     → expr_notexists_unsatisfied/8 (the forbidden key is present)
#     → selector_any_unsatisfied/8   (union of all failure modes; again a separate named
#                                     predicate so that selector_matches can negate it)
#     → selector_matches/8           (no requirement of any type is unsatisfied)

# ---- Base helpers ----

# Any object in the store is a potential selector target.
# TODO: object_exists is a redundant alias for k8s/5 with the data arg dropped.
# It can be removed by inlining k8s(ApiVersion, Kind, Namespace, Name, _) at each use site.
object_exists(ApiVersion, Kind, Namespace, Name) :-
    k8s(ApiVersion, Kind, Namespace, Name, _).

# Strips LabelValue so the key alone can be tested in negation.
#
# Mangle requires every variable in a negated literal to be bound by a positive
# literal in the same rule body. Writing !object_label(..., LabelKey, _) is illegal
# because the wildcard _ (the value) would be unbound at negation time. This helper
# exposes a 5-argument form that is safe to negate:
#   !object_has_label_key(ObjApiVersion, ObjKind, ObjNamespace, ObjName, LabelKey)
object_has_label_key(ApiVersion, Kind, Namespace, Name, LabelKey) :-
    object_label(ApiVersion, Kind, Namespace, Name, LabelKey, _).

# Identifies objects that declare at least one selector requirement of any type.
# Without this guard, sel_obj_candidate would be the full O(n²) cross-product of
# every object with every other object, even for objects that have no selector.
selector_has_requirements(SelApiVersion, SelKind, SelNamespace, SelName) :-
    selector_match_label(SelApiVersion, SelKind, SelNamespace, SelName, _, _).
selector_has_requirements(SelApiVersion, SelKind, SelNamespace, SelName) :-
    selector_expr_in(SelApiVersion, SelKind, SelNamespace, SelName, _, _).
selector_has_requirements(SelApiVersion, SelKind, SelNamespace, SelName) :-
    selector_expr_notin(SelApiVersion, SelKind, SelNamespace, SelName, _, _).
selector_has_requirements(SelApiVersion, SelKind, SelNamespace, SelName) :-
    selector_expr_exists(SelApiVersion, SelKind, SelNamespace, SelName, _).
selector_has_requirements(SelApiVersion, SelKind, SelNamespace, SelName) :-
    selector_expr_notexists(SelApiVersion, SelKind, SelNamespace, SelName, _).

# Cross-product of selector owners × candidate objects.
#
# Every *_unsatisfied rule below includes sel_obj_candidate in its body. This
# serves two purposes:
#   1. Scopes work to pairs that are actually worth evaluating.
#   2. Guarantees that all eight position variables are bound by a positive literal
#      before any negation fires — a hard requirement in Mangle.
#
# Matching is restricted to two cases to avoid an O(selectors × objects)
# cross-product blowup at scale:
#   1. Same-namespace pairs: the common case for all namespace-scoped objects
#      (Pods, Services, Deployments, etc.).
#   2. Selector → cluster-scoped target (ObjNamespace = ""): covers nodeSelector
#      matching against Nodes, PVC selector matching against PersistentVolumes,
#      and any other selector that targets cluster-scoped objects.
#
# True cross-namespace selectors (e.g. Prometheus Operator namespaceSelector,
# pod affinity namespaceSelector) are a different data shape and are handled
# by separate EDB predicates and rules, not by this predicate.

# Case 1: selector owner and target are in the same namespace.
sel_obj_candidate(SelApiVersion, SelKind, SelNamespace, SelName,
                  ObjApiVersion, ObjKind, ObjNamespace, ObjName) :-
    selector_has_requirements(SelApiVersion, SelKind, SelNamespace, SelName),
    object_exists(ObjApiVersion, ObjKind, ObjNamespace, ObjName),
    SelNamespace = ObjNamespace.

# Case 2: target is cluster-scoped (namespace ""). Covers Nodes, PersistentVolumes, etc.
sel_obj_candidate(SelApiVersion, SelKind, SelNamespace, SelName,
                  ObjApiVersion, ObjKind, ObjNamespace, ObjName) :-
    selector_has_requirements(SelApiVersion, SelKind, SelNamespace, SelName),
    object_exists(ObjApiVersion, ObjKind, ObjNamespace, ObjName),
    ObjNamespace = "".

# ---- matchLabels ----

# A matchLabels requirement (LabelKey=LabelValue) is not satisfied by the object.
# LabelKey and LabelValue are both bound by selector_match_label, so the negated
# object_label literal has all six arguments bound.
matchlabel_unsatisfied(SelApiVersion, SelKind, SelNamespace, SelName,
                       ObjApiVersion, ObjKind, ObjNamespace, ObjName) :-
    sel_obj_candidate(SelApiVersion, SelKind, SelNamespace, SelName,
                      ObjApiVersion, ObjKind, ObjNamespace, ObjName),
    selector_match_label(SelApiVersion, SelKind, SelNamespace, SelName, LabelKey, LabelValue),
    !object_label(ObjApiVersion, ObjKind, ObjNamespace, ObjName, LabelKey, LabelValue).

# ---- matchExpressions: In ----

# The In requirement for LabelKey is satisfied if the object has LabelKey=AllowedValue
# for at least one AllowedValue from the set.
#
# This must be a separate named predicate because expr_in_unsatisfied needs to negate
# the entire "any value matched" check. Mangle cannot negate an inline conjunction,
# only a named predicate.
expr_in_satisfied(SelApiVersion, SelKind, SelNamespace, SelName, LabelKey,
                  ObjApiVersion, ObjKind, ObjNamespace, ObjName) :-
    selector_expr_in(SelApiVersion, SelKind, SelNamespace, SelName, LabelKey, AllowedValue),
    object_label(ObjApiVersion, ObjKind, ObjNamespace, ObjName, LabelKey, AllowedValue).

# The In requirement is unsatisfied when no value in the allowed set matches.
# The wildcard _ in selector_expr_in(..., LabelKey, _) is in a positive literal —
# it asserts that some In requirement for LabelKey exists, binding LabelKey for use
# in the negation below without committing to a specific value.
expr_in_unsatisfied(SelApiVersion, SelKind, SelNamespace, SelName,
                    ObjApiVersion, ObjKind, ObjNamespace, ObjName) :-
    sel_obj_candidate(SelApiVersion, SelKind, SelNamespace, SelName,
                      ObjApiVersion, ObjKind, ObjNamespace, ObjName),
    selector_expr_in(SelApiVersion, SelKind, SelNamespace, SelName, LabelKey, _),
    !expr_in_satisfied(SelApiVersion, SelKind, SelNamespace, SelName, LabelKey,
                       ObjApiVersion, ObjKind, ObjNamespace, ObjName).

# ---- matchExpressions: NotIn ----

# The NotIn requirement is violated if the object has LabelKey=ExcludedValue for
# any value in the excluded set. No negation needed — finding any excluded value
# is a direct positive check.
expr_notin_unsatisfied(SelApiVersion, SelKind, SelNamespace, SelName,
                       ObjApiVersion, ObjKind, ObjNamespace, ObjName) :-
    sel_obj_candidate(SelApiVersion, SelKind, SelNamespace, SelName,
                      ObjApiVersion, ObjKind, ObjNamespace, ObjName),
    selector_expr_notin(SelApiVersion, SelKind, SelNamespace, SelName, LabelKey, ExcludedValue),
    object_label(ObjApiVersion, ObjKind, ObjNamespace, ObjName, LabelKey, ExcludedValue).

# ---- matchExpressions: Exists ----

# The Exists requirement is unsatisfied if the object has no label with LabelKey at all.
# Uses object_has_label_key/5 rather than object_label/6 to avoid an unbound wildcard
# in the negated position (see object_has_label_key comment above).
expr_exists_unsatisfied(SelApiVersion, SelKind, SelNamespace, SelName,
                        ObjApiVersion, ObjKind, ObjNamespace, ObjName) :-
    sel_obj_candidate(SelApiVersion, SelKind, SelNamespace, SelName,
                      ObjApiVersion, ObjKind, ObjNamespace, ObjName),
    selector_expr_exists(SelApiVersion, SelKind, SelNamespace, SelName, LabelKey),
    !object_has_label_key(ObjApiVersion, ObjKind, ObjNamespace, ObjName, LabelKey).

# ---- matchExpressions: DoesNotExist ----

# The DoesNotExist requirement is violated if the object has any label with LabelKey,
# regardless of its value. Again a direct positive check — no negation needed.
expr_notexists_unsatisfied(SelApiVersion, SelKind, SelNamespace, SelName,
                           ObjApiVersion, ObjKind, ObjNamespace, ObjName) :-
    sel_obj_candidate(SelApiVersion, SelKind, SelNamespace, SelName,
                      ObjApiVersion, ObjKind, ObjNamespace, ObjName),
    selector_expr_notexists(SelApiVersion, SelKind, SelNamespace, SelName, LabelKey),
    object_has_label_key(ObjApiVersion, ObjKind, ObjNamespace, ObjName, LabelKey).

# ---- selector_any_unsatisfied ----
#
# Union of all five failure modes. A separate named predicate is required here for
# the same reason as expr_in_satisfied: selector_matches must negate a single named
# predicate — it cannot negate a disjunction inline.

selector_any_unsatisfied(SelApiVersion, SelKind, SelNamespace, SelName,
                         ObjApiVersion, ObjKind, ObjNamespace, ObjName) :-
    matchlabel_unsatisfied(SelApiVersion, SelKind, SelNamespace, SelName,
                           ObjApiVersion, ObjKind, ObjNamespace, ObjName).
selector_any_unsatisfied(SelApiVersion, SelKind, SelNamespace, SelName,
                         ObjApiVersion, ObjKind, ObjNamespace, ObjName) :-
    expr_in_unsatisfied(SelApiVersion, SelKind, SelNamespace, SelName,
                        ObjApiVersion, ObjKind, ObjNamespace, ObjName).
selector_any_unsatisfied(SelApiVersion, SelKind, SelNamespace, SelName,
                         ObjApiVersion, ObjKind, ObjNamespace, ObjName) :-
    expr_notin_unsatisfied(SelApiVersion, SelKind, SelNamespace, SelName,
                           ObjApiVersion, ObjKind, ObjNamespace, ObjName).
selector_any_unsatisfied(SelApiVersion, SelKind, SelNamespace, SelName,
                         ObjApiVersion, ObjKind, ObjNamespace, ObjName) :-
    expr_exists_unsatisfied(SelApiVersion, SelKind, SelNamespace, SelName,
                            ObjApiVersion, ObjKind, ObjNamespace, ObjName).
selector_any_unsatisfied(SelApiVersion, SelKind, SelNamespace, SelName,
                         ObjApiVersion, ObjKind, ObjNamespace, ObjName) :-
    expr_notexists_unsatisfied(SelApiVersion, SelKind, SelNamespace, SelName,
                               ObjApiVersion, ObjKind, ObjNamespace, ObjName).

# ---- selector_matches ----
#
# A selector matches an object when it is a candidate pair and no requirement
# of any type is unsatisfied. This is the primary exported predicate.
#
# Args: (SelApiVersion, SelKind, SelNamespace, SelName,
#        ObjApiVersion, ObjKind, ObjNamespace, ObjName)

selector_matches(SelApiVersion, SelKind, SelNamespace, SelName,
                 ObjApiVersion, ObjKind, ObjNamespace, ObjName) :-
    sel_obj_candidate(SelApiVersion, SelKind, SelNamespace, SelName,
                      ObjApiVersion, ObjKind, ObjNamespace, ObjName),
    !selector_any_unsatisfied(SelApiVersion, SelKind, SelNamespace, SelName,
                              ObjApiVersion, ObjKind, ObjNamespace, ObjName).
