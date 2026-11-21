# Label selector rules - which objects a Kubernetes label selector selects.
#
# As in Kubernetes, a selector is evaluated only against the kinds its owner
# selects, in the owner's namespace or among cluster-scoped objects:
# k8s_selector_targets.mg lists them (a Service selects Pods in its namespace, a
# PersistentVolumeClaim selects PersistentVolumes). The matching itself does
# not care about kind: it checks every requirement of a selector against
# every candidate object, and selector_matches/9 keeps the pairs the target
# table allows. To match selectors against objects of any kind, see
# examples/selectors-any-kind/, which adds candidates and reads
# selector_pair_matches/9.
#
# An object can own more than one selector (a ClusterRole has one per
# aggregationRule.clusterRoleSelectors entry), so a selector is its owner
# plus Selector, the path of the field it was read from, written as
# Kubernetes writes field paths (apimachinery field.Path, as in API server
# validation errors). Requirements are ANDed within one selector; separate
# selectors of one owner match independently.
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
#   Selector    - which of the owner's selectors: the field path it was read
#                 from (e.g. "spec.selector", "aggregationRule.clusterRoleSelectors[1]")
#   Variables referencing the candidate target object are prefixed "Obj":
#     ObjApiVersion, ObjKind, ObjNamespace, ObjName
#
# Base facts (EDB - Extensional Database, i.e. facts asserted directly, not derived):
#   k8s/6                     - Kubernetes objects loaded from the cluster
#   object_label/6            - (ApiVersion, Kind, Namespace, Name, LabelKey, LabelValue)
#                               One fact per label on any object. Extracted at load time
#                               in Rust because Mangle cannot enumerate struct fields with
#                               a variable key — :match_field requires a constant field name.
#   selector_match_label/7    - (ApiVersion, Kind, Namespace, Name, Selector, LabelKey, LabelValue)
#                               One fact per matchLabels entry. Also covers flat
#                               Service-style .spec.selector maps (treated as matchLabels).
#   selector_expr_in/8        - (ApiVersion, Kind, Namespace, Name, Selector, Index, LabelKey, AllowedValue)
#                               matchExpressions In operator; one fact per allowed value.
#                               Index is the expression's position, so two In
#                               expressions on one key are separate requirements.
#   selector_expr_notin/7     - (ApiVersion, Kind, Namespace, Name, Selector, LabelKey, ExcludedValue)
#                               matchExpressions NotIn operator; one fact per excluded value.
#   selector_expr_exists/6    - (ApiVersion, Kind, Namespace, Name, Selector, LabelKey)
#                               matchExpressions Exists operator.
#   selector_expr_notexists/6 - (ApiVersion, Kind, Namespace, Name, Selector, LabelKey)
#                               matchExpressions DoesNotExist operator.
#   selector_selects_all/5    - (ApiVersion, Kind, Namespace, Name, Selector)
#                               A selector with no requirements that selects every
#                               target, like a PodDisruptionBudget's selector: {}.
#
# Predicate hierarchy (IDB - Intensional Database, i.e. facts derived by rules):
#   k8s/6
#     → object_in_namespace/4        (objects keyed by namespace, for candidate lookups)
#   object_label/6
#     → object_has_label_key/5       (strips LabelValue; needed because Mangle forbids
#                                     unbound wildcards in negated literals — see below)
#     → object_label_by_name/6       (object_label keyed by object name)
#   selector_* + selector_target_kind/5 (k8s_selector_targets.mg) + object_in_namespace/4
#     → selector_declared/5          (the selectors objects own)
#     → selector_candidate/9         (each selector paired with the objects it may select;
#                                     ensures every variable is bound before negation fires)
#     → matchlabel_unsatisfied/9     (a matchLabels Key=Value requirement is not met)
#     → expr_in_satisfied/10         (an In requirement IS met; a separate named predicate
#                                     is required because Mangle can only negate a named
#                                     predicate — it cannot negate an inline conjunction)
#     → expr_in_unsatisfied/9        (no allowed value in the In set matched)
#     → expr_notin_unsatisfied/9     (an excluded value from NotIn was found)
#     → expr_exists_unsatisfied/9    (the required key is absent)
#     → expr_notexists_unsatisfied/9 (the forbidden key is present)
#     → selector_any_unsatisfied/9   (union of all failure modes; again a separate named
#                                     predicate so that selector_pair_matches can negate it)
#     → selector_pair_matches/9      (a candidate pair with no requirement unsatisfied)
#     → selector_matches/9           (the pairs the target table allows)

# ---- Base helpers ----

# Every object, keyed by its namespace. Candidate rules look objects up by
# the selector owner's namespace; keyed on k8s/6's leading ApiVersion
# instead, each selector would pair with every "v1" object in the cluster
# before the namespace filter (see "Write rules with the planner's lookups
# in mind" in AGENTS.md).
object_in_namespace(Namespace, Kind, ApiVersion, Name) :-
    k8s(ApiVersion, Kind, Namespace, Name, _, _).

# Strips LabelValue so the key alone can be tested in negation.
#
# Mangle requires every variable in a negated literal to be bound by a positive
# literal in the same rule body. Writing !object_label(..., LabelKey, _) is illegal
# because the wildcard _ (the value) would be unbound at negation time. This helper
# exposes a 5-argument form that is safe to negate:
#   !object_has_label_key(ObjApiVersion, ObjKind, ObjNamespace, ObjName, LabelKey)
object_has_label_key(ApiVersion, Kind, Namespace, Name, LabelKey) :-
    object_label(ApiVersion, Kind, Namespace, Name, LabelKey, _).

# object_label with Name first, for lookups that already know the object.
#
# TODO: this only exists because of how Mangle joins. The planner looks a
# relation up on its first bound column and checks the rest afterwards, and the
# DD backend turns that into a join keyed on that one column. Keyed on
# object_label's ApiVersion, every candidate pairs with every label on a "v1"
# object before the filter: on the medium fixture one k8s::match built about 3M
# rows and peak memory went from 0.4GB to 2.6GB. Remove it once DD joins are
# keyed on every bound column.
object_label_by_name(Name, ApiVersion, Kind, Namespace, LabelKey, LabelValue) :-
    object_label(ApiVersion, Kind, Namespace, Name, LabelKey, LabelValue).

# The selectors objects own: each with at least one requirement, or one
# that selects everything.
selector_declared(SelApiVersion, SelKind, SelNamespace, SelName, Selector) :-
    selector_match_label(SelApiVersion, SelKind, SelNamespace, SelName, Selector, _, _).
selector_declared(SelApiVersion, SelKind, SelNamespace, SelName, Selector) :-
    selector_expr_in(SelApiVersion, SelKind, SelNamespace, SelName, Selector, _, _, _).
selector_declared(SelApiVersion, SelKind, SelNamespace, SelName, Selector) :-
    selector_expr_notin(SelApiVersion, SelKind, SelNamespace, SelName, Selector, _, _).
selector_declared(SelApiVersion, SelKind, SelNamespace, SelName, Selector) :-
    selector_expr_exists(SelApiVersion, SelKind, SelNamespace, SelName, Selector, _).
selector_declared(SelApiVersion, SelKind, SelNamespace, SelName, Selector) :-
    selector_expr_notexists(SelApiVersion, SelKind, SelNamespace, SelName, Selector, _).
selector_declared(SelApiVersion, SelKind, SelNamespace, SelName, Selector) :-
    selector_selects_all(SelApiVersion, SelKind, SelNamespace, SelName, Selector).

# ---- selector_candidate ----
#
# Each selector paired with the objects it may select. Every *_unsatisfied
# rule below includes selector_candidate in its body. This serves two
# purposes:
#   1. Scopes work to pairs that are actually worth evaluating.
#   2. Guarantees that all eight position variables are bound by a positive literal
#      before any negation fires — a hard requirement in Mangle.
#
# A selector with no requirements (selector_selects_all) has nothing to be
# unsatisfied, so it selects every candidate.
#
# True cross-namespace selectors (e.g. Prometheus Operator namespaceSelector,
# pod affinity namespaceSelector) are a different data shape and are handled
# by separate EDB predicates and rules, not by this predicate.

# Target kinds in the owner's namespace (a Service's Pods).
selector_candidate(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                   ObjApiVersion, ObjKind, SelNamespace, ObjName) :-
    selector_declared(SelApiVersion, SelKind, SelNamespace, SelName, Selector),
    selector_target_kind(SelApiVersion, SelKind, ObjApiVersion, ObjKind, /same_namespace),
    object_in_namespace(SelNamespace, ObjKind, ObjApiVersion, ObjName).

# Cluster-scoped target kinds (a PersistentVolumeClaim's PersistentVolumes).
selector_candidate(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                   ObjApiVersion, ObjKind, ObjNamespace, ObjName) :-
    selector_declared(SelApiVersion, SelKind, SelNamespace, SelName, Selector),
    selector_target_kind(SelApiVersion, SelKind, ObjApiVersion, ObjKind, /cluster),
    object_in_namespace(ObjNamespace, ObjKind, ObjApiVersion, ObjName),
    ObjNamespace = "".

# The query owner k8s::match adds (see match_selector in src/api.rs): every
# object in its namespace, whatever the kind.
selector_candidate("pallograph.dev/query", SelKind, SelNamespace, SelName, Selector,
                   ObjApiVersion, ObjKind, SelNamespace, ObjName) :-
    selector_declared("pallograph.dev/query", SelKind, SelNamespace, SelName, Selector),
    object_in_namespace(SelNamespace, ObjKind, ObjApiVersion, ObjName).

# ---- matchLabels ----

# A matchLabels requirement (LabelKey=LabelValue) is not satisfied by the object.
# LabelKey and LabelValue are both bound by selector_match_label, so the negated
# object_label literal has all six arguments bound.
matchlabel_unsatisfied(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                       ObjApiVersion, ObjKind, ObjNamespace, ObjName) :-
    selector_candidate(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                       ObjApiVersion, ObjKind, ObjNamespace, ObjName),
    selector_match_label(SelApiVersion, SelKind, SelNamespace, SelName, Selector, LabelKey, LabelValue),
    !object_label(ObjApiVersion, ObjKind, ObjNamespace, ObjName, LabelKey, LabelValue).

# ---- matchExpressions: In ----

# In expression Index is satisfied if the object has LabelKey=AllowedValue for
# at least one AllowedValue from its set. Keyed on Index rather than LabelKey
# so that two In expressions on one key must both hold, as in Kubernetes.
#
# This must be a separate named predicate because expr_in_unsatisfied needs to negate
# the entire "any value matched" check. Mangle cannot negate an inline conjunction,
# only a named predicate. The label is looked up by object name; see
# object_label_by_name.
expr_in_satisfied(SelApiVersion, SelKind, SelNamespace, SelName, Selector, Index,
                  ObjApiVersion, ObjKind, ObjNamespace, ObjName) :-
    selector_candidate(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                       ObjApiVersion, ObjKind, ObjNamespace, ObjName),
    selector_expr_in(SelApiVersion, SelKind, SelNamespace, SelName, Selector, Index, LabelKey, AllowedValue),
    object_label_by_name(ObjName, ObjApiVersion, ObjKind, ObjNamespace, LabelKey, AllowedValue).

# An In expression is unsatisfied when no value in its allowed set matches.
# The wildcards in selector_expr_in(..., Index, _, _) are in a positive
# literal: it asserts that In expression Index exists, binding Index for the
# negation below without committing to a specific value.
expr_in_unsatisfied(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                    ObjApiVersion, ObjKind, ObjNamespace, ObjName) :-
    selector_candidate(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                       ObjApiVersion, ObjKind, ObjNamespace, ObjName),
    selector_expr_in(SelApiVersion, SelKind, SelNamespace, SelName, Selector, Index, _, _),
    !expr_in_satisfied(SelApiVersion, SelKind, SelNamespace, SelName, Selector, Index,
                       ObjApiVersion, ObjKind, ObjNamespace, ObjName).

# ---- matchExpressions: NotIn ----

# The NotIn requirement is violated if the object has LabelKey=ExcludedValue for
# any value in the excluded set. No negation needed — finding any excluded value
# is a direct positive check. Several NotIn expressions on one key need no
# index: excluding each set is the same as excluding their union. The label
# is looked up by object name; see object_label_by_name.
expr_notin_unsatisfied(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                       ObjApiVersion, ObjKind, ObjNamespace, ObjName) :-
    selector_candidate(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                       ObjApiVersion, ObjKind, ObjNamespace, ObjName),
    selector_expr_notin(SelApiVersion, SelKind, SelNamespace, SelName, Selector, LabelKey, ExcludedValue),
    object_label_by_name(ObjName, ObjApiVersion, ObjKind, ObjNamespace, LabelKey, ExcludedValue).

# ---- matchExpressions: Exists ----

# The Exists requirement is unsatisfied if the object has no label with LabelKey at all.
# Uses object_has_label_key/5 rather than object_label/6 to avoid an unbound wildcard
# in the negated position (see object_has_label_key comment above).
expr_exists_unsatisfied(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                        ObjApiVersion, ObjKind, ObjNamespace, ObjName) :-
    selector_candidate(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                       ObjApiVersion, ObjKind, ObjNamespace, ObjName),
    selector_expr_exists(SelApiVersion, SelKind, SelNamespace, SelName, Selector, LabelKey),
    !object_has_label_key(ObjApiVersion, ObjKind, ObjNamespace, ObjName, LabelKey).

# ---- matchExpressions: DoesNotExist ----

# The DoesNotExist requirement is violated if the object has any label with LabelKey,
# regardless of its value. Again a direct positive check — no negation needed.
expr_notexists_unsatisfied(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                           ObjApiVersion, ObjKind, ObjNamespace, ObjName) :-
    selector_candidate(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                       ObjApiVersion, ObjKind, ObjNamespace, ObjName),
    selector_expr_notexists(SelApiVersion, SelKind, SelNamespace, SelName, Selector, LabelKey),
    object_has_label_key(ObjApiVersion, ObjKind, ObjNamespace, ObjName, LabelKey).

# ---- selector_any_unsatisfied ----
#
# Union of all five failure modes. A separate named predicate is required here for
# the same reason as expr_in_satisfied: selector_pair_matches must negate a single
# named predicate — it cannot negate a disjunction inline.

selector_any_unsatisfied(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                         ObjApiVersion, ObjKind, ObjNamespace, ObjName) :-
    matchlabel_unsatisfied(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                           ObjApiVersion, ObjKind, ObjNamespace, ObjName).
selector_any_unsatisfied(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                         ObjApiVersion, ObjKind, ObjNamespace, ObjName) :-
    expr_in_unsatisfied(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                        ObjApiVersion, ObjKind, ObjNamespace, ObjName).
selector_any_unsatisfied(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                         ObjApiVersion, ObjKind, ObjNamespace, ObjName) :-
    expr_notin_unsatisfied(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                           ObjApiVersion, ObjKind, ObjNamespace, ObjName).
selector_any_unsatisfied(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                         ObjApiVersion, ObjKind, ObjNamespace, ObjName) :-
    expr_exists_unsatisfied(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                            ObjApiVersion, ObjKind, ObjNamespace, ObjName).
selector_any_unsatisfied(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                         ObjApiVersion, ObjKind, ObjNamespace, ObjName) :-
    expr_notexists_unsatisfied(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                               ObjApiVersion, ObjKind, ObjNamespace, ObjName).

# ---- selector_pair_matches ----
#
# A candidate pair where no requirement of any type is unsatisfied. Rules
# loaded with --rules may add candidates (see examples/selectors-any-kind/),
# so this can hold pairs Kubernetes would never evaluate; selector_matches
# below keeps only the ones it would.

selector_pair_matches(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                      ObjApiVersion, ObjKind, ObjNamespace, ObjName) :-
    selector_candidate(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                       ObjApiVersion, ObjKind, ObjNamespace, ObjName),
    !selector_any_unsatisfied(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                              ObjApiVersion, ObjKind, ObjNamespace, ObjName).

# ---- selector_matches ----
#
# The objects a selector selects in Kubernetes: matching pairs whose object
# kind and scope the target table allows for the owner, plus k8s::match's
# query owner. This is the primary exported predicate.
#
# Args: (SelApiVersion, SelKind, SelNamespace, SelName, Selector,
#        ObjApiVersion, ObjKind, ObjNamespace, ObjName)

selector_matches(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                 ObjApiVersion, ObjKind, SelNamespace, ObjName) :-
    selector_pair_matches(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                          ObjApiVersion, ObjKind, SelNamespace, ObjName),
    selector_target_kind(SelApiVersion, SelKind, ObjApiVersion, ObjKind, /same_namespace).

selector_matches(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                 ObjApiVersion, ObjKind, ObjNamespace, ObjName) :-
    selector_pair_matches(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                          ObjApiVersion, ObjKind, ObjNamespace, ObjName),
    ObjNamespace = "",
    selector_target_kind(SelApiVersion, SelKind, ObjApiVersion, ObjKind, /cluster).

selector_matches("pallograph.dev/query", SelKind, SelNamespace, SelName, Selector,
                 ObjApiVersion, ObjKind, SelNamespace, ObjName) :-
    selector_pair_matches("pallograph.dev/query", SelKind, SelNamespace, SelName, Selector,
                          ObjApiVersion, ObjKind, SelNamespace, ObjName).

# ---- selector_matches_kind ----
#
# selector_matches restricted to one target kind, for owners that select
# more than one (a StatefulSet's Pods but not its ControllerRevisions).
#
# TargetApiVersion/TargetKind are bound by the caller and unified with the
# object's type, so the Obj type positions can be left as wildcards at the call
# site:
#   selector_matches_kind("apps/v1", "StatefulSet", "ns", "db", _, "v1", "Pod", _, _, _, _)
#
# Args: (SelApiVersion, SelKind, SelNamespace, SelName, Selector,
#        TargetApiVersion, TargetKind,
#        ObjApiVersion, ObjKind, ObjNamespace, ObjName)

selector_matches_kind(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                      TargetApiVersion, TargetKind,
                      ObjApiVersion, ObjKind, ObjNamespace, ObjName) :-
    selector_matches(SelApiVersion, SelKind, SelNamespace, SelName, Selector,
                     ObjApiVersion, ObjKind, ObjNamespace, ObjName),
    ObjApiVersion = TargetApiVersion,
    ObjKind = TargetKind.
