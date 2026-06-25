# NOTE: On these EDB relations the `bound [...]` types are DOCUMENTARY ONLY, not
# enforced. The k8s facts are added to the MemStore *after* compile_units runs
# (see src/engine.rs InterpreterBackend::evaluate), and the runtime type check
# `has_type` is only ever called from mangle-analysis bounds_check.rs, never by the
# interpreter/store. The compile-time BoundsChecker only checks literal facts/rules
# in the .mg sources plus rule-head conformance; nothing derives these EDB
# predicates, so their bounds are never validated against loaded data. Bounds would
# only be enforced if added to IDB (derived) rule heads. They are surfaced in the
# REPL's `::show` command for documentation.
Decl k8s(ApiVersion, Kind, Namespace, Name, Data)
  descr [
    doc("Raw Kubernetes objects, one row per live object."),
    arg(ApiVersion, "apiVersion, e.g. apps/v1"),
    arg(Kind, "object kind, e.g. Pod"),
    arg(Namespace, "namespace; empty for cluster-scoped objects"),
    arg(Name, "object name"),
    arg(Data, "spec/status blob; access via :match_field(Data, /spec, ...)")
  ]
  bound [/string, /string, /string, /string, /any].

Decl node_allocatable(NodeName, Resource, Quantity)
  descr [
    doc("Allocatable capacity per node, one row per resource."),
    arg(NodeName, "node name"),
    arg(Resource, "resource name, e.g. cpu or memory"),
    arg(Quantity, "allocatable quantity as reported by the node")
  ]
  bound [/string, /string, /string].

Decl pod_node_selector(Namespace, Name, Key, Value)
  descr [
    doc("Pod .spec.nodeSelector entries, one row per key/value."),
    arg(Namespace, "pod namespace"),
    arg(Name, "pod name"),
    arg(Key, "nodeSelector label key"),
    arg(Value, "required label value")
  ]
  bound [/string, /string, /string, /string].

Decl pod_anti_affinity_req(Namespace, Name, MatchKey, MatchValue, TopologyKey)
  descr [
    doc("Required pod anti-affinity terms, one row per match expression."),
    arg(Namespace, "pod namespace"),
    arg(Name, "pod name"),
    arg(MatchKey, "label key the term matches on"),
    arg(MatchValue, "label value the term matches on"),
    arg(TopologyKey, "topology key the constraint spreads across")
  ]
  bound [/string, /string, /string, /string, /string].

Decl user_groups(Username, Group)
  descr [
    doc("User-to-group membership, one row per membership."),
    arg(Username, "user name"),
    arg(Group, "group the user belongs to")
  ]
  bound [/string, /string].

Decl object_label(ApiVersion, Kind, Namespace, Name, LabelKey, LabelValue)
  descr [
    doc("Labels on objects, one row per label."),
    arg(ApiVersion, "object apiVersion"),
    arg(Kind, "object kind"),
    arg(Namespace, "object namespace; empty for cluster-scoped"),
    arg(Name, "object name"),
    arg(LabelKey, "label key"),
    arg(LabelValue, "label value")
  ]
  bound [/string, /string, /string, /string, /string, /string].

Decl selector_match_label(ApiVersion, Kind, Namespace, Name, LabelKey, LabelValue)
  descr [
    doc("matchLabels selector entries, one row per key/value."),
    arg(ApiVersion, "selecting object apiVersion"),
    arg(Kind, "selecting object kind"),
    arg(Namespace, "selecting object namespace; empty for cluster-scoped"),
    arg(Name, "selecting object name"),
    arg(LabelKey, "required label key"),
    arg(LabelValue, "required label value")
  ]
  bound [/string, /string, /string, /string, /string, /string].

Decl selector_expr_in(ApiVersion, Kind, Namespace, Name, LabelKey, AllowedValue)
  descr [
    doc("matchExpressions In terms, one row per allowed value."),
    arg(ApiVersion, "selecting object apiVersion"),
    arg(Kind, "selecting object kind"),
    arg(Namespace, "selecting object namespace; empty for cluster-scoped"),
    arg(Name, "selecting object name"),
    arg(LabelKey, "label key the expression matches on"),
    arg(AllowedValue, "one value from the In set")
  ]
  bound [/string, /string, /string, /string, /string, /string].

Decl selector_expr_notin(ApiVersion, Kind, Namespace, Name, LabelKey, ExcludedValue)
  descr [
    doc("matchExpressions NotIn terms, one row per excluded value."),
    arg(ApiVersion, "selecting object apiVersion"),
    arg(Kind, "selecting object kind"),
    arg(Namespace, "selecting object namespace; empty for cluster-scoped"),
    arg(Name, "selecting object name"),
    arg(LabelKey, "label key the expression matches on"),
    arg(ExcludedValue, "one value from the NotIn set")
  ]
  bound [/string, /string, /string, /string, /string, /string].

Decl selector_expr_exists(ApiVersion, Kind, Namespace, Name, LabelKey)
  descr [
    doc("matchExpressions Exists terms, one row per key."),
    arg(ApiVersion, "selecting object apiVersion"),
    arg(Kind, "selecting object kind"),
    arg(Namespace, "selecting object namespace; empty for cluster-scoped"),
    arg(Name, "selecting object name"),
    arg(LabelKey, "label key that must exist")
  ]
  bound [/string, /string, /string, /string, /string].

Decl selector_expr_notexists(ApiVersion, Kind, Namespace, Name, LabelKey)
  descr [
    doc("matchExpressions DoesNotExist terms, one row per key."),
    arg(ApiVersion, "selecting object apiVersion"),
    arg(Kind, "selecting object kind"),
    arg(Namespace, "selecting object namespace; empty for cluster-scoped"),
    arg(Name, "selecting object name"),
    arg(LabelKey, "label key that must not exist")
  ]
  bound [/string, /string, /string, /string, /string].
