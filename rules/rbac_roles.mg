# RBAC roles - what each Role and ClusterRole grants.
#
# Facts loaded from the cluster (EDB) used here:
#   k8s/5                                     - Role and ClusterRole objects
#   clusterrole_aggregation_empty_selector/2  - clusterRoleSelectors entries
#                                               with no requirements
#   selector_* / object_label                 - via selector_matches/8 in
#                                               labels.mg
#
# Derived relations (IDB):
#   role/3, clusterrole/2                           (type filters)
#   role_rule/3, clusterrole_own_rule/2             (PolicyRules as written)
#   clusterrole_aggregates/2                        (aggregation sources)
#   clusterrole_aggregation_reaches/2,
#   clusterrole_on_aggregation_cycle/1              (aggregation cycles)
#   clusterrole_rule/2                              (rules after aggregation)
#   policy_rule_perm/5, policy_rule_url_perm/3      (one PolicyRule, flattened)
#
# Wildcards: "*" in apiGroups, resources, verbs and nonResourceURLs is stored
# as the literal string "*"; rbac.mg matches it at decision time. In
# resourceNames, "*" is not a wildcard: Kubernetes compares it as a literal
# name. A rule with no resourceNames (absent or empty) applies to every name
# and is flattened to ResourceName /any, a name constant rather than a
# string, so it cannot collide with a resourceNames entry. resourceNames: [""]
# is the literal empty name: it only matches requests that name no object.
#
# Aggregation is recomputed from selectors, except on aggregation cycles,
# where a ClusterRole's stored rules are used as they are. See "Aggregated
# ClusterRoles" below.

# ---- Type filters ----

role(Namespace, Name, Data) :-
    k8s("rbac.authorization.k8s.io/v1", "Role", Namespace, Name, Data).

clusterrole(Name, Data) :-
    k8s("rbac.authorization.k8s.io/v1", "ClusterRole", "", Name, Data).

# ---- PolicyRules as written ----

Decl role_rule(Namespace, Role, Rule)
  descr [
    doc("PolicyRules written in a Role, one row per rule."),
    arg(Namespace, "Role namespace"),
    arg(Role, "Role name"),
    arg(Rule, "the PolicyRule struct; access via :match_field(Rule, /verbs, ...)")
  ].

role_rule(Namespace, Role, Rule) :-
    role(Namespace, Role, Data),
    :match_field(Data, /rules, Rules),
    :list:member(Rule, Rules).

Decl clusterrole_own_rule(Role, Rule)
  descr [
    doc("PolicyRules written in a ClusterRole, before aggregation; see clusterrole_rule."),
    arg(Role, "ClusterRole name"),
    arg(Rule, "the PolicyRule struct")
  ].

clusterrole_own_rule(Role, Rule) :-
    clusterrole(Role, Data),
    :match_field(Data, /rules, Rules),
    :list:member(Rule, Rules).

# ---- Aggregated ClusterRoles ----
#
# A ClusterRole with an aggregationRule has its rules managed by the
# clusterrole-aggregation controller (pkg/controller/clusterroleaggregation).
# The controller replaces the role's rules with the rules of every other
# ClusterRole matching any of its clusterRoleSelectors. If no matching role
# has rules, it leaves the role's own rules in place. Aggregation chains: a
# source that is itself aggregated contributes its aggregated rules.
#
# The RBAC authorizer never runs aggregation: it reads each ClusterRole's
# stored rules field, which the controller writes. Pallograph recomputes
# that field from the selectors anyway, so that a what-if change (\load a
# role labelled aggregate-to-admin) shows up in the roles that aggregate it.
# A loaded cluster's stored rules for an aggregated role are already the
# controller's output, and recomputing them gives the same answer, except on
# an aggregation cycle (see "Aggregation cycles" below), where stored rules
# are used as they are. This mirrors aggregate() in
# tools/rbac-oracle/world.go.
#
# Each clusterRoleSelectors[i] entry is emitted by edb.rs as a synthetic
# selector owner (ApiVersion="pallograph.dev/agg", Kind="ClusterRoleAggregation",
# Namespace=i, Name=<aggregating ClusterRole>), with its matchLabels and
# matchExpressions stored as the standard selector_* facts. selector_matches/8
# in labels.mg then gives AND semantics within one selector and OR semantics
# across selectors. An empty selector ({} or {matchLabels: {}}) has no
# requirements and matches every ClusterRole, as in Kubernetes; edb.rs marks
# it with clusterrole_aggregation_empty_selector. A selector edb.rs could not
# encode gets neither requirements nor the marker, so it matches nothing.

Decl clusterrole_aggregates(Aggregator, Source)
  descr [
    doc("ClusterRole Aggregator's clusterRoleSelectors match ClusterRole Source (never itself)."),
    arg(Aggregator, "ClusterRole with an aggregationRule"),
    arg(Source, "ClusterRole whose rules it pulls in")
  ].

clusterrole_aggregates(Aggregator, Source) :-
    selector_matches("pallograph.dev/agg", "ClusterRoleAggregation", _, Aggregator,
                     "rbac.authorization.k8s.io/v1", "ClusterRole", "", Source),
    Aggregator != Source.

clusterrole_aggregates(Aggregator, Source) :-
    clusterrole_aggregation_empty_selector(Aggregator, _),
    clusterrole(Source, _),
    Aggregator != Source.

# ---- Aggregation cycles ----
#
# On a cycle (cycle-a selects cycle-b and cycle-b selects cycle-a) the
# controller's result depends on the order it visits roles and on what the
# roles held before: a role visited before its sources are replaced copies
# their own rules, and the cycle can keep feeding a copied rule back to
# itself after the role that wrote it has replaced it. Recomputing from
# selectors cannot recover that history, so a ClusterRole on a cycle keeps
# its stored rules (clusterrole_own_rule) as final. That is exact for any
# snapshot of a cluster the controller has settled.
#
# Roles off the cycle are still recomputed: a role that aggregates a cycle
# role gets the cycle role's stored rules, like any other source.
# tests/rbac_compat/worlds/aggregation-cycle-own-rules shows both shapes.
#
# Cycle membership is reachability, not a negation, so these relations
# depend on clusterrole_aggregates alone and stratify below the negations
# that use them.

Decl clusterrole_aggregation_reaches(Aggregator, Source)
  descr [
    doc("ClusterRole Aggregator pulls in Source through one or more aggregation steps."),
    arg(Aggregator, "ClusterRole with an aggregationRule"),
    arg(Source, "ClusterRole reached by following clusterrole_aggregates")
  ].

clusterrole_aggregation_reaches(Aggregator, Source) :-
    clusterrole_aggregates(Aggregator, Source).

clusterrole_aggregation_reaches(Aggregator, Source) :-
    clusterrole_aggregates(Aggregator, Middle),
    clusterrole_aggregation_reaches(Middle, Source).

# A role is on a cycle when it reaches itself. The equality is a separate
# filter because a variable repeated within one atom loses its check
# (see AGENTS.md).
clusterrole_on_aggregation_cycle(Role) :-
    clusterrole_aggregation_reaches(Role, Reached),
    Role = Reached.

# ---- Effective rules ----

# A ClusterRole ends up with at least one rule: it has rules of its own, or
# it is recomputed (not on a cycle) and aggregates a role that does.
# Positive recursion, so it can sit below the negation in clusterrole_rule.
clusterrole_has_rules(Role) :-
    clusterrole_own_rule(Role, _).

clusterrole_has_rules(Role) :-
    clusterrole_aggregates(Role, Source),
    !clusterrole_on_aggregation_cycle(Role),
    clusterrole_has_rules(Source).

# Recomputed aggregation produces at least one rule, so the role's own
# rules are replaced.
clusterrole_aggregation_nonempty(Role) :-
    clusterrole_aggregates(Role, Source),
    !clusterrole_on_aggregation_cycle(Role),
    clusterrole_has_rules(Source).

Decl clusterrole_rule(Role, Rule)
  descr [
    doc("Effective PolicyRules of a ClusterRole. An aggregated ClusterRole's rules are recomputed from its selectors, except on an aggregation cycle, where the controller's result depends on visit order and history, so the stored rules are used as they are."),
    arg(Role, "ClusterRole name"),
    arg(Rule, "the PolicyRule struct")
  ].

# On an aggregation cycle: the stored rules, as the authorizer reads them.
clusterrole_rule(Role, Rule) :-
    clusterrole_on_aggregation_cycle(Role),
    clusterrole_own_rule(Role, Rule).

# Not aggregated, or aggregation found no rules: the role's own rules.
clusterrole_rule(Role, Rule) :-
    clusterrole_own_rule(Role, Rule),
    !clusterrole_on_aggregation_cycle(Role),
    !clusterrole_aggregation_nonempty(Role).

# Recomputed aggregation: every source's effective rules, a cycle role's
# stored rules included.
clusterrole_rule(Role, Rule) :-
    clusterrole_aggregates(Role, Source),
    !clusterrole_on_aggregation_cycle(Role),
    clusterrole_rule(Source, Rule).

# ---- Flattening one PolicyRule ----
#
# A PolicyRule lists apiGroups, resources, resourceNames and verbs, and
# allows a request when every list has a matching entry. That is the same as
# allowing it when one row of their cross product matches, so the rule is
# flattened into (ApiGroup, Resource, ResourceName, Verb) rows.

policy_rule(Rule) :- role_rule(_, _, Rule).
policy_rule(Rule) :- clusterrole_own_rule(_, Rule).

policy_rule_resource_name(Rule, Name) :-
    policy_rule(Rule),
    :match_field(Rule, /resourceNames, Names),
    :list:member(Name, Names).

# resourceNames absent and resourceNames: [] both mean "any name" (/any).
policy_rule_has_resource_names(Rule) :-
    policy_rule_resource_name(Rule, _).

policy_rule_name_scope(Rule, /any) :-
    policy_rule(Rule),
    !policy_rule_has_resource_names(Rule).

policy_rule_name_scope(Rule, Name) :-
    policy_rule_resource_name(Rule, Name).

Decl policy_rule_perm(Rule, ApiGroup, Resource, ResourceName, Verb)
  descr [
    doc("Resource permissions of one PolicyRule, flattened."),
    arg(Rule, "the PolicyRule struct"),
    arg(ApiGroup, "API group; * is a literal wildcard"),
    arg(Resource, "resource or resource/subresource; * and */sub are literal wildcards"),
    arg(ResourceName, "object name, or /any for every name; the empty name and * are literal names"),
    arg(Verb, "verb; * is a literal wildcard")
  ].

policy_rule_perm(Rule, ApiGroup, Resource, ResourceName, Verb) :-
    policy_rule_name_scope(Rule, ResourceName),
    :match_field(Rule, /apiGroups, ApiGroups),
    :match_field(Rule, /resources, Resources),
    :match_field(Rule, /verbs, Verbs),
    :list:member(ApiGroup, ApiGroups),
    :list:member(Resource, Resources),
    :list:member(Verb, Verbs).

Decl policy_rule_url_perm(Rule, Url, Verb)
  descr [
    doc("Non-resource URL permissions of one PolicyRule, flattened."),
    arg(Rule, "the PolicyRule struct"),
    arg(Url, "nonResourceURLs entry, e.g. /healthz; * and a trailing * are literal wildcards"),
    arg(Verb, "verb; * is a literal wildcard")
  ].

policy_rule_url_perm(Rule, Url, Verb) :-
    policy_rule(Rule),
    :match_field(Rule, /nonResourceURLs, Urls),
    :match_field(Rule, /verbs, Verbs),
    :list:member(Url, Urls),
    :list:member(Verb, Verbs).

# ---- Role and ClusterRole permissions ----
#
# What a role grants is not stored per role. Many roles repeat the same
# rules (an aggregated ClusterRole holds a copy of each source's rules), so
# the flattened rows are stored once per distinct PolicyRule and joined on
# demand:
#
#   role_rule(Namespace, Role, Rule), policy_rule_perm(Rule, G, R, N, V)
#   clusterrole_rule(Role, Rule), policy_rule_perm(Rule, G, R, N, V)
#   clusterrole_rule(Role, Rule), policy_rule_url_perm(Rule, Url, Verb)
#
# Roles cannot hold nonResourceURLs (API validation rejects them), so only
# ClusterRoles have URL permissions.
