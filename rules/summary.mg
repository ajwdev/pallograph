# Summary / aggregation rules
# These exercise GroupBy and give useful inventory counts.
#
# NOTE: Mangle's planner creates a fresh temporary relation ($temp_grp_0) per
# rule when materialising GroupBy sources.  Because the planner counter resets
# for each rule, multiple GroupBy rules in one ruleset share the same temp name
# and collide in the interpreter's store.  Until that upstream bug is fixed,
# keep exactly ONE GroupBy rule here.  The DD backend is unaffected (it inlines
# the temp relation and never materialises it).

# Count live objects grouped by (Kind, Namespace).
# Cluster-scoped resources (ClusterRoles, Nodes, etc.) appear with Namespace = "".
#
# Example output:
#   k8s_object_count("Pod",              "pallograph-test", 3)
#   k8s_object_count("ClusterRoleBinding", "",              1)
k8s_object_count(Kind, Namespace, N) :-
    k8s(_, Kind, Namespace, Name, _)
    |> do fn:group_by(Kind, Namespace), let N = fn:count(Name).
