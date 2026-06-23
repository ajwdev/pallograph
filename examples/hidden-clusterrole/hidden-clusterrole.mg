# Scenario: Binding to a ClusterRole whose permissions were silently expanded
#
# This simulates the "looks harmless in the diff" story from the demo:
# - Six months ago someone edited an existing ClusterRole to add wildcard access.
# - Today a PR adds a ClusterRoleBinding for alice to that ClusterRole.
# - The PR diff shows only the new binding — the dangerous ClusterRole edit is
#   not in scope, so reviewers miss the real impact.
#
# Here the ClusterRole "orphaned-sa-view" in the fixture already references
# cluster-admin level access in the test data. We bind alice directly to it.
#
# Demo flow:
#   \snapshot baseline
#   \source examples/hidden-clusterrole/hidden-clusterrole.mg
#   \access-diff baseline
#   \smt cluster-admin

clusterrolebinding_subject_user("crb-alice-view", "alice").
clusterrolebinding_roleref("crb-alice-view", "cluster-admin").
