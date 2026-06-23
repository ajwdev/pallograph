# Scenario: Binding to a ClusterRole whose permissions were silently expanded
# See README.md for the full story.
#
# ops-monitor started as a read-only pod monitoring role. Six months ago it
# was expanded to include "serviceaccounts/token create" to support a credential
# rotation project. That change passed review and was forgotten.
#
# Today's PR adds a RoleBinding for alice to ops-monitor in kube-system. The diff
# shows one new object — the RoleBinding. The ClusterRole is untouched and out of
# scope for review. Reviewers have no reason to audit it.
#
# pallograph evaluates the full current state of the cluster, not just the diff.
# \access-diff surfaces the effective capability alice gains — including the token
# creation permission that lives in ops-monitor's history, not today's change.
#
# Attack chain:
#   alice
#     --[ops-monitor RoleBinding in kube-system]-------> serviceaccounts/token create
#     --[mint token for kube-system:default]-----------> system:serviceaccount:kube-system:default
#     --[cluster-admin CRB]----------------------------> all permissions
#
# Demo flow:
#   \snapshot baseline
#   \source examples/hidden-clusterrole/hidden-clusterrole.mg
#   \access-diff baseline
#   \smt cluster-admin

# ops-monitor ClusterRole: pre-existing in the cluster, not part of today's PR.
# Originally read-only; "serviceaccounts/token create" was added months ago.
clusterrole_perm("ops-monitor", "", "pods", "get").
clusterrole_perm("ops-monitor", "", "pods", "list").
clusterrole_perm("ops-monitor", "", "pods", "watch").
clusterrole_perm("ops-monitor", "", "serviceaccounts/token", "create").

# Today's PR — the only change in the diff:
rolebinding_subject_user("kube-system", "rb-alice-ops", "alice").
rolebinding_roleref("kube-system", "rb-alice-ops", "ClusterRole", "ops-monitor").
