# Scenario: Two-hop escalation through an intermediate service account
# See README.md for the full story.
#
# Two independent grants, reviewed by two different teams, combine into a
# cross-namespace escalation chain. Neither reviewer had visibility into the
# other grant. Each looks reasonable in isolation.
#
# Grant 1 (app team): alice gets pods/exec in the "app" namespace.
# Grant 2 (platform team, months earlier): app:worker gets serviceaccounts/token
#   create in kube-system for credential rotation.
#
# pallograph traces both hops via the controls_identity transitive closure.
# Use \why on any controls_identity fact to see the shortest path explicitly.
#
# Attack chain:
#   alice
#     --[pods/exec in app]---------------------> exec into app:worker pod
#     --[steal mounted token of]---------------> system:serviceaccount:app:worker
#     --[serviceaccounts/token create in kube-system]--> mint kube-system:default token
#     --[cluster-admin CRB]-------------------> all permissions
#
# Demo flow:
#   \snapshot baseline
#   \source examples/two-hop-escalation/alice-twohop.mg
#   \access-diff baseline
#   \smt cluster-admin

# Grant 1: alice gets pods/exec in the app namespace (today's PR)
rolebinding_subject_user("app", "rb-alice-app-exec", "alice").
rolebinding_roleref("app", "rb-alice-app-exec", "Role", "app-exec").
role_perm("app", "app-exec", "", "pods/exec", "create").

# The app:worker SA runs a pod alice can exec into
serviceaccount("app", "worker", "").
pod_sa("app", "app-worker-pod", "worker").

# Grant 2: app:worker was previously given token creation in kube-system
# (platform team approved this separately for credential rotation)
rolebinding_subject_sa("kube-system", "rb-worker-token", "app", "worker").
rolebinding_roleref("kube-system", "rb-worker-token", "Role", "worker-token-creator").
role_perm("kube-system", "worker-token-creator", "", "serviceaccounts/token", "create").
