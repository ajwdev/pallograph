# Scenario: Two-hop escalation through an intermediate service account
#
# A PR grants alice pods/exec in the "app" namespace. Looks like a narrow
# debugging permission. But "app" has a deployment SA (app:worker) that was
# previously granted serviceaccounts/token create in kube-system — a
# legitimate cross-namespace grant made by a different team.
#
# The two grants were reviewed and approved independently. Neither team saw
# the combined effect:
#
#   alice
#     --[pods/exec in app]-----------> exec into app:worker pod
#     --[token create in kube-system]-> mint kube-system:default token
#     --[cluster-admin]--------------> all permissions
#
# This chain requires two separate privilege grants from two different
# namespaces. pallograph sees through both hops via the controls_identity
# transitive closure and shows the full chain.
#
# Demo flow:
#   \snapshot baseline
#   \source examples/two-hop-escalation/alice-twohop.mg
#   \access-diff baseline
#   \smt cluster-admin

# alice gets pods/exec in the app namespace
rolebinding_subject_user("app", "rb-alice-app-exec", "alice").
rolebinding_roleref("app", "rb-alice-app-exec", "Role", "app-exec").
role_perm("app", "app-exec", "", "pods/exec", "create").

# app:worker SA exists and has a running pod alice can exec into
serviceaccount("app", "worker", "").
pod_sa("app", "app-worker-pod", "worker").

# app:worker was previously granted token creation in kube-system
# (e.g., to rotate credentials for a shared secret)
rolebinding_subject_sa("kube-system", "rb-worker-token", "app", "worker").
rolebinding_roleref("kube-system", "rb-worker-token", "Role", "worker-token-creator").
role_perm("kube-system", "worker-token-creator", "", "serviceaccounts/token", "create").
