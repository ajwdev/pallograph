# Scenario: Indirect escalation via pods/exec
# See README.md for the full story.
#
# A PR adds one RoleBinding granting alice "pods/exec create" in kube-system.
# kube-system hosts static control-plane pods running as the default SA, which
# has cluster-admin. Exec access means alice can read the mounted token directly
# from the pod filesystem and authenticate as kube-system:default.
#
# The escalation is driven by exec_reachable_sa (escalation.mg), which finds
# the SA of any pod alice can exec into.
#
# Attack chain:
#   alice --[pods/exec create in kube-system]--> exec into control-plane pod
#         --[steal mounted token of]-----------> system:serviceaccount:kube-system:default
#         --[cluster-admin CRB]----------------> all permissions
#
# Note: the pod facts are in the baseline fixture (testdata/allpods.json).
# This scenario only adds the RoleBinding — the dangerous pods are already there.
#
# Demo flow:
#   \snapshot baseline
#   \source examples/exec-escalation/alice-exec.mg
#   \access-diff baseline
#   \smt cluster-admin

rolebinding_subject_user("kube-system", "rb-alice-exec", "alice").
rolebinding_roleref("kube-system", "rb-alice-exec", "Role", "alice-exec").
role_perm("kube-system", "alice-exec", "", "pods/exec", "create").
