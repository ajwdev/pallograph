# Scenario: Indirect escalation via pods/exec
#
# A PR adds a RoleBinding granting alice "pods/exec create" in kube-system.
# Looks like a narrowly-scoped operational permission. In practice, it lets
# alice exec into any pod in kube-system and steal the mounted SA token —
# including the default SA, which has cluster-admin.
#
# Attack chain:
#   alice --[pods/exec create]--> exec into pod
#         --[steal token of]---> system:serviceaccount:kube-system:default
#         --[cluster-admin]----> all permissions
#
# Demo flow:
#   \snapshot baseline
#   \source examples/exec-escalation/alice-exec.mg
#   \access-diff baseline
#   \smt cluster-admin

rolebinding_subject_user("kube-system", "rb-alice-exec", "alice").
rolebinding_roleref("kube-system", "rb-alice-exec", "Role", "alice-exec").
role_perm("kube-system", "alice-exec", "", "pods/exec", "create").
