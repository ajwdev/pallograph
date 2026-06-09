# Scenario: Indirect escalation via serviceaccounts/token
#
# A PR adds a RoleBinding granting alice "serviceaccounts/token create" in
# kube-system. This lets alice mint a token for any SA in that namespace —
# including the default SA, which has cluster-admin.
#
# Escalation mechanism: token_accessible_sa in escalation.mg
#   alice --[serviceaccounts/token create]--> mint token for default SA
#         --[cluster-admin]----------------> all permissions
#
# Contrast with alice-exec.mg: exec requires a running pod; token creation
# works even if no pods are scheduled. A quieter path.
#
# Demo flow:
#   \snapshot baseline
#   \source scenarios/alice-sa-token.mg
#   \access-diff baseline
#   \smt cluster-admin

rolebinding_subject_user("kube-system", "rb-alice-token", "alice").
rolebinding_roleref("kube-system", "rb-alice-token", "Role", "alice-token-creator").
role_perm("kube-system", "alice-token-creator", "", "serviceaccounts/token", "create").
