# Scenario: Indirect escalation via serviceaccounts/token
# See README.md for the full story.
#
# A PR adds one RoleBinding granting alice "serviceaccounts/token create" in
# kube-system. This lets alice mint a bearer token for any SA in the namespace
# — including kube-system:default, which has cluster-admin.
#
# The escalation is driven by token_accessible_sa (escalation.mg), which finds
# every SA in namespaces where alice can create tokens.
#
# Attack chain:
#   alice --[serviceaccounts/token create in kube-system]--> mint token for kube-system:default
#         --[cluster-admin CRB]----------------------------> all permissions
#
# Contrast with exec-escalation: exec requires a running pod in the namespace.
# Token creation works as long as the SA exists — no pods needed. Quieter.
#
# Demo flow:
#   \snapshot baseline
#   \source examples/token-escalation/alice-sa-token.mg
#   \access-diff baseline
#   \smt cluster-admin

rolebinding_subject_user("kube-system", "rb-alice-token", "alice").
rolebinding_roleref("kube-system", "rb-alice-token", "Role", "alice-token-creator").
role_perm("kube-system", "alice-token-creator", "", "serviceaccounts/token", "create").
