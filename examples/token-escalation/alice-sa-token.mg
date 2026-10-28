# Scenario: Indirect escalation via serviceaccounts/token
# See README.md for the full story.
#
# A PR adds one RoleBinding granting alice "serviceaccounts/token create" in
# kube-system. This lets alice mint a bearer token for any SA in the namespace
# — including kube-system:default, which has cluster-admin.
#
# The escalation is driven by subject_token_accessible_sa (escalation.mg), which finds
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
#   snapshot baseline
#   source examples/token-escalation/alice-sa-token.mg
#   rbac::diff baseline
#   rbac::cluster-admin

binding_subject("kube-system", "rb-alice-token", /user, "alice").
binding_roleref("kube-system", "rb-alice-token", "Role", "alice-token-creator").
role_rule("kube-system", "alice-token-creator", {/apiGroups: [""], /resources: ["serviceaccounts/token"], /verbs: ["create"]}).
