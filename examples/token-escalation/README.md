# Scenario: Indirect Escalation via serviceaccounts/token

## The Story

A PR adds a RoleBinding granting alice `serviceaccounts/token create` in kube-system.
The stated reason: she's building a credential rotation pipeline and needs to mint
tokens for service accounts programmatically. One RoleBinding, one Role. Sounds
scoped. Looks fine.

## What a Reviewer Misses

`serviceaccounts/token create` lets alice mint a token for *any* SA in the namespace —
not just the ones the reviewer assumed. The `default` SA in kube-system has a
ClusterRoleBinding to `cluster-admin`. Alice can mint a token for it directly, no pod
required.

**Contrast with exec-escalation:** exec requires a running pod in the namespace to be
useful. Token creation works even with no pods scheduled — the SA existing is enough.
This is a quieter path with fewer observable side effects.

## What pallograph Shows

`\access-diff` surfaces the new `serviceaccounts/token create` permission.

`\smt cluster-admin` confirms the escalation:

```
alice
  --[serviceaccounts/token create in kube-system]--> mint token for kube-system:default
  --[cluster-admin CRB]----------------------------> all permissions
```

## Demo

```
\snapshot baseline
\source examples/token-escalation/alice-sa-token.mg
\access-diff baseline
\smt cluster-admin
```
