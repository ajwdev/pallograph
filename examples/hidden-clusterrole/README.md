# Scenario: Binding to a Silently Expanded ClusterRole

## The Story

Six months ago, someone added `serviceaccounts/token create` to the `ops-monitor`
ClusterRole. It was originally a read-only pod monitoring role — `get`, `list`,
`watch` on pods. The addition was a small change to support a credential rotation
automation project. It passed review. Nobody thought much of it.

Today's PR: alice is given a RoleBinding to `ops-monitor` in kube-system. The PR
diff shows exactly one new object — a RoleBinding. The ClusterRole isn't touched,
so its current shape is entirely invisible in the diff.

## What a Reviewer Misses

`ops-monitor` is no longer a read-only role. It can create tokens for any SA in
kube-system — including `default`, which has cluster-admin. A reviewer approving
the RoleBinding has no reason to audit a ClusterRole that isn't part of the change.

This is the **privilege expansion** story: the dangerous capability was introduced
in a previous change. The current PR looks harmless because the harm is already
baked into cluster state.

## What pallograph Shows

pallograph evaluates the full current state of the cluster — not just the diff.

`\access-diff` shows alice gaining `serviceaccounts/token create` in kube-system,
surfacing the effective capability of `ops-monitor` even though the ClusterRole
definition isn't part of the PR.

`\smt cluster-admin` confirms the escalation:

```
alice
  --[ops-monitor RoleBinding in kube-system]-------> serviceaccounts/token create
  --[mint token for kube-system:default]-----------> cluster-admin CRB
  --[cluster-admin]---------------------------------> all permissions
```

## Demo

```
\snapshot baseline
\source examples/hidden-clusterrole/hidden-clusterrole.mg
\access-diff baseline
\smt cluster-admin
```
