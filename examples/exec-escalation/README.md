# Scenario: Indirect Escalation via pods/exec

## The Story

A PR lands in code review adding a RoleBinding that grants alice `pods/exec create`
in kube-system. The stated reason: she needs to exec into pods to debug a flaky
service. The diff is small — one RoleBinding, one Role. Nothing in the diff screams
"privilege escalation."

## What a Reviewer Misses

kube-system hosts static control-plane pods (etcd, kube-apiserver, etc.). Several
run as the `default` service account, which has a ClusterRoleBinding to `cluster-admin`.

`pods/exec create` lets alice exec into any pod in the namespace. Once inside, she
can read the mounted SA token directly from the pod filesystem:

```
/var/run/secrets/kubernetes.io/serviceaccount/token
```

That token authenticates as `kube-system:default` — giving alice full cluster-admin.

The danger isn't in the Role definition. It's in the combination of exec access and
whatever pods happen to be running in that namespace.

## What pallograph Shows

`\access-diff` surfaces the new `pods/exec create` permission.

`\smt cluster-admin` confirms the full escalation chain:

```
alice
  --[pods/exec create in kube-system]--> exec into kube-system pod
  --[steal mounted token of]-----------> system:serviceaccount:kube-system:default
  --[cluster-admin CRB]----------------> all permissions
```

## Demo

```
\snapshot baseline
\source examples/exec-escalation/alice-exec.mg
\access-diff baseline
\smt cluster-admin
```
