# Recipe: indirect_perm as a view

## Why there is no indirect_perm relation

Pallograph keeps RBAC relations normalized. `direct_perm` holds each binding
subject's own grants, and escalation is stored as edges between identities
(`controls_identity`, `controls_group`). Earlier versions also stored
`indirect_perm`: every permission a principal could borrow, copied once per
(principal, target) pair. On a real cluster that was most of the rows, and it
grows with every cluster you analyze, so it was removed.

The answer is still there; it is a join. [`indirect-perm.mg`](indirect-perm.mg)
defines it as a view you can load on demand.

## How it is built

A principal borrows permissions two ways:

- **Becoming an identity** (exec into a pod, mint a token, create a pod,
  impersonate a user): `controls_identity(P, Via)` joined with the grants of
  `Via`. The target acts with its own subject and the groups Kubernetes adds
  (`assumed_subject`), not the `user_groups` of the user it impersonates.
- **Impersonating a group**: `controls_group(P, Group)` joined with the
  group's own grants.

`ResourceName` is left out to match the old six-column shape. Add it back by
binding the sixth `direct_perm` column if you need it.

## Demo

```
source examples/exec-escalation/alice-exec.mg
source examples/indirect-perm/indirect-perm.mg
?- indirect_perm("alice", Ns, ApiGroup, Resource, Verb, Via)
```

On the small fixture this lists what alice reaches through the kube-system
ServiceAccounts she can exec into, for example:

```
Ns = "kube-system", ApiGroup = "", Resource = "endpoints", Verb = "get", Via = "system:serviceaccount:kube-system:coredns"
Ns = "", ApiGroup = "", Resource = "nodes", Verb = "list", Via = "system:serviceaccount:kube-system:kindnet"
```

For "who can reach X" questions, `rbac::reaches` and `rbac::cluster-admin` do
this expansion for you and also print the escalation path.
