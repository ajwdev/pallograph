# Scenario: Escalation Through EKS Pod Identity

## The Story

alice is on call for the app and can exec into its pods. Nothing in the
cluster's RBAC lets her do more.

Outside the cluster, the app's `uploader` ServiceAccount has an EKS Pod
Identity association with the `uploader` IAM role, which may assume the
`deploy` role for releases. `deploy` has an EKS access entry that puts it in
the `platform-admins` Kubernetes group, which holds cluster-admin.

Each piece was set up by a different team, in a different place:

```
alice
  --[pods/exec in app]-------------------> app:uploader          (Kubernetes RBAC)
  --[Pod Identity association]-----------> role/uploader         (EKS)
  --[sts:AssumeRole]---------------------> role/deploy           (IAM)
  --[access entry: platform-admins]------> cluster-admin         (EKS + RBAC)
```

## How it plugs in

Pallograph itself doesn't change. `eks.mg` is an adapter for the escalation
closure in `rules/closure.mg`. It adds the system `/aws` with the kind
`/role`, and writes:

- `pivot` rows for the two pivots: `/pod_identity` from a
  ServiceAccount to a role, and `/sts_assume_role` from one role to another.
- `acts_as` rows saying what an assumed role acts as: itself in AWS, and
  in the cluster, its access entry's user and groups.

The closure chains those rows with the Kubernetes ones, so a path can leave
the cluster and come back. The AWS facts come in as `json-tuples` (see
`pallograph.toml`). Here they're static files; against a real account,
a `shell` datasource can produce them with `aws` and `jq`. Deciding which
role may assume which is IAM policy evaluation, so it's left to the loader,
and `aws_role_can_assume` carries the result.

Not modeled: EKS access policies (EKS's own authorizer, outside RBAC),
IRSA, and access entries for IAM users.

## Running it

```sh
cd examples/eks-pod-identity
cargo run --bin pallograph -- -C pallograph.toml --rules eks.mg
```

```
pivots alice
?- k8s_group_via_aws(P, G, R)
?- controls("alice", /k8s, /user, T, TS, TK)
?- controls_group("alice", G)
```

`controls_group("alice", "platform-admins")` holds even though the path
leaves the cluster, so `rbac::cluster-admin` lists alice. It can't print
her chain yet (`no escalation chain`): the path display in Rust only walks
Kubernetes pivots.

`pivots` walks the same graph for any system and prints the chain, one
step per line. `pivots alice` shows every node alice reaches; with a
target, `pivots alice platform-admins` shows just her chain:

```
alice (/k8s /user)
  /pod_exec [/grant] → system:serviceaccount:app:uploader (/k8s /serviceaccount)
    /pod_identity [/grant] → arn:aws:iam::111122223333:role/uploader (/aws /role)
      /sts_assume_role [/grant] → arn:aws:iam::111122223333:role/deploy (/aws /role)
        as platform-admins (/k8s /group) /impersonate [/grant] → platform-admins (/k8s /group)
```

It's a naive walk: one shortest path to each node, for systems without
first-class commands.

`tests/cross_system.rs` runs this example on both backends.
