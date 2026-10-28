# Recipe: gate cluster-admins against an approval closure

## The idea

Some principals legitimately hold cluster-admin, but each should have security
sign-off. Express that sign-off as data: an **approval closure**, a list of
principals approved to be cluster-admin. Anything holding cluster-admin that is
not in the closure is a finding.

Pallograph does not ship this gate as a built-in relation, because the closure
is yours and the policy is yours. It ships only the empty EDB hook
`cluster_admin_allowed` (declared in `rules/00_edb_prelude.mg`). You provide
the closure facts and the view, both as Mangle files.

## The pieces

- [`cluster-admin-approved.mg`](cluster-admin-approved.mg) - the view:
  `cluster_admin(P)` is every principal (user, group or ServiceAccount) with a
  direct cluster-wide `*,*,*` grant; `unexpected_cluster_admin(P)` subtracts
  `cluster_admin_allowed`.
- [`approved.example.mg`](approved.example.mg) - a sample closure (facts for
  `cluster_admin_allowed`). Replace with your cluster's approved set.

Both are ordinary Mangle: the closure is EDB facts, the view is IDB rules.
Loaded through the engine they become part of the inputs a `snapshot` saves,
so they sit inside the provenance chain - the intended place for a future
signed-closure/digest scheme to attach.

## Use it

Load the closure and the view **before** `snapshot`, so the snapshot carries
the gate:

```
source examples/cluster-admin-approved/approved.example.mg
source examples/cluster-admin-approved/cluster-admin-approved.mg
snapshot base
?- unexpected_cluster_admin(P)
```

Two ways to inspect it:

- **Absolute** - "who is an un-approved cluster-admin right now":
  `?- unexpected_cluster_admin(P)` lists them.
- **Per-PR** - "what did this change do to the un-approved set": after
  `k8s::apply-delta base/ head/`, run
  `diff-relation base unexpected_cluster_admin` to see the rows it added or
  removed.

These are diagnostics, not pass/fail checks - `?-` and `diff-relation` just
report. Turning "a new un-approved admin" into a gating finding (exit 1) is
not wired yet; for now `rbac::diff` is the pass/fail check for permission
expansion, and this view tells you *which* admins and whether they are
approved.

## Loading the closure at startup

Runtime `source` works on both backends. If you prefer the closure to come
from a file loaded at startup (so a profile owns it), use a `json-tuples`
datasource into the same EDB relation:

```toml
[datasources.admin-allowlist]
source = "file"
paths = ["cluster-admin-allowlist.json"]   # [["eks:addon-manager"], ...]
content = "json-tuples"
relation = "cluster_admin_allowed"
```

and point `--rules` at a directory that includes `cluster-admin-approved.mg`.
Either way, load the closure and view **before** `snapshot` so the snapshot
carries them.

## Direct vs. reachable

This view flags **direct** cluster-admins: principals bound to a `*,*,*` role.
It does not chase escalation (who could *become* cluster-admin by impersonation,
token minting, or pod exec) - that is a graph reachability problem the finite
RBAC model does for you:

```
rbac::cluster-admin --all
```

prints the full roster, both the direct tier and the via-escalation tier, each
with its binding/role path - the source to copy approved principals from, and
the escalation-aware complement to this direct gate.
