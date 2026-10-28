# Recipe: review a PR with `apply-delta`

A runnable end-to-end example of inspecting a PR against a tiny synthetic
cluster: snapshot the live state, apply what merging the PR would do, and see
what changed.

## Layout

- `pallograph.toml` - a `dev` profile with two startup datasources: the live
  cluster (`cluster/`) and a cluster-admin approval closure
  (`cluster-admin-allowlist.json`, loaded into the `cluster_admin_allowed` EDB
  relation declared empty in `rules/00_edb_prelude.mg`).
- `cluster/rbac.yaml` - the live cluster as Argo has it deployed.
- `base/rbac.yaml` - the target-branch render (matches live, no drift).
- `head/rbac.yaml` - the PR merged into the target branch.
- `review.pg` - the review script.

The PR makes four changes vs base, one of each delta kind:

| Object | base -> head | Delta |
|---|---|---|
| `cluster-admin` ClusterRole | unchanged | - (counts as unchanged) |
| `app/pod-reader` Role | gains `watch` | `~` update |
| `app/alice-reader` RoleBinding | unchanged | - (counts as unchanged) |
| `legacy-admin` CRB (bob -> cluster-admin) | removed | `-` retract |
| `new-admin` CRB (eve -> cluster-admin) | added | `+` add |

## Run

From this directory:

```sh
../../target/debug/pallograph \
  -C pallograph.toml --profile dev --rules ../../rules --script review.pg
```

(Rules load from `./rules` by default, so point `--rules` back at the repo.)

## What it shows

```
Applied delta: +1 ~1 -1 (2 unchanged, 0 removed but not live) and evaluated.
FAIL  7 new permission(s) granted
    FAIL  alice@example.com  +2 gained / -0 lost
    FAIL  eve@example.com    +5 gained / -0 lost
    PASS  bob@example.com    +0 gained / -4 lost
  unexpected_cluster_admin  (+1 -1)
    + eve@example.com
    - bob@example.com
```

Three distinct things:

- **`apply-delta base/ head/`** applies the PR's effect to the live cluster:
  eve's binding added, pod-reader updated, bob's binding retracted,
  cluster-admin and alice-reader untouched (`+1 ~1 -1`, 2 unchanged).
- **`rbac::diff base`** is the **pass/fail gate**: any permission expansion
  exits 1. Here the PR grants eve cluster-admin and alice `watch`, so it
  fails. (Exit codes: 0 clean, 1 findings, 2 error.)
- **`diff-relation base unexpected_cluster_admin`** is a **diagnostic**, not a
  check: it just shows how that one relation changed (eve added, bob removed).
  It never passes or fails on its own.

The `unexpected_cluster_admin` relation comes from the sibling recipe
[`../cluster-admin-approved/`](../cluster-admin-approved/), sourced by
`review.pg`; the approval closure (`cluster-admin-allowlist.json`, empty here)
is loaded at startup. Add `eve@example.com` to the closure and eve drops out
of `unexpected_cluster_admin` - though `rbac::diff` still reports her new
access, since it is the broad expansion check and does not consult the
closure.

## Things to try

- **Brand-new chart** (empty base, everything is an add): `apply-delta - head/`.
- **Chart deleted** (empty head, everything retracted): `apply-delta base/ -`.
- **Scope the diagnostic** to any relation: `diff-relation base direct_perm`,
  or diff two snapshots: `diff-relation s1 s2 <relation>`.
