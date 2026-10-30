# Pallograph

An experiment in pairing Kubernetes state with Datalog
([Mangle](https://github.com/google/mangle)) and the Z3 solver. Successor to
[pallograph-ddlog](https://github.com/ajwdev/pallograph-ddlog).

Pallograph loads RBAC objects, pods, service accounts, and nodes from a cluster
(or a pile of JSON manifests), turns them into facts, and lets you ask
questions about the whole graph at once. ex: "who can reach cluster-admin, even
if it takes two hops through someone else's service account?"

This is a learning project as much as a tool. Expect sharp edges.

## Why

RBAC review happens one diff at a time. A RoleBinding granting `pods/exec` in
`app` looks fine in isolation; so does a service account that can mint tokens
in `kube-system`. Approved by two teams, months apart, they compose into a path
to cluster-admin that neither reviewer could see.

Datalog is a good fit for "follow every edge until nothing new shows up"
(reachability over the permission graph). Z3 handles the questions where the
search space is too big to enumerate, like "is there any node this pod could
ever be scheduled on?" Pallograph glues the two together behind a REPL.

## Quick start

Use the Nix dev shell (`nix develop`), or bring your own Rust toolchain. Then
run against the small fixture checked into the repo:

```sh
cp pallograph.toml.example pallograph.toml
cargo run --bin pallograph -- --profile dev
```

Point the `prod` profile at a live cluster (it uses your current KUBECONFIG
context) with `cargo run --bin pallograph -- --profile prod`.

A short session, run against the small fixture: an inventory count, cluster-wide
wildcard grants, who can reach cluster-admin, who can assume whose
identity, and the derivation behind one of those answers.

```
?- k8s_object_count
?- direct_perm(Who, Kind, "", "*", "*", /any, "*")
rbac::cluster-admin
?- controls_identity(P, Target)
why controls_identity("developer@example.com", "system:serviceaccount:kube-system:default")
```

Run `help` in the REPL for the full command list. Commands are bare paths
(e.g. `show`, `rbac::reaches`); a leading `::` is the fully-qualified form,
used to disambiguate (e.g. `::rbac::diff` vs `::diff`). Queries start with `?-`.
Tab completes command paths, relation names, and file arguments.

Startup commands are read from `$XDG_CONFIG_HOME/pallograph/pallographrc` (then
`./.pallographrc`); use `alias <name> <command...>` there for shorthands, e.g.
`alias ca rbac::cluster-admin`. `--rcfile <file>` and `--no-rc` override.

## What it can do

**Query the graph.** `?- <atom>, <atom>, ...` runs a Datalog query against
facts loaded from the cluster (EDB) and everything the rules derive from them.
A query is a read and keeps nothing; to reuse a result in later queries, name
it with `define`. `show` lists the documented relations along with their columns.

**Explain results.** `why <fact>` prints the derivation tree (provenance), so
you can see the chain of bindings and rules that produced a fact rather than
just trust it.

**Play what-if.** `+fact.` and `-fact.` add or retract facts, `define` adds a
rule, and `source` loads a whole `.mg` file (its ground facts go in as
facts, so `-` can retract them, and the rest as rules). Take a `snapshot`
first, then use `diff` or `rbac::diff` to see exactly which facts or RBAC
permissions moved, and `rollback <name>` to put the facts and rules back
as they were when you took it (the snapshot stays, so you can return to it
again; each snapshot holds its own copy of the facts). `use <name>`
points `?-`, `why` and `show` at that snapshot instead of the live state
(the prompt changes to `pallograph (<name>)>` and state-changing commands
are refused until a bare `use` returns to live); `use <name> <command>`
runs one command against the snapshot and returns automatically.

**Check access and scheduling.** The RBAC `rbac::` commands (`access`,
`reaches`, `cluster-admin`) scan the grants the rules derive; the scheduling
`sched::` ones hand the question to Z3:

| Command | Question |
|---------|----------|
| `rbac::access <ns> <r> <v> [p...]` | Who has this access beyond the expected set? |
| `rbac::reaches <ns> <ag> <r> <v> [p...]` | Who can reach this access, counting escalation paths? |
| `rbac::cluster-admin [p...]` | Shorthand for reaching `*` on everything |
| `sched::node-selector` | Which pods have a nodeSelector no node satisfies? |
| `sched::anti-affinity` | Is there any valid placement, or proof that none exists? |
| `sched::karpenter` | Where does Karpenter NodePool coverage leave gaps? |

Built-in Kubernetes and EKS principals are hidden from SMT output by default
(`--all` shows them). The list lives in `src/builtins.txt`.

**Script it.** `--format ndjson` emits one JSON object per row, which pipes
nicely into `jq` or DuckDB. `--script <file>` (`-` for stdin) runs one
command per line without the REPL and stops at the first line that is not a
command or whose command fails, so a typo'd path or command can't pass
silently. It exits 0 when clean, 1 on findings (a failed `rbac::`/`sched::`
check, or `rbac::diff` finding new permissions) and 2 on an error, so it can
gate CI:

```sh
cat > check.pg <<'EOF'
# The cluster is loaded at startup from the profile.
snapshot base
k8s::load rendered/head/
rbac::diff base
EOF
pallograph --profile prod --script check.pg
```

## Worked examples

Each directory under [`examples/`](examples/) tells the story of a plausible
escalation and the REPL commands that catch it:

- [`exec-escalation`](examples/exec-escalation/): `pods/exec` in
  `kube-system` turns into cluster-admin via a mounted token.
- [`two-hop-escalation`](examples/two-hop-escalation/): two independently
  reviewed grants compose across namespaces.
- [`token-escalation`](examples/token-escalation/): `serviceaccounts/token
  create` as a direct path.
- [`hidden-clusterrole`](examples/hidden-clusterrole/): binding to a ClusterRole
  that quietly grew `serviceaccounts/token create` months earlier.
- [`karpenter-unschedulable`](examples/karpenter-unschedulable/): pods no
  NodePool can ever satisfy.
- [`indirect-perm`](examples/indirect-perm/): rebuild the old `indirect_perm`
  table, permissions borrowed through escalation, as a view.
- [`cluster-admin-approved`](examples/cluster-admin-approved/): gate
  cluster-admins against a security-approved closure loaded as Mangle facts.
- [`k8s::apply-delta`](examples/apply-delta/): review a PR end to end - snapshot the
  live cluster, `k8s::apply-delta` its base->head render, and inspect what changed.

## Configuration

Pallograph reads `./pallograph.toml`, then
`~/.config/pallograph/config.toml`, or whatever you pass with `-C`. A config
has two parts:

- **Datasources** say where facts come from: a live cluster (`k8s`), files on
  disk (`file`), or a shell command (`shell`). File and shell sources parse
  either Kubernetes manifests or flat JSON tuples loaded into a named relation.
  The latter is how you pull in non-Kubernetes data (ex: GitHub org
  membership).
- **Profiles** are named lists of datasources, picked with `--profile`.

See [`pallograph.toml.example`](pallograph.toml.example) for every option.

Other flags worth knowing:

- `--rules <path>`: extra rules, a `.mg` file or a directory of them, loaded
  on top of the built-in rules. Repeatable.
- `--builtin-rules <dir>`: replace the built-in rules (embedded at build time)
  with a directory, so rule edits take effect without a rebuild. For
  development; hidden from `--help`.
- `--backend interpreter|dd`: evaluation engine, see below.
- `--provenance`: enable `why` on the DD backend.
- `--format default|compact|table|ndjson`: output format.
- `--script <file>`: run commands from a file (`-` for stdin) instead of the
  REPL; see "Script it" above.

## How it works

The rules live in [`rules/`](rules/) as plain Mangle files. `base.mg` projects
raw objects into typed relations; the three `rbac_roles.mg`, `rbac_subjects.mg`
and `rbac.mg` files model RBAC (see below); `escalation.mg` models identity
theft paths (exec into a pod, mint a token, impersonate); `rbac_write.mg`
models granting yourself a role by writing RBAC objects (`bind`,
`escalate`) and continues those paths through it; `labels.mg` implements label selectors; `summary.mg` does
inventory counts. `build.rs` compiles every rule file at build time, so a
broken rule fails `cargo build` instead of your demo.

There are two evaluation backends, and they must produce the same facts:

- **`interpreter`** (default): batch evaluation via `mangle-interpreter`.
  Simple, and the reference for correctness. Every change re-evaluates
  everything.
- **`dd`**: incremental evaluation on
  [differential-dataflow](https://github.com/TimelyDataflow/differential-dataflow).
  Adding or retracting a fact only does the work that fact touches, which
  matters once the cluster gets big. Provenance is lazy and opt-in; see
  [`docs/lazy-provenance.md`](docs/lazy-provenance.md).

### RBAC relations

The RBAC rules are split by question, and each file's header lists its
relations:

- `rbac_roles.mg`: what a role grants. `role_rule` and `clusterrole_rule`
  hold each role's PolicyRules (ClusterRole aggregation applied), and
  `policy_rule_perm` / `policy_rule_url_perm` flatten one PolicyRule into
  (apiGroup, resource, resourceName, verb) or (URL, verb) rows.
- `rbac_subjects.mg`: who a binding applies to. `binding_subject` and
  `binding_roleref` cover RoleBindings and ClusterRoleBindings alike, and
  `principal_subject(Username, Kind, Name)` lists the subjects a user or
  service account acts as: itself plus each of its groups.
- `rbac.mg`: the joins. `direct_perm/7` and `direct_url_perm/4` hold each
  binding subject's own grants, and `rbac_allowed` decides `access_request`
  facts the way the kube-apiserver RBAC authorizer does.

Subjects are kind-tagged (`/user`, `/group`, `/serviceaccount`), so a User
and a Group with the same name stay distinct. Grants are stored once per
binding subject rather than copied to every group member; to ask what a
principal can do, join through its groups:

```
?- principal_subject("alice", Kind, Name), direct_perm(Name, Kind, Ns, G, R, N, V)
```

Wildcards (`*`) stay literal strings in these relations, and a resourceName
of `/any` means any name (the rule lists no resourceNames). Escalation works the same way:
`controls_identity` and `controls_group` say who reaches whom, and the
permissions gained are joined on demand rather than stored.

### RBAC compatibility harness

`tests/rbac_compat.rs` checks `rbac_allowed` against upstream Kubernetes
itself. The Go program in [`tools/rbac-oracle/`](tools/rbac-oracle/) loads a
world of RBAC objects with the API server's defaulting, validation and
ClusterRole aggregation, generates probe requests for it, and decides them
with the real RBAC authorizer (the oracle). Pallograph decides the same
requests on both backends, which must agree with each other exactly; every
disagreement with the oracle is an over-grant or under-grant, bucketed by
feature tag.

Two escalation steps are decided outside the authorizer, so the oracle
also asks, per world, whether a principal may impersonate a user, group or
ServiceAccount (answered by the API server's impersonation filters) and
whether it may create or update a role or binding (answered by the RBAC
registry's bind and escalate checks). Pallograph answers these with the
single-step relations of its escalation rules; the table in
`tests/rbac_compat.rs` lists which.

- Curated worlds under `tests/rbac_compat/worlds/` each target a corner of
  RBAC (resourceNames, nonResourceURLs, subresources, aggregation shapes,
  subject kinds, the v1.37 bootstrap policy). `hack/rbac-compat-gen.sh`
  generates their requests and decisions into `target/rbac-compat/`.
- `tests/rbac_compat/baseline.json` is a ratchet of known mismatch counts
  per world. Every authorization request matches the authorizer exactly.
  The known gaps are in the escalation questions: RBAC writes allowed
  because the writer already holds every rule written, which gain it
  nothing and so are left out.
- `hack/rbac-compat.sh -s SEED -n COUNT` is the fuzz tier: it generates
  random worlds from a seed, decides them with the oracle, and reports
  worlds whose mismatches the curated worlds do not cover.

The authorizer never runs ClusterRole aggregation: it reads each role's
stored rules, which the aggregation controller writes. Pallograph and the
oracle recompute aggregated roles from their selectors, so a what-if change
(`load` a role labelled `aggregate-to-admin`) reaches `admin`. The
exception is a role on an aggregation cycle. There, what the controller
leaves depends on the order it visits the roles and on what they held
before, so both take the role's stored rules as they are, which is exact
for a cluster the controller has settled. Roles that aggregate a cycle role
are still recomputed and get its stored rules. The
`aggregation-cycle-own-rules` world pins these shapes.

## Development

CI runs inside the Nix shell, so run checks the same way:

```sh
nix develop .#ci -c cargo fmt --check
nix develop .#ci -c cargo clippy --all-targets --locked -- -D warnings
nix develop .#ci -c hack/rbac-compat-gen.sh   # needed before rbac_compat tests
nix develop .#ci -c cargo test --all-targets --locked
```

`hack/relation-sizes.sh` counts the rows each RBAC and escalation relation
derives for a rules directory and a set of manifests; use it to compare rule
revisions, since row counts drive evaluation time and memory. `hack/` also
has scripts for spinning up kind and KWOK clusters to test against. [`AGENTS.md`](AGENTS.md) covers repo conventions and known upstream
Mangle bugs we deliberately work around rather than patch.

## Benchmarks

The benchmark suite covers backend startup, incremental updates, provenance
costs, and the RBAC access hot path. Fixture loading and datasource I/O are kept
out of the measured loops unless noted in the benchmark source.

Run the small-fixture targets individually with:

```sh
cargo bench --bench small_bulk_load
cargo bench --bench small_fact_update
cargo bench --bench small_provenance
cargo bench --bench smt_access
```

Medium-fixture benchmarks require the anonymized medium dump first. After
fetching it, either run the medium targets individually or run the full bench
suite with `cargo bench`:

```sh
hack/fetch-fixtures.sh medium
cargo bench --bench medium_bulk_load
cargo bench --bench medium_fact_update
cargo bench --bench medium_provenance
```

### Backend benchmarks

- `small_bulk_load` / `medium_bulk_load`: initial query-ready load from
  preloaded facts and rules.
  - `*/mangle`: interpreter evaluation
  - `*/dd`: DD dataflow startup, initial feed, and settle
- `small_fact_update` / `medium_fact_update`: per-fact mutation cost after the
  initial state is settled.
  - `*_add_fact`: add one synthetic fact
  - `*_retract_fact`: remove one synthetic fact
  - small compares Mangle full re-evaluate against DD incremental updates;
    medium skips the very slow Mangle retract case.
- `small_provenance` / `medium_provenance`: DD with lazy provenance enabled,
  useful for comparing provenance-on costs against the matching provenance-off
  bulk-load and fact-update benchmarks.

### RBAC access benchmarks

RBAC access checks have a dedicated Criterion target:

```sh
cargo bench --bench smt_access
```

Important groups in that target:

- `small_smt_access/load_access_model`: build the finite RBAC access model from
  a pre-evaluated store.
- `small_smt_access/load_permission_tables`: build the permission tables
  `rbac::diff` compares, for one snapshot. Named `assert_rbac_axioms_z3`
  before it stopped loading anything into Z3.
- `small_smt_access/load_access_model_and_cluster_admin` and
  `small_smt_access/load_access_model_and_namespace_isolation`: include access
  model construction plus the query while excluding initial datasource/backend
  population.
- `small_smt_access/direct_cluster_admin`,
  `small_smt_access/reaches_cluster_admin`, and
  `small_smt_access/namespace_isolation_default`: query-only hot-path checks
  against an already-built access model.
- `small_smt_access_backend/{interpreter,dd}/evaluate`: backend evaluation
  only.
- `small_smt_access_backend/{interpreter,dd}/evaluate_and_load_access_model`:
  backend evaluation plus RBAC model construction.
- `small_smt_access_backend/{interpreter,dd}/evaluate_and_cluster_admin`:
  backend evaluation, RBAC model construction, and the cluster-admin query.

Use `--fixture medium` with the profiler after fetching the medium dump.

### Profiling RBAC access

For profiler runs, use the tight-loop driver so samply records the code under
inspection rather than Criterion harness overhead:

```sh
cargo build --profile profiling --bin profile_smt_access
samply record target/profiling/profile_smt_access --scenario cluster-admin --iters 1000
samply record target/profiling/profile_smt_access --scenario namespace-isolation --iters 1000
```

Other scenarios include `load-access-model`, `load-permission-tables`, and
`direct-cluster-admin`.

The `profiling` Cargo profile is the release profile plus debug symbols, so
samply can symbolize stacks. Release builds stay lean. To profile the main
binary, run `cargo build --profile profiling --bin pallograph` and point samply
at `target/profiling/pallograph`.

## Install

Static Linux binaries (x86_64, aarch64) are attached to each
[release](https://github.com/ajwdev/pallograph/releases). The rules are
embedded, so the binary works from any directory; `--rules <path>` adds to
them. With no config file it reads the cluster in your current kubeconfig
context (or in-cluster service account auth).

With Docker, mounting a kubeconfig (`--user` so the container can read a
0600 file):

```sh
docker run --rm -it --user "$(id -u)" \
  -v ~/.kube/config:/home/nonroot/.kube/config:ro \
  ghcr.io/ajwdev/pallograph
```

The image is the static binary plus busybox (for `shell` datasources) and CA
certificates. Exec credential plugins such as `aws` and `gcloud` are not
included, so use a token or certificate kubeconfig, or in-cluster
service account auth.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
