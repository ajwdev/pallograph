# AGENTS.md

Guidance for coding agents working in this repo. `CLAUDE.md` is a symlink to
this file.

## What this is

Pallograph analyzes Kubernetes state (RBAC, pods, service accounts, nodes)
with Datalog ([Mangle](https://github.com/google/mangle), via the `mangle-*`
crates pinned in `Cargo.toml`) and the Z3 solver. It ships as a REPL
(`src/repl.rs`) driven by meta-commands written as bare `::`-separated paths
(`why`, `rbac::reaches`, `diff`, `load`, `define`, ...). Analyses are grouped
into subsystem namespaces (`rbac::`, `sched::`, `k8s::`); a leading `::` is the
fully-qualified form, used to disambiguate (e.g. `::rbac::diff` vs `::diff`).
Queries start with `?-`.

Clarity beats cleverness.

## Writing for readers

Assume collaborators know Kubernetes and Rust but only the basics of Datalog,
SMT solving, and differential dataflow. In docs, comments, commit messages,
REPL output, and new identifiers, lead with plain words and keep the term of
art alongside so readers can look it up: "facts loaded from the cluster
(EDB)", "Z3 proved no such request exists (unsat)".

## Layout

Only the non-obvious parts:

- `rules/*.mg` - Mangle rules. `00_edb_prelude.mg` declares the input
  relations and is `include_str!`'d into the binary; `build.rs` compiles every
  rule file at build time, so a broken rule fails `cargo build`.
- RBAC rules are split three ways: `rules/rbac_roles.mg` (what a role grants,
  aggregation included), `rules/rbac_subjects.mg` (who a binding applies to,
  and the subjects a principal acts as) and `rules/rbac.mg` (`direct_perm`,
  `direct_url_perm` and `rbac_allowed`). File headers list the relations.
- `hack/relation-sizes.sh` counts rows per RBAC and escalation relation;
  use it to compare rule revisions.
- `src/engine.rs` - `Engine` and the `Backend` trait, with two backends
  selected by `--backend` (default `interpreter`):
  - `InterpreterBackend` - batch evaluation via `mangle-interpreter`.
  - `DdBackend` (`src/dd/`) - incremental evaluation on differential-dataflow.
    Provenance (`\why`) is lazy and opt-in (`--provenance`); see
    `docs/lazy-provenance.md`.
- `src/api.rs` - the `Core` trait, everything a client asks of the core:
  queries, provenance (the REPL's `why`; the API says "provenance"),
  snapshots and diffs, fact and rule writes, loading, selector matches,
  the `rbac::`/`sched::` checks, `explain` and `smtlib`. An `At { Live,
  Snapshot }` picks the state a read sees. `LocalCore` answers in-process:
  it owns the shared `Engine` (behind a mutex, which a cluster watcher also
  feeds), the named snapshots, and the live state cached by
  `Engine::version()`. The REPL goes through `Core` for every command, so
  a remote client (gRPC, planned) can implement the same trait; keep new
  commands on it. Results are plain Rust types, and each error displays as
  the line the REPL prints. `LocalCore::rollback` is deliberately not on
  the trait: on a shared core it would reset everyone's live state.
- Clients do the I/O; the core does anything that has to agree with the
  rules. The REPL reads files and runs `!` commands; the core turns k8s
  objects into facts (`edb::single_object_facts`) and splits a sourced
  file into facts and rules (`src/source.rs`). `src/delta.rs` diffs two
  renders of the same manifests for `k8s::apply-delta`.
- `?-` and `k8s::match` are reads: they evaluate over the state plus a
  query rule or extra facts (`Engine::evaluate_query_on`,
  `Engine::evaluate_with`) and leave nothing in the engine. Name a result
  with `define` to reuse it.
- `Engine::version()` is the DD worker's settled epoch (the interpreter
  counts changes instead). Rebuilds continue from it, so it never goes
  backwards; it is the one notion of time, not a second counter.
- `src/watch.rs` - with `watch = true` on a `k8s` datasource (or
  `--watch`), kube watchers keep the engine current through
  `Engine::apply_changes`, one DD commit per batch.
- `src/builtins.txt` - built-in K8s/EKS principals filtered from SMT output.
  Its header documents how to regenerate it.
- `api-resources.txt` (repo root) is `include_str!`'d by the fixture
  anonymizer (`src/bin/anonymize.rs`). It is not a stray; deleting it breaks
  the build.
- `tools/rbac-oracle/` - Go program wrapping upstream k8s RBAC authorization,
  the impersonation filters and the RBAC registry's escalation checks, used
  as the oracle for `tests/rbac_compat.rs`.
- `notes/` is gitignored scratch space. Don't rely on it existing.

## Building and testing

Use the Nix dev shell. CI runs clippy and tests inside `devShells.ci`, so run
them the same way:

```sh
nix develop .#ci -c cargo fmt --check
nix develop .#ci -c cargo clippy --all-targets --locked -- -D warnings
nix develop .#ci -c hack/rbac-compat-gen.sh   # needed before rbac_compat tests
nix develop .#ci -c cargo test --all-targets --locked
```

The CI fmt job runs on `dtolnay/rust-toolchain@stable` rather than Nix (see
`.github/workflows/ci.yml`), so rustfmt there can be newer than the pinned one.

`hack/rbac-compat-gen.sh` builds the Go oracle and writes generated test data
to `target/rbac-compat/`. That output is never committed; rerun it after
changing a world under `tests/rbac_compat/worlds/` or `tools/rbac-oracle/`.
Without it, `rbac_compat` fails rather than skips. Known gaps are tracked in
`tests/rbac_compat/baseline.json`; `UPDATE_BASELINE=1 cargo test --test
rbac_compat` rewrites it.

Running locally:

```sh
cargo run --bin pallograph -- -C pallograph.toml.example --profile dev
cargo run --bin pallograph -- --backend dd --provenance ...
```

To check a refactor leaves output alone, build `main` alongside (ex:
`git archive origin/main` into a scratch directory, with its own
`CARGO_TARGET_DIR`) and diff both binaries' stdout and stderr over the
same `--script` on both backends. Some output isn't reproducible between
runs of the same binary, so rule that out before calling a difference a
regression: interpreter row order (and GroupBy relations like
`k8s_object_count`), which gaps and placement Z3 reports for `sched::`,
and the order of strata in `--explain`. Compare those sorted.

Benchmarks live in `benches/` (criterion), split by fixture size
(`small_*`, `medium_*`) plus `smt_access`; ex: `cargo bench --bench
small_bulk_load`. Medium targets need `hack/fetch-fixtures.sh medium` first.
The README's Benchmarks section describes each target.

## Conventions

- Every `.rs` file starts with the copyright and
  `SPDX-License-Identifier: MIT OR Apache-2.0` header.
- Inside an already crate-private module (e.g. `dd`, `smt`), use plain `pub`,
  not `pub(crate)`.
- Spell new identifiers out in full (`ProvenanceMode`, not `ProvMode`;
  `annotation`, not `ann`).
- No ALL-CAPS emphasis in comments. Acronyms are fine.
- When a technique is borrowed from elsewhere (e.g. Soufflé), attribute it
  once where it is defined, not at every use site.
- Match the surrounding code's comment density and idiom.

## Backend parity

The DD backend must produce the same facts as the interpreter. Any change to
lowering, dataflow construction, or rules should keep `dd_interp_parity` and
the `dd_matches_interpreter` test in `src/engine.rs` passing. Prefer adding a
small feature-matrix case to `tests/dd_interp_parity.rs` when touching a
specific Datalog feature.

One deliberate difference: the DD backend rejects `fn:time:now` (see
`NON_DETERMINISTIC_FUNCTIONS` in `src/dd/build.rs`). DD evaluates a `let`
again on retraction, so a function that changes between calls would leave
stale rows behind.

Known upstream `mangle-rs` bugs, deliberately not patched here:

- A typo'd `:builtin` atom silently becomes a join against an empty relation,
  on both backends (`dd_call_filter_guard_rejects_unsupported` in
  `src/dd/session.rs`).
- The bounds checker rejects a zero-argument `fn:count()` ("reducer function
  fn:count expects at least one argument"). mangle-go is the reverse: it
  declares `fn:count` with arity 0 and rejects `fn:count(X)`. No form works
  on both, so rules here write `fn:count(X)` with a body variable.
- In the interpreter only, every GroupBy rule copies its body rows into the
  same temp relation (`$temp_grp_0`), even across strata. When two GroupBy
  rules read different relations, one picks up the other's rows (wrong
  counts and sums, extra groups) or loses its output entirely. So
  `rules/summary.mg` keeps a single GroupBy rule.
- The interpreter indexes a struct-valued column by its field count alone
  (`value_to_index_key` in `mangle-interpreter`), so a lookup keyed on a
  struct (e.g. a PolicyRule `Rule`) returns nearly every row. Results stay
  correct, but evaluation is slow. `policy_rule_has_wildcard_verb` in
  `rules/policies.mg` is shaped around it.
- The interpreter's store checks each new fact against every row already in
  its relation (`Vec::contains` in `MemStore::add_fact`), so loading facts
  takes quadratic time: about 0.76s for 20k facts in one relation, against
  0.007s on the DD backend.

Don't work around these by making the DD backend diverge from the
interpreter. Leave the affected test ignored or the rule shaped around the bug.

### Write rules with the planner's lookups in mind

The upstream planner indexes each body atom on its first bound argument
(variable or constant) only, and checks the other columns afterwards. The DD
backend turns that into a join keyed on that one column. So:

- Put the selective column first in any relation that other rules look up.
  `direct_perm` leads with `Principal` for this reason: keyed on its
  low-cardinality `Kind`, the `rbac_compat` run used about 3.9GB per chunk and
  ran the machine out of memory.
- A leading constant picks the index too. `direct_perm(N, K, Ns, "", "pods",
  _, "create")` with `N` unbound looks up on `ApiGroup = ""`, which is close
  to a scan.
- `hack/relation-sizes.sh` counts rows per relation, so you can compare
  revisions when you change rule shapes.

## Git

- Commit messages follow Tim Pope's style: imperative subject, 50 chars or
  less, blank line, body wrapped at 72.
- Only merge commits to `main` must build. Intermediate commits on a branch
  may be broken; don't squash just to fix that.
- `.git-blame-ignore-revs` lists mass-format commits.
