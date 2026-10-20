# AGENTS.md

Guidance for coding agents working in this repo. `CLAUDE.md` is a symlink to
this file.

## What this is

Pallograph analyzes Kubernetes state (RBAC, pods, service accounts, nodes)
with Datalog ([Mangle](https://github.com/google/mangle), via the `mangle-*`
crates pinned in `Cargo.toml`) and the Z3 solver. It ships as a REPL
(`src/repl.rs`) driven by `\` commands (`\why`, `\smt`, `\diff`, `\load`,
`\define`, ...). The REPL rewrites `\cmd` to `::cmd` before dispatch, so the
code matches on `::` and the older `::cmd` spelling still works.

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
- `src/engine.rs` - `Engine` and the `Backend` trait, with two backends
  selected by `--backend` (default `interpreter`):
  - `InterpreterBackend` - batch evaluation via `mangle-interpreter`.
  - `DdBackend` (`src/dd/`) - incremental evaluation on differential-dataflow.
    Provenance (`\why`) is lazy and opt-in (`--provenance`); see
    `docs/lazy-provenance.md`.
- `src/builtins.txt` - built-in K8s/EKS principals filtered from SMT output.
  Its header documents how to regenerate it.
- `api-resources.txt` (repo root) is `include_str!`'d by the fixture
  anonymizer (`src/bin/anonymize.rs`). It is not a stray; deleting it breaks
  the build.
- `tools/rbac-oracle/` - Go program wrapping upstream k8s RBAC authorization,
  used as the oracle for `tests/rbac_compat.rs`.
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

Known upstream `mangle-rs` bugs, deliberately not patched here:

- A typo'd `:builtin` atom silently becomes a join against an empty relation,
  on both backends (`dd_call_filter_guard_rejects_unsupported` in
  `src/dd/session.rs`).
- `fn:collect_distinct` fails on both backends (comment in
  `tests/dd_interp_parity.rs`).
- A variable repeated in one atom (`edge(X, X)`) loses its equality check,
  and the two backends return different wrong answers
  (`repeated_variable_in_atom`, an ignored test in
  `tests/dd_interp_parity.rs`).
- Multiple GroupBy rules in one ruleset collide on a shared temp relation in
  the interpreter only, so `rules/summary.mg` keeps a single GroupBy rule.
- The interpreter indexes a struct-valued column by its field count alone
  (`value_to_index_key` in `mangle-interpreter`), so a lookup keyed on a
  struct (e.g. a PolicyRule `Rule`) returns nearly every row. Results stay
  correct, but evaluation is slow. `policy_rule_has_wildcard_verb` in
  `rules/rbac_roles.mg` is shaped around it.

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
