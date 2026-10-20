# Pallograph

An experiment in pairing Kubernetes controllers with Datalog (Mangle) and Z3.
Successor to [pallograph-ddlog](https://github.com/ajwdev/pallograph-ddlog).

## Performance checks

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
- `small_smt_access/assert_rbac_axioms_z3`: build the optional Z3 RBAC model,
  retained as a comparison/control path.
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
cargo build --release --bin profile_smt_access
samply record target/release/profile_smt_access --scenario cluster-admin --iters 1000
samply record target/release/profile_smt_access --scenario namespace-isolation --iters 1000
```

Other scenarios include `load-access-model`, `encode-z3`, and
`direct-cluster-admin`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
