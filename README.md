# Pallograph

An experiment in pairing Kubernetes controllers with Datalog (Mangle) and Z3.
Successor to [pallograph-ddlog](https://github.com/ajwdev/pallograph-ddlog).

## Performance checks

SMT/RBAC access checks have a dedicated Criterion benchmark:

```sh
cargo bench --bench smt_access
```

Use `small_smt_access/load_access_model_and_cluster_admin` or
`small_smt_access/load_access_model_and_namespace_isolation` to include access
model construction/querying from a pre-evaluated store while excluding initial
datasource/backend population.

The `small_smt_access_backend` group compares interpreter and DD setup for the
same access workload:

- `{interpreter,dd}/evaluate`
- `{interpreter,dd}/evaluate_and_load_access_model`
- `{interpreter,dd}/evaluate_and_cluster_admin`

For profiler runs, use the tight-loop driver so samply records the code under
inspection rather than Criterion harness overhead:

```sh
cargo build --release --bin profile_smt_access
samply record target/release/profile_smt_access --scenario cluster-admin --iters 1000
samply record target/release/profile_smt_access --scenario namespace-isolation --iters 1000
```

Use `--fixture medium` after fetching the medium dump with
`hack/fetch-fixtures.sh medium`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
