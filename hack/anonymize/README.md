# anonymize

Rewrites a `kubectl get -o json` dump so it can be benchmarked or shared
without leaking real names. Every reference and string length is preserved,
so joins between objects (names, namespaces, labels, selectors, UUIDs,
`system:serviceaccount:<ns>:<sa>`) still line up and the engine derives the
same relation counts.

## Usage

```
cargo run --release --bin anonymize -- <input.json> -o <output.json> [flags]
```

The input can be a `List`, a single object, or concatenated objects.

| Flag | Purpose |
|---|---|
| `-o, --output <file>` | Output file (required). |
| `--check` | Scan the output for leaks and exit non-zero on a hit. |
| `--report` | Print every field path and value kept verbatim, with counts, to stderr. |
| `--deny <file>` | Local denylist: case-insensitive substrings, one per line. Matches are always rewritten and fail `--check` if they survive. |
| `--mapping <file>` | Write the real to fake token map. Never written unless asked. |
| `--seed <n>` | PRNG seed. Same seed and input gives the same output. Default is random. |

A typical run:

```
cargo run --release --bin anonymize -- real/dump.json \
    -o anon/dump.json --check --report --deny internal-names.local.txt
```

Read the `--report` output before sharing the result. It lists everything
that was deliberately left readable.

## What is kept and what is rewritten

It fails closed. Every string is split into alphanumeric runs (tokens) and
each token is replaced by a random fake of the same length and character
class. Separators are copied verbatim. The token map is global and
injective, which is what keeps references intact.

A path table in `src/bin/anonymize.rs` (`act_for`) carves out fields whose
values are public or structural and must stay readable:

- enums such as `operator` and `effect`, and `apiVersion`/`kind`
- RBAC verbs, resources and apiGroups, only when public (see below)
- well-known scheduling labels (arch, zone, instance-type, ...)
- resource quantities
- built-in principals from `src/builtins.txt`, plus `default`,
  `cluster-admin` and `kube-system`, so the engine's literals still match

Secret and ConfigMap base64 payloads are replaced with random base64 of the
same length.

### public-vocab.txt

A value in a schema-defined field (apiVersion, kind, apiGroup, RBAC verbs,
resources and apiGroups) is kept only if every word in it appears in
`public-vocab.txt` or `api-resources.txt`. Anything else, such as CRDs and
internal API groups, is rewritten. Add public Kubernetes words to
`public-vocab.txt` if a legitimate value is being scrambled. Never add
internal names.

## Files you must not commit

`.gitignore` covers `*.mapping.json` and `*.local.txt`. The mapping reverses
the anonymization, and a denylist is itself a list of internal names, so
keep both out of git. Real dumps are your responsibility to keep out of the
tree.

## Checking that structure survived

`tests/anonymize_equiv.rs` loads a real dump and its anonymized copy, runs
the rules on both, and asserts the per-relation tuple counts (EDB and
derived IDB) match. It is `#[ignore]`d because it needs real data:

```
PALLOGRAPH_REAL_FIXTURES=real PALLOGRAPH_ANON_FIXTURES=anon \
    cargo test --release --test anonymize_equiv -- --ignored --nocapture
```

Each variable is a directory of manifests, loaded the same way as
`fixtures/testdata/small/`.

## Publishing as the medium benchmark fixture

The `medium_*` benches run against an anonymized dump published as a
release asset. After `--check` passes and you have read the `--report`
output:

```
hack/publish-fixtures.sh anon fixtures-medium-v2
```

This tars the directory, uploads it to a GitHub release, and rewrites
`fixtures/testdata/medium.env` with the new tag and sha256. Commit that
file. Everyone else gets the dump with:

```
hack/fetch-fixtures.sh medium
cargo bench --bench medium_bulk_load
```

The fetch verifies the pinned sha256 before extracting. The medium benches
panic with this instruction if the dump is missing or stale. Signing the
asset (cosign) is not done yet.
