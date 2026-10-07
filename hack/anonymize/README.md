# anonymize

Rewrites a `kubectl get -o json` dump so it can be benchmarked or shared
without leaking real names. Every reference is preserved, and so is every string length except public IP addresses (see below),
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

### IP addresses and hostnames

IPv4 and IPv6 literals and `ip-A-B-C-D` / `ec2-A-B-C-D` hostnames are
rewritten before tokenizing, since their octets would otherwise pass as
quantities. The mapping is consistent and injective, and a node name stays
in step with its IP.

- Private ranges (10/8, 172.16/12, 192.168/16, 100.64/10) map into the same
  range and keep their string length.
- Public IPv4 maps into reserved, never-routed space: RFC 2544
  198.18.0.0/15 plus the three RFC 5737 TEST-NET /24s (131,840 addresses,
  `POOL` in `src/bin/anonymize.rs`). Length is not preserved.
- IPv6 maps into 2001:db8::/32 (RFC 3849). Length is not preserved.
- Unspecified, loopback, link-local and multicast/reserved addresses
  (including netmasks) are kept as they are.
- The run aborts before writing anything if the input has more distinct
  public IPv4 addresses than `POOL` can hand out.
- `--check` fails if any other address survives in the output.

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
release asset. Publishing is two steps so the pinned hash is the hash of
exactly the bytes that get uploaded. After `--check` passes and you have
read the `--report` output:

```
hack/publish-fixtures.sh pack anon dist/medium-v2     # builds the archive, writes the pin
git commit fixtures/testdata/medium.env               # review and merge
hack/publish-fixtures.sh upload dist/medium-v2 <merge-sha>
```

`pack` builds `medium.tar.zst` and its `.sha256` in the output directory and
writes the sha256 into `fixtures/testdata/medium.env`. Keep that directory:
the anonymizer's default seed is random, so a rebuilt archive will not match
the pin. To publish a new version, set `TAG` in `medium.env` first. `upload`
refuses to run unless the archive still matches the pin, then creates the
release for `TAG` (marked not-latest) at the given commit.

Everyone else gets the dump with:

```
hack/fetch-fixtures.sh medium
cargo bench --bench medium_bulk_load
```

The fetch verifies the pinned sha256 before extracting. The medium benches
panic with this instruction if the dump is missing or stale. Signing the
asset (cosign) is not done yet.
