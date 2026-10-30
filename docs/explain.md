# Reading a query plan with `explain`

`explain` shows how the engine will run a `?-` query: the physical operator
tree the planner builds, and a cost estimate for it. Use it when a query is
slow and you want to see why before changing it.

It plans the query but never runs it, so it is cheap and safe to try on
anything.

## Usage

`explain <body>` takes the same body as `?-`, projection included:

```
pallograph> explain host_network_pod(Ns, N), k8s(_, "Pod", Ns, N, R)
pallograph> explain _(R) :- host_network_pod(Ns, N), k8s(_, "Pod", Ns, N, R)
```

There is also a CLI flag, `--explain`, that dumps the plan for every rule in
the program and exits. It compiles only, so it has no facts loaded and prints
no cost estimate. The REPL `explain` command does have facts (the live state,
or a `use`d snapshot), so it adds the cost section.

The rest of this doc walks through one example:

```
pallograph> ::explain k8s(_, "Pod", Ns, N, R), host_network_pod(Ns, N)
● Stratum 139 (`__query`)
  ->  Iterate on k8s
        IndexLookup [_, $scan_0, Ns, N, R]
        Key on "Pod"
        ->  Filter
              Compare: $scan_0 = "Pod"
              ->  Iterate on host_network_pod
                    IndexLookup [$scan_1, $scan_2]
                    Key on Ns
                    ->  Filter
                          Compare: $scan_1 = Ns
                          ->  Filter
                                Compare: $scan_2 = N
                                ->  Insert `__query` [Ns, N, R]
  Cost (rows visited per probe, multiplied down the join):
    k8s (lookup col 1 = "Pod": 707/1456 match)                  707 rows
    host_network_pod (lookup col 0 = Ns: ~72/key over 4 keys)  ~72 rows
    => 707 x ~72 = ~50904 row visits (estimate; ~ is an averaged per-key fan-out)
```

---

## 1. The operator tree

A `?-` query is compiled into a throwaway rule named `__query`, whose body is
your query and whose head holds the variables you asked for. `explain` plans
that rule and prints its physical operator tree.

### 1.1 Strata

```
● Stratum 139 (`__query`)
```

Rules are grouped into **strata** (evaluation layers): a rule that reads a
relation runs in a later stratum than the rules that fill it. The number is an
internal id; all that matters here is that your `__query` rule gets its own
stratum at the top, because everything it reads (`k8s`, `host_network_pod`) was
computed earlier. `--explain` prints every stratum; the REPL `explain` prints
only the one holding `__query`.

### 1.2 Operators

The tree is read top to bottom, outermost to innermost. Each `->` is one step
feeding the next. The operators you will see:

- **`Iterate on <rel>`** - loop over rows of a relation. Its data source is one
  of:
  - **`Scan [vars]`** - read every row, binding the columns to `vars`.
  - **`IndexLookup [vars]` + `Key on <value>`** - read only the rows whose
    indexed column equals `<value>`. Far cheaper than a scan when the key is
    selective.
  - **`DeltaScan`** - read only the rows that changed since the last iteration
    (incremental evaluation); appears under `↻ Recursive` for recursive rules.
- **`Filter` + `Compare: a = b`** - keep only rows satisfying the condition.
  Also appears as `Negation` (`!rel(...)`) and `Call` (a built-in predicate).
- **`MatchField <struct> #> /field as Var`** - pull a field out of a struct
  value (how rules read into a Kubernetes object's nested spec).
- **`IterateList <list> #> Var`** - loop over the elements of a list field.
- **`Insert \`rel\` [args]`** - the leaf: emit a row into the result relation.

Names like `$scan_0` are internal temporaries the planner introduces for a
column it binds then constrains with a later `Filter`.

### 1.3 Nesting is a join

Nested `Iterate` operators are a **nested-loop join**: for each row from the
outer loop, run the inner loop. In the example:

- Outer: `Iterate on k8s`, keyed on `"Pod"` - loop over every Pod.
- Inner: for each Pod, `Iterate on host_network_pod`, keyed on `Ns` (the
  namespace taken from the current Pod row).

So the work is roughly *outer rows x inner rows per probe*, which is what the
cost section quantifies.

---

## 2. The planner indexes on one column

The upstream planner indexes each body atom on its **first bound argument**
(variable or constant) only, and checks the other columns afterward with a
`Filter`. This is the single most important thing to understand from a plan,
because it decides whether a lookup is selective or close to a scan.

Look at the two lookups in the example:

- `k8s(_, "Pod", Ns, N, R)`: the first column is `_` (unbound), so the first
  *bound* argument is the constant `"Pod"` in column 1 (`Kind`). The index keys
  on `Kind`, which is low-cardinality: `Key on "Pod"` matches every Pod in the
  cluster. The later `Filter`s on `Ns` and `N` then throw most of them away.
- `host_network_pod(Ns, N)`: `Ns` is already bound (from the outer Pod), so the
  index keys on column 0 (`Ns`, the namespace). More selective than `Kind`, but
  still only one column; `N` is applied as a `Filter`.

The lever you control is **which column is bound first**, through atom order
and how you write each atom. Put the selective column first. See `AGENTS.md`
("Write rules with the planner's lookups in mind") for the same guidance
applied to the shipped rules.

---

## 3. The cost estimate

```
  Cost (rows visited per probe, multiplied down the join):
    k8s (lookup col 1 = "Pod": 707/1456 match)                  707 rows
    host_network_pod (lookup col 0 = Ns: ~72/key over 4 keys)  ~72 rows
    => 707 x ~72 = ~50904 row visits (estimate; ~ is an averaged per-key fan-out)
```

One line per nested `Iterate`, in join order, giving the rows each **probe**
visits. The engine reads the counts from the active state (the live cluster, or
a `use`d snapshot), so they are your real data.

### 3.1 How each line is counted

- **Scan**: the full row count of the relation.
- **Constant index key** (`lookup col 1 = "Pod": 707/1456 match`): the **exact**
  number of rows whose indexed column equals the constant. Here 707 of 1456
  objects have `Kind = "Pod"`. Counted directly from the store, so no `~`.
- **Variable index key** (`lookup col 0 = Ns: ~72/key over 4 keys`): the key is
  bound per outer row, so there is no single match count. Instead it reports the
  average fan-out: the relation's rows divided by the number of distinct values
  in the key column. Here `host_network_pod` has 4 distinct namespaces, ~72 rows
  each (so ~288 rows total). When a probe supplies one namespace, it gets back
  **~72 rows on average**.

### 3.2 What "~72 per key" means

Each time the inner loop probes `host_network_pod` with a specific namespace, it
gets back the host-network pods in that namespace. On average that is ~72 rows,
because the ~288 rows are spread over 4 namespaces. It is an **average** because
the real number depends on *which* namespace the outer Pod is in: one namespace
might hold 200 host-network pods, another just 1. The cost model does not run
the join, so it cannot know the real per-probe result and assumes an even
spread.

### 3.3 Exact vs estimate

The `~` marks a figure that is an averaged fan-out rather than a measured count,
and it propagates:

- on the step (`~72 rows`),
- into the product term (`707 x ~72`),
- onto the total, which ends in `(estimate; ...)`.

If every line is a scan or a constant-key lookup, the total is exact and ends in
`(exact)` instead. So you can always tell at a glance whether to trust the
number or treat it as order-of-magnitude.

### 3.4 The total

707 outer probes x ~72 rows each is ~50,904 row visits: the estimated work to
produce this join. It is dominated by iterating every Pod (707) and the ~72
fan-out per namespace. A lower number is a cheaper query.

---

## 4. Using it to make a query faster

The example is a nested loop over every Pod, with the `k8s` atom keyed on the
unselective `Kind = "Pod"`. Two things help:

1. **Query a narrower relation.** `pod(Namespace, Name, Data)` (from `base.mg`)
   holds only Pods and leads with `Namespace`, so a lookup keys on the namespace
   instead of scanning all objects by `Kind`:

   ```
   pallograph> explain _(R) :- host_network_pod(Ns, N), pod(Ns, N, R)
   ```

2. **Order atoms so the smaller relation leads and the inner key is selective.**
   `host_network_pod` is far smaller than "all Pods," so leading with it makes a
   smaller outer loop.

Compare the `=>` totals of the variants to see which the planner makes cheaper.

---

## 5. Limits

- The cost is a **nested-loop estimate**. It assumes the plan is the nested
  loops shown and multiplies per-probe fan-out down the spine. It does not model
  the cost of `Filter`, `MatchField`, or `IterateList` (list fan-out), nor the
  DD backend's incremental sharing.
- Variable-key fan-out is an **average**; skewed data makes the real cost higher
  or lower. Constant-key and scan counts are exact.
- The counts come from whatever state is active. Under `use <snapshot>`, they
  reflect that snapshot. The `--explain` CLI flag has no facts loaded, so it
  omits the cost section.
- The plan reflects the planner's choices for *how you wrote the query*. Change
  the atom order or which columns are bound, and both the tree and the cost can
  change.
