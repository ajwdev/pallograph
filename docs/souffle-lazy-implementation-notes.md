# Lazy (Soufflé-style) provenance for the DD backend — implementation notes

Status: MVP prototype, working. Branch `dd-provenance-souffle`.

This documents the first working slice of *lazy* Soufflé-style provenance for the
DD backend, built as an alternative to the *eager* `ProofEdge` strategy so the
two can be compared. Eager lives on the `dd-provenance` branch; this branch
carries lazy only. It follows `souffle-lazy-provenance-design.md` and
`souffle-lazy-feasibility.md`.

## What was built

Per-derived-fact annotations `(rule_id, min_height)` computed *inside* the
recursive fixpoint, plus on-demand backward-chaining at query time.

1. **Rule identity** (`src/dd/lower.rs`, `src/dd/mod.rs`). Added
   `LoweredRule::rule_id: u32`, sourced in `build_strata` from the rule's
   `InstId::index()` (stable, globally unique across strata). `lower_op` gained a
   `rule_id` parameter.

2. **Annotation type** (`src/dd/value.rs`). Added `Annotated { fact, rule_id,
   height }` and `SENTINEL_EDB = u32::MAX`, mirroring `ProofEdge`'s derive set.
   In practice the dataflow carries the lighter side-collection element
   `(Row, (u32 rule_id, u32 height))` (aliased `Annotation = (u32, u32)` in
   `build.rs`); `Row` is never widened.

3. **Per-tuple annotation in the fixpoint** (`src/dd/build.rs`,
   `src/dd/session.rs`).
   - `build_rule` now takes `mode: ProvenanceMode` and a sibling `annotations` map, and
     returns a third optional collection: one candidate annotation per grounding,
     `(head_row, (rule_id, 1 + max(premise heights)))`. Premise heights are
     looked up by chaining a join per positive premise atom against that
     premise relation's annotation collection (keyed by the premise tuple),
     threading a running `max`.
   - `min_reduce_annotations` collapses candidates to one annotation per fact via
     a `reduce` picking the lexicographically-minimal `(height, rule_id)` — the
     DD realisation of the lattice join `min_g`.
   - In a recursive stratum the annotation lives in a **second coupled
     `VecVariable`** per head predicate, seeded empty (IDB heads have no EDB
     seed), fed `carried.concat(candidates)` then `min_reduce`d, `.set(...)` and
     `.leave()`d — a *side* collection keyed by `Row`. The existing fact
     `VecVariable` + `distinct()` termination driver is untouched.

4. **Lazy reconstruction commands** (`src/dd/session.rs`).
   - Annotation collections are arranged into `AnnotationTrace` traces, compacted in
     lockstep with the row traces on every `Commit`.
   - `Command::WhyHeight { rel, fact }` → `Option<(rule_id, height)>` (the design
     doc's `GetAnnotation`). Point lookup over the annotation trace.
   - `Command::WhyStep { rule_id, head, max_height }` → `Option<Grounding>` (the
     design doc's `Subproof`). Looks the rule up by id in a worker-resident
     `rules_by_id`, materialises the live premise rows + a `fact→Annotation` map, and
     calls `reconstruct_grounding`, which replays the rule's Scan/Join/Cmp steps
     as an in-memory nested-loop join, keeps wide rows whose head projection
     equals `head`, and returns the **first** grounding whose every positive
     premise has stored height strictly `< max_height`. All cursoring is on the
     worker thread (TraceAgent is `!Send`).
   - Public methods `DdSession::why_height` / `why_step`.

5. **Mode gating and `::why`** (`src/dd/mod.rs`, `src/engine.rs`,
   `src/repl.rs`). `ProvenanceMode { Off, Lazy }`; `spawn_mode(edb, rules, ProvenanceMode)`
   selects it. `--backend dd --provenance` makes `DdBackend` hand `Engine` a
   live `Lazy` session, and `::why` renders one shortest proof by recursing
   `why_height`/`why_step` against it (`print_why_lazy`). Adding a rule to a
   lazy session always rebuilds, since the layering path builds no annotations.

## What works (passing test)

`src/dd/session.rs::tests::lazy_provenance_transitive_closure` — the canonical
`path`/`edge` transitive-closure fixture (edges a→b, b→c; base rule
`path(X,Y):-edge(X,Y)` and recursive `path(X,Z):-edge(X,Y),path(Y,Z)`).

It reconstructs the proof of the transitively-derived `path(a,c)` purely through
the lazy commands and asserts:
- `path(a,c)` has minimal height **2**.
- its one-step grounding has two premises, `edge(a,b)` (EDB, height 0) and
  `path(b,c)` (height 1), **both strictly below 2**.
- descending into `path(b,c)` yields `edge(b,c)` (EDB, height 0), strictly below
  1, carrying `SENTINEL_EDB` — i.e. it bottoms out at an EDB leaf.

All 56 `cargo test --lib` tests pass (55 pre-existing + this one); `cargo build`
is clean.

## Did the min-height-in-fixpoint converge?

Yes. The heights the test observes (2 for `path(a,c)`, 1 for `path(b,c)`/
`path(a,b)`, 0 for EDB) are exactly the shortest-proof profile, and the session
settled without hanging. This is the load-bearing risk (#1 in the design doc):
DD's `reduce` re-fires on height improvement via differential retractions, and
because the tuple set is finite and heights are integers bounded below by 0, the
annotation variable reaches fixpoint on (or one round behind) the fact variable.
The min-reduce is a pure deterministic function of the input multiset (min
`(height, rule_id)`), so there is no oscillation. On this fixture it converged
cleanly.

## What is stubbed / incomplete (deliberate MVP scope)

- **Body shapes**: every `Step` is covered. Only `Scan`/`Join` add premises;
  `Cmp`/`CallFilter` filter, `Let`/`MatchField`/`IterateList` append columns,
  `Antijoin` surfaces `¬rel(args)` leaves, and `Reduce` is a leaf.
  `reconstruct_grounding` matches `Step` exhaustively and reuses the per-row
  helpers from `build.rs` (`match_field_row`, `iterate_list_row`, `eval_expr`,
  `eval_call_filter`), so build and replay cannot drift apart.
  `engine::tests::dd_provenance_explains_every_shipped_fact` checks that every
  fact the shipped k8s rules derive (1368 on the fixtures) has an annotation
  and a grounding with strictly lower, matching premise heights.
- **Negation / aggregation provenance**: negated atoms are absent-leaves (no
  why-not); aggregates are leaves with no descent into the group.
- **`WhyStep` search cost**: `reconstruct_grounding` materialises the full live
  row set of each premise relation and does an in-memory nested-loop join. This
  is fine for the MVP fixtures but is *not* the `O(log n)` index-probe join the
  design targets (§3.2). A production version would seek the arranged traces.
- **Incremental `::why`**: `::why` runs against the live session, so heights
  follow `+`/`-` fact deltas (`engine::tests::dd_provenance_heights_follow_deltas`:
  a shortcut lowers a height, retracting it restores it, and retracting one
  proof leaves the other). Adding a *rule* rebuilds the session.

## Deviations from the design docs

1. **`Cmp` is on the linear-recursion path.** The docs describe the target as
   "positive Scan/Join only". In reality the mangle planner lowers the recursive
   join `path(X,Z):-edge(X,Y),path(Y,Z)` as `Scan(edge)` + **cross**-`Join(path)`
   (empty join keys) + `Cmp(Eq)` binding `Y`. So `Cmp` had to be admitted to the
   guard and handled in `reconstruct_grounding` (as a pure positive filter, no
   premise, no height). Without this the MVP fixture itself would `bail!`.

2. **Annotation `min` reduce, not the `Annotated` struct, flows through DD.** The
   feasibility doc floated a dedicated `Annotated` struct as the collection
   element. I kept `Annotated` for documentation/seeding clarity but the actual
   dataflow element is the lighter keyed pair `(Row, (u32, u32))`, which composes
   directly with DD's `reduce` (Row = key). Cleaner and avoids an extra map.

3. **`WhyStep` reconstruction is an in-memory replay, not a one-shot dataflow.**
   The design's Approach 1 (§3.3) re-runs the rule as a tiny `worker.dataflow`
   importing traces. I used the simpler "drain the premise traces to `Vec<Row>`
   and replay the lowered steps by hand" approach — the design's noted fallback
   shape, chosen for MVP simplicity. It reuses the pure `eval_cmp`/`slot_val`
   evaluators from `build.rs`.

## Candid comparison to the eager approach

- **Storage**: as advertised, lazy stores exactly one `(rule_id, height)` per
  fact vs eager's one `ProofEdge` per *derivation*. On transitive closure that is
  the whole point — eager materialises every path decomposition.
- **Eval-time code complexity**: lazy is meaningfully *more* code in the hot
  path. Eager adds one `map` at the final `Insert` and a concat/distinct/arrange
  at the end. Lazy adds: a per-premise join chain in `build_rule`, a min-`reduce`
  per head relation, a **second coupled `VecVariable`** in every recursive
  stratum, annotation traces, and lockstep compaction. The coupled-variable
  bookkeeping in the iterative scope is the fiddliest part of the whole change.
- **Query-time complexity**: this is where lazy pays. Eager builds one flat index
  and walks a resident forest. Lazy needs a real backward-chaining engine
  (`reconstruct_grounding`) that must honour every `Step` variant — and getting
  the strict-`<`-height guard and head-projection matching right is exactly where
  bugs live. The MVP only covers Scan/Join/Cmp; a full implementation is
  substantial.
- **What surprised me**: (a) the planner's cross-join+`Cmp` lowering of a
  "linear" recursive rule — "positive Scan/Join only" is not actually reachable
  for the fixture the task names. (b) How *cleanly* DD's `reduce` gives the
  Soufflé "re-fire on height improvement" semantics for free — no hand-coded
  `ΔR` union was needed, matching the design's central bet. (c) The coupled
  annotation `VecVariable` "just worked" once seeded empty and fed the
  concat+min-reduce; convergence was not the hard part — the query-side
  reconstruction was.

Headline: lazy delivers the promised storage win and the fixpoint convergence
held, but it trades eager's trivial query path for a genuine backward-chaining
engine. For an interactive REPL on small programs, eager's simplicity is hard to
beat; lazy earns its keep only at scale, where the eager edge set explodes.
