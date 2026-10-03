# Lazy provenance for the DD backend

How `::why` works on the differential-dataflow (DD) backend: what is stored
during evaluation, how a proof is rebuilt on demand, and where the limits are.

The technique comes from the Soufflé Datalog engine:

- Zhao, Subotić & Scholz, "Debugging Large-scale Datalog: A Scalable Provenance
  Evaluation Strategy," TOPLAS 42(2), 2020.
  <https://souffle-lang.github.io/pdf/toplas20.pdf>,
  ACM: <https://dl.acm.org/doi/10.1145/3379446>
- Preprint with the same content, easier to cite by section: "Provenance for
  Large-scale Datalog," arXiv:1907.05045. <https://arxiv.org/abs/1907.05045>
- Soufflé docs: <https://souffle-lang.github.io/provenance>

Section citations below are to the arXiv preprint.

## Usage

```
pallograph --backend dd --provenance
> ::why escalation_hop(X, Y)
```

`--provenance` is off by default because it adds operators to every rule. The
interpreter backend always has provenance and ignores the flag.

---

## 1. The algorithm

### 1.1 Two numbers per fact

Every derived fact carries exactly two extra numbers (arXiv §4):

1. **Rule id** `k`: the rule that produced the fact's shortest derivation.
2. **Height** `h(t)`: the depth of the fact's shortest proof tree. EDB facts
   have height 0; each rule application adds one level above the tallest of
   its premises.

That pair is the entire stored provenance: no derivation edges, no proof
forest. The alternative, *eager* provenance, stores every one-step derivation
of every fact, which grows with the number of ways a fact can be derived. An
eager implementation lives on the `dd-provenance` branch for reference.

### 1.2 The height equation

For a fact `t`:

```
h(t) = min over every grounding g that derives t of
         ( 1 + max over the positive premises tᵢ of g of h(tᵢ) )
```

Within one derivation, take the deepest premise and add 1. Across all the
ways to derive `t`, keep the shallowest. This minimises proof *depth*, not
proof *size*: a min-plus formulation would add premise costs instead and could
pick a different proof.

Soufflé frames this as a provenance lattice (arXiv §4.1): moving "up" means
more facts and/or smaller heights, and evaluation reaches the point where
every fact has its true minimum height. Heights are non-negative integers that
only ever decrease, so this converges.

### 1.3 Semi-naïve evaluation

Plain semi-naïve evaluation only re-fires rules for *new* facts. The
provenance version also re-fires a fact when a lower-height derivation is
found for it (arXiv §4.2), so improvements propagate to everything built on
top of it. arXiv §4.3 shows this computes the same fact set as normal
evaluation, terminates, and ends with minimal heights.

### 1.4 Rebuilding a proof (backward chaining)

Nothing about a proof is stored beyond the two numbers. At `::why` time, given
a fact `t` with annotation `(k, h)`, find **one** grounding of rule `k` whose
head matches `t` and whose positive premises all have height **strictly less
than** `h` (arXiv §5, "subproof"). Then recurse into each premise, until every
branch reaches an EDB fact (height 0).

- **Termination:** each step down strictly decreases the height, and heights
  are non-negative integers, so every branch ends within `h` steps. This holds
  even for recursive rules. The strict `<` is the whole trick: it rules out a
  "proof" of `t` that cycles back through `t` itself, which is what makes naive
  backward chaining loop.
- **Minimality:** because `h(t)` is the minimum over all derivations, a
  grounding with every premise below `h(t)` is guaranteed to exist, and the
  tree it starts has height exactly `h(t)` (arXiv §5.1, Theorem 1).

The result is **one shortest proof**, not every derivation. For RBAC
escalation, `::why` shows one way principal A reaches B, not every path.

### 1.5 What it cannot explain

- **Why a fact is absent.** Heights only describe facts that exist. Soufflé
  offers a separate, interactive `explainnegation` (arXiv §6); pallograph does
  not implement it. Negated body atoms appear in proofs as satisfied
  conditions (`!blocked("d") (absent)`), but `::why` does not explain why the
  negated fact is absent.
- **Inside an aggregate.** An aggregate result (`fn:count`, `fn:sum`, ...) is
  a leaf with no premises, matching the interpreter.

---

## 2. Computing annotations in differential dataflow

### 2.1 A side collection per relation

`Row` is never widened: adding columns would change what joins, `distinct`,
and the `Val` ordering/hash contract see. Instead every relation gets a second
collection of `(Row, Annotation)` pairs, where `Annotation = (rule_id, height)`
(`src/dd/build.rs`). The plain relation drives evaluation exactly as it does
with provenance off; the annotation collection is computed alongside it.

EDB relations are seeded with `(SENTINEL_EDB, 0)` for every fact.

`rule_id` comes from the rule's `InstId` in the compiled IR (`build_strata` in
`src/dd/mod.rs`), which is stable and unique across strata.

### 2.2 One candidate per grounding

In `build_rule`, at the rule's final `Insert`, the pre-projection row still
holds every body variable, and each `PremiseAtom` records which columns hold
its arguments (`src/dd/lower.rs`). For each grounding:

1. Join the row against each positive premise relation's annotation
   collection, keyed by that premise's tuple, threading a running `max` of the
   premise heights. One join per premise, chained.
2. Emit `(head_row, (rule_id, max + 1))` as a candidate annotation.

A rule with no positive premises (a unit rule, or an aggregate) gets height 1.

Every other step is height-neutral, which is why the whole step set is
covered: `Cmp` and `CallFilter` only filter rows; `Let`, `MatchField` and
`IterateList` only append columns (so premise column indexes stay valid);
`Antijoin` atoms are not premises; `Reduce` makes the result a leaf. `Cmp` is
common, not a rarity: the mangle planner lowers
`path(X, Z) :- edge(X, Y), path(Y, Z)` as `Scan(edge)`, a `Join(path)` keyed
on `Y`, then a redundant `Cmp(Eq)` re-checking `Y`.

### 2.3 Keeping the minimum

`min_reduce_annotations` concatenates every rule's candidates for a head
relation and `reduce`s to one annotation per fact: the smallest
`(height, rule_id)`. Comparing the pair, rather than height alone, makes ties
deterministic (smallest rule id wins), so `::why` output is stable across
runs. The output always has multiplicity 1, so it is a proper set.

This `reduce` is the `min` in the height equation (§1.2); the `1 + max` happens
per candidate (§2.2).

### 2.4 Inside the recursive fixpoint

In a recursive stratum, each head predicate gets a second `VecVariable` for its
annotations, next to the one for its facts. Each round: build candidates from
the current premise annotations, concat them with the carried annotations,
min-reduce, and `set` the variable.

The fact variable's `distinct()` still decides when the stratum is done. The
annotation variable rides along and keeps changing only while heights
improve.

**Why it converges.** When a shorter derivation turns up in a later round,
`reduce` retracts the old `(row, (k, h_old))` and asserts `(row, (k', h_new))`.
That retraction is a real change, so the iterative scope keeps running until
heights stop improving. This is the "re-fire on height improvement" rule from
§1.3, and DD provides it through `reduce`'s differential updates rather than a
hand-written delta. It terminates because the fact set is finite and each
height is an integer that only decreases, bounded below by 0. The reduce output
is a pure function of its input (min of `(height, rule_id)`), so it cannot
oscillate.

**Negation across strata.** Negated relations always belong to a lower,
already finished stratum (stratification guarantees this), so their facts and
heights are final before a rule that negates them runs. No height cycle can
pass through a negation.

### 2.5 Pitfalls this design avoids

- **Height is a `min`, not a set union.** Keeping every `(row, height)` pair,
  for example by applying `distinct` to the annotation pairs, would keep
  several heights per fact alive and break minimality.
- **`1 + max` at evaluation, strict `<` at reconstruction.** Don't mix them up.
- **EDB facts need height 0 and the sentinel rule id.** A rule whose body is
  all EDB then gets height 1.
- **Deterministic tie-breaks** (see §2.3).

### 2.6 Evaluation cost

Measured 2026-10-07 on the shipped k8s rules and fixtures (171 EDB facts),
release build, median of 30 session spawns: **13.7 ms without provenance,
30.5 ms with it, about 2.2x.** Soufflé reports **1.27x** on average (arXiv
abstract), so we pay noticeably more.

The main reason is the side collection (§2.1). In Soufflé the height is a
column of the tuple, so a rule's body join already has every premise's height
in hand and `1 + max` is arithmetic. Here a premise's height lives in a
separate collection, so `build_rule` runs one extra join per positive premise
atom just to look it up (§2.2). On the shipped rules that is more join work
than evaluation itself does:

```
rules=165  head_relations=75  body_joins=60  premise_atoms (extra joins)=215
```

On top of that come one min-reduce per head relation, a second `VecVariable`
per recursive head, and an arranged annotation trace per relation.

A likely extra cost, not yet measured: each lookup joins against a fresh
`.map(...)` of the premise's annotation collection, and `join_map` on an
unarranged collection builds a new arrangement (index) for it. A relation used
as a premise by ten rules then has its annotations indexed ten times.

Caveats: the fixture is tiny, so fixed per-operator cost dominates and the
ratio may differ at cluster scale; and Soufflé's figure is from large
program-analysis benchmarks, not a like-for-like comparison.

---

## 3. Rebuilding proofs at `::why` time

### 3.1 Session API

The session arranges each annotation collection into a trace, compacted in
step with the row traces on every commit so both are read at the same
frontier. Two queries run on the worker thread (traces are `!Send`):

- `why_height(rel, fact) -> Option<(rule_id, height)>`: the fact's annotation.
  The paper calls this `GetAnnotation`.
- `why_step(rule_id, head, max_height) -> Option<Grounding>`: one grounding of
  the rule whose head matches and whose positive premises are all below
  `max_height`. Each `Premise` carries its own annotation so the caller can
  recurse. `Grounding::negated` lists the negated atoms that held, rendered as
  absent leaves. The paper calls this `Subproof`.

### 3.2 How `why_step` finds a grounding

`reconstruct_grounding` (`src/dd/session.rs`) replays the rule's steps in
memory over the live rows of each relation the rule reads, then keeps the
first wide row whose head projection equals the target and whose premises all
pass the strict-height check.

It handles every `Step` variant, using the same per-row helpers as the
dataflow (`match_field_row`, `iterate_list_row`, `eval_expr`,
`eval_call_filter`, `eval_cmp`, `eval_aggregate` in `src/dd/build.rs`), so
evaluation and replay cannot disagree. The `match` is exhaustive: a new `Step`
variant fails to compile until it has a replay arm.

**Known performance limits.** Correct first, fast later; these are the known
costs:

- Each `why_step` copies every row of the relations the rule reads and
  replays the joins as nested loops, so one join costs |left| x |right|. It
  enumerates every grounding of the rule before checking which one matches the
  head, so the head's bound values never narrow the search. A deep proof (a
  long chain, say) pays this once per level.
- `why_height` scans the whole annotation trace for one fact.

The fixes: filter the first scan on the columns the head binds, hash the
right side of each join (or seek the arranged traces), and seek the annotation
trace by key.

### 3.3 The frontend

`print_why_lazy` (`src/repl.rs`) calls `why_height` once on the fact, then
`why_step`, prints the premises, and recurses using each premise's own
annotation. EDB facts print as leaves. A fact with no annotation prints as a
provenance bug rather than as a base fact. No cycle check is needed, because
heights strictly decrease, but output still stops at `WHY_MAX_DEPTH` (12)
levels, shared with the interpreter's renderer, so a taller proof is cut off
with `... (depth limit)`.

`::why` reads facts from the live session, so it reflects `+`/`-` fact changes
immediately.

**Rules added in the REPL.** Provenance is for the core relations, the rules
loaded at startup. How a rule added later is handled depends on how it was
added:

- `::define` and `::source` rules get provenance. The session rebuilds from
  scratch (the worker shuts down and re-runs every rule over the full EDB),
  because the cheaper layering path builds no annotations and cannot register
  a rule for `why_step`.
- `?-` queries do not. Each query is a temporary rule (`_N(...) :- ...`),
  and it is layered onto the running dataflow without annotations
  (`Engine::add_query_rule`), so queries cost the same with `--provenance` as
  without. `::why` on a query result says it is not tracked.

Any rebuild annotates every rule, so a query rule that happens to be present
when a later rebuild runs does get provenance.

---

## 4. Testing

- `src/dd/session.rs` tests (`lazy_provenance_*`): transitive closure,
  stratified negation, aggregation as a leaf, multiple shortest derivations,
  multi-premise joins, constants in the head, and `CallFilter` in both
  polarities.
- `engine::tests::dd_provenance_explains_every_shipped_fact`: on the shipped
  k8s rules, every derived fact has an annotation and a grounding whose
  premises are real facts with strictly lower, matching heights. Each premise
  is checked as a fact itself, so by induction every full proof tree reaches
  EDB. It also checks that turning provenance on does not change which facts
  are derived.
- `engine::tests::dd_provenance_query_rule_layers_without_provenance`: a `?-`
  query rule is layered, not rebuilt, and core relations stay explainable.
- `engine::tests::dd_provenance_heights_follow_deltas`: heights drop when a
  shortcut fact is added, recover when it is retracted, and switch to the
  other proof when one path is removed.

## 5. Possible next steps

- **Cheaper annotation evaluation** (§2.6), cheapest first:
  1. Measure at realistic scale (e.g. a synthetic cluster 100x the fixture)
     to see whether the 2.2x holds.
  2. Arrange each relation's annotations once (`arrange_by_key`) and reuse
     that arrangement in every lookup join.
  3. Carry heights through the body joins as Soufflé does: with provenance on,
     evaluate rules over `(Row, height)` pairs, removing the per-premise
     lookup joins. A real restructuring of `build_rule`; the fact-set
     `distinct` must ignore the height.
- **Index-probe reconstruction** (§3.2), if `::why` gets slow on real clusters.
- **Layered rule addition with provenance** (§3.3), so `::define` and
  `::source` stop rebuilding the session: import the annotation traces into the
  new layer, build annotations for its rules, and register them for
  `why_step`.
- **All paths.** For escalation auditing you may want every route from A to
  B, not just the shortest. The same replay machinery without the height
  guard, plus explicit cycle detection, would enumerate them on demand.
- **Depth-limited output.** Soufflé can stop at a depth and hand back a
  resumable `subproof` handle. Each proof node is self-describing, so this
  would be cheap to add.
- **Explaining absence** (`explainnegation`, §1.5).
