# Lazy (Soufflé-style) provenance for the DD backend — design spec

Status: design only. No `src/` changes here.

This spec designs a *lazy* provenance strategy for the differential-dataflow
(DD) backend, modeled on Soufflé's approach, as an alternative to the *eager*
`ProofEdge` strategy already shipped. The eager strategy materializes every
one-step derivation of every fact (see `src/dd/value.rs::ProofEdge`,
`src/dd/build.rs::build_rule`, `src/dd/session.rs::snapshot_provenance`), which
costs roughly 1.4x eval time and materializes ~1.43x more tuples than facts.
The lazy strategy instead stores two tiny scalar annotations per derived fact
and reconstructs proof trees on demand at `::why` time.

References (read these):

- Zhao, Subotić & Scholz, "Debugging Large-scale Datalog: A Scalable Provenance
  Evaluation Strategy," TOPLAS 42(2), 2020. <https://souffle-lang.github.io/pdf/toplas20.pdf>
  ACM: <https://dl.acm.org/doi/10.1145/3379446>
- Preprint (same content, easier to cite by section):
  "Provenance for Large-scale Datalog," arXiv:1907.05045.
  <https://arxiv.org/html/1907.05045> / <https://arxiv.org/pdf/1907.05045>
- Soufflé docs: <https://souffle-lang.github.io/provenance>

Section citations below are to the arXiv preprint unless noted.

---

## 1. The Soufflé algorithm, precisely

### 1.1 Two annotations per IDB tuple

Soufflé augments every derived (IDB) tuple with exactly two extra scalar
columns (arXiv §4; docs "Provenance"):

1. **Rule number** `k` — the *static* identifier of the rule that produced the
   minimal-height derivation. Rules are numbered at compile time.
2. **Minimal proof-tree height** `h(t)` — the height of the *shortest* proof
   tree deriving `t`. Leaves (EDB facts) have height 0; each rule application
   adds one level above the tallest of its body subproofs.

Concretely, a tuple `path(1,3)` derived by rule 2 with a minimal proof tree of
height 4 is stored internally as `path(1, 3, 2, 4)` (docs "Provenance"). The
two annotations are appended columns; they do not change the logical relation.

These two numbers are the *entire* stored provenance. There is no edge set, no
proof forest — just `(rule_id, min_height)` per fact.

### 1.2 The provenance lattice and fixpoint semantics

Soufflé replaces Datalog's plain subset lattice with a **provenance lattice**
(arXiv §4.1). A provenance instance is a pair `(I, h)` where `I` is a set of
tuples and `h : I → ℕ` maps each tuple to its current best (smallest known)
minimal height. The order is:

```
(I₁, h₁) ⊑ (I₂, h₂)   iff   I₁ ⊆ I₂   and   ∀ t ∈ I₁. h₁(t) ≥ h₂(t)
```

Read: going "up" the lattice means *more tuples* and/or *smaller heights*. The
top-most element for a fixed tuple set assigns each tuple its true minimum
height. This is a join-semilattice where the binary join on heights is `min`
(for a tuple present in both operands) together with set union on tuples.

The **height update equation** for a freshly generated tuple `t` is (arXiv §4.1):

```
h'(t) = min over all rule-body groundings g deriving t of
          ( 1 + max over body atoms tᵢ in g of h(tᵢ) )
```

That is: within one grounding, height is `1 + max(body heights)` (a max-plus
step); across the many groundings/rules that can derive `t`, take the `min`.
Both the outer `min` and the "smaller height wins" order direction are what make
`h` a *least* fixpoint of the height functional while `I` is the *greatest*
(usual) fixpoint of the tuple set. Heights are bounded below by 0, so the height
descent converges.

### 1.3 Semi-naïve modification

Standard semi-naïve tracks all tuples `Rⁱ` and new tuples `ΔRⁱ`. The
provenance variant (arXiv §4.2) additionally re-fires a tuple when a
*smaller-height* derivation is discovered, even though the tuple already exists:

```
ΔR₀^(i+1) = ( new₀^(i+1) − R₀^i )                       // genuinely new tuples
            ∪ { t ∈ R₀^i | hⁱ(t) > h^(i+1)(t) }          // height improved
```

The rule transformation appends the annotation columns to head and body atoms:

```
R(X) :- R₁(X₁), …, Rₙ(Xₙ), ψ.
    ⟹
R(X, k, max(@h₁, …, @hₙ) + 1) :- R₁(X₁, _, @h₁), …, Rₙ(Xₙ, _, @hₙ), ψ.
```

where `k` is the constant rule id and `@hᵢ` binds the height column of body atom
`i`. Convergence: Theorem 1 / Lemma 2 (arXiv §4.3) show the provenance
consequence operator `𝒯_P` computes exactly the same tuple set as the standard
operator `Γ_P`, terminates, and yields *monotonically minimal* height
annotations at fixpoint (each tuple's height only ever decreases, and stops at
the true minimum). Worst-case a tuple's height is updated at most `max_h` times
(bound `O(n · max_h)`), but real programs rarely approach this.

### 1.4 Lazy proof-tree reconstruction (backward chaining)

At `::why` time, nothing is precomputed. Given a tuple `t` with its stored
`(k, h(t))`, Soufflé issues a **one-step subproof query** (arXiv §5,
"SUBPROOF") to find a single grounding of rule `k` whose positive body atoms all
have *strictly smaller* height than `t`:

```
? :- R₁(X₁), …, Rₙ(Xₙ), ψ(X₁,…,Xₙ),
     matches(t, X₁,…,Xₙ),          // head of rule k unifies with t
     h(R₁(X₁)) < h(t), …, h(Rₙ(Xₙ)) < h(t).
```

`matches` binds the head variables of rule `k` to `t`'s ground values; the
`h(Rᵢ) < h(t)` guards restrict each premise to a strictly-lower-height fact.
The query returns the *first* satisfying grounding (any minimal-height
grounding is as good as another for producing a minimal tree). Then recurse:
each premise `tᵢ` carries its own `(kᵢ, h(tᵢ))`, and we subproof-query it the
same way, until we bottom out at EDB facts (height 0, no rule).

**Why this terminates and is minimal** (arXiv §5.1, Theorem 1):

- *Termination*: every recursive descent strictly decreases `h`. Heights are
  non-negative integers, so any path bottoms out in at most `h(t)` steps — even
  when the rule is recursive (e.g. transitive closure). The strict `<` guard is
  the whole trick: it forbids a proof of `t` that cycles back through another
  copy of `t` (same or larger height), which is exactly the non-termination
  hazard naive backward chaining has.
- *Minimality*: because `h(t)` was computed as the min over groundings, a
  grounding with all premises `< h(t)` is guaranteed to exist (Theorem 1 part
  2), and the tree it induces has height exactly `h(t)` — the smallest possible.

### 1.5 Negation

Proof annotations describe existing tuples only. For "why does tuple `t` *not*
exist," heights are useless (arXiv §6). Soufflé provides a *semi-automated*
`explainnegation`: the user picks a candidate rule with a matching head and
instantiates the unbound variables; the system reports which body atoms hold
and which fail (absent tuple or violated constraint), guiding an interactive
descent into the failing sub-goals. This spec treats non-existence explanation
as out of scope for the first cut (see §5).

---

## 2. Adapting the annotation computation to differential dataflow

The core question: compute `(rule_id, min_height)` per head tuple *inside* a DD
iterative scope, where body heights come from the same relations being computed
in the same fixpoint.

### 2.1 What flows through the collections

Today the DD element type is `Row` (`src/dd/value.rs`). For lazy provenance we
compute a parallel annotated collection per relation whose element type is:

```
AnnRow { row: Row, rule_id: u32, height: u32 }
```

Do **not** widen `Row` itself (that would corrupt joins, `distinct`, and the
`Val` Ord/Hash parity contract in `value.rs`). Keep two collections per
relation:

- the plain `Collection<Row>` used for evaluation (joins, antijoins, reduce) —
  unchanged; and
- an `annotations: Collection<(Row, (u32 /*rule_id*/, u32 /*height*/))>`
  keyed by the row, holding one entry per row = its minimal annotation.

The plain relation drives the fixpoint exactly as now. The annotation
collection is a *derived observation* keyed on the same rows.

### 2.2 Per-rule candidate heights

Each lowered rule already carries `premise_atoms: Vec<PremiseAtom>` (positive
body atoms, `src/dd/lower.rs`). In `build_rule`, when provenance is enabled,
after the final `Insert` we have the wide pre-projection row, so each premise's
tuple is addressable by `arg_cols` — this is exactly the machinery the eager
path uses to build `ProofEdge` (`build.rs:467-481`). Instead of emitting the
full edge, we:

1. Join the wide row against the **annotation collection of each positive
   premise relation** to look up `@hᵢ = height(premise_i_tuple)`. This is an
   equijoin keyed on the premise tuple. There are `|premise_atoms|` such joins,
   chained (same shape as the existing body joins).
2. Compute the candidate `cand_height = 1 + max(@h₁, …, @hₙ)` (0 body atoms —
   unit/EDB-seeded rules — give `cand_height = 0`... see §2.6).
3. Emit `(head_row, (rule_id, cand_height))` as this rule's contribution to the
   head relation's candidate-annotation collection.

`rule_id` is a compile-time constant assigned per `LoweredRule` (add a
`rule_id: u32` field during lowering; deterministic ordering already exists via
stratum/rule iteration order).

### 2.3 The min-height reduce

Concatenate every rule's candidate-annotation collection for a given head
relation, then collapse to one annotation per row with a `reduce`:

```
candidates: Collection<(Row, (u32 rule_id, u32 height))>
annotation = candidates
    .reduce(|_row, input, output| {
        // input: &[((rule_id, height), diff)]
        // pick the entry with the smallest height; tie-break on smallest rule_id
        let best = input.iter().map(|((rid,h),_)| (*h,*rid)).min().unwrap();
        output.push(((best.1 /*rule_id*/, best.0 /*height*/), 1));
    });
```

`min` over `(height, rule_id)` implements the lattice join (§1.2): smallest
height wins, deterministic tie-break by rule id. Output multiplicity is always
1, so the annotation collection is automatically a proper set (one annotation
per row). This `reduce` is the DD realization of the height update equation
`h'(t) = min_g (1 + max_i h(tᵢ))`: the `1 + max` happens per-candidate in
§2.2, the `min_g` happens here.

### 2.4 Placing it inside the fixpoint

For a **recursive stratum**, the annotation collection must live in the same
`scope.iterative` block as the plain relation, as a second `VecVariable`
(`session.rs:344-367` shows the plain-relation pattern):

- Seed: EDB rows enter with annotation `(rule_id = SENTINEL_EDB, height = 0)`.
- Each iteration: build candidate annotations from this iteration's premise
  annotations (§2.2), concat with the carried annotation variable, `reduce` to
  min-height (§2.3), and `.set(...)` the annotation variable.
- Because heights only *decrease* toward their minimum and the reduce keeps the
  min, the annotation variable is monotone under the provenance lattice order
  (§1.2) and converges on the same schedule as (or one round behind) the plain
  relation.

**Key subtlety — does the annotation fixpoint converge on DD's `distinct`
schedule?** DD's `iterate`/`VecVariable` drives to a fixpoint of the
*collection contents*. The plain relation converges when no new rows appear
(`distinct` idempotent). The annotation collection changes shape not just when
rows appear but when a *height improves*: `reduce` will retract the old
`(row, (k, h_old))` and assert `(row, (k', h_new))` when a shorter derivation is
found in a later round. That retraction+assertion is a genuine collection
change, so the iterative scope keeps running until heights stabilize — which is
exactly Soufflé's semi-naïve height-improvement rule (§1.3). DD gives us the
"re-fire on height improvement" behavior *for free* via `reduce`'s differential
retractions; we do not need to hand-code the `ΔR` union.

This convergence is guaranteed because (a) the tuple set is finite and reaches
fixpoint, and (b) once the tuple set is fixed, each `min_height` is a
monotonically decreasing integer bounded below by 0, so the `reduce` output
stops changing after finitely many rounds.

### 2.5 Interaction with `reduce`, `distinct`, `VecVariable`, negation

- **`distinct`**: keep applying `distinct` to the *plain* relation as today. Do
  **not** `distinct` the annotation collection across the `(row, annotation)`
  pair — that would keep multiple heights per row alive. Instead the per-row
  `reduce` (§2.3) enforces single-annotation-per-row. (If you ever `distinct` a
  `(row, height)` pair collection you get one row per distinct height, which is
  wrong.)
- **`reduce`**: used twice — the existing aggregate `reduce` (unaffected) and
  the new min-height `reduce`. The min-height reduce sits *outside* the plain
  relation's `distinct` chain; it consumes the plain relation's premise
  annotations.
- **`VecVariable`**: one extra variable per recursive head predicate for its
  annotation collection, `leave`-ing the scope alongside the plain result
  (`session.rs:400-424` shows the leave pattern; annotations are pure
  observations like the current `left_proofs`, but unlike proofs they *do* need
  fixpoint feedback, so they are real variables, not just `.leave()`d
  observations).
- **Stratified negation / aggregation**: negated body atoms (`Step::Antijoin`)
  and aggregates (`Step::Reduce`) do **not** contribute a positive premise
  height. Per Soufflé, only *positive* body atoms feed `max(@hᵢ)`. So:
  - Antijoin premises are excluded from the height join list (they are not in
    `premise_atoms` for the height computation — verify: `premise_atoms`
    currently records positive atoms; negated atoms must be excluded, and
    `lower.rs:496` already clears the throwaway premise vec for negation, and
    `lower.rs:582` clears premise_atoms for aggregate rules).
  - Because negation is stratified (`build_strata`, `session.rs:67`), a negated
    relation belongs to a strictly *lower* stratum and is fully materialized
    (including its annotations) before this stratum runs. Its heights are final.
    No height cycle can cross a negation, matching Soufflé's stratification
    requirement (arXiv §6).
  - Aggregate rules (`fn:count`, etc.) have empty `premise_atoms` by design
    (mirrors the interpreter). Assign such head tuples `height = 1` and
    `rule_id = <the aggregate rule>`, and treat them as opaque leaves in
    reconstruction (§3) — we cannot descend into an aggregate's inputs with the
    height mechanism, which is an accepted limitation shared with the eager
    path (the interpreter also does not explain aggregate inputs).

### 2.6 Pitfalls

- **Height is a lattice join, not a set union.** The `reduce` must compute
  `min`, not keep-all. Getting this wrong silently reintroduces the eager blowup
  (many heights per row) or breaks minimality.
- **Strict `<` at reconstruction, `≤`-free at evaluation.** Evaluation uses
  `1 + max`; reconstruction uses `<`. Do not conflate.
- **EDB seed height.** EDB facts must enter with height 0 and a sentinel rule id
  (e.g. `u32::MAX` meaning "no rule / base fact"). A rule whose body is entirely
  EDB then gets height 1.
- **Determinism of tie-breaks.** Two rules can derive the same tuple at the same
  minimal height. Tie-break deterministically (smallest `rule_id`) so `::why`
  output is stable across runs and across DD worker counts.
- **Do not widen `Row`.** Keep annotations in a side collection to preserve the
  `Val`/`Row` Ord/Hash parity contract (`value.rs` header).
- **Multiplicities.** All annotation collections must carry multiplicity exactly
  1 per row after the reduce; assert this in tests (the eager path relies on the
  same invariant via `distinct`).

---

## 3. Lazy reconstruction at `::why` (query-time)

This is a **new frontend path**. It does *not* reuse
`build_provenance_index` / the flat `Vec<ProvenanceEntry>` edge consumer that
the eager path feeds (`engine.rs`, `mangle_interpreter::ProvenanceEntry`). It
also does not use `snapshot_provenance` (which drains the whole edge trace).
Instead it drives *targeted* backward-chaining queries against the arranged
traces.

### 3.1 What the session must expose

Today the session exposes `Command::Query { rel } → Vec<Vec<Value>>` and
snapshots. We add two things:

1. **Annotation traces.** For each relation, arrange the annotation collection
   (`Collection<(Row, (u32,u32))>`) into a `TraceAgent` alongside the existing
   `RowTrace` (`session.rs:127`, `arrange_by_self`/`arrange_by_key`). Call it
   `AnnotationTrace = TraceAgent<KeySpine<Row, (u32,u32), ...>>` keyed by row → its
   `(rule_id, height)`.

2. **A subproof query command.** A single primitive that answers the one-step
   query of §1.4:

```rust
/// Find ONE minimal grounding of `rule_id` whose head is `head_row` and whose
/// positive premises all have height < `max_height`.
Command::Subproof {
    head_rel: String,
    head_row: Row,
    rule_id: u32,
    max_height: u32,            // = height(head_row)
    resp: Sender<Option<Grounding>>,
}

/// The positive premises of one derivation, each with its own annotation so the
/// caller can recurse. `rule_id`/`height` come from the premise's AnnotationTrace.
struct Grounding {
    rule_id: u32,
    premises: Vec<Premise>,     // in body order
}
struct Premise {
    rel: String,
    row: Row,
    rule_id: u32,               // SENTINEL_EDB if base fact
    height: u32,                // 0 if base fact
}
```

Everything runs on the worker thread (traces are `!Send`, `Rc`-internal —
`session.rs:33`). The REPL sends `Subproof` and receives an owned `Grounding`.

### 3.2 Evaluating one `Subproof` on the worker

Given `rule_id`, recover its `LoweredRule` (keep the compiled `strata_work`
resident — it already is, `Arc<...>`, `session.rs:244`). Then, using the *plain*
row traces and the *annotation* traces:

1. Instantiate the rule head with `head_row` (bind head columns to constants).
2. Execute the rule body as a bounded search over the arranged premise traces,
   with the head bindings pushed down as constants. This is a small nested-loop
   / index-probe join *at a single point* (not a dataflow) — cursor each premise
   trace (`drain_trace`/cursor pattern, `session.rs:138-152`) filtered to rows
   consistent with the current partial binding.
3. For each candidate premise tuple, probe its `AnnotationTrace` to get `height`;
   **reject** it unless `height < max_height`.
4. Return the **first** fully-consistent grounding whose every positive premise
   passes the strict-height guard, packaged as `Grounding`.

Because we only ever need *one* grounding and all premises are height-bounded,
this is cheap: a handful of index probes per proof-tree node, `O(log n)` each
against the arranged (sorted) trace.

Note: the search must respect the rule's non-atom steps (`Cmp`, `CallFilter`,
`Let`, `MatchField`, `IterateList`) as *filters/binders* on the candidate
binding, reusing the pure evaluators already in `build.rs`
(`eval_cmp`, `eval_call_filter`, `eval_expr`) — those are side-effect-free and
callable outside a dataflow.

### 3.3 Driving the full tree in the frontend

`::why t`:

1. Look up `t`'s annotation `(k, h)` from its `AnnotationTrace` (a new
   `Command::GetAnnotation { rel, row }`).
2. If `h == 0` → base fact, emit a leaf.
3. Else send `Subproof { rel, row: t, rule_id: k, max_height: h }`, get the
   `Grounding`, emit the rule node, and recurse on each `Premise` (each already
   carries its `(rule_id, height)`, so no extra annotation lookup needed).
4. Reuse the existing proof-tree *rendering* in the REPL (`repl.rs`) — only the
   *source* of the tree changes (lazy walk vs. flat index).

Optional: honor a depth limit (Soufflé's `setdepth`/`subproof` labels, docs
"Provenance") by stopping recursion at depth `d` and emitting a resumable
`subproof` handle `(rel, row, rule_id, height)`. Cheap to add since each node is
self-describing.

---

## 4. Cost comparison vs. eager

| Dimension | Eager (`ProofEdge`, shipped) | Lazy (this spec) |
|---|---|---|
| Stored per fact | Every one-step derivation (edge = head + all premise tuples). Fact derivable N ways → N edges. Measured ~1.43x tuples vs facts. | Exactly 2 scalars (`rule_id`, `height`) per fact. One annotation row per fact. |
| Eval-time overhead | ~1.4x (extra edge collection per rule, arranged + `distinct`). | Extra: per-rule height joins + one `min` reduce per head relation + annotation `VecVariable` in recursive strata. Soufflé reports ~1.27x runtime, 1.45x storage on Doop/DaCapo (arXiv §7). Ours should be similar order; the annotation reduce re-fires on height improvement (bounded `O(n·max_h)`). |
| Query-time cost | ~O(1) index build once (`build_provenance_index`), then O(tree size) walk over a resident forest. | O(tree size) index probes into arranged traces; a handful of `O(log n)` probes per node. Pays only for explained facts. |
| Incremental maintenance | Edge set must be incrementally maintained too — every retracted/added fact churns its edges (large diffs). | Annotations churn only 2 scalars/fact; a height can improve/worsen on update, but the diff is one row per affected fact, not an edge fan-out. Strictly friendlier to `-`/`~` retraction and `::assert`/incremental (`AddRules`, `session.rs:608`). |
| Memory residency | Whole edge forest resident for the session. | Whole plain relation already resident; annotations add 2 columns of overhead. No forest. |

Headline: lazy trades a small, bounded *evaluation* cost (like eager) for a
*much* smaller storage footprint and far friendlier incremental behavior, at the
price of a more complex query-time path.

---

## 5. Honest risk assessment

**Where this is genuinely hard in DD:**

1. **Height-improvement convergence in `iterate`.** The claim in §2.4 (that DD's
   `reduce` re-fires on height improvement and still converges) is the load-
   bearing assumption. It is *correct in principle* (finite tuple set, integer
   heights bounded below), but the interaction with `VecVariable`'s round
   scheduling needs empirical validation: does the annotation variable actually
   reach fixpoint, or does it oscillate due to a non-monotone tie-break?
   Mitigation: make the reduce output a pure function of the input multiset
   (min height, min rule_id) — deterministic, monotone, no oscillation. Test on
   transitive closure where the shortest path height is well understood.

2. **Reconstructing a grounding outside a dataflow.** §3.2 executes a rule body
   as an ad-hoc index-probe join over arranged traces on the worker thread.
   That machinery does not exist yet (the current query path only cursors a
   single relation, `session.rs:138`). Writing a correct bounded join that
   honors all `Step` variants (`Join`, `Cmp`, `Antijoin`, `Let`, `MatchField`,
   `IterateList`, `Reduce`) is real work and is where most bugs will live. The
   eager path sidesteps this entirely by having DD do the join once.

3. **Negation / aggregation blind spots.** Height-based provenance cannot
   explain non-existence (needs `explainnegation`, §1.5) and cannot descend into
   aggregate inputs (§2.5). These are accepted gaps, but they mean the lazy path
   is not a strict superset of naive expectations. The eager path shares the
   aggregate gap but at least materializes negation-free positive edges
   uniformly.

4. **Antijoin height semantics under recursion.** If a negated relation were in
   the same stratum as its user (it can't be, stratification forbids it), the
   height mechanism would be unsound. We rely on `build_strata` guaranteeing
   negation crosses strata. Verify this invariant holds and add a build-time
   assertion; otherwise a mis-stratified program silently produces wrong heights.

5. **Frontier / compaction.** Reconstruction cursors traces at the settled
   frontier (`session.rs:576-585` compacts after each commit). Subproof queries
   must run against the same compacted frontier as the annotations; a race where
   annotations advanced but row traces did not (or vice versa) yields
   inconsistent proofs. Keep annotation and row traces compacted in lockstep.

**Recommended minimal-viable slice to prototype first:**

Prototype in this order, gating each on tests before the next:

1. **Non-recursive strata only.** Compute `(rule_id, height)` for a single
   non-recursive stratum (no `VecVariable`). Height join + min reduce +
   annotation trace + `GetAnnotation` command. Reconstruct one-level and
   multi-level trees where recursion is absent. This exercises §2.2, §2.3, §3.1,
   §3.2 without the convergence risk (#1) or the recursive-variable risk.
   Validate annotations against the eager `ProofEdge` output on the same fixture
   (heights should equal shortest-derivation depth; rules should match some
   eager edge).

2. **Linear recursion** (single recursive body atom, e.g. transitive closure /
   reachability). Adds the annotation `VecVariable` and directly tests the
   height-improvement convergence (#1) on a program with a known height profile.
   This is the smallest thing that can *break* and the highest-value test.

3. **General recursion + stratified negation.** Only after 1–2 are green. Adds
   multi-atom recursive bodies and cross-stratum negation guards (§2.5).

Explicitly **defer**: `explainnegation` (§1.5), aggregate-input descent,
depth-limited `subproof` resumption. Ship those (or decide not to) after the
positive-recursive core is proven.

**Fallback:** if the reconstruction join (#2) proves too costly to get right,
a middle ground is to keep the lazy *annotations* (cheap storage) but reconstruct
by re-running a small *single-tuple-seeded dataflow* per `::why` rather than an
ad-hoc probe join — slower per query but reuses `build_rule` verbatim. Note this
in the prototype if the hand-written join stalls.
