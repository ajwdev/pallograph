# Soufflé-style lazy provenance for the DD backend — feasibility map

Status: feasibility investigation, read-only. No `src/` changes made.
Scope: locate exactly where and how to (a) compute a per-IDB-tuple
annotation `(rule_id, min_proof_height)` during evaluation, and (b)
reconstruct proofs lazily at `::why` time by backward-chaining against the
arranged traces.

All file:line references are against this worktree
(`.worktrees/dd-provenance-souffle`). The design-doc companion
`docs/souffle-lazy-provenance-design.md` does not exist yet, so the open
questions below stand on their own; cross-check them against that doc when it
lands.

---

## 0. Background: what "eager" does today (the thing we are replacing)

The current eager strategy is entirely contained in three spots:

- `src/dd/value.rs:287` — `ProofEdge { head_rel, head, premises }`, one DD
  collection element per satisfying body grounding.
- `src/dd/build.rs:459-487` — `Step::Insert` arm. When `provenance && idx + 1
  == n_steps`, it re-uses the wide pre-projection `pipeline` row to emit a
  `ProofEdge` for *every* grounding, addressing premise tuples via
  `rule.premise_atoms` (`src/dd/lower.rs:150` `PremiseAtom { rel, arg_cols }`).
- `src/dd/session.rs:502-511` — all rules' proof collections are `concat`ed,
  `distinct()`ed and `arrange_by_self()`ed into a single `ProofEdgeTrace`
  (`src/dd/session.rs:130`), drained by `drain_proof_trace`
  (`src/dd/session.rs:158`) into `Vec<ProvenanceEntry>` on
  `Command::SnapshotProvenance` (`src/dd/session.rs:601`).

The cost is the edge set, which is `O(#derivations)` not `O(#facts)`; a fact
derivable N ways yields N resident edges. The lazy strategy keeps only an
`O(#facts)` annotation during eval and reconstructs on demand.

The pieces we reuse unchanged: `Row` (`src/dd/value.rs:243`), the per-relation
`RowTrace`/`TraceAgent` machinery (`src/dd/session.rs:127`), `drain_trace`'s
cursor pattern (`src/dd/session.rs:137`), and `PremiseAtom`
(`src/dd/lower.rs:150`) — the last is what makes backward-chaining possible
because it already records, per rule, which columns of a grounding row feed
each body atom.

---

## 1. Where to attach `(rule_id, min_height)` to each IDB tuple

### 1.1 First: rules need a stable identity

Today a `LoweredRule` (`src/dd/lower.rs:159`) has no id. `build_strata`
(`src/dd/mod.rs:85-123`) already iterates `ir.insts` and holds an `InstId` per
rule (`src/dd/mod.rs:85`, `rule_ids.push(InstId::new(i))`) but throws it away —
`lower_op` is called at `src/dd/mod.rs:122` and only the `LoweredRule` is
pushed. The cheapest stable id is a globally-assigned `u32` counter across all
strata, or the `InstId`'s inner `usize`. Concretely:

- Add `pub rule_id: u32` to `LoweredRule` (`src/dd/lower.rs:159-169`).
- Thread it through `lower_op` (`src/dd/lower.rs:179`) as a parameter, assigned
  in the `build_strata` loop at `src/dd/mod.rs:118-123` from an incrementing
  counter (stable because `ir.insts` order is stable).

This id is what `min_height` annotations and the eventual `::why` output key
on ("fact F was first derived at height h by rule R").

### 1.2 Two shapes for the annotation column — recommendation and trade-offs

**Option A — widen `Row` with two trailing columns `(rule_id, height)`.**
Rejected. `Row` is the join/dedup key everywhere; its `Eq`/`Hash`/`Ord`
(`src/dd/value.rs:242`) define set semantics and must match the interpreter
(the parity contract at `src/dd/value.rs:14-18`). Appending annotation columns
would (a) break `distinct()` — two derivations of the same fact at different
heights would no longer dedup to one fact — and (b) poison every downstream
`Join`/`Antijoin` key computation in `build.rs`, which slices `row.0[i]` by
column index (`src/dd/build.rs:270-286`, `:322-335`). Non-starter without a
schema-width bookkeeping rewrite.

**Option B — a parallel annotated collection `Collection<(Row, (u32, u64))>`
keyed by the fact tuple, with a min-reduce.** Recommended. The fact fixpoint
stays exactly as it is (`Row`-typed, `distinct()`-based), and heights live in a
*sibling* collection that is `reduce`d to keep the minimum per tuple. This is
the standard "annotated relation" encoding and it composes with the existing
`reduce` usage already in `build.rs` (`src/dd/build.rs:443`).

Encoding detail: represent the annotation as `Row` extended by exactly two
`Val`s (`Val::Number(rule_id as i64)`, `Val::Number(height as i64)`) *only
inside the annotation collection*, or introduce a small
`#[derive(...same trait set as Row...)]` struct
`Annotated { fact: Row, rule_id: u32, height: u64 }` in `src/dd/value.rs`
(mirror the derive list at `src/dd/value.rs:242` and `:286`). A dedicated
struct is clearer and keeps `Val` out of the height domain. It must derive
`Serialize/Deserialize/Ord/Hash` for `ExchangeData` just like `ProofEdge`
(`src/dd/value.rs:286`).

Trade-off summary: Option B costs one extra arranged trace per IDB relation
(the min-height annotation trace) plus one `reduce` per stratum, but leaves the
core fact dataflow byte-identical to today. Option A is "free" in trace count
but corrupts set semantics. Choose B.

### 1.3 Where the annotation is produced

The annotation is produced at the same site the head is produced: the final
`Step::Insert` in `build_rule` (`src/dd/build.rs:459`). Instead of (or in
addition to) building a `ProofEdge`, emit an
`(fact_row, rule_id, body_min_height + 1)` element. The `+1` and
`body_min_height` are the crux and are handled in §2 — at build time within a
single rule we know `rule_id` (from §1.1) but *not* the heights of the body
tuples, because those come from the sibling annotation collections of the body
relations, which must be joined in. See §2 for how that join threads through
the pipeline.

`build_rule`'s signature (`src/dd/build.rs:219-227`) would gain a fourth mode
or a fifth return element: `Option<VecCollection<'scope, T, Annotated>>`,
symmetric to the existing `Option<...ProofEdge>` at `src/dd/build.rs:224,229`.
The provenance flag plumbing already exists end-to-end (`spawn_prov` at
`src/dd/session.rs:216`, the `provenance` bool threaded into `build_rule` at
`src/dd/session.rs:377,446,683`), so a `ProvenanceMode { Off, Eager, LazyHeights }`
enum is the natural replacement for the current `bool`.

---

## 2. Computing `min_height` inside the recursive `iterative()` scope

This is the hard part and the make-or-break for feasibility.

### 2.1 The height recurrence

Soufflé's proof height: an EDB fact has height 0. An IDB fact derived by rule R
from body tuples `b1..bk` has height `1 + max(height(b1), .., height(bk))`; a
fact's stored height is the *minimum over all derivations* of that quantity
(the shortest proof). This is exactly the "min-plus / shortest derivation"
semiring, and it converges on the same fixpoint schedule as the fact set
itself, so it can ride inside the existing iteration.

### 2.2 Where the fixpoint lives

The recursive fixpoint is `scope.iterative::<u64, _, _>` at
`src/dd/session.rs:331`, with:

- inner timestamp `Product<u32, u64>` (`src/dd/session.rs:337`) — the `u64`
  inner coordinate is the iteration round. This is *not* the proof height, but
  it is monotone with derivation rounds and worth noting as a distraction: do
  not conflate the two. Height must be carried as data, not read off the
  timestamp, because a fact can be re-derived at a later round via a shorter
  proof.
- per-head `VecVariable` created at `src/dd/session.rs:355` (`new_from(seed,
  summary)`) / `:360` (`new(nested, summary)`).
- the fact recurrence `curr.concat(new_facts).distinct()` and `var.set(full)`
  at `src/dd/session.rs:404-412`.
- `full.leave(scope)` at `src/dd/session.rs:413` to export to the parent.

### 2.3 How to add the height min-reduce without breaking the fact fixpoint

Key structural fact: the fact `VecVariable` at `src/dd/session.rs:355` is
`Row`-typed and its `.distinct()` (`src/dd/session.rs:408,410`) is what
guarantees termination (bounded lattice: a finite set of `Row`s). If heights
were folded into the variable's element type, `distinct()` would no longer be
idempotent (height can keep decreasing), and the fixpoint could fail to
terminate or terminate at wrong heights.

Therefore run **two coupled variables per head predicate**:

1. The existing fact `VecVariable<_, Row, isize>` — untouched
   (`src/dd/session.rs:346`). This is the termination driver.
2. A new annotation `VecVariable<_, Annotated, isize>` (or
   `Variable<_, (Row,(u32,u64))>`), fed by a `reduce` that keeps, per fact
   `Row`, the minimum `(height, rule_id)` seen so far.

Per-rule, `build_rule` produces `(fact_coll, annot_coll)`. In the recursive
arm (`src/dd/session.rs:376-394`) these are collected into `by_head` (facts,
`:379`) and a parallel `by_head_annot`. Then, replacing/augmenting the fold at
`src/dd/session.rs:400-414`:

```
// facts: unchanged — drives termination
let full_facts = curr.concat(new_facts).distinct();          // :408
fact_var.set(full_facts.clone());

// heights: min-reduce over all derivations of each fact this round
let all_annots = seed_annots.concat(new_annots);             // new
let min_annots = all_annots
    .map(|a| (a.fact, (a.height, a.rule_id)))                // key by fact
    .reduce(|_fact, input, out| {
        // input: &[(&(u64,u32), isize)]; pick lexicographically-min (height,rule_id)
        let best = input.iter().map(|(hr, _)| **hr).min().unwrap();
        out.push((best, 1));
    });
annot_var.set(min_annots-as-Annotated);
out_annot.insert(pred, min_annots.leave(scope));
```

The `reduce` closure mirrors the one already in `build.rs`
(`src/dd/build.rs:443-448`) — same `input: &[(&V, isize)]` shape, same
`output.push((.., 1))` idiom. Because `reduce` output is deterministic and the
height lattice is bounded below by 0 and above by the (finite) fact-set
diameter, the annotation variable converges on the same round the fact variable
does. **The fact `distinct()` still governs termination; the height reduce is a
passenger.** That is why the current per-head-`VecVariable` + `distinct`
structure *can* accommodate the min-reduce — as a sibling, not a replacement.

### 2.4 Where `+1` and `max(body heights)` happen

Inside `build_rule`, the body's per-atom heights must be joined in. Each
positive body atom is recorded as a `PremiseAtom` (`src/dd/lower.rs:150`) at
scan (`src/dd/lower.rs:308`) and join (`src/dd/lower.rs:266`) time. For lazy
heights, each `Step::Scan`/`Step::Join` that reads relation `rel`
(`src/dd/build.rs:244`, `:258`) must *also* look up `rel`'s annotation
collection (passed in alongside `rels` — extend the `rels` HashMap parameter at
`src/dd/build.rs:221` with a sibling `annotations: &HashMap<String, Collection<...
Annotated>>`), join it on the atom's key columns, and carry a running
`max_height` accumulator column through the pipeline. At the final `Insert`
(`src/dd/build.rs:467`) emit `height = max_height + 1`.

This is more invasive than eager (which only reads columns at the very end).
The first-slice recommendation (§5) sidesteps most of it.

For EDB relations the annotation is the constant `(rule_id = sentinel, height =
0)`; seed one annotation collection per EDB relation next to the fact seed at
`src/dd/session.rs:307-311` / the EDB seed loop at `src/dd/session.rs:528-534`.

---

## 3. New session Commands / query interface for lazy reconstruction

### 3.1 What must change from eager

Eager ships whole `ProvenanceEntry`s via `Command::SnapshotProvenance`
(`src/dd/session.rs:91,601`) drained by `drain_proof_trace`
(`src/dd/session.rs:158`). Lazy replaces that bulk snapshot with an on-demand,
per-fact query that backward-chains one level at a time. The heavy invariant to
respect: **`TraceAgent` is `!Send`** (documented at `src/dd/session.rs:33-35`),
so *all* cursoring runs on the worker thread; the REPL thread only ever sends a
request and receives owned `Vec`/`ProvenanceEntry` data back. Every existing
drain already obeys this (`drain_trace` at `src/dd/session.rs:137`,
`drain_proof_trace` at `:158`, both called from inside the command loop at
`:589-607`).

### 3.2 New Commands

Add to the `Command` enum (`src/dd/session.rs:73-106`):

1. `Command::WhyHeight { rel: String, fact: Row, resp: Sender<Option<(u32,
   u64)>> }` — cursor the annotation trace for `rel`, return the stored
   `(rule_id, min_height)` for `fact` (or `None` if not derived). This is a
   point lookup: seek the cursor to `fact` rather than scanning (DD's `Cursor`
   supports `seek_key`; `drain_trace` currently only does full scans at
   `src/dd/session.rs:140-152`, so add a seek-based helper).

2. `Command::WhyStep { rule_id: u32, head: Row, max_sub_height: u64, resp:
   Sender<Vec<Vec<(String, Row)>>> }` — the backward-chaining primitive. Given
   the rule that achieved the min height for `head`, find all body groundings of
   that rule that (a) produce `head` and (b) whose every positive body atom has
   a stored height `< max_sub_height` (= `height(head)`), i.e. a strictly
   descending subproof. Returns each grounding as its list of `(rel, premise
   Row)` premises — the same shape as `ProvenanceEntry.premises`
   (`src/dd/session.rs:169-176`).

The `::why` frontend (unchanged `build_provenance_index`/`print_why`, per the
memory note) then recurses: for each premise it issues another `WhyHeight` +
`WhyStep`, descending strictly-lower heights until it bottoms out at EDB facts
(height 0). Because heights strictly decrease, recursion terminates and cannot
loop even in a cyclic IDB.

### 3.3 How `WhyStep` cursors the traces to find body groundings

This is the delicate part. `WhyStep` must re-evaluate *one rule, once,
restricted to a single head tuple*. Two implementable approaches:

**Approach 1 — re-run the rule's pipeline as a tiny dataflow on demand.** On
the worker, build a one-shot `worker.dataflow` (exactly as the layering path
does at `src/dd/session.rs:656`, which already imports existing traces via
`trace.import(scope).as_collection(...)` at `:661-666`), run the target rule's
lowered `Step`s but with a leading filter pinning the head projection to the
requested `head`, and read back the groundings. The rule's `LoweredRule`
(`Step`s + `premise_atoms`) is exactly what `build_rule` consumes, so the same
builder produces the grounding rows; a variant of the eager `Insert` arm
(`src/dd/build.rs:471-480`) emits the premise list instead of arranging it. The
height filter is applied by joining each body atom against its annotation trace
and keeping `height < max_sub_height`. This reuses the import machinery that is
already proven to work on the worker thread.

**Approach 2 — keep per-relation body-index traces resident.** Instead of
re-running, arrange each rule's pre-projection grounding collection keyed by
head tuple (an extra trace per rule, keyed `head -> premises`). `WhyStep`
becomes a seek on that trace. This is cheaper per query but reintroduces
resident state proportional to derivations — i.e. it drifts back toward eager's
cost, defeating the purpose. Prefer Approach 1; it pays cost only per explained
fact, which is the whole point of lazy.

Either way the cursor/seek helpers live next to `drain_trace`
(`src/dd/session.rs:137`) and run inside the command loop
(`src/dd/session.rs:554-750`), never on the REPL side. `LoweredRule` is
`Send + Sync + 'static` (`src/dd/lower.rs:176-178`), so the rule set can be
captured into the worker closure or stored worker-side at spawn; the `Row`
`fact`/`head` in the commands are owned and `Send` (they derive the full trait
set at `src/dd/value.rs:242`), so crossing the channel is fine.

### 3.4 Worker-side state additions

The worker currently owns `handles`, `traces`, `proof_trace`
(`src/dd/session.rs:286`). Lazy adds: `annotation_traces: HashMap<String,
AnnotTrace>` (one min-height trace per IDB relation, arranged at
`src/dd/session.rs:491-495` right beside the fact traces) and a worker-resident
`Vec<LoweredRule>` (or `HashMap<u32, LoweredRule>` keyed by `rule_id`) so
`WhyStep` can find the rule by id without recompiling. Compaction of the annot
traces must follow the fact traces' frontier advance at
`src/dd/session.rs:577-586`.

---

## 4. Interaction with stratified negation (antijoin) and aggregation (reduce)

### 4.1 Negation — `Step::Antijoin` (`src/dd/build.rs:309`)

A rule body with a negated literal `!p(..)` derives the head *because p is
absent*. There is no positive body tuple for the negated atom, so it
contributes no height and no premise to descend into. Two consequences:

- Height: `height(head) = 1 + max over positive body atoms only`. The antijoin
  atom is skipped in the max. This is consistent with Soufflé, which explains a
  negated subgoal as "no proof of `p(..)` exists" rather than descending.
- `::why` output: a negated premise should be reported as a *negative
  justification* ("... and no `p(..)`"), not a recursive descent. The current
  `PremiseAtom`/`ProofEdge` model records only *positive* premises
  (`src/dd/lower.rs:141-154` docstring says "positive body atom"; the eager
  `Antijoin` lowering at `src/dd/lower.rs:385-413` pushes a `Step::Antijoin`
  but adds nothing to `premise_atoms`). So negation is already invisible to
  provenance today; lazy inherits that limitation cleanly. Surfacing negative
  justifications is an enhancement orthogonal to height computation — note it as
  an open item, ideally cross-checked against
  `docs/souffle-lazy-provenance-design.md` (absent at time of writing).

### 4.2 Aggregation — `Step::Reduce` (`src/dd/build.rs:429`)

Aggregate-derived facts already carry **empty premises** in both backends by
design (interpreter parity; `src/dd/lower.rs:582` `premise_atoms.clear()`, and
the memory note "Aggregate + unit-rule facts carry empty premises"). The
`Op::Seq`/`Op::GroupBy` lowering wipes premises (`src/dd/lower.rs:496-497`,
`:580-582`). For heights, the sensible definition matching this choice is: an
aggregate fact's height = `1 + max height over the group's input tuples`, but
since we do not descend into an aggregate's justification anyway, the simplest
consistent choice is to treat aggregate (and unit) facts as **height 1 leaves
for `::why` purposes** — reconstruction stops there, exactly as eager stops
(empty premises → no descent). Soufflé itself treats aggregates as opaque in
its basic provenance; deep aggregate provenance is out of scope. Open question
for the design doc: whether to expose the group's contributing tuples at all.

Unit rules (`Step::Unit`, `src/dd/build.rs:237`; `src/dd/lower.rs:458-459`):
height 1, no premises, leaf. Same treatment.

---

## 5. Minimal first-slice recommendation

Goal: prove the height-annotation + lazy-reconstruction loop end to end on the
smallest rule shape, with the least disturbance to the fact fixpoint.

**Target rule shape: linear positive recursion, no negation, no aggregation.**
The canonical `path(X,Y) :- edge(X,Y).` / `path(X,Z) :- edge(X,Y), path(Y,Z).`
(already the test fixture at `src/dd/session.rs:929-930`,
`:1032`, `:1093`). This exercises: EDB height-0 seeding, a base rule (height 1),
and a recursive rule whose height grows — the exact case where "shortest proof"
matters and eager blows up.

**Functions to add/modify, in dependency order:**

1. `src/dd/value.rs` — add `Annotated { fact: Row, rule_id: u32, height: u64 }`
   deriving the same trait set as `ProofEdge` (`src/dd/value.rs:286`). ~10 LoC.

2. `src/dd/lower.rs:159` — add `rule_id: u32` to `LoweredRule`; thread through
   `lower_op` (`:179`).

3. `src/dd/mod.rs:118-123` — assign `rule_id` from a stratum-crossing counter in
   the lowering loop.

4. Replace the `provenance: bool` plumbing with `ProvenanceMode { Off, Eager,
   LazyHeights }`: `spawn_prov` (`src/dd/session.rs:216`), `build_rule`
   (`src/dd/build.rs:219`), and the three `build_rule` call sites
   (`src/dd/session.rs:377,446,683`). Keep `Eager` working (do not regress the
   existing `::why`).

5. `src/dd/build.rs` — in the `Scan`/`Join` arms (`:244`, `:258`) additionally
   thread the sibling annotation collection and a running `max_height` column;
   in the `Insert` arm (`:459`) emit an `Annotated` element under `LazyHeights`.
   For the first slice, restrict to rules whose body atoms are all plain
   `Scan`/`Join` (no `Let`/`MatchField`/`IterateList`/`Reduce`) and `bail!`
   otherwise, mirroring the existing loud-failure discipline
   (`src/dd/build.rs:348-350`).

6. `src/dd/session.rs` — the recursive arm (`:400-414`): add the second
   (annotation) `VecVariable` + min-`reduce` as in §2.3, leaving the fact
   variable and its `distinct()` untouched. Add `annotation_traces` arrangement
   beside `src/dd/session.rs:491-495`. Store the `Vec<LoweredRule>`
   worker-side.

7. `src/dd/session.rs` — add `Command::WhyHeight` and `Command::WhyStep`
   (§3.2) with worker-side seek-based cursor helpers next to `drain_trace`
   (`:137`), and public `DdSession` methods mirroring `snapshot_provenance`
   (`:826`). Implement `WhyStep` via the on-demand-dataflow approach (§3.3,
   Approach 1), reusing the `trace.import` pattern from the layering path
   (`src/dd/session.rs:656-667`).

8. A test mirroring `session_basic_query` (`src/dd/session.rs:922`) that spawns
   with `LazyHeights`, then reconstructs the proof of a 2-hop `path` fact and
   asserts it descends `path -> edge` with strictly decreasing heights and
   bottoms out at EDB.

**Deliberately deferred past the first slice:** negation justification (§4.1),
aggregate/unit descent (§4.2), non-Scan/Join body steps
(`Let`/`MatchField`/`IterateList`), and the incremental (post-delta) `::why`
path — the same follow-up eager already deferred (memory note: "Scope: batch
only").

---

## Appendix — quick reference of the load-bearing sites

| Concern | File:line |
| --- | --- |
| `Row` (fact tuple, join/dedup key) | `src/dd/value.rs:243` |
| `ProofEdge` (eager element) + successor note | `src/dd/value.rs:287`, doc `:271-285` |
| `PremiseAtom { rel, arg_cols }` | `src/dd/lower.rs:150` |
| premise atoms recorded at scan / join | `src/dd/lower.rs:308`, `:266` |
| premise atoms cleared for aggregates | `src/dd/lower.rs:582`, `:496-497` |
| `LoweredRule` (add `rule_id` here) | `src/dd/lower.rs:159` |
| rule ids available but discarded | `src/dd/mod.rs:85`, `:118-123` |
| `build_rule` signature + provenance return | `src/dd/build.rs:219-229` |
| `Step::Scan` / `Step::Join` (annotation join sites) | `src/dd/build.rs:244`, `:258` |
| `Step::Antijoin` (negation) | `src/dd/build.rs:309` |
| `Step::Reduce` (aggregation) + reduce closure shape | `src/dd/build.rs:429`, `:443-448` |
| eager `ProofEdge` emission at final Insert | `src/dd/build.rs:467-481` |
| recursive `scope.iterative` + inner ts | `src/dd/session.rs:331`, `:337` |
| per-head `VecVariable` | `src/dd/session.rs:346`, `:355`, `:360` |
| fact recurrence `concat.distinct` + `var.set` + `leave` | `src/dd/session.rs:408-413` |
| trace arrangement (add annot traces beside) | `src/dd/session.rs:491-495` |
| eager proof trace concat/distinct/arrange | `src/dd/session.rs:502-511` |
| compaction frontier advance | `src/dd/session.rs:577-586` |
| `Command` enum (add WhyHeight/WhyStep) | `src/dd/session.rs:73-106` |
| `drain_trace` cursor pattern (base for seek helper) | `src/dd/session.rs:137` |
| `drain_proof_trace` | `src/dd/session.rs:158` |
| command loop (all cursoring runs here) | `src/dd/session.rs:554-750` |
| on-demand dataflow / `trace.import` pattern | `src/dd/session.rs:656-667` |
| `TraceAgent` is `!Send` invariant | `src/dd/session.rs:33-35` |
| `provenance` flag plumbing | `src/dd/session.rs:216`, `:377`, `:446`, `:683` |
