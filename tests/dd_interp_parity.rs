// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! DD-backend vs mangle-interpreter fact-parity tests.
//!
//! `dd_matches_interpreter` (in `src/engine.rs`) already checks parity on the
//! full production ruleset over one fixed dataset. These tests complement it in
//! two ways that matter for trusting the DD backend (and the perf comparison):
//!
//! 1. **Feature matrix** — small, self-contained programs that each isolate one
//!    Datalog feature, so a regression points at the exact feature that broke.
//! 2. **Property-based** — the same rule shapes over randomly-generated EDBs
//!    (seeded, deterministic), which catches data-shape-dependent divergences
//!    (cycles, self-loops, duplicates, empty relations) that a single fixture
//!    never exercises.
//!
//! Both backends prepend the (Decls-only) EDB prelude, so the comparison is
//! symmetric. `$temp` planner relations are skipped (the interpreter
//! materialises them; the DD backend inlines them away).
//!
//! `fn:collect` / `fn:collect_distinct` are covered via [`assert_parity_unordered`],
//! which normalizes list order before comparing (the collected-list order is
//! unspecified, so we assert the multiset matches, not a particular order).

use std::collections::BTreeSet;

use mangle_common::{CompoundKind, Value};
use pallograph::engine::{Backend, DdBackend, InterpreterBackend};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type Edb = Vec<(String, Vec<Value>)>;

fn n(x: i64) -> Value {
    Value::Number(x)
}
fn s(x: &str) -> Value {
    Value::String(x.to_string())
}
fn f(x: f64) -> Value {
    Value::Float(x)
}

fn edb(facts: &[(&str, Vec<Value>)]) -> Edb {
    facts
        .iter()
        .map(|(r, t)| (r.to_string(), t.clone()))
        .collect()
}

/// Evaluate `rules` over `edb` on both backends; assert every (non-`$`) relation
/// has an identical fact set. Panics with a diff on mismatch, or with the
/// backend error if either fails to evaluate.
fn assert_parity(name: &str, e: &Edb, rules: &str) {
    assert_parity_impl(name, e, rules, false);
}

/// Like [`assert_parity`], but sorts the elements of every `List` value before
/// comparing. Use for aggregates like `fn:collect` whose output-list order is
/// unspecified and may legitimately differ between backends — we want to assert
/// the collected *multiset* matches, not a particular order.
fn assert_parity_unordered(name: &str, e: &Edb, rules: &str) {
    assert_parity_impl(name, e, rules, true);
}

/// Recursively sort the elements of any `List` compound, so two lists with the
/// same elements in different order normalize equal. Other value kinds (and
/// non-List compounds like structs/pairs, whose order IS meaningful) are left
/// structurally intact.
fn normalize_value(v: &Value) -> Value {
    match v {
        Value::Compound(CompoundKind::List, elems) => {
            let mut inner: Vec<Value> = elems.iter().map(normalize_value).collect();
            inner.sort();
            Value::Compound(CompoundKind::List, inner)
        }
        Value::Compound(kind, elems) => {
            Value::Compound(*kind, elems.iter().map(normalize_value).collect())
        }
        other => other.clone(),
    }
}

fn assert_parity_impl(name: &str, e: &Edb, rules: &str, normalize_lists: bool) {
    let rules = vec![rules.to_string()];
    let interp = InterpreterBackend
        .evaluate(e, &rules)
        .unwrap_or_else(|err| panic!("[{name}] interpreter failed: {err:#}"));
    let dd = DdBackend { provenance: false }
        .evaluate(e, &rules)
        .unwrap_or_else(|err| panic!("[{name}] dd failed: {err:#}"));

    let rels: BTreeSet<String> = interp
        .relation_names()
        .map(String::from)
        .chain(dd.relation_names().map(String::from))
        .filter(|r| !r.starts_with('$'))
        .collect();

    let prep = |tuples: &[Vec<Value>]| -> Vec<Vec<Value>> {
        let mut v: Vec<Vec<Value>> = tuples
            .iter()
            .map(|t| {
                if normalize_lists {
                    t.iter().map(normalize_value).collect()
                } else {
                    t.clone()
                }
            })
            .collect();
        v.sort();
        v
    };

    let mut failures = Vec::new();
    for rel in &rels {
        let i = prep(interp.scan(rel));
        let d = prep(dd.scan(rel));
        if i != d {
            let missing: Vec<_> = i
                .iter()
                .filter(|t| !d.contains(t))
                .take(3)
                .cloned()
                .collect();
            let extra: Vec<_> = d
                .iter()
                .filter(|t| !i.contains(t))
                .take(3)
                .cloned()
                .collect();
            failures.push(format!(
                "  {rel}: interp={} dd={}\n     missing from dd: {missing:?}\n     extra in dd:     {extra:?}",
                i.len(),
                d.len()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "[{name}] DD/interpreter parity failures:\n{}",
        failures.join("\n")
    );
}

// ---------------------------------------------------------------------------
// Feature matrix
// ---------------------------------------------------------------------------

#[test]
fn linear_recursion_transitive_closure() {
    let e = edb(&[
        ("edge", vec![n(1), n(2)]),
        ("edge", vec![n(2), n(3)]),
        ("edge", vec![n(3), n(4)]),
    ]);
    assert_parity(
        "transitive_closure",
        &e,
        "Decl edge(A, B).\nDecl path(A, B).\n\
         path(X, Y) :- edge(X, Y).\n\
         path(X, Z) :- path(X, Y), edge(Y, Z).",
    );
}

#[test]
fn recursion_with_cycle() {
    // A 3-cycle plus a tail: every node reaches every node in the cycle.
    let e = edb(&[
        ("edge", vec![n(1), n(2)]),
        ("edge", vec![n(2), n(3)]),
        ("edge", vec![n(3), n(1)]),
        ("edge", vec![n(3), n(4)]),
    ]);
    assert_parity(
        "cyclic_tc",
        &e,
        "Decl edge(A, B).\nDecl path(A, B).\n\
         path(X, Y) :- edge(X, Y).\n\
         path(X, Z) :- path(X, Y), edge(Y, Z).",
    );
}

#[test]
fn mutual_recursion() {
    let e = edb(&[
        ("base", vec![n(0)]),
        ("succ", vec![n(0), n(1)]),
        ("succ", vec![n(1), n(2)]),
        ("succ", vec![n(2), n(3)]),
        ("succ", vec![n(3), n(4)]),
    ]);
    assert_parity(
        "mutual_even_odd",
        &e,
        "Decl base(N).\nDecl succ(A, B).\nDecl even(N).\nDecl odd(N).\n\
         even(X) :- base(X).\n\
         odd(Y) :- even(X), succ(X, Y).\n\
         even(Y) :- odd(X), succ(X, Y).",
    );
}

#[test]
fn stratified_negation() {
    let e = edb(&[
        ("node", vec![n(1)]),
        ("node", vec![n(2)]),
        ("node", vec![n(3)]),
        ("edge", vec![n(1), n(2)]),
    ]);
    assert_parity(
        "negation",
        &e,
        "Decl node(N).\nDecl edge(A, B).\nDecl reachable(A, B).\nDecl unreachable(A, B).\n\
         reachable(X, Y) :- edge(X, Y).\n\
         reachable(X, Z) :- reachable(X, Y), edge(Y, Z).\n\
         unreachable(X, Y) :- node(X), node(Y), !reachable(X, Y).",
    );
}

#[test]
fn aggregate_count() {
    let e = edb(&[
        ("item", vec![s("a"), n(1)]),
        ("item", vec![s("a"), n(2)]),
        ("item", vec![s("b"), n(3)]),
    ]);
    assert_parity(
        "count",
        &e,
        "Decl item(Cat, Val).\nDecl cnt(Cat, N).\n\
         cnt(Cat, N) :- item(Cat, Val) |> do fn:group_by(Cat), let N = fn:count(Val).",
    );
}

#[test]
fn aggregate_sum() {
    let e = edb(&[
        ("item", vec![s("a"), n(10)]),
        ("item", vec![s("a"), n(5)]),
        ("item", vec![s("b"), n(3)]),
    ]);
    assert_parity(
        "sum",
        &e,
        "Decl item(Cat, Val).\nDecl total(Cat, S).\n\
         total(Cat, S) :- item(Cat, Val) |> do fn:group_by(Cat), let S = fn:sum(Val).",
    );
}

#[test]
fn aggregate_max() {
    let e = edb(&[
        ("item", vec![s("a"), n(10)]),
        ("item", vec![s("a"), n(5)]),
        ("item", vec![s("b"), n(3)]),
    ]);
    assert_parity(
        "max",
        &e,
        "Decl item(Cat, Val).\nDecl hi(Cat, M).\n\
         hi(Cat, M) :- item(Cat, Val) |> do fn:group_by(Cat), let M = fn:max(Val).",
    );
}

#[test]
fn aggregate_min() {
    let e = edb(&[
        ("item", vec![s("a"), n(10)]),
        ("item", vec![s("a"), n(5)]),
        ("item", vec![s("b"), n(3)]),
    ]);
    assert_parity(
        "min",
        &e,
        "Decl item(Cat, Val).\nDecl lo(Cat, M).\n\
         lo(Cat, M) :- item(Cat, Val) |> do fn:group_by(Cat), let M = fn:min(Val).",
    );
}

#[test]
fn aggregate_collect() {
    let e = edb(&[
        ("item", vec![s("a"), n(3)]),
        ("item", vec![s("a"), n(1)]),
        ("item", vec![s("a"), n(2)]),
        ("item", vec![s("b"), n(5)]),
    ]);
    // List order is unspecified, so compare collected lists as multisets.
    assert_parity_unordered(
        "collect",
        &e,
        "Decl item(Cat, Val).\nDecl grouped(Cat, L).\n\
         grouped(Cat, L) :- item(Cat, Val) |> do fn:group_by(Cat), let L = fn:collect(Val).",
    );
}

// NOTE: `fn:collect_distinct` is intentionally not tested because both backends
// currently reject it. The mangle planner's aggregate allow-list
// (`try_parse_aggregate` in mangle-analysis/src/planner.rs) includes `fn:collect`
// but not `fn:collect_distinct`, so it is never routed as an aggregate and falls
// through to the shared scalar `eval_function`, which errors "Unknown function"
// on both backends. The `eval_aggregate` arms for it (interpreter + DD) are dead
// code until the planner allow-list is updated upstream; this is not a
// DD-vs-interpreter divergence.

// A variable repeated within one body atom (`edge(X, X)`) loses its equality
// check in the mangle planner: `bound_vars` in mangle-analysis planner.rs is
// only updated after the scan, so no `Eq` constraint is emitted. The backends
// then misbind differently (interpreter yields 2, 3; DD yields 1, 3), where
// the correct answer is 3 alone. Ignored until fixed upstream.
#[test]
#[ignore = "upstream mangle planner drops the repeated-variable equality check"]
fn repeated_variable_in_atom() {
    let e = edb(&[("edge", vec![n(1), n(2)]), ("edge", vec![n(3), n(3)])]);
    assert_parity(
        "repeated_variable",
        &e,
        "Decl edge(A, B).\nDecl self_loop(X).\n\
         self_loop(X) :- edge(X, X).",
    );
}

#[test]
fn self_join() {
    let e = edb(&[
        ("knows", vec![n(1), n(2)]),
        ("knows", vec![n(2), n(3)]),
        ("knows", vec![n(1), n(4)]),
        ("knows", vec![n(4), n(3)]),
    ]);
    assert_parity(
        "self_join",
        &e,
        "Decl knows(A, B).\nDecl fof(A, C).\n\
         fof(X, Z) :- knows(X, Y), knows(Y, Z).",
    );
}

#[test]
fn cross_product() {
    let e = edb(&[
        ("a", vec![n(1)]),
        ("a", vec![n(2)]),
        ("b", vec![s("x")]),
        ("b", vec![s("y")]),
    ]);
    assert_parity(
        "cross_product",
        &e,
        "Decl a(X).\nDecl b(Y).\nDecl pair(X, Y).\n\
         pair(X, Y) :- a(X), b(Y).",
    );
}

#[test]
fn string_builtins() {
    let e = edb(&[
        ("name", vec![s("alpha")]),
        ("name", vec![s("alto")]),
        ("name", vec![s("beta")]),
    ]);
    assert_parity(
        "string_starts_with",
        &e,
        "Decl name(N).\nDecl hit(N).\n\
         hit(N) :- name(N), :string:starts_with(N, \"al\").",
    );
}

#[test]
fn string_ends_with() {
    let e = edb(&[
        ("url", vec![s("/debug/*")]),
        ("url", vec![s("/healthz")]),
        ("url", vec![s("*")]),
        ("url", vec![s("")]),
    ]);
    assert_parity(
        "string_ends_with",
        &e,
        "Decl url(U).\nDecl prefix_url(U).\n\
         prefix_url(U) :- url(U), :string:ends_with(U, \"*\").",
    );
}

#[test]
fn string_concat_feeds_starts_with() {
    // Both arguments of :string:starts_with are bound: the prefix is built
    // per namespace, the way service account usernames are matched to their
    // system:serviceaccounts:<ns> group.
    let e = edb(&[
        ("ns", vec![s("team-a")]),
        ("ns", vec![s("team")]),
        ("user", vec![s("system:serviceaccount:team-a:deployer")]),
        ("user", vec![s("system:serviceaccount:team-b:deployer")]),
        ("user", vec![s("alice")]),
    ]);
    assert_parity(
        "concat_starts_with",
        &e,
        "Decl ns(N).\nDecl user(U).\nDecl candidate(U, N, P).\nDecl in_ns(U, N).\n\
         candidate(U, N, P) :- user(U), ns(N)\n\
           |> let P = fn:string:concat(\"system:serviceaccount:\", N, \":\").\n\
         in_ns(U, N) :- candidate(U, N, P), :string:starts_with(U, P).",
    );
}

/// A struct value in the shape `json_to_value` builds: field names are
/// `/name` constants interleaved with their values.
fn record(fields: &[(&str, Value)]) -> Value {
    let mut pairs = Vec::new();
    for (field, value) in fields {
        pairs.push(Value::Name(format!("/{field}")));
        pairs.push(value.clone());
    }
    Value::Compound(CompoundKind::Struct, pairs)
}

fn string_list(values: &[&str]) -> Value {
    Value::Compound(CompoundKind::List, values.iter().map(|v| s(v)).collect())
}

#[test]
fn negated_match_field_absent_field() {
    // Rule 1 has resourceNames, rule 2 has it empty, rule 3 lacks the
    // field, and 4 is not a struct at all.
    let e = edb(&[
        (
            "rule",
            vec![
                n(1),
                record(&[
                    ("verbs", string_list(&["get"])),
                    ("resourceNames", string_list(&["a"])),
                ]),
            ],
        ),
        (
            "rule",
            vec![
                n(2),
                record(&[
                    ("verbs", string_list(&["get"])),
                    ("resourceNames", string_list(&[])),
                ]),
            ],
        ),
        (
            "rule",
            vec![n(3), record(&[("verbs", string_list(&["get"]))])],
        ),
        ("rule", vec![n(4), s("not a struct")]),
    ]);
    // Both planners reject `!:match_field(R, /resourceNames, _)` ("all
    // arguments must be bound by earlier premises"), so "field absent" is a
    // negation over a helper relation keyed on the struct. The negated
    // check mode itself needs a bound value.
    assert_parity(
        "negated_match_field",
        &e,
        "Decl rule(I, R).\nDecl names_present(R).\nDecl lacks_names(I).\nDecl lacks_get(I).\n\
         names_present(R) :- rule(_, R), :match_field(R, /resourceNames, _).\n\
         lacks_names(I) :- rule(I, R), !names_present(R).\n\
         lacks_get(I) :- rule(I, R), !:match_field(R, /verbs, [\"get\"]).",
    );
}

#[test]
fn negation_over_lower_recursive_stratum() {
    // The shape of ClusterRole aggregation: a role aggregating sources that
    // (transitively) have rules uses theirs, otherwise its own. has_rules is
    // positively recursive and sits in the stratum below the negation.
    // a -> b -> c is a chain, d <-> e is a cycle fed by c, and f aggregates
    // only g, which has no rules, so f keeps its own.
    let e = edb(&[
        ("own", vec![s("b"), s("b-own")]),
        ("own", vec![s("c"), s("c-own")]),
        ("own", vec![s("f"), s("f-own")]),
        ("agg", vec![s("a"), s("b")]),
        ("agg", vec![s("b"), s("c")]),
        ("agg", vec![s("d"), s("e")]),
        ("agg", vec![s("e"), s("d")]),
        ("agg", vec![s("e"), s("c")]),
        ("agg", vec![s("f"), s("g")]),
    ]);
    assert_parity(
        "negation_over_recursion",
        &e,
        "Decl own(R, X).\nDecl agg(R, S).\nDecl has_rules(R).\nDecl nonempty(R).\n\
         Decl effective(R, X).\n\
         has_rules(R) :- own(R, _).\n\
         has_rules(R) :- agg(R, S), has_rules(S).\n\
         nonempty(R) :- agg(R, S), has_rules(S).\n\
         effective(R, X) :- own(R, X), !nonempty(R).\n\
         effective(R, X) :- agg(R, S), effective(S, X).",
    );
}

#[test]
fn negation_over_empty_input_relation() {
    // The unexpected_cluster_admin shape: subtract an allow-list (a declared
    // EDB input) that is empty by default. Both backends must treat a
    // declared relation with no rows as the empty set under negation, not as
    // a missing relation. With a row present, that principal is filtered out.
    let rules = "Decl admin(P).\nDecl allowed(P).\nDecl unexpected(P).\n\
         unexpected(P) :- admin(P), !allowed(P).";

    let empty_list = edb(&[("admin", vec![s("alice")]), ("admin", vec![s("bob")])]);
    assert_parity("negation_over_empty_allowlist", &empty_list, rules);

    let with_row = edb(&[
        ("admin", vec![s("alice")]),
        ("admin", vec![s("bob")]),
        ("allowed", vec![s("bob")]),
    ]);
    assert_parity("negation_over_nonempty_allowlist", &with_row, rules);
}

#[test]
fn join_on_struct_column() {
    // Equal structs built separately must join. A struct with the same
    // fields in another order, or another value, must compare the same way
    // on both backends.
    let rule = record(&[("verbs", s("get")), ("resources", s("pods"))]);
    let reordered = record(&[("resources", s("pods")), ("verbs", s("get"))]);
    let other = record(&[("verbs", s("list")), ("resources", s("pods"))]);
    let e = edb(&[
        ("grant", vec![s("alice"), rule.clone()]),
        ("grant", vec![s("bob"), other.clone()]),
        ("needs", vec![rule, n(1)]),
        ("needs", vec![reordered, n(2)]),
        ("needs", vec![other, n(3)]),
    ]);
    assert_parity(
        "struct_join",
        &e,
        "Decl grant(P, R).\nDecl needs(R, I).\nDecl satisfied(P, I).\n\
         satisfied(P, I) :- grant(P, R), needs(R, I).",
    );
}

#[test]
fn constants_in_body() {
    let e = edb(&[
        ("perm", vec![s("alice"), s("read")]),
        ("perm", vec![s("alice"), s("write")]),
        ("perm", vec![s("bob"), s("read")]),
    ]);
    assert_parity(
        "constant_filter",
        &e,
        "Decl perm(P, Verb).\nDecl can_read(P).\n\
         can_read(P) :- perm(P, \"read\").",
    );
}

#[test]
fn ground_facts_as_rules() {
    let e: Edb = vec![];
    assert_parity(
        "ground_rules",
        &e,
        "Decl kind(K).\nDecl allowed(K).\n\
         kind(\"pod\").\nkind(\"service\").\n\
         allowed(K) :- kind(K).",
    );
}

#[test]
fn empty_result() {
    // a and b are disjoint, so the join `both` is empty in both backends.
    let e = edb(&[("a", vec![n(1)]), ("b", vec![n(2)])]);
    assert_parity(
        "empty_join",
        &e,
        "Decl a(X).\nDecl b(X).\nDecl both(X).\n\
         both(X) :- a(X), b(X).",
    );
}

#[test]
fn dedup_multiple_derivations() {
    // Node 2 is derived twice (as a source and a target); must dedup.
    let e = edb(&[("edge", vec![n(1), n(2)]), ("edge", vec![n(2), n(3)])]);
    assert_parity(
        "dedup",
        &e,
        "Decl edge(A, B).\nDecl touched(N).\n\
         touched(X) :- edge(X, _).\n\
         touched(X) :- edge(_, X).",
    );
}

#[test]
fn mixed_value_types() {
    let e = edb(&[
        ("rec", vec![n(1), s("a"), Value::Float(1.5)]),
        ("rec", vec![n(2), s("b"), Value::Float(2.5)]),
    ]);
    assert_parity(
        "value_types",
        &e,
        "Decl rec(I, S, F).\nDecl copy(I, S, F).\n\
         copy(I, S, F) :- rec(I, S, F).",
    );
}

#[test]
fn name_constant_and_strings_in_one_column() {
    // One column holding a /name constant next to strings, as ResourceName
    // does in rules/rbac_roles.mg: /any for every name, or a literal name,
    // including "". A join on the column must not equate /any with a string.
    let e = edb(&[
        ("rule", vec![s("r1")]),
        ("rule", vec![s("r2")]),
        ("rule", vec![s("r3")]),
        ("rule_name", vec![s("r2"), s("web")]),
        ("rule_name", vec![s("r3"), s("")]),
        ("request", vec![n(1), s("web")]),
        ("request", vec![n(2), s("")]),
        ("request", vec![n(3), s("other")]),
    ]);
    assert_parity(
        "name_and_strings",
        &e,
        "Decl rule(R).\nDecl rule_name(R, N).\nDecl request(I, N).\n\
         Decl named(R).\nDecl scope(R, N).\nDecl request_name(I, N).\nDecl allowed(I, R).\n\
         named(R) :- rule_name(R, _).\n\
         scope(R, /any) :- rule(R), !named(R).\n\
         scope(R, N) :- rule_name(R, N).\n\
         request_name(I, /any) :- request(I, _).\n\
         request_name(I, N) :- request(I, N).\n\
         allowed(I, R) :- request_name(I, N), scope(R, N).",
    );
}

#[test]
fn infix_numeric_comparison() {
    // Infix <, >, <=, >= as body terms (bound var vs constant) -> Cmp Lt/Gt/Le/Ge.
    let e = edb(&[
        ("val", vec![n(5)]),
        ("val", vec![n(10)]),
        ("val", vec![n(15)]),
    ]);
    assert_parity(
        "comparison_ops",
        &e,
        "Decl val(N).\nDecl above(N).\nDecl below(N).\nDecl at_least(N).\nDecl at_most(N).\n\
         above(N) :- val(N), N > 10.\n\
         below(N) :- val(N), N < 10.\n\
         at_least(N) :- val(N), N >= 10.\n\
         at_most(N) :- val(N), N <= 10.",
    );
}

#[test]
fn comparison_two_variables() {
    // Comparison between two bound variables (X < Y) over a self cross-product.
    let e = edb(&[("p", vec![n(1)]), ("p", vec![n(2)]), ("p", vec![n(3)])]);
    assert_parity(
        "two_var_cmp",
        &e,
        "Decl p(N).\nDecl less(X, Y).\n\
         less(X, Y) :- p(X), p(Y), X < Y.",
    );
}

#[test]
fn comparison_neq() {
    // `!=` takes the Ineq path -> Cmp Neq.
    let e = edb(&[
        ("val", vec![n(5)]),
        ("val", vec![n(10)]),
        ("val", vec![n(15)]),
    ]);
    assert_parity(
        "neq",
        &e,
        "Decl val(N).\nDecl not_ten(N).\n\
         not_ten(N) :- val(N), N != 10.",
    );
}

#[test]
fn aggregate_float_sum_max_min() {
    // Category b mixes a Number into a float group; fn:float:sum widens it.
    let e = edb(&[
        ("reading", vec![s("a"), f(1.5)]),
        ("reading", vec![s("a"), f(-2.25)]),
        ("reading", vec![s("a"), f(4.0)]),
        ("reading", vec![s("b"), f(0.5)]),
        ("reading", vec![s("b"), n(2)]),
    ]);
    assert_parity(
        "float_aggregates",
        &e,
        "Decl reading(Cat, V).\nDecl total(Cat, S).\nDecl hi(Cat, M).\nDecl lo(Cat, M).\n\
         total(Cat, S) :- reading(Cat, V) |> do fn:group_by(Cat), let S = fn:float:sum(V).\n\
         hi(Cat, M) :- reading(Cat, V), Cat = \"a\" |> do fn:group_by(Cat), let M = fn:float:max(V).\n\
         lo(Cat, M) :- reading(Cat, V), Cat = \"a\" |> do fn:group_by(Cat), let M = fn:float:min(V).",
    );
}

#[test]
fn positive_list_member() {
    // The bound-element form iterates the list (IterateList); an empty list
    // and a non-list contribute nothing.
    let e = edb(&[
        ("role", vec![n(1), string_list(&["get", "list"])]),
        ("role", vec![n(2), string_list(&[])]),
        ("role", vec![n(3), string_list(&["get", "get"])]),
        ("role", vec![n(4), s("not a list")]),
    ]);
    assert_parity(
        "positive_list_member",
        &e,
        "Decl role(I, Verbs).\nDecl grants(I, V).\n\
         grants(I, V) :- role(I, Verbs), :list:member(V, Verbs).",
    );
}

#[test]
fn positive_match_field() {
    // The bound-value form reads the field (MatchField); a struct without the
    // field and a non-struct contribute nothing.
    let e = edb(&[
        (
            "rule",
            vec![
                n(1),
                record(&[("verbs", string_list(&["get"])), ("apiGroup", s(""))]),
            ],
        ),
        (
            "rule",
            vec![n(2), record(&[("verbs", string_list(&["list"]))])],
        ),
        ("rule", vec![n(3), s("not a struct")]),
    ]);
    assert_parity(
        "positive_match_field",
        &e,
        "Decl rule(I, R).\nDecl verbs(I, V).\nDecl group(I, G).\n\
         verbs(I, V) :- rule(I, R), :match_field(R, /verbs, V).\n\
         group(I, G) :- rule(I, R), :match_field(R, /apiGroup, G).",
    );
}

#[test]
fn struct_pair_map_list_functions() {
    // Builds compound values with fn:* and reads them back, so both the
    // constructors and the accessors round-trip through Val.
    let e = edb(&[("kv", vec![s("a"), n(1)]), ("kv", vec![s("b"), n(2)])]);
    assert_parity(
        "compound_functions",
        &e,
        "Decl kv(K, V).\nDecl built(K, St, P, M, L).\nDecl read(K, A, B, C, D, Len).\n\
         built(K, St, P, M, L) :- kv(K, V)\n\
           |> let St = fn:struct(/key, K, /value, V),\n\
              let P = fn:pair(K, V),\n\
              let M = fn:map(K, V),\n\
              let L = fn:list(V, K, V).\n\
         read(K, A, B, C, D, Len) :- built(K, St, P, M, L)\n\
           |> let A = fn:struct:get(St, /value),\n\
              let B = fn:pair:first(P),\n\
              let C = fn:map:get(M, K),\n\
              let D = fn:list:get(L, 1),\n\
              let Len = fn:list:len(L).",
    );
}

#[test]
fn time_and_duration_values() {
    // Time and Duration facts, time arithmetic, and comparisons on both.
    let hour = 3_600_000_000_000;
    let e = edb(&[
        ("issued", vec![s("t1"), Value::Time(0)]),
        ("issued", vec![s("t2"), Value::Time(5 * hour)]),
        ("ttl", vec![s("t1"), Value::Duration(hour)]),
        ("ttl", vec![s("t2"), Value::Duration(10 * hour)]),
        ("now", vec![Value::Time(3 * hour)]),
    ]);
    assert_parity(
        "time_duration",
        &e,
        "Decl issued(Tok, T).\nDecl ttl(Tok, D).\nDecl now(N).\n\
         Decl expires(Tok, E).\nDecl expired(Tok).\nDecl ttl_limit(Tok, D, L).\nDecl long_lived(Tok).\n\
         expires(Tok, E) :- issued(Tok, T), ttl(Tok, D) |> let E = fn:time:add(T, D).\n\
         expired(Tok) :- expires(Tok, E), now(N), E < N.\n\
         ttl_limit(Tok, D, L) :- ttl(Tok, D) |> let L = fn:duration:from_hours(2).\n\
         long_lived(Tok) :- ttl_limit(Tok, D, L), D > L.",
    );
}

#[test]
fn let_function_error_fails_both_backends() {
    // A type error inside a `let` fails evaluation on both backends rather
    // than dropping the row on one of them.
    let e = edb(&[("num", vec![n(1)]), ("num", vec![s("x")])]);
    let rules = vec![
        "Decl num(X).\nDecl next(Y).\nnext(Y) :- num(X) |> let Y = fn:plus(X, 1).".to_string(),
    ];
    let interp = InterpreterBackend
        .evaluate(&e, &rules)
        .err()
        .expect("interpreter should fail");
    let dd = DdBackend { provenance: false }
        .evaluate(&e, &rules)
        .err()
        .expect("dd should fail");
    for err in [interp, dd] {
        assert!(
            format!("{err:#}").contains("fn:plus: expected integer"),
            "unexpected error: {err:#}"
        );
    }
}

// ---------------------------------------------------------------------------
// Property-based: random EDBs, fixed rule shapes
// ---------------------------------------------------------------------------

/// Small deterministic PRNG (LCG) — avoids a `rand` dev-dependency and keeps
/// failures reproducible by seed.
struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self {
        // Nudge away from 0 so the first output is non-trivial.
        Lcg(seed
            .wrapping_mul(2862933555777941757)
            .wrapping_add(3037000493))
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

/// Build a random directed graph as `edge` facts (may include self-loops,
/// duplicates, and cycles).
fn random_graph(rng: &mut Lcg, nodes: u64) -> Edb {
    let n_edges = rng.below(nodes * 2 + 1);
    (0..n_edges)
        .map(|_| {
            let a = rng.below(nodes) as i64;
            let b = rng.below(nodes) as i64;
            ("edge".to_string(), vec![n(a), n(b)])
        })
        .collect()
}

#[test]
fn property_transitive_closure_random_graphs() {
    let rules = "Decl edge(A, B).\nDecl path(A, B).\n\
         path(X, Y) :- edge(X, Y).\n\
         path(X, Z) :- path(X, Y), edge(Y, Z).";
    for seed in 0..40u64 {
        let mut rng = Lcg::new(seed.wrapping_add(1));
        let nodes = 2 + rng.below(6); // 2..=7 nodes
        let e = random_graph(&mut rng, nodes);
        assert_parity(&format!("tc_seed_{seed}"), &e, rules);
    }
}

#[test]
fn property_negation_random_graphs() {
    let rules = "Decl node(N).\nDecl edge(A, B).\nDecl reachable(A, B).\nDecl unreachable(A, B).\n\
         reachable(X, Y) :- edge(X, Y).\n\
         reachable(X, Z) :- reachable(X, Y), edge(Y, Z).\n\
         unreachable(X, Y) :- node(X), node(Y), !reachable(X, Y).";
    for seed in 0..30u64 {
        let mut rng = Lcg::new(seed.wrapping_add(100));
        let nodes = 2 + rng.below(5); // 2..=6 nodes
        let mut e: Edb = (0..nodes)
            .map(|i| ("node".to_string(), vec![n(i as i64)]))
            .collect();
        e.extend(random_graph(&mut rng, nodes));
        assert_parity(&format!("neg_seed_{seed}"), &e, rules);
    }
}
