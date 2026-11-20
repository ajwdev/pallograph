// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Random-program parity tests (differential testing). proptest generates
//! small Mangle programs with input facts, and every one must derive the same
//! facts on the DD backend as on the interpreter, which is the oracle.
//!
//! This checks that DD matches mangle-rs, not that either is correct
//! Datalog. Both backends share Mangle's parser, analysis and planner, so a
//! bug in those passes unseen. A disagreement that is a mangle-rs bug goes in
//! the known-bugs list in `AGENTS.md`, and [`repair`] steers around it.
//!
//! `dd_interp_parity.rs` holds one hand-written case per Datalog feature;
//! these find the bugs that need several features at once. The current
//! generator covers positive programs: joins, recursion (mutual too),
//! repeated variables, constants in the body, numbers and strings in one
//! column, and input facts loaded more than once.
//!
//! Strategies produce a loose [`RawProgram`] and [`repair`] turns it into a
//! valid one, so a program proptest shrinks stays valid and a failure is
//! always a backend disagreement, never a program Mangle rejects. A failure
//! prints the shrunk case as a `#[test]` ready to paste into
//! `dd_interp_parity.rs`. `PROPTEST_CASES=<n>` runs more cases than the
//! default 256.

mod common;

use common::{Edb, check_parity, n, s};
use mangle_common::Value;
use proptest::prelude::*;
use proptest::sample::Index;

/// The variables a rule draws from. Few names, so atoms share variables and
/// joins match.
const VARIABLES: [&str; 4] = ["A", "B", "C", "D"];

/// Relations have arity 1 to `MAX_ARITY`. Strategies always generate
/// `MAX_ARITY` terms or values, and [`repair`] cuts them to the arity.
const MAX_ARITY: usize = 3;

/// A value from a small domain, so facts collide in joins and repeat.
#[derive(Clone, Copy, Debug)]
enum Constant {
    Number(i64),
    Text(&'static str),
}

impl Constant {
    fn value(self) -> Value {
        match self {
            Constant::Number(x) => n(x),
            Constant::Text(x) => s(x),
        }
    }

    /// The constant as Mangle source.
    fn source(self) -> String {
        match self {
            Constant::Number(x) => x.to_string(),
            Constant::Text(x) => format!("{x:?}"),
        }
    }

    /// The constant as a `dd_interp_parity.rs` helper call.
    fn rust(self) -> String {
        match self {
            Constant::Number(x) => format!("n({x})"),
            Constant::Text(x) => format!("s({x:?})"),
        }
    }
}

#[derive(Clone, Debug)]
enum Term {
    Variable(usize),
    Constant(Constant),
}

/// A body atom. `relation` picks from inputs and derived relations alike.
#[derive(Clone, Debug)]
struct Atom {
    relation: Index,
    terms: Vec<Term>,
}

/// A rule before repair. `head` picks a derived relation, and each of
/// `head_variables` picks one of the variables the body binds.
#[derive(Clone, Debug)]
struct Rule {
    head: Index,
    head_variables: Vec<Index>,
    body: Vec<Atom>,
}

/// What the strategies generate. Relations are named by position: inputs
/// (EDB) are `e0`, `e1`, ... and derived relations (IDB) are `d0`, `d1`, ...
/// `duplicates` each pick a fact to load a second time.
#[derive(Clone, Debug)]
struct RawProgram {
    input_arities: Vec<usize>,
    derived_arities: Vec<usize>,
    /// One per derived relation, in order; atoms only read inputs.
    base_rules: Vec<Rule>,
    rules: Vec<Rule>,
    facts: Vec<(Index, Vec<Constant>)>,
    duplicates: Vec<Index>,
}

/// A valid program and its input facts, ready to run.
struct Case {
    /// Every relation as `(name, arity)`, inputs first.
    relations: Vec<(String, usize)>,
    rules: Vec<String>,
    facts: Vec<(String, Vec<Constant>)>,
}

fn constant() -> impl Strategy<Value = Constant> {
    prop_oneof![
        3 => (0..3i64).prop_map(Constant::Number),
        1 => Just(Constant::Text("x")),
    ]
}

fn term() -> impl Strategy<Value = Term> {
    prop_oneof![
        4 => (0..VARIABLES.len()).prop_map(Term::Variable),
        1 => constant().prop_map(Term::Constant),
    ]
}

fn atom() -> impl Strategy<Value = Atom> {
    (any::<Index>(), prop::collection::vec(term(), MAX_ARITY))
        .prop_map(|(relation, terms)| Atom { relation, terms })
}

fn rule() -> impl Strategy<Value = Rule> {
    (
        any::<Index>(),
        prop::collection::vec(any::<Index>(), MAX_ARITY),
        prop::collection::vec(atom(), 1..=3),
    )
        .prop_map(|(head, head_variables, body)| Rule {
            head,
            head_variables,
            body,
        })
}

fn raw_program() -> impl Strategy<Value = RawProgram> {
    (
        prop::collection::vec(1..=MAX_ARITY, 1..=3),
        prop::collection::vec(1..=MAX_ARITY, 1..=3),
        prop::collection::vec(rule(), 3),
        prop::collection::vec(rule(), 0..=6),
        prop::collection::vec(
            (any::<Index>(), prop::collection::vec(constant(), MAX_ARITY)),
            4..=24,
        ),
        prop::collection::vec(any::<Index>(), 0..=4),
    )
        .prop_map(
            |(input_arities, derived_arities, base_rules, rules, facts, duplicates)| RawProgram {
                input_arities,
                derived_arities,
                base_rules,
                rules,
                facts,
                duplicates,
            },
        )
}

/// Turn a generated program into a valid one. Pure, so shrinking is
/// deterministic: every program proptest tries goes through here.
///
/// - Each atom's terms and each fact's values are cut to the relation's arity.
/// - A derived relation appears at most once per body, steering around the
///   interpreter's nonlinear recursion bug (see `AGENTS.md`). A repeat is
///   dropped.
/// - Head variables are taken from the variables the body binds (range
///   restriction). A rule whose body binds none, with a head that needs some,
///   is dropped.
fn repair(raw: &RawProgram) -> Case {
    let inputs = raw.input_arities.len();
    let relations: Vec<(String, usize)> = raw
        .input_arities
        .iter()
        .enumerate()
        .map(|(i, &arity)| (format!("e{i}"), arity))
        .chain(
            raw.derived_arities
                .iter()
                .enumerate()
                .map(|(i, &arity)| (format!("d{i}"), arity)),
        )
        .collect();

    let mut facts: Vec<(String, Vec<Constant>)> = raw
        .facts
        .iter()
        .map(|(relation, values)| {
            let (name, arity) = &relations[relation.index(inputs)];
            (name.clone(), values[..*arity].to_vec())
        })
        .collect();
    if !facts.is_empty() {
        for duplicate in &raw.duplicates {
            facts.push(facts[duplicate.index(facts.len())].clone());
        }
    }

    // One base rule per derived relation reads only inputs, so recursion
    // has something to start from.
    let derived = raw.derived_arities.len();
    let base = raw
        .base_rules
        .iter()
        .take(derived)
        .enumerate()
        .filter_map(|(i, rule)| render_rule(rule, inputs + i, inputs, inputs, &relations));
    let general = raw.rules.iter().filter_map(|rule| {
        let head = inputs + rule.head.index(derived);
        render_rule(rule, head, relations.len(), inputs, &relations)
    });
    let rules = base.chain(general).collect();

    Case {
        relations,
        rules,
        facts,
    }
}

/// Render one rule with `head` as its head relation, its atoms picking from
/// the first `candidates` relations. `None` when the body binds no variable,
/// since every head needs one.
fn render_rule(
    rule: &Rule,
    head: usize,
    candidates: usize,
    inputs: usize,
    relations: &[(String, usize)],
) -> Option<String> {
    let mut bound: Vec<usize> = Vec::new();
    let mut body = Vec::new();
    let mut derived_used: Vec<usize> = Vec::new();
    for atom in &rule.body {
        let relation = atom.relation.index(candidates);
        if relation >= inputs {
            if derived_used.contains(&relation) {
                continue;
            }
            derived_used.push(relation);
        }
        let (name, arity) = &relations[relation];
        let terms: Vec<String> = atom.terms[..*arity]
            .iter()
            .map(|term| match term {
                Term::Variable(v) => {
                    bound.push(*v);
                    VARIABLES[*v].to_string()
                }
                Term::Constant(c) => c.source(),
            })
            .collect();
        body.push(format!("{name}({})", terms.join(", ")));
    }
    bound.sort();
    bound.dedup();
    if bound.is_empty() {
        return None;
    }

    let (head_name, head_arity) = &relations[head];
    let head: Vec<&str> = rule.head_variables[..*head_arity]
        .iter()
        .map(|pick| VARIABLES[bound[pick.index(bound.len())]])
        .collect();
    Some(format!(
        "{head_name}({}) :- {}.",
        head.join(", "),
        body.join(", ")
    ))
}

impl Case {
    fn edb(&self) -> Edb {
        self.facts
            .iter()
            .map(|(name, values)| {
                (
                    name.clone(),
                    values.iter().map(|value| value.value()).collect(),
                )
            })
            .collect()
    }

    /// The program as Mangle source: a `Decl` per relation, then the rules.
    fn source(&self) -> String {
        let declarations = self.relations.iter().map(|(name, arity)| {
            let columns: Vec<String> = (0..*arity).map(|i| format!("X{i}")).collect();
            format!("Decl {name}({}).", columns.join(", "))
        });
        declarations
            .chain(self.rules.iter().cloned())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The case as a test for `dd_interp_parity.rs`.
    fn paste_ready_test(&self) -> String {
        let mut out = String::from("#[test]\nfn generated_case() {\n    let e = edb(&[\n");
        for (name, values) in &self.facts {
            let values: Vec<String> = values.iter().map(|value| value.rust()).collect();
            out.push_str(&format!(
                "        ({name:?}, vec![{}]),\n",
                values.join(", ")
            ));
        }
        out.push_str(&format!(
            "    ]);\n    let rules = {:?};\n    assert_parity(\"generated_case\", &e, rules);\n}}\n",
            self.source()
        ));
        out
    }
}

proptest! {
    #[test]
    fn positive_programs_match(raw in raw_program()) {
        let case = repair(&raw);
        let result = check_parity("generated", &case.edb(), &case.source(), false);
        prop_assert!(
            result.is_ok(),
            "{}\n\nAs a test:\n\n{}",
            result.unwrap_err(),
            case.paste_ready_test()
        );
    }
}
