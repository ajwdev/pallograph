// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Random-program tests against an outside oracle. proptest generates small
//! Mangle programs with input facts, and each one runs on the DD backend, on
//! the interpreter, and through Soufflé (the `souffle` binary, from the Nix
//! dev shell). Both backends must derive the facts Soufflé does.
//!
//! Soufflé shares no code with mangle-rs, so this checks Datalog semantics,
//! not just that the two backends agree: a bug in Mangle's parser, analysis
//! or planner that both backends inherit shows up here. The interpreter is
//! skipped on programs that hit its nonlinear recursion bug (see
//! `AGENTS.md`); DD is checked on every program.
//!
//! `dd_interp_parity.rs` holds one hand-written case per Datalog feature;
//! these find the bugs that need several features at once. The current
//! generator covers positive programs: joins, recursion (mutual too),
//! repeated variables, constants in the body, numbers and strings in one
//! column, and input facts loaded more than once.
//!
//! Strategies produce a loose [`RawProgram`] and [`repair`] turns it into a
//! valid one, so a program proptest shrinks stays valid and a failure is
//! always a wrong answer, never a program Mangle or Soufflé rejects. A failure
//! prints the shrunk case as a `#[test]` ready to paste into
//! `dd_interp_parity.rs`. `PROPTEST_CASES=<n>` runs more cases than the
//! default 256.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{Edb, n, s};
use mangle_common::Value;
use pallograph::engine::{Backend, DdBackend, InterpreterBackend};
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

    /// The constant as a Soufflé `symbol`. The generator only compares
    /// values for equality, so tagging numbers `n` and strings `s` keeps
    /// their meaning without Soufflé's separate number and symbol types.
    fn souffle(self) -> String {
        match self {
            Constant::Number(x) => format!("\"n{x}\""),
            Constant::Text(x) => format!("\"s{x}\""),
        }
    }

    /// Decode a value from Soufflé output, written by [`Self::souffle`].
    fn from_souffle(cell: &str) -> Value {
        match cell.split_at(1) {
            ("n", number) => n(number.parse().expect("souffle number")),
            ("s", text) => s(text),
            _ => panic!("unexpected souffle value {cell:?}"),
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

/// A rule after repair: relations by position, variables by index into
/// [`VARIABLES`].
struct ValidRule {
    head: usize,
    head_variables: Vec<usize>,
    body: Vec<(usize, Vec<Term>)>,
}

/// A valid program and its input facts, ready to run.
struct Case {
    /// How many of `relations` are inputs; the rest are derived.
    inputs: usize,
    /// Every relation as `(name, arity)`, inputs first.
    relations: Vec<(String, usize)>,
    rules: Vec<ValidRule>,
    facts: Vec<(usize, Vec<Constant>)>,
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

    let mut facts: Vec<(usize, Vec<Constant>)> = raw
        .facts
        .iter()
        .map(|(relation, values)| {
            let relation = relation.index(inputs);
            (relation, values[..relations[relation].1].to_vec())
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
        .filter_map(|(i, rule)| repair_rule(rule, inputs + i, inputs, &relations));
    let general = raw.rules.iter().filter_map(|rule| {
        let head = inputs + rule.head.index(derived);
        repair_rule(rule, head, relations.len(), &relations)
    });
    let rules = base.chain(general).collect();

    Case {
        inputs,
        relations,
        rules,
        facts,
    }
}

/// Repair one rule with `head` as its head relation, its atoms picking from
/// the first `candidates` relations. `None` when the body binds no variable,
/// since every head needs one.
fn repair_rule(
    rule: &Rule,
    head: usize,
    candidates: usize,
    relations: &[(String, usize)],
) -> Option<ValidRule> {
    let body: Vec<(usize, Vec<Term>)> = rule
        .body
        .iter()
        .map(|atom| {
            let relation = atom.relation.index(candidates);
            (relation, atom.terms[..relations[relation].1].to_vec())
        })
        .collect();
    let mut bound: Vec<usize> = body
        .iter()
        .flat_map(|(_, terms)| terms)
        .filter_map(|term| match term {
            Term::Variable(v) => Some(*v),
            Term::Constant(_) => None,
        })
        .collect();
    bound.sort();
    bound.dedup();
    if bound.is_empty() {
        return None;
    }
    let head_variables = rule.head_variables[..relations[head].1]
        .iter()
        .map(|pick| bound[pick.index(bound.len())])
        .collect();
    Some(ValidRule {
        head,
        head_variables,
        body,
    })
}

/// Facts per derived relation, as one engine derived them.
type Derived = BTreeMap<String, BTreeSet<Vec<Value>>>;

impl Case {
    fn derived_names(&self) -> impl Iterator<Item = &str> {
        self.relations[self.inputs..]
            .iter()
            .map(|(name, _)| name.as_str())
    }

    /// Whether a rule body uses a derived relation twice, which the
    /// interpreter's nonlinear recursion bug can get wrong (see `AGENTS.md`).
    fn has_nonlinear_rule(&self) -> bool {
        self.rules.iter().any(|rule| {
            let derived: Vec<usize> = rule
                .body
                .iter()
                .map(|(relation, _)| *relation)
                .filter(|relation| *relation >= self.inputs)
                .collect();
            (1..derived.len()).any(|i| derived[..i].contains(&derived[i]))
        })
    }

    fn edb(&self) -> Edb {
        self.facts
            .iter()
            .map(|(relation, values)| {
                (
                    self.relations[*relation].0.clone(),
                    values.iter().map(|value| value.value()).collect(),
                )
            })
            .collect()
    }

    /// Render the rules with `constant` writing each constant.
    fn render_rules(&self, constant: impl Fn(Constant) -> String) -> Vec<String> {
        let atom = |relation: usize, terms: &[Term]| {
            let terms: Vec<String> = terms
                .iter()
                .map(|term| match term {
                    Term::Variable(v) => VARIABLES[*v].to_string(),
                    Term::Constant(c) => constant(*c),
                })
                .collect();
            format!("{}({})", self.relations[relation].0, terms.join(", "))
        };
        self.rules
            .iter()
            .map(|rule| {
                let head: Vec<&str> = rule.head_variables.iter().map(|v| VARIABLES[*v]).collect();
                let body: Vec<String> = rule
                    .body
                    .iter()
                    .map(|(relation, terms)| atom(*relation, terms))
                    .collect();
                format!(
                    "{}({}) :- {}.",
                    self.relations[rule.head].0,
                    head.join(", "),
                    body.join(", ")
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
            .chain(self.render_rules(Constant::source))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The program and its facts as Soufflé source. Every column is a
    /// `symbol` (see [`Constant::souffle`]), and every derived relation is an
    /// output.
    fn souffle_source(&self) -> String {
        let mut lines: Vec<String> = Vec::new();
        for (name, arity) in &self.relations {
            let columns: Vec<String> = (0..*arity).map(|i| format!("x{i}: symbol")).collect();
            lines.push(format!(".decl {name}({})", columns.join(", ")));
        }
        for name in self.derived_names() {
            lines.push(format!(".output {name}"));
        }
        for (relation, values) in &self.facts {
            let values: Vec<String> = values.iter().map(|value| value.souffle()).collect();
            lines.push(format!(
                "{}({}).",
                self.relations[*relation].0,
                values.join(", ")
            ));
        }
        lines.extend(self.render_rules(Constant::souffle));
        lines.join("\n")
    }

    /// The case as a test for `dd_interp_parity.rs`.
    fn paste_ready_test(&self) -> String {
        let mut out = String::from("#[test]\nfn generated_case() {\n    let e = edb(&[\n");
        for (relation, values) in &self.facts {
            let values: Vec<String> = values.iter().map(|value| value.rust()).collect();
            out.push_str(&format!(
                "        ({:?}, vec![{}]),\n",
                self.relations[*relation].0,
                values.join(", ")
            ));
        }
        out.push_str(&format!(
            "    ]);\n    let rules = {:?};\n    assert_parity(\"generated_case\", &e, rules);\n}}\n",
            self.source()
        ));
        out
    }

    fn evaluate(&self, backend: &dyn Backend) -> Result<Derived, String> {
        let store = backend
            .evaluate(&self.edb(), &[self.source()])
            .map_err(|err| format!("{err:#}"))?;
        Ok(self
            .derived_names()
            .map(|name| (name.to_string(), store.scan(name).iter().cloned().collect()))
            .collect())
    }

    /// Run the program through the `souffle` binary and read back every
    /// derived relation.
    fn evaluate_souffle(&self) -> Result<Derived, String> {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "pallograph-souffle-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&directory).map_err(|err| err.to_string())?;
        let program = directory.join("program.dl");
        std::fs::write(&program, self.souffle_source()).map_err(|err| err.to_string())?;

        let output = Command::new("souffle")
            .arg("-w")
            .arg("-D")
            .arg(&directory)
            .arg(&program)
            .output()
            .unwrap_or_else(|err| {
                panic!("could not run souffle ({err}); run the tests in `nix develop`")
            });
        let result = if output.status.success() {
            self.derived_names()
                .map(|name| {
                    let csv = std::fs::read_to_string(directory.join(format!("{name}.csv")))
                        .map_err(|err| format!("{name}.csv: {err}"))?;
                    let rows = csv
                        .lines()
                        .map(|line| line.split('\t').map(Constant::from_souffle).collect())
                        .collect();
                    Ok((name.to_string(), rows))
                })
                .collect()
        } else {
            Err(String::from_utf8_lossy(&output.stderr).into_owned())
        };
        let _ = std::fs::remove_dir_all(&directory);
        result
    }
}

/// Describe where `actual` differs from `expected`, one line per relation.
fn differences(actual: &Derived, expected: &Derived) -> Vec<String> {
    let mut out = Vec::new();
    for (name, want) in expected {
        let got = &actual[name];
        if got != want {
            let missing: Vec<_> = want.difference(got).take(3).collect();
            let extra: Vec<_> = got.difference(want).take(3).collect();
            out.push(format!(
                "  {name}: got {} want {}\n     missing: {missing:?}\n     extra:   {extra:?}",
                got.len(),
                want.len()
            ));
        }
    }
    out
}

/// Check DD, and the interpreter where it has no known bug in play, against
/// Soufflé.
fn check_against_souffle(case: &Case) -> Result<(), String> {
    let souffle = case
        .evaluate_souffle()
        .map_err(|err| format!("souffle failed: {err}"))?;
    let mut engines: Vec<(&str, &dyn Backend)> = vec![("dd", &DdBackend { provenance: false })];
    if !case.has_nonlinear_rule() {
        engines.push(("interpreter", &InterpreterBackend));
    }
    let mut failures = Vec::new();
    for (label, backend) in engines {
        match case.evaluate(backend) {
            Ok(derived) => {
                let lines = differences(&derived, &souffle);
                if !lines.is_empty() {
                    failures.push(format!(
                        "{label} differs from souffle:\n{}",
                        lines.join("\n")
                    ));
                }
            }
            Err(err) => failures.push(format!("{label} failed: {err}")),
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n"))
    }
}

proptest! {
    #[test]
    fn positive_programs_match_souffle(raw in raw_program()) {
        let case = repair(&raw);
        let result = check_against_souffle(&case);
        prop_assert!(
            result.is_ok(),
            "{}\n\nSoufflé program:\n\n{}\n\nAs a test:\n\n{}",
            result.unwrap_err(),
            case.souffle_source(),
            case.paste_ready_test()
        );
    }
}
