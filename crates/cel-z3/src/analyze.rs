//! Generic static-analysis primitives over translated CEL boolean expressions.

use std::collections::HashMap;

use z3::ast::Bool;
use z3::{SatResult, Solver};

use crate::env::Env;
use crate::error::{CelZ3Error, Result};
use crate::translate::Translator;

/// A translated CEL boolean expression, ready for analysis.
pub struct BoolExpr<'ctx>(Bool<'ctx>);

impl<'ctx> BoolExpr<'ctx> {
    /// The underlying Z3 boolean, for callers that want to compose further.
    pub fn as_z3(&self) -> &Bool<'ctx> {
        &self.0
    }
}

/// A concrete value assigned to a declared path in a satisfying model.
#[derive(Debug, Clone, PartialEq)]
pub enum ModelValue {
    Int(i64),
    Real(f64),
    Bool(bool),
    String(String),
}

/// A satisfying assignment: declared path -> concrete value.
pub type Assignment = HashMap<String, ModelValue>;

/// Translates CEL expressions and answers static-analysis questions about them
/// against a declared type environment.
pub struct Analyzer<'ctx, 'e> {
    ctx: &'ctx z3::Context,
    translator: Translator<'ctx, 'e>,
}

impl<'ctx, 'e> Analyzer<'ctx, 'e> {
    pub fn new(ctx: &'ctx z3::Context, env: &'e Env) -> Self {
        Self {
            ctx,
            translator: Translator::new(ctx, env),
        }
    }

    /// Parse and translate a CEL expression. The top-level expression must be
    /// boolean; otherwise a `TypeMismatch` is returned.
    pub fn translate(&self, src: &str) -> Result<BoolExpr<'ctx>> {
        let d = self.translator.translate_str(src)?;
        let b = d.as_bool().ok_or_else(|| CelZ3Error::TypeMismatch {
            expected: "bool".into(),
            found: format!("{:?}", d.sort_kind()),
            context: "top-level expression".into(),
        })?;
        Ok(BoolExpr(b))
    }

    /// Is there any assignment satisfying `a`?
    pub fn is_satisfiable(&self, a: &BoolExpr<'ctx>) -> bool {
        let s = Solver::new(self.ctx);
        s.assert(&a.0);
        s.check() == SatResult::Sat
    }

    /// Is `a` true under every assignment? (`¬a` is unsatisfiable.)
    pub fn is_tautology(&self, a: &BoolExpr<'ctx>) -> bool {
        let s = Solver::new(self.ctx);
        s.assert(&a.0.not());
        s.check() == SatResult::Unsat
    }

    /// Does `a` imply `b`? (`a ∧ ¬b` is unsatisfiable.)
    pub fn implies(&self, a: &BoolExpr<'ctx>, b: &BoolExpr<'ctx>) -> bool {
        let s = Solver::new(self.ctx);
        s.assert(&Bool::and(self.ctx, &[&a.0, &b.0.not()]));
        s.check() == SatResult::Unsat
    }

    /// Are `a` and `b` logically equivalent? (`a XOR b` is unsatisfiable.)
    pub fn equivalent(&self, a: &BoolExpr<'ctx>, b: &BoolExpr<'ctx>) -> bool {
        let s = Solver::new(self.ctx);
        s.assert(&a.0.xor(&b.0));
        s.check() == SatResult::Unsat
    }

    /// If `a` is satisfiable, return one satisfying assignment over the declared
    /// paths it references (a concrete witness / counterexample).
    pub fn model_for(&self, a: &BoolExpr<'ctx>) -> Option<Assignment> {
        let s = Solver::new(self.ctx);
        s.assert(&a.0);
        if s.check() != SatResult::Sat {
            return None;
        }
        let model = s.get_model()?;
        let mut out = Assignment::new();
        for (path, c) in self.translator.consts() {
            let Some(v) = model.eval(&c, true) else {
                continue;
            };
            let mv = if let Some(b) = v.as_bool().and_then(|b| b.as_bool()) {
                ModelValue::Bool(b)
            } else if let Some(i) = v.as_int().and_then(|i| i.as_i64()) {
                ModelValue::Int(i)
            } else if let Some((n, d)) = v.as_real().and_then(|r| r.as_real()) {
                ModelValue::Real(n as f64 / d as f64)
            } else if let Some(s) = v.as_string().and_then(|s| s.as_string()) {
                ModelValue::String(s)
            } else {
                continue;
            };
            out.insert(path, mv);
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::{CelType, Env};
    use z3::{Config, Context};

    fn analyzer_ctx() -> Context {
        Context::new(&Config::new())
    }

    fn env(decls: &[(&str, CelType)]) -> Env {
        let mut env = Env::new();
        for (p, t) in decls {
            env.declare(*p, *t);
        }
        env
    }

    #[test]
    fn tautology_and_contradiction() {
        let ctx = analyzer_ctx();
        let env = env(&[("x", CelType::Int)]);
        let a = Analyzer::new(&ctx, &env);

        assert!(a.is_tautology(&a.translate("x >= 0 || x < 0").unwrap()));
        assert!(!a.is_satisfiable(&a.translate("x > 5 && x < 3").unwrap()));
    }

    #[test]
    fn implication_holds_one_way() {
        let ctx = analyzer_ctx();
        let env = env(&[("x", CelType::Int)]);
        let a = Analyzer::new(&ctx, &env);

        let narrow = a.translate("x <= 5").unwrap();
        let wide = a.translate("x <= 10").unwrap();
        assert!(a.implies(&narrow, &wide));
        assert!(!a.implies(&wide, &narrow));
    }

    #[test]
    fn equivalence() {
        let ctx = analyzer_ctx();
        let env = env(&[("x", CelType::Int)]);
        let a = Analyzer::new(&ctx, &env);

        assert!(a.equivalent(
            &a.translate("x <= 5").unwrap(),
            &a.translate("!(x > 5)").unwrap()
        ));
        assert!(!a.equivalent(
            &a.translate("x <= 5").unwrap(),
            &a.translate("x <= 6").unwrap()
        ));
    }

    #[test]
    fn model_for_yields_counterexample() {
        let ctx = analyzer_ctx();
        let env = env(&[("x", CelType::Int)]);
        let a = Analyzer::new(&ctx, &env);

        // Counterexample to "x <= 5 implies x <= 3": a value with x<=5 but x>3.
        let f = a.translate("x <= 5 && x > 3").unwrap();
        let model = a.model_for(&f).expect("should be satisfiable");
        match model.get("x") {
            Some(ModelValue::Int(v)) => assert!(*v > 3 && *v <= 5, "got x={v}"),
            other => panic!("expected Int assignment for x, got {other:?}"),
        }
    }

    #[test]
    fn model_for_unsatisfiable_is_none() {
        let ctx = analyzer_ctx();
        let env = env(&[("x", CelType::Int)]);
        let a = Analyzer::new(&ctx, &env);
        assert!(a.model_for(&a.translate("x > 5 && x < 3").unwrap()).is_none());
    }

    #[test]
    fn non_boolean_top_level_is_type_mismatch() {
        use crate::error::CelZ3Error;
        let ctx = analyzer_ctx();
        let env = env(&[("x", CelType::Int)]);
        let a = Analyzer::new(&ctx, &env);
        assert!(matches!(
            a.translate("x + 1"),
            Err(CelZ3Error::TypeMismatch { .. })
        ));
    }
}
