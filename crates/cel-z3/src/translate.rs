//! Translate a parsed CEL expression into a Z3 `Dynamic` AST node.

use std::cell::RefCell;
use std::collections::HashMap;

use cel::common::ast::{operators as op, Expr, IdedExpr, LiteralValue, SelectExpr};
use cel::parser::Parser;
use z3::ast::{Ast, Bool, Dynamic, Int, Real};
use z3::ast::String as Z3String;

use crate::env::{CelType, Env};
use crate::error::{CelZ3Error, Result};

/// Translates a parsed CEL expression tree into Z3 `Dynamic` AST nodes against a
/// declared type environment. One Z3 constant is created (and reused) per
/// declared CEL path so the same path is the same Z3 variable everywhere.
pub struct Translator<'ctx, 'e> {
    ctx: &'ctx z3::Context,
    env: &'e Env,
    consts: RefCell<HashMap<String, Dynamic<'ctx>>>,
}

impl<'ctx, 'e> Translator<'ctx, 'e> {
    pub fn new(ctx: &'ctx z3::Context, env: &'e Env) -> Self {
        Self {
            ctx,
            env,
            consts: RefCell::new(HashMap::new()),
        }
    }

    /// Z3 constants created so far, one per referenced declared path. Used by
    /// the analyzer to read concrete values out of a satisfying model.
    pub(crate) fn consts(&self) -> Vec<(String, Dynamic<'ctx>)> {
        self.consts
            .borrow()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Parse `src` as CEL and translate it into a Z3 node.
    pub fn translate_str(&self, src: &str) -> Result<Dynamic<'ctx>> {
        let parsed = Parser::new()
            .parse(src)
            .map_err(|e| CelZ3Error::Parse(format!("{e:?}")))?;
        self.translate(&parsed)
    }

    fn translate(&self, e: &IdedExpr) -> Result<Dynamic<'ctx>> {
        match &e.expr {
            Expr::Literal(lit) => self.literal(lit),
            Expr::Ident(_) => self.path(&e.expr),
            // `has(x.y)` parses to a Select with `test: true`. It is a Bool
            // presence test, but this crate models paths as total variables
            // with no notion of absence, so reject it rather than silently
            // translating it to the field's value.
            Expr::Select(sel) if sel.test => {
                Err(CelZ3Error::Unsupported("has() presence test".into()))
            }
            Expr::Select(_) => self.path(&e.expr),
            Expr::Call(call) => self.call(call.func_name.as_str(), call.target.as_deref(), &call.args),
            Expr::List(_) => Err(CelZ3Error::Unsupported("bare list literal".into())),
            Expr::Map(_) => Err(CelZ3Error::Unsupported("map".into())),
            Expr::Struct(_) => Err(CelZ3Error::Unsupported("struct".into())),
            Expr::Comprehension(_) => {
                Err(CelZ3Error::Unsupported("comprehension macro".into()))
            }
            Expr::Unspecified => Err(CelZ3Error::Unsupported("unspecified expression".into())),
        }
    }

    fn literal(&self, lit: &LiteralValue) -> Result<Dynamic<'ctx>> {
        let d = match lit {
            LiteralValue::Boolean(b) => Bool::from_bool(self.ctx, *b.inner()).into(),
            LiteralValue::Int(i) => Int::from_i64(self.ctx, *i.inner()).into(),
            LiteralValue::UInt(u) => Int::from_u64(self.ctx, *u.inner()).into(),
            LiteralValue::Double(f) => {
                Real::from_real_str(self.ctx, &format!("{}", f.inner()), "1")
                    .ok_or_else(|| CelZ3Error::Unsupported("non-finite double literal".into()))?
                    .into()
            }
            LiteralValue::String(s) => Z3String::from_str(self.ctx, s.inner())
                .map_err(|_| CelZ3Error::Unsupported("string literal with NUL byte".into()))?
                .into(),
            LiteralValue::Null => return Err(CelZ3Error::Unsupported("null literal".into())),
            LiteralValue::Bytes(_) => return Err(CelZ3Error::Unsupported("bytes literal".into())),
        };
        Ok(d)
    }

    /// Flatten an `Ident`/`Select` chain into a dotted path, resolve its declared
    /// type, and return (creating once) the matching Z3 constant.
    fn path(&self, e: &Expr) -> Result<Dynamic<'ctx>> {
        let path = flatten_path(e)
            .ok_or_else(|| CelZ3Error::Unsupported("non-identifier field access".into()))?;
        let ty = self
            .env
            .get(&path)
            .ok_or_else(|| CelZ3Error::UnknownIdentifier(path.clone()))?;

        if let Some(c) = self.consts.borrow().get(&path) {
            return Ok(c.clone());
        }
        let c: Dynamic<'ctx> = match ty {
            CelType::Int => Int::new_const(self.ctx, path.clone()).into(),
            CelType::Real => Real::new_const(self.ctx, path.clone()).into(),
            CelType::String => Z3String::new_const(self.ctx, path.clone()).into(),
            CelType::Bool => Bool::new_const(self.ctx, path.clone()).into(),
        };
        self.consts.borrow_mut().insert(path, c.clone());
        Ok(c)
    }

    fn call(
        &self,
        func: &str,
        target: Option<&IdedExpr>,
        args: &[IdedExpr],
    ) -> Result<Dynamic<'ctx>> {
        match func {
            op::EQUALS | op::NOT_EQUALS | op::LESS | op::LESS_EQUALS | op::GREATER
            | op::GREATER_EQUALS => {
                let l = self.translate(&args[0])?;
                let r = self.translate(&args[1])?;
                self.compare(func, &l, &r)
            }
            op::ADD | op::SUBSTRACT | op::MULTIPLY | op::DIVIDE | op::MODULO => {
                let l = self.translate(&args[0])?;
                let r = self.translate(&args[1])?;
                self.arith(func, &l, &r)
            }
            op::LOGICAL_AND | op::LOGICAL_OR => {
                let l = self.as_bool(&args[0], "logical operand")?;
                let r = self.as_bool(&args[1], "logical operand")?;
                let b = if func == op::LOGICAL_AND {
                    Bool::and(self.ctx, &[&l, &r])
                } else {
                    Bool::or(self.ctx, &[&l, &r])
                };
                Ok(b.into())
            }
            op::LOGICAL_NOT => {
                let b = self.as_bool(&args[0], "logical not operand")?;
                Ok(b.not().into())
            }
            op::NEGATE => {
                let v = self.translate(&args[0])?;
                if let Some(i) = as_int(&v) {
                    Ok(i.unary_minus().into())
                } else if let Some(r) = as_real(&v) {
                    Ok(r.unary_minus().into())
                } else {
                    Err(type_mismatch("unary minus", "number", &v))
                }
            }
            op::CONDITIONAL => {
                let cond = self.as_bool(&args[0], "ternary condition")?;
                let then = self.translate(&args[1])?;
                let els = self.translate(&args[2])?;
                Ok(cond.ite(&then, &els))
            }
            op::IN => self.in_list(&args[0], &args[1]),
            "startsWith" | "endsWith" | "contains" => self.string_method(func, target, args),
            other => Err(CelZ3Error::Unsupported(format!("operator/function `{other}`"))),
        }
    }

    fn as_bool(&self, e: &IdedExpr, context: &str) -> Result<Bool<'ctx>> {
        let d = self.translate(e)?;
        d.as_bool().ok_or_else(|| type_mismatch(context, "bool", &d))
    }

    fn arith(&self, func: &str, l: &Dynamic<'ctx>, r: &Dynamic<'ctx>) -> Result<Dynamic<'ctx>> {
        if let (Some(a), Some(b)) = (as_int(l), as_int(r)) {
            let v: Int<'ctx> = match func {
                op::ADD => Int::add(self.ctx, &[&a, &b]),
                op::SUBSTRACT => Int::sub(self.ctx, &[&a, &b]),
                op::MULTIPLY => Int::mul(self.ctx, &[&a, &b]),
                op::DIVIDE => a.div(&b),
                _ => a.modulo(&b),
            };
            return Ok(v.into());
        }
        let a = as_real(l).ok_or_else(|| type_mismatch("arithmetic", "number", l))?;
        let b = as_real(r).ok_or_else(|| type_mismatch("arithmetic", "number", r))?;
        let v: Real<'ctx> = match func {
            op::ADD => Real::add(self.ctx, &[&a, &b]),
            op::SUBSTRACT => Real::sub(self.ctx, &[&a, &b]),
            op::MULTIPLY => Real::mul(self.ctx, &[&a, &b]),
            op::DIVIDE => a.div(&b),
            _ => return Err(CelZ3Error::Unsupported("modulo on real numbers".into())),
        };
        Ok(v.into())
    }

    fn in_list(&self, elem: &IdedExpr, list: &IdedExpr) -> Result<Dynamic<'ctx>> {
        let Expr::List(list) = &list.expr else {
            return Err(CelZ3Error::Unsupported(
                "`in` with a non-literal right-hand side".into(),
            ));
        };
        let e = self.translate(elem)?;
        let eqs: Vec<Bool<'ctx>> = list
            .elements
            .iter()
            .map(|item| Ok(e._eq(&self.translate(item)?)))
            .collect::<Result<_>>()?;
        let refs: Vec<&Bool<'ctx>> = eqs.iter().collect();
        Ok(Bool::or(self.ctx, &refs).into())
    }

    fn string_method(
        &self,
        func: &str,
        target: Option<&IdedExpr>,
        args: &[IdedExpr],
    ) -> Result<Dynamic<'ctx>> {
        let target = target.ok_or_else(|| {
            CelZ3Error::Unsupported(format!("`{func}` called without a target string"))
        })?;
        let t = self.translate(target)?;
        let t = t.as_string().ok_or_else(|| type_mismatch(func, "string", &t))?;
        let a = self.translate(&args[0])?;
        let a = a.as_string().ok_or_else(|| type_mismatch(func, "string", &a))?;
        // z3 prefix/suffix semantics: `x.prefix(y)` == "x is a prefix of y".
        let b = match func {
            "startsWith" => a.prefix(&t), // arg is a prefix of target
            "endsWith" => a.suffix(&t),   // arg is a suffix of target
            _ => t.contains(&a),          // target contains arg
        };
        Ok(b.into())
    }

    fn compare(&self, func: &str, l: &Dynamic<'ctx>, r: &Dynamic<'ctx>) -> Result<Dynamic<'ctx>> {
        let b = match func {
            op::EQUALS => l._eq(r),
            op::NOT_EQUALS => l._eq(r).not(),
            _ => {
                // ordered comparison: both operands must be the same numeric sort
                let li = as_int(l);
                let ri = as_int(r);
                match (li, ri) {
                    (Some(a), Some(b)) => num_cmp(func, &a, &b),
                    _ => {
                        let a = as_real(l).ok_or_else(|| type_mismatch("comparison", "number", l))?;
                        let b = as_real(r).ok_or_else(|| type_mismatch("comparison", "number", r))?;
                        num_cmp(func, &a, &b)
                    }
                }
            }
        };
        Ok(b.into())
    }
}

fn num_cmp<'ctx, T>(func: &str, a: &T, b: &T) -> Bool<'ctx>
where
    T: NumOrd<'ctx>,
{
    match func {
        op::LESS => a.lt_(b),
        op::LESS_EQUALS => a.le_(b),
        op::GREATER => a.gt_(b),
        _ => a.ge_(b),
    }
}

/// Shared ordered-comparison surface for Int and Real.
trait NumOrd<'ctx> {
    fn lt_(&self, o: &Self) -> Bool<'ctx>;
    fn le_(&self, o: &Self) -> Bool<'ctx>;
    fn gt_(&self, o: &Self) -> Bool<'ctx>;
    fn ge_(&self, o: &Self) -> Bool<'ctx>;
}

impl<'ctx> NumOrd<'ctx> for Int<'ctx> {
    fn lt_(&self, o: &Self) -> Bool<'ctx> { self.lt(o) }
    fn le_(&self, o: &Self) -> Bool<'ctx> { self.le(o) }
    fn gt_(&self, o: &Self) -> Bool<'ctx> { self.gt(o) }
    fn ge_(&self, o: &Self) -> Bool<'ctx> { self.ge(o) }
}

impl<'ctx> NumOrd<'ctx> for Real<'ctx> {
    fn lt_(&self, o: &Self) -> Bool<'ctx> { self.lt(o) }
    fn le_(&self, o: &Self) -> Bool<'ctx> { self.le(o) }
    fn gt_(&self, o: &Self) -> Bool<'ctx> { self.gt(o) }
    fn ge_(&self, o: &Self) -> Bool<'ctx> { self.ge(o) }
}

fn as_int<'ctx>(d: &Dynamic<'ctx>) -> Option<Int<'ctx>> {
    d.as_int()
}

fn as_real<'ctx>(d: &Dynamic<'ctx>) -> Option<Real<'ctx>> {
    d.as_real()
}

fn type_mismatch(context: &str, expected: &str, found: &Dynamic) -> CelZ3Error {
    CelZ3Error::TypeMismatch {
        expected: expected.to_string(),
        found: format!("{:?}", found.sort_kind()),
        context: context.to_string(),
    }
}

/// Flatten `a.b.c` (nested `Select` over a root `Ident`) into the dotted string
/// `"a.b.c"`. Returns `None` if the root is not a plain identifier.
fn flatten_path(e: &Expr) -> Option<String> {
    match e {
        Expr::Ident(name) => Some(name.clone()),
        Expr::Select(SelectExpr { operand, field, .. }) => {
            let base = flatten_path(&operand.expr)?;
            Some(format!("{base}.{field}"))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::{CelType, Env};
    use z3::{Config, Context, SatResult, Solver};

    fn ctx() -> Context {
        Context::new(&Config::new())
    }

    /// Translate `src` with the given declarations and return whether the
    /// resulting boolean formula is satisfiable.
    fn sat(ctx: &Context, decls: &[(&str, CelType)], src: &str) -> SatResult {
        let mut env = Env::new();
        for (p, t) in decls {
            env.declare(*p, *t);
        }
        let t = Translator::new(ctx, &env);
        let f = t.translate_str(src).unwrap();
        let s = Solver::new(ctx);
        s.assert(&f.as_bool().expect("top-level should be boolean"));
        s.check()
    }

    #[test]
    fn int_var_comparison_is_satisfiable() {
        let ctx = ctx();
        assert_eq!(sat(&ctx, &[("x", CelType::Int)], "x > 5"), SatResult::Sat);
    }

    #[test]
    fn logical_and_detects_contradiction() {
        let ctx = ctx();
        let d = &[("x", CelType::Int)];
        assert_eq!(sat(&ctx, d, "x > 5 && x < 10"), SatResult::Sat);
        assert_eq!(sat(&ctx, d, "x > 10 && x < 5"), SatResult::Unsat);
    }

    #[test]
    fn logical_or_and_not() {
        let ctx = ctx();
        let d = &[("b", CelType::Bool)];
        assert_eq!(sat(&ctx, d, "b || !b"), SatResult::Sat);
        assert_eq!(sat(&ctx, d, "b && !b"), SatResult::Unsat);
    }

    #[test]
    fn arithmetic_in_comparison() {
        let ctx = ctx();
        let d = &[("x", CelType::Int)];
        // x + 1 == 0 && x == 0  is unsatisfiable
        assert_eq!(sat(&ctx, d, "x + 1 == 0 && x == 0"), SatResult::Unsat);
        assert_eq!(sat(&ctx, d, "x * 2 == 10 && x == 5"), SatResult::Sat);
    }

    #[test]
    fn unary_minus() {
        let ctx = ctx();
        let d = &[("x", CelType::Int)];
        assert_eq!(sat(&ctx, d, "-x == 0 - 5 && x == 5"), SatResult::Sat);
    }

    #[test]
    fn ternary_selects_branch() {
        let ctx = ctx();
        let d = &[("x", CelType::Int)];
        // (x > 0 ? x : -x) < 0 is unsatisfiable (abs is never negative)
        assert_eq!(sat(&ctx, d, "(x > 0 ? x : 0 - x) < 0"), SatResult::Unsat);
    }

    #[test]
    fn string_starts_with() {
        let ctx = ctx();
        let d = &[("s", CelType::String)];
        assert_eq!(
            sat(&ctx, d, "s.startsWith(\"registry/\") && s == \"other\""),
            SatResult::Unsat
        );
        assert_eq!(sat(&ctx, d, "s.startsWith(\"a\")"), SatResult::Sat);
    }

    #[test]
    fn string_ends_with_and_contains() {
        let ctx = ctx();
        let d = &[("s", CelType::String)];
        assert_eq!(sat(&ctx, d, "s.endsWith(\":latest\")"), SatResult::Sat);
        assert_eq!(sat(&ctx, d, "s.contains(\"x\")"), SatResult::Sat);
    }

    #[test]
    fn in_list_literal() {
        let ctx = ctx();
        let d = &[("x", CelType::Int)];
        assert_eq!(sat(&ctx, d, "x in [1, 2, 3] && x == 2"), SatResult::Sat);
        assert_eq!(sat(&ctx, d, "x in [1, 2, 3] && x == 9"), SatResult::Unsat);
    }

    #[test]
    fn unknown_identifier_errors() {
        let ctx = ctx();
        let env = Env::new();
        let t = Translator::new(&ctx, &env);
        assert_eq!(
            t.translate_str("x > 5"),
            Err(CelZ3Error::UnknownIdentifier("x".into()))
        );
    }

    #[test]
    fn comprehension_is_unsupported() {
        let ctx = ctx();
        let mut env = Env::new();
        env.declare("xs", CelType::Int); // type irrelevant; macro rejected before use
        let t = Translator::new(&ctx, &env);
        assert!(matches!(
            t.translate_str("[1, 2].all(i, i > 0)"),
            Err(CelZ3Error::Unsupported(_))
        ));
    }

    #[test]
    fn has_presence_test_is_unsupported() {
        let ctx = ctx();
        let mut env = Env::new();
        env.declare("object.spec.replicas", CelType::Int);
        let t = Translator::new(&ctx, &env);
        // has() is a Bool presence test; this crate models paths as total
        // variables with no notion of absence, so it must be rejected rather
        // than silently translated to the field's value.
        assert!(matches!(
            t.translate_str("has(object.spec.replicas)"),
            Err(CelZ3Error::Unsupported(_))
        ));
    }

    #[test]
    fn type_mismatch_on_string_vs_int_comparison() {
        let ctx = ctx();
        let mut env = Env::new();
        env.declare("s", CelType::String);
        let t = Translator::new(&ctx, &env);
        assert!(matches!(
            t.translate_str("s > 5"),
            Err(CelZ3Error::TypeMismatch { .. })
        ));
    }
}
