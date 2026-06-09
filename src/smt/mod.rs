use std::collections::HashMap;

use mangle_common::Value;
use z3::ast::{Ast, Dynamic, Int};
use z3::ast::String as Z3String;
use z3::{FuncDecl, RecFuncDecl, Solver, Sort};

use crate::engine::EvalStore;

pub mod access;
pub mod diff;
pub mod rbac_model;
pub mod scheduling;

pub struct Violation {
    pub principal: String,
    pub namespace: String,
    pub resource: String,
    pub verb: String,
}

/// Encodes Mangle ground facts as Z3 assertions and exposes the solver for
/// constraint checking.
pub struct SmtEncoder<'ctx> {
    pub(crate) ctx: &'ctx z3::Context,
    pub(crate) solver: Solver<'ctx>,
    pub(crate) decls: HashMap<String, FuncDecl<'ctx>>,
    /// Recursively-defined functions (used for can, effective_can axioms).
    /// RecFuncDecl derefs to FuncDecl; use `get_decl` for a unified lookup.
    pub(crate) rec_decls: HashMap<String, RecFuncDecl<'ctx>>,
    pub(crate) facts: HashMap<String, Vec<Vec<Value>>>,
    /// (principal, namespace, apigroup, resource, verb) entries per named suffix.
    /// Key is the suffix passed to assert_rbac_axioms_as (empty string = bare "can").
    pub(crate) can_entries: HashMap<String, Vec<(String, String, String, String, String)>>,
    /// (principal, namespace, resource, verb) entries for effective_can, same keying.
    pub(crate) eff_entries: HashMap<String, Vec<(String, String, String, String)>>,
}

impl<'ctx> SmtEncoder<'ctx> {
    pub fn new(ctx: &'ctx z3::Context) -> Self {
        Self {
            ctx,
            solver: Solver::new(ctx),
            decls: HashMap::new(),
            rec_decls: HashMap::new(),
            facts: HashMap::new(),
            can_entries: HashMap::new(),
            eff_entries: HashMap::new(),
        }
    }

    /// Return a reference to the named decl, checking `rec_decls` (closed
    /// recursive definitions) before `decls` (ground-fact uninterpreted fns).
    pub(crate) fn get_decl(&self, name: &str) -> Option<&FuncDecl<'ctx>> {
        if let Some(rd) = self.rec_decls.get(name) {
            Some(rd)  // RecFuncDecl derefs to &FuncDecl<'ctx>
        } else {
            self.decls.get(name)
        }
    }

    pub fn load(&mut self, store: &EvalStore, relations: &[&str]) {
        for &rel in relations {
            self.load_relation(rel, store.scan(rel));
        }
    }

    pub fn load_relation(&mut self, name: &str, tuples: &[Vec<Value>]) {
        let Some(first) = tuples.first() else { return };
        if first.is_empty() {
            return;
        }

        let domain: Vec<Sort<'ctx>> = first.iter().map(|v| self.sort_of(v)).collect();
        let domain_refs: Vec<&Sort<'ctx>> = domain.iter().collect();
        let decl = FuncDecl::new(self.ctx, name, &domain_refs, &Sort::bool(self.ctx));

        for tuple in tuples {
            let args: Vec<Dynamic<'ctx>> = tuple.iter().map(|v| self.ast_of(v)).collect();
            let arg_refs: Vec<&dyn Ast<'ctx>> = args.iter().map(|a| a as &dyn Ast<'ctx>).collect();
            if let Some(fact) = decl.apply(&arg_refs).as_bool() {
                self.solver.assert(&fact);
            }
        }

        self.decls.insert(name.to_string(), decl);
        self.facts.insert(name.to_string(), tuples.to_vec());
    }

    pub fn to_smtlib(&self) -> String {
        self.solver.to_string()
    }

    pub(crate) fn sort_of(&self, v: &Value) -> Sort<'ctx> {
        match v {
            Value::Number(_) => Sort::int(self.ctx),
            _ => Sort::string(self.ctx),
        }
    }

    pub(crate) fn ast_of(&self, v: &Value) -> Dynamic<'ctx> {
        match v {
            Value::Number(n) => Int::from_i64(self.ctx, *n).into(),
            Value::String(s) | Value::Name(s) => {
                Z3String::from_str(self.ctx, s).unwrap().into()
            }
            other => Z3String::from_str(self.ctx, &other.to_string()).unwrap().into(),
        }
    }
}
