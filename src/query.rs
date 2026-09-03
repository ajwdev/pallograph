// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{anyhow, Result};
use mangle_ast::{Arena, BaseTerm, Const};
use mangle_common::Value;
use mangle_parse::Parser;

#[derive(Clone)]
pub struct ParsedQuery {
    pub predicate: String,
    pub args: Vec<QueryArg>,
}

#[derive(Clone)]
pub enum QueryArg {
    Variable,
    StringConst(String),
    NameConst(String),
    NumberConst(i64),
}

pub fn parse_query(query: &str) -> Result<ParsedQuery> {
    let arena = Arena::new_with_global_interner();
    let mut parser = Parser::new(&arena, query.as_bytes(), "query");
    parser.next_token().map_err(|e| anyhow!(e))?;
    let atom = parser.parse_atom()?;

    let predicate = arena
        .predicate_name(atom.sym)
        .ok_or_else(|| anyhow!("cannot resolve predicate name"))?
        .to_string();

    let args = atom
        .args
        .iter()
        .map(|arg| match arg {
            BaseTerm::Variable(_) => QueryArg::Variable,
            BaseTerm::Const(Const::String(s)) => QueryArg::StringConst(s.to_string()),
            BaseTerm::Const(Const::Name(n)) => {
                let name = arena.lookup_name(*n).unwrap_or("").to_string();
                QueryArg::NameConst(name)
            }
            BaseTerm::Const(Const::Number(n)) => QueryArg::NumberConst(*n),
            _ => QueryArg::Variable,
        })
        .collect();

    Ok(ParsedQuery { predicate, args })
}

pub fn filter_tuples<'a>(tuples: &'a [Vec<Value>], query: &ParsedQuery) -> Vec<&'a Vec<Value>> {
    tuples
        .iter()
        .filter(|tuple| {
            for (i, arg) in query.args.iter().enumerate() {
                let Some(val) = tuple.get(i) else {
                    return false;
                };
                match arg {
                    QueryArg::Variable => {}
                    QueryArg::StringConst(s) => {
                        if val != &Value::String(s.clone()) {
                            return false;
                        }
                    }
                    QueryArg::NameConst(s) => {
                        if val != &Value::Name(s.clone()) {
                            return false;
                        }
                    }
                    QueryArg::NumberConst(n) => {
                        if val != &Value::Number(*n) {
                            return false;
                        }
                    }
                }
            }
            true
        })
        .collect()
}
