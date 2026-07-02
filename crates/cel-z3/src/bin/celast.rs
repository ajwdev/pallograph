//! Debug helper: parse a CEL expression, pretty-print its AST, then translate
//! it into a Z3 node and print that too.
//!
//! Usage:
//!     celast '<expr>' [path:type ...]
//!
//! The expression is the first argument (or read from stdin if omitted).
//! Any remaining `path:type` arguments declare identifier types so the Z3
//! translation can resolve them; type is one of int, real, string, bool.
//!
//! Examples:
//!     cargo run --bin celast -- 'object.spec.replicas <= 10' object.spec.replicas:int
//!     echo 'a && b' | cargo run --bin celast -- '' a:bool b:bool

use std::io::Read;
use std::process::ExitCode;

use cel::parser::Parser;
use cel_z3::{CelType, Env, Translator};
use z3::{Config, Context};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);

    let expr = match args.next() {
        Some(a) if !a.is_empty() => a,
        _ => read_stdin(),
    };
    let expr = expr.trim();
    if expr.is_empty() {
        eprintln!("error: no expression given (pass as first arg or via stdin)");
        return ExitCode::FAILURE;
    }

    // Remaining args are `path:type` declarations for the Z3 translation.
    let mut env = Env::new();
    for decl in args {
        match parse_decl(&decl) {
            Ok((path, ty)) => {
                env.declare(path, ty);
            }
            Err(e) => {
                eprintln!("error: bad declaration {decl:?}: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    println!("expr: {expr}\n");

    // --- AST ---
    match Parser::new().parse(expr) {
        Ok(parsed) => println!("AST:\n{parsed:#?}\n"),
        Err(e) => {
            println!("AST: parse error:\n{e:#?}\n");
            return ExitCode::FAILURE;
        }
    }

    // --- Z3 translation ---
    let ctx = Context::new(&Config::new());
    let translator = Translator::new(&ctx, &env);
    match translator.translate_str(expr) {
        Ok(node) => println!("Z3:\n{node}"),
        Err(e) => println!("Z3: {e}"),
    }

    ExitCode::SUCCESS
}

fn read_stdin() -> String {
    let mut s = String::new();
    let _ = std::io::stdin().read_to_string(&mut s);
    s
}

fn parse_decl(decl: &str) -> Result<(&str, CelType), String> {
    let (path, ty) = decl.rsplit_once(':').ok_or("expected form path:type")?;
    let ty = match ty {
        "int" => CelType::Int,
        "real" => CelType::Real,
        "string" => CelType::String,
        "bool" => CelType::Bool,
        other => {
            return Err(format!(
                "unknown type {other:?} (want int|real|string|bool)"
            ));
        }
    };
    Ok((path, ty))
}
