// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

use mangle_ast::Arena;
use mangle_driver::compile_units;

fn main() {
    println!("cargo:rerun-if-changed=rules/");

    let mut rule_files: Vec<_> = glob::glob("rules/*.mg")
        .expect("glob failed")
        .filter_map(|e| e.ok())
        .collect();
    rule_files.sort();

    let mut sources: Vec<String> = Vec::new();

    for path in &rule_files {
        let src = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        sources.push(src);
    }

    let src_refs: Vec<&str> = sources.iter().map(String::as_str).collect();
    let arena = Arena::new_with_global_interner();
    if let Err(e) = compile_units(&src_refs, &arena) {
        panic!("rule compilation failed:\n{e:#}");
    }

    // Embed the rules so a released binary works from any directory. The
    // generated file is pulled into src/engine.rs with include!.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let mut embedded = String::from("pub const EMBEDDED_RULES: &[&str] = &[\n");
    for path in &rule_files {
        let abs = std::path::Path::new(&manifest_dir).join(path);
        embedded.push_str(&format!(
            "    include_str!({:?}),\n",
            abs.display().to_string()
        ));
    }
    embedded.push_str("];\n");
    // The same files' repo-relative paths, for the rule graph's locations.
    embedded.push_str("pub const EMBEDDED_RULE_NAMES: &[&str] = &[\n");
    for path in &rule_files {
        embedded.push_str(&format!("    {:?},\n", path.display().to_string()));
    }
    embedded.push_str("];\n");

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
    std::fs::write(
        std::path::Path::new(&out_dir).join("embedded_rules.rs"),
        embedded,
    )
    .expect("write embedded_rules.rs");

    std::fs::write(
        std::path::Path::new(&out_dir).join("edb_columns.rs"),
        edb_columns("rules/00_k8s_prelude.mg"),
    )
    .expect("write edb_columns.rs");
}

/// A module per input relation declared in the prelude, holding a constant
/// per column (named after its `Decl` argument) and the arity, so Rust that
/// reads a column by position gets it from the `Decl` rather than a literal.
/// Pulled into src/edb/mod.rs as `columns`.
fn edb_columns(prelude_path: &str) -> String {
    let source = std::fs::read_to_string(prelude_path)
        .unwrap_or_else(|e| panic!("failed to read {prelude_path}: {e}"));
    let arena = Arena::new_with_global_interner();
    let mut parser = mangle_parse::Parser::new(&arena, source.as_bytes(), prelude_path);
    parser.next_token().expect("prelude tokenizes");
    let unit = parser.parse_unit().expect("prelude parses");

    let mut out = String::new();
    for decl in unit.decls {
        // The parser adds a `Package` declaration with no arguments.
        if decl.atom.args.is_empty() {
            continue;
        }
        let relation = arena
            .predicate_name(decl.atom.sym)
            .expect("declared predicate has a name");
        out.push_str(&format!(
            "pub mod {relation} {{\n    pub const ARITY: usize = {};\n",
            decl.atom.args.len()
        ));
        for (position, arg) in decl.atom.args.iter().enumerate() {
            let mangle_ast::BaseTerm::Variable(variable) = arg else {
                panic!("{relation}: Decl argument {position} is not a variable");
            };
            let name = arena.lookup_name(variable.0).expect("variable has a name");
            out.push_str(&format!(
                "    pub const {}: usize = {position};\n",
                screaming_snake_case(name)
            ));
        }
        out.push_str("}\n");
    }
    out
}

/// `ApiVersion` to `API_VERSION`.
fn screaming_snake_case(name: &str) -> String {
    let mut out = String::new();
    let mut previous_lowercase = false;
    for c in name.chars() {
        if c.is_ascii_uppercase() && previous_lowercase {
            out.push('_');
        }
        previous_lowercase = c.is_ascii_lowercase() || c.is_ascii_digit();
        out.push(c.to_ascii_uppercase());
    }
    out
}
