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
}
