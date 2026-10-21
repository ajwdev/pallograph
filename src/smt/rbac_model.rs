// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

// RBAC tables for `\access-diff`.
//
// Mangle provides the derived facts (IDB): grants per binding subject
// (direct_perm), the subjects each principal acts as (principal_subject) and
// the escalation closure (controls_identity, controls_group and their group_
// counterparts). `PermissionTables` indexes them, one set of tables per
// snapshot, keyed by a name suffix, and `diff` compares two of them in Rust.
// Nothing is asserted into the Z3 solver.
//
// TODO(ajw): the RecFuncDecl builders for subject_grants, can and
// effective_can were removed, since no command queried them. Restore them
// from git if Z3 gets a role in RBAC analysis again; this finds the commit
// that removed them:
// `git log -S build_effective_can --oneline -- src/smt/rbac_model.rs`.

use mangle_common::Value;

use super::SmtEncoder;
use crate::engine::EvalStore;
use crate::rbac::PermissionTables;

impl<'ctx> SmtEncoder<'ctx> {
    /// Index the Mangle RBAC relations in `PermissionTables`, under the
    /// empty suffix.
    pub fn load_rbac_tables(&mut self, store: &EvalStore) {
        self.load_rbac_tables_named(|rel| store.scan(rel).to_vec(), "");
    }

    /// Like `load_rbac_tables` but keyed by a name suffix, so that two
    /// snapshots can be compared.
    pub fn load_rbac_tables_as(&mut self, store: &EvalStore, suffix: &str) {
        self.load_rbac_tables_named(|rel| store.scan(rel).to_vec(), suffix);
    }

    /// Like `load_rbac_tables_as` but reads from a saved `Snapshot` instead
    /// of a live eval store.
    pub fn load_rbac_tables_from_snapshot_as(
        &mut self,
        snap: &crate::snapshot::Snapshot,
        suffix: &str,
    ) {
        self.load_rbac_tables_named(|rel| snap.scan_rel(rel), suffix);
    }

    fn load_rbac_tables_named<F: Fn(&str) -> Vec<Vec<Value>>>(&mut self, scan: F, suffix: &str) {
        let tables = PermissionTables::from_scan(&scan);
        self.permission_tables.insert(suffix.to_string(), tables);
    }
}
