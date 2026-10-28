// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

// RBAC tables for the `profile_smt_access` benchmark.
//
// Mangle provides the derived facts (IDB): grants per binding subject
// (direct_perm), the subjects each principal acts as (principal_subject) and
// the escalation closure (controls_identity, controls_group and their group_
// counterparts). `PermissionTables` indexes them. Nothing is asserted into
// the Z3 solver.
//
// `rbac::diff` builds `PermissionTables` directly (see `rbac::diff`) and
// does not go through `SmtEncoder`.
//
// TODO(ajw): the RecFuncDecl builders for subject_grants, can and
// effective_can were removed, since no command queried them. Restore them
// from git if Z3 gets a role in RBAC analysis again; this finds the commit
// that removed them:
// `git log -S build_effective_can --oneline -- src/smt/rbac_model.rs`.

use super::SmtEncoder;
use crate::engine::EvalStore;
use crate::rbac::PermissionTables;

impl<'ctx> SmtEncoder<'ctx> {
    /// Index the Mangle RBAC relations in `PermissionTables`, under the
    /// empty key.
    pub fn load_rbac_tables(&mut self, store: &EvalStore) {
        let tables = PermissionTables::from_scan(&|rel| store.scan(rel).to_vec());
        self.permission_tables.insert(String::new(), tables);
    }
}
