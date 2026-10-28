# cluster-admin approval gate: flag any principal holding cluster-admin that
# the security team has not approved. See README.md for the full story.
#
# Two inputs, both loaded as Mangle files (facts are EDB, rules are IDB):
#   - this file: the view rules below.
#   - an approval closure: facts for cluster_admin_allowed, the EDB relation
#     declared (empty) in rules/00_edb_prelude.mg. See approved.example.mg.
#
# Load both BEFORE snapshot so a snapshot carries the view. source works on
# both backends; a profile datasource (facts) plus the --rules dir (this view)
# is an equivalent startup path. See README.md.

# cluster_admin(Principal): holds a cluster-wide *,*,* grant directly, whether
# a user, group or ServiceAccount.
cluster_admin(Principal) :-
    direct_perm(Principal, _, "", "*", "*", _, "*").

# unexpected_cluster_admin(Principal): a cluster-admin absent from the
# approval closure. Inspect it with `?- unexpected_cluster_admin(P)` (who is
# un-approved now) or `diff-relation <snapshot> unexpected_cluster_admin`
# (what a change did to that set). Both are diagnostics, not pass/fail checks.
unexpected_cluster_admin(Principal) :-
    cluster_admin(Principal),
    !cluster_admin_allowed(Principal).
