# indirect_perm: the permissions a principal borrows through escalation.
# See README.md for the full story.
#
# Pallograph does not store this relation. It would copy a target's whole
# grant set once per principal that controls it, which dominated the row
# count on real clusters. This file rebuilds it as a view you can \source
# into the REPL when you want the flat table.
#
# indirect_perm(Principal, Namespace, ApiGroup, Resource, Verb, Via): Principal
# can perform Verb on Resource in Namespace ("" is cluster-wide) by acting as
# Via, a user or ServiceAccount it can become, or a group it can impersonate.
#
# Demo flow:
#   \source examples/exec-escalation/alice-exec.mg
#   \source examples/indirect-perm/indirect-perm.mg
#   ?- indirect_perm("alice", Ns, ApiGroup, Resource, Verb, Via)

# Becoming an identity: its own grants plus the groups Kubernetes adds
# (assumed_subject), but not the target's user_groups, which an
# impersonated request does not carry.
indirect_perm(P, Ns, ApiGroup, Resource, Verb, Via) :-
    controls_identity(P, Via),
    assumed_subject(Via, Kind, Name),
    direct_perm(Name, Kind, Ns, ApiGroup, Resource, _, Verb).

# Impersonating a group: that group's own grants.
indirect_perm(P, Ns, ApiGroup, Resource, Verb, Group) :-
    controls_group(P, Group),
    direct_perm(Group, /group, Ns, ApiGroup, Resource, _, Verb).
