# Escalation closure - who can reach whom by chaining escalation hops.
#
# One hop relation and one closure over it, whatever system the hop comes
# from. The Kubernetes rules fill the inputs:
#   k8s_rbac_escalation.mg  - subject_hop from a binding subject's own grants
#                    (Source /grant), and acts_as for logging in and for
#                    being assumed
#   k8s_rbac_write.mg  - subject_hop through a role a subject can grant itself
#                    by writing RBAC objects (Source /rbac_write), and
#                    acts_as for the writes an assumed identity can make
#
# Derived relations (IDB):
#   subject_hop/8       - one hop from a subject's grants, with how and why
#   acts_as/6           - the subjects an identity acts as, per mode
#   subject_controls/6  - every target a subject reaches in one or more hops
#   controls_identity/2, controls_group/2, group_controls_identity/2,
#   group_controls_group/2, escalation_hop/2, perm_group_impersonate/2
#                       - the same per principal or group, by name
#
# Identities (users and ServiceAccounts) and subjects (what a binding
# names: a user, a ServiceAccount or a group) are flat columns: name,
# system, kind. Every system is /k8s for now.
#
# A path starts at a subject: one a principal acts as when it logs in, or
# a group, whose members are mostly unknown. Every hop after the first
# starts from what the previous hop reached:
#   - an identity acts only as its assumed subjects (acts_as /assumed), and
#     can make only the RBAC writes it could make assumed (/assumed_writes);
#   - an impersonated group acts with its own grants, and only its hops to
#     identities count. Impersonating a group does not let the request
#     impersonate further groups.

identity_kind(/user).
identity_kind(/serviceaccount).

# A constant in the recursive atom would make the planner look up the
# whole relation on it every round instead of only the new rows, so the
# rule matches MidKind against this fact.
group_kind(/group).

# Paths start from subjects a principal can log in as, or from a group.
# /assumed_user subjects (k8s_rbac_write.mg) are only reached mid-path.
start_subject_kind(/user).
start_subject_kind(/serviceaccount).
start_subject_kind(/group).

Decl subject_hop(Subject, SubjectSystem, SubjectKind, Target, TargetSystem, TargetKind, Mechanism, Source)
  descr [
    doc("One escalation hop: whoever acts as subject (SubjectKind, Subject) can assume identity Target, or impersonate group Target, by Mechanism."),
    arg(Subject, "subject name: user or group name, or system:serviceaccount:<ns>:<name>"),
    arg(SubjectSystem, "/k8s"),
    arg(SubjectKind, "/user, /group or /serviceaccount; /assumed_user for a user with user_groups groups, as it acts when assumed (Source /rbac_write only)"),
    arg(Target, "user name, system:serviceaccount:<ns>:<name>, or group name"),
    arg(TargetSystem, "/k8s"),
    arg(TargetKind, "/user, /serviceaccount or /group"),
    arg(Mechanism, "/impersonate, /token, /pod_exec (exec or attach) or /pod_create"),
    arg(Source, "/grant: the subject's own grants; /rbac_write: a role the subject can grant itself by writing RBAC objects")
  ].

Decl acts_as(Identity, IdentitySystem, Subject, SubjectSystem, SubjectKind, Mode)
  descr [
    doc("The binding subjects identity Identity acts as. Hops from those subjects are hops from the identity."),
    arg(Identity, "user name or system:serviceaccount:<ns>:<name>"),
    arg(IdentitySystem, "/k8s"),
    arg(Subject, "subject name"),
    arg(SubjectSystem, "/k8s"),
    arg(SubjectKind, "/user, /group, /serviceaccount, or /assumed_user in mode /assumed_writes"),
    arg(Mode, "/login: logged in, with its user_groups groups (principal_subject); /assumed: reached by a hop, for /grant hops (assumed_subject); /assumed_writes: reached by a hop, for /rbac_write hops (assumed_gains_subject)")
  ].

Decl subject_controls(Subject, SubjectSystem, SubjectKind, Target, TargetSystem, TargetKind)
  descr [
    doc("Whoever acts as subject (SubjectKind, Subject) reaches Target in one or more escalation hops (transitively closed)."),
    arg(Subject, "subject name: user or group name, or system:serviceaccount:<ns>:<name>"),
    arg(SubjectSystem, "/k8s"),
    arg(SubjectKind, "/user, /group or /serviceaccount"),
    arg(Target, "user name, system:serviceaccount:<ns>:<name>, or group name"),
    arg(TargetSystem, "/k8s"),
    arg(TargetKind, "/user, /serviceaccount or /group")
  ].

# The next hop from an identity reached on the way.
assumed_hop(Identity, IdentitySystem, Target, TargetSystem, TargetKind) :-
    acts_as(Identity, IdentitySystem, Subject, SubjectSystem, SubjectKind, /assumed),
    subject_hop(Subject, SubjectSystem, SubjectKind, Target, TargetSystem, TargetKind, _, /grant).

assumed_hop(Identity, IdentitySystem, Target, TargetSystem, TargetKind) :-
    acts_as(Identity, IdentitySystem, Subject, SubjectSystem, SubjectKind, /assumed_writes),
    subject_hop(Subject, SubjectSystem, SubjectKind, Target, TargetSystem, TargetKind, _, /rbac_write).

# The next hop from an impersonated group: its own grants, to identities.
impersonated_group_hop(Group, GroupSystem, Target, TargetSystem, TargetKind) :-
    subject_hop(Group, GroupSystem, /group, Target, TargetSystem, TargetKind, _, _),
    identity_kind(TargetKind).

# Each recursive rule extends a path by one hop, so why on a
# subject_controls fact shows a shortest path: the interpreter derives paths
# one hop per round and keeps the first proof, and the DD backend's lazy
# provenance picks the proof of least height.
subject_controls(Subject, SubjectSystem, SubjectKind, Target, TargetSystem, TargetKind) :-
    subject_hop(Subject, SubjectSystem, SubjectKind, Target, TargetSystem, TargetKind, _, _),
    start_subject_kind(SubjectKind).

subject_controls(Subject, SubjectSystem, SubjectKind, Target, TargetSystem, TargetKind) :-
    subject_controls(Subject, SubjectSystem, SubjectKind, Mid, MidSystem, MidKind),
    identity_kind(MidKind),
    assumed_hop(Mid, MidSystem, Target, TargetSystem, TargetKind).

subject_controls(Subject, SubjectSystem, SubjectKind, Target, TargetSystem, TargetKind) :-
    subject_controls(Subject, SubjectSystem, SubjectKind, Mid, MidSystem, MidKind),
    group_kind(MidKind),
    impersonated_group_hop(Mid, MidSystem, Target, TargetSystem, TargetKind).

# ---- Per principal and per group ----
#
# What src/k8s/rbac reads. A principal reaches what any subject it logs in as
# reaches.

Decl controls_identity(Principal, Target)
  descr [
    doc("Principal can assume Target's identity via one or more escalation hops, through identities and impersonated groups (transitively closed)."),
    arg(Principal, "the user or ServiceAccount that gains control"),
    arg(Target, "the user or ServiceAccount Principal ultimately controls")
  ].

controls_identity(Principal, Target) :-
    acts_as(Principal, /k8s, Subject, SubjectSystem, SubjectKind, /login),
    subject_controls(Subject, SubjectSystem, SubjectKind, Target, /k8s, TargetKind),
    identity_kind(TargetKind),
    Principal != Target.

# A path back to Principal through another identity: Principal assumed
# can do no more than Principal logged in, but the row says the cycle
# exists.
controls_identity(Principal, Principal) :-
    controls_identity(Principal, Mid),
    Mid != Principal,
    assumed_hop(Mid, /k8s, Principal, /k8s, TargetKind),
    identity_kind(TargetKind).

Decl controls_group(Principal, Group)
  descr [
    doc("Principal, or an identity it controls, can impersonate Group, which holds grants."),
    arg(Principal, "user name or system:serviceaccount:<ns>:<name>"),
    arg(Group, "group whose direct_perm grants Principal can use")
  ].

controls_group(Principal, Group) :-
    acts_as(Principal, /k8s, Subject, SubjectSystem, SubjectKind, /login),
    subject_controls(Subject, SubjectSystem, SubjectKind, Group, /k8s, /group).

Decl group_controls_identity(Group, Target)
  descr [
    doc("Any member of Group can assume Target's identity via one or more escalation hops, starting from the group's own grants."),
    arg(Group, "group whose direct_perm grants start the escalation"),
    arg(Target, "the user or ServiceAccount members of Group ultimately control")
  ].

group_controls_identity(Group, Target) :-
    subject_controls(Group, /k8s, /group, Target, /k8s, TargetKind),
    identity_kind(TargetKind).

Decl group_controls_group(Group, Other)
  descr [
    doc("Any member of Group, or an identity the group controls, can impersonate Other, which holds grants."),
    arg(Group, "group whose direct_perm grants start the escalation"),
    arg(Other, "another group whose direct_perm grants members of Group can use")
  ].

group_controls_group(Group, Other) :-
    subject_controls(Group, /k8s, /group, Other, /k8s, /group),
    Group != Other.

Decl escalation_hop(Principal, Target)
  descr [
    doc("Single-step escalation: Principal, logged in with all its groups, can assume Target's identity via one mechanism, with the grants it holds now."),
    arg(Principal, "the user or ServiceAccount performing the escalation"),
    arg(Target, "the user or ServiceAccount whose identity Principal can directly assume")
  ].

escalation_hop(Principal, Target) :-
    acts_as(Principal, /k8s, Subject, SubjectSystem, SubjectKind, /login),
    subject_hop(Subject, SubjectSystem, SubjectKind, Target, /k8s, TargetKind, _, /grant),
    identity_kind(TargetKind).

# The same for groups: Principal may impersonate Group now, in one request.
perm_group_impersonate(Principal, Group) :-
    acts_as(Principal, /k8s, Subject, SubjectSystem, SubjectKind, /login),
    subject_hop(Subject, SubjectSystem, SubjectKind, Group, /k8s, /group, _, /grant).
