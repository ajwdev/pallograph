# Privilege escalation by writing RBAC objects.
#
# The kube-apiserver refuses to let a user create or update a role or binding
# that grants more than the user already holds, with two exceptions
# (pkg/registry/rbac/validation and the policybased storage in
# pkg/registry/rbac, documented under "Privilege escalation prevention and
# bootstrapping" in the RBAC docs):
#
#   bind      - a ClusterRoleBinding may reference a ClusterRole the user
#               may bind (verb bind on clusterroles, which resourceNames can
#               limit to some roles).
#   escalate  - a ClusterRole may hold rules the user does not, when the user
#               has verb escalate on clusterroles.
#
# So a principal that can write ClusterRoleBindings and bind a ClusterRole
# gains that role cluster-wide, and one that can write ClusterRoles and
# escalate gains whatever it writes into a role bound to it: everything.
# Wildcards in apiGroups, resources and verbs count as usual.
#
# Paths modeled, cluster-wide only (grants with Namespace ""):
#   bind      - create clusterrolebindings, bind ClusterRole R: a new
#               ClusterRoleBinding of R. Or update/patch
#               clusterrolebindings, bind R: add itself to an existing
#               ClusterRoleBinding of R (roleRef cannot change).
#   escalate  - escalate and update/patch clusterroles, already bound to
#               ClusterRole R by a ClusterRoleBinding: rewrite R. Or
#               escalate, create or update clusterroles, create
#               clusterrolebindings and bind on any ClusterRole: write a
#               role and bind it.
#
# Not modeled: RoleBindings and Roles (the same paths within a namespace,
# including a RoleBinding that references a ClusterRole), and continuing an
# escalation path (escalation.mg) through a role gained here, or from an
# identity reached there. ResourceNames are ignored except on bind, which
# over-approximates, the safe side for finding escalation paths.
#
# Derived relations (IDB):
#   rbac_write_role/5  - the ClusterRole a writer can grant itself, and how
#   rbac_write_perm/8  - the permissions that grants

# ---- Permission guards ----
#
# Cluster-wide grants on the rbac.authorization.k8s.io API group, then one
# relation per permission, each checking wildcard and literal resource and
# verb.

grant_rbac_cluster(Name, Kind, Resource, ResourceName, Verb) :-
    direct_perm(Name, Kind, "", "rbac.authorization.k8s.io", Resource, ResourceName, Verb).
grant_rbac_cluster(Name, Kind, Resource, ResourceName, Verb) :-
    direct_perm(Name, Kind, "", "*", Resource, ResourceName, Verb).

grant_clusterrolebindings_create(Name, Kind) :- grant_rbac_cluster(Name, Kind, "clusterrolebindings", _, "create").
grant_clusterrolebindings_create(Name, Kind) :- grant_rbac_cluster(Name, Kind, "clusterrolebindings", _, "*").
grant_clusterrolebindings_create(Name, Kind) :- grant_rbac_cluster(Name, Kind, "*",                   _, "create").
grant_clusterrolebindings_create(Name, Kind) :- grant_rbac_cluster(Name, Kind, "*",                   _, "*").

grant_clusterrolebindings_update(Name, Kind) :- grant_rbac_cluster(Name, Kind, "clusterrolebindings", _, "update").
grant_clusterrolebindings_update(Name, Kind) :- grant_rbac_cluster(Name, Kind, "clusterrolebindings", _, "patch").
grant_clusterrolebindings_update(Name, Kind) :- grant_rbac_cluster(Name, Kind, "clusterrolebindings", _, "*").
grant_clusterrolebindings_update(Name, Kind) :- grant_rbac_cluster(Name, Kind, "*",                   _, "update").
grant_clusterrolebindings_update(Name, Kind) :- grant_rbac_cluster(Name, Kind, "*",                   _, "patch").
grant_clusterrolebindings_update(Name, Kind) :- grant_rbac_cluster(Name, Kind, "*",                   _, "*").

grant_clusterroles_create(Name, Kind) :- grant_rbac_cluster(Name, Kind, "clusterroles", _, "create").
grant_clusterroles_create(Name, Kind) :- grant_rbac_cluster(Name, Kind, "clusterroles", _, "*").
grant_clusterroles_create(Name, Kind) :- grant_rbac_cluster(Name, Kind, "*",            _, "create").
grant_clusterroles_create(Name, Kind) :- grant_rbac_cluster(Name, Kind, "*",            _, "*").

grant_clusterroles_update(Name, Kind) :- grant_rbac_cluster(Name, Kind, "clusterroles", _, "update").
grant_clusterroles_update(Name, Kind) :- grant_rbac_cluster(Name, Kind, "clusterroles", _, "patch").
grant_clusterroles_update(Name, Kind) :- grant_rbac_cluster(Name, Kind, "clusterroles", _, "*").
grant_clusterroles_update(Name, Kind) :- grant_rbac_cluster(Name, Kind, "*",            _, "update").
grant_clusterroles_update(Name, Kind) :- grant_rbac_cluster(Name, Kind, "*",            _, "patch").
grant_clusterroles_update(Name, Kind) :- grant_rbac_cluster(Name, Kind, "*",            _, "*").

grant_clusterroles_escalate(Name, Kind) :- grant_rbac_cluster(Name, Kind, "clusterroles", _, "escalate").
grant_clusterroles_escalate(Name, Kind) :- grant_rbac_cluster(Name, Kind, "clusterroles", _, "*").
grant_clusterroles_escalate(Name, Kind) :- grant_rbac_cluster(Name, Kind, "*",            _, "escalate").
grant_clusterroles_escalate(Name, Kind) :- grant_rbac_cluster(Name, Kind, "*",            _, "*").

# ResourceName is kept: it is /any, or the one ClusterRole bind applies to.
grant_clusterroles_bind(Name, Kind, ResourceName) :- grant_rbac_cluster(Name, Kind, "clusterroles", ResourceName, "bind").
grant_clusterroles_bind(Name, Kind, ResourceName) :- grant_rbac_cluster(Name, Kind, "clusterroles", ResourceName, "*").
grant_clusterroles_bind(Name, Kind, ResourceName) :- grant_rbac_cluster(Name, Kind, "*",            ResourceName, "bind").
grant_clusterroles_bind(Name, Kind, ResourceName) :- grant_rbac_cluster(Name, Kind, "*",            ResourceName, "*").

# ---- Writers ----
#
# A writer is a known user or ServiceAccount, acting with all its subjects
# (principal_subject), or a group, acting with its own grants: as in
# escalation.mg, members of a group are mostly unknown, so a group is also
# where a path can start. The permissions a path needs may come from
# different subjects of one writer.

Decl rbac_writer_subject(Writer, WriterKind, Kind, Name)
  descr [
    doc("Binding subjects whose grants a writer of RBAC objects uses."),
    arg(Writer, "user name, system:serviceaccount:<ns>:<name>, or group name"),
    arg(WriterKind, "/principal for a user or ServiceAccount, /group for a group"),
    arg(Kind, "/user, /group or /serviceaccount"),
    arg(Name, "subject name")
  ].

rbac_writer_subject(Username, /principal, Kind, Name) :-
    principal_subject(Username, Kind, Name).

rbac_writer_subject(Group, /group, /group, Group) :-
    grant_rbac_cluster(Group, /group, _, _, _).

writer_creates_clusterrolebindings(Writer, WriterKind) :-
    rbac_writer_subject(Writer, WriterKind, Kind, Name),
    grant_clusterrolebindings_create(Name, Kind).

writer_updates_clusterrolebindings(Writer, WriterKind) :-
    rbac_writer_subject(Writer, WriterKind, Kind, Name),
    grant_clusterrolebindings_update(Name, Kind).

writer_writes_clusterroles(Writer, WriterKind) :-
    rbac_writer_subject(Writer, WriterKind, Kind, Name),
    grant_clusterroles_create(Name, Kind).

writer_writes_clusterroles(Writer, WriterKind) :-
    writer_updates_clusterroles(Writer, WriterKind).

writer_updates_clusterroles(Writer, WriterKind) :-
    rbac_writer_subject(Writer, WriterKind, Kind, Name),
    grant_clusterroles_update(Name, Kind).

writer_escalates_clusterroles(Writer, WriterKind) :-
    rbac_writer_subject(Writer, WriterKind, Kind, Name),
    grant_clusterroles_escalate(Name, Kind).

writer_binds_clusterroles(Writer, WriterKind, ResourceName) :-
    rbac_writer_subject(Writer, WriterKind, Kind, Name),
    grant_clusterroles_bind(Name, Kind, ResourceName).

writer_bindable_clusterrole(Writer, WriterKind, Role) :-
    writer_binds_clusterroles(Writer, WriterKind, /any),
    clusterrole(Role, _).

writer_bindable_clusterrole(Writer, WriterKind, Role) :-
    writer_binds_clusterroles(Writer, WriterKind, Role),
    clusterrole(Role, _).

# ---- What a writer can grant itself ----

Decl rbac_write_role(Writer, WriterKind, Mechanism, Binding, Role)
  descr [
    doc("Writer can grant itself ClusterRole Role cluster-wide by writing RBAC objects."),
    arg(Writer, "user name, system:serviceaccount:<ns>:<name>, or group name"),
    arg(WriterKind, "/principal for a user or ServiceAccount, /group for a group"),
    arg(Mechanism, "bind: bind an existing role; escalate: write rules into a role"),
    arg(Binding, "the existing ClusterRoleBinding used, or empty for a new one"),
    arg(Role, "the ClusterRole granted, or empty for a new one")
  ].

rbac_write_role(Writer, WriterKind, "bind", "", Role) :-
    writer_creates_clusterrolebindings(Writer, WriterKind),
    writer_bindable_clusterrole(Writer, WriterKind, Role).

rbac_write_role(Writer, WriterKind, "bind", Binding, Role) :-
    writer_updates_clusterrolebindings(Writer, WriterKind),
    writer_bindable_clusterrole(Writer, WriterKind, Role),
    binding_roleref("", Binding, "ClusterRole", Role).

rbac_write_role(Writer, WriterKind, "escalate", Binding, Role) :-
    writer_escalates_clusterroles(Writer, WriterKind),
    writer_updates_clusterroles(Writer, WriterKind),
    rbac_writer_subject(Writer, WriterKind, Kind, Name),
    binding_subject("", Binding, Kind, Name),
    binding_roleref("", Binding, "ClusterRole", Role).

rbac_write_role(Writer, WriterKind, "escalate", "", "") :-
    writer_escalates_clusterroles(Writer, WriterKind),
    writer_writes_clusterroles(Writer, WriterKind),
    writer_creates_clusterrolebindings(Writer, WriterKind),
    writer_binds_clusterroles(Writer, WriterKind, _).

Decl rbac_write_perm(Writer, WriterKind, Mechanism, Binding, Role, ApiGroup, Resource, Verb)
  descr [
    doc("Permissions Writer can grant itself cluster-wide through rbac_write_role. Through escalate that is every permission, written as * for apiGroup, resource and verb."),
    arg(Writer, "user name, system:serviceaccount:<ns>:<name>, or group name"),
    arg(WriterKind, "/principal for a user or ServiceAccount, /group for a group"),
    arg(Mechanism, "bind or escalate, as in rbac_write_role"),
    arg(Binding, "as in rbac_write_role"),
    arg(Role, "as in rbac_write_role"),
    arg(ApiGroup, "API group; * is a literal wildcard"),
    arg(Resource, "resource or resource/subresource; * is a literal wildcard"),
    arg(Verb, "verb; * is a literal wildcard")
  ].

rbac_write_perm(Writer, WriterKind, "bind", Binding, Role, ApiGroup, Resource, Verb) :-
    rbac_write_role(Writer, WriterKind, "bind", Binding, Role),
    clusterrole_rule(Role, Rule),
    policy_rule_perm(Rule, ApiGroup, Resource, _, Verb).

rbac_write_perm(Writer, WriterKind, "escalate", Binding, Role, "*", "*", "*") :-
    rbac_write_role(Writer, WriterKind, "escalate", Binding, Role).
