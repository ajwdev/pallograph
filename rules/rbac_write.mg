# Privilege escalation by writing RBAC objects.
#
# The kube-apiserver refuses to let a user create or update a role or binding
# that grants more than the user already holds, with two exceptions
# (pkg/registry/rbac/validation and the policybased storage in
# pkg/registry/rbac, documented under "Privilege escalation prevention and
# bootstrapping" in the RBAC docs):
#
#   bind      - a binding may reference a role the user may bind: verb bind
#               on roles or clusterroles (the roleRef's kind), checked in the
#               binding's namespace ("" for a ClusterRoleBinding) and on the
#               roleRef's name.
#   escalate  - a role may hold rules the user does not, when the user has
#               verb escalate on roles or clusterroles, checked on the role's
#               name.
#
# Members of system:masters skip both checks (and authorization): they are
# given every RBAC permission below.
#
# So a writer can grant itself a role by writing a binding that names it,
# and with escalate can write any rules into a role it holds or can bind.
# Paths modeled:
#
#   bind      - create a ClusterRoleBinding of a ClusterRole it may bind, or
#               add itself to an existing one (update; roleRef cannot
#               change). The same with RoleBindings in a namespace, of a Role
#               there or of a ClusterRole, which then applies only in that
#               namespace.
#   escalate  - rewrite a ClusterRole or Role (update) it is bound to or can
#               bind, or create a new one it can bind. Creating a ClusterRole
#               whose labels match the aggregationRule of a ClusterRole
#               extends that role too: the aggregation controller copies the
#               rules in.
#
# Wildcards in apiGroups, resources and verbs count as usual. ResourceNames
# are honored: an update, patch, bind or escalate is checked on the object's
# name, and a create on the empty name, so only rules without resourceNames
# (or with resourceNames: [""]) allow it. Any aggregationRule is taken to be
# satisfiable, since the writer chooses the new role's labels.
#
# ---- Writers and namespaces ----
#
# A writer is a known user or ServiceAccount, acting with all its subjects
# (principal_subject), or a group, acting with its own grants: as in
# escalation.mg, a group's members are mostly unknown, so a group is also
# where a path can start. The permissions a path needs may come from
# different subjects of one writer. A writer that already holds every
# permission cluster-wide gains nothing and is left out.
#
# What a writer gains is recorded against the writer, which is also the
# binding subject the binding it writes would name: (/user or
# /serviceaccount, username), or (/group, group). Gains feed back in two
# ways:
#
#   - Into the writer's own RBAC permissions (Mode /all), so binding a role
#     that allows more RBAC writes continues the path, through any number
#     of writes. A group's gains count for its members too.
#   - Into the escalation closure of escalation.mg (controls_identity and
#     the rest, through gained_escalation_hop), so a role gained here can
#     reach identities, and an identity reached there brings what it can
#     grant itself. escalation_hop and the grant_* guards stay as they are:
#     they say what a principal may do now, in one request.
#
# An identity assumed through escalation acts without its user_groups
# groups, so for a user that has some, what it can write when assumed is
# worked out apart, as writer kind /assumed_user.
#
# Namespace columns hold "" for cluster-wide (a ClusterRoleBinding), a
# namespace, or "*" for every namespace: a writer allowed to create
# RoleBindings anywhere gains a ClusterRole through a RoleBinding in each
# namespace, which is not the same as cluster-wide (no cluster-scoped
# resources), and naming each namespace would multiply rows by their count.
# A namespaced RBAC permission counts at "*" when it was granted cluster-wide
# or at "*", and also in each namespace the writer has a namespaced RBAC
# permission in, so that two permissions held in different ways meet there.
#
# Derived relations (IDB):
#   rbac_write_binding/7         - the roles a writer can grant itself, after
#                                  any chain of writes
#   rbac_write_binding_direct/7  - those it can grant itself in one request
#   rbac_role_writable/5         - the roles it can write any rules into, in
#                                  one request
#   rbac_write_anything/1        - principals that may write anything
#   gained_escalation_hop/4      - escalation hops through gained roles
#   rbac_write_role/5            - rbac_write_binding_direct cluster-wide,
#                                  by principal, for tests/rbac_compat.rs
#
# What a gained role grants is joined on demand, as for direct_perm:
#
#   rbac_write_binding(Name, Kind, "bind", Ns, _, "ClusterRole", Role),
#       clusterrole_rule(Role, Rule), policy_rule_perm(Rule, G, R, N, V)
#   rbac_write_binding(Name, Kind, "bind", Ns, _, "Role", Role),
#       role_rule(Ns, Role, Rule), policy_rule_perm(Rule, G, R, N, V)
#   rbac_write_binding(Name, Kind, "escalate", Ns, ...): every permission in Ns

# ---- Classifying RBAC permissions ----

rbac_api_group("rbac.authorization.k8s.io").
rbac_api_group("*").

rbac_resource_class("clusterrolebindings", /clusterrolebindings).
rbac_resource_class("clusterroles", /clusterroles).
rbac_resource_class("rolebindings", /rolebindings).
rbac_resource_class("roles", /roles).
rbac_resource_class("*", Class) :- rbac_resource_class(_, Class).

rbac_verb_class("create", /create).
rbac_verb_class("update", /update).
rbac_verb_class("patch", /update).
rbac_verb_class("escalate", /escalate).
rbac_verb_class("bind", /bind).
rbac_verb_class("*", Class) :- rbac_verb_class(_, Class).

any_namespace("").
any_namespace("*").

# A create request names no object: rules without resourceNames match it,
# and so does resourceNames: [""].
create_name(/any).
create_name("").

# ---- RBAC permissions per binding subject ----
#
# subject_rbac_power(Name, Kind, Ns, Resource, Verb, ResourceName): binding
# subject (Kind, Name) may use Verb (a class above) on Resource (likewise)
# in Ns, from its direct grants or as a member of system:masters.

subject_rbac_grant(Name, Kind, Ns, Resource, ResourceName, Verb) :-
    direct_perm(Name, Kind, Ns, ApiGroup, Resource, ResourceName, Verb),
    rbac_api_group(ApiGroup).

subject_rbac_grant("system:masters", /group, "", "*", /any, "*") :-
    principal_group(_, "system:masters").

subject_rbac_power(Name, Kind, Ns, ResourceClass, VerbClass, ResourceName) :-
    subject_rbac_grant(Name, Kind, Ns, Resource, ResourceName, Verb),
    rbac_resource_class(Resource, ResourceClass),
    rbac_verb_class(Verb, VerbClass).

rbac_subject(Name, Kind) :-
    subject_rbac_power(Name, Kind, _, _, _, _).

# The RBAC permissions a role grants, by role and in the namespace it is
# gained in, for writes that chain. A role that grants every permission is
# left out: having it, the writer gains nothing more by writing, and
# feeding it back would only list every other write.
rule_grants_everything(Rule) :-
    policy_rule_perm(Rule, "*", "*", /any, "*").

clusterrole_grants_everything(Role) :-
    rule_grants_everything(Rule),
    clusterrole_rule(Role, Rule).

role_grants_everything(Ns, Role) :-
    rule_grants_everything(Rule),
    role_rule(Ns, Role, Rule).

rbac_rule_power(Rule, ResourceClass, VerbClass, ResourceName) :-
    policy_rule_perm(Rule, ApiGroup, Resource, ResourceName, Verb),
    rbac_api_group(ApiGroup),
    rbac_resource_class(Resource, ResourceClass),
    rbac_verb_class(Verb, VerbClass).

clusterrole_rbac_power(Role, ResourceClass, VerbClass, ResourceName) :-
    rbac_rule_power(Rule, ResourceClass, VerbClass, ResourceName),
    clusterrole_rule(Role, Rule),
    !clusterrole_grants_everything(Role).

role_rbac_power(Ns, Role, ResourceClass, VerbClass, ResourceName) :-
    rbac_rule_power(Rule, ResourceClass, VerbClass, ResourceName),
    role_rule(Ns, Role, Rule),
    !role_grants_everything(Ns, Role).

# ---- Writers ----

# Holds every permission cluster-wide already, so gains nothing.
subject_holds_everything(Name, Kind) :-
    direct_perm(Name, Kind, "", "*", "*", /any, "*").

principal_holds_everything(Username) :-
    principal_subject(Username, Kind, Name),
    subject_holds_everything(Name, Kind).

rbac_writer(Username, /user) :-
    principal_subject(Username, Kind, Name),
    rbac_subject(Name, Kind),
    known_principal(/user, Username),
    !principal_holds_everything(Username).

rbac_writer(Username, /serviceaccount) :-
    principal_subject(Username, Kind, Name),
    rbac_subject(Name, Kind),
    known_principal(/serviceaccount, Username),
    !principal_holds_everything(Username).

rbac_writer(Group, /group) :-
    rbac_subject(Group, /group),
    !subject_holds_everything(Group, /group).

Decl rbac_writer_subject(Writer, WriterKind, Kind, Name)
  descr [
    doc("Binding subjects whose grants a writer of RBAC objects uses. The writer's own subject is (WriterKind, Writer)."),
    arg(Writer, "user name, system:serviceaccount:<ns>:<name>, or group name"),
    arg(WriterKind, "/user, /serviceaccount, /group, or /assumed_user for a user as it acts when assumed"),
    arg(Kind, "/user, /group or /serviceaccount"),
    arg(Name, "subject name")
  ].

rbac_writer_subject(Username, /user, Kind, Name) :-
    rbac_writer(Username, /user),
    principal_subject(Username, Kind, Name).

rbac_writer_subject(Username, /serviceaccount, Kind, Name) :-
    rbac_writer(Username, /serviceaccount),
    principal_subject(Username, Kind, Name).

rbac_writer_subject(Group, /group, /group, Group) :-
    rbac_writer(Group, /group).

# A user with user_groups groups, assumed through escalation (impersonated),
# acts without those groups (assumed_subject in escalation.mg), so what it
# can write then is worked out apart, as writer kind /assumed_user. Other
# users and ServiceAccounts act the same either way.
user_has_groups(Username) :- user_groups(Username, _).

assumed_holds_everything(Username) :-
    assumed_subject(Username, Kind, Name),
    subject_holds_everything(Name, Kind).

rbac_writer(Username, /assumed_user) :-
    user_has_groups(Username),
    assumed_subject(Username, Kind, Name),
    rbac_subject(Name, Kind),
    !assumed_holds_everything(Username).

rbac_writer_subject(Username, /assumed_user, Kind, Name) :-
    rbac_writer(Username, /assumed_user),
    assumed_subject(Username, Kind, Name).

# Mode /direct: the writer's own RBAC permissions. Mode /all adds those of
# the roles it gains by bind, and those its groups gain, so that a role
# allowing more RBAC writes continues the path, through any number of
# writes. Every relation below carries Mode last, because it is the least
# selective column: /direct rows are what one request may do, /all rows are
# what a writer can reach.
writer_power(Writer, WriterKind, Ns, ResourceClass, VerbClass, ResourceName, /direct) :-
    rbac_writer_subject(Writer, WriterKind, Kind, Name),
    subject_rbac_power(Name, Kind, Ns, ResourceClass, VerbClass, ResourceName).

writer_power(Writer, WriterKind, Ns, ResourceClass, VerbClass, ResourceName, /all) :-
    writer_power(Writer, WriterKind, Ns, ResourceClass, VerbClass, ResourceName, /direct).

writer_power(Writer, WriterKind, Ns, ResourceClass, VerbClass, ResourceName, /all) :-
    rbac_write(Writer, WriterKind, "bind", Ns, _, "ClusterRole", Role, /all),
    clusterrole_rbac_power(Role, ResourceClass, VerbClass, ResourceName).

writer_power(Writer, WriterKind, Ns, ResourceClass, VerbClass, ResourceName, /all) :-
    rbac_write(Writer, WriterKind, "bind", Ns, _, "Role", Role, /all),
    role_rbac_power(Ns, Role, ResourceClass, VerbClass, ResourceName).

writer_power(Writer, WriterKind, Ns, ResourceClass, VerbClass, ResourceName, /all) :-
    rbac_writer_subject(Writer, WriterKind, /group, Group),
    rbac_write(Group, /group, "bind", Ns, _, "ClusterRole", Role, /all),
    clusterrole_rbac_power(Role, ResourceClass, VerbClass, ResourceName).

writer_power(Writer, WriterKind, Ns, ResourceClass, VerbClass, ResourceName, /all) :-
    rbac_writer_subject(Writer, WriterKind, /group, Group),
    rbac_write(Group, /group, "bind", Ns, _, "Role", Role, /all),
    role_rbac_power(Ns, Role, ResourceClass, VerbClass, ResourceName).

# Cluster-scoped requests: ClusterRoleBindings, ClusterRoles.
writer_cluster_power(Writer, WriterKind, ResourceClass, VerbClass, ResourceName, Mode) :-
    writer_power(Writer, WriterKind, "", ResourceClass, VerbClass, ResourceName, Mode).

# Namespaced requests (RoleBindings, Roles, and bind checked for a
# RoleBinding), at "*" or in a namespace; see the header.
writer_ns_power(Writer, WriterKind, "*", ResourceClass, VerbClass, ResourceName, Mode) :-
    writer_power(Writer, WriterKind, Ns, ResourceClass, VerbClass, ResourceName, Mode),
    any_namespace(Ns).

writer_ns_power(Writer, WriterKind, Ns, ResourceClass, VerbClass, ResourceName, Mode) :-
    writer_power(Writer, WriterKind, Ns, ResourceClass, VerbClass, ResourceName, Mode),
    Ns != "",
    Ns != "*".

writer_namespace(Writer, WriterKind, Ns, Mode) :-
    writer_ns_power(Writer, WriterKind, Ns, _, _, _, Mode),
    Ns != "*".

writer_ns_power_at(Writer, WriterKind, Ns, ResourceClass, VerbClass, ResourceName, Mode) :-
    writer_ns_power(Writer, WriterKind, Ns, ResourceClass, VerbClass, ResourceName, Mode).

writer_ns_power_at(Writer, WriterKind, Ns, ResourceClass, VerbClass, ResourceName, Mode) :-
    writer_ns_power(Writer, WriterKind, "*", ResourceClass, VerbClass, ResourceName, Mode),
    writer_namespace(Writer, WriterKind, Ns, Mode).

# ---- Permissions on named objects ----

cluster_object(/clusterroles, Role) :- clusterrole(Role, _).
cluster_object(/clusterrolebindings, Binding) :- binding_roleref("", Binding, _, _).

namespaced_object(/roles, Ns, Role) :- role(Ns, Role, _).
namespaced_object(/rolebindings, Ns, Binding) :-
    binding_roleref(Ns, Binding, _, _),
    Ns != "".

# The writer may use Verb on the cluster-scoped object Name.
writer_cluster_power_on(Writer, WriterKind, ResourceClass, VerbClass, Name, Mode) :-
    writer_cluster_power(Writer, WriterKind, ResourceClass, VerbClass, /any, Mode),
    cluster_object(ResourceClass, Name).

writer_cluster_power_on(Writer, WriterKind, ResourceClass, VerbClass, Name, Mode) :-
    writer_cluster_power(Writer, WriterKind, ResourceClass, VerbClass, Name, Mode),
    cluster_object(ResourceClass, Name).

# The writer may use Verb on object Name in namespace Ns.
writer_ns_power_on(Writer, WriterKind, Ns, ResourceClass, VerbClass, Name, Mode) :-
    writer_ns_power_at(Writer, WriterKind, Ns, ResourceClass, VerbClass, /any, Mode),
    namespaced_object(ResourceClass, Ns, Name).

writer_ns_power_on(Writer, WriterKind, Ns, ResourceClass, VerbClass, Name, Mode) :-
    writer_ns_power_at(Writer, WriterKind, "*", ResourceClass, VerbClass, /any, Mode),
    namespaced_object(ResourceClass, Ns, Name).

writer_ns_power_on(Writer, WriterKind, Ns, ResourceClass, VerbClass, Name, Mode) :-
    writer_ns_power_at(Writer, WriterKind, Ns, ResourceClass, VerbClass, Name, Mode),
    namespaced_object(ResourceClass, Ns, Name).

writer_ns_power_on(Writer, WriterKind, Ns, ResourceClass, VerbClass, Name, Mode) :-
    writer_ns_power_at(Writer, WriterKind, "*", ResourceClass, VerbClass, Name, Mode),
    namespaced_object(ResourceClass, Ns, Name).

# The writer may use Verb on a new object (a create request).
writer_cluster_power_new(Writer, WriterKind, ResourceClass, VerbClass, Mode) :-
    writer_cluster_power(Writer, WriterKind, ResourceClass, VerbClass, ResourceName, Mode),
    create_name(ResourceName).

writer_ns_power_new(Writer, WriterKind, Scope, ResourceClass, VerbClass, Mode) :-
    writer_ns_power_at(Writer, WriterKind, Scope, ResourceClass, VerbClass, ResourceName, Mode),
    create_name(ResourceName).

# ---- Roles a writer may bind ----

# Scope "" for a ClusterRoleBinding, else as for writer_ns_power_at.
writer_bindable_clusterrole(Writer, WriterKind, "", Role, Mode) :-
    writer_cluster_power_on(Writer, WriterKind, /clusterroles, /bind, Role, Mode).

writer_bindable_clusterrole(Writer, WriterKind, Scope, Role, Mode) :-
    writer_ns_power_at(Writer, WriterKind, Scope, /clusterroles, /bind, /any, Mode),
    clusterrole(Role, _).

writer_bindable_clusterrole(Writer, WriterKind, Scope, Role, Mode) :-
    writer_ns_power_at(Writer, WriterKind, Scope, /clusterroles, /bind, Role, Mode),
    clusterrole(Role, _).

# A Role lives in one namespace, so Ns is always that namespace.
writer_bindable_role(Writer, WriterKind, Ns, Role, Mode) :-
    writer_ns_power_on(Writer, WriterKind, Ns, /roles, /bind, Role, Mode).

writer_bindable_ref(Writer, WriterKind, Ns, "ClusterRole", Role, Mode) :-
    writer_bindable_clusterrole(Writer, WriterKind, Ns, Role, Mode).

writer_bindable_ref(Writer, WriterKind, Ns, "Role", Role, Mode) :-
    writer_bindable_role(Writer, WriterKind, Ns, Role, Mode).

# ---- Roles a writer may write any rules into ----
#
# writer_role_writable(Writer, WriterKind, Ns, RoleKind, Role, Mode): Role
# empty for a new one; Ns "" for a ClusterRole, a namespace or "*" for a
# Role.

writer_role_writable(Writer, WriterKind, "", "ClusterRole", Role, Mode) :-
    writer_cluster_power_on(Writer, WriterKind, /clusterroles, /escalate, Role, Mode),
    writer_cluster_power_on(Writer, WriterKind, /clusterroles, /update, Role, Mode).

writer_creates_any_clusterrole(Writer, WriterKind, Mode) :-
    writer_cluster_power_new(Writer, WriterKind, /clusterroles, /escalate, Mode),
    writer_cluster_power_new(Writer, WriterKind, /clusterroles, /create, Mode).

writer_role_writable(Writer, WriterKind, "", "ClusterRole", "", Mode) :-
    writer_creates_any_clusterrole(Writer, WriterKind, Mode).

# Creating a ClusterRole that an aggregating role selects extends it.
clusterrole_aggregating(Role) :-
    clusterrole(Role, Data),
    :match_field(Data, /aggregationRule, Rule),
    :match_field(Rule, /clusterRoleSelectors, Selectors),
    :list:member(_, Selectors).

# A ClusterRole the writer can put any rules into: rewrite it, or, when it
# aggregates, create a role it selects.
writer_extends_clusterrole(Writer, WriterKind, Role, Mode) :-
    writer_role_writable(Writer, WriterKind, "", "ClusterRole", Role, Mode),
    Role != "".

writer_extends_clusterrole(Writer, WriterKind, Role, Mode) :-
    writer_creates_any_clusterrole(Writer, WriterKind, Mode),
    clusterrole_aggregating(Role).

writer_role_writable(Writer, WriterKind, Ns, "Role", Role, Mode) :-
    writer_ns_power_on(Writer, WriterKind, Ns, /roles, /escalate, Role, Mode),
    writer_ns_power_on(Writer, WriterKind, Ns, /roles, /update, Role, Mode).

writer_role_writable(Writer, WriterKind, Scope, "Role", "", Mode) :-
    writer_ns_power_new(Writer, WriterKind, Scope, /roles, /escalate, Mode),
    writer_ns_power_new(Writer, WriterKind, Scope, /roles, /create, Mode).

# ---- What a binding subject can grant itself ----

Decl rbac_write(Name, Kind, Mechanism, Namespace, Binding, RoleKind, Role, Mode)
  descr [
    doc("Binding subject (Kind, Name) can grant itself a role by writing RBAC objects: through a binding it creates or updates, of a role it may bind or write rules into."),
    arg(Name, "user name, system:serviceaccount:<ns>:<name>, or group name"),
    arg(Kind, "/user, /serviceaccount or /group"),
    arg(Mechanism, "bind: bind the role as it is; escalate: every permission, written into the role"),
    arg(Namespace, "where the role applies: empty for cluster-wide (ClusterRoleBinding), a namespace (RoleBinding), or * for a RoleBinding in every namespace"),
    arg(Binding, "the existing binding used, or empty for a new one"),
    arg(RoleKind, "ClusterRole or Role"),
    arg(Role, "the role, or empty for a new one"),
    arg(Mode, "/direct: with the writer's own RBAC permissions; /all: also those of roles it gains, so writes chain")
  ].

# bind, new ClusterRoleBinding.
rbac_write(Writer, WriterKind, "bind", "", "", "ClusterRole", Role, Mode) :-
    writer_cluster_power_new(Writer, WriterKind, /clusterrolebindings, /create, Mode),
    writer_bindable_clusterrole(Writer, WriterKind, "", Role, Mode).

# bind, existing ClusterRoleBinding.
rbac_write(Writer, WriterKind, "bind", "", Binding, "ClusterRole", Role, Mode) :-
    writer_cluster_power_on(Writer, WriterKind, /clusterrolebindings, /update, Binding, Mode),
    binding_roleref("", Binding, "ClusterRole", Role),
    writer_bindable_clusterrole(Writer, WriterKind, "", Role, Mode).

# bind, new RoleBinding of a ClusterRole.
rbac_write(Writer, WriterKind, "bind", Scope, "", "ClusterRole", Role, Mode) :-
    writer_ns_power_new(Writer, WriterKind, Scope, /rolebindings, /create, Mode),
    writer_bindable_clusterrole(Writer, WriterKind, Scope, Role, Mode).

# bind, new RoleBinding of a Role.
rbac_write(Writer, WriterKind, "bind", Ns, "", "Role", Role, Mode) :-
    writer_bindable_role(Writer, WriterKind, Ns, Role, Mode),
    writer_ns_power_new(Writer, WriterKind, Ns, /rolebindings, /create, Mode).

rbac_write(Writer, WriterKind, "bind", Ns, "", "Role", Role, Mode) :-
    writer_bindable_role(Writer, WriterKind, Ns, Role, Mode),
    writer_ns_power_new(Writer, WriterKind, "*", /rolebindings, /create, Mode).

# bind, existing RoleBinding.
rbac_write(Writer, WriterKind, "bind", Ns, Binding, RoleKind, Role, Mode) :-
    writer_ns_power_on(Writer, WriterKind, Ns, /rolebindings, /update, Binding, Mode),
    binding_roleref(Ns, Binding, RoleKind, Role),
    writer_bindable_ref(Writer, WriterKind, Ns, RoleKind, Role, Mode).

rbac_write(Writer, WriterKind, "bind", Ns, Binding, "ClusterRole", Role, Mode) :-
    writer_ns_power_on(Writer, WriterKind, Ns, /rolebindings, /update, Binding, Mode),
    binding_roleref(Ns, Binding, "ClusterRole", Role),
    writer_bindable_clusterrole(Writer, WriterKind, "*", Role, Mode).

# escalate, a role the writer holds through an existing binding: a
# ClusterRole cluster-wide or in a RoleBinding's namespace, or a Role.
rbac_write(Writer, WriterKind, "escalate", Ns, Binding, "ClusterRole", Role, Mode) :-
    writer_extends_clusterrole(Writer, WriterKind, Role, Mode),
    binding_roleref(Ns, Binding, "ClusterRole", Role),
    rbac_writer_subject(Writer, WriterKind, Kind, Name),
    binding_subject(Ns, Binding, Kind, Name).

rbac_write(Writer, WriterKind, "escalate", Ns, Binding, "Role", Role, Mode) :-
    writer_role_writable(Writer, WriterKind, Ns, "Role", Role, Mode),
    Role != "",
    rbac_writer_subject(Writer, WriterKind, Kind, Name),
    binding_subject(Ns, Binding, Kind, Name),
    binding_roleref(Ns, Binding, "Role", Role).

# escalate, an existing role the writer can bind.
rbac_write(Writer, WriterKind, "escalate", Ns, Binding, "ClusterRole", Role, Mode) :-
    writer_extends_clusterrole(Writer, WriterKind, Role, Mode),
    rbac_write(Writer, WriterKind, "bind", Ns, Binding, "ClusterRole", Role, Mode).

rbac_write(Writer, WriterKind, "escalate", Ns, Binding, "Role", Role, Mode) :-
    writer_role_writable(Writer, WriterKind, Ns, "Role", Role, Mode),
    Role != "",
    rbac_write(Writer, WriterKind, "bind", Ns, Binding, "Role", Role, Mode).

# escalate, a new ClusterRole bound cluster-wide, or in RoleBindings; bind
# is checked on the name the writer picks, so any bind grant will do.
rbac_write(Writer, WriterKind, "escalate", "", "", "ClusterRole", "", Mode) :-
    writer_creates_any_clusterrole(Writer, WriterKind, Mode),
    writer_cluster_power_new(Writer, WriterKind, /clusterrolebindings, /create, Mode),
    writer_cluster_power(Writer, WriterKind, /clusterroles, /bind, _, Mode).

rbac_write(Writer, WriterKind, "escalate", Scope, "", "ClusterRole", "", Mode) :-
    writer_creates_any_clusterrole(Writer, WriterKind, Mode),
    writer_ns_power_new(Writer, WriterKind, Scope, /rolebindings, /create, Mode),
    writer_ns_power_at(Writer, WriterKind, Scope, /clusterroles, /bind, _, Mode).

# escalate, a new Role.
rbac_write(Writer, WriterKind, "escalate", Scope, "", "Role", "", Mode) :-
    writer_role_writable(Writer, WriterKind, Scope, "Role", "", Mode),
    writer_ns_power_new(Writer, WriterKind, Scope, /rolebindings, /create, Mode),
    writer_ns_power_at(Writer, WriterKind, Scope, /roles, /bind, _, Mode).

# ---- Results ----

Decl rbac_write_binding(Name, Kind, Mechanism, Namespace, Binding, RoleKind, Role)
  descr [
    doc("Writer (Kind, Name) can grant itself a role by writing RBAC objects, possibly after earlier writes that gain it more RBAC permissions."),
    arg(Name, "user name, system:serviceaccount:<ns>:<name>, or group name"),
    arg(Kind, "/user, /serviceaccount or /group; /assumed_user for a user with user_groups groups, as it acts when assumed through escalation (assumed_subject)"),
    arg(Mechanism, "bind: bind the role as it is; escalate: every permission, written into the role"),
    arg(Namespace, "where the role applies: empty for cluster-wide (ClusterRoleBinding), a namespace (RoleBinding), or * for a RoleBinding in every namespace"),
    arg(Binding, "the existing binding used, or empty for a new one"),
    arg(RoleKind, "ClusterRole or Role"),
    arg(Role, "the role, or empty for a new one")
  ].

rbac_write_binding(Name, Kind, Mechanism, Namespace, Binding, RoleKind, Role) :-
    rbac_write(Name, Kind, Mechanism, Namespace, Binding, RoleKind, Role, /all).

Decl rbac_write_binding_direct(Name, Kind, Mechanism, Namespace, Binding, RoleKind, Role)
  descr [
    doc("The rbac_write_binding rows a writer can write in one request, with the RBAC permissions it holds now."),
    arg(Name, "as in rbac_write_binding"),
    arg(Kind, "as in rbac_write_binding"),
    arg(Mechanism, "as in rbac_write_binding"),
    arg(Namespace, "as in rbac_write_binding"),
    arg(Binding, "as in rbac_write_binding"),
    arg(RoleKind, "as in rbac_write_binding"),
    arg(Role, "as in rbac_write_binding")
  ].

rbac_write_binding_direct(Name, Kind, Mechanism, Namespace, Binding, RoleKind, Role) :-
    rbac_write(Name, Kind, Mechanism, Namespace, Binding, RoleKind, Role, /direct).

Decl rbac_role_writable(Name, Kind, Namespace, RoleKind, Role)
  descr [
    doc("Writer (Kind, Name) may write any rules into a role in one request, using escalate: update an existing role, or create a new one."),
    arg(Name, "user name, system:serviceaccount:<ns>:<name>, or group name"),
    arg(Kind, "/user, /serviceaccount or /group"),
    arg(Namespace, "empty for a ClusterRole; for a Role its namespace, or * for every namespace"),
    arg(RoleKind, "ClusterRole or Role"),
    arg(Role, "the role, or empty for a new one")
  ].

rbac_role_writable(Name, Kind, Namespace, RoleKind, Role) :-
    writer_role_writable(Name, Kind, Namespace, RoleKind, Role, /direct).

Decl rbac_write_anything(Username)
  descr [
    doc("Principals that may write any RBAC object: members of system:masters, for whom the API server skips authorization and the escalation checks, and principals RBAC grants every permission cluster-wide. Listed here rather than in the write relations above, which leave out writers that already hold everything, as gaining nothing."),
    arg(Username, "user name or system:serviceaccount:<ns>:<name>")
  ].

rbac_write_anything(Username) :-
    principal_group(Username, "system:masters").

rbac_write_anything(Username) :-
    principal_holds_everything(Username).

Decl rbac_write_role(Writer, WriterKind, Mechanism, Binding, Role)
  descr [
    doc("rbac_write_binding_direct for ClusterRoleBindings of ClusterRoles, with users and ServiceAccounts as /principal. Kept for tests/rbac_compat.rs."),
    arg(Writer, "user name, system:serviceaccount:<ns>:<name>, or group name"),
    arg(WriterKind, "/principal for a user or ServiceAccount, /group for a group"),
    arg(Mechanism, "bind or escalate"),
    arg(Binding, "the existing ClusterRoleBinding used, or empty for a new one"),
    arg(Role, "the ClusterRole, or empty for a new one")
  ].

rbac_write_role(Writer, /principal, Mechanism, Binding, Role) :-
    rbac_write(Writer, /user, Mechanism, "", Binding, "ClusterRole", Role, /direct).

rbac_write_role(Writer, /principal, Mechanism, Binding, Role) :-
    rbac_write(Writer, /serviceaccount, Mechanism, "", Binding, "ClusterRole", Role, /direct).

rbac_write_role(Writer, /group, Mechanism, Binding, Role) :-
    rbac_write(Writer, /group, Mechanism, "", Binding, "ClusterRole", Role, /direct).

# ---- Feeding escalation.mg ----
#
# The permissions escalation.mg's mechanisms need, by resource and verb,
# projected per role like clusterrole_rbac_perm.

# (Action, Resource, Verb), each matched literally or by "*".
escalation_action(/pods_create, "pods", "create").
escalation_action(/pods_exec, "pods/exec", "create").
escalation_action(/pods_attach, "pods/attach", "create").
escalation_action(/sa_token, "serviceaccounts/token", "create").
escalation_action(/sa_impersonate, "serviceaccounts", "impersonate").
escalation_action(/user_impersonate, "users", "impersonate").
escalation_action(/group_impersonate, "groups", "impersonate").

escalation_matches(Resource, Verb, Action) :- escalation_action(Action, Resource, Verb).
escalation_matches("*", Verb, Action) :- escalation_action(Action, _, Verb).
escalation_matches(Resource, "*", Action) :- escalation_action(Action, Resource, _).
escalation_matches("*", "*", Action) :- escalation_action(Action, _, _).

core_api_group("").
core_api_group("*").

escalation_rule_action(Rule, Action) :-
    policy_rule_perm(Rule, ApiGroup, Resource, _, Verb),
    core_api_group(ApiGroup),
    escalation_matches(Resource, Verb, Action).

clusterrole_escalation_action(Role, Action) :-
    escalation_rule_action(Rule, Action),
    clusterrole_rule(Role, Rule).

role_escalation_action(Ns, Role, Action) :-
    escalation_rule_action(Rule, Action),
    role_rule(Ns, Role, Rule).

gained_action(Name, Kind, Ns, Action) :-
    rbac_write_binding(Name, Kind, "bind", Ns, _, "ClusterRole", Role),
    clusterrole_escalation_action(Role, Action).

gained_action(Name, Kind, Ns, Action) :-
    rbac_write_binding(Name, Kind, "bind", Ns, _, "Role", Role),
    role_escalation_action(Ns, Role, Action).

gained_action(Name, Kind, Ns, Action) :-
    rbac_write_binding(Name, Kind, "escalate", Ns, _, _, _),
    escalation_action(Action, _, _).

# Pods and ServiceAccounts are namespaced, so a gain in every namespace
# reaches them as a cluster-wide grant does.
gained_namespaced_action(Name, Kind, Ns, Action) :-
    gained_action(Name, Kind, Ns, Action),
    Ns != "*".

gained_namespaced_action(Name, Kind, "", Action) :-
    gained_action(Name, Kind, "*", Action).

# How each action reaches a ServiceAccount, with the mechanism labels
# src/rbac uses: any ServiceAccount in the namespace, or one a pod there
# runs as.
action_reaches_serviceaccount(/pods_create, "pod-create").
action_reaches_serviceaccount(/sa_token, "token").
action_reaches_serviceaccount(/sa_impersonate, "impersonate").
action_reaches_pod(/pods_exec, "pod-exec").
action_reaches_pod(/pods_attach, "pod-exec").

gained_reachable_sa(Name, Kind, SANs, SAName, Mechanism) :-
    gained_namespaced_action(Name, Kind, SANs, Action),
    action_reaches_serviceaccount(Action, Mechanism),
    serviceaccount(SANs, SAName, _).

gained_reachable_sa(Name, Kind, SANs, SAName, Mechanism) :-
    gained_namespaced_action(Name, Kind, "", Action),
    action_reaches_serviceaccount(Action, Mechanism),
    serviceaccount(SANs, SAName, _).

gained_reachable_sa(Name, Kind, PodNs, SAName, Mechanism) :-
    gained_namespaced_action(Name, Kind, PodNs, Action),
    action_reaches_pod(Action, Mechanism),
    pod_sa(PodNs, _, SAName).

gained_reachable_sa(Name, Kind, PodNs, SAName, Mechanism) :-
    gained_namespaced_action(Name, Kind, "", Action),
    action_reaches_pod(Action, Mechanism),
    pod_sa(PodNs, _, SAName).

Decl gained_escalation_hop(Name, Kind, Target, Mechanism)
  descr [
    doc("Like subject_escalation_hop, through a role binding subject (Kind, Name) can grant itself by writing RBAC objects (rbac_write_binding) rather than its own grants. Kept apart from escalation_hop, which answers what a principal may do now."),
    arg(Name, "subject name: user or group name, or system:serviceaccount:<ns>:<name>"),
    arg(Kind, "/user, /group or /serviceaccount"),
    arg(Target, "the user or ServiceAccount whose identity can then be assumed"),
    arg(Mechanism, "pod-create, token, impersonate or pod-exec")
  ].

gained_escalation_hop(Name, Kind, Target, Mechanism) :-
    gained_reachable_sa(Name, Kind, SANs, SAName, Mechanism)
    |> let Target = fn:string:concat("system:serviceaccount:", SANs, ":", SAName).

# Users and groups are cluster-scoped: only a cluster-wide gain counts.
gained_escalation_hop(Name, Kind, Target, "impersonate") :-
    gained_action(Name, Kind, "", /user_impersonate),
    user_has_own_grant(Target).

gained_group_impersonate(Name, Kind) :-
    gained_action(Name, Kind, "", /group_impersonate).

# The escalation closure of escalation.mg, continued through these hops:
# from a principal as it logs in, from an identity assumed on the way, and
# from a group. An assumed user with user_groups groups uses its
# /assumed_user writes, not those it could make logged in.
controls_identity(P, Target) :-
    principal_subject(P, Kind, Name),
    gained_escalation_hop(Name, Kind, Target, _),
    P != Target.

assumed_gains_subject(Identity, /group, Group) :-
    assumed_subject(Identity, /group, Group).

assumed_gains_subject(Identity, /serviceaccount, Identity) :-
    assumed_subject(Identity, /serviceaccount, Identity).

assumed_gains_subject(Identity, /user, Identity) :-
    assumed_subject(Identity, /user, Identity),
    !user_has_groups(Identity).

assumed_gains_subject(Identity, /assumed_user, Identity) :-
    assumed_subject(Identity, /user, Identity),
    user_has_groups(Identity).

assumed_escalation_hop(Identity, Target) :-
    assumed_gains_subject(Identity, Kind, Name),
    gained_escalation_hop(Name, Kind, Target, _).

group_escalation_hop(Group, Target) :-
    gained_escalation_hop(Group, /group, Target, _).

controls_group(P, Group) :-
    principal_subject(P, Kind, Name),
    gained_group_impersonate(Name, Kind),
    group_has_grant(Group).

assumed_group_impersonate(Identity) :-
    assumed_gains_subject(Identity, Kind, Name),
    gained_group_impersonate(Name, Kind).

group_controls_group(Group, Other) :-
    gained_group_impersonate(Group, /group),
    group_has_grant(Other),
    Group != Other.

# A user or group that can grant itself a role holds grants of its own,
# which impersonating it brings.
user_has_own_grant(Username) :-
    rbac_write_binding(Username, /user, _, _, _, _, _),
    !user_has_groups(Username).

user_has_own_grant(Username) :-
    rbac_write_binding(Username, /assumed_user, _, _, _, _, _).

group_has_grant(Group) :-
    rbac_write_binding(Group, /group, _, _, _, _, _).
