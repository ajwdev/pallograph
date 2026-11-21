# Escalation closure - who can reach whom by chaining pivots.
#
# A pivot is one step of escalation: whoever holds one node's grants can
# take over another node, by some mechanism. This file has one pivot
# relation and one closure over it, whatever system a pivot comes from.
# Nothing here names a system, a kind or a mechanism: each system's rules
# (its adapter) fill the inputs, and a pivot whose two ends are in
# different systems links them. The Kubernetes adapter is
# k8s_rbac_escalation.mg and k8s_rbac_write.mg.
#
# Inputs, filled by each adapter:
#   pivot/8          - one pivot: whoever holds From's grants can take over
#                      To, by a mechanism and from a source
#   acts_as/7        - whose grants a node acts with, per mode
#   pivot_mode/2     - which pivot source each acts_as mode uses
#   start_kind/2     - the kinds a path can start from
#   identity_kind/2  - the kinds that are identities (for views)
#
# Derived relations (IDB):
#   node_pivot/6  - pivot re-keyed by the node a path reaches (a lookup
#                   table for the recursion)
#   controls/6    - every node From reaches in one or more pivots
#
# Glossary. Each term has one meaning in this file; the Kubernetes and IAM
# words are the nearest equivalents.
#
#   node        Anything a path can pass through: (name, system, kind).
#   system      Where a node lives: /k8s, /aws, ...
#   identity    A node that can be assumed (identity_kind): a Kubernetes
#               user or ServiceAccount, an IAM role.
#   grant       A permission given to a grantee. Kubernetes: what a
#               binding's role allows (direct_perm). IAM: a policy.
#   grantee     Whatever a grant names. Kubernetes: a binding subject (a
#               User, Group or ServiceAccount in a binding's subjects).
#               IAM: the role, user or group a policy is attached to.
#   ambient     Held without doing anything ("ambient authority", from
#               capability security). Logged in as alice, the grants of
#               alice and of her groups apply. acts_as lists a node's
#               ambient grantees.
#   mode        How a node is acting, which changes its ambient grantees:
#               Kubernetes /login (with user_groups) vs /assumed (reached
#               by a pivot, without them).
#   pivot       One escalation step a grant makes possible: becoming
#               another node, by a mechanism (/pod_exec, /token,
#               /impersonate, /pod_identity, ...). Unlike acts_as, a
#               pivot is an action.
#   source      Where the grant behind a pivot comes from: /grant (held
#               already) or /rbac_write (one the grantee can give itself
#               by writing RBAC objects first). pivot_mode pairs each
#               source with the mode that may use it.
#   path        Alternating ambient grantees and pivots, which controls
#               closes over.
#
# Example, from examples/eks-pod-identity/:
#
#   alice
#     -acts_as->               alice (the grantee in her binding)
#     -pivot /pod_exec->       app:uploader
#     -acts_as->               app:uploader
#     -pivot /pod_identity->   role/uploader
#     ...
#
#   acts_as("alice", /k8s, /user, "alice", /k8s, /user, /login)
#   direct_perm("alice", /user, "app", "", "pods/exec", /any, "create")
#   pivot("alice", /k8s, /user, "system:serviceaccount:app:uploader",
#         /k8s, /serviceaccount, /pod_exec, /grant)
#
# A node is three flat columns: name, system, kind. A path starts at a
# grantee (start_kind): whatever a grant names, such as a Kubernetes
# binding subject or an IAM role. Each later pivot starts from what the
# previous one reached: that node acts with some grantees' grants in some
# mode (acts_as), and takes their pivots from the source that mode uses
# (pivot_mode). A mode with no pivot_mode row, such as Kubernetes's
# /login, never continues a path; views read it instead.
#
# What a node acts as is up to its adapter. A node can act as a grantee of
# a kind that exists only partway along a path, and that grantee's pivots
# say what it can do there (in Kubernetes, /assumed_user and
# /impersonated_group).

Decl pivot(From, FromSystem, FromKind, To, ToSystem, ToKind, Mechanism, Source)
  descr [
    doc("One pivot: whoever holds the grants of (FromSystem, FromKind, From) can assume identity To, or act as group To, by Mechanism."),
    arg(From, "grantee name, e.g. a Kubernetes user or group name, system:serviceaccount:<ns>:<name>, or an IAM role ARN"),
    arg(FromSystem, "From's system, e.g. /k8s"),
    arg(FromKind, "From's kind within its system, e.g. /user, /group or /serviceaccount"),
    arg(To, "name of the node taken over"),
    arg(ToSystem, "To's system"),
    arg(ToKind, "To's kind within its system"),
    arg(Mechanism, "how the pivot is made, e.g. /impersonate, /token, /pod_exec or /pod_create"),
    arg(Source, "what the pivot comes from, e.g. /grant (From's own grants) or /rbac_write (a role From can grant itself); pivot_mode says which acts_as mode uses it")
  ].

Decl acts_as(Actor, ActorSystem, ActorKind, Grantee, GranteeSystem, GranteeKind, Mode)
  descr [
    doc("Node (ActorSystem, ActorKind, Actor) acts with the grants of (GranteeSystem, GranteeKind, Grantee) in Mode. Pivots from the grantee are pivots from the node."),
    arg(Actor, "node name"),
    arg(ActorSystem, "the node's system"),
    arg(ActorKind, "the node's kind, as pivot names it as a To"),
    arg(Grantee, "grantee name"),
    arg(GranteeSystem, "the grantee's system"),
    arg(GranteeKind, "the grantee's kind"),
    arg(Mode, "how the node is acting, e.g. /login, /assumed or /assumed_writes; pivot_mode says which modes continue a path")
  ].

Decl pivot_mode(Mode, Source)
  descr [
    doc("A node reached partway along a path, acting in Mode, takes its grantees' pivots from Source."),
    arg(Mode, "an acts_as mode"),
    arg(Source, "a pivot source")
  ].

Decl start_kind(System, Kind)
  descr [
    doc("Paths start from grantees of this kind."),
    arg(System, "the grantee's system"),
    arg(Kind, "the grantee's kind")
  ].

Decl identity_kind(System, Kind)
  descr [
    doc("Nodes of this kind are identities: something that can be assumed, not a group of them. The closure doesn't read it; views over controls do."),
    arg(System, "the node's system"),
    arg(Kind, "the node's kind")
  ].

Decl controls(From, FromSystem, FromKind, To, ToSystem, ToKind)
  descr [
    doc("Whoever holds the grants of (FromSystem, FromKind, From) reaches To in one or more pivots (transitively closed)."),
    arg(From, "grantee name"),
    arg(FromSystem, "From's system"),
    arg(FromKind, "From's kind, one start_kind lists"),
    arg(To, "name of the node reached"),
    arg(ToSystem, "To's system"),
    arg(ToKind, "To's kind")
  ].

# pivot is keyed by grantee, but a path arrives at a node, which holds the
# grants of several grantees (acts_as). node_pivot joins the two once, so
# that each round of the recursion below looks up a reached node's
# pivots directly. Each row is a pivot row with From replaced by a node
# that holds From's grants, and the mechanism dropped; nothing in it is
# new. Joining acts_as and pivot inside the recursive rule instead gives
# the same answers but redoes the join every round, about 20% slower on
# the DD backend (medium fixture).
node_pivot(Node, NodeSystem, NodeKind, To, ToSystem, ToKind) :-
    acts_as(Node, NodeSystem, NodeKind, Grantee, GranteeSystem, GranteeKind, Mode),
    pivot_mode(Mode, Source),
    pivot(Grantee, GranteeSystem, GranteeKind, To, ToSystem, ToKind, _, Source).

# Each recursive rule extends a path by one pivot, so why on a controls
# fact shows a shortest path: the interpreter derives paths one pivot per
# round and keeps the first proof, and the DD backend's lazy provenance
# picks the proof of least height.
controls(From, FromSystem, FromKind, To, ToSystem, ToKind) :-
    pivot(From, FromSystem, FromKind, To, ToSystem, ToKind, _, _),
    start_kind(FromSystem, FromKind).

controls(From, FromSystem, FromKind, To, ToSystem, ToKind) :-
    controls(From, FromSystem, FromKind, Mid, MidSystem, MidKind),
    node_pivot(Mid, MidSystem, MidKind, To, ToSystem, ToKind).
