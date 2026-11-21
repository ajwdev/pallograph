# EKS Pod Identity and access entries as escalation pivots: an AWS adapter
# for the escalation closure (rules/closure.mg), loaded with --rules and
# json-tuples datasources, with no change to Pallograph itself.
#
# It adds one system, /aws, with one kind, /role, and links it to the
# cluster both ways:
#   - into AWS: a ServiceAccount with a Pod Identity association can get
#     the role's credentials (mechanism /pod_identity);
#   - within AWS: a role that may assume another role (/sts_assume_role);
#   - back into the cluster: an access entry maps the role to a Kubernetes
#     user and groups, which the role acts as once assumed (acts_as).
#
# Deciding which roles may assume which is IAM policy evaluation (identity
# policy on one side, trust policy on the other, with conditions). The
# loader does that and hands over the result as aws_role_can_assume; these
# rules only chain the edges.
#
# The inputs are for the one cluster Pallograph is looking at: the loader
# filters Pod Identity associations and access entries by cluster name.

# ---- Facts loaded from AWS (EDB) ----

Decl aws_pod_identity_association(Namespace, ServiceAccount, RoleArn)
  descr [
    doc("An EKS Pod Identity association: pods running as the ServiceAccount get the role's credentials (aws eks list-pod-identity-associations)."),
    arg(Namespace, "the ServiceAccount's namespace"),
    arg(ServiceAccount, "the ServiceAccount's name"),
    arg(RoleArn, "IAM role ARN")
  ].

Decl aws_role_trusts_pod_identity(RoleArn)
  descr [
    doc("The role's trust policy lets pods.eks.amazonaws.com call sts:AssumeRole and sts:TagSession, which Pod Identity needs."),
    arg(RoleArn, "IAM role ARN")
  ].

Decl aws_role_can_assume(RoleArn, TargetRoleArn)
  descr [
    doc("A session of RoleArn may assume TargetRoleArn: its policies allow sts:AssumeRole on the target, and the target's trust policy allows RoleArn."),
    arg(RoleArn, "IAM role ARN"),
    arg(TargetRoleArn, "IAM role ARN")
  ].

Decl aws_eks_access_entry(PrincipalArn, Username)
  descr [
    doc("An EKS access entry: the IAM principal authenticates to the cluster as Username."),
    arg(PrincipalArn, "IAM role ARN"),
    arg(Username, "Kubernetes username")
  ].

Decl aws_eks_access_entry_group(PrincipalArn, Group)
  descr [
    doc("A Kubernetes group an access entry puts the IAM principal in (kubernetesGroups)."),
    arg(PrincipalArn, "IAM role ARN"),
    arg(Group, "Kubernetes group name")
  ].

# ---- What the closure needs to know about AWS ----

identity_kind(/aws, /role).
start_kind(/aws, /role).

aws_role(Role) :- aws_pod_identity_association(_, _, Role).
aws_role(Role) :- aws_role_can_assume(Role, _).
aws_role(Role) :- aws_role_can_assume(_, Role).
aws_role(Role) :- aws_eks_access_entry(Role, _).
aws_role(Role) :- aws_eks_access_entry_group(Role, _).

# ---- Pivots ----

# Whoever acts as the ServiceAccount can get the role's credentials: a pod
# running as it, or a token for it (the Pod Identity agent accepts a
# projected token with audience pods.eks.amazonaws.com).
pivot(ServiceAccount, /k8s, /serviceaccount, Role, /aws, /role, /pod_identity, /grant) :-
    aws_pod_identity_association(Namespace, Name, Role),
    aws_role_trusts_pod_identity(Role)
    |> let ServiceAccount = fn:string:concat("system:serviceaccount:", Namespace, ":", Name).

pivot(Role, /aws, /role, Target, /aws, /role, /sts_assume_role, /grant) :-
    aws_role_can_assume(Role, Target).

# ---- What an assumed role acts as ----

# Its own AWS permissions.
acts_as(Role, /aws, /role, Role, /aws, /role, /assumed) :-
    aws_role(Role).

# In the cluster, the access entry's user and groups, plus
# system:authenticated, for pivots from their grants and from roles they
# can grant themselves. Access policies (EKS's own authorizer) are not
# modeled.
aws_eks_mode(/assumed).
aws_eks_mode(/assumed_writes).

acts_as(Role, /aws, /role, Username, /k8s, /user, Mode) :-
    aws_eks_access_entry(Role, Username),
    aws_eks_mode(Mode).

acts_as(Role, /aws, /role, "system:authenticated", /k8s, /group, Mode) :-
    aws_eks_access_entry(Role, _),
    aws_eks_mode(Mode).

acts_as(Role, /aws, /role, Group, /k8s, /group, Mode) :-
    aws_eks_access_entry_group(Role, Group),
    aws_eks_mode(Mode).

# ---- Views ----

Decl k8s_group_via_aws(Principal, Group, Role)
  descr [
    doc("Kubernetes principal Principal reaches AWS role Role, which acts as Kubernetes group Group through an access entry."),
    arg(Principal, "user name or system:serviceaccount:<ns>:<name>"),
    arg(Group, "Kubernetes group name"),
    arg(Role, "IAM role ARN")
  ].

k8s_group_via_aws(Principal, Group, Role) :-
    acts_as(Principal, /k8s, _, Grantee, GranteeSystem, GranteeKind, /login),
    controls(Grantee, GranteeSystem, GranteeKind, Role, /aws, /role),
    acts_as(Role, /aws, /role, Group, /k8s, /group, /assumed).
