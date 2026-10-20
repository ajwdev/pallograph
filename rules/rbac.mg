# RBAC decisions - joins subjects to role permissions and answers
# authorization requests the way the kube-apiserver RBAC authorizer does.
#
# The model is split across three files:
#   rbac_roles.mg     - what each Role and ClusterRole grants (role_rule,
#                       clusterrole_rule, policy_rule_perm), including
#                       ClusterRole aggregation
#   rbac_subjects.mg  - who each binding applies to (binding_subject,
#                       binding_roleref) and the subjects a principal acts
#                       as (principal_group, principal_subject)
#   rbac.mg           - this file: direct_perm, direct_url_perm and
#                       rbac_allowed
#
# Facts loaded from the cluster or supplied by the caller (EDB) used here:
#   access_request/9, access_request_group/2  - requests to decide
#
# Derived relations (IDB):
#   direct_perm/7, direct_url_perm/4  (grants per binding subject)
#   rbac_allowed/1                    (decisions for access_request)
#
# Grants are kept per binding subject, not copied to every member of a
# group: a grant to system:authenticated would otherwise be repeated for
# every principal. To ask what a principal can do, join principal_subject
# with direct_perm:
#
#   principal_subject(P, Kind, Name), direct_perm(Name, Kind, Ns, G, R, N, V)
#
# Wildcards ("*") are kept as literal strings in the permission relations and
# only interpreted by rbac_allowed. A ResourceName of /any means any name.

# ---- Grants per binding subject ----
#
# The subject name comes first in these relations because the planner looks
# a relation up by the first argument already bound (or constant) and checks
# the rest afterwards. Keyed on Kind, which only has three values, a join
# would compare every request against almost every grant.

Decl direct_perm(Principal, Kind, Namespace, ApiGroup, Resource, ResourceName, Verb)
  descr [
    doc("Resource permissions each binding subject holds directly, before group membership or escalation; join principal_subject to expand groups."),
    arg(Principal, "subject name: user or group name, or system:serviceaccount:<ns>:<name>"),
    arg(Kind, "/user, /group or /serviceaccount"),
    arg(Namespace, "namespace the grant applies in; empty for cluster-wide"),
    arg(ApiGroup, "API group; * is a literal wildcard"),
    arg(Resource, "resource or resource/subresource; * and */sub are literal wildcards"),
    arg(ResourceName, "object name, or /any for every name; the empty name and * are literal names"),
    arg(Verb, "verb, e.g. get/list/create; * is a literal wildcard")
  ].

# RoleBinding to a Role: the Role lives in the binding's namespace, and the
# grant applies there.
direct_perm(Name, Kind, Namespace, ApiGroup, Resource, ResourceName, Verb) :-
    binding_subject(Namespace, Binding, Kind, Name),
    binding_roleref(Namespace, Binding, "Role", Role),
    role_rule(Namespace, Role, Rule),
    policy_rule_perm(Rule, ApiGroup, Resource, ResourceName, Verb).

# RoleBinding to a ClusterRole applies in the binding's namespace;
# ClusterRoleBinding (binding namespace "") applies cluster-wide.
direct_perm(Name, Kind, Namespace, ApiGroup, Resource, ResourceName, Verb) :-
    binding_subject(Namespace, Binding, Kind, Name),
    binding_roleref(Namespace, Binding, "ClusterRole", Role),
    clusterrole_rule(Role, Rule),
    policy_rule_perm(Rule, ApiGroup, Resource, ResourceName, Verb).

# Non-resource requests are never namespaced, so the authorizer only reaches
# URL rules through ClusterRoleBindings.
Decl direct_url_perm(Principal, Kind, Url, Verb)
  descr [
    doc("Non-resource URL permissions each binding subject holds via ClusterRoleBindings."),
    arg(Principal, "subject name: user or group name, or system:serviceaccount:<ns>:<name>"),
    arg(Kind, "/user, /group or /serviceaccount"),
    arg(Url, "nonResourceURLs entry; * and a trailing * are literal wildcards"),
    arg(Verb, "verb; * is a literal wildcard")
  ].

direct_url_perm(Name, Kind, Url, Verb) :-
    binding_subject("", Binding, Kind, Name),
    binding_roleref("", Binding, "ClusterRole", Role),
    clusterrole_rule(Role, Rule),
    policy_rule_url_perm(Rule, Url, Verb).

# ---- Access decisions ----
#
# rbac_allowed(Id) answers, for each access_request, whether the RBAC
# authorizer would allow it. It mirrors RuleAllows in k8s
# plugin/pkg/auth/authorizer/rbac/rbac.go. The RBAC compatibility harness
# (tests/rbac_compat.rs) measures it against the real authorizer.
#
# The request_* relations list, per request, every value a grant could hold
# and still match one field of the request. A request is allowed when some
# direct_perm row is built entirely from such values.

Decl rbac_allowed(Id)
  descr [
    doc("access_request ids the RBAC authorizer would allow."),
    arg(Id, "access_request id")
  ].

# Subjects a request matches: a User or ServiceAccount subject by username,
# a Group subject by membership.
request_subject(Id, /user, User) :-
    access_request(Id, User, _, _, _, _, _, _, _).

request_subject(Id, /serviceaccount, User) :-
    access_request(Id, User, _, _, _, _, _, _, _).

request_subject(Id, /group, Group) :-
    access_request_group(Id, Group).

request_subject(Id, /group, Group) :-
    request_service_account_group(Id, Group).

# A ServiceAccount token authenticates as system:serviceaccount:<ns>:<name>
# and carries the groups system:serviceaccounts,
# system:serviceaccounts:<ns> and system:authenticated. Requests list no
# groups for service accounts, so they are derived from the username here.
request_service_account_rest(Id, Rest) :-
    access_request(Id, User, _, _, _, _, _, _, _),
    :string:starts_with(User, "system:serviceaccount:")
    |> let Rest = fn:string:replace(User, "system:serviceaccount:", "", 1).

# The username must split into <ns>:<name>.
request_service_account(Id, User) :-
    request_service_account_rest(Id, Rest),
    :string:contains(Rest, ":"),
    access_request(Id, User, _, _, _, _, _, _, _).

# There is no string split, so instead of extracting <ns> from the username,
# each system:serviceaccounts:<ns> group some binding names is turned into
# the username prefix system:serviceaccount:<ns>: and tested against it.
# A <ns> containing ":" can never be the namespace part of a username.
service_account_namespace_group(Group, Namespace) :-
    binding_subject(_, _, /group, Group),
    :string:starts_with(Group, "system:serviceaccounts:")
    |> let Namespace = fn:string:replace(Group, "system:serviceaccounts:", "", 1).

service_account_namespace_group_prefix(Group, Prefix) :-
    service_account_namespace_group(Group, Namespace),
    !:string:contains(Namespace, ":")
    |> let Prefix = fn:string:concat("system:serviceaccount:", Namespace, ":").

request_service_account_group(Id, "system:serviceaccounts") :-
    request_service_account(Id, _).

request_service_account_group(Id, "system:authenticated") :-
    request_service_account(Id, _).

request_service_account_group(Id, Group) :-
    request_service_account(Id, User),
    service_account_namespace_group_prefix(Group, Prefix),
    :string:starts_with(User, Prefix).

# RoleBinding grants apply in their own namespace; ClusterRoleBinding grants
# (Namespace "") apply everywhere, including cluster-scoped requests.
request_grant_namespace(Id, Namespace) :-
    access_request(Id, _, Namespace, _, _, _, _, _, _).

request_grant_namespace(Id, "") :-
    access_request(Id, _, _, _, _, _, _, _, _).

request_grant_api_group(Id, ApiGroup) :-
    access_request(Id, _, _, ApiGroup, _, _, _, _, _).

request_grant_api_group(Id, "*") :-
    access_request(Id, _, _, _, _, _, _, _, _).

# Rules name subresources as "resource/subresource". "*" matches every
# resource and subresource, and "*/sub" matches subresource sub of any
# resource. "res/*" is not a wildcard.
request_grant_resource(Id, Resource) :-
    access_request(Id, _, _, _, Resource, Subresource, _, _, _),
    Subresource = "".

request_grant_resource(Id, Combined) :-
    access_request(Id, _, _, _, Resource, Subresource, _, _, _),
    Subresource != ""
    |> let Combined = fn:string:concat(Resource, "/", Subresource).

request_grant_resource(Id, AnyResource) :-
    access_request(Id, _, _, _, _, Subresource, _, _, _),
    Subresource != ""
    |> let AnyResource = fn:string:concat("*/", Subresource).

request_grant_resource(Id, "*") :-
    access_request(Id, _, _, _, _, _, _, _, _).

# A grant without resourceNames (/any) matches any request; a named grant only
# matches a request for exactly that name. A request without a name (list,
# create) has Name "", so it only matches a grant with resourceNames: [""].
request_grant_resource_name(Id, /any) :-
    access_request(Id, _, _, _, _, _, _, _, _).

request_grant_resource_name(Id, Name) :-
    access_request(Id, _, _, _, _, _, Name, _, _).

request_grant_verb(Id, Verb) :-
    access_request(Id, _, _, _, _, _, _, Verb, _).

request_grant_verb(Id, "*") :-
    access_request(Id, _, _, _, _, _, _, _, _).

# Resource requests are the ones without a Path.
rbac_allowed(Id) :-
    access_request(Id, _, _, _, _, _, _, _, Path),
    Path = "",
    request_subject(Id, Kind, Name),
    direct_perm(Name, Kind, Namespace, ApiGroup, Resource, ResourceName, Verb),
    request_grant_namespace(Id, Namespace),
    request_grant_api_group(Id, ApiGroup),
    request_grant_resource(Id, Resource),
    request_grant_resource_name(Id, ResourceName),
    request_grant_verb(Id, Verb).

# ---- Non-resource URL matching ----
#
# A nonResourceURLs entry matches a path exactly, or, when it ends in "*",
# as a prefix: Kubernetes strips every trailing "*" (strings.TrimRight) and
# tests the rest with HasPrefix. "*" alone thus matches every path.
#
# There is no string slicing, so trailing stars are removed one at a time.
# fn:string:replace only replaces the first match, so a newline is appended
# as an end marker and "*\n" replaced: that is always the last "*". Paths
# never contain a newline.
url_trim_step(Url, Url) :-
    policy_rule_url_perm(_, Url, _),
    :string:ends_with(Url, "*").

url_trim_step(Url, Shorter) :-
    url_trim_step(Url, Current),
    :string:ends_with(Current, "*")
    |> let Shorter = fn:string:replace(fn:string:concat(Current, "\n"), "*\n", "", 1).

url_prefix(Url, Prefix) :-
    url_trim_step(Url, Prefix),
    !:string:ends_with(Prefix, "*").

request_grant_url(Id, Path) :-
    access_request(Id, _, _, _, _, _, _, _, Path),
    Path != "".

request_grant_url(Id, Url) :-
    access_request(Id, _, _, _, _, _, _, _, Path),
    Path != "",
    url_prefix(Url, Prefix),
    :string:starts_with(Path, Prefix).

# Non-resource requests are the ones with a Path.
rbac_allowed(Id) :-
    request_grant_url(Id, Url),
    request_subject(Id, Kind, Name),
    request_grant_verb(Id, Verb),
    direct_url_perm(Name, Kind, Url, Verb).
