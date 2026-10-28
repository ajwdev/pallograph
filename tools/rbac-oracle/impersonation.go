package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	authenticationv1 "k8s.io/api/authentication/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/filters/impersonation"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
)

// Impersonation questions ask whether a principal may impersonate one
// identity: a user, a group or a ServiceAccount. They are answered by the
// API server's impersonation filters from k8s.io/apiserver, run over the
// RBAC authorizer: the filter builds the authorization requests itself, so
// the oracle never constructs impersonation attributes to decide with.
//
// Kubernetes 1.37 serves impersonation with WithConstrainedImpersonation
// (feature gate ConstrainedImpersonation, on by default), whose legacy mode
// is a reimplementation of the older WithImpersonation. Both are run, and
// a disagreement is an error. Worlds hold no constrained impersonation
// verbs (impersonate:user-info and the like), so the legacy checks decide.

// impersonationPlaceholderUser is the user a group question impersonates.
// The filters only accept Impersonate-Group alongside Impersonate-User, so
// a group question impersonates this user too, and placeholderAuthorizer
// allows that part. What remains is the filter's check of the group alone,
// which is what Pallograph models.
const impersonationPlaceholderUser = "pallograph-impersonation-placeholder"

// impersonationFilters are the two impersonation filters over one
// authorizer, each wrapped around a handler that answers
// http.StatusNoContent: a request that reaches it was allowed.
type impersonationFilters struct {
	legacy, constrained http.Handler
}

func newImpersonationFilters(a authorizer.UnconditionalAuthorizer) impersonationFilters {
	reached := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	return impersonationFilters{
		legacy:      impersonation.WithImpersonation(reached, a, legacyscheme.Codecs),
		constrained: impersonation.WithConstrainedImpersonation(reached, a, legacyscheme.Codecs),
	}
}

// placeholderAuthorizer allows impersonating impersonationPlaceholderUser,
// whatever the verb (constrained modes use their own), and asks its
// delegate everything else.
type placeholderAuthorizer struct {
	delegate authorizer.UnconditionalAuthorizer
}

func (p placeholderAuthorizer) Authorize(ctx context.Context, attributes authorizer.Attributes) (authorizer.Decision, string, error) {
	if attributes.IsResourceRequest() && attributes.GetAPIGroup() == "" &&
		attributes.GetResource() == "users" && attributes.GetName() == impersonationPlaceholderUser {
		return authorizer.DecisionAllow, "placeholder user", nil
	}
	return p.delegate.Authorize(ctx, attributes)
}

// impersonationHeaders are the headers a client sends to impersonate the
// identity request names.
func impersonationHeaders(r *Request) (http.Header, error) {
	headers := http.Header{}
	switch r.Resource {
	case "users":
		headers.Set(authenticationv1.ImpersonateUserHeader, r.Name)
	case "serviceaccounts":
		headers.Set(authenticationv1.ImpersonateUserHeader, serviceAccountUsername(r.Namespace, r.Name))
	case "groups":
		headers.Set(authenticationv1.ImpersonateUserHeader, impersonationPlaceholderUser)
		headers.Add(authenticationv1.ImpersonateGroupHeader, r.Name)
	default:
		return nil, fmt.Errorf("request %d: cannot impersonate %q", r.ID, r.Resource)
	}
	return headers, nil
}

// serveImpersonation sends the impersonation request through filter as the
// request's principal, and reports whether it got through. The request it
// impersonates for is a list of namespaces; only constrained modes look at
// it.
func serveImpersonation(filter http.Handler, r *Request) (bool, string, error) {
	headers, err := impersonationHeaders(r)
	if err != nil {
		return false, "", err
	}
	httpRequest := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces", nil)
	httpRequest.Header = headers
	ctx := request.WithUser(httpRequest.Context(), &user.DefaultInfo{Name: r.User, Groups: r.Groups})
	ctx = request.WithRequestInfo(ctx, &request.RequestInfo{
		IsResourceRequest: true, Path: "/api/v1/namespaces", Verb: "list",
		APIVersion: "v1", Resource: "namespaces",
	})
	recorder := httptest.NewRecorder()
	filter.ServeHTTP(recorder, httpRequest.WithContext(ctx))
	switch recorder.Code {
	case http.StatusNoContent:
		return true, "", nil
	case http.StatusForbidden:
		return false, recorder.Body.String(), nil
	default:
		return false, "", fmt.Errorf("request %d: impersonation filter answered %d: %s", r.ID, recorder.Code, recorder.Body.String())
	}
}

// impersonationAllowed decides an impersonation question with both
// filters.
func (d *decider) impersonationAllowed(r *Request) (bool, string, error) {
	filters := d.impersonation
	if r.Resource == "groups" {
		filters = d.groupImpersonation
	}
	legacy, reason, err := serveImpersonation(filters.legacy, r)
	if err != nil {
		return false, "", err
	}
	constrained, _, err := serveImpersonation(filters.constrained, r)
	if err != nil {
		return false, "", err
	}
	if legacy != constrained {
		return false, "", fmt.Errorf("request %d: WithImpersonation allows = %v but WithConstrainedImpersonation allows = %v",
			r.ID, legacy, constrained)
	}
	return legacy, reason, nil
}

// impersonationAttributes are the attributes the legacy filter authorizes
// for request's identity, used only to find the allowing rule for tagging.
// They mirror actingAsAttributes in WithImpersonation
// (k8s.io/apiserver/pkg/endpoints/filters/impersonation/impersonation.go,
// v0.37.1 lines 72-98): verb impersonate, the core API group, and a
// namespace only for a ServiceAccount, its own.
func impersonationAttributes(r *Request) authorizer.AttributesRecord {
	attributes := authorizer.AttributesRecord{
		User:            &user.DefaultInfo{Name: r.User, Groups: r.Groups},
		Verb:            "impersonate",
		Resource:        r.Resource,
		Name:            r.Name,
		ResourceRequest: true,
	}
	if r.Resource == "serviceaccounts" {
		attributes.Namespace = r.Namespace
	}
	return attributes
}

// GenerateImpersonationRequests asks every principal that might impersonate
// (see escalationPrincipals) about every identity worth impersonating:
//
//   - each user a binding names whose role grants something on resources,
//   - each group the same, and
//   - each ServiceAccount object.
//
// Pallograph's escalation rules only follow impersonation to identities
// like these: impersonating a user or group without grants of its own, or a
// ServiceAccount that does not exist, gains nothing (rules/escalation.mg).
func GenerateImpersonationRequests(world *World) []Request {
	impersonates := func(rule rbacv1.PolicyRule) bool {
		return ruleHasVerb(rule, "impersonate")
	}
	var targets []Request
	users, groups := subjectsWithResourceGrants(world)
	for _, name := range users {
		targets = append(targets, Request{Resource: "users", Name: name})
	}
	for _, name := range groups {
		targets = append(targets, Request{Resource: "groups", Name: name})
	}
	for _, account := range world.ServiceAccounts {
		targets = append(targets, Request{Resource: "serviceaccounts", Namespace: account.Namespace, Name: account.Name})
	}

	var requests []Request
	for _, principal := range escalationPrincipals(world, impersonates) {
		for _, target := range targets {
			target.Kind = impersonateKind
			target.User = principal.name
			target.Groups = principal.groups
			target.Verb = "impersonate"
			requests = append(requests, target)
		}
	}
	return requests
}
