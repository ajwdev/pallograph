package main

import (
	"context"
	"fmt"
	"slices"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	rbacregistryvalidation "k8s.io/kubernetes/pkg/registry/rbac/validation"
	rbacauthorizer "k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac"
)

// Oracle answers requests with the kube-apiserver RBAC authorizer and,
// for impersonation and RBAC write questions, the API server code that
// consults it.
type Oracle struct {
	*decider
	counterfactuals []counterfactual
}

// decider is the API server's RBAC machinery over one world: the
// authorizer, the rule resolver the RBAC registry checks writes with, and
// the impersonation filters built on the authorizer.
type decider struct {
	world              *World
	authorizer         *rbacauthorizer.RBACAuthorizer
	resolver           *rbacregistryvalidation.DefaultRuleResolver
	impersonation      impersonationFilters
	groupImpersonation impersonationFilters
}

func newDecider(world *World) *decider {
	_, static := rbacregistryvalidation.NewTestRuleResolver(
		world.Roles, world.RoleBindings, world.ClusterRoles, world.ClusterRoleBindings)
	authorizer := rbacauthorizer.New(static, static, static, static)
	return &decider{
		world:              world,
		authorizer:         authorizer,
		resolver:           rbacregistryvalidation.NewDefaultRuleResolver(static, static, static, static),
		impersonation:      newImpersonationFilters(authorizer),
		groupImpersonation: newImpersonationFilters(placeholderAuthorizer{authorizer}),
	}
}

// allowed decides request. The tags explain how a write question was
// decided; other kinds get none.
func (d *decider) allowed(request *Request) (bool, string, []string, error) {
	switch request.Kind {
	case accessKind:
		verdict, reason, err := d.authorizer.Authorize(context.Background(), request.attributes())
		return verdict == authorizer.DecisionAllow, reason, nil, err
	case impersonateKind:
		allowed, reason, err := d.impersonationAllowed(request)
		return allowed, reason, nil, err
	case writeKind:
		return d.writeAllowed(request)
	}
	return false, "", nil, fmt.Errorf("request %d: unknown kind %q", request.ID, request.Kind)
}

// counterfactual is the API server over a deliberately altered copy of the
// world. A denied request it would allow gets its tag, which names the
// Kubernetes behavior responsible for the denial.
type counterfactual struct {
	tag      string
	decider  *decider
	fallback bool
}

// AddCounterfactual tags every denied request that world would allow with
// tag. Over-grants carrying such a tag are explained by that behavior;
// over-grants carrying none are unexplained. A fallback counterfactual is
// only consulted when no earlier one explained the denial, so a combination
// of behaviors is reported only when no single one suffices.
func (o *Oracle) AddCounterfactual(tag string, world *World, fallback bool) {
	o.counterfactuals = append(o.counterfactuals, counterfactual{tag, newDecider(world), fallback})
}

func NewOracle(world *World) *Oracle {
	return &Oracle{decider: newDecider(world)}
}

// Decide returns the API server's decision for request. The decision
// itself comes only from the API server's code (see decider.allowed); the
// second rule walk exists to find the allowing rule so its features can be
// tagged.
func (o *Oracle) Decide(request *Request) (Decision, error) {
	allowed, reason, kindTags, err := o.allowed(request)
	if err != nil {
		return Decision{}, err
	}

	decision := Decision{
		ID:      request.ID,
		Allowed: allowed,
		Reason:  reason,
		Tags:    append(requestTags(request), kindTags...),
	}
	if !decision.Allowed {
		explained := false
		for _, counterfactual := range o.counterfactuals {
			if counterfactual.fallback && explained {
				continue
			}
			allowed, _, _, err := counterfactual.decider.allowed(request)
			if err != nil {
				return Decision{}, err
			}
			if allowed {
				decision.Tags = append(decision.Tags, counterfactual.tag)
				explained = true
			}
		}
		slices.Sort(decision.Tags)
		return decision, nil
	}

	var attributes authorizer.AttributesRecord
	switch request.Kind {
	case accessKind:
		attributes = request.attributes()
	case impersonateKind:
		attributes = impersonationAttributes(request)
	default:
		// A write is allowed by several checks, named by its tags.
		slices.Sort(decision.Tags)
		return decision, nil
	}

	var allowingSource fmt.Stringer
	var allowingRule *rbacv1.PolicyRule
	o.resolver.VisitRulesFor(context.Background(), attributes.User, attributes.Namespace,
		func(source fmt.Stringer, rule *rbacv1.PolicyRule, err error) bool {
			if rule != nil && rbacauthorizer.RuleAllows(attributes, rule) {
				allowingSource, allowingRule = source, rule
				return false
			}
			return true
		})
	if allowingRule == nil {
		return Decision{}, fmt.Errorf("request %d: allowed but no allowing rule found", request.ID)
	}

	sourceTags, err := o.sourceTags(allowingSource.String())
	if err != nil {
		return Decision{}, fmt.Errorf("request %d: %w", request.ID, err)
	}
	decision.Tags = append(decision.Tags, sourceTags...)
	decision.Tags = append(decision.Tags, ruleTags(allowingRule)...)
	slices.Sort(decision.Tags)
	return decision, nil
}

func requestTags(request *Request) []string {
	tags := []string{}
	switch request.Kind {
	case impersonateKind:
		tags = append(tags, "request-impersonate-"+request.Resource)
	case writeKind:
		tags = append(tags, "request-write-"+request.Verb+"-"+request.Resource)
	}
	if request.Kind != accessKind {
		if _, _, ok := splitServiceAccount(request.User); ok {
			tags = append(tags, "principal-serviceaccount")
		}
		return tags
	}
	switch {
	case request.Path != "":
		tags = append(tags, "request-nonresource")
	case request.Subresource != "":
		tags = append(tags, "request-subresource")
	}
	if request.Path == "" && request.Name != "" {
		tags = append(tags, "request-named")
	}
	if request.Namespace == "" {
		tags = append(tags, "request-cluster-scope")
	}
	if _, _, ok := splitServiceAccount(request.User); ok {
		tags = append(tags, "principal-serviceaccount")
	}
	return tags
}

func ruleTags(rule *rbacv1.PolicyRule) []string {
	var tags []string
	if slices.Contains(rule.Verbs, rbacv1.VerbAll) {
		tags = append(tags, "rule-wildcard-verb")
	}
	if slices.Contains(rule.APIGroups, rbacv1.APIGroupAll) {
		tags = append(tags, "rule-wildcard-group")
	}
	if slices.Contains(rule.Resources, rbacv1.ResourceAll) {
		tags = append(tags, "rule-wildcard-resource")
	}
	if slices.ContainsFunc(rule.Resources, func(r string) bool { return strings.HasPrefix(r, "*/") }) {
		tags = append(tags, "rule-wildcard-subresource")
	}
	if len(rule.ResourceNames) > 0 {
		tags = append(tags, "rule-resource-names")
	}
	if slices.Contains(rule.NonResourceURLs, rbacv1.NonResourceAll) {
		tags = append(tags, "rule-wildcard-url")
	} else if slices.ContainsFunc(rule.NonResourceURLs, func(u string) bool { return strings.HasSuffix(u, "*") }) {
		tags = append(tags, "rule-url-prefix")
	}
	return tags
}

// sourceTags tags the binding that granted a request. source is the
// resolver's describer string, one of:
//
//	ClusterRoleBinding "name" of ClusterRole "role" to Kind "subject"
//	RoleBinding "name/ns" of Role "role" to Kind "subject"
//
// where a ServiceAccount subject is rendered as "name/namespace".
func (o *Oracle) sourceTags(source string) ([]string, error) {
	var bindingKind, bindingName, roleKind, roleName, subjectKind, subjectName string
	_, err := fmt.Sscanf(source, "%s %q of %s %q to %s %q",
		&bindingKind, &bindingName, &roleKind, &roleName, &subjectKind, &subjectName)
	if err != nil {
		return nil, fmt.Errorf("parse binding description %q: %w", source, err)
	}

	var tags []string
	var subjects []rbacv1.Subject
	switch bindingKind {
	case "ClusterRoleBinding":
		tags = append(tags, "binding-clusterrolebinding")
		for _, binding := range o.world.ClusterRoleBindings {
			if binding.Name == bindingName {
				subjects = binding.Subjects
			}
		}
	case "RoleBinding":
		tags = append(tags, "binding-rolebinding")
		name, namespace, _ := strings.Cut(bindingName, "/")
		for _, binding := range o.world.RoleBindings {
			if binding.Name == name && binding.Namespace == namespace {
				subjects = binding.Subjects
			}
		}
		if roleKind == "ClusterRole" {
			tags = append(tags, "binding-rolebinding-to-clusterrole")
		}
	}
	if roleKind == "ClusterRole" && o.world.AggregatedRoles[roleName] {
		tags = append(tags, "role-aggregated")
	}
	if roleKind == "ClusterRole" && o.world.AggregationCycleRoles[roleName] {
		tags = append(tags, "role-on-aggregation-cycle")
	}

	switch subjectKind {
	case rbacv1.UserKind:
		tags = append(tags, "subject-user")
	case rbacv1.GroupKind:
		tags = append(tags, "subject-group")
		if strings.HasPrefix(subjectName, "system:") {
			tags = append(tags, "subject-system-group")
		}
	case rbacv1.ServiceAccountKind:
		tags = append(tags, "subject-serviceaccount")
		name, _, _ := strings.Cut(subjectName, "/")
		for _, subject := range subjects {
			if subject.Kind == rbacv1.ServiceAccountKind && subject.Name == name && subject.Namespace == "" {
				tags = append(tags, "subject-serviceaccount-namespace-defaulted")
				break
			}
		}
	}
	return tags, nil
}

// serviceAccountUsername is the username the authenticator gives a
// service account token.
func serviceAccountUsername(namespace, name string) string {
	return serviceaccount.MakeUsername(namespace, name)
}
