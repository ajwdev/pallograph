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

// Oracle answers requests with the kube-apiserver RBAC authorizer.
type Oracle struct {
	world      *World
	authorizer *rbacauthorizer.RBACAuthorizer
	resolver   *rbacregistryvalidation.DefaultRuleResolver
}

func NewOracle(world *World) *Oracle {
	_, static := rbacregistryvalidation.NewTestRuleResolver(
		world.Roles, world.RoleBindings, world.ClusterRoles, world.ClusterRoleBindings)
	return &Oracle{
		world:      world,
		authorizer: rbacauthorizer.New(static, static, static, static),
		resolver:   rbacregistryvalidation.NewDefaultRuleResolver(static, static, static, static),
	}
}

// Decide returns the authorizer's decision for request. The decision
// itself comes only from RBACAuthorizer.Authorize; the second rule walk
// exists to find the allowing rule so its features can be tagged.
func (o *Oracle) Decide(request *Request) (Decision, error) {
	attributes := request.attributes()
	ctx := context.Background()
	verdict, reason, err := o.authorizer.Authorize(ctx, attributes)
	if err != nil {
		return Decision{}, err
	}

	decision := Decision{
		ID:      request.ID,
		Allowed: verdict == authorizer.DecisionAllow,
		Reason:  reason,
		Tags:    requestTags(request),
	}
	if !decision.Allowed {
		slices.Sort(decision.Tags)
		return decision, nil
	}

	var allowingSource fmt.Stringer
	var allowingRule *rbacv1.PolicyRule
	o.resolver.VisitRulesFor(ctx, attributes.User, attributes.Namespace,
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
